"""已封禁 IP 反复访问：静默 + 累计拦截次数 + 惯犯升级黑名单（2026-10-22 用户反馈）。

用户原话：「已拦截了还弹窗提示或者右下角窗口提示，影响电脑操作。如果已经拦截的，
可以记录拦截次数。或者已封禁的 IP 反复访问的话，直接列入黑名单，加强安全防护。」

这批用例盯五件事，每条都对应一个「写错了也没人当场发现」的地方：

1. 迁移 v5 真的给 ban_list 加了列（否则次数永远是 0，界面显示得像没拦过）；
2. 次数只打在 **active** 记录上 —— 打到已解封/失败的记录上，数字会失真；
3. 封禁期间的重复命中，告警必须**完全静默**（气泡、声音、弹窗一个都不许有），
   这是本条需求的全部意义；
4. 达到阈值后 **真的** 进了黑名单、封禁改成永久，且只提示一次；
5. 已封禁的 IP 不再出现在「待确认的封禁建议」里，但要说出「藏着几项」。
"""

import sqlite3
from typing import Any, Dict, List

import pytest

from core import database, pipeline, rule_engine
from core import settings as cfg
from core.event_bus import bus
from core.models import DISPOSITION_BLOCK, AccessRecord, BanRecord, now_ms
from core.rule_engine import RuleEngine, set_engine

IP = "203.0.113.88"


# ═══════════════════ 夹具 ═══════════════════


@pytest.fixture(autouse=True)
def _db(isolated_env):
    """fresh_db 只删库文件不建表，这里补建。"""
    database.init_db()
    bus.drain_alert(max_n=1000)
    yield
    bus.drain_alert(max_n=1000)


@pytest.fixture
def engine():
    """最小规则集：一条 100 分规则（记录里带 sqlmap UA 必然命中）

    刻意**不用**黑名单规则打分：那要求 IP 已经在名单里，而「惯犯升级」用例
    正是要观察「从不在名单 → 进了名单」这件事，两者会互相打架。
    """
    e = RuleEngine()
    e._cfg = {
        "version": 1,
        "rules": {
            "scanner_ua": {"enabled": True, "score": 100, "patterns": ["sqlmap"]},
        },
    }
    e._compile()
    set_engine(e)
    yield e
    rule_engine._engine = None


@pytest.fixture
def sink(monkeypatch):
    """替身写入器：不落库、不起线程（起线程会让 conftest 的删库护栏炸）"""

    class _Sink:
        def __init__(self) -> None:
            self.risk: List[Any] = []
            self.access: List[Any] = []

        def submit_risk(self, rec, result):
            self.risk.append((rec, result))
            return True

        def submit_access(self, rec):
            self.access.append(rec)
            return True

    s = _Sink()
    monkeypatch.setattr(pipeline, "get_writer", lambda: s)
    return s


def _active_ban(ip: str = IP, duration: int = 3600) -> int:
    """直接落一条 active 封禁（模拟「上一轮已经封过、规则还在防火墙里」）"""
    return database.insert_ban(
        BanRecord(
            ip=ip,
            reason="[自动] 命中黑名单",
            risk_score=100,
            source="auto",
            status="active",
            duration_sec=duration,
            expire_at=now_ms() + duration * 1000,
        )
    )


def _rec(ip: str = IP) -> AccessRecord:
    """默认带 sqlmap UA：配合 engine 夹具那条 100 分规则稳定判为「严重风险」"""
    return AccessRecord(
        ip=ip,
        remote_port=51234,
        local_port=18080,
        protocol="tcp",
        event_ts=now_ms(),
        user_agent="sqlmap/1.7",
    )


# ═══════════════════ 迁移 v5 ═══════════════════


def test_migration_v5_adds_hit_columns_and_backfills_zero(isolated_env, tmp_path):
    """老库（v4，ban_list 没有这两列）升级后：列存在、老记录次数为 0 不是 NULL"""
    from core.migrations import SCHEMA_VERSION, migrate

    conn = sqlite3.connect(str(tmp_path / "v4.db"))
    try:
        conn.execute(
            "CREATE TABLE ban_list ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " ip TEXT NOT NULL,"
            " status TEXT NOT NULL DEFAULT 'pending')"
        )
        conn.execute("INSERT INTO ban_list(ip, status) VALUES ('1.2.3.4', 'active')")
        conn.execute("PRAGMA user_version = 4")
        conn.commit()

        assert migrate(conn) == SCHEMA_VERSION == 6

        cols = {r[1] for r in conn.execute("PRAGMA table_info(ban_list)")}
        assert {"hit_count", "last_hit_at"} <= cols
        # NOT NULL DEFAULT 0：界面直接读 int(row.hit_count)，拿到 None 会显示空白
        assert conn.execute("SELECT hit_count FROM ban_list").fetchone()[0] == 0
        assert conn.execute("SELECT last_hit_at FROM ban_list").fetchone()[0] is None
    finally:
        conn.close()


# ═══════════════════ 拦截次数 ═══════════════════


def test_bump_ban_hits_counts_only_active_records():
    """次数只打在 active 上：已解封 / 失败的记录再被命中不算「拦下一次」"""
    ban_id = _active_ban()
    assert database.bump_ban_hits(IP) == 1
    assert database.bump_ban_hits(IP) == 2

    row = database.query_bans(limit=10)[0]
    assert row.hit_count == 2
    assert row.last_hit_at and row.last_hit_at > 0

    # 解封后：防火墙那边已经不拦了，这次命中不是「拦下」→ 返回 None 且不计数
    database.update_ban(ban_id, status="unbanned")
    assert database.bump_ban_hits(IP) is None
    assert database.query_bans(limit=10)[0].hit_count == 2


def test_bump_ban_hits_returns_none_when_never_banned():
    """从没封过的 IP：返回 None（调用方据此区分「重复命中」和「本次刚封」）"""
    assert database.bump_ban_hits("198.51.100.9") is None


# ── 计数不能走「每次一条新连接」的同步写 ──
#
# 这条不是洁癖：本机实测「新连接 + UPDATE + commit + close」单次 170ms
# （慢在 close 触发的 WAL checkpoint），长连接只要 2ms。攻击期每秒几十次，
# 同步写会把采集线程堵死、直接漏采。所以要钉住「进的是队列，不是同步写库」。


def test_count_block_hit_goes_through_writer_queue(monkeypatch):
    """计数必须投给批量写入器，绝不就地同步写库"""
    from core import db_writer
    from core.db_writer import BatchWriter

    _active_ban()
    ban = database.find_active_ban_by_ip(IP)
    assert ban is not None

    sync_calls: List[Any] = []
    monkeypatch.setattr(pipeline, "bump_ban_hits", lambda *a, **kw: sync_calls.append(a))

    w = BatchWriter()  # 不启动线程：只验证它进的是队列
    db_writer.set_writer(w)
    try:
        assert pipeline.count_block_hit(ban) == 1
        assert w.pending() == 1, "应当进写入队列"
    finally:
        db_writer.set_writer(None)
    assert sync_calls == [], "不允许同步写库（170ms/次 会堵死采集线程）"


def test_writer_persists_hit_count():
    """批量写入器真的把次数落库（长连接、随批次一次 fsync）"""
    from core.db_writer import BatchWriter

    _active_ban()
    w = BatchWriter()
    w.start()
    try:
        assert w.submit_hit(IP, now_ms())
        assert w.flush(timeout=5)
        assert w.stats()["hits"] == 1
    finally:
        w.stop(timeout=5)

    row = database.query_bans(limit=1)[0]
    assert row.hit_count == 1
    assert row.last_hit_at, "last_hit_at 要一起写入，否则界面说不出「最近一次」"


def test_count_block_hit_resumes_from_persisted_count():
    """进程重启后从库里的次数接着算，不能把门槛重新爬一遍"""
    _active_ban()
    ban = database.find_active_ban_by_ip(IP)
    assert ban is not None
    database.update_ban(ban.id, hit_count=4)  # 上一轮已经拦了 4 次
    refreshed = database.find_active_ban_by_ip(IP)
    assert refreshed is not None

    assert pipeline.count_block_hit(refreshed) == 5, "重启后应当直接够到阈值 5"


# ═══════════════════ pipeline：重复命中要能被识别 ═══════════════════


def test_repeat_hit_is_flagged_in_alert_payload(engine, sink):
    """已在封禁中的 IP 再次命中：结论仍是「已拦截」，且告警里带上重复标记 + 次数"""
    _active_ban()
    pipeline.process_record(_rec())
    alerts = bus.drain_alert(max_n=10)
    assert alerts and alerts[-1]["blocked_again"] is True
    assert alerts[-1]["block_hits"] == 1

    pipeline.process_record(_rec())
    alerts = bus.drain_alert(max_n=10)
    assert alerts[-1]["blocked_again"] is True
    assert alerts[-1]["block_hits"] == 2, "第二次命中要累加，不能一直报 1"


def test_first_ban_is_not_flagged_as_repeat(engine, sink, monkeypatch):
    """本次刚封（之前没有 active 记录）不算重复命中 —— 状态变了，值得通知一次"""
    monkeypatch.setattr(pipeline, "auto_ban_record", lambda *a, **kw: True)
    cfg.set("auto_mode", "1", persist=False)
    cfg.set("auto_ban_threshold", "90", persist=False)
    try:
        pipeline.process_record(_rec())
    finally:
        cfg.set("auto_mode", "0", persist=False)
    alerts = bus.drain_alert(max_n=10)
    assert alerts[-1]["disposition"] == DISPOSITION_BLOCK
    assert alerts[-1]["blocked_again"] is False


# ═══════════════════ 告警静默 ═══════════════════


def _alert(**kw) -> Dict[str, Any]:
    a: Dict[str, Any] = {
        "ip": IP,
        "level": "critical",
        "score": 100,
        "reason": "命中黑名单",
        "geo": "",
        "local_port": 18080,
        "disposition": DISPOSITION_BLOCK,
    }
    a.update(kw)
    return a


class _Tray:
    """托盘替身：只记录气泡，不创建真实托盘图标"""

    def __init__(self) -> None:
        self.msgs: List[Any] = []

    def showMessage(self, *args):
        self.msgs.append(args)


class _Probe:
    """Alerter + 记录下来的「响铃 / 推送」调用，避免在测试机上真的打断人

    2026-10-27 用户要求取消模态弹窗后，`_popup` 已从 Alerter 移除，这里也就没有
    可替换的弹窗钩子 —— 反向证明「告警路径上不存在 QMessageBox」这件事本身
    由 `test_no_modal_popup_on_any_level` 守着。
    """

    def __init__(self) -> None:
        self.calls: List[str] = []
        self.tray = _Tray()
        self.alerter: Any = None


@pytest.fixture
def probe(monkeypatch) -> _Probe:
    from core import alerts as alerts_mod

    cfg.set("alert_sound", "1", persist=False)
    cfg.set("alert_block_silent", "1", persist=False)

    p = _Probe()
    a = alerts_mod.Alerter(tray=p.tray)
    monkeypatch.setattr(a, "_beep", lambda *x, **kw: p.calls.append("beep"))
    monkeypatch.setattr(a, "_notify_webhook", lambda *x, **kw: p.calls.append("webhook"))
    p.alerter = a
    return p


def test_repeated_block_is_completely_silent(probe):
    """封禁期间的重复命中：不响铃、不冒气泡 —— 一个都不许有

    这是本条需求的核心：防火墙已经挡住了，弹窗说的还是同一句「已拦截」，
    唯一的效果是抢走用户正在打字的焦点。
    """
    assert probe.alerter.notify(_alert(blocked_again=True, block_hits=7)) is False
    assert probe.calls == []
    assert probe.tray.msgs == []


def test_first_block_still_notifies(probe):
    """首次拦截照常提示（静默只针对「同一件事又发生一次」，不能把新事件也吞掉）"""
    assert probe.alerter.notify(_alert(blocked_again=False)) is True
    assert "beep" in probe.calls
    assert probe.tray.msgs, "首次拦截必须有右下角气泡，否则用户完全不知道发生过什么"


def test_no_modal_popup_on_any_level(probe, monkeypatch):
    """任何级别、任何处置结论都不再弹模态窗口（用户 2026-10-27 的明确要求）

    从「有没有调用弹窗」反过来验证已经不够 —— 弹窗函数本身被删了。所以这里
    直接盯住 QMessageBox：只要告警路径碰它一次，测试就红。
    """
    import qtcompat

    calls: List[str] = []

    class _Boom:
        @staticmethod
        def information(*a, **kw):
            calls.append("information")

        @staticmethod
        def warning(*a, **kw):
            calls.append("warning")

        @staticmethod
        def critical(*a, **kw):
            calls.append("critical")

        @staticmethod
        def question(*a, **kw):
            calls.append("question")

    monkeypatch.setattr(qtcompat, "QMessageBox", _Boom, raising=False)
    for level in ("low", "medium", "high", "critical"):
        probe.alerter._last_alert.clear()
        probe.alerter.notify(_alert(level=level, blocked_again=False))
    assert calls == []
    assert probe.tray.msgs, "气泡才是唯一的提醒通道，不能被一起取消"


def test_escalation_is_not_silenced(probe):
    """升级黑名单是「状态真的变了」：即使带重复标记也要提示（但只走气泡）"""
    assert probe.alerter.notify(_alert(blocked_again=True, block_hits=5, escalated=True)) is True
    assert probe.tray.msgs, "升级必须冒一个气泡，否则等于偷偷改了安全策略"
    assert "beep" not in probe.calls, "升级不额外响铃"


def test_silence_can_be_turned_off(probe):
    """关掉「静默」开关就回到老行为：重复命中照样提示"""
    cfg.set("alert_block_silent", "0", persist=False)
    assert probe.alerter.notify(_alert(blocked_again=True, block_hits=3)) is True
    assert probe.tray.msgs


# ═══════════════════ 惯犯升级黑名单 ═══════════════════


def test_escalation_below_threshold_does_nothing(engine, monkeypatch):
    from app.blacklist_service import escalate_repeat_offender

    _active_ban()
    ban = database.find_active_ban_by_ip(IP)
    cfg.set("repeat_blacklist_enabled", "1", persist=False)
    cfg.set("repeat_blacklist_hits", "5", persist=False)

    assert escalate_repeat_offender(IP, ban, 4) is False
    assert IP not in engine.blacklist


def test_escalation_at_threshold_blacklists_and_makes_permanent(engine, monkeypatch):
    """达到阈值：进黑名单 + 封禁改永久 + 记审计 + 气泡提示一次"""
    from app import audit
    from app.blacklist_service import PERMANENT, SOURCE_BLACKLIST, escalate_repeat_offender

    monkeypatch.setattr(engine, "save_lists", lambda: None)  # 别在测试机上落盘
    _active_ban()
    ban = database.find_active_ban_by_ip(IP)
    cfg.set("repeat_blacklist_enabled", "1", persist=False)
    cfg.set("repeat_blacklist_hits", "5", persist=False)

    assert escalate_repeat_offender(IP, ban, 5) is True

    assert IP in engine.blacklist, "必须真的写进名单，否则下次访问还是只按一次封禁处理"
    row = database.query_bans(limit=10)[0]
    assert row.duration_sec == PERMANENT, "封禁要改成永久，否则到期后攻击者又能回来"
    assert row.source == SOURCE_BLACKLIST

    records = database.query_audit(limit=10, action=audit.ACTION_BAN_ESCALATE)
    assert records, "程序自己收紧了安全策略，必须留痕"
    assert IP in records[0]["summary"]

    alerts = bus.drain_alert(max_n=10)
    assert any(a.get("escalated") for a in alerts), "升级要通知一次"

    # 只提示一次：已经在名单里就不该再升一次、再弹一次
    assert escalate_repeat_offender(IP, ban, 99) is False


def test_escalation_is_skipped_when_disabled(engine):
    from app.blacklist_service import escalate_repeat_offender

    _active_ban()
    ban = database.find_active_ban_by_ip(IP)
    cfg.set("repeat_blacklist_enabled", "0", persist=False)
    cfg.set("repeat_blacklist_hits", "5", persist=False)

    assert escalate_repeat_offender(IP, ban, 50) is False
    assert IP not in engine.blacklist


def test_repeat_hits_trigger_escalation_end_to_end(engine, sink, monkeypatch):
    """整条链路：同一 IP 被封着又命中 5 次 → 自动进黑名单（不需要人工点）"""
    from app.blacklist_service import escalate_repeat_offender

    monkeypatch.setattr(engine, "save_lists", lambda: None)
    monkeypatch.setattr(pipeline, "_maybe_escalate", escalate_repeat_offender)
    cfg.set("repeat_blacklist_enabled", "1", persist=False)
    cfg.set("repeat_blacklist_hits", "5", persist=False)
    _active_ban()

    for _ in range(5):
        pipeline.process_record(_rec())

    assert IP in engine.blacklist
    assert database.query_bans(limit=10)[0].duration_sec == 0


# ═══════════════════ 建议表过滤 ═══════════════════


class _Sort:
    def apply(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return list(rows)


class _Host:
    """`BansPage._load_suggestions` 的最小替身（不建 Qt 控件）"""

    def __init__(self) -> None:
        self._banned: Dict[str, Any] = {}
        self._sug_rows_src: List[Dict[str, Any]] = []
        self._sug_rows: List[Dict[str, Any]] = []
        self._sug_hidden = 0
        self.sug_sort = _Sort()

    def _render_suggestions(self) -> None:
        pass


def _evt(eid: int, ip: str) -> Dict[str, Any]:
    return {
        "id": eid,
        "event_ts": now_ms() + eid,
        "ip": ip,
        "local_port": 1024,
        "risk_level": "critical",
        "risk_score": 100,
        "handled": 0,
        "summary": "命中规则：管理端口归属地检测",
    }


def test_suggestions_hide_already_banned_and_say_how_many(monkeypatch):
    """已封禁的 IP 不再出现在「待确认的封禁建议」里，但要说清藏了几项"""
    from gui import page_bans

    rows = [_evt(1, "120.1.1.1"), _evt(2, "8.8.4.4")]
    monkeypatch.setattr(page_bans, "query_risk_events", lambda **kw: rows)
    monkeypatch.setattr(page_bans, "active_ban_ip_map", lambda: {"120.1.1.1": 3})

    host = _Host()
    page_bans.BansPage._load_suggestions(host)  # type: ignore[arg-type]

    assert [r["ip"] for r in host._sug_rows] == ["8.8.4.4"]
    assert host._sug_hidden == 1, "少了几行必须说出来，否则用户以为建议丢了"
