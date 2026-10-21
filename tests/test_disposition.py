"""处置结论（disposition）：弹窗与界面必须说清「到底拦没拦」。

用户反馈的原话：「弹窗和程序里面应该显示处理结果，比如已放行、已拦截、
仅提醒」。此前弹窗只写「风险评分 20」，用户看不出这条访问是被放过去了、
只记了笔账，还是真的被防火墙挡在门外 —— 而这恰恰是安全工具最该回答的问题。

这里钉住四件事：
1. 规则引擎给出的**基础结论**：白名单 / 无命中 → 已放行；高/严重 → 待确认；
   低/中 → 仅提醒；
2. 该 IP 已在封禁中时，pipeline 把结论升级为「已拦截」，且**先定结论、后投递
   告警** —— 顺序反了弹窗就会说「仅提醒」，而防火墙其实已经拦了；
3. 自动封禁成功后同一条告警里报「已拦截」（不需要用户自己去封禁页确认）；
4. 老库（disposition 列为空）按等级兜底，**不能**凭「现在是否被封」倒推，
   否则上周只提醒过的记录会显示成「已拦截」，复盘时会误判处置是否及时。
"""

import sqlite3

import pytest

from core import pipeline, rule_engine
from core.database import init_db
from core.event_bus import bus
from core.models import (
    DISPOSITION_ALERT,
    DISPOSITION_ALLOW,
    DISPOSITION_BLOCK,
    DISPOSITION_CONFIRM,
    DISPOSITION_IGNORED,
    AccessRecord,
    BanRecord,
    RiskResult,
    disposition_base,
    disposition_of,
    now_ms,
)
from core.rule_engine import RuleEngine, set_engine

IP = "203.0.113.55"


# ═══════════════════ 夹具 ═══════════════════


@pytest.fixture(autouse=True)
def _clean_bus():
    """告警是全局队列，用例之间必须清干净，否则上一条用例的 alert 会被读到"""
    bus.drain_alert(max_n=1000)
    yield
    bus.drain_alert(max_n=1000)


@pytest.fixture
def engine(isolated_env):
    init_db()
    e = RuleEngine()
    e._cfg = {
        "version": 1,
        "rules": {
            "blacklist": {"enabled": True, "score": 100},
            "scanner_ua": {"enabled": True, "score": 45, "patterns": ["sqlmap"], "empty_ua": True},
            "suspicious_method": {"enabled": True, "score": 30, "methods": ["TRACE"]},
        },
    }
    e._compile()
    e.whitelist = type(e.whitelist)()  # 干净的白名单，避免宿主机配置影响结论
    set_engine(e)
    yield e
    # 直接清全局单例：`set_engine` 的签名不接受 None，而下一个用例必须能
    # 重新 get_engine() 建出真实引擎（否则会继承本用例的假规则集）
    rule_engine._engine = None


class _Sink:
    """替身写入器：不落库、不启线程，只记录提交了什么"""

    def __init__(self):
        self.risk = []
        self.access = []

    def submit_risk(self, rec, result):
        self.risk.append((rec, result))
        return True

    def submit_access(self, rec):
        self.access.append(rec)
        return True


@pytest.fixture
def sink(monkeypatch):
    s = _Sink()
    monkeypatch.setattr(pipeline, "get_writer", lambda: s)
    return s


@pytest.fixture
def no_ban(monkeypatch):
    """默认：这个 IP 没有被封过"""
    monkeypatch.setattr(pipeline, "find_active_ban_by_ip", lambda ip: None)


@pytest.fixture
def banned(monkeypatch):
    rec = BanRecord(id=7, ip=IP, status="active", source="manual")
    monkeypatch.setattr(pipeline, "find_active_ban_by_ip", lambda ip: rec)
    return rec


def _rec(**kw) -> AccessRecord:
    kw.setdefault("ip", IP)
    kw.setdefault("local_port", 3000)
    kw.setdefault("event_ts", now_ms())
    # 默认带一个正常 UA：空 UA 会被 scanner_ua 规则当成扫描器（+45），
    # 那是刻意的防误伤设计，但会让「干净记录」的用例变成中危
    kw.setdefault("user_agent", "Mozilla/5.0 (Windows NT 10.0)")
    return AccessRecord(**kw)


# ═══════════════════ 引擎给出的基础结论 ═══════════════════


def test_whitelisted_ip_is_allowed(engine):
    """白名单命中：连「仅提醒」都不该出，结论就是已放行"""
    engine.whitelist.add(IP)
    r = engine.evaluate(_rec())
    assert r.whitelisted is True
    assert r.disposition == DISPOSITION_ALLOW
    assert r.disposition_label == "已放行"


def test_normal_traffic_is_allowed(engine):
    """一条规则都没命中：普通访问，结论同样是已放行（不是「仅提醒」）"""
    r = engine.evaluate(_rec())
    assert r.level == "normal"
    assert r.disposition == DISPOSITION_ALLOW


def test_medium_risk_is_alert_only(engine):
    """45 分（中危）：记录 + 提醒，没拦住 —— 这就是「仅提醒」"""
    r = engine.evaluate(_rec(user_agent="sqlmap/1.7"))
    assert r.level == "medium"
    assert r.disposition == DISPOSITION_ALERT
    assert r.disposition_label == "仅提醒"


def test_high_risk_waits_for_confirmation(engine):
    """黑名单 100 分：建议封禁但没自动封 —— 结论是「待确认」"""
    engine.blacklist.add(IP)
    r = engine.evaluate(_rec())
    assert r.suggest_ban is True
    assert r.disposition == DISPOSITION_CONFIRM
    assert r.disposition_label == "待确认"


# ═══════════════════ 历史数据兜底 ═══════════════════


def test_disposition_of_uses_stored_value():
    row = {"disposition": DISPOSITION_BLOCK, "handled": 0, "risk_level": "low"}
    assert disposition_of(row) == DISPOSITION_BLOCK


def test_disposition_of_falls_back_by_level():
    """老库该列为空：按等级推断，**不能**按「现在是否被封」倒推"""
    assert disposition_of({"risk_level": "critical"}) == DISPOSITION_CONFIRM
    assert disposition_of({"risk_level": "low"}) == DISPOSITION_ALERT
    # 人工忽略过的事件，结论就是「已忽略」，哪怕等级很高
    assert disposition_of({"risk_level": "critical", "handled": 2}) == DISPOSITION_IGNORED


def test_disposition_base_normal_is_allow():
    assert disposition_base("normal") == DISPOSITION_ALLOW
    assert disposition_base("normal", whitelisted=True) == DISPOSITION_ALLOW
    assert disposition_base("high") == DISPOSITION_CONFIRM


# ═══════════════════ pipeline：把「已在封禁中」写成「已拦截」 ═══════════════════


def test_existing_ban_turns_disposition_into_block(engine, sink, banned):
    """IP 已在封禁中：这条访问是被防火墙挡下的，弹窗必须说「已拦截」"""
    rec = _rec(user_agent="sqlmap/1.7")
    result = pipeline.process_record(rec)

    assert result.disposition == DISPOSITION_BLOCK
    assert result.disposition_label == "已拦截"
    # 实时监控读的是 rec.disposition（它不查库）
    assert rec.disposition == DISPOSITION_BLOCK
    # 落库的也是结论，不是「仅提醒」
    assert sink.risk and sink.risk[0][1].disposition == DISPOSITION_BLOCK


def test_alert_payload_carries_disposition(engine, sink, no_ban):
    """弹窗拿到的必须带处置结论，否则界面只能回到「只报分数」的老样子"""
    pipeline.process_record(_rec(user_agent="sqlmap/1.7"))
    alerts = bus.drain_alert(max_n=10)
    assert len(alerts) == 1
    assert alerts[0]["disposition"] == DISPOSITION_ALERT


def test_auto_ban_result_is_reported_as_block(engine, sink, no_ban, monkeypatch):
    """自动封禁成功 → 同一条告警里直接报「已拦截」，不让用户去封禁页确认"""
    from core import settings as cfg

    cfg.set("auto_mode", True)
    cfg.set("auto_ban_threshold", 90)
    monkeypatch.setattr(pipeline, "auto_ban_record", lambda *a, **kw: True)
    try:
        pipeline.process_record(_rec(user_agent="sqlmap/1.7"))  # 45 分，不会触发
        engine.blacklist.add(IP)  # 100 分，达标
        pipeline.process_record(_rec())
        alerts = bus.drain_alert(max_n=10)
        assert alerts and alerts[-1]["disposition"] == DISPOSITION_BLOCK
    finally:
        cfg.set("auto_mode", False)


def test_disposition_is_decided_before_alert_is_queued(engine, sink, no_ban, monkeypatch):
    """先定结论、后投递：封禁动作发生时会话里应该还一条告警都没有。

    这条用例防的是「把回填/封禁挪到 emit_alert 之后」—— 那正是用户报的
    「弹窗说仅提醒，其实已经拦了」的成因。
    """
    from core import settings as cfg

    cfg.set("auto_mode", True)
    cfg.set("auto_ban_threshold", 90)
    seen = {}

    def fake_auto_ban(rec, result, actor=None, existing=None):
        seen["alerts_when_banning"] = bus.drain_alert(max_n=10)
        return True

    monkeypatch.setattr(pipeline, "auto_ban_record", fake_auto_ban)
    try:
        engine.blacklist.add(IP)
        pipeline.process_record(_rec())
    finally:
        cfg.set("auto_mode", False)
        bus.drain_alert(max_n=10)

    assert seen["alerts_when_banning"] == []


def test_non_risk_record_is_allowed(engine, sink, no_ban):
    """正常访问不告警，但监控页仍要显示「已放行」"""
    rec = _rec()
    result = pipeline.process_record(rec)
    assert result.is_risk is False
    assert rec.disposition == DISPOSITION_ALLOW
    assert bus.drain_alert(max_n=10) == []


# ═══════════════════ 弹窗文案 ═══════════════════


def _alert(disposition: str, level: str = "low") -> dict:
    return {
        "ip": IP,
        "level": level,
        "score": 20,
        "reason": "命中规则：扫描器 UA",
        "geo": "中国·河南省·焦作市·移动",
        "local_port": 1024,
        "disposition": disposition,
    }


def test_alert_title_leads_with_result():
    from core.alerts import Alerter

    assert "已拦截" in Alerter._title("high", DISPOSITION_BLOCK)
    assert "待确认" in Alerter._title("high", DISPOSITION_CONFIRM)
    assert "仅提醒" in Alerter._title("low", DISPOSITION_ALERT)
    assert "已放行" in Alerter._title("normal", DISPOSITION_ALLOW)


def test_alert_body_shows_result_and_hint():
    from core.alerts import Alerter

    body = Alerter._body(_alert(DISPOSITION_BLOCK))
    assert "处置结果：已拦截" in body
    assert "防火墙" in body  # 一句话说明，用户不用去翻文档
    # 原有信息一条都不能少
    assert f"来源 IP：{IP}" in body
    assert "风险评分：20" in body


def test_alert_body_without_disposition_still_works():
    """老调用方（或单测）只喂 ip+level 时不能崩，也不能凭空编个结论"""
    from core.alerts import Alerter

    body = Alerter._body({"ip": IP, "level": "low", "score": 20})
    assert "处置结果" not in body
    assert f"来源 IP：{IP}" in body


# ═══════════════════ 导出与迁移 ═══════════════════


def test_export_event_rows_include_disposition():
    from app.export_csv import EVENT_CSV_HEADERS, iter_event_rows

    assert "处置结果" in EVENT_CSV_HEADERS
    idx = EVENT_CSV_HEADERS.index("处置结果")
    row = next(
        iter(
            iter_event_rows(
                [{"id": 1, "ip": IP, "risk_level": "high", "disposition": DISPOSITION_BLOCK}]
            )
        )
    )
    assert row[idx] == "已拦截"


def test_migration_v4_adds_and_backfills_disposition(isolated_env, tmp_path):
    """老库（v3，无该列）升级后：列存在、老记录被回填成非空的合理解论"""
    from core.migrations import SCHEMA_VERSION, migrate

    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(str(db))
    try:
        conn.execute(
            """
            CREATE TABLE risk_event (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                access_id   INTEGER,
                ip          TEXT NOT NULL,
                local_port  INTEGER DEFAULT 0,
                path        TEXT,
                risk_score  INTEGER NOT NULL,
                risk_level  TEXT NOT NULL,
                matched_rules TEXT,
                summary     TEXT,
                geo         TEXT,
                handled     INTEGER NOT NULL DEFAULT 0,
                event_ts    INTEGER NOT NULL,
                created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime'))
            )
            """
        )
        conn.execute(
            "INSERT INTO risk_event(ip, risk_score, risk_level, handled, event_ts)"
            " VALUES ('1.2.3.4', 90, 'critical', 0, 1)"
        )
        conn.execute(
            "INSERT INTO risk_event(ip, risk_score, risk_level, handled, event_ts)"
            " VALUES ('1.2.3.5', 20, 'low', 0, 2)"
        )
        conn.execute(
            "INSERT INTO risk_event(ip, risk_score, risk_level, handled, event_ts)"
            " VALUES ('1.2.3.6', 70, 'high', 2, 3)"
        )
        conn.execute("PRAGMA user_version = 3")
        conn.commit()

        assert migrate(conn) == SCHEMA_VERSION
        cols = [r[1] for r in conn.execute("PRAGMA table_info(risk_event)")]
        assert "disposition" in cols

        rows = {r[1]: r[0] for r in conn.execute("SELECT disposition, ip FROM risk_event")}
        # 当时自动封禁默认关闭 → 高危只是「待确认」，绝不能回填成「已拦截」
        assert rows["1.2.3.4"] == DISPOSITION_CONFIRM
        assert rows["1.2.3.5"] == DISPOSITION_ALERT
        assert rows["1.2.3.6"] == DISPOSITION_IGNORED
    finally:
        conn.close()


def test_insert_and_query_roundtrip_keeps_disposition(isolated_env):
    """落库 → 查回来仍是同一个结论（避免列加了但 INSERT 忘了写）"""
    from core.database import insert_risk_event, query_risk_events

    init_db()
    rec = _rec()
    result = RiskResult(score=100, level="critical", suggest_ban=True, disposition="block")
    insert_risk_event(rec, result, access_id=None)

    rows = query_risk_events(limit=10)
    assert rows and rows[0]["disposition"] == "block"


# ═══════════════════ 界面：事件表与实时监控表 ═══════════════════


def _qapp():
    import os

    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from qtcompat import QApplication

    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication([])
    return app


def _cell(page, row: int) -> str:
    """取处置列的文本（QTableWidgetItem 可能是 None，断言后才取）"""
    from gui import page_events

    item = page.table.item(row, page_events.COL_DISPOSITION)
    assert item is not None, f"第 {row} 行的处置列没有内容"
    return item.text()


def test_events_table_renders_disposition_column(fresh_db):
    """事件表必须有「处置」列，且老记录（该列为空）按等级兜底而不是空白"""
    from core import database
    from gui import page_events

    database.init_db()  # 构造页面时 refresh() 会查库，必须先建表
    _qapp()  # 必须持有 QApplication，否则控件无法创建
    page = page_events.EventsPage()
    rows = [
        {
            "id": 1,
            "ip": "1.1.1.1",
            "risk_level": "critical",
            "risk_score": 95,
            "disposition": DISPOSITION_BLOCK,
            "handled": 1,
            "event_ts": 1_700_000_000_000,
        },
        {
            "id": 2,
            "ip": "2.2.2.2",
            "risk_level": "low",
            "risk_score": 20,
            "disposition": DISPOSITION_ALERT,
            "handled": 0,
            "event_ts": 1_700_000_001_000,
        },
        {
            "id": 3,
            "ip": "3.3.3.3",
            "risk_level": "high",
            "risk_score": 70,
            "handled": 0,
            "event_ts": 1_700_000_002_000,
        },
    ]
    page._rows = rows
    page._render(rows)

    assert _cell(page, 0) == "已拦截"
    assert _cell(page, 1) == "仅提醒"
    assert _cell(page, 2) == "待确认"


def test_events_header_and_widths_stay_aligned():
    """表头、列宽、列号三者长度必须一致 —— 少一个就会整表错位"""
    from gui import page_events

    assert len(page_events.HEADERS) == len(page_events.COL_WIDTHS)
    assert len(page_events.HEADERS) - 1 == page_events.COL_ACTION
    assert page_events.HEADERS[page_events.COL_DISPOSITION] == "处置"


def test_monitor_shows_disposition_text():
    """实时监控的行文本也要给出处置结论（含「已放行」）"""
    from gui.page_monitor import COL_DISPOSITION, AccessTableModel

    _qapp()
    rec = AccessRecord(ip=IP, local_port=3000, disposition=DISPOSITION_ALLOW)
    assert AccessTableModel._cell_text(rec, COL_DISPOSITION) == "已放行"
    # 没判定过的记录不能硬编「已放行」
    assert AccessTableModel._cell_text(AccessRecord(ip=IP), COL_DISPOSITION) == "-"
    assert "处置结果：已放行" in AccessTableModel._tooltip(rec)
