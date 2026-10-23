"""操作审计测试（app/audit.py + core/database.py 的 audit_log 读写）

这里的每条断言都对应一次**变异验证**（改坏代码后对应用例必须变红），
具体做法写在每个用例的 docstring 里 —— 审计这种「不影响业务流程」的功能
最容易写出「永远绿」的测试：删掉埋点，业务测试一条都不红，只有这里会红。
"""

import datetime
from typing import Any, List

import pytest

from app import audit, ban_service
from core import database, firewall
from core.database import count_audit, init_db, query_audit
from core.models import (
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_UNBANNED,
    AccessRecord,
    BanRecord,
    RiskResult,
)
from core.pipeline import auto_ban_record

IP = "203.0.113.77"


def _boom(*_args, **_kwargs):
    raise RuntimeError("审计表不可用（模拟）")


@pytest.fixture(autouse=True)
def _schema(fresh_db):
    database.init_db()
    yield


@pytest.fixture
def admin(monkeypatch):
    monkeypatch.setattr(firewall, "is_admin", lambda: True)


@pytest.fixture
def fake_fw(monkeypatch):
    monkeypatch.setattr(
        firewall,
        "block_ip",
        lambda ip, duration=None, note="": (True, f"PortGuard_Block_{ip}_1_aa", ""),
    )
    monkeypatch.setattr(firewall, "unblock_ip", lambda ip, names=None, existing=None: (True, "", 1))
    monkeypatch.setattr(firewall, "unblock_all", lambda: (True, 1, ""))


@pytest.fixture
def as_user(monkeypatch):
    """把「本机交互者」钉成一个固定值，免得不同机器用户名不同导致用例飘"""
    monkeypatch.setenv("USERNAME", "alice")
    monkeypatch.delenv("USER", raising=False)
    return "alice"


def _last(action: str = "") -> dict:
    rows = query_audit(limit=10, action=action)
    assert rows, f"没有查到审计记录（action={action!r}）"
    return rows[0]


# ═══════════════════ actor 口径 ═══════════════════


def test_actor_local_reads_username(as_user):
    """变异：把 actor_local 改成读 USER 或写死常量 → 本例变红"""
    assert audit.actor_local() == "alice"


def test_actor_local_falls_back_when_username_missing(monkeypatch):
    monkeypatch.delenv("USERNAME", raising=False)
    monkeypatch.setenv("USER", "bob")
    assert audit.actor_local() == "bob"


def test_actor_http_keeps_prefix():
    """变异：actor_http 退化成裸 IP（丢前缀）→ 本例变红，且三种口径无法区分"""
    assert audit.actor_http("203.0.113.7") == "http:203.0.113.7"
    assert audit.actor_http("") == "http:unknown"


def test_actor_system_is_plain_word():
    assert audit.ACTOR_SYSTEM == "system"


# ═══════════════════ 写入 ═══════════════════


def test_record_writes_row_with_epoch_ms(as_user):
    """
    变异：把 ts 改成 `datetime('now','localtime')` 字符串 → 本例变红。

    全项目时间口径是 epoch 毫秒（event_ts / expire_at 都是），审计用字符串
    会让「某天下午发生了什么」这类区间查询退化成字符串比较，跨时区即错。
    """
    before = 1_600_000_000_000
    audit.record(audit.ACTION_BAN_MANUAL, target_type="ip", target_id=IP, summary="封禁测试")
    row = _last(audit.ACTION_BAN_MANUAL)
    assert isinstance(row["ts"], int)
    assert row["ts"] > before
    assert row["actor"] == "alice"
    assert row["target_type"] == "ip"
    assert row["target_id"] == IP
    assert row["result"] == audit.RESULT_OK


def test_record_never_raises(monkeypatch, as_user):
    """
    变异：把 record 里的 try/except 去掉 → 本例变红。

    审计写不进去绝不能反过来中断业务动作：防火墙规则已经加了、库状态已经改了，
    却因为审计表写不进去而回滚，等于把记账系统变成业务系统的单点故障。

    ⚠️ 必须打在 `app.audit.insert_audit` 上：app/audit.py 是
    `from core.database import insert_audit`（把函数对象绑进自己的命名空间），
    打 `core.database.insert_audit` 对 record() 无效，测试会假绿。
    """
    monkeypatch.setattr(audit, "insert_audit", _boom)
    assert audit.record(audit.ACTION_BAN_MANUAL, summary="x") == 0


def test_dumps_keeps_chinese_unescaped():
    """变异：去掉 ensure_ascii=False → 本例变红（中文全变 \\uXXXX，界面没法看）"""
    text = audit.dumps({"geo": "中国·广东·深圳", "rule": "黑名单命中"})
    assert text is not None
    assert "中国·广东·深圳" in text
    assert "\\u" not in text


def test_dumps_survives_datetime():
    """变异：去掉 default=str → 本例变红（datetime 直接抛 TypeError，整条记录丢失）"""
    text = audit.dumps({"t": datetime.datetime(2026, 10, 20, 15, 30, 0), "n": 1})
    assert text and "2026-10-20 15:30:00" in text


def test_dumps_none_is_none():
    assert audit.dumps(None) is None


# ═══════════════════ 埋点覆盖 ═══════════════════


def test_manual_ban_is_audited_with_local_user(isolated_env, admin, fake_fw, as_user):
    """变异：删掉 execute() 里的 audit.record → 本例变红"""
    ban_id, err = ban_service.execute(IP, 95, "扫端口", 60)
    assert ban_id and err == ""
    row = _last(audit.ACTION_BAN_MANUAL)
    assert row["actor"] == "alice"
    assert row["target_id"] == str(ban_id)
    assert row["result"] == audit.RESULT_OK


def test_ban_failure_is_audited_as_fail(isolated_env, admin, monkeypatch, as_user):
    """封禁失败时 result 必须是 fail —— 只看「有人点过」会得出错误结论"""
    monkeypatch.setattr(firewall, "block_ip", lambda *a, **k: (False, "", "Access denied"))
    ban_service.execute(IP, 95, "扫端口", 60)
    row = _last(audit.ACTION_BAN_MANUAL)
    assert row["result"] == audit.RESULT_FAIL


def test_duplicate_ban_is_audited_as_skipped(isolated_env, admin, fake_fw, as_user):
    ban_service.execute(IP, 95, "x", 60)
    ban_service.execute(IP, 95, "x", 60)
    rows = [r for r in query_audit(limit=50) if r["result"] == audit.RESULT_SKIP]
    assert rows, "重复封禁应该记一条 skipped 而不是静默返回"


def test_auto_ban_is_audited_with_http_actor(isolated_env, monkeypatch):
    """
    变异：删掉 auto_ban_record 里的埋点，或把 actor 写死成 system → 本例变红。

    「哪个业务系统让我们封的」只能靠 actor 回答，写死成 system 就永远查不到。
    """
    monkeypatch.setattr(firewall, "block_ip", lambda ip, d=None, note="": (True, f"PG_{ip}", ""))
    auto_ban_record(
        AccessRecord(ip=IP, local_port=18080),
        RiskResult(score=95, level="high", matched_rules=["scan"], suggest_ban=True),
        actor=audit.actor_http("203.0.113.7"),
    )
    row = _last(audit.ACTION_BAN_AUTO)
    assert row["actor"] == "http:203.0.113.7"


def test_auto_ban_defaults_to_system(isolated_env, monkeypatch):
    """本机采集路径不传 actor 时按 system 记（不是当前登录用户名）"""
    monkeypatch.setattr(firewall, "block_ip", lambda ip, d=None, note="": (True, f"PG_{ip}", ""))
    auto_ban_record(
        AccessRecord(ip=IP, local_port=18080),
        RiskResult(score=95, level="high", matched_rules=["scan"], suggest_ban=True),
    )
    assert _last(audit.ACTION_BAN_AUTO)["actor"] == "system"


def test_unban_audits_and_fills_unblocked_by(isolated_env, admin, fake_fw, as_user):
    """
    变异：unban() 里退回 update_ban(ban.id, status='unbanned')（不填 unblocked_by）
    → 本例变红。unblocked_by 是 v2 就加好、此前零写入点的列。
    """
    ban_id, _ = ban_service.execute(IP, 95, "x", 60)
    rec = database.find_active_ban_by_ip(IP)
    assert rec is not None and rec.id == ban_id
    ok, err = ban_service.unban(rec)
    assert ok and err == ""

    row = _last(audit.ACTION_BAN_UNBAN)
    assert row["actor"] == "alice"
    after = database.query_bans(limit=10)[0]
    assert after.unblocked_by == "alice"


def test_check_expired_fills_unblocked_by_system(isolated_env, admin, fake_fw):
    """到期巡检是程序自己干的，unblocked_by 必须记 system 而不是某个用户"""
    ban_id, _ = ban_service.execute(IP, 95, "x", 60)
    database.update_ban(ban_id, status=STATUS_ACTIVE, expire_at=1)
    done = ban_service.check_expired()
    assert len(done) == 1
    row = database.query_bans(limit=10, status=STATUS_EXPIRED)
    assert row and row[0].unblocked_by == "system"
    assert _last(audit.ACTION_BAN_EXPIRE)["actor"] == "system"


def test_settings_save_uses_local_user(as_user):
    """设置保存的埋点在 gui 层，这里钉的是「不传 actor 时落到本机用户」这条口径"""
    audit.record(audit.ACTION_SETTINGS_SAVE, target_type="setting", summary="保存设置")
    assert _last(audit.ACTION_SETTINGS_SAVE)["actor"] == "alice"


# ═══════════════════ 查询 / 分页 ═══════════════════


def test_query_audit_filters_by_actor_and_action(as_user):
    """变异：_audit_where 漏掉 actor 条件 → 本例变红"""
    audit.record(audit.ACTION_BAN_MANUAL, summary="a")
    audit.record(audit.ACTION_RULES_SAVE, summary="b")
    audit.record(audit.ACTION_BAN_MANUAL, actor=audit.ACTOR_SYSTEM, summary="c")

    assert len(query_audit(limit=50, actor="alice")) == 2
    assert len(query_audit(limit=50, actor=audit.ACTOR_SYSTEM)) == 1
    assert len(query_audit(limit=50, action=audit.ACTION_RULES_SAVE)) == 1
    assert len(query_audit(limit=50, actor="alice", action=audit.ACTION_BAN_MANUAL)) == 1


def test_query_audit_keyword_matches_summary(as_user):
    audit.record(audit.ACTION_BAN_MANUAL, summary="封禁 203.0.113.77")
    audit.record(audit.ACTION_BAN_MANUAL, summary="保存规则")
    assert len(query_audit(limit=50, keyword="203.0.113.77")) == 1


def test_query_audit_newest_first(as_user):
    for i in range(5):
        audit.record(audit.ACTION_BAN_MANUAL, summary=f"第 {i} 条")
    rows = query_audit(limit=50)
    assert [r["summary"] for r in rows] == [f"第 {i} 条" for i in (4, 3, 2, 1, 0)]


def test_count_audit_matches_query(as_user):
    """分页的前提：count 与 query 必须**同条件**，否则末页会空"""
    for i in range(7):
        audit.record(audit.ACTION_BAN_MANUAL, summary=f"s{i}")
    assert count_audit() == 7
    assert count_audit(action=audit.ACTION_BAN_MANUAL) == 7
    assert count_audit(action=audit.ACTION_RULES_SAVE) == 0
    assert len(query_audit(limit=3, offset=6)) == 1


def test_query_audit_paginates(as_user):
    for i in range(5):
        audit.record(audit.ACTION_BAN_MANUAL, summary=f"s{i}")
    p1 = query_audit(limit=2, offset=0)
    p2 = query_audit(limit=2, offset=2)
    assert [r["summary"] for r in p1] == ["s4", "s3"]
    assert [r["summary"] for r in p2] == ["s2", "s1"]


def test_list_audit_actors_dedups(as_user):
    audit.record(audit.ACTION_BAN_MANUAL, actor="alice", summary="a")
    audit.record(audit.ACTION_BAN_MANUAL, actor="alice", summary="b")
    audit.record(audit.ACTION_BAN_MANUAL, actor=audit.ACTOR_SYSTEM, summary="c")
    actors = database.list_audit_actors()
    assert "alice" in actors
    assert audit.ACTOR_SYSTEM in actors
    assert len([a for a in actors if a == "alice"]) == 1


# ═══════════════════ 迁移 / 展示 ═══════════════════


def test_schema_version_is_five():
    """版本闸门：升版时必须把这里的期望值一起改掉。

    变异：把 SCHEMA_VERSION 改回 4 → 本例变红（v5 的
    `ban_list.hit_count` / `last_hit_at` 不会被执行，拦截次数永远落不了库）。
    """
    from core.migrations import SCHEMA_VERSION

    assert SCHEMA_VERSION == 5


def test_v3_creates_audit_table_and_covering_index():
    """变异：从 MIGRATIONS[3] 里删掉任一条 → 本例变红"""
    init_db()
    conn = database._connect()
    try:
        tables = {
            r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        indexes = {
            r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
        }
    finally:
        conn.close()
    assert "audit_log" in tables
    assert "idx_audit_ts" in indexes
    assert "idx_audit_actor" in indexes
    assert "idx_audit_act" in indexes
    # P2-6 的覆盖索引：count_risk_unhandled 每 2 秒全表 COUNT，靠它免扫表
    assert "idx_event_handled_id" in indexes


def test_fmt_ts_and_snapshot(as_user):
    assert audit.fmt_ts(0) == ""
    assert audit.fmt_ts(None) == ""
    text = audit.fmt_ts(1_700_000_000_000)
    assert len(text) == 19 and text[4] == "-"
    assert audit.fmt_snapshot(None) == "-"
    assert audit.fmt_snapshot("短") == "短"
    assert audit.fmt_snapshot("x" * 500).endswith("…")


def test_action_labels_cover_all_actions():
    """新增 action 必须同时登记中文名，否则界面下拉框会出现空白项"""
    for act in audit.ACTIONS:
        assert audit.ACTION_LABELS.get(act)
        assert audit.action_label(act) != act


# ═══════════════════ 回归：审计不影响业务 ═══════════════════


def test_ban_still_works_when_audit_table_broken(isolated_env, admin, fake_fw, monkeypatch):
    """
    审计表不可用时封禁必须照常成功 —— 这是「审计绝不能成为单点故障」的硬验证。
    变异：把 record 的异常吞掉逻辑删掉 → 本例变红。
    """
    monkeypatch.setattr(audit, "insert_audit", _boom)
    ban_id, err = ban_service.execute(IP, 95, "x", 60)
    assert ban_id is not None
    assert err == ""
    assert database.query_bans(limit=10)[0].status == STATUS_ACTIVE


def test_ban_record_has_unblocked_by_field():
    """BanRecord 必须带 unblocked_by，否则 _row_to_ban 取出来会丢"""
    rec = BanRecord(ip=IP, unblocked_by="alice")
    assert rec.unblocked_by == "alice"
    assert BanRecord(ip=IP).unblocked_by == ""


# ═══════════════════ GUI 手工操作的埋点 ═══════════════════
#
# 事件页 / 封禁页 / 主窗口这三处是「人点出来的」破坏性动作，也是审计最该覆盖
# 的地方 —— 但它们写在 Qt 页面里。这里沿用 tests/test_about_dialog.py 的思路：
# **不构造真页面**（会拖进表格、定时器、8 个 tab），而是把方法当普通函数调用，
# 用一个只提供「方法体真正用到的那几个属性」的替身宿主。断言的是「动作发生后
# 审计真的落库」以及「审计炸了不影响主流程」，不是界面长什么样。
#
# ⚠️ QMessageBox 用**替换模块内名字**的方式打桩（`monkeypatch.setattr` 到
# `gui.page_events.QMessageBox`），不是给 Qt 类挂属性 —— PySide2/PySide6 的
# wrapper 类型都可能拒绝外部赋值，那样用例会在有的栈上直接报 AttributeError。


def _call(fn: Any, host: Any, *args: Any) -> Any:
    """
    把页面方法当普通函数调（不构造真页面）。

    签名上 `EventsPage._set_handled(self, ...)` 的 self 是 EventsPage，
    而这里传的是替身宿主，所以对 mypy 走 Any 通道 —— 与
    tests/test_about_dialog.py 里 `_BUILD_SIDEBAR: Any = MainWindow._build_sidebar`
    是同一个手法，理由也相同。
    """
    return fn(host, *args)


class _Lbl:
    """替身 QLabel：只需要 setText"""

    def __init__(self) -> None:
        self.text = ""

    def setText(self, text: str) -> None:
        self.text = str(text)


class _Sig:
    """替身 Signal：只需要 emit"""

    def __init__(self) -> None:
        self.n = 0

    def emit(self) -> None:
        self.n += 1


class _Btn:
    """
    替身 StandardButton 的单个按钮。

    必须支持 `Yes | No` 这种写法 —— 真代码是用位或拼按钮组合的，
    所以 `__or__` 返回自身（组合后的「结果」在替身里没有意义，
    真正决定分支的是 `question()` 的返回值）。
    """

    def __or__(self, _other):
        return self


class _StdBtn:
    Yes = _Btn()
    No = _Btn()


class _FakeMsgBox:
    """替身 QMessageBox：一律回答「是」，并把弹过的框记下来"""

    StandardButton = _StdBtn
    calls: List[str]

    def __init__(self) -> None:
        self.calls = []

    def question(self, *_a, **_k):
        self.calls.append("question")
        return _StdBtn.Yes

    def information(self, *_a, **_k):
        self.calls.append("information")

    def warning(self, *_a, **_k):
        self.calls.append("warning")


@pytest.fixture
def msgbox(monkeypatch):
    """
    把三个页面模块里的 `QMessageBox` 名字换掉。

    只换模块内的名字、不动 Qt 类本身：PySide 的 wrapper 类型在有的版本上
    拒绝外部赋值，直接给 `QMessageBox.question` 打桩会变成另一种「有的栈红」。
    """
    box = _FakeMsgBox()
    from gui import main_window, page_bans, page_events

    monkeypatch.setattr(page_events, "QMessageBox", box)
    monkeypatch.setattr(page_bans, "QMessageBox", box)
    monkeypatch.setattr(main_window, "QMessageBox", box)
    return box


def _event_row(rid: int, ip: str = IP, handled: int = 0) -> dict:
    return {
        "id": rid,
        "ip": ip,
        "handled": handled,
        "risk_level": "high",
        "risk_score": 95,
        "summary": "扫端口",
    }


def test_handled_action_maps_confirm_and_ignore():
    """变异：把两个 action 写成同一个 → 本例变红（确认/忽略在审计里就分不开了）"""
    from gui.page_events import _handled_action

    assert _handled_action(1) == audit.ACTION_EVENT_CONFIRM
    assert _handled_action(2) == audit.ACTION_EVENT_IGNORE


def test_event_snapshot_keeps_key_fields():
    """变异：快照只留 id → 本例变红（事后答不出「删了哪些 IP」）"""
    from gui.page_events import _event_snapshot

    snap = _event_snapshot([_event_row(7)])
    assert snap == [
        {"id": 7, "ip": IP, "handled": 0, "level": "high", "score": 95},
    ]


def test_single_event_confirm_is_audited(isolated_env, msgbox, as_user):
    """
    变异：删掉 `_set_handled` 里的 audit.record → 本例变红。
    事件页此前是「直接改库、什么都不留」，这是最典型的一条。
    """
    from gui.page_events import EventsPage

    rid = database.insert_risk_event(
        AccessRecord(ip=IP, local_port=18080),
        RiskResult(score=95, level="high", matched_rules=["scan"], suggest_ban=True),
    )

    class _Host:
        def refresh(self) -> None:
            pass

    _call(EventsPage._set_handled, _Host(), _event_row(rid), 1)

    row = _last(audit.ACTION_EVENT_CONFIRM)
    assert row["target_id"] == str(rid)
    assert row["actor"] == "alice"
    assert '"handled": 0' in (row["before_json"] or "")


def test_single_event_ignore_is_audited(isolated_env, msgbox):
    from gui.page_events import EventsPage

    class _Host:
        def refresh(self) -> None:
            pass

    _call(EventsPage._set_handled, _Host(), _event_row(3), 2)
    assert _last(audit.ACTION_EVENT_IGNORE)["target_id"] == "3"


def test_batch_event_confirm_is_audited_with_before_state(isolated_env, msgbox):
    """
    变异：before 只记条数不记原状态 → 本例变红。
    确认/忽略可以来回切，只记条数的话事后判断不出「这条是被确认过还是改回来过」。
    """
    from gui.page_events import EventsPage

    rows = [_event_row(11, "203.0.113.1"), _event_row(12, "203.0.113.2", handled=2)]

    class _Host:
        _rows = rows
        lbl_info = _Lbl()

        def _checked_rows(self):
            return rows

        def refresh(self) -> None:
            pass

    _call(EventsPage._batch_handled, _Host(), 1)
    row = _last(audit.ACTION_EVENT_CONFIRM)
    assert '"id": 12' in (row["before_json"] or "")
    assert '"handled": 2' in (row["before_json"] or ""), "已被忽略的记录改确认，原状态必须留档"


def test_batch_event_delete_is_audited_with_full_snapshot(isolated_env, msgbox):
    """变异：删掉 `_batch_delete` 里的 audit.record → 本例变红（删除不可逆）"""
    from gui.page_events import EventsPage

    rid = database.insert_risk_event(
        AccessRecord(ip=IP, local_port=18080),
        RiskResult(score=95, level="high", matched_rules=["scan"], suggest_ban=True),
    )
    rows = [_event_row(rid)]

    class _Host:
        _rows = rows
        lbl_info = _Lbl()

        def _checked_rows(self):
            return rows

        def refresh(self) -> None:
            pass

    _call(EventsPage._batch_delete, _Host())
    row = _last(audit.ACTION_EVENT_DELETE)
    before = row["before_json"] or ""
    assert str(rid) in before
    assert IP in before
    assert "handled" in before


def test_batch_ban_delete_is_audited_with_full_snapshot(isolated_env, msgbox):
    """
    变异：删掉 `_batch_delete_bans` 里的 audit.record → 本例变红。

    封禁记录是「记账」：删掉之后「这个 IP 曾经被封过、当时是什么状态」就再也
    查不到了，而防火墙规则还在（本操作不改规则）—— 更需要这条审计来解释规则来源。
    """
    from gui.page_bans import BansPage

    ban_id = database.insert_ban(
        BanRecord(ip=IP, status=STATUS_UNBANNED, source="manual", rule_name="PG_x")
    )
    rows = [b for b in database.query_bans(limit=10) if b.id == ban_id]

    class _Host:
        _ban_rows = rows
        lbl_info = _Lbl()
        request_refresh_stats = _Sig()

        def _checked_bans(self):
            return rows

        def refresh(self) -> None:
            pass

    _call(BansPage._batch_delete_bans, _Host())
    row = _last(audit.ACTION_BAN_DELETE)
    before = row["before_json"] or ""
    assert str(ban_id) in before
    assert IP in before
    assert STATUS_UNBANNED in before
    assert "PG_x" in before
    # 前提校验：真的删掉了，否则这条审计可能只是「记了一笔没发生的删除」
    assert database.query_bans(limit=10) == []


def test_add_blacklist_is_audited(isolated_env, msgbox, monkeypatch, as_user):
    """
    变异：删掉 `_add_blacklist` 里的 audit.record → 本例变红。

    这是「右键顺手加黑」的捷径，与规则页文本框保存是两条路径；不记就会有
    「这个 IP 什么时候被谁拉黑的」查不到的空档。
    """
    from gui import main_window

    class _Set(set):
        def add(self, x):
            super().add(x)

    class _Eng:
        def __init__(self):
            self.blacklist = _Set()
            self.whitelist = _Set()
            self.saved = 0

        def save_lists(self):
            self.saved += 1

    eng = _Eng()
    monkeypatch.setattr(main_window, "get_engine", lambda: eng)

    class _PageRules:
        def reload(self):
            pass

    class _Host:
        page_rules = _PageRules()

        def _set_status(self, *_a, **_k):
            pass

        def _sync_blacklist_bans(self, *_a, **_k):
            # 加黑后要联动防火墙封禁（后台线程）；本用例只验审计，把这一步短路
            pass

    _call(main_window.MainWindow._add_blacklist, _Host(), IP)

    assert eng.saved == 1
    row = _last(audit.ACTION_LIST_SAVE)
    assert row["actor"] == "alice"
    assert row["target_type"] == "blacklist"
    assert row["target_id"] == IP


def test_add_blacklist_triggers_firewall_sync(isolated_env, msgbox, monkeypatch, as_user):
    """加入黑名单必须**立刻**写防火墙 —— 只进名单不拦截等于没拦。"""
    from gui import main_window

    class _Set(set):
        def add(self, x):
            super().add(x)

    class _Eng:
        def __init__(self):
            self.blacklist = _Set()
            self.whitelist = _Set()

        def save_lists(self):
            pass

    monkeypatch.setattr(main_window, "get_engine", _Eng)

    class _PageRules:
        def reload(self):
            pass

    seen = {}

    class _Host:
        page_rules = _PageRules()

        def _set_status(self, *_a, **_k):
            pass

        def _sync_blacklist_bans(self, added, removed):
            seen["added"] = list(added)
            seen["removed"] = list(removed)

    _call(main_window.MainWindow._add_blacklist, _Host(), IP)
    assert seen.get("added") == [IP], "加入黑名单后没有触发防火墙封禁"
    assert seen.get("removed") == []


def test_gui_audit_failure_does_not_break_ban_delete(isolated_env, msgbox, monkeypatch):
    """
    变异：把 `audit.record` 的 try/except 去掉 → 本例会抛异常、删除流程中断。

    ⚠️ 打的是 `app.audit.insert_audit`（record 真正调用的那个名字）。
    打 `core.database.insert_audit` 对 record() 无效，测试会假绿。
    """
    from gui.page_bans import BansPage

    ban_id = database.insert_ban(BanRecord(ip=IP, status=STATUS_UNBANNED))
    rows = [b for b in database.query_bans(limit=10) if b.id == ban_id]
    monkeypatch.setattr(audit, "insert_audit", _boom)

    class _Host:
        _ban_rows = rows
        lbl_info = _Lbl()
        request_refresh_stats = _Sig()

        def _checked_bans(self):
            return rows

        def refresh(self) -> None:
            pass

    _call(BansPage._batch_delete_bans, _Host())  # 不抛异常
    assert database.query_bans(limit=10) == [], "审计写失败不能让删除半途而废"


def test_new_gui_actions_are_registered():
    """新增 action 必须进 ACTION_LABELS，否则审计 tab 的下拉框里选不到"""
    for act in (
        audit.ACTION_EVENT_CONFIRM,
        audit.ACTION_EVENT_IGNORE,
        audit.ACTION_EVENT_DELETE,
        audit.ACTION_BAN_DELETE,
        audit.ACTION_LIST_SAVE,
    ):
        assert act in audit.ACTION_LABELS
        assert act in audit.ACTIONS
