"""操作审计测试（app/audit.py + core/database.py 的 audit_log 读写）

这里的每条断言都对应一次**变异验证**（改坏代码后对应用例必须变红），
具体做法写在每个用例的 docstring 里 —— 审计这种「不影响业务流程」的功能
最容易写出「永远绿」的测试：删掉埋点，业务测试一条都不红，只有这里会红。
"""

import datetime

import pytest

from app import audit, ban_service
from core import database, firewall
from core.database import count_audit, init_db, query_audit
from core.models import STATUS_ACTIVE, STATUS_EXPIRED, AccessRecord, BanRecord, RiskResult
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
    monkeypatch.setattr(firewall, "unblock_ip", lambda ip, names=None: (True, "", 1))
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


def test_schema_version_is_three():
    """变异：把 SCHEMA_VERSION 改回 2 → 本例变红（v3 内容不会被执行）"""
    from core.migrations import SCHEMA_VERSION

    assert SCHEMA_VERSION == 3


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
