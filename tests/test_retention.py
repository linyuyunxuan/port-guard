"""保留期清理测试（P2-5：risk_event / ban_list / audit_log 三张表的清理覆盖）

每条断言都标注了对应的**变异验证**：改坏哪一行、哪个用例会红。
这三张表此前根本没有清理入口，测的是「补齐」而不是「改动」，所以最容易
犯的错是写出永远绿的断言（比如只断言「删了点东西」而不管删的是不是该删的）。
"""

import datetime

import pytest

from app import maintenance
from core import database
from core import settings as cfg
from core.config import (
    DEFAULT_AUDIT_RETENTION_DAYS,
    DEFAULT_BAN_RETENTION_DAYS,
    DEFAULT_LOG_RETENTION_DAYS,
    DEFAULT_RISK_RETENTION_DAYS,
    DEFAULT_SETTINGS,
)
from core.database import (
    CLEANABLE_BAN_STATUS,
    delete_old_audit,
    delete_old_bans,
    delete_old_risk_events,
    init_db,
    insert_access_log,
    insert_ban,
    insert_risk_event,
)
from core.models import (
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_UNBANNED,
    AccessRecord,
    BanRecord,
    RiskResult,
    now_ms,
)

IP = "203.0.113.77"
DAY_MS = 86_400_000


@pytest.fixture(autouse=True)
def _schema(fresh_db):
    database.init_db()
    yield


# ── 造数据 ──


def _risk(days_ago: int, ip: str = IP) -> int:
    """插一条 `days_ago` 天前的风险事件"""
    return insert_risk_event(
        AccessRecord(ip=ip, event_ts=now_ms() - days_ago * DAY_MS, local_port=18080),
        RiskResult(score=95, level="high", matched_rules=["scan"], suggest_ban=True),
    )


def _access(days_ago: int, ip: str = IP) -> int:
    return insert_access_log(AccessRecord(ip=ip, event_ts=now_ms() - days_ago * DAY_MS))


def _ban(status: str, days_ago: int, ip: str = IP) -> int:
    """
    插一条 `days_ago` 天前的封禁记录。

    `created_at` 由 insert_ban 用 `datetime('now','localtime')` 生成且不在
    `_BAN_UPDATABLE` 白名单里，所以只能直接改库回拨 —— 这也正好逼着
    `delete_old_bans` 必须按**字符串**比较（见 test_delete_old_bans_uses_string_time）。
    """
    ban_id = insert_ban(BanRecord(ip=ip, status=status, reason="t", risk_score=90))
    old = (datetime.datetime.now() - datetime.timedelta(days=days_ago)).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    conn = database._connect()
    try:
        conn.execute("UPDATE ban_list SET created_at = ? WHERE id = ?", (old, ban_id))
        conn.commit()
    finally:
        conn.close()
    return ban_id


def _audit(days_ago: int) -> int:
    """
    插一条 `days_ago` 天前的审计记录。

    直接用 `insert_audit` 而不是 `audit.record()`：后者永远写「现在」，
    造不出过期数据。审计的 ts 本来就是 epoch 毫秒，直接给即可。
    """
    return database.insert_audit(
        ts=now_ms() - days_ago * DAY_MS,
        actor="alice",
        action="ban.manual",
        target_type="ip",
        target_id=IP,
        summary=f"{days_ago} 天前",
    )


def _ban_ids(status: str = "") -> list:
    rows = database.query_bans(limit=1000, status=status)
    return [r.id for r in rows]


def _risk_count() -> int:
    return len(database.query_risk_events(limit=1000))


def _audit_count() -> int:
    from core.database import count_audit

    return count_audit()


# ═══════════════════ risk_event：保留期必须独立 ═══════════════════


def test_risk_retention_is_independent_of_log_retention(isolated_env):
    """
    变异：让 delete_old_risk_events 复用 log_retention_days(30) → 本例变红。

    事件是规则算出的结论，流水是原始事实。共用 30 天的话「这台机器三个月前
    被判过严重风险」会比流水更早消失，事件页未处理计数还会某天突然掉一大截。
    """
    cfg.set("log_retention_days", "30")
    cfg.set("risk_retention_days", "90")
    _risk(45)  # 超过流水保留期、但没超过事件保留期 → 必须留下
    _risk(100)  # 两个都超 → 删掉

    assert delete_old_risk_events(90) == 1
    assert _risk_count() == 1


def test_cleanup_risk_reads_its_own_setting(isolated_env):
    """
    变异：cleanup_risk() 读 log_retention_days → 本例变红。
    这里故意把 log_retention_days 设成 365：一旦读错键，一条都删不掉。
    """
    cfg.set("log_retention_days", "365")
    cfg.set("risk_retention_days", "7")
    _risk(2)
    _risk(30)
    assert maintenance.cleanup_risk() == 1
    assert _risk_count() == 1


def test_delete_old_risk_events_zero_days_is_noop(isolated_env):
    """days<=0 必须一条不删 —— 界面上限是 1，但配置被手改成 0 时不能清库"""
    _risk(999)
    assert delete_old_risk_events(0) == 0
    assert _risk_count() == 1


# ═══════════════════ ban_list：只清终态 ═══════════════════


def test_active_and_pending_bans_are_never_cleaned(isolated_env):
    """
    变异：把 active 或 pending 加进 CLEANABLE_BAN_STATUS → 本例变红。

    · active 背后是一条真实存在的防火墙规则，删记账会让规则变无主
      （既不会被到期巡检解封，也不会出现在「已封禁」列表里）；
    · pending 是「插库 → 调防火墙 → 回填」之间的瞬态，进程被杀就会残留，
      清掉它等于替用户做「这次封禁没发生过」的决定。
    """
    active = _ban(STATUS_ACTIVE, 400)
    pending = _ban(STATUS_PENDING, 400)
    assert delete_old_bans(180) == 0
    left = _ban_ids()
    assert active in left
    assert pending in left


def test_terminal_bans_are_cleaned(isolated_env):
    """变异：CLEANABLE_BAN_STATUS 漏掉 expired / failed → 本例变红"""
    _ban(STATUS_UNBANNED, 400)
    _ban(STATUS_EXPIRED, 400)
    _ban(STATUS_FAILED, 400)
    _ban(STATUS_ACTIVE, 400)  # 对照：不该被删
    assert delete_old_bans(180) == 3
    assert len(_ban_ids()) == 1


def test_fresh_bans_survive_regardless_of_status(isolated_env):
    """没到期的终态记录也不能删 —— 保留期是「至少留这么久」不是「到期就删」"""
    _ban(STATUS_UNBANNED, 10)
    _ban(STATUS_EXPIRED, 10)
    assert delete_old_bans(180) == 0


def test_delete_old_bans_uses_string_time_column(isolated_env):
    """
    变异：把 `datetime(created_at) < datetime('now','localtime',?)` 改成
    `created_at < <epoch 毫秒>` → 本例变红（字符串与整数比较，SQLite 里
    类型亲和性会让两边都不成立，一条都删不掉）。

    这是 ban_list 的历史包袱：全项目时间是 epoch 毫秒，唯独 created_at 是
    `YYYY-MM-DD HH:MM:SS` 字符串。改表结构要另开一次迁移。
    """
    _ban(STATUS_UNBANNED, 400)
    assert delete_old_bans(180) == 1


def test_delete_old_bans_zero_days_is_noop(isolated_env):
    _ban(STATUS_UNBANNED, 9999)
    assert delete_old_bans(0) == 0
    assert len(_ban_ids()) == 1


def test_cleanable_status_excludes_active_and_pending():
    """白名单而不是黑名单：将来新增状态默认**不被清理**，只影响库大小不影响安全"""
    assert STATUS_ACTIVE not in CLEANABLE_BAN_STATUS
    assert STATUS_PENDING not in CLEANABLE_BAN_STATUS
    assert {STATUS_UNBANNED, STATUS_EXPIRED, STATUS_FAILED} <= set(CLEANABLE_BAN_STATUS)


# ═══════════════════ audit_log ═══════════════════


def test_audit_has_its_own_retention(isolated_env):
    """
    变异：不给 audit_log 保留期 → 审计表自己变成新的无界增长表。
    本例钉住「审计能被清理」这件事本身。
    """
    _audit(0)
    _audit(400)
    assert delete_old_audit(180) == 1
    assert _audit_count() == 1


def test_delete_old_audit_zero_days_is_noop(isolated_env):
    _audit(400)
    assert delete_old_audit(0) == 0


def test_cleanup_audit_reads_its_own_setting(isolated_env):
    cfg.set("audit_retention_days", "7")
    _audit(2)
    _audit(30)
    assert maintenance.cleanup_audit() == 1


# ═══════════════════ run_all 编排 ═══════════════════


def test_run_all_covers_four_tables(isolated_env):
    """
    变异：run_all 少调一个 cleanup_* → 本例变红（且线上没有任何别的机制兜底，
    漏掉的那张表就永远不会被清理）。
    """
    cfg.set("log_retention_days", "30")
    cfg.set("risk_retention_days", "90")
    cfg.set("ban_retention_days", "180")
    cfg.set("audit_retention_days", "180")
    _access(400)
    _risk(400)
    _ban(STATUS_UNBANNED, 400)
    _audit(400)

    rows, risk, bans, audits, _files, _bak, _tmp = maintenance.run_all()
    assert rows == 1
    assert risk == 1
    assert bans == 1
    assert audits == 1


def test_run_all_returns_seven_counts(isolated_env):
    """返回值长度与字段顺序：`gui/mixins._cleanup_logs` 直接按位置解包"""
    assert len(maintenance.RUN_ALL_FIELDS) == 7
    assert maintenance.RUN_ALL_FIELDS[0] == "访问记录"
    assert maintenance.RUN_ALL_FIELDS[3] == "审计记录"
    assert len(maintenance.run_all()) == 7


def test_run_all_leaves_active_bans_alone(isolated_env):
    """编排层也要满足「active 不清理」—— 单独测过还不够"""
    cfg.set("ban_retention_days", "180")
    active = _ban(STATUS_ACTIVE, 400)
    _ban(STATUS_EXPIRED, 400)
    _rows, _risk, bans, _audits, _f, _b, _t = maintenance.run_all()
    assert bans == 1
    assert active in _ban_ids()


# ═══════════════════ 默认值 ═══════════════════


def test_default_settings_have_all_four_retention_keys():
    """变异：只加函数不加配置键 → 界面读不到，设置页永远显示默认值"""
    for key in (
        "log_retention_days",
        "risk_retention_days",
        "ban_retention_days",
        "audit_retention_days",
    ):
        assert key in DEFAULT_SETTINGS


def test_retention_defaults_are_not_uniform():
    """
    变异：把四个默认保留期合并成同一个值 → 本例变红。

    这是本批次最容易被「顺手简化」掉的一条：四个数看着像重复配置，
    实际对应四件不同的事（原始流水 / 派生结论 / 封禁账本 / 审计留痕）。
    """
    values = {
        DEFAULT_LOG_RETENTION_DAYS,
        DEFAULT_RISK_RETENTION_DAYS,
        DEFAULT_BAN_RETENTION_DAYS,
        DEFAULT_AUDIT_RETENTION_DAYS,
    }
    assert len(values) >= 3, f"保留期被合并了：{values}"
    assert DEFAULT_RISK_RETENTION_DAYS > DEFAULT_LOG_RETENTION_DAYS
    assert DEFAULT_BAN_RETENTION_DAYS > DEFAULT_RISK_RETENTION_DAYS


def test_settings_roundtrip_for_new_keys(isolated_env):
    init_db()
    cfg.set("risk_retention_days", "7")
    cfg.set("ban_retention_days", "14")
    cfg.set("audit_retention_days", "21")
    assert cfg.get_int("risk_retention_days", 90) == 7
    assert cfg.get_int("ban_retention_days", 180) == 14
    assert cfg.get_int("audit_retention_days", 180) == 21
