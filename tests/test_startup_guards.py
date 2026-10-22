"""上线前补的四根钉子：每日自动备份 / 残留 pending 收敛 / CLI 跨进程互斥

对应评测报告的第二批（S7 / S8 / S9），逐条钉住：

1. **每日维护必须真的产出备份**，且备份失败不能反过来把清理结果丢掉
   （报告 F3：备份一直只能手动点，磁盘故障时没有退路）；
2. **残留 pending 必须按「防火墙里规则是否真的存在」回填**，不能按时间一刀切
   —— 判反了要么让规则永久生效，要么把「没拦住」写成「封禁中」；
3. **`--enable-firewall` 必须在拿到单实例互斥之后才执行**（原来它在
   `acquire()` 之前就 return 了，CLI 与界面可同时改防火墙）。

每条都问过「改回错的行为什么会红」：
· 把 `run_daily` 里的 backup 删掉 → `test_run_daily_backs_up...` 红；
· 备份失败时抛异常 → `test_run_daily_...failure...` 红；
· 收敛时按「超时即失败」一刀切 → `test_recover_keeps_rule_that_exists` 红；
· 非管理员也去改记录 → `test_recover_skips_without_admin` 红；
· CLI 在 acquire 之前执行 → `test_cli_waits_for_single_instance` 红。
"""

from typing import Any, List

import pytest

import main as main_mod
from app import ban_service, maintenance
from core import database, firewall
from core.models import STATUS_ACTIVE, STATUS_FAILED, STATUS_PENDING, BanRecord, now_ms

IP = "203.0.113.90"


@pytest.fixture
def admin(monkeypatch):
    monkeypatch.setattr(firewall, "is_admin", lambda: True)


# ═══════════════════ S8：每日自动备份 ═══════════════════


def test_run_daily_backs_up_after_cleanup(isolated_env, monkeypatch):
    """清理 + 备份都要发生，且**备份在清理之后**（否则每天白拷一遍待删数据）"""
    order: List[str] = []

    def fake_cleanup() -> Any:
        order.append("cleanup")
        return (1, 2, 3, 4, 5, 6, 7)

    def fake_backup() -> Any:
        order.append("backup")
        return True, "C:/bak/x.bak"

    def fake_rotate() -> Any:
        order.append("rotate")
        return 0

    monkeypatch.setattr(maintenance, "run_all", fake_cleanup)
    monkeypatch.setattr(maintenance, "backup_db", fake_backup)
    monkeypatch.setattr(maintenance, "cleanup_db_backups", fake_rotate)

    counts, ok, detail = maintenance.run_daily()

    assert order == ["cleanup", "backup", "rotate"]
    assert counts == (1, 2, 3, 4, 5, 6, 7)
    assert ok is True and detail.endswith("x.bak")


def test_run_daily_survives_backup_failure(isolated_env, monkeypatch):
    """备份失败只上报，不抛异常、不撤掉清理结果 —— 清理已经提交，回滚不了"""
    rotated: List[int] = []

    def fake_rotate() -> int:
        rotated.append(1)
        return 0

    monkeypatch.setattr(maintenance, "run_all", lambda: (0, 0, 0, 0, 0, 0, 0))
    monkeypatch.setattr(maintenance, "backup_db", lambda: (False, "磁盘已满"))
    monkeypatch.setattr(maintenance, "cleanup_db_backups", fake_rotate)

    counts, ok, detail = maintenance.run_daily()

    assert counts == (0, 0, 0, 0, 0, 0, 0)
    assert ok is False
    assert "磁盘已满" in detail
    assert rotated == [], "备份没成功就不该轮转（不然会把唯一的老备份删掉）"


# ═══════════════════ S7：残留 pending 收敛 ═══════════════════


def _pending(ip: str, rule: str, created_at: str) -> int:
    """造一条 pending 记录并把 created_at 改到指定时刻。

    `insert_ban` 不写 created_at（列默认 `datetime('now','localtime')`），
    而 `update_ban` 的白名单里没有它（状态列不许随便改），只能直接改库 ——
    这正是要复现的现场：记录是**上次进程留下的**。
    """
    import sqlite3

    from core.config import db_path

    bid = database.insert_ban(
        BanRecord(
            ip=ip,
            rule_name=rule,
            status=STATUS_PENDING,
            source="auto",
            duration_sec=3600,
            expire_at=now_ms() + 3600_000,
        )
    )
    conn = sqlite3.connect(db_path())
    try:
        conn.execute("UPDATE ban_list SET created_at = ? WHERE id = ?", (created_at, bid))
        conn.commit()
    finally:
        conn.close()
    return bid


def _old() -> str:
    """早就过了 10 分钟宽限期的时间戳（格式与库里的 created_at 一致）"""
    import time

    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 3600))


def _recent() -> str:
    import time

    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - 30))


def _status(ban_id: int) -> str:
    rec = database.get_ban(ban_id)
    assert rec is not None
    return rec.status


def test_recover_keeps_rule_that_exists(isolated_env, admin, monkeypatch):
    """规则真的在防火墙里 → 记成 active（继续受巡检管辖，到期会正常解封）"""
    database.init_db()
    bid = _pending(IP, "PortGuard_Block_203.0.113.90", _old())
    monkeypatch.setattr(firewall, "list_rule_names", lambda: ["PortGuard_Block_203.0.113.90"])

    assert ban_service.recover_stale_pending() == 1
    assert _status(bid) == STATUS_ACTIVE


def test_recover_fails_rule_that_is_missing(isolated_env, admin, monkeypatch):
    """规则不在防火墙里 → 记成 failed。写成「封禁中」就是最坏的假成功"""
    database.init_db()
    bid = _pending(IP, "PortGuard_Block_203.0.113.90", _old())
    monkeypatch.setattr(firewall, "list_rule_names", list)

    assert ban_service.recover_stale_pending() == 1
    rec = database.get_ban(bid)
    assert rec is not None
    assert rec.status == STATUS_FAILED
    assert "未建立" in rec.error_msg


def test_recover_skips_fresh_pending(isolated_env, admin, monkeypatch):
    """刚写进去的 pending 是「正在封禁中」，不能动"""
    database.init_db()
    bid = _pending(IP, "PortGuard_Block_203.0.113.90", _recent())
    monkeypatch.setattr(firewall, "list_rule_names", list)

    assert ban_service.recover_stale_pending() == 0
    assert _status(bid) == STATUS_PENDING


def test_recover_skips_without_admin(isolated_env, monkeypatch):
    """非管理员读不到规则清单 → 一条都不动。宁可不收敛，也不凭空改状态"""
    database.init_db()
    monkeypatch.setattr(firewall, "is_admin", lambda: False)
    bid = _pending(IP, "PortGuard_Block_203.0.113.90", _old())

    assert ban_service.recover_stale_pending() == 0
    assert _status(bid) == STATUS_PENDING


def test_recover_skips_when_rule_list_unreadable(isolated_env, admin, monkeypatch):
    """读规则失败时不能把「读不到」当成「规则不存在」——那会把真拦着的记成失败"""
    database.init_db()
    bid = _pending(IP, "PortGuard_Block_203.0.113.90", _old())

    def boom() -> List[str]:
        raise RuntimeError("netsh 不可用")

    monkeypatch.setattr(firewall, "list_rule_names", boom)

    assert ban_service.recover_stale_pending() == 0
    assert _status(bid) == STATUS_PENDING


def test_recover_is_audited(isolated_env, admin, monkeypatch):
    """状态被程序改过就要留痕，否则运维看到「封禁中突然变失败」无从查起"""
    from app import audit

    database.init_db()
    _pending(IP, "PortGuard_Block_203.0.113.90", _old())
    monkeypatch.setattr(firewall, "list_rule_names", list)

    ban_service.recover_stale_pending()

    rows = database.query_audit(limit=10, action=audit.ACTION_BAN_RECOVER)
    assert rows and rows[0]["actor"] == audit.ACTOR_SYSTEM


# ═══════════════════ S9：CLI 与界面跨进程互斥 ═══════════════════


def test_cli_waits_for_single_instance(isolated_env, monkeypatch):
    """拿不到互斥 → 明确退出（返回 2），绝不去改防火墙"""
    monkeypatch.setattr(main_mod, "_check_deps", lambda: True)
    monkeypatch.setattr(main_mod, "_init_backend", lambda: None)
    monkeypatch.setattr(main_mod, "_enable_firewall_cli", pytest.fail)

    import core.single_instance as si

    monkeypatch.setattr(si, "acquire", lambda name="", wait_sec=0.0: False)
    monkeypatch.setattr("sys.argv", ["PortGuard.exe", "--enable-firewall"])

    assert main_mod.main() == 2


def test_acquire_wait_is_bounded(monkeypatch):
    """wait_sec 的语义：一直被占着就按时返回 False，拿到了立刻返回 True"""
    import time

    import core.single_instance as si

    monkeypatch.setattr(si, "_should_allow_multi", lambda: False)
    monkeypatch.setattr("sys.platform", "win32")

    calls: List[int] = []

    def busy(name: str) -> Any:
        calls.append(1)
        return False, True

    monkeypatch.setattr(si, "_try_acquire", busy)
    started = time.monotonic()
    assert si.acquire(wait_sec=0.3) is False
    assert time.monotonic() - started >= 0.2
    assert len(calls) >= 2, "等待期间必须重试，不能只试一次就说失败"

    monkeypatch.setattr(si, "_try_acquire", lambda name: (True, False))
    assert si.acquire(wait_sec=5.0) is True
