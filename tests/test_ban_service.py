"""封禁编排测试（app/ban_service.py）"""
import pytest

from app import ban_service
from core import firewall
from core.database import find_active_ban_by_ip, init_db, query_bans
from core.models import STATUS_ACTIVE, STATUS_FAILED, STATUS_PENDING, BanRecord


@pytest.fixture
def admin(monkeypatch):
    monkeypatch.setattr(firewall, "is_admin", lambda: True)


@pytest.fixture
def no_admin(monkeypatch):
    monkeypatch.setattr(firewall, "is_admin", lambda: False)


@pytest.fixture
def fake_fw(monkeypatch):
    """假装防火墙执行成功"""
    monkeypatch.setattr(firewall, "block_ip",
                        lambda ip, duration=None, note="": (True, f"PortGuard_Block_{ip}_1_aa", ""))


@pytest.fixture
def failing_fw(monkeypatch):
    monkeypatch.setattr(firewall, "block_ip",
                        lambda ip, duration=None, note="": (False, "", "Access denied"))


# ═══════════════════ prepare ═══════════════════

def test_prepare_accepts_valid(isolated_env):
    init_db()
    rec = ban_service.prepare("203.0.113.10", 95, "扫端口", 3600)
    assert rec.ip == "203.0.113.10"
    assert rec.risk_score == 95
    assert rec.duration_sec == 3600
    assert rec.expire_at is not None
    assert rec.status == STATUS_PENDING


def test_prepare_permanent_ban_has_no_expire(isolated_env):
    init_db()
    rec = ban_service.prepare("203.0.113.10", 0, "x", 0)
    assert rec.duration_sec is None
    assert rec.expire_at is None


@pytest.mark.parametrize("evil", [
    '1.2.3.4"; Start-Process calc; #',
    "$(calc)",
    "abc",
    "",
    "10.0.0.1",
    "192.168.1.1",
    "127.0.0.1",
    "::1",
])
def test_prepare_rejects_bad_or_protected(isolated_env, evil):
    init_db()
    with pytest.raises(ban_service.BanError):
        ban_service.prepare(evil)


def test_prepare_clamps_and_sanitizes(isolated_env):
    init_db()
    rec = ban_service.prepare("203.0.113.10", 99999, "a" * 500, 10 ** 12)
    assert rec.risk_score == 100
    assert rec.duration_sec == ban_service.MAX_BAN_SECONDS
    assert len(rec.reason) <= 180
    assert "\n" not in rec.reason


def test_prepare_sanitizes_injection_in_reason(isolated_env):
    """原因里的引号只是文本，不能逃出命令字面量（真正的防线在 firewall.ps_quote）"""
    init_db()
    rec = ban_service.prepare("203.0.113.10", 10, '"; Start-Process calc; #', 60)
    assert "Start-Process calc" in rec.reason  # 作为普通文本保留，但会被 ps_quote 包裹


# ═══════════════════ execute ═══════════════════

def test_execute_requires_admin(isolated_env, no_admin):
    init_db()
    ban_id, err = ban_service.execute("203.0.113.10", 90, "x", 60)
    assert ban_id is None
    assert "管理员" in err


def test_execute_success(isolated_env, admin, fake_fw):
    init_db()
    ban_id, err = ban_service.execute("203.0.113.10", 90, "扫端口", 60)
    assert ban_id is not None
    assert err == ""
    rec = find_active_ban_by_ip("203.0.113.10")
    assert rec and rec.status == STATUS_ACTIVE
    assert rec.rule_name


def test_execute_failure_records_failed_status(isolated_env, admin, failing_fw):
    init_db()
    ban_id, err = ban_service.execute("203.0.113.10", 90, "x", 60)
    assert ban_id is not None
    assert err
    rec = find_active_ban_by_ip("203.0.113.10")
    assert rec is None, "失败的封禁不应处于 active"
    assert query_bans(limit=10)[0].status == STATUS_FAILED


def test_execute_rejects_injection_without_touching_firewall(isolated_env, admin, monkeypatch):
    init_db()
    called = []
    monkeypatch.setattr(firewall, "block_ip",
                        lambda *a, **k: called.append(a) or (True, "r", ""))
    ban_id, err = ban_service.execute('1.2.3.4"; Start-Process calc; #', 90, "x", 60)
    assert ban_id is None
    assert err
    assert called == [], "非法 IP 绝不能触达防火墙层"
    assert query_bans(limit=10) == []


def test_execute_is_idempotent_for_active_ip(isolated_env, admin, fake_fw):
    init_db()
    first, _ = ban_service.execute("203.0.113.10", 90, "x", 60)
    second, err = ban_service.execute("203.0.113.10", 90, "x", 60)
    assert second == first
    assert "已处于封禁状态" in err


# ═══════════════════ 解封 / 巡检 ═══════════════════

def test_unban_requires_admin(isolated_env, no_admin):
    init_db()
    b = BanRecord(id=1, ip="203.0.113.10", rule_name="PortGuard_Block_x")
    ok, err = ban_service.unban(b)
    assert ok is False and err


def test_unban_success(isolated_env, admin, monkeypatch):
    init_db()
    from core.database import insert_ban
    bid = insert_ban(BanRecord(ip="203.0.113.10", rule_name="PortGuard_Block_x_1_aa",
                               status=STATUS_ACTIVE, source="manual"))
    monkeypatch.setattr(firewall, "unblock_ip", lambda ip, names=None: (True, "", 1))
    b = find_active_ban_by_ip("203.0.113.10")
    ok, err = ban_service.unban(b)
    assert ok and err == ""
    assert query_bans(limit=10)[0].status == "unbanned"
    assert bid


def test_check_expired_requires_admin(isolated_env, no_admin):
    init_db()
    assert ban_service.check_expired() == []


def test_check_expired_marks_expired(isolated_env, admin, monkeypatch):
    init_db()
    from core.database import insert_ban
    insert_ban(BanRecord(ip="203.0.113.10", rule_name="PortGuard_Block_x_1_aa",
                         status=STATUS_ACTIVE, source="manual",
                         duration_sec=60, expire_at=1))     # 早已过期
    monkeypatch.setattr(firewall, "unblock_ip", lambda ip, names=None: (True, "", 1))
    done = ban_service.check_expired()
    assert len(done) == 1
    assert query_bans(limit=10)[0].status == "expired"


def test_reconcile_fixes_stale_records(isolated_env, admin):
    init_db()
    from core.database import insert_ban
    insert_ban(BanRecord(ip="203.0.113.10", rule_name="PortGuard_Block_gone_1_aa",
                         status=STATUS_ACTIVE, source="manual"))
    insert_ban(BanRecord(ip="203.0.113.11", rule_name="PortGuard_Block_keep_1_bb",
                         status=STATUS_ACTIVE, source="manual"))
    fixed = ban_service.reconcile(["PortGuard_Block_keep_1_bb"])
    assert fixed == 1
    statuses = {b.ip: b.status for b in query_bans(limit=10)}
    assert statuses["203.0.113.10"] == "unbanned"
    assert statuses["203.0.113.11"] == STATUS_ACTIVE
