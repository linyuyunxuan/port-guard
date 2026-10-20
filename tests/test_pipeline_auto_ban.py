"""自动封禁路径（core/pipeline.auto_ban_record）的查重守门。

自动模式是「每来一条达标事件就封一次」：同一个攻击者持续扫描会连续触发，
缺了查重就会每次都 insert 一条记录、并新建一条防火墙规则（规则名带随机
后缀，不会互相覆盖），最终规则数无限增长、封禁页被重复记录填满。

这里钉住四件事：
1. 同一 IP 连续触发 → 只插一条记录、只调一次防火墙；
2. 命中查重时不发 emit_ban（否则界面会不停弹「封禁成功」气泡）；
3. 已解封的 IP 必须能重新封禁（去重不能误伤）；
4. 内网 / 回环仍然被 is_never_ban 拦住（回归）。
"""

import pytest

from core import database, firewall
from core.event_bus import bus
from core.models import AccessRecord, RiskResult
from core.pipeline import auto_ban_record

IP = "203.0.113.77"


@pytest.fixture(autouse=True)
def _schema(fresh_db):
    """fresh_db 只清库文件、不建表，这里补一次建表（建在临时库里）。"""
    database.init_db()
    yield


@pytest.fixture(autouse=True)
def _drain_bus():
    """每个用例前后清空 ban 队列，避免上一条用例的事件污染计数。"""
    bus.drain_ban(max_n=1000)
    yield
    bus.drain_ban(max_n=1000)


@pytest.fixture
def fake_fw(monkeypatch):
    """假装防火墙执行成功，并记录调用次数"""
    calls = []

    def _block(ip, duration=None, note=""):
        calls.append((ip, duration, note))
        return (True, f"PortGuard_Block_{ip}_1_aa", "")

    monkeypatch.setattr(firewall, "block_ip", _block)
    return calls


def _rec(ip: str = IP) -> AccessRecord:
    return AccessRecord(ip=ip, remote_port=51234, local_port=18080, protocol="tcp")


def _result() -> RiskResult:
    return RiskResult(score=95, level="high", matched_rules=["scan"], suggest_ban=True)


def _ban_count(ip: str = "") -> int:
    return len(database.query_bans(limit=1000, keyword=ip))


# ═══════════════════ 查重 ═══════════════════


def test_auto_ban_is_idempotent_for_same_ip(isolated_env, fake_fw):
    """同一 IP 连续触发两次：只插 1 条记录、只调 1 次防火墙"""
    auto_ban_record(_rec(), _result())
    auto_ban_record(_rec(), _result())

    assert _ban_count() == 1
    assert len(fake_fw) == 1


def test_auto_ban_dedupe_uses_active_status(isolated_env, fake_fw):
    """第一次封禁成功后记录为 active，第二次才被拦住（靠状态不是靠 IP 缓存）"""
    auto_ban_record(_rec(), _result())
    assert database.find_active_ban_by_ip(IP) is not None

    auto_ban_record(_rec(), _result())
    assert _ban_count() == 1


def test_auto_ban_dedupe_emits_no_ban_event(isolated_env, fake_fw):
    """命中查重时不发 emit_ban，界面才不会刷出一堆「封禁成功」气泡"""
    auto_ban_record(_rec(), _result())
    bus.drain_ban(max_n=1000)

    auto_ban_record(_rec(), _result())
    assert bus.drain_ban(max_n=1000) == []


def test_auto_ban_emits_event_on_first_ban(isolated_env, fake_fw):
    """首次封禁仍然要投递事件（去重不能把正常事件一起吞掉）"""
    auto_ban_record(_rec(), _result())
    events = bus.drain_ban(max_n=1000)
    assert len(events) == 1
    assert events[0]["ip"] == IP
    assert events[0]["ok"] is True
    assert events[0]["auto"] is True


def test_auto_ban_dedupe_is_per_ip(isolated_env, fake_fw):
    """不同 IP 互不影响"""
    auto_ban_record(_rec(IP), _result())
    auto_ban_record(_rec("198.51.100.20"), _result())

    assert _ban_count() == 2
    assert len(fake_fw) == 2


# ═══════════════════ 不能误伤 ═══════════════════


def test_unbanned_ip_can_be_banned_again(isolated_env, fake_fw):
    """已解封的 IP 再次触发必须能重新封禁"""
    auto_ban_record(_rec(), _result())
    first = database.find_active_ban_by_ip(IP)
    assert first is not None
    database.update_ban(first.id, status="unbanned")

    auto_ban_record(_rec(), _result())

    assert _ban_count() == 2
    assert len(fake_fw) == 2
    assert database.find_active_ban_by_ip(IP) is not None


def test_expired_ip_can_be_banned_again(isolated_env, fake_fw):
    """到期解封（status=expired）的 IP 同样要能重新封禁"""
    auto_ban_record(_rec(), _result())
    first = database.find_active_ban_by_ip(IP)
    assert first is not None
    database.update_ban(first.id, status="expired")

    auto_ban_record(_rec(), _result())

    assert _ban_count() == 2
    assert len(fake_fw) == 2


def test_failed_ban_can_be_retried(isolated_env, monkeypatch):
    """上次封禁失败（状态 failed，非 active）时允许重试"""
    calls = []

    def _block(ip, duration=None, note=""):
        calls.append(ip)
        return (False, "", "Access denied") if len(calls) == 1 else (True, "r2", "")

    monkeypatch.setattr(firewall, "block_ip", _block)
    auto_ban_record(_rec(), _result())
    assert database.query_bans(limit=10)[0].status == "failed"

    auto_ban_record(_rec(), _result())
    assert len(calls) == 2
    assert _ban_count() == 2


def test_dedupe_query_failure_does_not_block_ban(isolated_env, fake_fw, monkeypatch):
    """查重本身抛异常时不能放弃封禁：宁可多封一次，也不放过正在扫描的 IP"""

    def _boom(ip):
        raise RuntimeError("db down")

    monkeypatch.setattr(database, "find_active_ban_by_ip", _boom)
    auto_ban_record(_rec(), _result())

    assert _ban_count() == 1
    assert len(fake_fw) == 1


# ═══════════════════ 永不封禁地址（回归） ═══════════════════


@pytest.mark.parametrize(
    "protected",
    [
        "127.0.0.1",
        "::1",
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
    ],
)
def test_never_ban_addresses_are_still_skipped(isolated_env, fake_fw, protected):
    """内网 / 回环 / 保留地址：不落库、不调防火墙、不发事件"""
    auto_ban_record(_rec(protected), _result())

    assert _ban_count() == 0
    assert fake_fw == []
    assert bus.drain_ban(max_n=1000) == []
