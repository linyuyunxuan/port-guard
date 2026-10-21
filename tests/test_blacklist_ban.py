"""黑名单 → 防火墙联动，以及「封禁必须真的生效」的用例。

背景：黑名单原来只打分不拦截（自动封禁默认关闭），用户明确要求
「黑名单的 IP 不能继续访问」。两条硬约束：
1. 加入黑名单 = 立即写防火墙阻止规则（永久）
2. 非管理员时如实报告「未拦截」，绝不假装成功

变异验证（逐条把实现改回错的，确认会红）：
- apply_changes 不调 execute → test_add_blacklist_bans_immediately 红
- 非管理员返回成功 → test_non_admin_reports_not_enforced 红
- 移除时不管来源一律解封 → test_remove_does_not_unban_manual_ban 红
- duration 用策略默认而不是永久 → test_blacklist_ban_is_permanent 红
- block_ip 去掉回读复核 → test_block_ip_fails_when_rule_not_readable 红
- is_never_ban_target 不支持网段 → test_protected_network_is_rejected 红
"""

from typing import Any, Dict, List, Optional

from app import ban_service, blacklist_service
from core import firewall
from core.rule_engine import is_never_ban_target


class _Ban:
    """替身 BanRecord（只带本模块用到的字段）"""

    def __init__(self, ip: str, source: str = "manual", rule_name: str = "PortGuard_Block_x"):
        self.id = 1
        self.ip = ip
        self.source = source
        self.rule_name = rule_name
        self.status = "active"


def _patch_exec(
    monkeypatch,
    existing: Optional[Dict[str, _Ban]] = None,
    admin: bool = True,
    unbanned: Optional[List[str]] = None,
):
    """把 execute / unban / find_active_ban_by_ip / is_admin 全打桩，记录调用。"""
    existing = existing or {}
    calls: Dict[str, Any] = {"execute": [], "unban": []}

    monkeypatch.setattr(firewall, "is_admin", lambda: admin)

    def fake_execute(
        ip,
        score=0,
        reason="",
        duration_sec=None,
        source="manual",
        rule_ids=None,
        actor=None,
    ):
        calls["execute"].append(
            {
                "ip": ip,
                "score": score,
                "duration_sec": duration_sec,
                "source": source,
                "reason": reason,
            }
        )
        if not admin:
            return None, "需要管理员权限才能修改 Windows 防火墙"
        # 已有活动封禁时与真实实现一致：返回 (id, "…已处于封禁状态…")
        if ip in existing:
            return existing[ip].id, f"{ip} 已处于封禁状态（记录 #{existing[ip].id}）"
        return 1, ""

    def fake_unban(ban, actor=None):
        calls["unban"].append(ban.ip)
        if unbanned is not None:
            unbanned.append(ban.ip)
        return True, ""

    monkeypatch.setattr(ban_service, "execute", fake_execute)
    monkeypatch.setattr(ban_service, "unban", fake_unban)
    monkeypatch.setattr(blacklist_service, "find_active_ban_by_ip", existing.get)
    return calls


def test_diff_reports_added_and_removed():
    added, removed = blacklist_service.diff(["1.1.1.1", "2.2.2.2"], ["2.2.2.2", "3.3.3.3"])
    assert added == ["3.3.3.3"]
    assert removed == ["1.1.1.1"]


def test_add_blacklist_bans_immediately(monkeypatch):
    calls = _patch_exec(monkeypatch)
    res = blacklist_service.apply_changes(["203.0.113.7"], [])
    assert calls["execute"], "加入黑名单没有触发封禁 —— 黑名单就只是打分，拦不住访问"
    c = calls["execute"][0]
    assert c["ip"] == "203.0.113.7"
    assert c["source"] == blacklist_service.SOURCE_BLACKLIST
    assert c["score"] == 100
    assert res["banned"] and res["failed"] == []


def test_blacklist_ban_is_permanent(monkeypatch):
    calls = _patch_exec(monkeypatch)
    blacklist_service.apply_changes(["203.0.113.8"], [])
    assert calls["execute"][0]["duration_sec"] == 0, "黑名单封禁必须是永久（0 = 永久）"


def test_non_admin_reports_not_enforced(monkeypatch):
    calls = _patch_exec(monkeypatch, admin=False)
    res = blacklist_service.apply_changes(["203.0.113.9"], ["203.0.113.10"])
    assert res["admin"] is False
    assert res["banned"] == []
    assert [ip for ip, _e in res["failed"]] == ["203.0.113.9"]
    assert "管理员权限" in res["failed"][0][1]
    assert calls["execute"] == [], "非管理员时不该调用封禁"
    summary = blacklist_service.format_summary(res)
    assert "不会拦截" in summary or "未写防火墙" in summary


def test_remove_unbans_blacklist_source(monkeypatch):
    existing = {"203.0.113.11": _Ban("203.0.113.11", source=blacklist_service.SOURCE_BLACKLIST)}
    calls = _patch_exec(monkeypatch, existing)
    res = blacklist_service.apply_changes([], ["203.0.113.11"])
    assert calls["unban"] == ["203.0.113.11"]
    assert res["unbanned"] and not res["skipped_unban"]


def test_remove_does_not_unban_manual_ban(monkeypatch):
    """手工封禁不能因为「从黑名单移除」被顺手解掉 —— 那是越权。"""
    existing = {"203.0.113.12": _Ban("203.0.113.12", source="manual")}
    calls = _patch_exec(monkeypatch, existing)
    res = blacklist_service.apply_changes([], ["203.0.113.12"])
    assert calls["unban"] == []
    assert [ip for ip, _s in res["skipped_unban"]] == ["203.0.113.12"]


def test_already_banned_is_not_duplicated(monkeypatch):
    existing = {"203.0.113.13": _Ban("203.0.113.13", source="manual")}
    _patch_exec(monkeypatch, existing)
    res = blacklist_service.apply_changes(["203.0.113.13"], [])
    assert [ip for ip, _e in res["already"]] == ["203.0.113.13"]
    assert res["banned"] == []


def test_ensure_enforced_only_fills_missing(monkeypatch, tmp_path):
    """启动补封只处理「名单里有、没有活动封禁」的条目。"""
    calls = _patch_exec(monkeypatch, existing={"203.0.113.20": _Ban("203.0.113.20")})

    class _Eng:
        class blacklist:
            @staticmethod
            def entries():
                return ["203.0.113.20", "203.0.113.21"]

    monkeypatch.setattr("core.rule_engine.get_engine", _Eng)
    res = blacklist_service.ensure_enforced()
    assert [c["ip"] for c in calls["execute"]] == ["203.0.113.21"]
    assert [ip for ip, _n in res["banned"]] == ["203.0.113.21"]


# ── 封禁生效性复核 ──


def _fake_fw(monkeypatch, exists: bool, calls: List[List[str]]):
    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    monkeypatch.setattr(firewall, "_powershell", lambda s, timeout=30: (0, ""))

    def fake_run(cmd, timeout=30):
        calls.append(list(cmd))
        return 0, ""

    monkeypatch.setattr(firewall, "_run", fake_run)
    monkeypatch.setattr(firewall, "rule_exists", lambda name: exists)


def test_block_ip_fails_when_rule_not_readable(monkeypatch):
    """命令返回 0 但回读不到规则 → 必须按失败返回，不能显示「已封禁」却拦不住。"""
    _fake_fw(monkeypatch, exists=False, calls=[])
    ok, name, err = firewall.block_ip("203.0.113.30")
    assert not ok and name == ""
    assert "回读不到" in err


def test_block_ip_succeeds_when_verified(monkeypatch):
    _fake_fw(monkeypatch, exists=True, calls=[])
    ok, name, err = firewall.block_ip("203.0.113.31")
    assert ok and name.startswith(firewall.RULE_PREFIX) and err == ""


def test_block_ip_accepts_cidr(monkeypatch):
    """黑名单允许写网段，封禁路径必须能处理 —— 否则网段条目等于没拦。"""
    scripts: List[str] = []

    def fake_ps(script, timeout=30):
        scripts.append(script)
        return 0, ""

    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    monkeypatch.setattr(firewall, "_powershell", fake_ps)
    monkeypatch.setattr(firewall, "rule_exists", lambda name: True)
    ok, _name, err = firewall.block_ip("203.0.113.0/24")
    assert ok, err
    assert any("-RemoteAddress '203.0.113.0/24'" in s for s in scripts), scripts


def test_protected_network_is_rejected():
    """内网/回环网段绝不能被封（否则一次误操作断内网）。"""
    assert is_never_ban_target("192.168.0.0/16")
    assert is_never_ban_target("10.0.0.0/8")
    assert is_never_ban_target("127.0.0.1")
    assert not is_never_ban_target("203.0.113.0/24")


def test_block_ip_refuses_protected_cidr(monkeypatch):
    _fake_fw(monkeypatch, exists=True, calls=[])
    ok, _name, err = firewall.block_ip("192.168.0.0/16")
    assert not ok
    assert "受保护" in err
