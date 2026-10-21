"""防火墙开关状态 + 规则名唯一化（2026-10-21）

背景（真机事故）：规则写得完全正确 —— Enabled=True / Inbound / Block /
RemoteAddress 对得上 —— 但 Windows 防火墙三个配置文件全是关闭的，于是
**没有任何规则参与过滤**，攻击者照连，界面显示「已封禁」。

这一组用例锁死三件事：
1. 防火墙关着时 `block_ip` 必须判失败（不许再出现「显示已封禁却拦不住」）
2. 规则名一个 IP 一条（原来每次封禁新建一条，解封只删一条 → 残留永久封禁）
3. 解封要把同一 IP 的历史规则删干净（按名字反解 IP）
"""

from types import SimpleNamespace
from typing import Any, Dict

import pytest

from core import firewall

#: conftest 的 autouse 打桩会覆盖这个名字，先把真实实现留一份
_REAL_FIREWALL_ENABLED = firewall.firewall_enabled

# ═══════════════════════════════════════════════════════════
#  开关状态解析
# ═══════════════════════════════════════════════════════════

CN_ALL_OFF = """
域配置文件 设置:
----------------------------------------------------------------------
状态                                   关闭

专用配置文件 设置:
----------------------------------------------------------------------
状态                                   关闭

公用配置文件 设置:
----------------------------------------------------------------------
状态                                   关闭

确定。
"""

CN_ALL_ON = CN_ALL_OFF.replace("关闭", "启用")

EN_MIXED = """
Domain Profile Settings:
----------------------------------------------------------------------
State                                 OFF

Private Profile Settings:
----------------------------------------------------------------------
State                                 ON

Public Profile Settings:
----------------------------------------------------------------------
State                                 ON
"""


def test_parse_profiles_chinese_all_off():
    state = firewall.parse_profiles_output(CN_ALL_OFF)
    assert state == {"domain": False, "private": False, "public": False}


def test_parse_profiles_chinese_all_on():
    assert firewall.parse_profiles_output(CN_ALL_ON) == {
        "domain": True,
        "private": True,
        "public": True,
    }


def test_parse_profiles_english_mixed():
    assert firewall.parse_profiles_output(EN_MIXED) == {
        "domain": False,
        "private": True,
        "public": True,
    }


def test_parse_profiles_garbage_returns_none():
    """读不出来必须返回 None —— **未知不等于关闭**，不能拿解析失败去误报不安全"""
    assert firewall.parse_profiles_output("") is None
    assert firewall.parse_profiles_output("确定。\n") is None
    # 只解析出两段：宁可返回未知，也不猜第三段
    two = CN_ALL_OFF.split("公用配置文件", maxsplit=1)[0]
    assert firewall.parse_profiles_output(two) is None


def test_format_profiles():
    text = firewall.format_profiles({"domain": False, "private": True, "public": False})
    assert "域=关" in text and "专用=开" in text and "公用=关" in text
    assert firewall.format_profiles(None) == "读不出防火墙状态"


def test_firewall_enabled_reads_any_profile(monkeypatch):
    # conftest 里有一条 autouse 的 `firewall_enabled` 打桩（避免用例依赖本机防火墙
    # 开关），这条用例测的正是它本身 → 先换回真实实现
    monkeypatch.setattr(firewall, "firewall_enabled", _REAL_FIREWALL_ENABLED)
    monkeypatch.setattr(firewall, "profiles_state", lambda force=False: None)
    assert firewall.firewall_enabled() is None
    monkeypatch.setattr(
        firewall,
        "profiles_state",
        lambda force=False: {"domain": False, "private": False, "public": False},
    )
    assert firewall.firewall_enabled() is False
    monkeypatch.setattr(
        firewall,
        "profiles_state",
        lambda force=False: {"domain": False, "private": True, "public": False},
    )
    assert firewall.firewall_enabled() is True


# ═══════════════════════════════════════════════════════════
#  监听端口解析（安全启用防火墙前要放行这些端口）
# ═══════════════════════════════════════════════════════════

NETSTAT = """
活动连接

  协议  本地地址          外部地址        状态           PID
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       4
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       4
  TCP    127.0.0.1:1433         0.0.0.0:0              LISTENING       1234
  TCP    192.168.1.9:3389       0.0.0.0:0              LISTENING       5678
  TCP    192.168.1.9:49152      93.184.216.34:443      ESTABLISHED     9999
  UDP    0.0.0.0:123            *:*                                    1111
  UDP    127.0.0.1:5353         *:*                                    2222
"""


def test_parse_listen_ports_skips_loopback_and_established():
    tcp, udp = firewall.parse_listen_ports(NETSTAT)
    # 80/443 通配 + 3389 指定网卡；127.0.0.1:1433 是回环（外部不可达，不开放行）
    assert tcp == [80, 443, 3389]
    assert udp == [123]


def test_parse_listen_ports_empty_on_garbage():
    assert firewall.parse_listen_ports("") == ([], [])


# ═══════════════════════════════════════════════════════════
#  block_ip：防火墙关着必须判失败
# ═══════════════════════════════════════════════════════════


@pytest.fixture
def fake_fw(monkeypatch):
    """把真实的 netsh/PowerShell 全部挡掉，只看封禁逻辑"""
    calls: Dict[str, Any] = {"create": [], "remove": [], "update": [], "exists": set()}
    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    monkeypatch.setattr(firewall, "rule_exists", lambda name: name in calls["exists"])

    def fake_create(name, ip, desc):
        calls["create"].append((name, ip, desc))
        calls["exists"].add(name)
        return True, ""

    def fake_update(name, desc):
        calls["update"].append((name, desc))
        return True

    def fake_remove(name):
        calls["remove"].append(name)
        calls["exists"].discard(name)
        return True, ""

    monkeypatch.setattr(firewall, "_create_rule", fake_create)
    monkeypatch.setattr(firewall, "_update_desc_locked", fake_update)
    monkeypatch.setattr(firewall, "_remove_rule_locked", fake_remove)
    return calls


def test_block_ip_fails_when_firewall_is_off(fake_fw, monkeypatch):
    """核心：规则写进去了，但防火墙关着 → 必须判失败，而不是「已封禁」"""
    monkeypatch.setattr(firewall, "firewall_enabled", lambda force=False: False)
    monkeypatch.setattr(
        firewall,
        "profiles_state",
        lambda force=False: {"domain": False, "private": False, "public": False},
    )
    ok, name, err = firewall.block_ip("203.0.113.40")
    assert ok is False
    assert name == "PortGuard_Block_203.0.113.40"
    assert "防火墙" in err and "关闭" in err
    # 规则确实写了（开关一开就生效），所以不能把名字丢掉
    assert fake_fw["create"], "规则应当被写入，只是不能算成功"


def test_block_ip_succeeds_when_firewall_unknown(fake_fw, monkeypatch):
    """读不出开关状态时不下结论 —— 不能因为解析失败就说人家没开防火墙"""
    monkeypatch.setattr(firewall, "firewall_enabled", lambda force=False: None)
    ok, _name, err = firewall.block_ip("203.0.113.41")
    assert ok is True and err == ""


def test_block_ip_reuses_existing_rule(fake_fw, monkeypatch):
    """续封同一个 IP：复用同名规则，只刷新描述，不再新建第二条"""
    monkeypatch.setattr(firewall, "firewall_enabled", lambda force=False: True)
    fake_fw["exists"].add("PortGuard_Block_203.0.113.42")
    ok, name, _err = firewall.block_ip("203.0.113.42", 1800)
    assert ok is True
    assert name == "PortGuard_Block_203.0.113.42"
    assert fake_fw["create"] == [], "已存在同名规则时不该再建一条"
    assert fake_fw["update"] and "到期" in fake_fw["update"][0][1]


def test_block_ip_rebuilds_when_desc_update_unsupported(fake_fw, monkeypatch):
    """2008 R2 没有 Set-NetFirewallRule：退回「删了重建」，但名字仍是一个"""
    monkeypatch.setattr(firewall, "firewall_enabled", lambda force=False: True)
    monkeypatch.setattr(firewall, "_update_desc_locked", lambda name, desc: False)
    fake_fw["exists"].add("PortGuard_Block_203.0.113.43")
    ok, _name, _err = firewall.block_ip("203.0.113.43")
    assert ok is True
    assert fake_fw["remove"] == ["PortGuard_Block_203.0.113.43"]
    assert len(fake_fw["create"]) == 1


# ═══════════════════════════════════════════════════════════
#  解封：同一 IP 的历史规则必须删干净
# ═══════════════════════════════════════════════════════════


def test_unblock_ip_removes_legacy_rules_of_same_ip(monkeypatch):
    """真机事故：同 IP 十几条旧规则，解封只删一条 → 用户以为解封了，实际还在拦"""
    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    monkeypatch.setattr(
        firewall,
        "list_rule_names",
        lambda: [
            "PortGuard_Block_203.0.113.50_1792455311422_7b18",
            "PortGuard_Block_203.0.113.50_1792455322071_6687",
            "PortGuard_Block_203.0.113.50",
            # 别的 IP 不能误删
            "PortGuard_Block_203.0.113.51",
        ],
    )
    removed_names = []

    def fake_unblock_by_name(name):
        removed_names.append(name)
        return True, ""

    monkeypatch.setattr(firewall, "unblock_by_name", fake_unblock_by_name)
    ok, _err, n = firewall.unblock_ip("203.0.113.50")
    assert ok is True
    assert n == 3
    assert "PortGuard_Block_203.0.113.51" not in removed_names


def test_unblock_ip_still_removes_named_rule(monkeypatch):
    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    monkeypatch.setattr(firewall, "list_rule_names", list)
    removed = []

    def fake_unblock(name):
        removed.append(name)
        return True, ""

    monkeypatch.setattr(firewall, "unblock_by_name", fake_unblock)
    ok, _err, n = firewall.unblock_ip("203.0.113.52", ["PortGuard_Block_203.0.113.52"])
    assert ok is True and n == 1
    assert removed == ["PortGuard_Block_203.0.113.52"]


# ═══════════════════════════════════════════════════════════
#  启动对齐（reenforce_all）
# ═══════════════════════════════════════════════════════════


def _ban(ip, status="active", rule_name="", bid=1):
    return SimpleNamespace(
        id=bid,
        ip=ip,
        status=status,
        rule_name=rule_name,
        reason="测试",
        duration_sec=1800,
    )


@pytest.fixture
def reenforce_env(monkeypatch):
    from app import ban_service

    calls: Dict[str, Any] = {"blocked": [], "updated": [], "removed": []}
    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    monkeypatch.setattr(firewall, "firewall_enabled", lambda force=False: True)
    monkeypatch.setattr(firewall, "profiles_state", lambda force=False: None)
    monkeypatch.setattr(firewall, "rule_exists", lambda name: False)

    def fake_block(ip, duration=None, note=""):
        calls["blocked"].append(ip)
        return True, firewall.rule_name(ip), ""

    monkeypatch.setattr(firewall, "block_ip", fake_block)
    monkeypatch.setattr(
        ban_service, "update_ban", lambda bid, **kw: calls["updated"].append((bid, kw))
    )
    monkeypatch.setattr(ban_service.audit, "record", lambda *a, **k: None)
    monkeypatch.setattr(ban_service, "query_bans", lambda status="", limit=0: [])
    return calls


def test_reenforce_refuses_when_firewall_off(reenforce_env, monkeypatch):
    from app import ban_service

    monkeypatch.setattr(firewall, "firewall_enabled", lambda force=False: False)
    monkeypatch.setattr(ban_service, "list_all_active_bans", lambda: [_ban("203.0.113.60")])
    res = ban_service.reenforce_all()
    assert res["ok"] is False
    assert "防火墙" in res["error"]
    assert reenforce_env["blocked"] == [], "防火墙没开时补封毫无意义，不该产生任何写操作"


def test_reenforce_restores_missing_rules(reenforce_env, monkeypatch):
    from app import ban_service

    monkeypatch.setattr(
        ban_service, "list_all_active_bans", lambda: [_ban("203.0.113.61", rule_name="old_name")]
    )
    monkeypatch.setattr(firewall, "legacy_rule_names", list)
    res = ban_service.reenforce_all()
    assert res["ok"] is True
    assert res["restored"] == ["203.0.113.61"]
    # 库里的 rule_name 要跟着改成新名字，否则对账会把它当成「规则已不存在」
    assert reenforce_env["updated"][0][1]["rule_name"] == "PortGuard_Block_203.0.113.61"


def test_reenforce_cleans_legacy_rules(reenforce_env, monkeypatch):
    from app import ban_service

    monkeypatch.setattr(ban_service, "list_all_active_bans", list)
    legacy = ["PortGuard_Block_203.0.113.62_1792455311422_7b18"]
    monkeypatch.setattr(firewall, "legacy_rule_names", lambda: legacy)
    monkeypatch.setattr(
        firewall, "remove_rules", lambda names: (reenforce_env["removed"].extend(names), (1, []))[1]
    )
    res = ban_service.reenforce_all()
    assert res["legacy_removed"] == 1
    assert reenforce_env["removed"] == legacy


def test_format_reenforce():
    from app import ban_service

    assert "补建规则 2 条" in ban_service.format_reenforce(
        {"ok": True, "restored": ["a", "b"], "legacy_removed": 0, "failed": []}
    )
    assert ban_service.format_reenforce({"ok": False, "error": "没有权限"}) == "没有权限"
    assert "无变化" in ban_service.format_reenforce(
        {"ok": True, "restored": [], "legacy_removed": 0, "failed": []}
    )
