"""
防火墙命令安全回归测试（对应审查报告 S1）

核心断言：**恶意输入不得触发任何命令执行**。
做法是把 `_powershell` / `_run` 换成记录器，既不真的动系统防火墙，
又能看到到底拼接出了什么命令。
"""
import re

import pytest

from core import firewall
from core.validators import ps_quote

EVIL_IPS = [
    '1.2.3.4"; Start-Process calc; #',
    '$(Get-Content C:\\Windows\\win.ini)',
    "1.2.3.4' ; Remove-Item C:\\ -Recurse",
    "1.2.3.4`nStart-Process calc",
    "1.2.3.4; shutdown -s -t 0",
    "8.8.8.8/0",
    "abc",
    "",
]


@pytest.fixture
def spy(monkeypatch):
    """记录所有被拼接出来的命令，并假装执行成功"""
    calls = []

    def fake_ps(script, timeout=30):
        calls.append(("ps", script))
        return 0, ""

    def fake_run(cmd, timeout=30):
        calls.append(("run", cmd))
        return 0, ""

    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    monkeypatch.setattr(firewall, "_powershell", fake_ps)
    monkeypatch.setattr(firewall, "_run", fake_run)
    return calls


@pytest.mark.parametrize("evil", EVIL_IPS)
def test_block_ip_rejects_injection(spy, evil):
    ok, name, err = firewall.block_ip(evil)
    assert ok is False
    assert name == ""
    assert err
    assert spy == [], f"非法 IP 不应触发任何命令，却产生了 {spy}"


@pytest.mark.parametrize("evil", EVIL_IPS)
def test_unblock_ip_rejects_injection(spy, evil):
    ok, _err, n = firewall.unblock_ip(evil, [f"PortGuard_Block_x_{evil}"])
    assert ok is False
    assert n == 0
    assert spy == [], f"非法 IP 不应触发任何命令，却产生了 {spy}"


@pytest.mark.parametrize("evil", [
    'PortGuard_Block_x"; Start-Process calc; #',
    "PortGuard_Block_x'; calc; #",
    'PortGuard_Block_x$(calc)',
    "SomeOtherRule",
    "PortGuard_Block_x`ncalc",
])
def test_unblock_by_name_rejects_bad_names(spy, evil):
    ok, _err = firewall.unblock_by_name(evil)
    assert ok is False
    assert spy == [], f"非法规则名不应触发任何命令，却产生了 {spy}"


def test_block_ip_uses_single_quote_literals(spy):
    """合法 IP 也要用单引号字面量，而不是双引号插值"""
    ok, name, _err = firewall.block_ip("203.0.113.10", note="测试")
    assert ok is True
    assert spy, "合法封禁应当产生命令"
    kind, script = spy[0]
    assert kind == "ps"
    assert "-RemoteAddress '203.0.113.10'" in script
    assert '"203.0.113.10"' not in script
    assert name.startswith(firewall.RULE_PREFIX)


def test_block_ip_rejects_protected_networks(spy):
    """内网 / 回环 / 保留地址永不封禁"""
    for ip in ("127.0.0.1", "192.168.1.10", "10.0.0.5", "::1", "169.254.1.1"):
        ok, _n, err = firewall.block_ip(ip)
        assert ok is False and err
    assert spy == []


def test_block_ip_without_admin_does_nothing(monkeypatch):
    calls = []
    monkeypatch.setattr(firewall, "is_admin", lambda: False)
    monkeypatch.setattr(firewall, "_powershell",
                        lambda s, timeout=30: calls.append(s) or (0, ""))
    ok, _n, err = firewall.block_ip("203.0.113.10")
    assert ok is False
    assert "管理员" in err
    assert calls == []


def _ps_arg(script: str, flag: str) -> str:
    """
    从拼好的 PowerShell 命令里取出某个参数的字面量内容（并还原被翻倍的引号）。
    非贪婪 + 断言后面跟 ` -` / ` |`，保证不会把后一个参数也吞进来。
    """
    m = re.search(rf"{re.escape(flag)} '(.*?)'(?= -| \|)", script)
    assert m, f"未找到 {flag} 参数：{script}"
    return m.group(1).replace("''", "'")


@pytest.mark.parametrize("note", [
    '"; Start-Process calc; #',
    "'; Start-Process calc; #",
    "$(Get-Content C:\\Windows\\win.ini)",
    "`nStart-Process calc",
])
def test_note_is_quoted_not_interpolated(spy, note):
    """封禁原因里的引号/子表达式必须被单引号字面量吃掉，不能逃到参数之外"""
    ok, _n, err = firewall.block_ip("203.0.113.10", note=note)
    assert ok, err
    _kind, script = spy[0]

    desc = _ps_arg(script, "-Description")
    assert note in desc, f"原因原文被篡改：{desc!r}"
    assert desc.endswith(note), f"原因后面被拼进了别的东西：{desc!r}"
    assert "-RemoteAddress" not in desc, "payload 溢出了参数边界"
    assert _ps_arg(script, "-RemoteAddress") == "203.0.113.10"


def test_rule_name_is_unique_within_same_millisecond():
    """原实现用秒级时间戳，同秒重复封禁会重名；现在必须唯一"""
    names = {firewall.rule_name("203.0.113.10", ts=1700000000000) for _ in range(50)}
    assert len(names) == 50


def test_parse_ip_from_rule_name_roundtrip():
    n = firewall.rule_name("203.0.113.10")
    assert firewall.parse_ip_from_rule_name(n) == "203.0.113.10"


def test_unblock_uses_single_quote(spy):
    firewall.unblock_by_name("PortGuard_Block_1.2.3.4_1700000000000_ab12")
    _kind, script = spy[0]
    assert "Remove-NetFirewallRule -DisplayName 'PortGuard_Block_" in script


def test_ps_quote_is_used_for_prefix_wildcards(spy):
    firewall.list_active_rules()
    _kind, script = spy[0]
    assert ps_quote(firewall.RULE_PREFIX + "*") in script
