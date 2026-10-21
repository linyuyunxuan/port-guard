"""
防火墙命令安全回归测试（对应审查报告 S1）

核心断言：**恶意输入不得触发任何命令执行**。
做法是把 `_powershell` / `_run` 换成记录器，既不真的动系统防火墙，
又能看到到底拼接出了什么命令。
"""

import re
from typing import List

import pytest

from core import firewall
from core.validators import ps_quote

EVIL_IPS = [
    '1.2.3.4"; Start-Process calc; #',
    "$(Get-Content C:\\Windows\\win.ini)",
    "1.2.3.4' ; Remove-Item C:\\ -Recurse",
    "1.2.3.4`nStart-Process calc",
    "1.2.3.4; shutdown -s -t 0",
    "8.8.8.8/0",
    "abc",
    "",
]


@pytest.fixture
def spy(monkeypatch):
    """记录所有被拼接出来的命令，并假装执行成功。

    注意这里维护了一张「假规则表」：block_ip 现在会**先查规则是否已存在**，
    存在就复用（续封只刷新描述），不存在才新建。固定返回 True/False 都会让
    另一条分支永远走不到 —— 那等于用例只测了一半。
    """
    calls: List[tuple] = []
    exists: set = set()

    def _track_ps(script: str) -> None:
        for m in re.finditer(r"New-NetFirewallRule -DisplayName '([^']+)'", script):
            exists.add(m.group(1))
        for m in re.finditer(r"Remove-NetFirewallRule -DisplayName '([^']+)'", script):
            exists.discard(m.group(1))

    def fake_ps(script, timeout=30):
        calls.append(("ps", script))
        _track_ps(script)
        return 0, ""

    def fake_run(cmd, timeout=30):
        calls.append(("run", cmd))
        joined = " ".join(str(c) for c in cmd)
        m = re.search(r"name=(\S+)", joined)
        if m and " add " in joined + " " and "rule" in cmd:
            exists.add(m.group(1))
        if m and "delete" in cmd and "rule" in cmd:
            exists.discard(m.group(1))
        return 0, ""

    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    monkeypatch.setattr(firewall, "rule_exists", lambda name: name in exists)
    monkeypatch.setattr(firewall, "_powershell", fake_ps)
    monkeypatch.setattr(firewall, "_run", fake_run)
    # 「本机有没有 New-NetFirewallRule」是模块级缓存，用例之间必须重置，
    # 否则前一条用例探出的结论会让这条用例走了另一条分支
    monkeypatch.setattr(firewall, "_ps_cmdlet_missing", None)
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


@pytest.mark.parametrize(
    "evil",
    [
        'PortGuard_Block_x"; Start-Process calc; #',
        "PortGuard_Block_x'; calc; #",
        "PortGuard_Block_x$(calc)",
        "SomeOtherRule",
        "PortGuard_Block_x`ncalc",
    ],
)
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

    def fake_ps(script, timeout=30):
        calls.append(script)
        return (0, "")

    monkeypatch.setattr(firewall, "_powershell", fake_ps)
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


@pytest.mark.parametrize(
    "note",
    [
        '"; Start-Process calc; #',
        "'; Start-Process calc; #",
        "$(Get-Content C:\\Windows\\win.ini)",
        "`nStart-Process calc",
        'Korea|Republic say "hi"',
    ],
)
def test_note_is_sanitized_not_interpolated(spy, note):
    """
    封禁原因里的引号 / 子表达式 / 竖线必须被**净化掉**，而不是原样带进描述。

    原用例断言的是「原文原样保留」（只靠 ps_quote 兜），但真机证明那样不够：
    netsh 的 description 有字符白名单，`|` 与成对引号会让它拒建规则，
    而 Server 2008 R2 上没有 New-NetFirewallRule，只能走 netsh。
    所以现在的口径是「净化之后再 ps_quote」，本用例同时钉住两边：
    危险字符不能出现，可读内容要留下，参数边界不能溢出。
    """
    ok, _n, err = firewall.block_ip("203.0.113.10", note=note)
    assert ok, err
    _kind, script = spy[0]

    desc = _ps_arg(script, "-Description")
    for bad in ('"', "|", "`", "$", "\\"):
        assert bad not in desc, f"描述里仍残留 {bad!r}：{desc!r}"
    assert "-RemoteAddress" not in desc, "payload 溢出了参数边界"
    assert _ps_arg(script, "-RemoteAddress") == "203.0.113.10"
    # 净化不等于整段丢弃：字母数字部分必须留下痕迹，否则描述就失去意义了
    assert any(k in desc for k in ("Start-Process", "Get-Content", "win.ini", "Korea"))


def test_rule_name_is_stable_per_ip():
    """一个 IP 恒定一个规则名（2026-10-21 改）。

    原来带毫秒时间戳 + 随机后缀，每次封禁都新建一条：真机上同一个 IP 堆了十几条，
    而解封只删库里记的那条 → 「解封了还封着」。现在同名复用，续封只刷新描述。
    """
    names = {firewall.rule_name("203.0.113.10") for _ in range(50)}
    assert names == {"PortGuard_Block_203.0.113.10"}


def test_rule_name_handles_ipv6_and_cidr():
    assert firewall.rule_name("2001:db8::1") == "PortGuard_Block_2001-db8--1"
    assert firewall.rule_name("203.0.113.0/24") == "PortGuard_Block_203.0.113.0-24"


def test_legacy_rule_name_is_recognized():
    """旧的 `<ip>_<毫秒>_<4位随机>` 必须能被识别出来（启动时据此清理）"""
    old = "PortGuard_Block_203.0.113.10_1792455311422_7b18"
    assert firewall.is_legacy_rule_name(old)
    assert not firewall.is_legacy_rule_name(firewall.rule_name("203.0.113.10"))
    # IPv4 的旧名能反解回 IP，解封时靠它把同 IP 的历史规则一起删掉
    assert firewall.parse_ip_from_rule_name(old) == "203.0.113.10"


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
