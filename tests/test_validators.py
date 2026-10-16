"""
输入校验与命令安全测试（对应审查报告 S1 的修复）

这是整个测试套件里最重要的一组：它把「命令注入」固化成回归用例，
保证以后任何人改动 `firewall` / 封禁入口时，都不能再引入同类漏洞。
"""

import pytest

from core.validators import (
    InvalidIP,
    InvalidRuleName,
    InvalidURL,
    clamp_int,
    is_valid_ip,
    normalize_ip,
    normalize_rule_name,
    ps_quote,
    safe_https_url,
    safe_text,
)

# 覆盖各类 PowerShell / cmd 注入手法
EVIL_INPUTS = [
    '1.2.3.4"; Start-Process calc; #',
    '1.2.3.4"; Start-Process calc; #" ',
    "$(Get-Content C:\\Windows\\win.ini)",
    "1.2.3.4' ; Remove-Item C:\\ -Recurse",
    "1.2.3.4`nStart-Process calc",
    "1.2.3.4 && calc",
    "1.2.3.4 | Out-File x",
    "1.2.3.4; shutdown -s -t 0",
    "`whoami`",
    "1.2.3.4\nStart-Process calc",
    "8.8.8.8/0",  # 网段写法在 IP 位置不允许
    "",
    "   ",
    "abc",
    "999.999.999.999",
    "1.2.3",
    "x" * 100,
]


@pytest.mark.parametrize("evil", EVIL_INPUTS)
def test_normalize_ip_rejects(evil):
    with pytest.raises(InvalidIP):
        normalize_ip(evil)
    assert is_valid_ip(evil) is False


@pytest.mark.parametrize(
    "good,expected",
    [
        ("113.118.113.77", "113.118.113.77"),
        (" 113.118.113.77 ", "113.118.113.77"),
        ("8.8.8.8", "8.8.8.8"),
        ("2408:8000::1", "2408:8000::1"),
        ("::1", "::1"),
        ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:db8::1"),
        ("2001:DB8::1", "2001:db8::1"),
    ],
)
def test_normalize_ip_accepts(good, expected):
    assert normalize_ip(good) == expected


def test_normalize_ip_leading_zero_v4():
    """带前导零的 IPv4 归一化（部分业务系统会这么发）"""
    assert normalize_ip("010.001.001.001") == "10.1.1.1"


def test_normalize_ip_network_requires_flag():
    with pytest.raises(InvalidIP):
        normalize_ip("10.0.0.0/8")
    assert normalize_ip("10.0.0.0/8", allow_network=True) == "10.0.0.0/8"
    assert normalize_ip("10.1.2.3/8", allow_network=True) == "10.0.0.0/8"


def test_normalize_ip_output_is_injection_free():
    """归一化后的产物只含安全字符集，可直接进命令行"""
    out = normalize_ip("1.1.1.1")
    assert set(out) <= set("0123456789abcdefABCDEF:.")


# ── ps_quote ──


def test_ps_quote_single_quote_doubling():
    assert ps_quote("abc") == "'abc'"
    assert ps_quote("a'b") == "'a''b'"
    assert ps_quote("a'; calc; #") == "'a''; calc; #'"
    assert ps_quote('a"; calc; #') == "'a\"; calc; #'"


def test_ps_quote_neutralizes_subexpression():
    """单引号串在 PowerShell 中不做变量展开与子表达式求值"""
    quoted = ps_quote("$(Get-Process)")
    assert quoted.startswith("'") and quoted.endswith("'")
    assert quoted == "'$(Get-Process)'"


# ── 规则名 ──


def test_normalize_rule_name_ok():
    n = "PortGuard_Block_1.2.3.4_1700000000000_ab12"
    assert normalize_rule_name(n, prefix="PortGuard_Block_") == n


@pytest.mark.parametrize(
    "bad",
    [
        'x"; Remove-Item C:\\ -Recurse; #',
        "x'; calc; #",
        "x$(calc)",
        "x`ncalc",
        "",
        "x" * 300,
    ],
)
def test_normalize_rule_name_rejects(bad):
    with pytest.raises(InvalidRuleName):
        normalize_rule_name(bad)


def test_normalize_rule_name_enforces_prefix():
    with pytest.raises(InvalidRuleName):
        normalize_rule_name("Windows_Update_Rule", prefix="PortGuard_Block_")


# ── 自由文本 ──


def test_safe_text_strips_control_and_newlines():
    assert safe_text("a\r\nb\tc") == "a  b c"
    assert safe_text("a\x00b") == "ab"
    assert safe_text("x" * 500, maxlen=10) == "x" * 10
    assert safe_text("", default="d") == "d"
    assert safe_text(None, default="d") == "d"


def test_clamp_int():
    assert clamp_int("50", 0, 100, 0) == 50
    assert clamp_int(9999, 0, 100, 0) == 100
    assert clamp_int(-5, 0, 100, 0) == 0
    assert clamp_int("abc", 0, 100, 7) == 7
    assert clamp_int(None, 0, 100, 7) == 7


# ── URL（离线库下载源）──


def test_safe_https_url_ok():
    u = "https://cdn.jsdelivr.net/gh/x/y@master/data/a.xdb"
    assert safe_https_url(u, allowed_hosts=["cdn.jsdelivr.net"]) == u


@pytest.mark.parametrize(
    "bad",
    [
        "http://cdn.jsdelivr.net/x",  # 非 https
        "ftp://example.com/x",
        "https://user:pw@cdn.jsdelivr.net/x",  # 内嵌凭据
        "https://127.0.0.1/x",  # 不在白名单
        "https://internal.corp.local/x",
        "",
        "not a url",
        "file:///etc/passwd",
    ],
)
def test_safe_https_url_rejects(bad):
    with pytest.raises(InvalidURL):
        safe_https_url(bad, allowed_hosts=["cdn.jsdelivr.net"])


def test_safe_https_url_subdomain_allowed():
    u = "https://objects.githubusercontent.com/x"
    assert safe_https_url(u, allowed_hosts=["githubusercontent.com"]) == u
