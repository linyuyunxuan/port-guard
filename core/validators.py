"""
PortGuard — 输入校验与命令安全

铁律：**任何拼进命令行 / PowerShell 的值，必须先经本模块处理。**

原实现的漏洞（已实测复现）：手动封禁输入框的文本未做任何校验就插值进
PowerShell 命令，输入

    1.2.3.4"; Start-Process calc; #

会让 PowerShell 在 `;` 处断开语句，真实执行 `Start-Process calc`；
而封禁功能强制要求管理员权限 —— 等于「打字即可拿到管理员命令执行」。

两道防线，缺一不可：
1. 白名单校验：把值归一化成只含 ``[0-9a-f:./-]`` 的安全形态（非法即拒绝）
2. 单引号字面量包裹（ps_quote）：PowerShell 单引号串不做变量展开与子表达式
   求值，``$(...)``、``$var``、反引号转义全部失效；内部单引号按规则翻倍

为什么不用 `-EncodedCommand`：它只解决编码问题，不解决拼接问题。
"""

import ipaddress
import re
from typing import Any, Optional
from urllib.parse import urlparse

# ── 允许的字符集（白名单）──
_RULE_NAME_RE = re.compile(r"^[A-Za-z0-9_\-.]+$")
_IP_CHARS_RE = re.compile(r"^[0-9a-fA-F:.]+$")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# 形如 010.1.1.1 的「带前导零 IPv4」：Python 3.9.5+ 出于安全考虑会拒绝，
# 但不少业务系统确实会这么发，故单独识别后归一化（去掉前导零）。
_DOTTED_V4_RE = re.compile(r"^(\d{1,4})\.(\d{1,4})\.(\d{1,4})\.(\d{1,4})$")


class InvalidIP(ValueError):
    """非法 IP 输入"""


class InvalidRuleName(ValueError):
    """非法防火墙规则名"""


class InvalidURL(ValueError):
    """非法 URL"""


# ═══════════════════════════════════════════════════════════
#  IP
# ═══════════════════════════════════════════════════════════


def normalize_ip(raw: Any, allow_network: bool = False) -> str:
    """
    校验并归一化 IP（或 CIDR 网段）。

    - 合法：返回标准文本形态，只含 `[0-9a-f:./]`，天然无注入字符
    - 非法：抛 InvalidIP

    例：'113.118.113.77 ' -> '113.118.113.77'
        '192.168.001.1'  -> '192.168.1.1'
        '1.2.3.4/24'     -> 需 allow_network=True
    """
    if raw is None:
        raise InvalidIP("IP 不能为空")
    s = str(raw).strip()
    if not s:
        raise InvalidIP("IP 不能为空")
    if len(s) > 64:
        raise InvalidIP("IP 长度异常")
    # 快速字符白名单：把绝大多数注入串挡在解析之前
    if not _IP_CHARS_RE.match(s) and "/" not in s:
        raise InvalidIP(f"IP 含非法字符: {raw!r}")

    if "/" in s:
        if not allow_network:
            raise InvalidIP(f"这里不允许网段写法: {raw!r}")
        try:
            return str(ipaddress.ip_network(s, strict=False))
        except ValueError as e:
            raise InvalidIP(f"无效的网段: {raw!r}") from e

    try:
        return str(ipaddress.ip_address(s))
    except ValueError as e:
        # 兼容带前导零的 IPv4（010.1.1.1）：归一化后重试一次
        m = _DOTTED_V4_RE.match(s)
        if m:
            try:
                cleaned = ".".join(str(int(g)) for g in m.groups())
                return str(ipaddress.ip_address(cleaned))
            except ValueError:
                pass
        raise InvalidIP(f"无效的 IP 地址: {raw!r}") from e


def is_valid_ip(raw: Any, allow_network: bool = False) -> bool:
    try:
        normalize_ip(raw, allow_network=allow_network)
        return True
    except InvalidIP:
        return False


# ═══════════════════════════════════════════════════════════
#  PowerShell / 命令行转义
# ═══════════════════════════════════════════════════════════


def ps_quote(value: Any) -> str:
    """
    把值安全嵌入 PowerShell **单引号**字面量。

    单引号串在 PowerShell 中不做变量展开、不做子表达式求值，
    所以 `$(...)`、`$env:X`、反引号转义全部失效；内部单引号按规则翻倍。

    >>> ps_quote("a'; calc; #")
    "'a''; calc; #'"
    """
    return "'" + str(value).replace("'", "''") + "'"


def normalize_rule_name(raw: Any, prefix: str = "") -> str:
    """
    校验防火墙规则名。只允许 `[A-Za-z0-9_.-]`，可选强制前缀。
    规则名会被现网真实创建/删除，必须严格白名单。
    """
    s = "" if raw is None else str(raw).strip()
    if not s:
        raise InvalidRuleName("规则名不能为空")
    if len(s) > 200:
        raise InvalidRuleName("规则名过长")
    if not _RULE_NAME_RE.match(s):
        raise InvalidRuleName(f"规则名含非法字符: {raw!r}")
    if prefix and not s.startswith(prefix):
        raise InvalidRuleName(f"非 PortGuard 规则名，拒绝操作: {raw!r}")
    return s


# ═══════════════════════════════════════════════════════════
#  通用文本
# ═══════════════════════════════════════════════════════════


def safe_text(value: Any, maxlen: int = 200, default: str = "") -> str:
    """
    清洗「会进命令行参数或落库」的自由文本（如封禁原因 note）。
    去掉控制字符与换行，截断长度。注意：这只是一层净化，
    真正进命令行时仍必须用 ps_quote() 包裹。
    """
    if value is None:
        return default
    s = _CONTROL_RE.sub("", str(value))
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ").strip()
    if len(s) > maxlen:
        s = s[:maxlen]
    return s or default


#: `cli_note()` 允许保留的标点。**这是实测出来的白名单，别随意往里加**：
#: 2026-10-20 在 Windows 上用 `netsh advfirewall firewall add rule` 逐字符试过，
#: `A|B` 直接报「描述包含无效的字符，或具有无效的长度。」；`say "hi"` 里成对的
#: 双引号会打乱 netsh 自己的分词，报「应用程序包含无效的字符…」。其余常见标点
#: （`; & < > ( ) { } \ , % ! ^ ~ = # * ? [ ] + @ : / . -`）、汉字、带重音的拉丁字母
#: （Côte d'Ivoire）都能通过。为了不依赖「逐个试过」的结论，这里取**交集**：
#: 只保留确定安全的那几个，其余一律换成空格。
_NOTE_KEEP = frozenset(" -_.:/+,#()'")


def cli_note(value: Any, maxlen: int = 160, default: str = "") -> str:
    """
    清洗「要写进防火墙规则描述」的自由文本。

    为什么不能只用 `safe_text()`：它只去控制字符，拦不住 `|` 与成对双引号 ——
    而 **Server 2008 R2 上根本没有 New-NetFirewallRule**（Win8/2012 才提供），
    交付环境每次封禁都走 netsh 回退，netsh 会因此拒建规则，封禁整个失败。
    归属地来自离线库（`Korea, Republic of`、`Côte d'Ivoire` 这类），又长又带符号。

    策略：**非白名单字符换成空格**（不是删除 —— 删了会把前后两个词粘成一个），
    折叠连续空白，按字符数截断。宁可描述难看，也不能让描述挡住封禁。
    """
    if value is None:
        return default
    s = _CONTROL_RE.sub("", str(value))
    chars = []
    for ch in s:
        if ch.isalnum() or ch in _NOTE_KEEP:
            chars.append(ch)
        else:
            # 控制字符 / 非法标点 / 全角符号统一成空格
            chars.append(" ")
    text = " ".join("".join(chars).split())
    if len(text) > maxlen:
        text = text[:maxlen].rstrip()
    return text or default


def clamp_int(value: Any, low: int, high: int, default: int) -> int:
    """把外部传入的数值夹到安全区间（防止超大封禁时长等）"""
    try:
        v = int(value)
    except (TypeError, ValueError):
        return default
    return max(low, min(high, v))


# ═══════════════════════════════════════════════════════════
#  URL（用于离线库在线同步）
# ═══════════════════════════════════════════════════════════


def safe_https_url(raw: Any, allowed_hosts: Optional[list] = None, max_len: int = 500) -> str:
    """
    校验下载源 URL：必须 https、有主机名、无内嵌凭据。
    allowed_hosts 非空时强制主机白名单（防 SSRF / 被改成内网地址）。
    """
    s = "" if raw is None else str(raw).strip()
    if not s:
        raise InvalidURL("URL 不能为空")
    if len(s) > max_len:
        raise InvalidURL("URL 过长")
    p = urlparse(s)
    if p.scheme != "https":
        raise InvalidURL(f"仅允许 https 下载源: {s!r}")
    if not p.hostname:
        raise InvalidURL(f"URL 缺少主机名: {s!r}")
    if p.username or p.password:
        raise InvalidURL("URL 不允许内嵌凭据")
    if allowed_hosts:
        host = p.hostname.lower()
        if not any(host == h or host.endswith("." + h) for h in allowed_hosts):
            raise InvalidURL(f"不在允许的下载源白名单内: {host}")
    return s
