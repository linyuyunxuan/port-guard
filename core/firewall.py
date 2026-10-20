"""
PortGuard — Windows 防火墙执行器

封禁策略：
- 优先 PowerShell（New-NetFirewallRule），原生支持 IPv6
- 失败回退 netsh advfirewall
- 所有规则统一前缀 PortGuard_Block_，便于列举 / 批量解封 / 对账
- 规则名中把 IPv6 的冒号替换成横线，保证名称合法

安全约定（重要）：
**所有拼进命令行的值都必须先过 core.validators。**
- IP：normalize_ip() 归一化（非法直接拒绝，不产生任何命令）
- 自由文本（原因 / 描述）：cli_note() 净化 + ps_quote() 单引号字面量包裹
- 规则名：normalize_rule_name() 白名单校验

关于描述为什么单独净化（2026-10-20 实测）：`netsh advfirewall firewall add rule`
的 description 有自己的字符白名单，`|` 会让它报「描述包含无效的字符」，成对双引号
会打乱它自己的分词并报「应用程序包含无效的字符」。而 **Server 2008 R2 上没有
New-NetFirewallRule**（Win8 / Server 2012 起才有），交付环境每次封禁都走 netsh
回退 —— 归属地里的英文长名（`Korea, Republic of`、`Côte d'Ivoire`）一旦带上这类
符号，封禁就会整个失败。所以描述必须净化，且**失败时降级为无描述重建**。

原实现直接 f'... -RemoteAddress "{ip}"' 拼接，实测存在命令注入：
输入 `1.2.3.4"; Start-Process calc; #` 会让 PowerShell 真的执行后面的语句，
而封禁强制要求管理员权限 —— 等于在输入框打字即可提权执行命令。

注意：封禁/解封必须管理员权限。
"""

import ctypes
import datetime
import json
import re
import secrets
import subprocess
import threading
from typing import Dict, List, Optional, Tuple

from core.logger import get_logger
from core.validators import (
    InvalidIP,
    InvalidRuleName,
    cli_note,
    normalize_ip,
    normalize_rule_name,
    ps_quote,
)

log = get_logger(__name__)

RULE_PREFIX = "PortGuard_Block_"
_CREATE_NO_WINDOW = 0x08000000

_exec_lock = threading.Lock()


# ═══════════════════════════════════════════════════════════
#  基础
# ═══════════════════════════════════════════════════════════


def is_admin() -> bool:
    """当前进程是否具备管理员权限"""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run(cmd: List[str], timeout: int = 30) -> Tuple[int, str]:
    """执行命令并解码输出（Windows 中文环境依次尝试 mbcs / gbk / utf-8）"""
    try:
        p = subprocess.run(
            cmd, capture_output=True, timeout=timeout, check=False, creationflags=_CREATE_NO_WINDOW
        )
    except subprocess.TimeoutExpired:
        return -1, "命令执行超时"
    except FileNotFoundError as e:
        return -2, f"未找到命令: {e}"
    except Exception as e:
        return -3, f"命令执行失败: {e}"

    raw = (p.stdout or b"") + (p.stderr or b"")
    for enc in ("mbcs", "gbk", "utf-8"):
        try:
            return p.returncode, raw.decode(enc)
        except Exception:
            continue
    return p.returncode, raw.decode("utf-8", "replace")


def _powershell(script: str, timeout: int = 30) -> Tuple[int, str]:
    return _run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        timeout=timeout,
    )


def rule_name(ip: str, ts: Optional[int] = None) -> str:
    """
    生成规则名：PortGuard_Block_<ip>_<毫秒时间戳>_<随机后缀>
    原实现用秒级时间戳，同一 IP 同秒内重复封禁会重名（后者覆盖前者）。
    """
    ms = ts if ts is not None else int(datetime.datetime.now().timestamp() * 1000)
    safe = (ip or "").replace(":", "-").replace("/", "-").replace(" ", "")
    # 规则名要进命令行，这里再兜一层白名单清洗
    safe = "".join(ch for ch in safe if ch.isalnum() or ch in "-._")[:64] or "ip"
    return f"{RULE_PREFIX}{safe}_{ms}_{secrets.token_hex(2)}"


def parse_ip_from_rule_name(name: str) -> str:
    """从规则名反解 IP（IPv6 的横线还原为冒号需要外部判断，这里仅还原 IPv4）"""
    if not name.startswith(RULE_PREFIX):
        return ""
    rest = name[len(RULE_PREFIX) :]
    parts = rest.rsplit("_", 1)
    if len(parts) == 2 and len(parts[1]) <= 4:
        rest = parts[0]  # 去掉随机后缀
    parts = rest.rsplit("_", 1)
    if len(parts) == 2 and parts[1].isdigit():
        rest = parts[0]  # 去掉毫秒时间戳
    return rest


# ═══════════════════════════════════════════════════════════
#  封禁 / 解封
# ═══════════════════════════════════════════════════════════

#: 规则描述的最大长度。netsh 对 description 的长度限制很宽松（实测 8000 字符仍被
#: 接受，只是先报权限），真正的坑在字符集（见 `validators.cli_note`）。这里压到 160
#: 是为了让描述在防火墙控制台里一行可读 —— 描述只是给人看的附注，不是数据。
MAX_DESC_LEN = 160

#: 本机是否有 `New-NetFirewallRule`。**None = 还没探过**。
#: Server 2008 R2 没有这个 cmdlet（Win8 / Server 2012 才有），探测结果缓存起来，
#: 免得每次封禁都先跑一次注定失败的命令（约 0.3~0.5 秒）再回退 netsh。
_ps_cmdlet_missing: Optional[bool] = None


def reset_backend_probe() -> None:
    """清掉「本机有无 New-NetFirewallRule」的探测缓存（测试与 --diag 用）"""
    global _ps_cmdlet_missing
    _ps_cmdlet_missing = None


def ps_cmdlet_missing() -> bool:
    """本机是否确定缺 `New-NetFirewallRule`（尚未探测过时返回 False）"""
    return bool(_ps_cmdlet_missing)


def _looks_like_missing_cmdlet(out: str) -> bool:
    """判断 PowerShell 的报错是不是「没有这个命令」（而不是权限/策略问题）"""
    text = out or ""
    for marker in (
        "CommandNotFoundException",
        "识别为 cmdlet",
        "不是可识别的",
        "未被识别为",
        "is not recognized",
    ):
        if marker in text:
            return True
    return False


def build_description(ip: str, duration_sec: Optional[int] = None, note: str = "") -> str:
    """
    生成防火墙规则描述：`PortGuard 封禁 <ip> - <到期时间> - <原因>`。

    为什么把到期时间写进描述：**Windows 防火墙规则本身没有时长**（netsh 与
    New-NetFirewallRule 都没有到期参数），到期只能靠本程序的巡检删规则。
    写进描述后，管理员打开防火墙控制台就能看到这条规则什么时候该消失，
    而不是只能从 PortGuard 的库里查 —— 程序没在跑时这是唯一线索。
    永久封禁写「永久」，避免被误读成「到期时间未知」。
    """
    parts = [f"PortGuard 封禁 {ip}"]
    if duration_sec and int(duration_sec) > 0:
        try:
            until = datetime.datetime.now() + datetime.timedelta(seconds=int(duration_sec))
            parts.append(until.strftime("%Y-%m-%d %H:%M 到期"))
        except (OverflowError, OSError, ValueError):  # 极端时长不去猜，退化成永久
            parts.append("永久")
    else:
        parts.append("永久")
    clean_note = cli_note(note, 100)
    if clean_note:
        parts.append(clean_note)
    return cli_note(" - ".join(parts), MAX_DESC_LEN)


def _ps_new_rule(name: str, ip: str, desc: str) -> str:
    return (
        f"New-NetFirewallRule -DisplayName {ps_quote(name)} "
        + (f"-Description {ps_quote(desc)} " if desc else "")
        + f"-Direction Inbound -Action Block "
        f"-RemoteAddress {ps_quote(ip)} "
        f"-Profile Any -Enabled True -ErrorAction Stop | Out-Null"
    )


def _netsh_add(name: str, ip: str, desc: str) -> List[str]:
    cmd = [
        "netsh",
        "advfirewall",
        "firewall",
        "add",
        "rule",
        f"name={name}",
        "dir=in",
        "action=block",
        f"remoteip={ip}",
        "profile=any",
        "enable=yes",
    ]
    if desc:
        cmd.append(f"description={desc}")
    return cmd


def _create_rule(name: str, ip: str, desc: str) -> Tuple[bool, str]:
    """
    真正创建规则：PowerShell 优先，失败回退 netsh。返回 (成功, 错误)。
    调用方必须已持 `_exec_lock` 并已校验 ip / name / desc。
    """
    global _ps_cmdlet_missing
    errs: List[str] = []

    if not _ps_cmdlet_missing:
        code, out = _powershell(_ps_new_rule(name, ip, desc))
        if code == 0:
            return True, ""
        if _looks_like_missing_cmdlet(out):
            # 只在这种确定性信号下才缓存，避免一次偶发失败让后续封禁永远跳过 PS
            _ps_cmdlet_missing = True
            log.info("本机没有 New-NetFirewallRule（2008 R2 等旧系统），改用 netsh")
        errs.append(f"PowerShell: {out.strip()[:300]}")

    code2, out2 = _run(_netsh_add(name, ip, desc))
    if code2 == 0:
        return True, ""
    errs.append(f"netsh: {out2.strip()[:300]}")
    return False, " | ".join(errs)


def block_ip(ip: str, duration_sec: Optional[int] = None, note: str = "") -> Tuple[bool, str, str]:
    """
    创建入站阻止规则。
    返回 (成功, rule_name, 错误信息)

    `note` 只是规则描述里的附注（来自封禁原因 / 归属地）。它**从不是封禁的前置条件**：
    描述被防火墙拒绝时会自动降级为「无描述」重建，绝不能因为一句人话让封禁失败。
    """
    if not is_admin():
        return False, "", "需要管理员权限才能修改 Windows 防火墙"

    # ── 唯一入口做校验：非法输入在这里就被拒绝，不产生任何命令 ──
    try:
        safe_ip = normalize_ip(ip)
    except InvalidIP as e:
        log.warning("拒绝封禁：%s（输入 %r）", e, ip)
        return False, "", str(e)

    from core.rule_engine import is_never_ban

    if is_never_ban(safe_ip):
        return False, "", f"{safe_ip} 属于受保护地址段，拒绝封禁"

    name = rule_name(safe_ip)
    desc = build_description(safe_ip, duration_sec, note)

    with _exec_lock:
        ok, err = _create_rule(name, safe_ip, desc)
        if not ok and desc:
            # 描述是装饰：降级为无描述再试一次。
            # 不降级的话，攻击者只要让归属地/规则名带上 `|` 或成对引号，
            # 就能让自己的封禁静默失败（这是可被利用的绕过）。
            ok2, err2 = _create_rule(name, safe_ip, "")
            if ok2:
                log.warning(
                    "规则描述被防火墙拒绝，已改为无描述创建 ip=%s 描述=%r 原因=%s",
                    safe_ip,
                    desc,
                    err[:200],
                )
                return True, name, ""
            err = f"{err} | 无描述重试: {err2}"
        if ok:
            log.info("已封禁 %s（规则 %s）", safe_ip, name)
            return True, name, ""

        log.error("封禁 %s 失败：%s", safe_ip, err[:400])
        return False, "", err[:600]


def unblock_by_name(name: str) -> Tuple[bool, str]:
    if not is_admin():
        return False, "需要管理员权限才能修改 Windows 防火墙"
    # 只允许删自己创建的规则，且规则名必须通过白名单校验
    try:
        safe_name = normalize_rule_name(name, prefix=RULE_PREFIX)
    except InvalidRuleName as e:
        log.warning("拒绝删除规则：%s（输入 %r）", e, name)
        return False, str(e)

    with _exec_lock:
        code, out = _powershell(
            f"Remove-NetFirewallRule -DisplayName {ps_quote(safe_name)} "
            f"-ErrorAction SilentlyContinue"
        )
        if code == 0:
            return True, ""
        code2, out2 = _run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={safe_name}"]
        )
        if code2 == 0:
            return True, ""
        return False, f"PowerShell: {out.strip()[:200]} | netsh: {out2.strip()[:200]}"


def unblock_ip(ip: str, names: Optional[List[str]] = None) -> Tuple[bool, str, int]:
    """
    按 IP 解封：先删指定规则名，再兜底按 RemoteAddress 精确匹配删除。
    返回 (成功, 错误, 删除数量)
    """
    if not is_admin():
        return False, "需要管理员权限才能修改 Windows 防火墙", 0

    try:
        safe_ip = normalize_ip(ip)
    except InvalidIP as e:
        return False, str(e), 0

    removed = 0
    errors = []
    for n in names or []:
        if not n:
            continue
        ok, err = unblock_by_name(n)
        if ok:
            removed += 1
        else:
            errors.append(err)

    if removed == 0:
        # 兜底：按远端地址删除所有 PortGuard 规则
        with _exec_lock:
            ps = (
                f"$r = Get-NetFirewallRule -DisplayName {ps_quote(RULE_PREFIX + '*')} "
                f"-ErrorAction SilentlyContinue | Where-Object {{ "
                f"(Get-NetFirewallRule -DisplayName $_.DisplayName | "
                f"Get-NetFirewallAddressFilter).RemoteAddress -contains {ps_quote(safe_ip)} }}; "
                f'if ($r) {{ $r | Remove-NetFirewallRule; "removed" }} else {{ "none" }}'
            )
            code, out = _powershell(ps)
            if code == 0 and "removed" in out:
                removed += 1
            elif code != 0:
                errors.append(out.strip()[:200])

    return (removed > 0), " | ".join(errors), removed


def list_active_rules() -> List[Dict]:
    """列出所有 PortGuard 规则（PS 读不到时回退 netsh）"""
    if ps_cmdlet_missing():
        return _list_rules_netsh()
    ps = (
        f"Get-NetFirewallRule -DisplayName {ps_quote(RULE_PREFIX + '*')} "
        f"-ErrorAction SilentlyContinue | "
        f"Select-Object DisplayName,Enabled,Direction,Action | ConvertTo-Json -Compress"
    )
    code, out = _powershell(ps, timeout=60)
    if code != 0 or not out.strip():
        return _list_rules_netsh()
    text = out.strip()
    # 取最后一个 JSON 片段（PowerShell 可能输出多余内容）
    start = text.find("[")
    if start < 0:
        start = text.find("{")
    if start < 0:
        return _list_rules_netsh()
    try:
        data = json.loads(text[start:])
    except Exception:
        return _list_rules_netsh()
    if isinstance(data, dict):
        return [data]
    return data if isinstance(data, list) else []


#: 从 netsh 文本输出里抓规则名。规则名是白名单字符集 `[A-Za-z0-9_.-]`，
#: 而描述里是中文「PortGuard 封禁 …」，所以正则不会把描述误认成名字。
_RULE_NAME_IN_TEXT = re.compile(re.escape(RULE_PREFIX) + r"[A-Za-z0-9_.\-]+")


def _list_rules_netsh() -> List[Dict]:
    """
    netsh 回退：Server 2008 R2 上没有 `Get-NetFirewallRule`。

    **不解析表头**：netsh 的输出是本地化的（「规则名:」/「Rule Name:」随语言变），
    直接在原文里抓 `PortGuard_Block_…` 就够了。

    这条不只是「让列表能显示」：`ban_service.reconcile()` 拿空列表当「规则都不存在」，
    在 2008 R2 上会把库里所有 active 记录标成已解封，而防火墙规则还在 ——
    记录没了、也没人再巡检解封，就成了无主规则。
    """
    code, out = _run(
        ["netsh", "advfirewall", "firewall", "show", "rule", f"name={RULE_PREFIX}*"],
        timeout=60,
    )
    if code != 0:
        return []
    names: List[str] = []
    for m in _RULE_NAME_IN_TEXT.findall(out or ""):
        if m not in names:
            names.append(m)
    return [{"DisplayName": n} for n in names]


def list_rule_names() -> List[str]:
    return [str(r.get("DisplayName", "")) for r in list_active_rules() if r.get("DisplayName")]


def unblock_all() -> Tuple[bool, int, str]:
    """一键解封所有 PortGuard 规则，返回 (成功, 数量, 错误)"""
    if not is_admin():
        return False, 0, "需要管理员权限才能修改 Windows 防火墙"
    before = list_rule_names()
    n = len(before)
    with _exec_lock:
        code, out = 1, "本机没有 New-NetFirewallRule"
        if not ps_cmdlet_missing():
            code, out = _powershell(
                f"Get-NetFirewallRule -DisplayName {ps_quote(RULE_PREFIX + '*')} "
                f"-ErrorAction SilentlyContinue | Remove-NetFirewallRule",
                timeout=120,
            )
        if code != 0:
            # 2008 R2 没有 Get/Remove-NetFirewallRule：netsh 的 name= 支持通配符，
            # 一次删掉所有同前缀规则（仍然只动 PortGuard_Block_ 前缀）
            code, alt = _run(
                ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_PREFIX}*"],
                timeout=120,
            )
            if code != 0:
                return False, 0, (alt or out).strip()[:300]
    return True, n, ""


def firewall_available() -> bool:
    """
    防火墙命令是否可用（不需要管理员也能查）。

    原实现探的是 `Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue`，
    但 `-ErrorAction SilentlyContinue` 会把「命令不存在」一起吞掉、退出码仍是 0
    → **永远返回 True**，等于没检查。改为以 netsh 为准：它从 XP 起就有，
    而 New-NetFirewallRule 是 Win8 / Server 2012 才加的，不能拿它当门槛。
    """
    code, _ = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
    return code == 0


def open_admin_restart() -> Tuple[bool, str]:
    """以管理员身份重新启动当前程序（源码运行时重启 python main.py）"""
    import os
    import sys

    from core.config import project_dir

    try:
        if getattr(sys, "frozen", False):
            target, params = sys.executable, ""
        else:
            target = sys.executable
            main_py = os.path.join(project_dir(), "main.py")
            if '"' in main_py:
                return False, "程序路径包含引号，拒绝提权重启"
            params = f'"{main_py}"'
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", target, params, project_dir(), 1)
        return (ret > 32), "" if ret > 32 else f"提权失败，错误码 {ret}"
    except Exception as e:
        return False, str(e)
