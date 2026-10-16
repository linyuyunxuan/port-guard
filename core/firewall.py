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
- 自由文本（原因等）：safe_text() 净化 + ps_quote() 单引号字面量包裹
- 规则名：normalize_rule_name() 白名单校验

原实现直接 f'... -RemoteAddress "{ip}"' 拼接，实测存在命令注入：
输入 `1.2.3.4"; Start-Process calc; #` 会让 PowerShell 真的执行后面的语句，
而封禁强制要求管理员权限 —— 等于在输入框打字即可提权执行命令。

注意：封禁/解封必须管理员权限。
"""

import ctypes
import datetime
import json
import secrets
import subprocess
import threading
from typing import Dict, List, Optional, Tuple

from core.logger import get_logger
from core.validators import (
    InvalidIP,
    InvalidRuleName,
    normalize_ip,
    normalize_rule_name,
    ps_quote,
    safe_text,
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


def block_ip(ip: str, duration_sec: Optional[int] = None, note: str = "") -> Tuple[bool, str, str]:
    """
    创建入站阻止规则。
    返回 (成功, rule_name, 错误信息)
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
    desc = safe_text(f"PortGuard 自动封禁 {safe_ip}" + (f" · {note}" if note else ""), 200)

    with _exec_lock:
        # 优先 PowerShell。单引号字面量 + 归一化后的 IP，双重保险。
        ps = (
            f"New-NetFirewallRule -DisplayName {ps_quote(name)} "
            f"-Description {ps_quote(desc)} -Direction Inbound -Action Block "
            f"-RemoteAddress {ps_quote(safe_ip)} "
            f"-Profile Any -Enabled True -ErrorAction Stop | Out-Null"
        )
        code, out = _powershell(ps)
        if code == 0:
            log.info("已封禁 %s（规则 %s）", safe_ip, name)
            return True, name, ""

        # 回退 netsh（参数以列表传入，subprocess 不做 shell 解析，天然安全）
        netsh = [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={name}",
            "dir=in",
            "action=block",
            f"remoteip={safe_ip}",
            "profile=any",
            "enable=yes",
            f"description={desc}",
        ]
        code2, out2 = _run(netsh)
        if code2 == 0:
            log.info("已封禁 %s（规则 %s，netsh 回退）", safe_ip, name)
            return True, name, ""

        log.error("封禁 %s 失败：ps=%s | netsh=%s", safe_ip, out.strip()[:200], out2.strip()[:200])
        return False, "", f"PowerShell: {out.strip()[:300]} | netsh: {out2.strip()[:300]}"


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
    """列出所有 PortGuard 规则"""
    ps = (
        f"Get-NetFirewallRule -DisplayName {ps_quote(RULE_PREFIX + '*')} "
        f"-ErrorAction SilentlyContinue | "
        f"Select-Object DisplayName,Enabled,Direction,Action | ConvertTo-Json -Compress"
    )
    code, out = _powershell(ps, timeout=60)
    if code != 0 or not out.strip():
        return []
    text = out.strip()
    # 取最后一个 JSON 片段（PowerShell 可能输出多余内容）
    start = text.find("[")
    if start < 0:
        start = text.find("{")
    if start < 0:
        return []
    try:
        data = json.loads(text[start:])
    except Exception:
        return []
    if isinstance(data, dict):
        return [data]
    return data if isinstance(data, list) else []


def list_rule_names() -> List[str]:
    return [str(r.get("DisplayName", "")) for r in list_active_rules() if r.get("DisplayName")]


def unblock_all() -> Tuple[bool, int, str]:
    """一键解封所有 PortGuard 规则，返回 (成功, 数量, 错误)"""
    if not is_admin():
        return False, 0, "需要管理员权限才能修改 Windows 防火墙"
    before = list_rule_names()
    n = len(before)
    with _exec_lock:
        code, out = _powershell(
            f"Get-NetFirewallRule -DisplayName {ps_quote(RULE_PREFIX + '*')} "
            f"-ErrorAction SilentlyContinue | Remove-NetFirewallRule",
            timeout=120,
        )
    if code != 0:
        return False, 0, out.strip()[:300]
    return True, n, ""


def firewall_available() -> bool:
    """防火墙命令是否可用（不需要管理员也能查）"""
    code, _ = _powershell(
        "Get-Command New-NetFirewallRule -ErrorAction SilentlyContinue | Out-Null"
    )
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
