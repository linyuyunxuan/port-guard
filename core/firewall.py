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
import subprocess
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

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


def ip_token(ip: str) -> str:
    """把 IP / 网段压成规则名里可用的片段（IPv6 冒号与网段斜杠换成横线）"""
    safe = (ip or "").replace(":", "-").replace("/", "-").replace(" ", "")
    # 规则名要进命令行，这里再兜一层白名单清洗
    return "".join(ch for ch in safe if ch.isalnum() or ch in "-._")[:64] or "ip"


def rule_name(ip: str) -> str:
    """
    生成规则名：`PortGuard_Block_<ip>`

    **一个 IP 恒定一个名字**（2026-10-21 改）。原实现是
    `<ip>_<毫秒时间戳>_<随机后缀>`，每次封禁都新建一条规则 —— 真机实测同一个 IP
    堆了 10 条以上；而解封只按库里记的那一条名字去删，其余继续生效，于是同时出现
    两种反向事故：**解封了还封着**、以及规则越滚越多。

    固定名字之后：
    - 重复封禁不再产生新规则，只是刷新描述与到期时间
    - 解封按名字删，一定删干净
    - 对账（库里 active ↔ 系统里有规则）变成可以按 IP 一一对应
    """
    safe = (ip or "").replace(":", "-").replace("/", "-").replace(" ", "")
    # 规则名要进命令行，这里再兜一层白名单清洗
    return f"{RULE_PREFIX}{ip_token(safe)}"


#: 旧式规则名后缀：`_<10~16 位毫秒时间戳>_<4 位十六进制随机>`
_LEGACY_SUFFIX_RE = re.compile(r"^(?P<ip>.+)_\d{10,16}_[0-9a-f]{4}$")


def is_legacy_rule_name(name: str) -> bool:
    """是否是历史遗留的「带时间戳 + 随机后缀」规则名（需要迁移清理）"""
    if not name or not name.startswith(RULE_PREFIX):
        return False
    return bool(_LEGACY_SUFFIX_RE.match(name[len(RULE_PREFIX) :]))


def parse_ip_from_rule_name(name: str) -> str:
    """从规则名反解 IP（兼容旧的 `<ip>_<毫秒>_<随机>` 形式；IPv6 的横线不还原）"""
    if not name.startswith(RULE_PREFIX):
        return ""
    rest = name[len(RULE_PREFIX) :]
    m = _LEGACY_SUFFIX_RE.match(rest)
    if m:
        rest = m.group("ip")
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


def rule_exists(name: str) -> bool:
    """规则是否真的存在于系统防火墙里（按名字精确判定）。

    为什么必须有这一层：`netsh` / `New-NetFirewallRule` 返回 0 只代表命令被接受，
    不代表规则被策略放行。没有复核时，界面会显示「已封禁」而实际拦截不存在 ——
    对安全工具来说这是最坏的一种失败：人以为安全了。
    """
    if not name:
        return False
    try:
        if name in list_rule_names():
            return True
    except Exception:
        log.exception("回读规则列表失败，改用精确名探测 name=%s", name)
    # 列表可能因权限/解析失败而为空，再按精确名探一次（不解析本地化表头，只找名字）
    try:
        code, out = _run(["netsh", "advfirewall", "firewall", "show", "rule", f"name={name}"])
    except Exception:
        log.exception("精确名探测规则失败 name=%s", name)
        return False
    text = out or ""
    return code == 0 and name.lower() in text.lower()


def block_ip(ip: str, duration_sec: Optional[int] = None, note: str = "") -> Tuple[bool, str, str]:
    """
    创建入站阻止规则。
    返回 (成功, rule_name, 错误信息)

    `ip` 可以是单个 IP，也可以是 CIDR 网段（黑名单允许写网段）——
    网段会先过受保护范围的重叠判定，内网/回环/保留段一律拒绝。

    `note` 只是规则描述里的附注（来自封禁原因 / 归属地）。它**从不是封禁的前置条件**：
    描述被防火墙拒绝时会自动降级为「无描述」重建，绝不能因为一句人话让封禁失败。

    创建成功后会**回读复核规则确实存在**，读不到就再建一次；仍读不到按失败返回
    （调用方据此把封禁记录标成 failed，而不是显示「已封禁」却拦不住）。
    """
    if not is_admin():
        return False, "", "需要管理员权限才能修改 Windows 防火墙"

    # ── 唯一入口做校验：非法输入在这里就被拒绝，不产生任何命令 ──
    try:
        safe_ip = normalize_ip(ip, allow_network=True)
    except InvalidIP as e:
        log.warning("拒绝封禁：%s（输入 %r）", e, ip)
        return False, "", str(e)

    from core.rule_engine import is_never_ban_target

    if is_never_ban_target(safe_ip):
        return False, "", f"{safe_ip} 属于受保护地址段，拒绝封禁"

    name = rule_name(safe_ip)
    desc = build_description(safe_ip, duration_sec, note)

    with _exec_lock:
        reused = False
        # 规则名现在是「一 IP 一名」，重复封禁必须**复用**这条规则，不能新建第二条。
        # 优先原地改描述（没有解封窗口）；`Set-NetFirewallRule` 只有 Win8 / 2012+
        # 才有，2008 R2 上退回「删了重建」—— 那是一个毫秒级窗口，但也远好过
        # 「同一 IP 堆十几条规则、解封只删掉其中一条」。
        if rule_exists(name):
            reused = _update_desc_locked(name, desc)
            if not reused:
                ok_del, err_del = _remove_rule_locked(name)
                if not ok_del:
                    log.warning(
                        "续封前清理旧规则失败（继续尝试创建）ip=%s err=%s", safe_ip, err_del
                    )

        if reused:
            ok, err = True, ""
        else:
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
                    ok, err = True, ""
                else:
                    err = f"{err} | 无描述重试: {err2}"
            if not ok:
                log.error("封禁 %s 失败：%s", safe_ip, err[:400])
                return False, "", err[:600]

            # 复核：命令成功 ≠ 规则存在（可能被组策略/安全软件拦掉）
            if not rule_exists(name):
                log.error("封禁 %s 的规则写入后回读不到，重建一次（规则 %s）", safe_ip, name)
                _create_rule(name, safe_ip, "")
                if not rule_exists(name):
                    return (
                        False,
                        "",
                        f"防火墙命令返回成功，但回读不到规则 {name} —— 可能被组策略或安全软件拦截",
                    )

    # 最后一道、也是最容易被忽略的一道：**规则存在 ≠ 规则生效**。
    # 若 Windows 防火墙三个配置文件全关，规则写得再对也不参与过滤，
    # 攻击者该连还是连（真机复现过），所以这种情况必须判失败，不能报「已封禁」。
    if firewall_enabled(force=True) is False:
        state = profiles_state()
        log.error(
            "已写入规则 %s，但 Windows 防火墙未启用（%s），规则不会拦截任何流量",
            name,
            format_profiles(state),
        )
        return (
            False,
            name,
            "封禁规则已写入，但 Windows 防火墙处于关闭状态（"
            + format_profiles(state)
            + "），规则不会拦截任何流量。请在「封禁管理」页点「安全启用防火墙」，"
            "启用后本程序会自动补封。",
        )

    log.info("已封禁 %s（规则 %s）", safe_ip, name)
    return True, name, ""


def _update_desc_locked(safe_name: str, desc: str) -> bool:
    """
    原地更新规则描述（续封用）。**调用方必须已持 `_exec_lock`**。

    返回 True 表示已刷新、无需重建；False 表示本机不支持（2008 R2 没有
    `Set-NetFirewallRule`）或更新失败，调用方应退回「删了重建」。
    存在这条捷径的意义：续封时不留任何解封窗口。
    """
    if ps_cmdlet_missing():
        return False
    code, _ = _powershell(
        f"Set-NetFirewallRule -DisplayName {ps_quote(safe_name)} "
        f"-Description {ps_quote(desc)} -ErrorAction Stop"
    )
    return code == 0


def _remove_rule_locked(safe_name: str) -> Tuple[bool, str]:
    """删除单条规则。**调用方必须已持 `_exec_lock`**（threading.Lock 不可重入）。"""
    code, out = _powershell(
        f"Remove-NetFirewallRule -DisplayName {ps_quote(safe_name)} -ErrorAction SilentlyContinue"
    )
    if code == 0:
        return True, ""
    code2, out2 = _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={safe_name}"])
    if code2 == 0:
        return True, ""
    return False, f"PowerShell: {out.strip()[:200]} | netsh: {out2.strip()[:200]}"


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
        return _remove_rule_locked(safe_name)


def unblock_ip(
    ip: str,
    names: Optional[List[str]] = None,
    existing: Optional[Iterable[str]] = None,
) -> Tuple[bool, str, int]:
    """
    按 IP 解封：先删指定规则名，再兜底按 RemoteAddress 精确匹配删除。
    返回 (成功, 错误, 删除数量)

    `existing`：调用方已经列举好的规则名快照。不传就自己列一次。
    **批量解封必须传**：`list_active_rules()` 每次是一次 PowerShell（实测
    200~600ms）或一次 netsh，到期巡检一轮几十个 IP 就是几十次全量列举，
    巡检会从秒级涨到分钟级 —— 而它跑在 60 秒的定时器上，会越拖越积压。
    """
    if not is_admin():
        return False, "需要管理员权限才能修改 Windows 防火墙", 0

    try:
        safe_ip = normalize_ip(ip)
    except InvalidIP as e:
        return False, str(e), 0

    removed = 0
    errors: List[str] = []
    done: set = set()
    for n in names or []:
        if not n:
            continue
        ok, err = unblock_by_name(n)
        if ok:
            removed += 1
            done.add(n)
        else:
            errors.append(err)

    # 再把「同一 IP 的历史规则」一并删掉。
    # 2026-10-21 之前每次封禁都新建 `<ip>_<毫秒>_<随机>`，而解封只删库里记的那一条，
    # 其余规则继续生效 —— 真机上同一个 IP 堆了十几条，用户点了「解封」照样连不上。
    # 规则名能反解出 IP，这里按名字清干净，不依赖 PowerShell（2008 R2 也能跑）。
    target = ip_token(safe_ip)
    if existing is None:
        try:
            existing = list_rule_names()
        except Exception:
            log.exception("列举规则失败，跳过同 IP 清理 ip=%s", safe_ip)
            existing = []
    same_ip = [n for n in existing if n not in done and parse_ip_from_rule_name(n) == target]
    for n in same_ip:
        ok, err = unblock_by_name(n)
        if ok:
            removed += 1
            done.add(n)
        else:
            errors.append(f"{n}: {err}")

    if removed == 0:
        # 兜底：按远端地址删除（规则名反解不出来的情况，例如人工改过名字）
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


# ═══════════════════════════════════════════════════════════
#  防火墙是否真的开着（2026-10-21）
#
#  这是本轮最贵的一课：规则写得再正确，只要 Windows 防火墙的三个配置文件
#  （域 / 专用 / 公用）都是「关闭」，**没有任何规则会参与过滤** —— 攻击者照样
#  能连，而界面显示「已封禁」。真机复现：规则 Enabled=True / Inbound / Block /
#  RemoteAddress 正确、创建于 09:10:46，09:12:08 仍有 ESTABLISHED 连接。
#
#  所以「封禁成功」必须同时满足三件事：命令返回 0、规则回读存在、
#  **防火墙至少在生效**。少一件都不能叫封禁。
# ═══════════════════════════════════════════════════════════

PROFILE_KEYS = ("domain", "private", "public")
PROFILE_LABELS = {"domain": "域", "private": "专用", "public": "公用"}

#: 状态缓存秒数。封禁页每次刷新都会问一次，没必要每次都起一个 netsh 进程；
#: 但开关可能被用户在控制台里改，所以缓存时间要短，并且支持 force 强刷。
PROFILE_CACHE_SEC = 5.0

#: (取缓存的时刻, 解析结果)。解析结果 None 表示「读不出来」，不能当成关闭。
_profile_cache: Optional[Tuple[float, Optional[Dict[str, bool]]]] = None


def reset_profile_cache() -> None:
    """清掉防火墙开关状态缓存（测试、`--diag`、以及刚改过开关之后用）"""
    global _profile_cache
    _profile_cache = None


def parse_profiles_output(text: str) -> Optional[Dict[str, bool]]:
    """
    解析 `netsh advfirewall show allprofiles state` 的输出。

    为什么要手写解析：**Server 2008 R2 没有 `Get-NetFirewallProfile`**（和
    New-NetFirewallRule 一样是 Win8 / 2012 才有的），交付环境只能读 netsh 的
    本地化文本。中文是「状态  关闭 / 启用」，英文是「State  OFF / ON」，
    顺序固定为 域 → 专用 → 公用。

    读不出三段时返回 None —— **未知不等于关闭**，不能让一次解析失败把结果判成
    「防火墙没开」，那会把正常环境误报成不安全。
    """
    found: List[bool] = []
    for line in (text or "").splitlines():
        s = line.strip()
        if not s:
            continue
        low = s.lower()
        tokens = low.split()
        if not ("状态" in s or tokens[:1] == ["state"]):
            continue
        if "关闭" in s or "off" in tokens:
            found.append(False)
        elif "启用" in s or "on" in tokens:
            found.append(True)
    if len(found) < len(PROFILE_KEYS):
        return None
    return dict(zip(PROFILE_KEYS, found[: len(PROFILE_KEYS)]))


def profiles_state(force: bool = False) -> Optional[Dict[str, bool]]:
    """三个配置文件各自的启用状态。None = 读不出来（未知）。"""
    global _profile_cache
    now = time.monotonic()
    if not force and _profile_cache is not None and now - _profile_cache[0] < PROFILE_CACHE_SEC:
        return _profile_cache[1]
    code, out = _run(["netsh", "advfirewall", "show", "allprofiles", "state"])
    state = parse_profiles_output(out) if code == 0 else None
    _profile_cache = (now, state)
    return state


def firewall_enabled(force: bool = False) -> Optional[bool]:
    """
    防火墙当前是否会真正过滤流量。

    True = 至少一个配置文件开着（规则在那个 profile 上生效）
    False = **三个全关，规则完全不生效**（封禁必然失败）
    None = 读不出来，不下结论
    """
    state = profiles_state(force=force)
    if state is None:
        return None
    return any(state.values())


def format_profiles(state: Optional[Dict[str, bool]]) -> str:
    """`域=关 专用=关 公用=关` 这种一行摘要，用于告警文案与诊断"""
    if not state:
        return "读不出防火墙状态"
    return " ".join(f"{PROFILE_LABELS[k]}={'开' if state.get(k) else '关'}" for k in PROFILE_KEYS)


#: 防火墙开关的四种结论。界面文案（顶栏 / 封禁页）只认这四档，避免两处各写一套判断。
STATE_OK = "ok"
STATE_PARTIAL = "partial"
STATE_OFF = "off"
STATE_UNKNOWN = "unknown"


def state_verdict(state: Optional[Dict[str, bool]]) -> str:
    """把三档开关状态归成一个结论。

    分开成函数而不是在界面里 `sum(...)`：**「读不出来」必须与「全关」区分开** ——
    一次 netsh 解析失败判成「未开启」会把正常机器误报成不安全，用户很快就会
    学会无视这条提示，那时真正的「全关」也就没人看了。
    """
    if not state:
        return STATE_UNKNOWN
    on = sum(1 for v in state.values() if v)
    if on == len(state):
        return STATE_OK
    return STATE_PARTIAL if on else STATE_OFF


# ── 安全启用防火墙 ──────────────────────────────────────────────
#
#  直接把防火墙打开是有自锁风险的：这台机器上跑着 IIS(80/443)、SQL Server(1433)、
#  远程桌面(3389)，一旦入站默认变 Block 而这些端口没有放行规则，**远程会话立刻断**。
#  所以顺序必须是「先按当前监听端口建放行规则 → 再开总开关 → 回读确认」。
#
#  放行规则只覆盖「此刻正在监听」的端口，属于快照语义：之后新起的服务要再点一次
#  「安全启用 / 同步放行」。这是刻意取舍 —— 全放行等于没开防火墙。

ALLOW_PREFIX = "PortGuard_Allow_"

#: netstat 的两类行：`TCP  0.0.0.0:80  0.0.0.0:0  LISTENING  4`
#: UDP 没有状态列： `UDP  0.0.0.0:500  *:*  1234`
_LISTEN_TCP_RE = re.compile(r"^\s*TCP\s+(\S+)\s+\S+\s+LISTEN", re.IGNORECASE)
_UDP_LINE_RE = re.compile(r"^\s*UDP\s+(\S+)\s+\S+", re.IGNORECASE)


def parse_listen_ports(text: str) -> Tuple[List[int], List[int]]:
    """
    从 `netstat -ano` 输出里取「对外可达的监听端口」，返回 (tcp_ports, udp_ports)。

    只认通配/指定地址，**跳过回环**：`127.0.0.1:x` / `[::1]:x` 本来就外部不可达，
    给它们建放行规则等于白白多开一个洞。
    """
    tcp: set = set()
    udp: set = set()
    for line in (text or "").splitlines():
        m_tcp = _LISTEN_TCP_RE.match(line)
        m_udp = _UDP_LINE_RE.match(line)
        if m_tcp:
            bucket, laddr = tcp, m_tcp.group(1)
        elif m_udp:
            bucket, laddr = udp, m_udp.group(1)
        else:
            continue
        host, _, port = laddr.rpartition(":")
        if not port.isdigit():
            continue
        if host.startswith("127.") or host in ("[::1]", "::1"):
            continue
        bucket.add(int(port))
    return sorted(tcp), sorted(udp)


def listening_ports() -> Tuple[List[int], List[int]]:
    """本机当前正在监听的 (tcp, udp) 端口。读不到时返回空列表（调用方据此拒绝启用）"""
    code, out = _run(["netstat", "-ano"], timeout=30)
    if code != 0:
        return [], []
    return parse_listen_ports(out)


def _allow_rule_name(proto: str, port: int) -> str:
    return f"{ALLOW_PREFIX}{proto.upper()}_{int(port)}"


def _add_allow_rule(proto: str, port: int) -> Tuple[bool, str]:
    """放行单个端口（入站、任意配置文件）。调用方已持 _exec_lock。"""
    global _ps_cmdlet_missing
    name = _allow_rule_name(proto, port)
    errs: List[str] = []
    if not _ps_cmdlet_missing:
        code, out = _powershell(
            f"New-NetFirewallRule -DisplayName {ps_quote(name)} -Direction Inbound "
            f"-Action Allow -Protocol {proto.upper()} -LocalPort {int(port)} "
            f"-Profile Any -Enabled True -ErrorAction Stop | Out-Null"
        )
        if code == 0:
            return True, ""
        if _looks_like_missing_cmdlet(out):
            _ps_cmdlet_missing = True
        errs.append(out.strip()[:200])
    code2, out2 = _run(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={name}",
            "dir=in",
            "action=allow",
            f"protocol={proto.upper()}",
            f"localport={int(port)}",
            "profile=any",
            "enable=yes",
        ]
    )
    if code2 == 0:
        return True, ""
    errs.append(out2.strip()[:200])
    return False, " | ".join(errs)


def ensure_allow_rules() -> Dict[str, Any]:
    """
    给当前所有监听端口补齐放行规则（幂等：同名规则重复添加会被 netsh/PS 报错，
    所以先查存在性）。返回 {"tcp": [...], "udp": [...], "created": n, "failed": [...]}
    """
    tcp, udp = listening_ports()
    created: List[str] = []
    failed: List[str] = []
    existing: set = set()
    try:
        existing = set(list_rule_names())
    except Exception:
        log.exception("列举现有放行规则失败，按「都不存在」处理（重复添加只会报错，不会破坏）")
    with _exec_lock:
        for proto, ports in (("TCP", tcp), ("UDP", udp)):
            for port in ports:
                name = _allow_rule_name(proto, port)
                if name in existing:
                    continue
                ok, err = _add_allow_rule(proto, port)
                if ok:
                    created.append(name)
                else:
                    failed.append(f"{name}: {err}")
    return {"tcp": tcp, "udp": udp, "created": created, "failed": failed}


def enable_firewall() -> Tuple[bool, str, Dict[str, Any]]:
    """
    安全启用 Windows 防火墙：**先放行当前监听端口，再打开总开关，最后回读确认**。

    返回 (成功, 错误, 明细)。明细里带 profiles_before / profiles_after / created /
    failed，界面据此展示「放了哪些端口、还剩什么没放通」。

    已开启时直接返回成功（already=True），不改任何东西。
    """
    if not is_admin():
        return False, "需要管理员权限才能修改 Windows 防火墙", {}

    before = profiles_state(force=True)
    if before is not None and all(before.values()):
        return True, "", {"already": True, "profiles_before": before, "created": []}

    allow = ensure_allow_rules()
    if allow["failed"]:
        # 放行规则没建全就开总开关，可能把正在用的服务挡在外面 → 宁可不开。
        return (
            False,
            "有监听端口没能放行，为避免影响现有服务，未开启防火墙："
            + "；".join(allow["failed"][:5]),
            {"profiles_before": before, "created": allow["created"], "failed": allow["failed"]},
        )

    with _exec_lock:
        code, out = _run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"], timeout=60)
    detail: Dict[str, Any] = {
        "profiles_before": before,
        "created": allow["created"],
        "tcp": allow["tcp"],
        "udp": allow["udp"],
        "failed": [],
    }
    if code != 0:
        detail["output"] = (out or "").strip()[:300]
        return False, f"开启防火墙失败：{(out or '').strip()[:200]}", detail

    reset_profile_cache()
    after = profiles_state(force=True)
    detail["profiles_after"] = after
    if after is None:
        # 开关命令成功但读不出状态：不谎报成功，交由调用方提示复查
        return False, "已执行开启命令，但回读不到防火墙状态，请在防火墙控制台确认", detail
    if not any(after.values()):
        return (
            False,
            "已执行开启命令，但三个配置文件仍为关闭 —— 可能被组策略或安全软件（如火绒/360）接管",
            detail,
        )
    return True, "", detail


def remove_rules(names: List[str]) -> Tuple[int, List[str]]:
    """按名字批量删规则（只允许 PortGuard_Block_ 前缀，逐条走 unblock_by_name 的校验）"""
    removed = 0
    errors: List[str] = []
    for name in names or []:
        ok, err = unblock_by_name(name)
        if ok:
            removed += 1
        else:
            errors.append(f"{name}: {err}")
    return removed, errors


def legacy_rule_names() -> List[str]:
    """系统里存在的历史遗留规则名（带时间戳 + 随机后缀，一个 IP 可能好几条）"""
    try:
        return [n for n in list_rule_names() if is_legacy_rule_name(n)]
    except Exception:
        log.exception("列举历史规则失败")
        return []


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
