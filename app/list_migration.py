"""PortGuard — 黑 / 白名单并入「拦截 / 放行」规则，以及防火墙校准

2026-10-23 用户要求：
  ① 加入黑名单的 IP 无视其他规则直接拦截；
  ② 加入白名单的 IP 无视其他规则直接放行；
  ③ 封禁记录显示归属地；
  ④ 「新增规则」里也能选放行 / 拦截，把独立的黑 / 白名单取消掉。

①②③ 的判定在 `core/rule_engine` 与 `gui/page_bans`，本模块负责 ④ 里
**最容易被做错的那一半**：名单不是「删掉两个文件」就完事。

名单背后挂着两样东西：
  · 黑名单 → 每个条目在防火墙里有一条**永久**阻止规则（`app.blacklist_service`）；
  · 白名单 → 语义是「永不封禁」，但已经被封的 IP 仍被防火墙挡着。
所以直接把名单文件清空，等于「已拦的 IP 全部放出去」，而界面上看不到任何提示。

于是这里做两件事：
1. `migrate_lists_to_rules()` —— 把名单条目**逐条**翻译成等价的规则
   （黑名单 → `action=block`，白名单 → `action=allow` + `exempt_only`），
   备份原文件后清空名单；幂等，名单为空时什么都不做。
2. `calibrate_firewall()` —— 让防火墙状态追上规则：block 目标没有封禁就补封
   （永久），allow 目标有封禁就补解封。保存规则后与启动时各跑一次。

为什么校准是「全量对齐」而不是「按 diff 增量」：规则可以被改名、改端口、
停用、删除、导入，增量 diff 要处理的状态组合太多，漏一种就会留下「规则说拦、
防火墙没拦」的静默漏洞。全量对齐是幂等的，多跑几次也只有一个结果。
"""

import os
import secrets
import shutil
import time
from typing import Any, Dict, List, Optional, Tuple

from app import audit, ban_service
from core import firewall
from core.config import backup_dir, blacklist_path, rules_path, whitelist_path
from core.database import find_active_ban_by_ip
from core.logger import get_logger

log = get_logger(__name__)

#: 迁移出来的规则名前缀。界面上要一眼看出这条规则从哪来
BLOCK_PREFIX = "拦截"
ALLOW_PREFIX = "放行"
MIGRATE_NOTE = "由旧黑名单迁移（2026-10-23 名单并入规则）"
MIGRATE_NOTE_WHITE = "由旧白名单迁移（2026-10-23 名单并入规则）"
#: 迁移出来的规则 id 前缀，便于按来源筛选与幂等判重
BLOCK_ID_PREFIX = "blk-"
ALLOW_ID_PREFIX = "alw-"

#: 拦截规则封多久：0 = 永久。规则是「策略」，策略还在就该一直生效，
#: 而不是每过一小时让攻击者进来一次。要临时放开就停用/删除规则。
PERMANENT = 0
#: 校准单次最多处理多少条，避免一次启动写上百条防火墙规则（netsh 每条几十~几百毫秒）
CALIBRATE_LIMIT = 200


# ═══════════════════════════════════════════════════════════
#  工具
# ═══════════════════════════════════════════════════════════


def precise_ip(entry: str) -> Optional[str]:
    """把规则里的 cidrs 条目归一成**单个** IP；网段返回 None。

    只有精确 IP 才能「按条目补封 / 补解封」——
    `1.2.3.0/24` 没法逐条封（那是 256 个 IP），也不会有人希望校准的时候
    一次写 256 条规则。网段条目在引擎里照常实时生效，只是不做防火墙预置。
    """
    import ipaddress

    v = str(entry or "").strip()
    if not v:
        return None
    try:
        net = ipaddress.ip_network(v, strict=False)
    except Exception:
        return None
    if net.num_addresses != 1:
        return None
    return str(net.network_address)


def _backup_files(paths: List[str]) -> str:
    """把即将改动的文件复制到 `data/backup/lists-migrate-<ts>/`，返回该目录。

    名单文件一旦迁移就被清空，没有备份的话「迁移前到底有哪些 IP」将永久丢失。
    """
    stamp = time.strftime("%Y%m%d-%H%M%S")
    dest = os.path.join(backup_dir(), f"lists-migrate-{stamp}")
    os.makedirs(dest, exist_ok=True)
    for p in paths:
        if p and os.path.exists(p):
            try:
                shutil.copy2(p, os.path.join(dest, os.path.basename(p)))
            except Exception:
                log.exception("备份名单文件失败：%s", p)
    return dest


def _new_id(prefix: str) -> str:
    return prefix + secrets.token_hex(3)


def _rule_signature(action: str, cidr: str) -> Tuple[str, str]:
    return (action, str(cidr or "").strip())


def _match_of(rule: Dict[str, Any]) -> Dict[str, Any]:
    """取规则里的 `match` 字典；缺失或类型不对时返回空字典

    写成函数而不是 `x if isinstance(x, dict) else {}`：`Dict.get()` 返回
    `Any | None`，mypy 对这种「三元表达式里做 isinstance 收窄」会保留原始
    联合类型，于是拿到 `Any | dict | None`，后面 `.get()` 直接报 union-attr。
    """
    raw = rule.get("match")
    if not isinstance(raw, dict):
        return {}
    return raw


def _existing_signatures(rules: List[Dict[str, Any]]) -> set:
    """已有规则里「动作 + 网段条目」的组合，用来判重（迁移可能被重复触发）"""
    sigs = set()
    for r in rules:
        if not isinstance(r, dict):
            continue
        act = str(r.get("action") or "")
        if act == "whitelist":  # 旧名，语义等同 allow
            act = "allow"
        match = _match_of(r)
        for c in match.get("cidrs") or []:
            sigs.add(_rule_signature(act, str(c)))
    return sigs


def _make_rule(action: str, entry: str) -> Dict[str, Any]:
    """名单条目 → 规则。字段与 `gui.region_rules.RegionRuleDialog.values()` 对齐"""
    block = action == "block"
    rule: Dict[str, Any] = {
        "id": _new_id(BLOCK_ID_PREFIX if block else ALLOW_ID_PREFIX),
        "name": f"{BLOCK_PREFIX if block else ALLOW_PREFIX}：{entry}",
        "enabled": True,
        "action": action,
        # 名单语义是「这个 IP 本身」，与端口无关 → 全部端口
        "target_ports": [],
        "score": 100 if block else 90,
        "factor": 0.3,
        "match": {
            "provinces": [],
            "cities": [],
            "countries": [],
            "isp": [],
            "cidrs": [entry],
            "ip_keywords": [],
            "only_china": False,
        },
        "note": MIGRATE_NOTE if block else MIGRATE_NOTE_WHITE,
    }
    if not block:
        # 白名单 = 仅豁免，不做「未命中即拦截」的默认拒绝半边。
        # 不写这个标记的话，编译期会对「放行规则没填端口」告警 —— 那是给
        # 手写规则的提醒，对迁移来的条目属于噪音（它的语义本来就是只豁免）。
        rule["exempt_only"] = True
    return rule


# ═══════════════════════════════════════════════════════════
#  迁移
# ═══════════════════════════════════════════════════════════


def migrate_lists_to_rules(actor: Optional[str] = None) -> Dict[str, Any]:
    """把黑 / 白名单条目并入规则，然后清空名单文件。

    返回摘要（见 `format_migrate`）。**幂等**：名单为空时直接返回 `migrated=0`，
    不会重复生成规则，也不写审计 —— 启动时每次都会调它，不能每次都留一条记录。
    """
    from core.rule_engine import _IPSet, get_engine

    res: Dict[str, Any] = {
        "black": 0,
        "white": 0,
        "migrated": 0,
        "skipped": [],
        "backup": "",
        "error": "",
    }
    eng = get_engine()
    try:
        eng.load_lists()
        blacks = list(eng.blacklist.entries())
        whites = list(eng.whitelist.entries())
    except Exception as e:
        log.exception("读取旧名单失败，跳过迁移")
        res["error"] = f"读取旧名单失败：{e}"
        return res
    if not blacks and not whites:
        return res
    res["black"], res["white"] = len(blacks), len(whites)

    cfg_now = eng.get_config()
    rules: List[Dict[str, Any]] = [
        dict(r) for r in (cfg_now.get("region_rules") or []) if isinstance(r, dict)
    ]
    seen = _existing_signatures(rules)

    def add(action: str, entries: List[str]) -> int:
        n = 0
        for entry in entries:
            e = str(entry or "").strip()
            if not e or _rule_signature(action, e) in seen:
                res["skipped"].append(f"{action}:{e}")
                continue
            rules.append(_make_rule(action, e))
            seen.add(_rule_signature(action, e))
            n += 1
        return n

    # 先备份「即将被改的三份文件」—— 规则文件也要备份：迁移会往里追加规则，
    # 万一用户不认这个结果，能整份退回去。
    res["backup"] = _backup_files([blacklist_path(), whitelist_path(), rules_path()])

    res["migrated"] = add("block", blacks) + add("allow", whites)

    cfg_now["region_rules"] = rules
    try:
        eng.save_config(cfg_now)
        # 同上：不要再 reload()（会把内存名单冲成磁盘上的旧内容）。
        # save_config 内部已经写完文件并编译了新配置。
        # 规则写成功之后才清空名单：写规则失败却清了名单 = 策略凭空消失
        eng.blacklist = _IPSet()
        eng.whitelist = _IPSet()
        eng.save_lists()
    except Exception as e:
        log.exception("名单并入规则失败（名单保持原样，未清空）")
        res["error"] = f"写入规则失败：{e}"
        audit.record(
            audit.ACTION_LIST_MIGRATE,
            actor=actor or audit.ACTOR_SYSTEM,
            target_type="list",
            summary=f"黑白名单并入规则失败：{e}",
            result=audit.RESULT_FAIL,
            detail=res["error"],
        )
        return res

    audit.record(
        audit.ACTION_LIST_MIGRATE,
        actor=actor or audit.ACTOR_SYSTEM,
        target_type="list",
        summary=(
            f"黑白名单已并入规则：黑名单 {res['black']} 条 → 拦截规则、"
            f"白名单 {res['white']} 条 → 放行规则（名单文件已清空）"
        ),
        before={
            "blacklist": sorted(blacks),
            "whitelist": sorted(whites),
        },
        after={
            "region_rules": len(rules),
            "migrated": res["migrated"],
            "backup": res["backup"],
        },
    )
    log.warning(
        "名单并入规则完成：黑名单 %d 条 / 白名单 %d 条，新增规则 %d 条，备份 %s",
        res["black"],
        res["white"],
        res["migrated"],
        res["backup"],
    )
    return res


# ═══════════════════════════════════════════════════════════
#  单条拦截规则（监控页右键入口）
# ═══════════════════════════════════════════════════════════


def add_block_rule(entry: str, actor: Optional[str] = None, name: str = "") -> Dict[str, Any]:
    """往访问规则里追加一条「拦截」规则，保存并热重载；返回该规则。

    幂等：已经有一条拦截规则覆盖同一个条目时直接返回它 ——
    右键连点两次不该产生两条一模一样的规则（会在规则页里堆成一片）。
    """
    from core.rule_engine import get_engine

    v = str(entry or "").strip()
    eng = get_engine()
    cfg_now = eng.get_config()
    rules: List[Dict[str, Any]] = [
        dict(r) for r in (cfg_now.get("region_rules") or []) if isinstance(r, dict)
    ]
    for r in rules:
        match = _match_of(r)
        if str(r.get("action") or "") == "block" and v in [
            str(c) for c in match.get("cidrs") or []
        ]:
            return r
    rule = _make_rule("block", v)
    if name:
        rule["name"] = name
    rules.append(rule)
    cfg_now["region_rules"] = rules
    # 只走 save_config（它内部会写盘 + 编译新配置），**不要**再调 reload()：
    # reload 会连名单一起从磁盘重读，把内存里刚加进名单、还没来得及落盘
    # 的条目冲掉（`save_lists` 失败或被测用例 stub 掉时尤其明显）。
    eng.save_config(cfg_now)
    log.warning("新增拦截规则：%s（id=%s）", v, rule["id"])
    return rule


# ═══════════════════════════════════════════════════════════
#  防火墙校准
# ═══════════════════════════════════════════════════════════


def rule_targets() -> Tuple[List[str], List[str], List[str]]:
    """收集规则里的「拦截目标 / 放行目标 / 无法预置的网段」。

    只收启用中的 block / allow 规则、且 cidrs 是精确 IP 的条目。
    返回 (blocks, allows, networks)，已去重保序。
    """
    from core.rule_engine import get_engine

    cfg_now = get_engine().get_config()
    blocks: List[str] = []
    allows: List[str] = []
    nets: List[str] = []
    for r in cfg_now.get("region_rules") or []:
        if not isinstance(r, dict) or not r.get("enabled", True):
            continue
        act = str(r.get("action") or "").strip().lower()
        if act == "whitelist":  # 旧名
            act = "allow"
        if act not in ("block", "allow"):
            continue
        match = _match_of(r)
        for c in match.get("cidrs") or []:
            ip = precise_ip(str(c))
            if ip is None:
                label = f"{act}:{str(c).strip()}"
                if label not in nets:
                    nets.append(label)
                continue
            bucket = blocks if act == "block" else allows
            if ip not in bucket:
                bucket.append(ip)
    # 同一 IP 既被拦截又被放行时以拦截为准（与引擎里 block 优先一致）：
    # 先补封、后解封的顺序会把它解除，所以必须从放行目标里剔掉。
    allows = [ip for ip in allows if ip not in blocks]
    return blocks, allows, nets


def calibrate_firewall(actor: Optional[str] = None, limit: int = CALIBRATE_LIMIT) -> Dict[str, Any]:
    """让防火墙追上「拦截 / 放行」规则：缺封的补封，该放的补放。

    在后台线程调用（netsh 每条几十~几百毫秒）。单条失败不影响其它条目。
    """
    res: Dict[str, Any] = {
        "admin": firewall.is_admin(),
        "banned": [],
        "already": [],
        "failed": [],
        "unbanned": [],
        "unban_failed": [],
        "skipped_networks": [],
        "total": 0,
    }
    try:
        blocks, allows, nets = rule_targets()
    except Exception as e:
        log.exception("读取规则目标失败")
        res["failed"] = [("", f"读取规则失败：{e}")]
        return res
    res["skipped_networks"] = nets
    res["total"] = len(blocks) + len(allows)
    if not blocks and not allows:
        return res
    if not res["admin"]:
        # 无管理员权限时**不假装成功**（同 blacklist_service 的教训：
        # 假成功会让用户以为规则已经拦住了）
        res["failed"] = [(ip, "需要管理员权限才能修改 Windows 防火墙") for ip in blocks]
        return res

    who = actor or audit.actor_local()
    for ip in blocks[:limit]:
        try:
            rec = find_active_ban_by_ip(ip)
        except Exception as e:
            log.exception("校准：查询封禁状态失败 ip=%s", ip)
            res["failed"].append((ip, str(e)))
            continue
        if rec is not None:
            res["already"].append(ip)
            continue
        try:
            ban_id, err = ban_service.execute(
                ip,
                score=100,
                reason="命中拦截规则（规则维护）",
                duration_sec=PERMANENT,
                source="rule",
                actor=who,
            )
        except Exception as e:
            log.exception("校准：补封异常 ip=%s", ip)
            res["failed"].append((ip, str(e)))
            continue
        if ban_id is None:
            res["failed"].append((ip, err or "封禁失败"))
        else:
            res["banned"].append(ip)

    for ip in allows[:limit]:
        try:
            rec = find_active_ban_by_ip(ip)
        except Exception as e:
            log.exception("校准：查询封禁状态失败 ip=%s", ip)
            res["unban_failed"].append((ip, str(e)))
            continue
        if rec is None:
            continue
        try:
            ok, err = ban_service.unban(rec, actor=who)
        except Exception as e:
            log.exception("校准：解封异常 ip=%s", ip)
            res["unban_failed"].append((ip, str(e)))
            continue
        if ok:
            res["unbanned"].append(ip)
        else:
            res["unban_failed"].append((ip, err or "解封失败"))

    if res["banned"] or res["unbanned"] or res["failed"] or res["unban_failed"]:
        audit.record(
            audit.ACTION_RULE_ENFORCE,
            actor=who,
            target_type="rule",
            summary=(
                f"规则联动防火墙：补封 {len(res['banned'])} 个、"
                f"放行解封 {len(res['unbanned'])} 个、失败 {len(res['failed'])} 个"
            ),
            before={"blocks": blocks[:limit], "allows": allows[:limit]},
            after={
                "banned": res["banned"],
                "unbanned": res["unbanned"],
                "failed": res["failed"],
                "unban_failed": res["unban_failed"],
            },
            result=audit.RESULT_OK
            if not (res["failed"] or res["unban_failed"])
            else audit.RESULT_FAIL,
        )
    return res


# ═══════════════════════════════════════════════════════════
#  文案（UI 直接用）
# ═══════════════════════════════════════════════════════════


def format_migrate(res: Dict[str, Any], limit: int = 10) -> str:
    if res.get("error"):
        return f"名单并入规则失败：{res['error']}\n名单已保持原样，请重试。"
    if not res.get("migrated") and not res.get("black") and not res.get("white"):
        return ""
    lines = [
        f"已把旧名单并入规则：黑名单 {res['black']} 条 → 「拦截」规则，"
        f"白名单 {res['white']} 条 → 「放行」规则（仅豁免）。",
        f"原文件已备份到：{res['backup']}",
    ]
    if res.get("skipped"):
        lines.append(f"已有等价规则、跳过 {len(res['skipped'])} 条。")
    lines.append("名单入口已取消，之后统一在「访问规则」里维护。")
    return "\n".join(lines[: limit + 2])


def format_calibrate(res: Dict[str, Any], limit: int = 8) -> str:
    """一句话摘要 + 明细，供状态栏 / 弹窗使用"""
    if not res.get("admin"):
        if res.get("total"):
            return "规则已保存，但当前没有管理员权限，拦截规则不会实际生效"
        return ""
    parts: List[str] = []
    if res.get("banned"):
        parts.append(f"补封 {len(res['banned'])} 个")
    if res.get("unbanned"):
        parts.append(f"放行解封 {len(res['unbanned'])} 个")
    if res.get("failed"):
        parts.append(f"封禁失败 {len(res['failed'])} 个")
    if res.get("unban_failed"):
        parts.append(f"解封失败 {len(res['unban_failed'])} 个")
    if res.get("skipped_networks"):
        parts.append(f"{len(res['skipped_networks'])} 个网段不做预置")
    return "，".join(parts)


def format_calibrate_detail(res: Dict[str, Any], limit: int = 8) -> str:
    lines: List[str] = []
    if not res.get("admin") and res.get("total"):
        lines.append("⚠ 当前以普通权限运行，无法修改 Windows 防火墙：")
        lines.append("   拦截规则只会在收到访问时判为「已拦截」，实际没有规则挡住它。")
        return "\n".join(lines)
    if res.get("banned"):
        lines.append("已按拦截规则补写防火墙（永久）：")
        lines += [f"   · {ip}" for ip in res["banned"][:limit]]
    if res.get("unbanned"):
        lines.append("已按放行规则解除封禁：")
        lines += [f"   · {ip}" for ip in res["unbanned"][:limit]]
    if res.get("failed"):
        lines.append("封禁失败：")
        lines += [f"   · {ip}：{e}" for ip, e in res["failed"][:limit]]
    if res.get("unban_failed"):
        lines.append("解封失败：")
        lines += [f"   · {ip}：{e}" for ip, e in res["unban_failed"][:limit]]
    if res.get("skipped_networks"):
        lines.append("网段条目不做防火墙预置（命中时按规则实时拦截）：")
        lines += [f"   · {n}" for n in res["skipped_networks"][:limit]]
    return "\n".join(lines)
