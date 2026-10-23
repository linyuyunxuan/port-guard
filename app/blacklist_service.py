"""PortGuard — 黑名单 → 防火墙联动

背景（2026-10-21 用户提出）：黑名单原来只是**打分依据**（`rule_engine` 命中
黑名单加 100 分、建议封禁），真正写防火墙要等「自动封禁开启 + 分数过阈值」，
而自动封禁默认关闭。结果是加进黑名单的 IP **照样能访问业务系统** ——
对「设为黑名单」的直觉预期（不许再连）完全不成立。

本模块把黑名单变成真正的拦截动作：
- 加入黑名单 → 立即写防火墙阻止规则（**永久**，黑名单语义就是永不信任）
- 移出黑名单 → 只解**黑名单来源**的封禁；手工/自动封禁的一律不动
- 无管理员权限 → 明确返回「未实际拦截」，绝不假装成功

为什么不放进 `core/`：它要调 `app/ban_service`（有审计、有 bus 事件），
放 core 会形成 core → app 的反向依赖。
"""

import logging
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from app import audit, ban_service
from core import firewall
from core import settings as cfg
from core.config import DEFAULT_REPEAT_BLACKLIST_HITS
from core.database import find_active_ban_by_ip

log = logging.getLogger("portguard.blacklist")

# 黑名单来源的封禁标记：解封时靠它区分「这条规则是谁加的」
SOURCE_BLACKLIST = "blacklist"
# 永久：duration_sec=0 是 ban_service 里约定的「永久」，不是「未设置」
PERMANENT = 0
REASON = "命中黑名单（人工维护）"


def diff(old: Iterable[str], new: Iterable[str]) -> Tuple[List[str], List[str]]:
    """名单变更差分。返回 (新增, 移除)，顺序稳定便于复现与测试。"""
    o: Set[str] = {x for x in old if x}
    n: Set[str] = {x for x in new if x}
    return sorted(n - o), sorted(o - n)


def _new_result() -> Dict[str, Any]:
    return {
        "admin": firewall.is_admin(),
        "banned": [],  # [(ip, rule_name)]
        "already": [],  # 已处于封禁状态（不重复建规则）
        "failed": [],  # [(ip, 错误)]
        "unbanned": [],  # [(ip, rule_name)]
        "unban_failed": [],  # [(ip, 错误)]
        "skipped_unban": [],  # 该 IP 有封禁但不是黑名单来源，按约定不动
    }


def apply_changes(
    added: Iterable[str], removed: Iterable[str], actor: Optional[str] = None
) -> Dict[str, Any]:
    """把黑名单变更落到防火墙。逐条处理，单条失败不影响其它条目。

    返回结构给 UI 直接展示（见 `format_summary`）。
    """
    res = _new_result()
    added_list = [x for x in added if x]
    removed_list = [x for x in removed if x]

    if not res["admin"]:
        # 没有管理员权限时**不写库、不写规则**，如实报告「未拦截」。
        # 假装成功是这个功能最危险的失败形态：用户以为已经拦住了。
        res["failed"] = [(ip, "需要管理员权限才能修改 Windows 防火墙") for ip in added_list]
        res["unban_failed"] = [(ip, "需要管理员权限才能修改 Windows 防火墙") for ip in removed_list]
        log.warning(
            "黑名单变更未生效：当前非管理员权限（新增 %d / 移除 %d）",
            len(added_list),
            len(removed_list),
        )
        return res

    for ip in added_list:
        try:
            ban_id, err = ban_service.execute(
                ip,
                score=100,
                reason=REASON,
                duration_sec=PERMANENT,
                source=SOURCE_BLACKLIST,
                actor=actor or audit.actor_local(),
            )
        except Exception as e:  # 单条异常不能打断整批
            log.exception("黑名单封禁异常 ip=%s", ip)
            res["failed"].append((ip, str(e)))
            continue
        if ban_id is None:
            res["failed"].append((ip, err or "封禁失败"))
        elif err:  # 已有活动封禁：execute 返回 (id, "…已处于封禁状态…")
            res["already"].append((ip, err))
        else:
            res["banned"].append((ip, ""))
    # 规则名要回查：execute 不回传 rule_name，这里按 IP 找活动记录补上
    for i, (ip, _n) in enumerate(res["banned"]):
        try:
            rec = find_active_ban_by_ip(ip)
            if rec and rec.rule_name:
                res["banned"][i] = (ip, rec.rule_name)
        except Exception:
            log.exception("回查封禁规则名失败 ip=%s", ip)

    for ip in removed_list:
        try:
            rec = find_active_ban_by_ip(ip)
        except Exception as e:
            log.exception("查询封禁记录失败 ip=%s", ip)
            res["unban_failed"].append((ip, str(e)))
            continue
        if rec is None:
            continue  # 没有活动封禁，无需解封
        if rec.source != SOURCE_BLACKLIST:
            # 手工封禁 / 自动封禁不能因为「从黑名单移除」就被解掉
            res["skipped_unban"].append((ip, rec.source or "manual"))
            continue
        ok, err = ban_service.unban(rec, actor=actor or audit.actor_local())
        if ok:
            res["unbanned"].append((ip, rec.rule_name or ""))
        else:
            res["unban_failed"].append((ip, err or "解封失败"))

    return res


def ensure_enforced(limit: int = 100) -> Dict[str, Any]:
    """启动时补齐：黑名单里存在、但当前没有活动封禁的条目，重新封禁。

    为什么需要：非管理员时加入黑名单只落文件（明确提示未拦截），
    之后以管理员身份重启就应当补上；否则「名单里有、实际没拦」会一直存在。
    只处理前 `limit` 条，避免一次启动写几十上百条规则。
    """
    from core.rule_engine import get_engine

    res = _new_result()
    entries = list(get_engine().blacklist.entries())
    pending: List[str] = []
    for ip in entries:
        try:
            if find_active_ban_by_ip(ip) is None:
                pending.append(ip)
        except Exception:
            log.exception("查询封禁记录失败 ip=%s", ip)
    if not pending:
        return res
    if not res["admin"]:
        res["failed"] = [(ip, "需要管理员权限才能修改 Windows 防火墙") for ip in pending]
        return res
    log.info("启动补封：黑名单 %d 条中 %d 条无活动封禁，开始补齐", len(entries), len(pending))
    return apply_changes(pending[:limit], [], actor=audit.ACTOR_SYSTEM)


def escalate_repeat_offender(
    ip: str, ban: Optional[Any] = None, hits: int = 0, actor: Optional[str] = None
) -> bool:
    """
    已封禁 IP 反复访问到阈值 → 写进黑名单，并把这条封禁改成**永久**。

    为什么不是「再封一次」：封禁本来就有到期时间，攻击者等它到期就能再来一轮，
    于是「封 → 到期 → 再来 → 再封」永远循环。黑名单语义是**永不信任**，
    正好对上「封了还在撞」这种最明确的恶意信号（2026-10-22 用户提出）。

    做三件事，缺一不可：
    1. 写名单文件（`rule_engine.blacklist`）—— 之后每次访问按 100 分算，
       而且**重启后仍然生效**（这是它区别于一次封禁的地方）；
    2. 把当前这条封禁改成永久 + 来源标成 `blacklist`（有 active 记录时）。
       不新建规则的理由：规则已经在防火墙里生效了，重建反而会留下两条规则
       （旧的那条没人认领，见 ban_service.reenforce_all 的历史教训）；
       改成永久只是让到期巡检**不再删它**，代价最小。
       封禁记录不是 active（pending / failed，规则没建成）时才走
       `apply_changes` 真去建一条；
    3. 审计 + 一次托盘提示。这是**程序自己改了安全策略**，必须留痕，
       也必须让人知道 —— 但只提示一次，用 tray 而不是弹窗。

    返回是否真的执行了升级（已在黑名单 / 未达阈值 / 关闭开关 都返回 False）。
    """
    ip = (ip or "").strip()
    if not ip:
        return False
    try:
        if not cfg.get_bool("repeat_blacklist_enabled", True):
            return False
        need = max(1, cfg.get_int("repeat_blacklist_hits", DEFAULT_REPEAT_BLACKLIST_HITS))
    except Exception:
        log.exception("读取惯犯升级设置失败 ip=%s，本次不升级", ip)
        return False
    if hits < need:
        return False

    from core.rule_engine import get_engine

    engine = get_engine()
    if ip in engine.blacklist:
        return False  # 已经是黑名单，别重复提示

    who = actor or audit.ACTOR_SYSTEM
    before = {
        "ip": ip,
        "hits": hits,
        "threshold": need,
        "ban_id": getattr(ban, "id", None),
        "status": getattr(ban, "status", ""),
        "duration_sec": getattr(ban, "duration_sec", None),
    }

    try:
        engine.blacklist.add(ip)
        engine.save_lists()
    except Exception:
        log.exception("写入黑名单文件失败 ip=%s", ip)
        audit.record(
            audit.ACTION_BAN_ESCALATE,
            actor=who,
            target_type="ip",
            target_id=ip,
            summary=f"惯犯升级失败：写入黑名单文件出错（ip={ip}）",
            before=before,
            result=audit.RESULT_FAIL,
            detail="名单未写入，本次不升级封禁",
        )
        return False

    # 同时落一条「拦截」规则（2026-10-23）。
    # 名单入口已经取消，只写名单等于**写进一个界面上看不见的地方**：
    # 用户没法在规则页找到它、也没法停用，下次启动还会被迁移逻辑再翻译一遍。
    # 写成规则之后它就是一条看得见、能编辑、能停用的拦截规则。
    # 失败不影响升级本身（名单仍然生效，下次启动会迁移）。
    try:
        from app.list_migration import add_block_rule

        add_block_rule(ip)
    except Exception:
        log.exception("惯犯升级：写入拦截规则失败 ip=%s（名单已生效，启动时会迁移）", ip)

    permanent = False
    note = ""
    try:
        if ban is not None and getattr(ban, "id", None) and getattr(ban, "status", "") == "active":
            # 规则已在防火墙里：改成永久即可，不动规则本身
            from core.database import update_ban

            update_ban(
                int(ban.id),
                duration_sec=PERMANENT,
                expire_at=None,
                source=SOURCE_BLACKLIST,
            )
            permanent = True
            note = f"封禁记录 #{ban.id} 已改为永久"
        elif firewall.is_admin():
            res = apply_changes([ip], [], actor=who)
            if res.get("banned"):
                permanent = True
                note = "已写入永久防火墙规则"
            elif res.get("already"):
                permanent = True
                note = "已有生效封禁，未重复建规则"
            else:
                failed = res.get("failed") or []
                note = f"建规则失败：{failed[0][1]}" if failed else "建规则未完成"
        else:
            note = "已写入名单，但当前无管理员权限，防火墙规则待下次以管理员运行补齐"
    except Exception:
        log.exception("惯犯升级：改为永久封禁失败 ip=%s", ip)
        note = "改为永久封禁失败"

    audit.record(
        audit.ACTION_BAN_ESCALATE,
        actor=who,
        target_type="ban",
        target_id=getattr(ban, "id", None),
        summary=f"惯犯升级：{ip} 封禁期间又命中 {hits} 次，已列入黑名单（永久）",
        before=before,
        after={"blacklisted": True, "permanent": permanent, "note": note},
        result=audit.RESULT_OK if permanent else audit.RESULT_SKIP,
        detail=note,
    )
    log.warning("惯犯升级黑名单：%s（封禁期间命中 %d 次，%s）", ip, hits, note or "-")

    # 提示一次：程序自己收紧了安全策略，不说就是「偷偷改了配置」。
    # 用 tray 而不是弹窗 —— 用户明确抱怨过弹窗打断操作（2026-10-22）。
    from core.event_bus import bus

    bus.emit_alert(
        {
            "ip": ip,
            "level": "critical",
            "score": 100,
            "reason": f"封禁期间反复访问 {hits} 次，已达阈值 {need}",
            "geo": "",
            "local_port": "",
            "disposition": "block",
            "escalated": True,
            "block_hits": hits,
        }
    )
    return True


def format_summary(res: Dict[str, Any]) -> str:
    """一句话结果，给状态栏用（弹窗用 `format_detail`）。"""
    if not res["admin"]:
        return "黑名单已保存，但当前没有管理员权限，未写防火墙规则（不会拦截）"
    parts: List[str] = []
    if res["banned"]:
        parts.append(f"已封禁 {len(res['banned'])} 个")
    if res["already"]:
        parts.append(f"已在封禁中 {len(res['already'])} 个")
    if res["failed"]:
        parts.append(f"封禁失败 {len(res['failed'])} 个")
    if res["unbanned"]:
        parts.append(f"已解封 {len(res['unbanned'])} 个")
    if res["unban_failed"]:
        parts.append(f"解封失败 {len(res['unban_failed'])} 个")
    if res["skipped_unban"]:
        parts.append(f"保留封禁 {len(res['skipped_unban'])} 个（非黑名单来源）")
    return "，".join(parts) or "无变更"


def format_detail(res: Dict[str, Any], limit: int = 12) -> str:
    """多行明细，给确认/结果弹窗用。"""
    lines: List[str] = []
    if not res["admin"]:
        lines.append("⚠ 当前以普通权限运行，无法修改 Windows 防火墙。")
        lines.append("   黑名单已保存，但下列 IP **不会**被实际拦截：")
        lines += [f"   · {ip}" for ip, _e in res["failed"][:limit]]
        return "\n".join(lines)

    if res["banned"]:
        lines.append("已封禁（防火墙入站阻止）：")
        lines += [f"   · {ip}" for ip, _n in res["banned"][:limit]]
    if res["already"]:
        lines.append("已在封禁中（未重复建规则）：")
        lines += [f"   · {ip}" for ip, _e in res["already"][:limit]]
    if res["failed"]:
        lines.append("封禁失败：")
        lines += [f"   · {ip}：{e}" for ip, e in res["failed"][:limit]]
    if res["unbanned"]:
        lines.append("已解封（黑名单来源）：")
        lines += [f"   · {ip}" for ip, _n in res["unbanned"][:limit]]
    if res["skipped_unban"]:
        lines.append("保留封禁（手工/自动封禁，不随黑名单移除而解封）：")
        lines += [f"   · {ip}（来源 {s}）" for ip, s in res["skipped_unban"][:limit]]
    if res["unban_failed"]:
        lines.append("解封失败：")
        lines += [f"   · {ip}：{e}" for ip, e in res["unban_failed"][:limit]]
    return "\n".join(lines) or "无变更"
