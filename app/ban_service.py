"""
PortGuard — 封禁编排（不依赖 Qt，可脱离界面单测）

为什么单独抽出来：原实现把「校验 → 落库 → 调防火墙 → 回填 → 投递事件」
全塞在 `MainWindow._execute_ban` 里，既无法单测，也让封禁入口分散在多处
（右键菜单 / 风险事件页 / 封禁页 / 自动模式），容易出现某条路径漏校验。

这里把校验收敛成唯一入口 `prepare()`，所有调用方都必须过它。
"""

import contextlib
import time
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

from app import audit
from core import firewall
from core import settings as cfg
from core.config import (
    BAN_DURATION_TIER_DEFAULTS,
    DEFAULT_BAN_DURATION_SEC,
    DEFAULT_ESCALATION_FACTOR,
    DEFAULT_ESCALATION_MAX_SEC,
    LEVEL_CRITICAL,
    LEVEL_HIGH,
    LEVEL_LABEL,
    LEVEL_LOW,
    LEVEL_MEDIUM,
)
from core.database import (
    count_bans_by_ip,
    find_active_ban_by_ip,
    insert_ban,
    list_all_active_bans,
    list_expired_bans,
    mark_ban_unbanned,
    query_bans,
    set_risk_handled_by_ip,
    update_ban,
)
from core.event_bus import bus
from core.logger import get_logger
from core.models import (
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_UNBANNED,
    BanRecord,
)
from core.rule_engine import RuleEngine, get_engine, is_never_ban
from core.rules_meta import REGION_PREFIX, region_rule_key, rule_label
from core.validators import InvalidIP, clamp_int, normalize_ip, safe_text

log = get_logger(__name__)

MAX_BAN_SECONDS = 365 * 24 * 3600
MAX_IP_LEN = 64


# ═══════════════════════════════════════════════════════════
#  封禁时长策略（P2-8）
#
#  ⚠️ 语义分界（踩了就是线上事故）：
#  `BanRecord.duration_sec = 0 / None` 表示**永久封禁**（expire_at 也为 None）。
#  因此策略函数**绝不能返回 0** —— 递增算法一旦算出 0（例如用户把倍数配成 0，
#  或乘法溢出被截断），「按策略封 1 小时」就会静默变成「永久封禁」。
#  本模块所有策略出口都过 `_sec()`，下限硬钉在 1 秒。
# ═══════════════════════════════════════════════════════════

#: 策略出口的硬下限。1 秒在业务上等同于「立刻到期」，但**不是永久**
_MIN_POLICY_SEC = 1

#: 时长来源，用于日志与界面解释「为什么是这个值」
SOURCE_RULE = "rule"
SOURCE_ESCALATION = "escalation"
SOURCE_LEVEL = "level"
SOURCE_DEFAULT = "default"

SOURCE_LABEL = {
    SOURCE_RULE: "规则指定时长",
    SOURCE_ESCALATION: "重复封禁递增",
    SOURCE_LEVEL: "按风险等级分档",
    SOURCE_DEFAULT: "默认时长",
}

#: 风险等级 -> 分档设置项。normal 没有档位（它本就不该被封）
_LEVEL_TIER_KEY = {
    LEVEL_CRITICAL: "ban_duration_critical_sec",
    LEVEL_HIGH: "ban_duration_high_sec",
    LEVEL_MEDIUM: "ban_duration_medium_sec",
    LEVEL_LOW: "ban_duration_low_sec",
}


class DurationDecision(NamedTuple):
    """一次时长解析的结果（秒数 + 来源 + 人话解释，供日志和界面直接展示）"""

    seconds: int
    source: str
    detail: str

    @property
    def source_label(self) -> str:
        return SOURCE_LABEL.get(self.source, self.source)


def _sec(value: Any, fallback: Optional[int] = None) -> int:
    """
    把任意外部值收敛成合法封禁时长：`1 <= v <= MAX_BAN_SECONDS`。

    非法 / 非正 / 超出上限时退回 fallback（再退 DEFAULT_BAN_DURATION_SEC）。
    这是「策略绝不返回 0」的唯一出口，别在别处绕过它。
    """
    v = clamp_int(value, 0, MAX_BAN_SECONDS, 0)
    if v <= 0:
        v = clamp_int(fallback, 0, MAX_BAN_SECONDS, 0)
    if v <= 0:
        v = DEFAULT_BAN_DURATION_SEC
    return max(_MIN_POLICY_SEC, min(v, MAX_BAN_SECONDS))


def _default_sec(override: Optional[int] = None) -> int:
    """兜底时长：优先用调用方给的 default，其次读设置，最后用内置默认"""
    if override is not None:
        return _sec(override)
    return _sec(cfg.get_int("default_ban_duration_sec", DEFAULT_BAN_DURATION_SEC))


def tier_sec_for_level(level: Optional[str]) -> int:
    """
    该风险等级在设置里配的分档时长（秒）。未配栏杆位（normal / 未知等级）返回 0，
    表示「不分档」，由调用方决定退回哪个兜底值。
    """
    key = _LEVEL_TIER_KEY.get(level or "")
    if not key:
        return 0
    builtin = int(BAN_DURATION_TIER_DEFAULTS.get(level or "", 0))
    # 传入内置默认值：老库可能还没有这个 key（INSERT OR IGNORE 只补新库缺的行，
    # 但用户手动删过 settings 行时同样缺失），此时不能静默退化成「不分档」
    return clamp_int(cfg.get_int(key, builtin), 0, MAX_BAN_SECONDS, 0)


def duration_for_level(level: Optional[str], fallback: Optional[int] = None) -> int:
    """按风险等级取封禁时长；该等级未配栏杆位时用 fallback（默认取默认时长）"""
    base = _default_sec(fallback)
    return _sec(tier_sec_for_level(level) or base, base)


def escalation_sec(base: int, prior_bans: int) -> int:
    """
    重复封禁递增：历史封禁 `prior_bans` 次后，本次时长 = base × factor^prior_bans，
    并以 `ban_escalation_max_sec` 封顶。

    · prior_bans <= 0 时原样返回（**首次封禁不放大**）；
    · factor <= 1 时不递增（配置失误不该变成「越封越短」）；
    · 封顶值低于 base 时不生效 —— 封顶是用来限制「递增」的，
      不应该把用户配的分档值反过来压短；
    · 循环逐次相乘而不是一步 pow：prior_bans 可能很大（历史记录被清过又攒回来），
      `factor ** n` 会直接算出一个天文数字再被截断，结果依赖浮点/大整数行为。
    """
    if base <= 0 or prior_bans <= 0:
        return base
    factor = max(1, cfg.get_int("ban_escalation_factor", DEFAULT_ESCALATION_FACTOR))
    if factor <= 1:
        return base
    cap = clamp_int(
        cfg.get_int("ban_escalation_max_sec", DEFAULT_ESCALATION_MAX_SEC),
        base,
        MAX_BAN_SECONDS,
        MAX_BAN_SECONDS,
    )
    out = base
    for _ in range(prior_bans):
        if out >= cap:
            return cap
        out = min(out * factor, cap)
    return min(out, cap)


def _rule_duration_sec(rule_id: str) -> int:
    """
    规则级时长：`rules.json` 里该规则若配了 `ban_duration_sec`，返回其秒数，否则 0。
    普通规则从 `rules.<id>` 读；区域规则（命中标记形如 `region_suggest_ban:r1`）
    从 `region_rules` 原始配置里按同样的 key 规则反查。
    """
    engine = get_engine()
    body = engine.rule(rule_id)
    if not body and rule_id.startswith(REGION_PREFIX):
        for r in engine.get_config().get("region_rules") or []:
            if not isinstance(r, dict):
                continue
            key = region_rule_key(str(r.get("action") or "").lower(), str(r.get("id") or ""))
            if key == rule_id:
                body = r
                break
    if not body:
        return 0
    return clamp_int(body.get("ban_duration_sec"), 0, MAX_BAN_SECONDS, 0)


def _prior_ban_count(ip: str) -> int:
    """历史封禁次数；查库失败按 0 处理（不递增，但绝不能因此挡住封禁）"""
    try:
        return count_bans_by_ip(ip)
    except Exception:
        log.exception("统计历史封禁次数失败 ip=%s（本次不做递增）", ip)
        return 0


def prior_ban_count(ip: str) -> int:
    """
    某 IP 的历史封禁次数（界面展示 / 排查用；不含「当前这条」，因为它还没落库）。
    查库失败返回 0 —— 展示用的数字不值得把界面弄崩。
    """
    return _prior_ban_count(ip)


def resolve_duration_detail(
    score: Optional[int] = None,
    level: Optional[str] = None,
    rule_ids: Optional[List[str]] = None,
    ip: Optional[str] = None,
    default: Optional[int] = None,
) -> DurationDecision:
    """
    解析本次封禁应该封多久，并给出「为什么这么长」。

    优先级（前者命中就不再往后看）：
      1. 规则级   —— `rule_ids` 里有规则配了 `ban_duration_sec`，取最狠（最长）的那条
      2. 递增级   —— 开启递增且该 IP 有历史封禁记录，按倍数在「等级档位」上加长并封顶
      3. 等级级   —— 按 `score`/`level` 映射的档位（`ban_duration_*_sec`）
      4. 默认     —— `default`，未传则 `default_ban_duration_sec`
    返回值恒 ≥ 1 秒（见模块顶部「语义分界」）。

    ⚠️ 调用点必须在 `insert_ban` **之前**：递增要用「历史次数」，插库后再解析
    会把本次自己数进去，第一次封禁就翻倍（core.database.count_bans_by_ip 亦同）。
    """
    base = _default_sec(default)

    # 1. 规则级：最狠 = 最长
    hits = [(rid, _rule_duration_sec(rid)) for rid in (rule_ids or []) if rid]
    hits = [(rid, sec) for rid, sec in hits if sec > 0]
    if hits:
        rid, sec = max(hits, key=lambda kv: kv[1])
        return DurationDecision(
            _sec(sec, base), SOURCE_RULE, f"规则「{rule_label(rid)}」指定 {format_duration(sec)}"
        )

    lv = level or (RuleEngine.level_of(int(score)) if score is not None else None)
    tier = tier_sec_for_level(lv)

    # 2. 递增级：以等级档位（无档位则默认时长）为基准放大
    if ip and cfg.get_bool("ban_escalation_enabled", False):
        # factor <= 1 等于没开递增（也不该出现「越封越短」），此时仍按等级档位走
        factor = max(1, cfg.get_int("ban_escalation_factor", DEFAULT_ESCALATION_FACTOR))
        prior = _prior_ban_count(ip) if factor > 1 else 0
        if prior > 0:
            start = _sec(tier or base, base)
            sec = _sec(escalation_sec(start, prior), start)
            return DurationDecision(
                sec,
                SOURCE_ESCALATION,
                f"{ip} 历史已封禁 {prior} 次，基准 {format_duration(start)} × {factor}^{prior} → {format_duration(sec)}",
            )

    # 3. 等级级
    if tier > 0:
        return DurationDecision(
            _sec(tier, base),
            SOURCE_LEVEL,
            f"风险等级「{LEVEL_LABEL.get(lv or '', lv or '未定')}」对应 {format_duration(tier)}",
        )

    # 4. 默认
    return DurationDecision(
        base, SOURCE_DEFAULT, f"未命中分档 / 递增，使用默认 {format_duration(base)}"
    )


def resolve_duration(
    score: Optional[int] = None,
    level: Optional[str] = None,
    rule_ids: Optional[List[str]] = None,
    ip: Optional[str] = None,
    default: Optional[int] = None,
) -> int:
    """
    封禁时长策略的纯数值入口：返回**秒数，恒 ≥ 1**（永不返回 0=永久）。
    需要「为什么是这个值」时用 `resolve_duration_detail()`。
    """
    return resolve_duration_detail(
        score=score, level=level, rule_ids=rule_ids, ip=ip, default=default
    ).seconds


def format_duration(sec: int) -> str:
    """秒数 -> 「1 天 / 6 小时 / 30 分钟」，复用表格里那套口径"""
    return BanRecord(duration_sec=sec).duration_label


class BanError(Exception):
    """封禁前置校验失败（消息可直接展示给用户）"""


def prepare(
    ip: str,
    score: int = 0,
    reason: str = "",
    duration_sec: Optional[int] = None,
    rule_ids: Optional[List[str]] = None,
) -> BanRecord:
    """
    校验并构造封禁记录（**不落库、不执行**）。
    这里是所有封禁路径的唯一校验入口。

    `duration_sec` 三种传法，语义必须分清：
    · `None`（默认）—— 走封禁时长策略：规则级 > 递增级 > 等级级 > 默认；
    · `0`            —— **永久封禁**（duration_sec/expire_at 都是 None）；
    · `>0`           —— 调用方指定的秒数（超出上限会被夹到 365 天）。
    策略分支永远拿不到 0：`resolve_duration_detail()` 的下限硬钉在 1 秒。
    """
    try:
        safe_ip = normalize_ip(ip)
    except InvalidIP as e:
        raise BanError(str(e)) from e

    if is_never_ban(safe_ip):
        raise BanError(f"{safe_ip} 属于内网 / 回环 / 保留地址，PortGuard 永不封禁此类地址")

    if duration_sec is None:
        # 递增要读「历史次数」，此处尚未 insert，天然不含本次记录（见 resolve_duration_detail）
        decision = resolve_duration_detail(score=score, rule_ids=rule_ids, ip=safe_ip)
        duration = decision.seconds
        log.info(
            "封禁时长按「%s」取 %s：%s（ip=%s）",
            decision.source_label,
            format_duration(duration),
            decision.detail,
            safe_ip,
        )
    else:
        duration = clamp_int(duration_sec, 0, MAX_BAN_SECONDS, 0)

    expire = None if not duration else int(time.time() * 1000) + duration * 1000
    return BanRecord(
        ip=safe_ip,
        reason=safe_text(reason, 180, "手动封禁"),
        risk_score=clamp_int(score, 0, 100, 0),
        source="manual",
        status=STATUS_PENDING,
        duration_sec=duration or None,
        expire_at=expire,
    )


def execute(
    ip: str,
    score: int = 0,
    reason: str = "",
    duration_sec: Optional[int] = None,
    source: str = "manual",
    rule_ids: Optional[List[str]] = None,
    actor: Optional[str] = None,
) -> Tuple[Optional[int], str]:
    """
    完整封禁流程：校验 → 写 pending → 调防火墙 → 回填结果 → 投递事件。
    返回 (ban_id, 错误信息)。成功时错误信息为空串。

    `duration_sec` 的语义同 `prepare()`（None=走策略 / 0=永久 / >0=指定秒数）。

    `actor` 留空表示「本机交互」，审计会记成当前登录用户名；自动路径走
    `core.pipeline.auto_ban_record`，由它自己带 actor 过来。

    注意：调用方应在后台线程执行（防火墙命令可能耗时数秒）。
    """
    # 手动封禁是唯一「界面点出来的封禁」，actor 默认取本机用户；
    # source 非 manual 说明是程序链路，记成 system 而不是当前用户名。
    # `blacklist` 同理：加黑名单是人点的按钮，记成本机用户才答得出「谁封的」。
    manual_like = (not source) or source in ("manual", "blacklist")
    who = actor or (audit.actor_local() if manual_like else audit.ACTOR_SYSTEM)
    action = audit.ACTION_BAN_MANUAL if manual_like else audit.ACTION_BAN_AUTO

    if not firewall.is_admin():
        audit.record(
            action,
            actor=who,
            target_type="ip",
            target_id=ip,
            summary="封禁失败：无管理员权限",
            result=audit.RESULT_FAIL,
        )
        return None, "需要管理员权限才能修改 Windows 防火墙"

    try:
        rec = prepare(ip, score, reason, duration_sec, rule_ids)
    except BanError as e:
        log.warning("拒绝封禁：%s", e)
        audit.record(
            action,
            actor=who,
            target_type="ip",
            target_id=ip,
            summary=f"拒绝封禁：{e}",
            result=audit.RESULT_SKIP,
        )
        return None, str(e)
    rec.source = source

    # 已处于封禁状态：不重复创建规则
    existing = None
    try:
        existing = find_active_ban_by_ip(rec.ip)
    except Exception:
        log.exception("查询已有封禁记录失败 ip=%s", rec.ip)
    if existing:
        audit.record(
            action,
            actor=who,
            target_type="ban",
            target_id=existing.id,
            summary=f"{rec.ip} 已在封禁中，未重复创建规则",
            result=audit.RESULT_SKIP,
        )
        return existing.id, f"{rec.ip} 已处于封禁状态（记录 #{existing.id}）"

    try:
        ban_id = insert_ban(rec)
    except Exception as e:
        log.exception("写入封禁记录失败 ip=%s", rec.ip)
        audit.record(
            action,
            actor=who,
            target_type="ip",
            target_id=rec.ip,
            summary=f"写入封禁记录失败：{e}",
            result=audit.RESULT_FAIL,
        )
        return None, f"写入封禁记录失败：{e}"

    ok, name, err = firewall.block_ip(rec.ip, rec.duration_sec, note=rec.reason)
    try:
        update_ban(
            ban_id, status=(STATUS_ACTIVE if ok else STATUS_FAILED), rule_name=name, error_msg=err
        )
    except Exception:
        log.exception("回填封禁结果失败 ban_id=%s", ban_id)

    # 审计：before 是「请求封禁」，after 是「防火墙真实结果」。
    # 记 after 而不是只记「点了封禁」，是因为防火墙可能被组策略挡掉 ——
    # 只看「有人点过」会得出错误的结论。
    audit.record(
        action,
        actor=who,
        target_type="ban",
        target_id=ban_id,
        summary=(
            f"封禁 {rec.ip}"
            + (f" {format_duration(rec.duration_sec)}" if rec.duration_sec else " 永久")
            + ("成功" if ok else f"失败：{err}")
        ),
        before={"ip": rec.ip, "score": rec.risk_score, "reason": rec.reason, "source": source},
        after={"ban_id": ban_id, "status": STATUS_ACTIVE if ok else STATUS_FAILED, "rule": name},
        result=audit.RESULT_OK if ok else audit.RESULT_FAIL,
        detail=err or "",
    )

    # 封禁真切落地 → 该 IP 的「未处理」事件整批标成「已确认」（人工/黑名单/
    # 批量三条入口都走这里，所以只写一处）。
    #
    # ⚠️ 必须在 `bus.emit_ban` **之前**：界面收到封禁事件就会刷新事件页，
    # 反过来（先投递再回填）刷新时读到的还是「未处理」，用户看到的就是
    # 「封了但状态没变」—— 这正是要被修掉的那个反馈。
    if ok:
        try:
            marked = set_risk_handled_by_ip(rec.ip, 1)
            if marked:
                log.info("封禁 %s 后回填 %d 条事件为已确认", rec.ip, marked)
        except Exception:
            # 回填失败不该让封禁本身变成失败：规则已经写进防火墙了
            log.exception("封禁后回填事件状态失败 ip=%s", rec.ip)

    bus.emit_ban(
        {
            "ip": rec.ip,
            "ok": ok,
            "rule_name": name,
            "error": err,
            "ban_id": ban_id,
            "source": source,
        }
    )
    if ok:
        log.info("封禁成功 ip=%s rule=%s 时长=%s", rec.ip, name, rec.duration_sec or "永久")
    return ban_id, ("" if ok else err)


def unban(ban: BanRecord, actor: Optional[str] = None) -> Tuple[bool, str]:
    """
    解封单条记录（防火墙规则 + 数据库状态）。

    `actor` 用于两处：审计的 actor，以及 `ban_list.unblocked_by`（v2 就加好、
    此前一个写入点都没有的列）。
    """
    who = actor or audit.actor_local()
    if not firewall.is_admin():
        audit.record(
            audit.ACTION_BAN_UNBAN,
            actor=who,
            target_type="ban",
            target_id=ban.id,
            summary=f"解封 {ban.ip} 失败：无管理员权限",
            result=audit.RESULT_FAIL,
        )
        return False, "需要管理员权限才能修改 Windows 防火墙"
    names = [ban.rule_name] if ban.rule_name else []
    ok, err, n = firewall.unblock_ip(ban.ip, names)
    if not ok:
        log.warning("解封失败 ip=%s err=%s", ban.ip, err)
        audit.record(
            audit.ACTION_BAN_UNBAN,
            actor=who,
            target_type="ban",
            target_id=ban.id,
            summary=f"解封 {ban.ip} 失败：{err}",
            result=audit.RESULT_FAIL,
            detail=err or "",
        )
        return False, err or "未知错误"
    try:
        mark_ban_unbanned(ban.id, STATUS_UNBANNED, unblocked_by=who)
    except Exception:
        log.exception("回填解封状态失败 ban_id=%s", ban.id)
    audit.record(
        audit.ACTION_BAN_UNBAN,
        actor=who,
        target_type="ban",
        target_id=ban.id,
        summary=f"解封 {ban.ip}",
        before={"status": ban.status, "rule": ban.rule_name},
        after={"status": STATUS_UNBANNED, "unblocked_by": who},
    )
    log.info("已解封 ip=%s（删除 %d 条规则）", ban.ip, n)
    return True, ""


def unban_all(actor: Optional[str] = None) -> Tuple[bool, int, str]:
    """一键解封所有 PortGuard 规则"""
    who = actor or audit.actor_local()
    if not firewall.is_admin():
        audit.record(
            audit.ACTION_BAN_UNBAN_ALL,
            actor=who,
            summary="一键解封失败：无管理员权限",
            result=audit.RESULT_FAIL,
        )
        return False, 0, "需要管理员权限才能修改 Windows 防火墙"
    ok, n, err = firewall.unblock_all()
    if not ok:
        audit.record(
            audit.ACTION_BAN_UNBAN_ALL,
            actor=who,
            summary=f"一键解封失败：{err}",
            result=audit.RESULT_FAIL,
        )
        return False, 0, err or "未知错误"
    done = 0
    try:
        from core.database import query_bans

        for b in query_bans(status=STATUS_ACTIVE, limit=100000):
            mark_ban_unbanned(b.id, STATUS_UNBANNED, unblocked_by=who)
            done += 1
    except Exception:
        log.exception("批量回填解封状态失败")
    audit.record(
        audit.ACTION_BAN_UNBAN_ALL,
        actor=who,
        target_type="ban",
        summary=f"一键解封：删除 {n} 条防火墙规则，回填 {done} 条记录",
        after={"rules": n, "records": done, "unblocked_by": who},
    )
    return True, n, ""


#: 非管理员时「到期解封被跳过」的告警限流（秒）。巡检每 60 秒一次，
#: 不限流的话日志会被同一句刷满，真正的问题反而被淹没。
_ADMIN_SKIP_WARN_SEC = 600.0
_admin_skip_warned_at = 0.0


def expired_backlog(now: Optional[int] = None) -> int:
    """
    已到期但仍处于 active 的封禁条数 —— 也就是「本该被解封、实际还封着」的数量。

    存在的意义：到期巡检依赖管理员权限，普通权限运行时它什么都做不了。
    没有这个数字，界面就只能说「可能有封禁没解开」，说不清有几条。
    查库失败按 0 处理（展示用的数字不值得把界面弄崩）。
    """
    try:
        return len(list_expired_bans(now))
    except Exception:
        log.exception("统计到期未解封条数失败")
        return 0


def _warn_expire_without_admin() -> None:
    """
    非管理员时，把「巡检跳过」这件事显式说出来（限流到 10 分钟一次）。

    原实现在这里直接 `return []`，一声不响 —— 后果很具体：以管理员封过的 IP，
    之后以普通权限（`start.bat`，只监控模式）运行，那些规则**永远不会到期解封**，
    而界面上没有任何提示，用户以为封禁是自动到期的。
    """
    global _admin_skip_warned_at
    n = expired_backlog()
    if n <= 0:
        return  # 没有积压就不必打扰：普通权限运行本来就是设计内的正常用法
    now = time.time()
    if now - _admin_skip_warned_at < _ADMIN_SKIP_WARN_SEC:
        return
    _admin_skip_warned_at = now
    log.warning(
        "到期巡检已跳过：有 %d 条封禁已到期，但当前进程不是管理员，无法删除防火墙规则。"
        "这些规则仍在生效（Windows 防火墙规则本身没有到期时间，只能靠本程序删）。"
        "以管理员身份运行一次即可自动补解封。",
        n,
    )


def check_expired(now: Optional[int] = None) -> List[BanRecord]:
    """
    到期解封巡检：把已到期但仍 active 的封禁真正解掉。
    返回本次成功解封的记录列表。

    ⚠️ 非管理员时返回空列表，但**不再静默**：会记一条限流告警（见
    `_warn_expire_without_admin`），界面侧还有 `expired_backlog()` 可用。
    """
    if not firewall.is_admin():
        _warn_expire_without_admin()
        return []
    done: List[BanRecord] = []
    try:
        expired = list_expired_bans(now)
    except Exception:
        log.exception("查询到期封禁失败")
        return []

    for b in expired:
        ok, err, _n = firewall.unblock_ip(b.ip, [b.rule_name] if b.rule_name else [])
        if ok:
            try:
                mark_ban_unbanned(b.id, STATUS_EXPIRED, unblocked_by=audit.ACTOR_SYSTEM)
            except Exception:
                log.exception("标记到期解封失败 ban_id=%s", b.id)
            done.append(b)
            log.info("封禁已到期自动解封 ip=%s（记录 #%s）", b.ip, b.id)
            audit.record(
                audit.ACTION_BAN_EXPIRE,
                actor=audit.ACTOR_SYSTEM,
                target_type="ban",
                target_id=b.id,
                summary=f"{b.ip} 封禁到期，自动解封",
                before={"status": b.status, "expire_at": b.expire_at},
                after={"status": STATUS_EXPIRED, "unblocked_by": audit.ACTOR_SYSTEM},
            )
        else:
            with contextlib.suppress(Exception):
                update_ban(b.id, error_msg=err)
            audit.record(
                audit.ACTION_BAN_EXPIRE,
                actor=audit.ACTOR_SYSTEM,
                target_type="ban",
                target_id=b.id,
                summary=f"{b.ip} 到期解封失败：{err}",
                result=audit.RESULT_FAIL,
                detail=err or "",
            )
    return done


def reconcile(rule_names: List[str]) -> int:
    """
    与防火墙对账：数据库里 active 但防火墙中已不存在的规则，标记为已解封。
    返回修正条数。
    """
    from core.database import query_bans

    existing = set(rule_names or [])
    if not existing:
        # 空列表可能是「真的都没了」，也可能是「本机读不到规则」（2008 R2 没有
        # Get-NetFirewallRule，或权限不足）。二者在这里无法区分，但后果差别巨大：
        # 后者会把所有 active 记录标成已解封，而防火墙规则仍在拦截。
        # 调用方（封禁页）会先弹确认；这里至少留下可追溯的日志。
        log.warning(
            "对账收到空的规则列表：若本机读不到防火墙规则，"
            "本次会把所有 active 记录标记为已解封（防火墙规则并不会被删除）"
        )
    fixed: List[str] = []
    for b in query_bans(status=STATUS_ACTIVE, limit=100000):
        if b.rule_name and b.rule_name not in existing:
            try:
                mark_ban_unbanned(b.id, STATUS_UNBANNED, unblocked_by=audit.ACTOR_SYSTEM)
                fixed.append(f"{b.ip}(#{b.id})")
            except Exception:
                log.exception("对账修正失败 ban_id=%s", b.id)
    log.info("与防火墙对账完成：现存规则 %d 条，修正 %d 条失效记录", len(existing), len(fixed))
    if fixed:
        # 只记一条汇总：对账一次可能修正几十条，逐条记会把审计表刷爆，
        # 而排查时真正需要的是「这次对账动过哪些 IP」，一条就够。
        audit.record(
            audit.ACTION_BAN_RECONCILE,
            actor=audit.ACTOR_SYSTEM,
            target_type="ban",
            summary=f"防火墙对账：{len(fixed)} 条记录已无对应规则，标记为已解封",
            after={"fixed": fixed, "unblocked_by": audit.ACTOR_SYSTEM},
        )
    return len(fixed)


def reenforce_all(cleanup_legacy: bool = True, retry_failed: bool = True) -> Dict[str, Any]:
    """
    把「库里的封禁」与「系统里的防火墙规则」对齐一次。返回摘要字典。

    触发点：程序启动（管理员）、刚启用防火墙之后、以及封禁页的「重新校验」。

    做三件事，顺序有讲究：
    1. **先补建** active 但系统里没有规则的封禁（新名字 `PortGuard_Block_<ip>`）
    2. **再清历史遗留规则**（`<ip>_<毫秒>_<随机>`，真机上同一个 IP 堆过十几条）。
       放在补建之后是为了不留解封窗口：新规则已经挡住了，再删旧的才安全
    3. 重试 `failed` 记录 —— 失败原因多数是「封禁那会儿防火墙没开」，现在开了就该补上

    防火墙未启用时直接返回、不做任何写操作：这时补封一万条也不会拦下一个包。
    """
    res: Dict[str, Any] = {
        "ok": False,
        "legacy_removed": 0,
        "restored": [],
        "failed": [],
        "error": "",
    }
    if not firewall.is_admin():
        res["error"] = "需要管理员权限才能修改 Windows 防火墙"
        return res
    if firewall.firewall_enabled(force=True) is False:
        res["error"] = (
            "Windows 防火墙当前未启用（"
            + firewall.format_profiles(firewall.profiles_state())
            + "），补封不会有任何效果"
        )
        return res

    # 1) 补建 active 封禁
    targets: List[BanRecord] = []
    try:
        targets = list(list_all_active_bans())
    except Exception as e:
        log.exception("读取活动封禁失败")
        res["error"] = f"读取活动封禁失败：{e}"
        return res

    if retry_failed:
        try:
            targets += list(query_bans(status=STATUS_FAILED, limit=500))
        except Exception:
            log.exception("读取失败封禁记录失败（忽略，只补 active）")

    seen: set = set()
    for ban in targets:
        if ban.ip in seen:
            continue
        seen.add(ban.ip)
        name = firewall.rule_name(ban.ip)
        if ban.status == STATUS_ACTIVE and firewall.rule_exists(name):
            if ban.rule_name != name:
                with contextlib.suppress(Exception):
                    update_ban(ban.id, rule_name=name)
            continue
        ok, rule, err = firewall.block_ip(ban.ip, ban.duration_sec, note=ban.reason)
        if ok:
            with contextlib.suppress(Exception):
                update_ban(ban.id, rule_name=rule, status=STATUS_ACTIVE, error_msg="")
            res["restored"].append(ban.ip)
        else:
            res["failed"].append(f"{ban.ip}: {err}")

    # 2) 清历史遗留规则
    if cleanup_legacy:
        legacy = firewall.legacy_rule_names()
        if legacy:
            n, errs = firewall.remove_rules(legacy)
            res["legacy_removed"] = n
            if errs:
                res["failed"].extend(errs[:10])

    res["ok"] = True
    if res["restored"] or res["legacy_removed"]:
        audit.record(
            audit.ACTION_BAN_RECONCILE,
            actor=audit.ACTOR_SYSTEM,
            target_type="ban",
            summary=(
                f"补齐封禁 {len(res['restored'])} 条，清理历史规则 {res['legacy_removed']} 条"
            ),
            after={
                "restored": res["restored"][:50],
                "legacy_removed": res["legacy_removed"],
            },
        )
    log.info(
        "封禁对齐完成：补建 %d 条，清理历史规则 %d 条，失败 %d 条",
        len(res["restored"]),
        res["legacy_removed"],
        len(res["failed"]),
    )
    return res


def format_reenforce(res: Dict[str, Any]) -> str:
    """把 reenforce_all 的结果整理成一句人能读的话（状态栏 / 弹窗共用）"""
    if not res.get("ok"):
        return res.get("error") or "对齐失败"
    parts: List[str] = []
    if res.get("restored"):
        parts.append(f"补建规则 {len(res['restored'])} 条")
    if res.get("legacy_removed"):
        parts.append(f"清理历史规则 {res['legacy_removed']} 条")
    if res.get("failed"):
        parts.append(f"失败 {len(res['failed'])} 条")
    return "，".join(parts) or "无变化（库与防火墙已一致）"
