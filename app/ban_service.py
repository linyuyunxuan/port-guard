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
    MAX_BAN_DURATION_DEFAULT_SEC,
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
    DISPOSITION_BLOCK,
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

#: 最大封禁时长（秒）的内置默认值：7 天（值在 core.config，界面也用同一个）。
#:
#: 为什么需要这个「硬上限」：Windows 防火墙规则**没有到期时间**（见 core/firewall.py
#: 关于「规则无时长」的注释），到期完全靠进程内 60 秒巡检去删规则。程序一旦长期
#: 不在（关机、卸载、崩溃后没人管），「封 365 天」就等于永久封掉一个可能无辜的
#: 地址，而没有任何东西会把它解掉。7 天是「够打击 / 不会变事故」的折中，可在
#: 设置页「封禁策略」里调整，上限本身最高到 365 天。
#: 上限本身不允许低于 1 小时：配成 5 分钟等于让封禁形同虚设
_MIN_MAX_BAN_SEC = 3600


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


def max_ban_seconds() -> int:
    """
    当前生效的封禁时长硬上限（秒）。

    取设置 `max_ban_duration_sec` 与内置 365 天兜底的较小者；非法值退回 7 天。

    ⚠️ **永久封禁（`duration_sec=0`，黑名单）不受此限**：0 是用户显式选择的
    「永久拦截」语义，把它截成一个有限值会让「设为黑名单」第二天自动失效。
    这里限制的是「有限时长到底能多长」。
    """
    configured = cfg.get_int("max_ban_duration_sec", MAX_BAN_DURATION_DEFAULT_SEC)
    return clamp_int(configured, _MIN_MAX_BAN_SEC, MAX_BAN_SECONDS, MAX_BAN_DURATION_DEFAULT_SEC)


def _sec(value: Any, fallback: Optional[int] = None) -> int:
    """
    把任意外部值收敛成合法封禁时长：`1 <= v <= 当前最大封禁时长`。

    非法 / 非正 / 超出上限时退回 fallback（再退 DEFAULT_BAN_DURATION_SEC）。
    这是「策略绝不返回 0」的唯一出口，别在别处绕过它。
    """
    v = clamp_int(value, 0, MAX_BAN_SECONDS, 0)
    if v <= 0:
        v = clamp_int(fallback, 0, MAX_BAN_SECONDS, 0)
    if v <= 0:
        v = DEFAULT_BAN_DURATION_SEC
    cap = max_ban_seconds()
    return max(_MIN_POLICY_SEC, min(v, cap))


def _default_raw(override: Optional[int] = None) -> int:
    """兜底时长的**原始配置值**（未经 `_sec` 收敛），只用于给出诚实的说明文字"""
    if override is not None:
        return int(override)
    return cfg.get_int("default_ban_duration_sec", DEFAULT_BAN_DURATION_SEC)


def _default_sec(override: Optional[int] = None) -> int:
    """兜底时长：优先用调用方给的 default，其次读设置，最后用内置默认"""
    return _sec(_default_raw(override))


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
    cap = max_ban_seconds()

    def _cut(requested: int) -> str:
        """被最大封禁时长截断时补一句说明，别让「为什么这么长」与实际生效值不符"""
        if requested > cap:
            return f"（受最大封禁时长 {format_duration(cap)} 限制，已截断）"
        return ""

    # 1. 规则级：最狠 = 最长
    hits = [(rid, _rule_duration_sec(rid)) for rid in (rule_ids or []) if rid]
    hits = [(rid, sec) for rid, sec in hits if sec > 0]
    if hits:
        rid, sec = max(hits, key=lambda kv: kv[1])
        return DurationDecision(
            _sec(sec, base),
            SOURCE_RULE,
            f"规则「{rule_label(rid)}」指定 {format_duration(sec)}{_cut(sec)}",
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
            raw = escalation_sec(start, prior)
            sec = _sec(raw, start)
            return DurationDecision(
                sec,
                SOURCE_ESCALATION,
                f"{ip} 历史已封禁 {prior} 次，基准 {format_duration(start)} × {factor}^{prior} → "
                f"{format_duration(sec)}{_cut(raw)}",
            )

    # 3. 等级级
    if tier > 0:
        return DurationDecision(
            _sec(tier, base),
            SOURCE_LEVEL,
            f"风险等级「{LEVEL_LABEL.get(lv or '', lv or '未定')}」对应 "
            f"{format_duration(tier)}{_cut(tier)}",
        )

    # 4. 默认
    raw_default = _default_raw(default)
    return DurationDecision(
        base,
        SOURCE_DEFAULT,
        f"未命中分档 / 递增，使用默认 {format_duration(raw_default)}{_cut(raw_default)}",
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
    · `>0`           —— 调用方指定的秒数（超出「最大封禁时长」会被截断）。
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
        # 0 = 永久封禁（黑名单在用），是用户显式选择的语义，不受上限影响。
        # 有限时长一律按「最大封禁时长」截断 —— 这是防「误封一年」的最后一道闸：
        # 防火墙规则没有到期时间，程序长期不在时没人会把它解掉。
        if duration > 0:
            cap = max_ban_seconds()
            if duration > cap:
                log.warning(
                    "封禁时长 %s 超过最大封禁时长 %s，已截断（ip=%s）",
                    format_duration(duration),
                    format_duration(cap),
                    safe_ip,
                )
                duration = cap

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
            # 处置结论一并改成「已拦截」：这条 IP 之后的访问真的会被防火墙挡下，
            # 事件页若还写「仅提醒」，用户会以为封禁只在库里生效。
            # 注意 disposition 是整批改（含人工忽略过的行）—— 按 IP 生效的
            # 防火墙不区分单条事件，事实就是它们都被拦了。
            marked = set_risk_handled_by_ip(rec.ip, 1, disposition=DISPOSITION_BLOCK)
            if marked:
                log.info("封禁 %s 后回填 %d 条事件为已确认/已拦截", rec.ip, marked)
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


#: 到期巡检「一轮最多解几条」。
#:
#: 为什么需要限速：一次解封 = 至少一次 netsh/PowerShell 删除（实测 100~400ms），
#: 再加一条审计写入。积压 300 条时一轮要跑两分钟以上，而巡检定时器是 60 秒一次 ——
#: 会一直处在「上一轮没跑完」的状态。分轮次处理既能让界面尽快看到进展，也不会
#: 让审计表在瞬间被灌满。剩下的不会丢：下一轮（60 秒后）继续，`expired_backlog()`
#: 会把真实积压数显示在权限条上。
EXPIRE_BATCH_LIMIT = 50


def check_expired(now: Optional[int] = None, limit: int = EXPIRE_BATCH_LIMIT) -> List[BanRecord]:
    """
    到期解封巡检：把已到期但仍 active 的封禁真正解掉。
    返回本次成功解封的记录列表。

    `limit`：本轮最多解多少条（默认 `EXPIRE_BATCH_LIMIT`）。传 0 或负数表示不限，
    仅供测试与手工修复使用。

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

    if limit and limit > 0 and len(expired) > limit:
        log.warning(
            "到期封禁积压 %d 条，本轮先解 %d 条，其余留待下一轮",
            len(expired),
            limit,
        )
        expired = expired[:limit]

    # 整轮只列一次规则清单。
    # unblock_ip 内部要按 IP 清理「同 IP 的历史规则」，不传快照就每条都自己列一次
    # （一次 PowerShell 200~600ms）—— 50 条就是 10~30 秒的纯列举开销，巡检会越拖越慢。
    try:
        existing: List[str] = list(firewall.list_rule_names())
    except Exception:
        log.exception("列举防火墙规则失败，本轮按逐条反解处理（会慢一些）")
        existing = []

    for b in expired:
        ok, err, _n = firewall.unblock_ip(b.ip, [b.rule_name] if b.rule_name else [], existing)
        if ok:
            if b.rule_name:
                # 快照是「本轮开始时」的，已经删掉的规则名要摘掉，
                # 否则后面的 IP 会重复尝试删除一个已不存在的规则并记一条失败
                with contextlib.suppress(ValueError):
                    existing.remove(b.rule_name)
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


#: 残留 pending 的判定阈值（秒）。`execute()` 写 pending → 调防火墙 → 回填结果
#: 之间被杀，记录会永远停在 pending；给一段宽限期再动手，避免把「正在封禁中」误收。
PENDING_STALE_SEC = 600


def recover_stale_pending(timeout_sec: int = PENDING_STALE_SEC) -> int:
    """
    启动时收敛「插了 pending 记录但进程中途被杀」的残留，返回处理条数。

    为什么必须做：`execute()` 的顺序是 写 pending → 调防火墙 → 回填结果。
    中间被杀（关机、崩溃、用户强杀）会留下一条永远 pending 的记录，而它有两种
    截然不同的真实状态，界面上却长得一模一样：
      · 防火墙里规则**已建**：其实拦住了，但因为不是 active，到期巡检永远不管它
        → 规则永久生效，误封变事故；
      · 防火墙里规则**没建**：其实没拦住，界面上却写着「封禁中」
        → 用户以为拦住了，最坏的一种假成功。
    所以启动时必须按「规则是否真实存在」回填，而不是按时间一刀切。

    ⚠️ 判定只依据防火墙规则清单，**绝不因为「超时了」就判失败**；非管理员读不到
    清单时一条都不动（宁可不收敛，也不凭空改状态）。
    """
    if not firewall.is_admin():
        return 0

    cutoff = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - max(60, timeout_sec)))
    try:
        # created_at 是本地时间字符串（YYYY-MM-DD HH:MM:SS），同格式可直接比大小
        rows = [
            b
            for b in query_bans(status=STATUS_PENDING, limit=2000)
            if b.created_at and b.created_at <= cutoff
        ]
    except Exception:
        log.exception("查询残留 pending 记录失败")
        return 0
    if not rows:
        return 0

    try:
        existing = set(firewall.list_rule_names())
    except Exception:
        log.exception("读取防火墙规则失败，本次不收敛残留 pending（避免误判）")
        return 0

    fixed = 0
    for b in rows:
        alive = bool(b.rule_name) and b.rule_name in existing
        status = STATUS_ACTIVE if alive else STATUS_FAILED
        msg = "" if alive else "进程在封禁过程中退出，防火墙规则未建立"
        try:
            update_ban(b.id, status=status, error_msg=msg)
        except Exception:
            log.exception("收敛残留 pending 失败 ban_id=%s", b.id)
            continue
        fixed += 1
        log.warning("残留 pending 已收敛：ip=%s（记录 #%s）→ %s", b.ip, b.id, status)
        audit.record(
            audit.ACTION_BAN_RECOVER,
            actor=audit.ACTOR_SYSTEM,
            target_type="ban",
            target_id=b.id,
            summary=f"{b.ip} 上次封禁未收尾，启动时按防火墙实际状态回填为「{status}」",
            before={"status": STATUS_PENDING, "rule_name": b.rule_name},
            after={"status": status},
            detail=msg,
        )
    return fixed


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
