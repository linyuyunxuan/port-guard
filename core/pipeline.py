"""
PortGuard — 记录处理流水线（本机采集双通道共用）

一条记录从「已经是合法的 AccessRecord」到「落库 + 投递 UI + 告警 + 自动封禁」
的完整链路，抽成独立模块的原因：

本机采集有**两条互不相干的通道**
  1. TCP 连接表快照   → core/port_watcher.py（table）
  2. Windows 防火墙日志 → core/win_fwlog.py（fwlog）

两条通道必须走**完全一致**的归属地查询、规则评分、落库事务、告警与自动封禁，
否则「TCP 表看到的直连」与「防火墙日志看到的被丢包连接」会得出不一致的结论 ——
那是排障时最难查的一类问题（同一个 IP 在两条通道一个高危一个正常）。

本模块不依赖 Qt，可单测。
"""

import time
from typing import Optional

from core import settings as cfg
from core.database import find_active_ban_by_ip
from core.db_writer import get_writer
from core.event_bus import bus
from core.geo_locator import get_locator
from core.logger import get_logger
from core.models import (
    DISPOSITION_BLOCK,
    STATUS_ACTIVE,
    STATUS_FAILED,
    AccessRecord,
    BanRecord,
    RiskResult,
    disposition_base,
)
from core.rule_engine import get_engine, is_never_ban

log = get_logger(__name__)


def _resolve_ban_duration(ip: str, result: RiskResult) -> int:
    """
    自动封禁该封多久：规则级 > 递增级 > 等级级 > 默认（见 app.ban_service）。

    为什么在函数内 import app：分层上 core 不该在模块级依赖 app（现有代码里
    core→app 的边一条都没有）。这里只在「真的触发自动封禁」这条冷路径上借用一次
    业务层策略实现，放函数内既不动分层，也避免将来出现模块级循环依赖。

    ⚠️ 必须在 insert_ban **之前**调用：递增策略要数「历史封禁次数」，
    插库后再算会把本次自己数进去，第一次封禁就被当成第二次而直接翻倍。
    """
    from app.ban_service import resolve_duration_detail

    try:
        decision = resolve_duration_detail(
            score=result.score, level=result.level, rule_ids=result.matched_rules, ip=ip
        )
    except Exception:
        # 策略解析失败（规则库读不到 / 设置值是脏数据）不能挡住封禁
        log.exception("解析封禁时长策略失败 ip=%s，退回默认时长", ip)
        return max(1, cfg.get_int("default_ban_duration_sec", 3600))
    log.info(
        "自动封禁时长按「%s」取 %d 秒：%s（ip=%s）",
        decision.source_label,
        decision.seconds,
        decision.detail,
        ip,
    )
    return decision.seconds


def auto_ban_record(
    rec: AccessRecord,
    result: RiskResult,
    actor: Optional[str] = None,
    existing: Optional[BanRecord] = None,
) -> bool:
    """
    自动模式：无需人工确认直接封禁（默认关闭，需在设置页显式开启）。

    与手动封禁的关系：这里只是把「已经在 ban_records 里落一条 pending」
    与「真的去改防火墙」串起来，最终结果通过 bus.emit_ban 回给 UI，
    与手动封禁走的是同一个封禁页展示。

    参数 `existing` 由 `process_record` 预先查好传进来（它本来就要查一次来判断
    处置结论是「已拦截」还是「待确认」），省掉高频路径上的第二次查库。

    返回「本次是否真的把这批访问拦下来了」——用于决定这条记录的处置结论。

    已处于封禁状态（ban_list 中该 IP 有 active 记录）时直接返回：
    不插记录、不调防火墙、不发 emit_ban。与手动路径 app/ban_service.py
    的口径一致。这一步是必须的 —— 自动路径是「每次达标事件都触发一次」，
    同一个攻击者持续扫描会在每秒都满足封禁条件，缺了查重就会不断
    insert 新记录并新建防火墙规则（规则名带随机后缀，不会互相覆盖），
    最终规则数无限增长、封禁页被重复记录填满。
    """
    from core.database import insert_ban, update_ban
    from core.firewall import block_ip

    if is_never_ban(rec.ip):
        return False

    # 已封禁则直接返回。查库失败不能阻断封禁（宁可多一次封禁尝试，
    # 也不能因为一次查询异常就放过正在扫描的 IP），所以异常只记日志。
    #
    # 只按 active 查重、不拦 pending：pending 在本函数内是「插库 → 调防火墙 →
    # 回填 active/failed」之间的瞬态，正常情况下几毫秒就消失；而一旦进程在这
    # 个窗口里被杀掉（关机 / 崩溃），残留的 pending 就再没人回填，若把 pending
    # 也算作「已在封禁中」，这个 IP 将被永久漏封，是比偶发重复更糟的结果。
    # 至于两个采集通道同时命中的并发窗口（微秒级），不值得为此在高频路径
    # 上加全局锁 —— 后续真要收紧，应该走数据库唯一约束而不是锁。
    if existing is None:
        try:
            existing = find_active_ban_by_ip(rec.ip)
        except Exception:
            log.exception("自动封禁：查询已有封禁记录失败 ip=%s", rec.ip)
    if existing:
        # 自动路径高频触发，用 debug 而不是 warning，避免刷屏淹没真正的问题
        log.debug(
            "自动封禁跳过：ip=%s 已在封禁中（记录 #%s）",
            rec.ip,
            existing.id,
        )
        return True

    duration = _resolve_ban_duration(rec.ip, result)
    expire = int(time.time() * 1000) + duration * 1000
    rec_ban = BanRecord(
        ip=rec.ip,
        reason=f"[自动] {result.reason}",
        risk_score=result.score,
        source="auto",
        status="pending",
        duration_sec=duration,
        expire_at=expire,
    )
    ban_id = None
    try:
        ban_id = insert_ban(rec_ban)
    except Exception:
        log.exception("自动封禁：写入 pending 记录失败 ip=%s", rec.ip)
    ok, name, err = block_ip(rec.ip, duration, note=result.reason)
    if ban_id:
        try:
            update_ban(
                ban_id,
                status=(STATUS_ACTIVE if ok else "failed"),
                rule_name=name,
                error_msg=err,
            )
        except Exception:
            log.exception("自动封禁：回填记录失败 ban_id=%s", ban_id)
    if ok:
        log.warning("自动封禁生效 ip=%s rule=%s score=%d", rec.ip, name, result.score)
    else:
        log.error("自动封禁失败 ip=%s err=%s", rec.ip, err)

    # 审计。这里必须记 —— 自动封禁是**唯一没有人在场**的封禁路径，
    # 事后「这个 IP 为什么被封」只能靠这条记录回答。actor 由调用方带进来
    # （本机采集是 `system`，见 process_record；老库里还留着 `http:<来源IP>`）。
    #
    # 懒导入而不是顶层导入：app.audit 依赖 core.database，而 core.database 在
    # 导入期又会牵到本模块的模型，顶层互引会在部分入口下成环。
    # 本文件 `from app.ban_service import ...` 也是同样的懒导入写法。
    from app.audit import ACTION_BAN_AUTO as _ACTION
    from app.audit import ACTOR_SYSTEM as _SYSTEM
    from app.audit import RESULT_FAIL as _FAIL
    from app.audit import RESULT_OK as _OK
    from app.audit import record as _audit

    _audit(
        _ACTION,
        actor=actor or _SYSTEM,
        target_type="ban",
        target_id=ban_id,
        summary=(
            f"自动封禁 {rec.ip}"
            + (f" {duration} 秒" if duration else " 永久")
            + ("成功" if ok else f"失败：{err}")
        ),
        before={
            "ip": rec.ip,
            "score": result.score,
            "level": result.level,
            "matched": result.matched_rules,
            "reason": result.reason,
        },
        after={
            "ban_id": ban_id,
            "status": STATUS_ACTIVE if ok else STATUS_FAILED,
            "rule": name,
            "duration_sec": duration,
        },
        result=_OK if ok else _FAIL,
        detail=err or "",
    )

    bus.emit_ban(
        {
            "ip": rec.ip,
            "ok": ok,
            "rule_name": name,
            "error": err,
            "source": "auto",
            "ban_id": ban_id,
            "auto": True,
        }
    )
    return bool(ok)


def process_record(
    rec: AccessRecord,
    *,
    allow_auto_ban: bool = True,
    emit_alert: bool = True,
    actor: Optional[str] = None,
) -> RiskResult:
    """
    处理一条已构造好的访问记录。

    参数：
    · allow_auto_ban —— 是否允许触发自动封禁。本机采集在「仅观察」模式下
      会传 False（用户可能只是想知道谁在访问，不想因为自采数据就封人）。
    · emit_alert —— 是否投递告警事件（托盘气泡/声音）。
    · actor —— 这条记录的「发起人」，只用于自动封禁的审计。
      本机采集传 `system`，留空按 system 处理。

    返回评估结果（调用方通常还需要它来构造响应体）。
    """
    # 1. 归属地（整库在内存，微秒级；内部有 LRU）
    geo = get_locator().lookup(rec.ip)
    rec.geo = geo

    # 2. 规则评估（含区域白名单规则的优先级处理）
    result = get_engine().evaluate(rec, geo)
    rec.risk_score = result.score
    rec.risk_level = result.level
    rec.matched_rules = result.matched_rules
    rec.suggest_ban = result.suggest_ban

    # 3. 处置结论必须在**落库与告警之前**定下来，因为两者说的都是「最终结论」：
    #    落库存的是结论，弹窗显示的是结论。事后再改就得改两处，界面还可能先
    #    弹「仅提醒」再跳成「已拦截」—— 用户看不懂到底拦没拦。
    #
    #    顺序也因此调整过：原来 `emit_alert` 在前、自动封禁在后，弹窗只能写
    #    「风险评分 90」，因为它说不出这次到底拦没拦。现在先封、后提醒。
    #    代价是告警延后一次防火墙写入（几十~几百毫秒），换弹窗里一句确定的
    #    「已拦截」，这个交换是值得的：告警的价值在于让人知道结果，不在于抢秒。
    if not result.disposition:
        # 引擎漏填时兜底（自定义引擎 / 老插件）；正常路径上引擎已经填好
        result.disposition = disposition_base(result.level, result.whitelisted)
    if result.is_risk:
        existing = None
        try:
            existing = find_active_ban_by_ip(rec.ip)
        except Exception:
            # 查库失败不能阻断主流程：宁可当成「没封过」，也不能因为一次
            # 查询异常就丢掉这条风险记录的告警。
            log.exception("查询封禁状态失败 ip=%s", rec.ip)
        # 两种「已拦截」：这个 IP 本来就在封禁中（防火墙前面已经挡住了），
        # 或者本次触发了自动封禁并且真的写进了防火墙。
        # 写成一条 `or` 是为了让「结论只有一个赋值点」—— 分成两个分支各自赋值
        # 的话，以后加第三种拦截来源必然只改一处。
        if existing is not None or (
            allow_auto_ban
            and result.suggest_ban
            and cfg.get_bool("auto_mode", False)
            and result.score >= cfg.get_int("auto_ban_threshold", 90)
            # 自动封禁默认关闭，条件全满足才会走到调用；and 短路保证了顺序
            and auto_ban_record(rec, result, actor=actor, existing=existing)
        ):
            result.disposition = DISPOSITION_BLOCK

    # 实时监控页直接读 rec.disposition（它不查库，也不需要知道具体封禁记录）
    rec.disposition = result.disposition

    # 4. 投递落库（非阻塞：入队即返回，由单写线程批量提交）
    writer = get_writer()
    if result.is_risk:
        # 风险条目：访问日志 + 风险事件在同一事务内写入并关联 access_id
        writer.submit_risk(rec, result)
    else:
        writer.submit_access(rec)

    # 5. 投递给 UI（实时监控）
    bus.emit_access(rec)

    # 6. 风险事件后续处理
    if result.is_risk:
        bus.emit_risk({"record": rec, "result": result})

        if emit_alert:
            bus.emit_alert(
                {
                    "ip": rec.ip,
                    "level": result.level,
                    "score": result.score,
                    "reason": result.reason or "命中风险规则",
                    "geo": geo.display,
                    "local_port": rec.local_port,
                    # 弹窗/托盘气泡都靠这个字段回答「到底拦没拦」
                    "disposition": result.disposition,
                }
            )

    return result
