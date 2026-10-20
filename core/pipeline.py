"""
PortGuard — 记录处理流水线（上报来源 / 本机采集来源共用）

一条记录从「已经是合法的 AccessRecord」到「落库 + 投递 UI + 告警 + 自动封禁」
的完整链路，抽成独立模块的原因：

现在有**两类互不相干的来源**
  1. 业务系统 HTTP 上报          → core/report_server.py
  2. 本机端口访问采集（双通道）  → core/port_watcher.py

两条来源必须走**完全一致**的归属地查询、规则评分、落库事务、告警与自动封禁，
否则「本机自己看到的扫描」与「业务系统上报的攻击」会得出不一致的结论 ——
那是排障时最难查的一类问题（同一个 IP 在两处一个高危一个正常）。

本模块不依赖 Qt，可单测。
"""

import time
from typing import Any, Dict

from core import settings as cfg
from core.db_writer import get_writer
from core.event_bus import bus
from core.geo_locator import get_locator
from core.logger import get_logger
from core.models import STATUS_ACTIVE, AccessRecord, BanRecord, RiskResult
from core.rule_engine import get_engine, is_never_ban

log = get_logger(__name__)


def auto_ban_record(rec: AccessRecord, result: RiskResult) -> None:
    """
    自动模式：无需人工确认直接封禁（默认关闭，需在设置页显式开启）。

    与手动封禁的关系：这里只是把「已经在 ban_records 里落一条 pending」
    与「真的去改防火墙」串起来，最终结果通过 bus.emit_ban 回给 UI，
    与手动封禁走的是同一个封禁页展示。

    已处于封禁状态（ban_list 中该 IP 有 active 记录）时直接返回：
    不插记录、不调防火墙、不发 emit_ban。与手动路径 app/ban_service.py
    的口径一致。这一步是必须的 —— 自动路径是「每次达标事件都触发一次」，
    同一个攻击者持续扫描会在每秒都满足封禁条件，缺了查重就会不断
    insert 新记录并新建防火墙规则（规则名带随机后缀，不会互相覆盖），
    最终规则数无限增长、封禁页被重复记录填满。
    """
    from core.database import find_active_ban_by_ip, insert_ban, update_ban
    from core.firewall import block_ip

    if is_never_ban(rec.ip):
        return

    # 已封禁则直接返回。查库失败不能阻断封禁（宁可多一次封禁尝试，
    # 也不能因为一次查询异常就放过正在扫描的 IP），所以异常只记日志。
    #
    # 只按 active 查重、不拦 pending：pending 在本函数内是「插库 → 调防火墙 →
    # 回填 active/failed」之间的瞬态，正常情况下几毫秒就消失；而一旦进程在这
    # 个窗口里被杀掉（关机 / 崩溃），残留的 pending 就再没人回填，若把 pending
    # 也算作「已在封禁中」，这个 IP 将被永久漏封，是比偶发重复更糟的结果。
    # 至于两条上报线程同时命中的并发窗口（微秒级），不值得为此在高频上报路径
    # 上加全局锁 —— 后续真要收紧，应该走数据库唯一约束而不是锁。
    existing = None
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
        return

    duration = cfg.get_int("default_ban_duration_sec", 3600)
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


def process_record(
    rec: AccessRecord,
    *,
    allow_auto_ban: bool = True,
    emit_alert: bool = True,
) -> RiskResult:
    """
    处理一条已构造好的访问记录。

    参数：
    · allow_auto_ban —— 是否允许触发自动封禁。本机采集在「仅观察」模式下
      会传 False（用户可能只是想知道谁在访问，不想因为自采数据就封人）。
    · emit_alert —— 是否投递告警事件（托盘气泡/声音）。

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

    # 3. 投递落库（非阻塞：入队即返回，由单写线程批量提交）
    writer = get_writer()
    if result.is_risk:
        # 风险条目：访问日志 + 风险事件在同一事务内写入并关联 access_id
        writer.submit_risk(rec, result)
    else:
        writer.submit_access(rec)

    # 4. 投递给 UI（实时监控）
    bus.emit_access(rec)

    # 5. 风险事件后续处理
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
                }
            )

        # 自动封禁模式（默认关闭）
        if (
            allow_auto_ban
            and result.suggest_ban
            and cfg.get_bool("auto_mode", False)
            and result.score >= cfg.get_int("auto_ban_threshold", 90)
        ):
            auto_ban_record(rec, result)

    return result


def result_payload(rec: AccessRecord, result: RiskResult) -> Dict[str, Any]:
    """上报接口的响应体（与 v1.x 保持完全一致的字段）"""
    return {
        "id": None,
        "ip": rec.ip,
        "geo": rec.geo.display,
        "risk_score": result.score,
        "risk_level": result.level,
        "matched_rules": result.matched_rules,
        "suggest_ban": result.suggest_ban,
    }
