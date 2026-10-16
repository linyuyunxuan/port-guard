"""
PortGuard — 封禁编排（不依赖 Qt，可脱离界面单测）

为什么单独抽出来：原实现把「校验 → 落库 → 调防火墙 → 回填 → 投递事件」
全塞在 `MainWindow._execute_ban` 里，既无法单测，也让封禁入口分散在多处
（右键菜单 / 风险事件页 / 封禁页 / 自动模式），容易出现某条路径漏校验。

这里把校验收敛成唯一入口 `prepare()`，所有调用方都必须过它。
"""
import contextlib
import time
from typing import List, Optional, Tuple

from core import firewall
from core.database import (
    find_active_ban_by_ip,
    insert_ban,
    list_expired_bans,
    mark_ban_unbanned,
    update_ban,
)
from core.event_bus import bus
from core.logger import get_logger
from core.models import (
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_PENDING,
    BanRecord,
)
from core.rule_engine import is_never_ban
from core.validators import InvalidIP, clamp_int, normalize_ip, safe_text

log = get_logger(__name__)

MAX_BAN_SECONDS = 365 * 24 * 3600
MAX_IP_LEN = 64


class BanError(Exception):
    """封禁前置校验失败（消息可直接展示给用户）"""


def prepare(ip: str, score: int = 0, reason: str = "",
            duration_sec: int = 0) -> BanRecord:
    """
    校验并构造封禁记录（**不落库、不执行**）。
    这里是所有封禁路径的唯一校验入口。
    """
    try:
        safe_ip = normalize_ip(ip)
    except InvalidIP as e:
        raise BanError(str(e)) from e

    if is_never_ban(safe_ip):
        raise BanError(f"{safe_ip} 属于内网 / 回环 / 保留地址，PortGuard 永不封禁此类地址")

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


def execute(ip: str, score: int = 0, reason: str = "",
            duration_sec: int = 0, source: str = "manual") -> Tuple[Optional[int], str]:
    """
    完整封禁流程：校验 → 写 pending → 调防火墙 → 回填结果 → 投递事件。
    返回 (ban_id, 错误信息)。成功时错误信息为空串。

    注意：调用方应在后台线程执行（防火墙命令可能耗时数秒）。
    """
    if not firewall.is_admin():
        return None, "需要管理员权限才能修改 Windows 防火墙"

    try:
        rec = prepare(ip, score, reason, duration_sec)
    except BanError as e:
        log.warning("拒绝封禁：%s", e)
        return None, str(e)
    rec.source = source

    # 已处于封禁状态：不重复创建规则
    existing = None
    try:
        existing = find_active_ban_by_ip(rec.ip)
    except Exception:
        log.exception("查询已有封禁记录失败 ip=%s", rec.ip)
    if existing:
        return existing.id, f"{rec.ip} 已处于封禁状态（记录 #{existing.id}）"

    try:
        ban_id = insert_ban(rec)
    except Exception as e:
        log.exception("写入封禁记录失败 ip=%s", rec.ip)
        return None, f"写入封禁记录失败：{e}"

    ok, name, err = firewall.block_ip(rec.ip, rec.duration_sec, note=rec.reason)
    try:
        update_ban(ban_id,
                   status=(STATUS_ACTIVE if ok else STATUS_FAILED),
                   rule_name=name, error_msg=err)
    except Exception:
        log.exception("回填封禁结果失败 ban_id=%s", ban_id)

    bus.emit_ban({"ip": rec.ip, "ok": ok, "rule_name": name, "error": err,
                  "ban_id": ban_id, "source": source})
    if ok:
        log.info("封禁成功 ip=%s rule=%s 时长=%s", rec.ip, name,
                 rec.duration_sec or "永久")
    return ban_id, ("" if ok else err)


def unban(ban: BanRecord) -> Tuple[bool, str]:
    """解封单条记录（防火墙规则 + 数据库状态）"""
    if not firewall.is_admin():
        return False, "需要管理员权限才能修改 Windows 防火墙"
    names = [ban.rule_name] if ban.rule_name else []
    ok, err, n = firewall.unblock_ip(ban.ip, names)
    if not ok:
        log.warning("解封失败 ip=%s err=%s", ban.ip, err)
        return False, err or "未知错误"
    try:
        update_ban(ban.id, status="unbanned")
    except Exception:
        log.exception("回填解封状态失败 ban_id=%s", ban.id)
    log.info("已解封 ip=%s（删除 %d 条规则）", ban.ip, n)
    return True, ""


def unban_all() -> Tuple[bool, int, str]:
    """一键解封所有 PortGuard 规则"""
    if not firewall.is_admin():
        return False, 0, "需要管理员权限才能修改 Windows 防火墙"
    ok, n, err = firewall.unblock_all()
    if not ok:
        return False, 0, err or "未知错误"
    try:
        from core.database import query_bans
        for b in query_bans(status=STATUS_ACTIVE, limit=100000):
            update_ban(b.id, status="unbanned")
    except Exception:
        log.exception("批量回填解封状态失败")
    return True, n, ""


def check_expired(now: Optional[int] = None) -> List[BanRecord]:
    """
    到期解封巡检：把已到期但仍 active 的封禁真正解掉。
    返回本次成功解封的记录列表。
    """
    if not firewall.is_admin():
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
                mark_ban_unbanned(b.id, STATUS_EXPIRED)
            except Exception:
                log.exception("标记到期解封失败 ban_id=%s", b.id)
            done.append(b)
            log.info("封禁已到期自动解封 ip=%s（记录 #%s）", b.ip, b.id)
        else:
            with contextlib.suppress(Exception):
                update_ban(b.id, error_msg=err)
    return done


def reconcile(rule_names: List[str]) -> int:
    """
    与防火墙对账：数据库里 active 但防火墙中已不存在的规则，标记为已解封。
    返回修正条数。
    """
    from core.database import query_bans
    existing = set(rule_names or [])
    fixed = 0
    for b in query_bans(status=STATUS_ACTIVE, limit=100000):
        if b.rule_name and b.rule_name not in existing:
            try:
                update_ban(b.id, status="unbanned")
                fixed += 1
            except Exception:
                log.exception("对账修正失败 ban_id=%s", b.id)
    log.info("与防火墙对账完成：现存规则 %d 条，修正 %d 条失效记录", len(existing), fixed)
    return fixed
