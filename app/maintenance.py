"""
PortGuard — 数据与文件维护（不依赖 Qt）

- 访问日志（access_log）按保留天数清理
- 风险事件（risk_event）按**自己的**保留天数清理（比流水长，见核心说明）
- 封禁记录（ban_list）只清**终态**，且按**自己的**保留天数清理
- 审计记录（audit_log）按自己的保留天数清理（否则审计表自己就是新的无界表）
- 日志文件按保留天数清理（按日期滚动后的归档 + 历史遗留归档）
- 离线库备份保留最近 N 份，其余删除（否则每次同步都留一份 11~37MB 的副本）
- 下载临时目录清扫（异常中断可能留下 .part）

⚠️ 大批量 DELETE 会让 WAL 文件涨到与被删数据同量级，且 SQLite **不会自动把
这部分空间还给文件系统**（只是留给后续写入复用）。想要真正回收磁盘，需要
在清理后执行一次 `VACUUM`（设置页「数据库维护」里的入口，P2-7）。
"""

import os
import time
from typing import Tuple

from app import audit
from core import settings as cfg
from core.config import (
    DEFAULT_AUDIT_RETENTION_DAYS,
    DEFAULT_BAN_RETENTION_DAYS,
    DEFAULT_LOG_RETENTION_DAYS,
    DEFAULT_RISK_RETENTION_DAYS,
    backup_dir,
    download_dir,
)
from core.database import (
    delete_old_access,
    delete_old_audit,
    delete_old_bans,
    delete_old_risk_events,
)
from core.logger import get_logger, log_file, logs_dir

log = get_logger(__name__)

# 每个库保留的备份份数
KEEP_BACKUPS_PER_FILE = 3


def cleanup_logs(days: int = 0) -> int:
    """删除超过保留期的访问日志，返回删除条数"""
    days = days or cfg.get_int("log_retention_days", DEFAULT_LOG_RETENTION_DAYS)
    try:
        n = delete_old_access(days)
        if n:
            log.info("已清理 %d 条超过 %d 天的访问日志", n, days)
        return n
    except Exception:
        log.exception("清理过期日志失败")
        return 0


def cleanup_risk(days: int = 0) -> int:
    """
    删除超过保留期的**风险事件**，返回删除条数。

    ⚠️ 保留期**刻意独立**于访问日志（`risk_retention_days` 默认 90 天，
    比 `log_retention_days` 的 30 天长）。曾经踩过的坑：两者共用 30 天时，
    「这台机器三个月前被判过严重风险」会比流水更早消失，事件页的未处理计数
    还会在某天早上突然掉一大截。
    """
    days = days or cfg.get_int("risk_retention_days", DEFAULT_RISK_RETENTION_DAYS)
    try:
        n = delete_old_risk_events(days)
        if n:
            log.info("已清理 %d 条超过 %d 天的风险事件", n, days)
        return n
    except Exception:
        log.exception("清理过期风险事件失败")
        return 0


def cleanup_bans(days: int = 0) -> int:
    """
    删除超过保留期的**终态封禁记录**，返回删除条数。

    `active` / `pending` 永不清（见 `core.database.delete_old_bans` 的三条硬边界）：
    active 背后是一条真实存在的防火墙规则，pending 是「已插库、还没回填」的
    瞬态。把它们清掉等于替用户做「这次封禁没发生过」的决定。
    """
    days = days or cfg.get_int("ban_retention_days", DEFAULT_BAN_RETENTION_DAYS)
    try:
        n = delete_old_bans(days)
        if n:
            log.info("已清理 %d 条超过 %d 天的终态封禁记录", n, days)
        return n
    except Exception:
        log.exception("清理过期封禁记录失败")
        return 0


def cleanup_audit(days: int = 0) -> int:
    """
    删除超过保留期的审计记录，返回删除条数。

    审计表自己也在持续写入（自动封禁、到期巡检、定期清理都会记），不给它
    保留期就等于「修好三张无界表的同时新造第四张」。默认 180 天。
    """
    days = days or cfg.get_int("audit_retention_days", DEFAULT_AUDIT_RETENTION_DAYS)
    try:
        n = delete_old_audit(days)
        if n:
            log.info("已清理 %d 条超过 %d 天的审计记录", n, days)
        return n
    except Exception:
        log.exception("清理过期审计记录失败")
        return 0


def due_today() -> bool:
    """
    判断今天的定期清理是不是该跑了；判定通过时顺手把「今天已跑」落库。

    执行时刻由设置 `maintenance_hour`（0-23，默认 3 点）决定，跨天自动重置。
    首次运行（从没清理过）不受时刻限制，立即跑一次，免得新装用户等一天。

    放在这里而不是界面层：逻辑不依赖 Qt，可以直接单测（原实现埋在 QTimer
    回调里，除了跑起来看日志没有别的验证办法）。
    """
    now = time.localtime()
    today = time.strftime("%Y-%m-%d", now)
    last = (cfg.get("maintenance_last_date", "") or "").strip()
    if last == today:
        return False
    if last and now.tm_hour < cfg.get_int("maintenance_hour", 3):
        return False
    cfg.set("maintenance_last_date", today)
    return True


def cleanup_log_files(days: int = 0) -> int:
    """
    删除超过保留期的日志文件（按日期），返回删除个数。

    为什么还要单独扫一遍：文件日志虽然是按天滚动的，但「滚动」只在**有日志
    写入**时才发生，而且旧版本用的是按大小滚动（portguard.log.1 ~ .5）。程序
    若长期不写日志、或经历过版本升级，logs/ 下就会留下永远不会被回收的归档。
    这里按 mtime 做一次兜底清扫，保证「日志保留 N 天」是真的 N 天。

    安全边界：绝不删除当前正在写入的 portguard.log —— 一是它是活跃句柄，
    二是 Windows 上删除在用文件本来也会失败。
    """
    days = max(1, int(days or cfg.get_int("log_retention_days", 30)))
    removed = 0
    try:
        d = logs_dir()
        active = os.path.basename(log_file()).lower()
        cutoff = time.time() - days * 86400
        for f in os.listdir(d):
            if f.lower() == active or ".log" not in f.lower():
                continue
            p = os.path.join(d, f)
            if not os.path.isfile(p):
                continue
            try:
                if os.path.getmtime(p) < cutoff:
                    os.remove(p)
                    removed += 1
            except OSError:
                log.exception("删除过期日志文件失败：%s", f)
        if removed:
            log.info("已清理 %d 个超过 %d 天的日志文件", removed, days)
    except Exception:
        log.exception("清理日志文件失败")
    return removed


def cleanup_backups(keep: int = KEEP_BACKUPS_PER_FILE) -> int:
    """每个离线库只保留最近 keep 份备份，返回删除文件数"""
    removed = 0
    try:
        d = backup_dir()
        groups: dict = {}
        for f in os.listdir(d):
            if "." not in f:
                continue
            name = f.rsplit(".", 2)[0] if f.count(".") >= 2 else f
            groups.setdefault(name, []).append(f)
        for _name, files in groups.items():
            files.sort(reverse=True)  # 文件名内含时间戳，倒序即最新在前
            for stale in files[keep:]:
                try:
                    os.remove(os.path.join(d, stale))
                    removed += 1
                except Exception:
                    log.exception("删除旧备份失败：%s", stale)
        if removed:
            log.info("已清理 %d 个过期离线库备份", removed)
    except Exception:
        log.exception("清理离线库备份失败")
    return removed


def cleanup_downloads() -> int:
    """清扫下载临时目录（.part / .new 残留）"""
    removed = 0
    try:
        d = download_dir()
        for f in os.listdir(d):
            p = os.path.join(d, f)
            if os.path.isfile(p) and (f.endswith((".part", ".new"))):
                try:
                    os.remove(p)
                    removed += 1
                except Exception:
                    pass
    except Exception:
        log.exception("清理下载临时目录失败")
    return removed


#: `run_all()` 返回值的字段顺序。改这里必须同步改 gui/mixins.py 的解包。
RUN_ALL_FIELDS = ("访问记录", "风险事件", "封禁记录", "审计记录", "日志文件", "备份", "下载残留")


def run_all() -> Tuple[int, int, int, int, int, int, int]:
    """
    一次性维护（供定时器调用）。

    返回 (访问记录, 风险事件, 封禁记录, 审计记录, 日志文件, 备份, 下载残留)，
    字段顺序见 `RUN_ALL_FIELDS`。

    审计在**清理之后**记一次汇总，而且刻意放在最后：它是唯一会在本次清理中
    被自己删掉一部分的表，先记后清意味着刚写的这条可能立刻被删。
    """
    rows = cleanup_logs()
    risk = cleanup_risk()
    bans = cleanup_bans()
    files = cleanup_log_files()
    backups = cleanup_backups()
    downloads = cleanup_downloads()
    audits = cleanup_audit()
    total = rows + risk + bans + audits
    if total or files or backups or downloads:
        audit.record(
            audit.ACTION_DATA_CLEANUP,
            actor=audit.ACTOR_SYSTEM,
            target_type="data",
            summary=(
                f"定期清理：访问 {rows}、事件 {risk}、封禁 {bans}、审计 {audits}、"
                f"日志文件 {files}、备份 {backups}、下载残留 {downloads}"
            ),
            after={
                "access_log": rows,
                "risk_event": risk,
                "ban_list": bans,
                "audit_log": audits,
                "log_files": files,
                "backups": backups,
                "downloads": downloads,
            },
            detail=(
                "大批量删除会让 WAL 文件变大且不会自动归还磁盘，"
                "需要回收空间请在设置页执行数据库维护（VACUUM）"
            ),
        )
    return rows, risk, bans, audits, files, backups, downloads
