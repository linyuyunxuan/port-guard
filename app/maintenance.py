"""
PortGuard — 数据与文件维护（不依赖 Qt）

- 访问日志按保留天数清理
- 日志文件按保留天数清理（按日期滚动后的归档 + 历史遗留归档）
- 离线库备份保留最近 N 份，其余删除（否则每次同步都留一份 11~37MB 的副本）
- 下载临时目录清扫（异常中断可能留下 .part）
"""

import os
import time
from typing import Tuple

from core import settings as cfg
from core.config import backup_dir, download_dir
from core.database import delete_old_access
from core.logger import get_logger, log_file, logs_dir

log = get_logger(__name__)

# 每个库保留的备份份数
KEEP_BACKUPS_PER_FILE = 3


def cleanup_logs(days: int = 0) -> int:
    """删除超过保留期的访问日志，返回删除条数"""
    days = days or cfg.get_int("log_retention_days", 30)
    try:
        n = delete_old_access(days)
        if n:
            log.info("已清理 %d 条超过 %d 天的访问日志", n, days)
        return n
    except Exception:
        log.exception("清理过期日志失败")
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


def run_all() -> Tuple[int, int, int, int]:
    """一次性维护（供定时器调用）：(访问记录, 日志文件, 备份, 下载残留)"""
    return cleanup_logs(), cleanup_log_files(), cleanup_backups(), cleanup_downloads()
