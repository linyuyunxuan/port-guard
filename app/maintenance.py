"""
PortGuard — 数据与文件维护（不依赖 Qt）

- 访问日志按保留天数清理
- 离线库备份保留最近 N 份，其余删除（否则每次同步都留一份 11~37MB 的副本）
- 下载临时目录清扫（异常中断可能留下 .part）
"""

import os
from typing import Tuple

from core import settings as cfg
from core.config import backup_dir, download_dir
from core.database import delete_old_access
from core.logger import get_logger

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


def run_all() -> Tuple[int, int, int]:
    """一次性维护（供定时器调用）"""
    return cleanup_logs(), cleanup_backups(), cleanup_downloads()
