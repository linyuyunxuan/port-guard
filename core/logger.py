"""
PortGuard — 日志系统

为什么需要：原实现里关键路径全靠 `except Exception: pass`，线上出问题
（上报丢数据、防火墙命令失败、xdb 加载异常）没有任何痕迹，无法排障。

策略：
- 统一 logger 名 `portguard`，子模块用 `get_logger(__name__)` 获取
- 轮转落盘到 <用户数据目录>/logs/portguard.log（5MB × 5 份）
- 有控制台时同时输出到 stderr（pythonw 启动无 stderr，自动跳过）
- 目录不可写时降级为 NullHandler，绝不因为日志把主流程搞崩
"""
import logging
import os
import sys
from logging.handlers import RotatingFileHandler

_LOGGER_NAME = "portguard"
_configured = False
_MAX_BYTES = 5 * 1024 * 1024
_BACKUP_COUNT = 5

_FORMAT = "%(asctime)s %(levelname)-7s [%(threadName)s] %(name)s: %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"


def logs_dir() -> str:
    """日志目录（用户数据目录下的 logs/）"""
    from core.config import user_data_dir
    d = os.path.join(user_data_dir(), "logs")
    os.makedirs(d, exist_ok=True)
    return d


def log_file() -> str:
    return os.path.join(logs_dir(), "portguard.log")


def setup(level: int = logging.INFO, console: bool = True) -> logging.Logger:
    """初始化日志（幂等，多次调用只生效一次）"""
    global _configured
    logger = logging.getLogger(_LOGGER_NAME)
    if _configured:
        return logger

    logger.setLevel(level)
    logger.propagate = False

    fmt = logging.Formatter(_FORMAT, datefmt=_DATEFMT)

    try:
        handler = RotatingFileHandler(
            log_file(), maxBytes=_MAX_BYTES, backupCount=_BACKUP_COUNT,
            encoding="utf-8", delay=True)
        handler.setFormatter(fmt)
        logger.addHandler(handler)
    except Exception:
        # 目录不可写等情况：退化为仅控制台，绝不抛异常打断启动
        logger.addHandler(logging.NullHandler())

    if console:
        try:
            if sys.stderr is not None and sys.stderr.fileno() >= 0:
                sh = logging.StreamHandler(sys.stderr)
                sh.setFormatter(fmt)
                logger.addHandler(sh)
        except Exception:
            pass

    _configured = True
    return logger


def get_logger(name: str = "") -> logging.Logger:
    """取子 logger（未初始化时自动初始化）"""
    if not _configured:
        setup()
    if not name:
        return logging.getLogger(_LOGGER_NAME)
    short = name[5:] if name.startswith("core.") else name
    return logging.getLogger(f"{_LOGGER_NAME}.{short}")


# 全局 logger：`from core.logger import log`
log = logging.getLogger(_LOGGER_NAME)
