"""
PortGuard — 日志系统（工作日志）

为什么需要：原实现里关键路径全靠 `except Exception: pass`，线上出问题
（上报丢数据、防火墙命令失败、xdb 加载异常）没有任何痕迹，无法排障。

策略：
- 统一 logger 名 `portguard`，子模块用 `get_logger(__name__)` 获取
- 按【天】滚动落盘到 <用户数据目录>/logs/portguard.log，保留天数见
  `log_retention_days`（设置页可改，默认 30 天）；单日超 5MB 时再按大小兜底一次，
  防止日志风暴把磁盘写满
- 有控制台时同时输出到 stderr（pythonw / 打包后的窗口程序没有控制台，
  此时 `sys.stdout`/`sys.stderr` 为 None，由 `ensure_std_streams()` 顶上安全空流）
- 目录不可写时降级为 NullHandler，绝不因为日志把主流程搞崩
- `route_uvicorn_logs()` 把 uvicorn 自己的日志并到同一个文件，避免排障时
  要去两个地方找

⚠️ 关于 `sys.stdout is None`（2026-10-16 修）：
uvicorn 的 `DefaultFormatter.__init__` 会执行 `sys.stdout.isatty()`。窗口化运行
（pythonw 或 PyInstaller `console=False`）时 std 流为 None，于是抛
`AttributeError: 'NoneType' object has no attribute 'isatty'`，被
`logging.config.dictConfig` 包成 `ValueError: Unable to configure formatter 'default'`，
表现为「接收服务启动失败」——与端口占用、权限毫无关系。
这里用两道独立防线堵住：① `ensure_std_streams()` 保证 std 流永不为 None；
② 调用方给 uvicorn 传 `log_config=None`，根本不走它那套 formatter。
"""

import io
import logging
import os
import re
import sys
import threading
from logging.handlers import TimedRotatingFileHandler
from typing import List, Optional

_LOGGER_NAME = "portguard"
_configured = False
_setup_lock = threading.RLock()
_MAX_BYTES = 5 * 1024 * 1024
_DEFAULT_KEEP_DAYS = 30

_FORMAT = "%(asctime)s %(levelname)-7s [%(threadName)s] %(name)s: %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"

# 由 uvicorn 自己创建的 logger；它们的输出统一并入 portguard 的 handler
_UVICORN_LOGGERS = ("uvicorn", "uvicorn.error", "uvicorn.access")

_file_handler: Optional[logging.Handler] = None


class _NullStream(io.TextIOBase):
    """
    无控制台运行时的替身流。

    `isatty()` 恒为 False —— 等价于「输出不是终端」，所以第三方库（uvicorn
    的彩色 formatter 是典型）会走无色分支而不会崩。`fileno()` 故意抛 OSError，
    让「有没有真实控制台」的判断依然能得出正确结论（会走到 except 分支）。
    """

    encoding = "utf-8"
    errors = "replace"

    def write(self, s: str) -> int:
        return len(s)

    def writelines(self, lines) -> None:
        return None

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None

    def isatty(self) -> bool:
        return False

    def writable(self) -> bool:
        return True

    def readable(self) -> bool:
        return False

    def fileno(self) -> int:
        raise OSError("无控制台：没有可用的文件描述符")


class DailySizeRotatingFileHandler(TimedRotatingFileHandler):
    """
    按天滚动（便于「按日期清理」），同时按大小兜底。

    为什么要动标准库的两个地方：

    1. `TimedRotatingFileHandler.shouldRollover()` **只比较时间，完全不读
       `maxBytes`** —— 构造参数会被存下来但没有任何代码引用它。也就是说直接传
       `maxBytes=5MB` 是**静默失效**的：日志一旦遇到风暴（例如被封 IP 疯狂重试）
       可能长到几个 GB。这里补上大小判断。
    2. `doRollover()` 里那句 `if os.path.exists(dfn): os.remove(dfn)`：同一天内的
       第二次滚动会算出**相同**的目标文件名，于是把当天早些时候那份日志直接删掉
       —— 静默丢数据。这里通过 `rotation_filename()` 给同名归档补序号。

    取舍：归档份数（`backupCount`）与保留天数是同一个数字。日志风暴下当天会产生
    多个归档，可用空间会被更早用满，实际保留时间可能短于 N 天 —— 这是为「磁盘不
    被写满」付出的有意代价。
    """

    def __init__(self, filename: str, *, keep_days: int, max_bytes: int, **kwargs) -> None:
        super().__init__(
            filename,
            when="midnight",
            interval=1,
            backupCount=max(1, int(keep_days)),
            encoding="utf-8",
            delay=True,
            **kwargs,
        )
        self.maxBytes = max_bytes
        # 归档名可能是 portguard.log.2026-10-16，也可能是加过序号的 ..._2
        self.extMatch = re.compile(r"\d{4}-\d{2}-\d{2}(_\d+)?", re.ASCII)

    def shouldRollover(self, record) -> bool:
        if super().shouldRollover(record):
            return True
        if self.maxBytes <= 0:
            return False
        if self.stream is None:
            self.stream = self._open()
        self.stream.seek(0, os.SEEK_END)
        return self.stream.tell() + len(self.format(record)) + 1 >= self.maxBytes

    def rotation_filename(self, default_name: str) -> str:
        """同名归档加序号，避免同一天内的第二次滚动覆盖掉上一份"""
        if not os.path.exists(default_name):
            return default_name
        n = 1
        while True:
            n += 1
            candidate = f"{default_name}_{n}"
            if not os.path.exists(candidate):
                return candidate


def ensure_std_streams() -> List[str]:
    """
    窗口化运行（pythonw / 打包 exe 的 console=False）时 `sys.stdout` 与
    `sys.stderr` 是 None，任何 `sys.stdout.isatty()` / `sys.stderr.write()`
    都会把它们拖崩。这里顶上安全空流。

    返回被替换的流名列表，供调用方作为工作日志记录一条。
    """
    patched: List[str] = []
    for name in ("stdout", "stderr"):
        if getattr(sys, name, None) is None:
            setattr(sys, name, _NullStream())
            patched.append(name)
    return patched


def logs_dir() -> str:
    """日志目录（用户数据目录下的 logs/）"""
    from core.config import user_data_dir

    d = os.path.join(user_data_dir(), "logs")
    os.makedirs(d, exist_ok=True)
    return d


def log_file() -> str:
    return os.path.join(logs_dir(), "portguard.log")


def retention_days() -> int:
    """日志保留天数（设置 `log_retention_days`，读不到时用 30）"""
    try:
        from core import settings as cfg

        return max(1, cfg.get_int("log_retention_days", _DEFAULT_KEEP_DAYS))
    except Exception:
        return _DEFAULT_KEEP_DAYS


def set_retention(days: int) -> None:
    """
    运行时调整日志保留天数。

    `backupCount` 是滚动时才读取的属性，所以直接改即可生效，无需重建 handler
    （重建会让已打开的日志句柄短暂断开，可能丢行）。
    """
    if _file_handler is not None and hasattr(_file_handler, "backupCount"):
        _file_handler.backupCount = max(1, int(days))


def setup(level: int = logging.INFO, console: bool = True) -> logging.Logger:
    """初始化日志（幂等，多次调用只生效一次）"""
    global _configured, _file_handler
    with _setup_lock:
        logger = logging.getLogger(_LOGGER_NAME)
        if _configured:
            return logger

        # ⚠️ 必须**先置位再配置**。下面 `retention_days()` 会读设置 → 触达
        # core.database，而该模块末尾的 `log = get_logger(__name__)` 会回调
        # setup()。没有这道重入保护，就会被装上两套 handler —— 表现为每条日志
        # 在终端/文件里重复输出两遍（真实踩过）。
        _configured = True

        # 兜住 std 流：日志本身、以及后面所有第三方库都依赖它
        ensure_std_streams()

        logger.setLevel(level)
        logger.propagate = False

        fmt = logging.Formatter(_FORMAT, datefmt=_DATEFMT)

        try:
            handler: logging.Handler = DailySizeRotatingFileHandler(
                log_file(), keep_days=retention_days(), max_bytes=_MAX_BYTES
            )
            handler.setFormatter(fmt)
            logger.addHandler(handler)
            _file_handler = handler
        except Exception:
            # 目录不可写等情况：退化为仅控制台，绝不抛异常打断启动
            logger.addHandler(logging.NullHandler())
            _file_handler = None

        if console:
            try:
                if sys.stderr is not None and sys.stderr.fileno() >= 0:
                    sh = logging.StreamHandler(sys.stderr)
                    sh.setFormatter(fmt)
                    logger.addHandler(sh)
            except Exception:
                # _NullStream.fileno() 会抛 OSError —— 没有控制台，跳过即可
                pass

        return logger


def route_uvicorn_logs(level: int = logging.WARNING) -> None:
    """
    把 uvicorn 自己的 logger 接到 portguard 的 handler 上。

    配合 `uvicorn.Config(log_config=None)` 使用：完全不执行 uvicorn 的
    dictConfig，因此不会再碰它的 `DefaultFormatter`（那正是
    `Unable to configure formatter 'default'` 的来源）。
    """
    root = logging.getLogger(_LOGGER_NAME)
    for name in _UVICORN_LOGGERS:
        lg = logging.getLogger(name)
        lg.handlers = list(root.handlers)
        lg.propagate = False
        lg.setLevel(level)


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
