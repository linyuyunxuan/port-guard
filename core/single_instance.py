"""
PortGuard — 单实例保护

原来用 Qt 的 QSharedMemory，但 **PySide2（Qt5）并没有导出这个类**
（QtCore / QtGui / QtWidgets 里都找不到），而一套产物要同时跑在 Qt5 与 Qt6 上。
换成 Windows 命名互斥体（CreateMutexW）之后：

- 不依赖任何 Qt 绑定，Qt5 / Qt6 / 无界面模式都能用；
- Windows 7 SP1 起就有，覆盖 Win7 → Win11；
- 互斥体由内核持有，进程被强杀或崩溃时自动释放，不会像锁文件那样留下残留
  （这是不用「写一个 .lock 文件」的关键原因）。

语义：acquire() 返回 True 表示本进程拿到了唯一实例；返回 False 表示
已经有别的实例在跑。同一进程内重复调用 acquire() 视为失败。
"""

import atexit
import contextlib
import ctypes
import sys
import threading
import time
from typing import Any, Optional, Tuple

# 命名互斥体名。不带 Global\ 前缀 = 会话级（Local），
# 带 Global\ 需要 SeCreateGlobalPrivilege（管理员），对单机工具没必要。
DEFAULT_MUTEX_NAME = "PortGuard_SingleInstance_v1"

_ERROR_ALREADY_EXISTS = 183

# 关于开关：设成 1 可跳过单实例限制（调试多开时用）
ALLOW_MULTI_ENV = "PORTGUARD_ALLOW_MULTI"

_lock = threading.Lock()
_handle: Optional[int] = None
_k32: Optional[Any] = None


def _kernel32():
    """延迟加载 kernel32：非 Windows 环境下本模块也要能被导入（供测试跑）。"""
    global _k32
    if _k32 is None:
        _k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    return _k32


def _close(handle: int) -> None:
    with contextlib.suppress(Exception):  # pragma: no cover —— 关不掉也只能算了
        _kernel32().CloseHandle(handle)


def acquire(name: str = DEFAULT_MUTEX_NAME, wait_sec: float = 0.0) -> bool:
    """尝试成为唯一实例。True = 本进程是唯一实例。

    `wait_sec`：名字已被占用时最多再等多久（秒）。为什么需要它 —— 命令行入口
    （`--enable-firewall`）可能和界面几乎同时启动（开机脚本 / 安装器），
    这时候「对方还活着」和「对方刚好退出」看起来是一样的；短暂等一等再判失败，
    比直接放弃更符合预期。界面路径保持 0 秒（重复启动就该立刻提示）。
    """
    if sys.platform != "win32":  # pragma: no cover —— 本项目只跑 Windows
        return True
    if _should_allow_multi():
        return True

    deadline = time.monotonic() + max(0.0, wait_sec)
    while True:
        won, retryable = _try_acquire(name)
        if won:
            return True
        if not retryable or time.monotonic() >= deadline:
            return False
        time.sleep(0.2)


def _try_acquire(name: str) -> Tuple[bool, bool]:
    """(是否拿到, 是否值得重试)。名字被别的进程占着才值得重试"""
    global _handle

    with _lock:
        if _handle is not None:
            # 本进程已经获取过，说明是重复调用而非「另一个实例」
            return False, False

        k32 = _kernel32()
        k32.CreateMutexW.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p]
        k32.CreateMutexW.restype = ctypes.c_void_p

        handle = k32.CreateMutexW(None, False, name)
        if not handle:
            raise OSError(ctypes.get_last_error(), f"CreateMutexW 失败：{name}")

        if ctypes.get_last_error() == _ERROR_ALREADY_EXISTS:
            # 名字已存在 = 已有实例在跑。注意必须关掉这次拿到的句柄，
            # 否则会凭空多留一个引用，导致对方退出后本进程仍「占着」名字。
            _close(handle)
            return False, True

        _handle = int(handle)
        atexit.register(release)
        return True, False


def release() -> None:
    """释放互斥体。进程退出时内核也会自动释放，这里显式关一次更干净。"""
    global _handle
    with _lock:
        if _handle is not None:
            _close(_handle)
            _handle = None


def _should_allow_multi() -> bool:
    import os

    return str(os.environ.get(ALLOW_MULTI_ENV, "")).strip() in ("1", "true", "yes")
