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
from typing import Any, Optional

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


def acquire(name: str = DEFAULT_MUTEX_NAME) -> bool:
    """尝试成为唯一实例。True = 本进程是唯一实例。"""
    global _handle

    if sys.platform != "win32":  # pragma: no cover —— 本项目只跑 Windows
        return True
    if _should_allow_multi():
        return True

    with _lock:
        if _handle is not None:
            # 本进程已经获取过，说明是重复调用而非「另一个实例」
            return False

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
            return False

        _handle = int(handle)
        atexit.register(release)
        return True


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
