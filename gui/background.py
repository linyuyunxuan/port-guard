"""PortGuard — 后台任务：把「会起进程 / 会等 IO」的调用挪出界面线程

为什么需要：界面线程里每起一个 `netsh` / `powershell` 进程就是 100~300ms 的
完全冻结（真实用例：30 条到期封禁逐条解封，界面能假死几十秒，用户强杀进程后
还会留下没删干净的防火墙规则）。这类调用必须挪到后台，结果用信号送回主线程
再碰控件 —— 在工作线程里直接改 QWidget 会让 Qt 随机崩。

用法（调用方必须在主线程）：

    run_in_background(
        self,                       # 任意 QObject/QWidget：既做父对象也负责保活
        lambda: ban_service.unban(rec),
        lambda result: self._on_done(result),
        lambda msg: self._on_failed(msg),
        name="unban",
    )

两条约定：

1. **回调都在主线程执行**。信号从工作线程发出、接收者住在主线程 → Qt 自动
   走队列连接（`BackgroundTask` 在主线程创建且从未 moveToThread）。
2. **任务对象由 owner 持有**，跑完自动断开并移除；不让它被 GC 提前回收，
   否则信号还没派发就被销毁，界面永远等不到结果。
"""

import contextlib
import threading
import traceback
from typing import Any, Callable, List, Optional

from core.logger import get_logger
from qtcompat import QObject, Signal

log = get_logger(__name__)


class BackgroundTask(QObject):
    """跑一个无参函数，把结果 / 异常文本 / 完成事件送回主线程"""

    done = Signal(object)  # 正常返回值
    failed = Signal(str)  # 异常文本（含 traceback）
    finished = Signal()  # 无论成败

    def __init__(self, parent: Optional[QObject] = None):
        super().__init__(parent)
        self._thread: Optional[threading.Thread] = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, fn: Callable[[], Any], name: str = "bg-task") -> None:
        def work() -> None:
            try:
                result = fn()
            except Exception:
                # 后台线程里的异常没人接，必须带 traceback 上报，否则只剩一句
                # 「操作没反应」，现场查不出根因
                log.exception("后台任务失败：%s", name)
                self.failed.emit(traceback.format_exc())
            else:
                self.done.emit(result)
            finally:
                self.finished.emit()

        self._thread = threading.Thread(target=work, daemon=True, name=name)
        self._thread.start()


def run_in_background(
    owner: QObject,
    fn: Callable[[], Any],
    on_done: Optional[Callable[[Any], None]] = None,
    on_error: Optional[Callable[[str], None]] = None,
    name: str = "bg-task",
) -> BackgroundTask:
    """在后台线程跑 fn；结果回主线程交给 on_done / on_error。

    owner 上会挂一个 `_bg_tasks` 列表保活 —— 只靠信号连接不足以阻止 Python 侧
    对象被回收（PySide 只保证 C++ 对象归父对象管）。
    """
    existing = getattr(owner, "_bg_tasks", None)
    tasks: List[BackgroundTask] = existing if isinstance(existing, list) else []
    if not isinstance(existing, list):
        # setattr 而不是直接赋值：owner 的类型是 QObject，静态检查不认动态属性
        setattr(owner, "_bg_tasks", tasks)  # noqa: B010

    task = BackgroundTask(owner)
    tasks.append(task)

    def _drop() -> None:
        if task in tasks:
            tasks.remove(task)
        # 父对象已销毁时 deleteLater 会抛 RuntimeError，这里不需要清理
        with contextlib.suppress(Exception):
            task.deleteLater()

    if on_done is not None:
        task.done.connect(on_done)
    if on_error is not None:
        task.failed.connect(on_error)
    task.finished.connect(_drop)
    task.start(fn, name=name)
    return task


#: 给页面用的「忙」标记：同一个动作不能并发跑两遍
class BusyGuard:
    """按 key 记录正在执行的动作（解封某条记录、对账、巡检…）

    界面上的意义：重复点击不该起第二个进程，而按钮/横幅要能说出「正在处理」。
    """

    def __init__(self) -> None:
        self._keys: set = set()

    def __contains__(self, key: object) -> bool:
        return key in self._keys

    def enter(self, key: object = "") -> bool:
        """占用 key；已经在跑则返回 False（调用方直接 return）"""
        if key in self._keys:
            return False
        self._keys.add(key)
        return True

    def leave(self, key: object = "") -> None:
        self._keys.discard(key)

    def clear(self) -> None:
        self._keys.clear()

    def __len__(self) -> int:
        return len(self._keys)
