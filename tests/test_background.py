"""后台任务脚手架的护栏（gui/background.py）。

这一层的存在理由：界面线程里每起一个 netsh / powershell 就是 100~300ms 的完全
冻结，几十条到期解封能假死几十秒。挪到后台之后有两件事必须钉死：

1. **回调一定在主线程**——在工作线程里改 QWidget 会让 Qt 随机崩溃，而这种崩溃
   偶发、无栈、只在客户现场出现；
2. **异常必须带 traceback 回到界面**——后台线程的异常默认被吞进 stderr，
   窗口化运行时连 stderr 都没有，现场只剩「点了没反应」。
"""

import threading
import time
from typing import Any, List

from gui.background import BackgroundTask, BusyGuard, run_in_background


def _qapp():
    import os

    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from qtcompat import QApplication

    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication([])
    return app


def _pump_until(app, predicate, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        app.processEvents()
        if predicate():
            return True
        time.sleep(0.01)
    return False


def test_result_comes_back_on_the_main_thread() -> None:
    app = _qapp()
    seen: List[Any] = []

    def work() -> str:
        # 工作线程里确实不是主线程
        seen.append(("worker_thread", threading.current_thread() is threading.main_thread()))
        return "done"

    def on_done(result: str) -> None:
        # 回调必须在主线程：在工作线程里改控件会让 Qt 随机崩
        seen.append(("ui_thread", threading.current_thread() is threading.main_thread()))
        seen.append(("result", result))

    owner = BackgroundTask()  # 任意 QObject 都能当 owner
    task = run_in_background(owner, work, on_done, name="t")
    assert task is not None
    assert _pump_until(app, lambda: any(isinstance(s, tuple) and s[0] == "result" for s in seen))

    assert ("worker_thread", False) in seen, "任务没有真的跑在后台线程"
    assert ("ui_thread", True) in seen, "回调没回到主线程，改控件会随机崩"
    assert ("result", "done") in seen


def test_exception_returns_traceback_text() -> None:
    app = _qapp()
    errors: List[str] = []

    def boom() -> None:
        raise RuntimeError("netsh 挂了")

    owner = BackgroundTask()
    run_in_background(owner, boom, None, errors.append, name="t")
    assert _pump_until(app, lambda: bool(errors))
    assert "RuntimeError" in errors[0] and "netsh 挂了" in errors[0]


def test_task_is_released_after_finish() -> None:
    """跑完必须从 owner 上摘掉：否则每次巡检都会攒一个死线程对象"""
    app = _qapp()
    owner = BackgroundTask()
    done: List[int] = []
    run_in_background(owner, lambda: None, lambda _r: done.append(1), name="t")
    assert _pump_until(app, lambda: bool(done))
    # finished 的清理是同一批排队的，再抽一拍让它落地
    _pump_until(app, lambda: not getattr(owner, "_bg_tasks", []), timeout=1.0)
    assert getattr(owner, "_bg_tasks", []) == []


def test_busy_guard_blocks_reentry() -> None:
    """重复点击不能起第二个进程（解封 / 对账 / 巡检都用它挡）"""
    guard = BusyGuard()
    assert guard.enter("1.2.3.4") is True
    assert guard.enter("1.2.3.4") is False
    assert "1.2.3.4" in guard
    # 不同 key 互不影响：同时解封两个 IP 是允许的
    assert guard.enter("5.6.7.8") is True
    guard.leave("1.2.3.4")
    assert "1.2.3.4" not in guard
    assert guard.enter("1.2.3.4") is True
    guard.clear()
    assert len(guard) == 0
