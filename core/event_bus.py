"""
PortGuard — 跨线程事件总线

后台线程（HTTP 服务 / 规则评估 / 防火墙执行）只往队列里 put，
Qt 主线程用 QTimer 周期性 drain 并刷新界面。
这样后台线程永远不触碰任何 Qt 控件，从根本上避免跨线程崩溃。

本模块不依赖 PyQt，可独立测试。
"""

import queue
import threading
from typing import Any, List


class EventBus:
    """进程内唯一事件总线"""

    def __init__(
        self,
        access_size: int = 50000,
        risk_size: int = 10000,
        ban_size: int = 2000,
        alert_size: int = 2000,
        xdb_size: int = 500,
    ):
        self.access_q: queue.Queue = queue.Queue(maxsize=access_size)
        self.risk_q: queue.Queue = queue.Queue(maxsize=risk_size)
        self.ban_q: queue.Queue = queue.Queue(maxsize=ban_size)
        self.alert_q: queue.Queue = queue.Queue(maxsize=alert_size)
        self.xdb_q: queue.Queue = queue.Queue(maxsize=xdb_size)
        self._dropped = 0
        self._lock = threading.Lock()

    # ── 投递（后台线程调用）──
    def emit_access(self, rec: Any) -> None:
        self._put(self.access_q, rec)

    def emit_risk(self, obj: Any) -> None:
        self._put(self.risk_q, obj)

    def emit_ban(self, obj: Any) -> None:
        self._put(self.ban_q, obj)

    def emit_alert(self, obj: Any) -> None:
        self._put(self.alert_q, obj)

    def emit_xdb(self, obj: Any) -> None:
        """离线库在线同步的进度/结果事件"""
        self._put(self.xdb_q, obj)

    def _put(self, q: "queue.Queue", item: Any) -> None:
        try:
            q.put_nowait(item)
        except queue.Full:
            # 极端高并发时丢弃最旧的一条，保护 UI 不卡死
            try:
                q.get_nowait()
                q.put_nowait(item)
            except Exception:
                pass
            with self._lock:
                self._dropped += 1

    # ── 消费（UI 线程调用）──
    @staticmethod
    def drain(q: "queue.Queue", max_n: int = 500, batch: List[Any] | None = None) -> List[Any]:
        batch = [] if batch is None else batch
        try:
            while len(batch) < max_n:
                batch.append(q.get_nowait())
        except queue.Empty:
            pass
        return batch

    def drain_access(self, max_n: int = 500) -> List[Any]:
        return self.drain(self.access_q, max_n)

    def drain_risk(self, max_n: int = 200) -> List[Any]:
        return self.drain(self.risk_q, max_n)

    def drain_ban(self, max_n: int = 200) -> List[Any]:
        return self.drain(self.ban_q, max_n)

    def drain_alert(self, max_n: int = 50) -> List[Any]:
        return self.drain(self.alert_q, max_n)

    def drain_xdb(self, max_n: int = 100) -> List[Any]:
        return self.drain(self.xdb_q, max_n)

    @property
    def dropped(self) -> int:
        with self._lock:
            return self._dropped

    def pending(self) -> int:
        return (
            self.access_q.qsize()
            + self.risk_q.qsize()
            + self.ban_q.qsize()
            + self.alert_q.qsize()
            + self.xdb_q.qsize()
        )


# 全局单例
bus = EventBus()
