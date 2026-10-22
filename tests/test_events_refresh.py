"""事件页自动刷新的节流护栏（gui/mixins.py 的 `_flush_events_refresh`）。

为什么要有这一层：整表重渲染的耗时随行数线性增长（2000 行约 0.5 秒），
而事件泵 150ms 一拍。攻击时风险事件成批到达，如果「来一条刷一次」，
刷新会一轮压一轮 —— 界面越刷越滞后，正好在最需要看列表的时候最卡。

这里钉四条语义：

1. 同一拍里攒下的脏标记只刷一次（合并）；
2. 两次自动刷新之间有最小间隔，且按上次耗时自适应退避；
3. 单次渲染过慢 → 暂停自动刷新并明示（手动刷新永远有效）；
4. 页面不可见时不刷、也不丢脏标记（切回来还能立刻看到最新）。
"""

import time
from types import SimpleNamespace
from typing import Any, List

from gui import mixins


class _FakePage:
    """替身页面：只实现节流用到的那两个方法"""

    def __init__(self, cost: float = 0.0):
        self.cost = cost
        self.calls: List[bool] = []
        self.auto_paused = False
        self.paused_calls: List[bool] = []

    def refresh(self, auto: bool = False) -> None:
        self.calls.append(auto)
        if self.cost:
            time.sleep(self.cost)

    def set_auto_paused(self, paused: bool) -> None:
        self.paused_calls.append(bool(paused))
        self.auto_paused = bool(paused)


class _Host(mixins.EventPumpMixin):
    """够用的宿主：节流只碰 stack / page_events / 四个状态字段

    直接继承 Mixin（它在运行期的基类是 object，见 gui/mixins.py 的 _HostBase），
    这样方法才是绑定的；用 SimpleNamespace 挂函数会因为拿不到 self 而报错。
    """

    def __init__(self, page: Any, visible: bool = True):
        self.stack: Any = SimpleNamespace(currentWidget=lambda: page if visible else object())
        self.page_events = page
        self._events_dirty = False
        self._events_interval = mixins.EVENTS_REFRESH_MIN_SEC
        self._events_ready_at = 0.0
        self._events_paused = False


def _host(page: Any, visible: bool = True) -> "_Host":
    return _Host(page, visible)


def test_dirty_flag_is_coalesced_into_one_refresh() -> None:
    """同一拍里来 50 条事件也只该刷一次 —— 这就是节流的全部意义"""
    page = _FakePage()
    host = _host(page)
    host._events_dirty = True
    host._flush_events_refresh()
    # 第二拍立刻又来事件：还没到下次可刷时间，必须跳过
    host._events_dirty = True
    host._flush_events_refresh()

    assert page.calls == [True], f"实际刷新 {len(page.calls)} 次"
    assert host._events_dirty is True, "被跳过的脏标记要留着，不能丢"


def test_interval_is_at_least_the_configured_minimum() -> None:
    page = _FakePage()
    host = _host(page)
    host._events_dirty = True
    host._flush_events_refresh()

    wait = host._events_ready_at - time.monotonic()
    assert wait > mixins.EVENTS_REFRESH_MIN_SEC * 0.5, "间隔太短等于没节流"
    assert host._events_interval >= mixins.EVENTS_REFRESH_MIN_SEC


def test_slow_render_pauses_auto_refresh() -> None:
    """渲染慢到用户能感到卡顿时：停掉自动刷新，别让界面一直在重建"""
    page = _FakePage(cost=mixins.EVENTS_SLOW_RENDER_SEC + 0.05)
    host = _host(page)
    host._events_dirty = True
    host._flush_events_refresh()

    assert host._events_paused is True
    assert page.paused_calls == [True], "暂停了却不在界面上说，用户只会以为程序卡死"

    # 暂停后再来事件：不再刷新
    host._events_dirty = True
    host._flush_events_refresh()
    assert page.calls == [True]


def test_invisible_page_neither_refreshes_nor_forgets() -> None:
    """停在别的页面时只是攒着：白刷一次就是几秒钟的卡顿"""
    page = _FakePage()
    host = _host(page, visible=False)
    host._events_dirty = True
    host._flush_events_refresh()

    assert page.calls == []
    assert host._events_dirty is True


def test_manual_refresh_resumes_auto_refresh() -> None:
    """用户手动刷过之后自动刷新要恢复，不能一停到底"""
    page = _FakePage(cost=mixins.EVENTS_SLOW_RENDER_SEC + 0.05)
    host = _host(page)
    host._events_dirty = True
    host._flush_events_refresh()
    assert host._events_paused is True

    host._resume_events_auto_refresh()
    assert host._events_paused is False
    assert host._events_ready_at == 0.0

    host._events_dirty = True
    host._flush_events_refresh()
    assert page.calls == [True, True]


def test_auto_refresh_is_flagged_as_automatic() -> None:
    """页面要知道这次刷新是自动的还是用户点的（暂停逻辑挂在自动那边）"""
    page = _FakePage()
    host = _host(page)
    host._events_dirty = True
    host._flush_events_refresh()
    assert page.calls == [True]


# ═══════════════════ 页面侧：暂停时自动刷新直接返回 ═══════════════════


def test_paused_page_ignores_auto_refresh_but_honours_manual(fresh_db) -> None:
    import os

    os.environ["QT_QPA_PLATFORM"] = "offscreen"

    from core import database
    from qtcompat import QApplication

    database.init_db()
    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication([])
    from gui.page_events import EventsPage

    page = EventsPage()
    loads: List[Any] = []
    page._load = lambda: loads.append(1)  # type: ignore[method-assign]

    page.set_auto_paused(True)
    assert "暂停自动刷新" in page.lbl_info.text()

    page.refresh(auto=True)
    assert loads == [], "暂停状态下自动刷新还在重载整表"

    # 手动刷新：照常加载，并且解除暂停、通知主窗口
    fired: List[int] = []
    page.refreshed_manually.connect(lambda: fired.append(1))
    page.refresh()
    assert loads == [1]
    assert page.auto_paused is False
    assert fired == [1]
    app.processEvents()
