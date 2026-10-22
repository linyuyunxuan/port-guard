"""事件页自动刷新的节流护栏（gui/mixins.py 的 `_flush_events_refresh`）。

为什么要有这一层：整表重渲染的耗时随行数线性增长（2000 行约 0.5 秒），
而事件泵 150ms 一拍。攻击时风险事件成批到达，如果「来一条刷一次」，
刷新会一轮压一轮 —— 界面越刷越滞后，正好在最需要看列表的时候最卡。

这里钉四条语义：

1. 同一拍里攒下的脏标记只刷一次（合并）；
2. 两次自动刷新之间有最小间隔，且按上次耗时自适应退避；
3. 单次渲染过慢 → 先自动降档（2000 → 500 → 200 行）继续刷，降到最小档
   仍慢才暂停并明示（手动刷新永远有效）；
4. 页面不可见时不刷、也不丢脏标记（切回来还能立刻看到最新）。
"""

import time
from types import SimpleNamespace
from typing import Any, List

from gui import mixins


class _FakePage:
    """替身页面：只实现节流用到的那三个方法"""

    def __init__(self, cost: float = 0.0, downgradable: bool = True):
        self.cost = cost
        self.downgradable = downgradable
        self.calls: List[bool] = []
        self.auto_paused = False
        self.paused_calls: List[bool] = []
        self.downgrades = 0

    def refresh(self, auto: bool = False) -> None:
        self.calls.append(auto)
        if self.cost:
            time.sleep(self.cost)

    def set_auto_paused(self, paused: bool) -> None:
        self.paused_calls.append(bool(paused))
        self.auto_paused = bool(paused)

    def downgrade_rows(self) -> bool:
        """返回 True 表示「还有更小档位，已经降了」"""
        if not self.downgradable:
            return False
        self.downgrades += 1
        # 降一档就便宜一档，模拟真实曲线（2000 行 1.37s → 500 行 0.36s → 200 行 80ms）
        self.cost = min(self.cost, mixins.EVENTS_SLOW_RENDER_SEC * 0.4)
        return True


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
        self._events_burst = 0


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


def test_slow_render_downgrades_rows_before_pausing() -> None:
    """渲染慢先降档，不要一上来就停刷。

    依据实测：60 秒攻击压测（200 条/秒、2000 行档位）里旧逻辑只刷了 1 次就
    永久暂停，而当时 CPU 才 7.9% —— 卡的是「一次渲染多少行」，不是资源不够。
    攻击期恰恰是用户最需要盯列表的时候，停刷等于把最该看的东西藏起来。
    """
    page = _FakePage(cost=mixins.EVENTS_SLOW_RENDER_SEC + 0.05)
    host = _host(page)
    host._events_dirty = True
    host._flush_events_refresh()

    assert page.downgrades == 1, "过慢却没有降档"
    assert host._events_paused is False, "还有更小档位就停刷，等于放弃治疗"
    assert page.paused_calls == []
    # 降档后要接着刷：脏标记留着，间隔回到最小
    assert host._events_dirty is True
    assert host._events_interval == mixins.EVENTS_REFRESH_MIN_SEC


def test_slow_render_pauses_auto_refresh_at_smallest_limit() -> None:
    """已经降到最小档还慢才暂停，并在界面上明说"""
    page = _FakePage(cost=mixins.EVENTS_SLOW_RENDER_SEC + 0.05, downgradable=False)
    host = _host(page)
    host._events_dirty = True
    host._flush_events_refresh()

    assert page.downgrades == 0
    assert host._events_paused is True
    assert page.paused_calls == [True], "暂停了却不在界面上说，用户只会以为程序卡死"

    # 暂停后再来事件：不再刷新
    host._events_dirty = True
    host._flush_events_refresh()
    assert page.calls == [True]


def test_downgrade_keeps_refreshing_afterwards() -> None:
    """降档的目的就是「继续刷」：下一拍必须真的再刷一次新的条数"""
    page = _FakePage(cost=mixins.EVENTS_SLOW_RENDER_SEC + 0.05)
    host = _host(page)
    host._events_dirty = True
    host._flush_events_refresh()
    assert page.calls == [True]

    host._events_ready_at = 0.0  # 跳过最小间隔等待
    host._events_dirty = True
    host._flush_events_refresh()
    assert page.calls == [True, True], "降档之后就再也不刷新了，等于换了个理由停刷"
    assert host._events_paused is False


def test_burst_downgrades_before_the_first_slow_render() -> None:
    """攻击信号一出现就先降档，别先把最大档位完整渲染一遍。

    实测依据：只靠「上次渲染太慢」来降档时，攻击刚起来的那一次必然要渲染
    2000 行（含一次 Python 全量 GC）—— 心跳最长 1763ms，正是用户第一次
    要看列表的时刻。改判据后第一屏就按小档位渲染。
    """
    page = _FakePage()  # 这次渲染本身不慢，慢的是「还没发生的那一次」
    host = _host(page)
    host._events_burst = mixins.EVENTS_BURST_HINT
    host._events_dirty = True
    host._flush_events_refresh()

    assert page.downgrades == 1, "拍内条数已经到攻击量级，却还按最大档位渲染"
    assert page.calls == [True], "降档不能把这次刷新吞掉"

    # 降档后攻击还在继续：下一拍继续往下走（2000 → 500 → 200），收敛即可
    host._events_ready_at = 0.0
    host._events_burst = mixins.EVENTS_BURST_HINT
    host._events_dirty = True
    host._flush_events_refresh()
    assert page.downgrades == 2


def test_burst_below_hint_does_not_touch_the_limit() -> None:
    """业务高峰（单拍十几条）不许自动改用户的筛选条件"""
    page = _FakePage()
    host = _host(page)
    host._events_burst = mixins.EVENTS_BURST_HINT - 1
    host._events_dirty = True
    host._flush_events_refresh()

    assert page.downgrades == 0
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
    page = _FakePage(cost=mixins.EVENTS_SLOW_RENDER_SEC + 0.05, downgradable=False)
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


def test_downgrade_walks_down_one_step_at_a_time(fresh_db) -> None:
    """降档走 2000 → 500 → 200，到最小档返回 False 交给调用方去暂停"""
    page = _page_for_downgrade(fresh_db)

    assert page._limit_value() == 2000
    assert page.downgrade_rows() is True
    assert page._limit_value() == 500
    assert page.downgrade_rows() is True
    assert page._limit_value() == 200
    assert page.downgrade_rows() is False, "最小档还返回 True，调用方会以为降成功了"
    assert page._limit_value() == 200


def test_downgrade_does_not_reload_by_itself(fresh_db) -> None:
    """降档只改档位，不在这里顺手重刷：这一拍已经花掉 1.4 秒了，别再叠一次"""
    page = _page_for_downgrade(fresh_db)
    loads: List[int] = []
    page._load = lambda: loads.append(1)

    assert page.downgrade_rows() is True
    assert loads == [], "降档顺带重刷，会在同一次事件泵里叠两遍渲染"


def test_downgrade_is_announced_in_the_info_line(fresh_db) -> None:
    """降档必须写在计数行：否则「列表怎么只剩 200 条」会被当成 bug"""
    page = _page_for_downgrade(fresh_db)
    page.downgrade_rows()
    page.refresh()
    assert "已临时降到最近 500 条" in page.lbl_info.text()

    # 用户自己把条数改回去，提示要自动消失（不能一直挂着一句过期的话）
    page.limit.setCurrentIndex(2)
    page.refresh()
    assert "已临时降到" not in page.lbl_info.text()


def _page_for_downgrade(fresh_db: Any) -> Any:
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
    page.limit.setCurrentIndex(2)  # 最近 2000 条
    return page
