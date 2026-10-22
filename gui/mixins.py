"""
PortGuard — 主窗口的行为 Mixin

原 `MainWindow` 是 609 行 God Object：UI 组装、托盘、事件泵、服务启停、
封禁编排、到期巡检、统计刷新、日志清理全塞在一起，改一处要在 600 行里翻找。

现在按职责拆开：
- 本文件（gui/mixins.py）：与 Qt 生命周期强耦合的胶水逻辑
  · EventPumpMixin —— 事件泵 / 统计刷新 / 状态栏
- app/*.py：不依赖 Qt 的业务编排（可单测）
- gui/main_window.py：只剩界面组装与信号连线
"""

import contextlib
import threading
import time
from typing import TYPE_CHECKING, Any, Dict, Optional

from app import ban_service, maintenance
from app.xdb_service import get_service as get_xdb_service
from core import settings as cfg
from core.config import (
    DEFAULT_AUDIT_RETENTION_DAYS,
    DEFAULT_BAN_RETENTION_DAYS,
    DEFAULT_RISK_RETENTION_DAYS,
    LEVEL_LABEL,
)
from core.database import count_active_bans, count_risk_unhandled, count_today
from core.event_bus import bus
from core.logger import get_logger
from gui.background import BusyGuard, run_in_background
from gui.theme import C
from qtcompat import QTimer

if TYPE_CHECKING:
    from core.alerts import Alerter
    from core.geo_locator import GeoLocator
    from gui.page_access import AccessPage
    from gui.page_bans import BansPage
    from gui.page_events import EventsPage
    from gui.page_iplookup import IpLookupPage
    from gui.page_logs import LogsPage
    from gui.page_monitor import MonitorPage
    from gui.page_settings import SettingsPage
    from qtcompat import QLabel, QMainWindow, QStackedWidget

    # 这两个 Mixin 运行时通过 MainWindow 组合成 QMainWindow 的子类，
    # 但单看 Mixin 自身，self 只是个 object —— 类型检查器因此既认不出
    # QTimer(self) 的父对象，也认不出 QMessageBox.warning(self, ...) 的窗口。
    # 这里只在「类型检查视角」把基类换成 QMainWindow，运行期仍是 object，
    # 因此不会影响实际 MRO（MainWindow 会显式继承 QMainWindow）。
    _HostBase = QMainWindow
else:
    _HostBase = object

log = get_logger(__name__)

# 事件泵节拍（毫秒）：兼顾实时感与 CPU
PUMP_INTERVAL_MS = 150
STATS_INTERVAL_MS = 2000
EXPIRE_INTERVAL_MS = 60_000
# 维护巡检节拍：只负责「看一眼今天到点没有」，真正的清理每天最多跑一次
CLEANUP_TICK_MS = 10 * 60_000

# ── 风险事件页的自动刷新节流（秒）──
# 为什么不能「来一条刷一次」：整表重建的耗时随行数线性增长（见 gui/row_action.py
# 开头的实测），而事件泵 150ms 一拍；攻击时风险事件成批到达，刷新会一轮压一轮，
# 界面越刷越滞后 —— 正好在最需要看列表的时候最卡。
# 所以：合并成一拍一刷、两次之间至少隔 EVENTS_REFRESH_MIN_SEC，并按上次渲染
# 耗时自适应退避；单次渲染超过 EVENTS_SLOW_RENDER_SEC 先**自动降档**（2000 →
# 500 → 200 行，攻击期最需要盯列表，不能停刷），降到最小档仍慢才暂停自动刷新
# 并在计数行明示（手动点「刷新」始终有效）。
EVENTS_REFRESH_MIN_SEC = 1.0
EVENTS_REFRESH_MAX_SEC = 5.0
EVENTS_SLOW_RENDER_SEC = 0.8
# 单拍（150ms）内新到的风险事件条数达到这个量，就认定「正在被攻击」，在刷新
# **之前**先降档。为什么不只靠「上次渲染太慢」：那样攻击期必然要先把最大档位
# 完整渲染一遍（实测 2000 行单次 1.66 秒，其中含一次 Python 全量 GC），这 1.6
# 秒的卡顿就发生在攻击刚起来的时刻，正是用户第一次要看列表的时候。
# 20 条/150ms ≈ 130 条/秒，正常业务流量（个位数/秒）差着一个数量级，不会误伤。
EVENTS_BURST_HINT = 20


class EventPumpMixin(_HostBase):
    """
    跨线程事件泵 + 统计刷新 + 状态栏

    下面的「宿主属性」由 MainWindow 在 __init__ 中创建；在此声明只是为了
    让类型检查器知道它们存在，运行期不产生任何实际赋值。
    """

    stack: "QStackedWidget"
    page_monitor: "MonitorPage"
    page_events: "EventsPage"
    page_access: "AccessPage"
    page_bans: "BansPage"
    page_settings: "SettingsPage"
    page_iplookup: "IpLookupPage"
    page_logs: "LogsPage"
    alerter: "Alerter"
    lbl_status: "QLabel"
    lbl_ban_count: "QLabel"
    lbl_geo: "QLabel"
    lbl_xdb: "QLabel | None"
    _last_stats: float
    # 事件页自动刷新的节流状态（见文件头的 EVENTS_* 常量）
    _events_dirty: bool
    _events_interval: float
    _events_ready_at: float
    _events_paused: bool
    # 本拍新到的风险事件条数（见 EVENTS_BURST_HINT）
    _events_burst: int
    _expire_busy: BusyGuard
    _maint_busy: BusyGuard

    # 这两个方法由 MainWindow 实现（MainWindow 自身的定义优先于 Mixin），
    # 在此声明仅为让类型检查器知道它们存在；单独使用本 Mixin 会直接报错，
    # 这也是刻意的——本 Mixin 不打算被独立实例化。
    def _is_admin(self) -> bool:
        raise NotImplementedError

    def _locator(self) -> "GeoLocator":
        raise NotImplementedError

    def _refresh_watch_label(self) -> None:
        raise NotImplementedError

    # 顶部 44 状态条的两项：服务运行态 / 本机观察态。
    # 状态栏已不再承担健康态（P0-8），文本与颜色由这里的调用方决定。
    def _set_watch_state(self, text: str, color: str) -> None:
        raise NotImplementedError

    def _set_ban_count(self, n: int) -> None:
        raise NotImplementedError

    def _maybe_poll_firewall(self) -> None:
        raise NotImplementedError

    def _setup_timers(self) -> None:
        # 事件页自动刷新：脏标记由事件泵置位，刷新本身按最小间隔节流
        self._events_dirty = False
        self._events_interval = EVENTS_REFRESH_MIN_SEC
        self._events_ready_at = 0.0
        self._events_paused = False
        self._events_burst = 0
        # 到期巡检在后台线程跑，用忙标记挡住「上一轮还没完下一轮又起」
        self._expire_busy = BusyGuard()
        # 每日维护（清理 + 自动备份）也走后台：清理要删几十万行，备份要拷库文件，
        # 放界面线程里跑就是「凌晨三点界面突然卡住几十秒」，被人当成崩了
        self._maint_busy = BusyGuard()

        # 主事件泵：批量把后台队列里的记录搬到界面
        self.pump = QTimer(self)
        self.pump.setInterval(PUMP_INTERVAL_MS)
        self.pump.timeout.connect(self._drain_events)
        self.pump.start()

        self.stat_timer = QTimer(self)
        self.stat_timer.setInterval(STATS_INTERVAL_MS)
        self.stat_timer.timeout.connect(self._refresh_stats)
        self.stat_timer.start()

        # 到期自动解封巡检
        self.expire_timer = QTimer(self)
        self.expire_timer.setInterval(EXPIRE_INTERVAL_MS)
        self.expire_timer.timeout.connect(self._check_expired)
        self.expire_timer.start()
        # 启动补检：定时器第一次触发在 60 秒后，而程序关了一整晚再打开时，
        # 这 60 秒里所有本该解封的 IP 仍然被封着。启动后立刻补跑一次。
        QTimer.singleShot(1500, self._check_expired)

        # 残留 pending 收敛：上次封禁「写完记录但没回填结果」的，要按防火墙实际
        # 状态补一个结论 —— 否则界面上它永远显示「封禁中」，而实际可能两头都不对。
        # 放在黑名单补封之前：它会改记录状态，后面的补封才看得到准确的 active 集合。
        QTimer.singleShot(2500, self._recover_pending)

        # 黑名单补封：普通权限下加入的黑名单只落了文件（当时已明确提示「未拦截」），
        # 之后以管理员身份启动必须补上，否则「名单里有、实际没拦」会一直存在。
        QTimer.singleShot(3000, self._enforce_blacklist)

        # 封禁对齐：补建缺失规则 + 清理历史重复规则（一个 IP 堆十几条的老问题）。
        # 放在黑名单补封之后：那时活动封禁已经齐全，清理旧规则不会留漏洞。
        QTimer.singleShot(5000, self._reenforce_bans)

        # 日志/备份清理：每 10 分钟看一眼，每天到点才真跑（见 _maintenance_due）
        self.clean_timer = QTimer(self)
        self.clean_timer.setInterval(CLEANUP_TICK_MS)
        self.clean_timer.timeout.connect(self._cleanup_logs)
        self.clean_timer.start()

        # 离线库自动同步调度（间隔由设置决定，默认 24 小时）
        self.xdb_timer = QTimer(self)
        self.xdb_timer.setInterval(10 * 60_000)
        self.xdb_timer.timeout.connect(lambda: self._maybe_sync_xdb(first_run=False))
        self.xdb_timer.start()

    def _drain_events(self) -> None:
        # 1) 实时访问记录
        records = bus.drain_access(500)
        if records:
            self.page_monitor.append_records(records)
            # 同一批记录同时喂给「运行日志」页的端口访问日志流
            self.page_logs.append_access(records)

        # 2) 风险事件
        risks = bus.drain_risk(200)
        # 本拍数量单独记：`_flush_events_refresh` 用它判断「是不是正在被攻击」，
        # 从而在渲染之前就降档（见 EVENTS_BURST_HINT）。每拍重算，不累积。
        self._events_burst = len(risks)
        if risks:
            last = risks[-1]
            rec, res = last.get("record"), last.get("result")
            if rec and res:
                self._set_status(
                    f"风险事件：{rec.ip} · {LEVEL_LABEL.get(res.level, res.level)} · "
                    f"{res.score} 分 · {rec.geo.region_short if rec.geo else '未知'}",
                    C.warning,
                )
            # 页面不可见时不刷新（原实现每次事件都重载整表）。
            # 判据用「当前页是不是这个页面对象」而不是下标常量：导航顺序会变
            # （P2-4 在事件页与封禁页之间插了「历史访问」），写死下标就会静默刷错页。
            self._events_dirty = True

        # 3) 告警（只走程序内弹窗与托盘气泡）
        for a in bus.drain_alert(50):
            self.alerter.notify(a)

        # 4) 封禁结果
        bans = bus.drain_ban(200)
        if bans:
            for b in bans:
                if b.get("error"):
                    self._set_status(f"封禁 {b.get('ip')} 失败：{b.get('error')}", C.danger)
                else:
                    self._set_status(f"已封禁 {b.get('ip')}", C.success)
            # 封禁会连带改两处状态：该 IP 的事件变「已确认」、行内「封禁」按钮
            # 变「已封禁」。当前页不重刷的话，用户看到的是封禁前的快照 ——
            # 「封了但什么都没变」的观感就是这么来的。
            cur = self.stack.currentWidget()
            if cur is self.page_events:
                # 走同一个节流入口：批量封禁会连着来几十条结果，逐条刷等于自锁
                self._events_dirty = True
            elif cur is self.page_bans and self.page_bans.isVisible():
                self.page_bans.refresh()
            self._refresh_stats(force=True)

        # 5) 离线库同步事件
        for ev in bus.drain_xdb(100):
            self._on_xdb_event(ev)

        # 6) 事件页合并刷新（必须放在本拍最后：本拍攒到的脏标记一次刷完）
        self._flush_events_refresh()

    def _flush_events_refresh(self) -> None:
        """把本拍攒下的「事件页需要刷新」落到界面上（节流 + 自适应退避）

        脏标记只有「当前页就是事件页」时才消费；停在别的页时一直攒着，
        切回来时由导航处的 refresh 统一处理，不会漏也不会白刷。
        """
        if not self._events_dirty:
            return
        if self.stack.currentWidget() is not self.page_events:
            return

        if self._events_paused:
            # 暂停期间不再刷：脏标记留着（用户点「刷新」时会重新加载），
            # 但每拍都调用一次 set_auto_paused 只会重复写同一行字，这里直接跳过
            self._events_dirty = False
            return

        now = time.monotonic()
        if now < self._events_ready_at:
            return

        self._events_dirty = False
        # 攻击信号：单拍新到的事件条数已经达到「几百条/秒」的量级，就在这一次
        # 渲染**之前**把条数档位降下来。否则第一屏必然要完整渲染最大档位，
        # 用户第一次看列表时正好卡住（实测量到 1.66 秒）。
        burst, self._events_burst = self._events_burst, 0
        if burst >= EVENTS_BURST_HINT and self.page_events.downgrade_rows():
            log.info("单拍新增 %d 条风险事件，攻击期先降档再看列表", burst)

        started = time.monotonic()
        self.page_events.refresh(auto=True)
        cost = time.monotonic() - started

        if cost >= EVENTS_SLOW_RENDER_SEC:
            # 先降档，别急着停刷：事件激增正是最需要盯着列表的时刻，停刷等于把
            # 最该看的东西藏起来（实测旧逻辑在 60 秒攻击压测里只刷了 1 次就永久
            # 暂停，而 CPU 才 7.9% —— 卡的是渲染行数，不是资源）。
            # 2000 行单次 1.37s → 500 行约 0.36s → 200 行约 80ms，降两档后仍能
            # 每秒刷一次，点击响应（心跳 P95 18ms）不受影响。
            if self.page_events.downgrade_rows():
                log.info("事件页单次刷新 %.0fms，已临时降低显示条数", cost * 1000)
                self._events_interval = EVENTS_REFRESH_MIN_SEC
                self._events_ready_at = time.monotonic() + self._events_interval
                self._events_dirty = True  # 降档后的新条数还没渲染，下一拍补上
                return
            # 已经是最小档还慢：这时候再刷只会让界面长期处于「一直在重建」，
            # 停掉自动刷新、把决定权交回用户（手动「刷新」始终有效）。
            self._events_paused = True
            self._events_interval = EVENTS_REFRESH_MAX_SEC
            self._events_ready_at = time.monotonic() + EVENTS_REFRESH_MAX_SEC
            self.page_events.set_auto_paused(True)
            log.info("事件页单次刷新 %.0fms，已暂停自动刷新", cost * 1000)
            return

        # 退避系数 3：渲染 300ms → 间隔 900ms，仍留 2/3 的时间给用户操作
        self._events_interval = min(EVENTS_REFRESH_MAX_SEC, max(EVENTS_REFRESH_MIN_SEC, cost * 3))
        self._events_ready_at = time.monotonic() + self._events_interval

    def _resume_events_auto_refresh(self) -> None:
        """用户手动刷新过事件页：解除暂停并重置节流窗口"""
        self._events_paused = False
        self._events_interval = EVENTS_REFRESH_MIN_SEC
        self._events_ready_at = 0.0
        self._events_dirty = False

    def _on_xdb_event(self, ev: Dict) -> None:
        """离线库同步进度 → 状态栏 + 设置页进度条"""
        stage = ev.get("stage", "")
        msg = ev.get("message", "")
        pct = int(ev.get("percent", 0) or 0)
        try:
            self.page_settings.on_xdb_progress(stage, msg, pct)
        except Exception:
            log.exception("刷新离线库同步进度失败")

        color = C.text_secondary
        if stage == "failed":
            color = C.danger
        elif stage in ("done",):
            color = C.success
        elif stage in ("download", "verify", "apply", "reload", "check"):
            color = C.warning
        self._set_status(f"离线库同步：{msg}", color)
        if self.lbl_xdb is not None:
            self.lbl_xdb.setText(f"IP 库 {msg[:24]}")
            self.lbl_xdb.setStyleSheet(f"color:{color};font-size:12.5px;")
            self.lbl_xdb.setToolTip(msg)

        if stage == "done":
            with contextlib.suppress(Exception):
                self.page_iplookup._update_lib_info()
            # 换库后缓存已清空，刷新一次统计里的定位库提示
            self._poll_geo_after_update()

    def _poll_geo_after_update(self) -> None:
        try:
            loc = self._locator()
            # 与 main_window._poll_geo 同一口径：状态栏只写「已加载」，细节进 tooltip
            self.lbl_geo.setText("定位库 已加载")
            self.lbl_geo.setStyleSheet(f"color:{C.success};font-size:12.5px;")
            self.lbl_geo.setToolTip(
                f"离线定位库 v{loc.generation} · 缓存 {loc.cache_info().get('size', 0)} 条"
            )
        except Exception:
            log.exception("刷新定位库状态失败")

    # ── 统计 ──
    def _refresh_stats(self, force: bool = False) -> None:
        import time

        now = time.time()
        if not force and now - self._last_stats < 1.5:
            return
        self._last_stats = now
        try:
            total, risk = count_today()
            bans = count_active_bans()
            unhandled = count_risk_unhandled()
        except Exception:
            log.exception("统计刷新失败")
            total = risk = bans = unhandled = 0
        self.page_monitor.set_stats(total, risk, bans)
        self.lbl_ban_count.setText(f"已封禁 {bans}")
        # 圆点颜色随计数切换：有数 danger / 0 时 success（P2-1）
        self._set_ban_count(bans)
        if unhandled:
            self.lbl_status.setText(f"有 {unhandled} 条风险事件待处理")
            self.lbl_status.setStyleSheet(f"color:{C.warning};font-size:12.5px;")

        # 状态栏上的本机观察指示 + 设置页的运行状态行
        with contextlib.suppress(Exception):
            self._refresh_watch_label()
        with contextlib.suppress(Exception):
            self.page_settings._refresh_watch_state()
        # 顶部「防火墙」健康项（内部自带 30 秒节流 + 后台线程）
        with contextlib.suppress(Exception):
            self._maybe_poll_firewall()

    def _set_status(self, text: str, color: Optional[str] = None) -> None:
        self.lbl_status.setText(text)
        self.lbl_status.setStyleSheet(f"color:{color or C.text_secondary};font-size:12.5px;")

    # ── 到期巡检 / 清理 ──
    def _check_expired(self) -> None:
        """到期自动解封（后台线程）

        为什么必须后台：`check_expired` 每条到期记录都要起一次 netsh 删规则，
        30 条就是几十秒。放界面线程里跑，用户看到的是「点了没反应」，而且
        Windows 会把窗口标成「未响应」，绝大多数人到这里就会强杀进程 ——
        强杀后规则还在系统里，库里却已经记了「解封中」，两边从此对不上。
        """
        if not self._is_admin():
            self._report_expired_backlog()
            return
        if not self._expire_busy.enter("expire"):
            return

        def work() -> Dict:
            done = ban_service.check_expired()
            # 积压数与解封结果一起回主线程：分两次查会读到两个时刻的状态，
            # 界面上就会出现「已解封 3 个」但「另有 2 条已到期」的错位
            return {"done": done, "backlog": ban_service.expired_backlog()}

        run_in_background(self, work, self._on_expired_done, self._on_expired_failed, name="expire")

    def _on_expired_done(self, payload: Dict) -> None:
        self._expire_busy.leave("expire")
        done = payload.get("done") or []
        # 无论这次有没有解封到东西，都把积压数同步给封禁页：
        # 权限条上那句「另有 N 条已到期」必须跟着真实状态走，
        # 否则解封完了界面还在说「解不掉」。
        with contextlib.suppress(Exception):
            self.page_bans.set_expired_backlog(int(payload.get("backlog") or 0))
        if not done:
            return
        self._set_status(f"已自动解封 {len(done)} 个到期 IP", C.success)
        if self.stack.currentWidget() is self.page_bans:
            self.page_bans.refresh()
        self._refresh_stats(force=True)

    def _on_expired_failed(self, err: str) -> None:
        self._expire_busy.leave("expire")
        log.error("到期解封巡检失败：%s", err)
        self._set_status("到期解封巡检失败，详情见运行日志", C.danger)

    def _recover_pending(self) -> None:
        """启动时收敛残留 pending 封禁记录（后台线程）

        判定逻辑全在 `ban_service.recover_stale_pending`：按防火墙里规则是否
        真的存在回填 active / failed。这里只负责别占界面线程、并在有结果时
        让用户看得见（否则「记录状态自己变了」会让人以为出了灵异事件）。
        """
        if not self._is_admin():
            return
        run_in_background(
            self,
            ban_service.recover_stale_pending,
            self._on_pending_recovered,
            self._on_pending_recover_failed,
            name="recover-pending",
        )

    def _on_pending_recovered(self, n: Any) -> None:
        if not n:
            return
        log.warning("启动已收敛 %d 条上次未收尾的封禁记录", n)
        self._set_status(f"已收敛 {n} 条上次未完成的封禁记录，详情见审计页", C.warning)
        if self.stack.currentWidget() is self.page_bans:
            self.page_bans.refresh()
        self._refresh_stats(force=True)

    def _on_pending_recover_failed(self, err: str) -> None:
        log.error("收敛残留封禁记录失败：%s", err)

    def _enforce_blacklist(self) -> None:
        """黑名单补封（后台线程）：只处理「名单里有、但没有活动封禁」的条目。

        这条链路是黑名单承诺「不能继续访问」的兜底：普通权限时加黑只落了文件，
        以管理员身份重启后必须把拦截补上。批量写规则要几秒，放后台跑。
        """
        if not self._is_admin():
            return

        def work():
            try:
                from app import blacklist_service

                res = blacklist_service.ensure_enforced()
                if res.get("banned"):
                    log.info("启动补封完成：%d 条黑名单补齐封禁", len(res["banned"]))
            except Exception:
                log.exception("启动黑名单补封失败")

        threading.Thread(target=work, daemon=True, name="blacklist-enforce").start()

    def _reenforce_bans(self) -> None:
        """启动时对齐一次封禁（后台线程）：补建缺失规则 + 清理历史重复规则。

        为什么启动要做：2026-10-21 之前规则名带时间戳，同 IP 会堆出十几条；
        解封只删一条 → 「点了封禁还在拦 / 解封了还封着」。这里把历史规则清掉、
        按新名字（`PortGuard_Block_<ip>`）重建，库与系统才对得上。
        防火墙没开时 `reenforce_all` 会自己返回，不产生任何写操作。
        """
        if not self._is_admin():
            return

        def work():
            try:
                res = ban_service.reenforce_all()
                if not res.get("ok"):
                    log.info("启动封禁对齐跳过：%s", res.get("error"))
                    return
                if res.get("restored") or res.get("legacy_removed") or res.get("failed"):
                    log.info("启动封禁对齐：%s", ban_service.format_reenforce(res))
            except Exception:
                log.exception("启动封禁对齐失败")

        threading.Thread(target=work, daemon=True, name="ban-reenforce").start()

    def _report_expired_backlog(self) -> None:
        """
        普通权限下的到期巡检：做不了事，但**必须说清楚**。
        「以管理员封过的 IP，之后以普通权限运行就永不解封」这件事，原来在界面上
        完全没有痕迹。现在把积压条数报给封禁页的权限条，并在状态栏提一句
        （状态栏会被后续事件覆盖，所以真正的常驻提示在权限条上）。
        """
        try:
            n = ban_service.expired_backlog()
        except Exception:
            log.exception("统计到期未解封条数失败")
            return
        with contextlib.suppress(Exception):
            self.page_bans.set_expired_backlog(n)
        if n > 0:
            self._set_status(
                f"有 {n} 条封禁已到期，但当前无管理员权限，无法删除防火墙规则",
                C.warning,
            )

    def _cleanup_logs(self) -> None:
        """
        每日维护：清理四张表 + 日志文件 + 备份 + 下载残留，**然后自动备份数据库**
        （每天到点跑一次，见 `maintenance.run_daily`）。

        四张表各有各的保留期（`run_all` 内部按 `*_retention_days` 分别读），
        这里只负责编排与日志，不再逐个调 cleanup_* —— 少一个就漏一张表，
        而漏掉的表是没有别的机制兜底的。

        为什么整段搬后台：清理要删几十万行（`DELETE` + WAL 增长），备份要逐页拷库，
        两者都是秒级到分钟级的磁盘活。放在界面线程里，表现就是「凌晨三点界面突然
        卡死一分钟」，而没人会想到是维护任务干的。
        """
        if not maintenance.due_today():
            return
        if not self._maint_busy.enter("maintenance"):
            return
        run_in_background(
            self,
            maintenance.run_daily,
            self._on_maintenance_done,
            self._on_maintenance_failed,
            name="maintenance",
        )

    def _on_maintenance_done(self, payload: Any) -> None:
        self._maint_busy.leave("maintenance")
        counts, backup_ok, backup_detail = payload
        rows, risk, bans, audits, n_files, n_bak, n_tmp = counts
        log.info(
            "定期清理完成：访问 %d 条（保留 %d 天）、风险事件 %d 条（%d 天）、"
            "终态封禁 %d 条（%d 天）、审计 %d 条（%d 天）、"
            "日志文件 %d 个、备份 %d 个、下载残留 %d 个",
            rows,
            cfg.get_int("log_retention_days", 30),
            risk,
            cfg.get_int("risk_retention_days", DEFAULT_RISK_RETENTION_DAYS),
            bans,
            cfg.get_int("ban_retention_days", DEFAULT_BAN_RETENTION_DAYS),
            audits,
            cfg.get_int("audit_retention_days", DEFAULT_AUDIT_RETENTION_DAYS),
            n_files,
            n_bak,
            n_tmp,
        )
        if backup_ok:
            self._set_status("每日维护完成，已自动备份数据库", C.success)
        else:
            # 「备份失败」必须说出来：安静地失败三次，等于用户以为有退路其实没有
            self._set_status(f"每日备份失败：{backup_detail}", C.warning)

    def _on_maintenance_failed(self, err: str) -> None:
        self._maint_busy.leave("maintenance")
        log.error("定期维护失败：%s", err)
        self._set_status("定期维护失败，详情见运行日志", C.danger)

    # ── 离线库同步 ──
    def _maybe_sync_xdb(self, first_run: bool = False) -> None:
        svc = get_xdb_service()
        if svc.busy:
            return
        started = svc.maybe_auto(first_run=first_run)
        if started:
            self._set_status("正在检查离线 IP 库更新…", C.text_secondary)

    def _sync_xdb_now(self, force: bool = False) -> None:
        """手动触发同步（设置页 / IP 查询页按钮）"""
        svc = get_xdb_service()
        if svc.busy:
            self._set_status("已有离线库同步任务在进行中", C.warning)
            return
        if svc.update_async(force=force):
            self._set_status("已开始同步离线 IP 库…", C.warning)
