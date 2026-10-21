"""
PortGuard — 主窗口的行为 Mixin

原 `MainWindow` 是 609 行 God Object：UI 组装、托盘、事件泵、服务启停、
封禁编排、到期巡检、统计刷新、日志清理全塞在一起，改一处要在 600 行里翻找。

现在按职责拆开：
- 本文件（gui/mixins.py）：与 Qt 生命周期强耦合的胶水逻辑
  · EventPumpMixin —— 事件泵 / 统计刷新 / 状态栏
  · ServerCtlMixin —— 上报服务启停
- app/*.py：不依赖 Qt 的业务编排（可单测）
- gui/main_window.py：只剩界面组装与信号连线
"""

import contextlib
import threading
from typing import TYPE_CHECKING, Dict, Optional

from app import ban_service, maintenance, server_ctl
from app.notify_service import get_service as get_notify_service
from app.xdb_service import get_service as get_xdb_service
from core import report_server
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
    from qtcompat import QAction, QLabel, QMainWindow, QStackedWidget

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

    def _setup_timers(self) -> None:
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
            if self.stack.currentWidget() is self.page_events:
                self.page_events.refresh()

        # 3) 告警
        notify = get_notify_service()
        for a in bus.drain_alert(50):
            self.alerter.notify(a)
            # 外部通道（Webhook）：入队即返回，真正的 HTTP 在后台线程。
            # 这里绝不能同步发请求 —— 事件泵跑在 Qt 主线程上，会直接冻住界面。
            notify.send(a)

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
                self.page_events.refresh()
            elif cur is self.page_bans and self.page_bans.isVisible():
                self.page_bans.refresh()
            self._refresh_stats(force=True)

        # 5) 离线库同步事件
        for ev in bus.drain_xdb(100):
            self._on_xdb_event(ev)

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
            self.lbl_xdb.setStyleSheet(f"color:{color};font-size:11px;")
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
            self.lbl_geo.setStyleSheet(f"color:{C.success};font-size:11px;")
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
        self.page_monitor.set_stats(
            total, risk, bans, report_server.is_running(), report_server.get_port()
        )
        self.lbl_ban_count.setText(f"已封禁 {bans}")
        # 圆点颜色随计数切换：有数 danger / 0 时 success（P2-1）
        self._set_ban_count(bans)
        if unhandled:
            self.lbl_status.setText(f"有 {unhandled} 条风险事件待处理")
            self.lbl_status.setStyleSheet(f"color:{C.warning};font-size:11px;")

        # 状态栏上的本机观察指示 + 设置页的运行状态行
        with contextlib.suppress(Exception):
            self._refresh_watch_label()
        with contextlib.suppress(Exception):
            self.page_settings._refresh_watch_state()

    def _set_status(self, text: str, color: Optional[str] = None) -> None:
        self.lbl_status.setText(text)
        self.lbl_status.setStyleSheet(f"color:{color or C.text_secondary};font-size:11px;")

    # ── 到期巡检 / 清理 ──
    def _check_expired(self) -> None:
        if not self._is_admin():
            self._report_expired_backlog()
            return
        try:
            done = ban_service.check_expired()
        except Exception:
            log.exception("到期解封巡检失败")
            return
        # 无论这次有没有解封到东西，都把积压数同步给封禁页：
        # 权限条上那句「另有 N 条已到期」必须跟着真实状态走，
        # 否则解封完了界面还在说「解不掉」。
        with contextlib.suppress(Exception):
            self.page_bans.set_expired_backlog(ban_service.expired_backlog())
        if done:
            self._set_status(f"已自动解封 {len(done)} 个到期 IP", C.success)
            if self.stack.currentWidget() is self.page_bans:
                self.page_bans.refresh()
            self._refresh_stats(force=True)

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
        定期清理：四张表 + 日志文件 + 备份 + 下载残留（每天到点跑一次）。

        四张表各有各的保留期（`run_all` 内部按 `*_retention_days` 分别读），
        这里只负责编排与日志，不再逐个调 cleanup_* —— 少一个就漏一张表，
        而漏掉的表是没有别的机制兜底的。
        """
        if not maintenance.due_today():
            return
        try:
            rows, risk, bans, audits, n_files, n_bak, n_tmp = maintenance.run_all()
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
        except Exception:
            log.exception("定期清理失败")

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


class ServerCtlMixin(_HostBase):
    """上报服务启停"""

    page_settings: "SettingsPage"
    a_server: "QAction"

    # 由 EventPumpMixin 实现（MRO 中排在前面），在此声明仅供类型检查
    def _set_status(self, text: str, color: Optional[str] = None) -> None:
        raise NotImplementedError

    def _refresh_stats(self, force: bool = False) -> None:
        raise NotImplementedError

    def _set_server_state(self, text: str, color: str) -> None:
        raise NotImplementedError

    def _maybe_start_server_on_launch(self) -> None:
        if server_ctl.should_autostart():
            QTimer.singleShot(600, lambda: self._toggle_server(True))
        else:
            self._update_server_labels()

    def _toggle_server(self, start=None) -> None:
        ok, msg = server_ctl.toggle(start)
        if not ok:
            self._set_status(msg.splitlines()[0], C.danger)
            from qtcompat import QMessageBox

            QMessageBox.warning(self, "启动失败", msg)
        else:
            color = C.success if report_server.is_running() else C.text_secondary
            first = msg.splitlines()[0]
            self._set_status(first, color)
            if report_server.get_generated_key():
                from qtcompat import QMessageBox

                QMessageBox.information(
                    self,
                    "已启用局域网监听",
                    msg + "\n\n安全提示：监听非本机地址时必须设置 API Key，"
                    "否则局域网内任意主机都能伪造上报记录，"
                    "进而污染风险判定甚至触发误封。",
                )
        self._update_server_labels()

    def _update_server_labels(self) -> None:
        st = server_ctl.state()
        if st["running"]:
            suffix = "" if st["loopback"] else "（局域网）"
            self._set_server_state(f"接收服务 :{st['port']}{suffix}", C.success)
            self.a_server.setText("停止接收服务")
        else:
            self._set_server_state("接收服务 未启动", C.text_muted)
            self.a_server.setText("启动接收服务")
        try:
            self.page_settings.refresh_server_state()
        except Exception:
            log.exception("刷新服务状态失败")
        self._refresh_stats(force=True)
