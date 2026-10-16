"""
PortGuard — 主窗口

职责被刻意收窄为「界面组装 + 页面切换 + 信号连线 + 托盘」。
其它逻辑分别落在：
- gui/mixins.py   事件泵 / 统计 / 服务启停（Qt 胶水）
- app/*.py        封禁编排 / 维护 / 服务控制 / 离线库同步（不依赖 Qt，可单测）
"""

import threading

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QColor, QFont, QIcon, QPainter, QPixmap
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QStackedWidget,
    QStatusBar,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from app import ban_service, server_ctl
from app.xdb_service import get_service as get_xdb_service
from core import firewall
from core import settings as cfg
from core.alerts import Alerter
from core.config import APP_TITLE, APP_VERSION
from core.database import find_active_ban_by_ip, init_db
from core.event_bus import bus
from core.geo_locator import get_locator
from core.logger import get_logger
from core.rule_engine import get_engine, is_never_ban
from gui.mixins import EventPumpMixin, ServerCtlMixin
from gui.page_bans import BansPage, ManualBanDialog
from gui.page_events import EventsPage
from gui.page_iplookup import IpLookupPage
from gui.page_monitor import MonitorPage
from gui.page_rules import RulesPage
from gui.page_settings import SettingsPage
from gui.theme import GLOBAL_STYLE, C

log = get_logger(__name__)

NAV_ITEMS = [
    ("实时监控", "监控"),
    ("风险事件", "事件"),
    ("封禁管理", "封禁"),
    ("规则配置", "规则"),
    ("IP 查询", "查询"),
    ("设置", "设置"),
]

PAGE_MONITOR, PAGE_EVENTS, PAGE_BANS, PAGE_RULES, PAGE_LOOKUP, PAGE_SETTINGS = range(6)


def _make_icon(color: str | None = None, size: int = 64) -> QIcon:
    """生成内置盾牌图标（避免依赖外部资源文件）"""
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QColor(color or C.primary))
    p.setPen(Qt.PenStyle.NoPen)
    from PySide6.QtCore import QPointF
    from PySide6.QtGui import QPolygonF

    w = size
    pts = [
        QPointF(w * 0.5, w * 0.06),
        QPointF(w * 0.90, w * 0.22),
        QPointF(w * 0.90, w * 0.55),
        QPointF(w * 0.5, w * 0.95),
        QPointF(w * 0.10, w * 0.55),
        QPointF(w * 0.10, w * 0.22),
    ]
    p.drawPolygon(QPolygonF(pts))
    p.setPen(QColor("#FFFFFF"))
    f = QFont("Segoe UI Symbol")
    f.setPixelSize(int(w * 0.42))
    f.setBold(True)
    p.setFont(f)
    p.drawText(pm.rect(), Qt.AlignmentFlag.AlignCenter, "✓")
    p.end()
    return QIcon(pm)


class BanDurationDialog(QDialog):
    """确认封禁对话框（可调整时长）"""

    def __init__(self, ip: str, score: int, reason: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("确认封禁")
        self.setMinimumWidth(400)
        form = QFormLayout(self)
        form.setContentsMargins(18, 18, 18, 12)
        form.setSpacing(10)

        form.addRow("IP 地址", QLabel(ip))
        form.addRow("风险评分", QLabel(str(score)))
        rl = QLabel(reason or "命中风险规则")
        rl.setWordWrap(True)
        form.addRow("封禁原因", rl)

        self.sp = QSpinBox()
        self.sp.setRange(0, 365 * 24 * 60)
        self.sp.setValue(max(1, cfg.get_int("default_ban_duration_sec", 3600) // 60))
        self.sp.setSpecialValueText("永久")
        self.sp.setSuffix(" 分钟（0=永久）")
        form.addRow("封禁时长", self.sp)

        note = QLabel("将执行 New-NetFirewallRule 创建入站阻止规则（需管理员权限）。")
        note.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
        note.setWordWrap(True)
        form.addRow(note)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.button(QDialogButtonBox.StandardButton.Ok).setText("确认封禁")
        btns.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        form.addRow(btns)

    def duration_sec(self) -> int:
        m = self.sp.value()
        return 0 if m == 0 else m * 60


class MainWindow(EventPumpMixin, ServerCtlMixin, QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_TITLE}  v{APP_VERSION}")
        self.setMinimumSize(1200, 720)
        self.resize(1360, 820)
        self.setStyleSheet(GLOBAL_STYLE)

        self._app_icon = _make_icon()
        self.setWindowIcon(self._app_icon)

        self._last_stats = 0.0
        self._geo_info = None
        self.lbl_xdb = None

        init_db()
        cfg.warm()

        self._build_ui()
        self._setup_tray()
        self.alerter = Alerter(tray=self.tray, parent_widget=self)
        self._wire_pages()
        self._setup_timers()
        self._load_geo_async()
        self._refresh_stats(force=True)
        self._maybe_start_server_on_launch()

        # 启动后延迟做一次离线库检查（后台线程，不阻塞界面）
        QTimer.singleShot(3000, lambda: self._maybe_sync_xdb(first_run=True))

        self._maybe_warn_insecure()

    # ═══════════════════════════════════════════════
    #  小工具
    # ═══════════════════════════════════════════════

    # 这两个方法被 gui/mixins.py 的 Mixin 以 self.xxx() 调用，
    # 故写成实例方法（而非 staticmethod），这样 Mixin 的声明能与之正常对齐。
    def _is_admin(self) -> bool:
        return firewall.is_admin()

    def _locator(self):
        return get_locator()

    # ═══════════════════════════════════════════════
    #  界面
    # ═══════════════════════════════════════════════

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_sidebar())

        self.stack = QStackedWidget()
        root.addWidget(self.stack, 1)

        self.page_monitor = MonitorPage()
        self.page_events = EventsPage()
        self.page_bans = BansPage()
        self.page_rules = RulesPage()
        self.page_iplookup = IpLookupPage()
        self.page_settings = SettingsPage()
        for p in (
            self.page_monitor,
            self.page_events,
            self.page_bans,
            self.page_rules,
            self.page_iplookup,
            self.page_settings,
        ):
            self.stack.addWidget(p)

        sb = QStatusBar()
        self.setStatusBar(sb)
        self.lbl_status = QLabel("正在初始化…")
        self.lbl_status.setStyleSheet(f"color:{C.text_secondary};font-size:12px;")
        self.lbl_geo = QLabel("定位库：加载中…")
        self.lbl_geo.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
        self.lbl_xdb = QLabel("IP 库：—")
        self.lbl_xdb.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
        self.lbl_server = QLabel("服务：未启动")
        self.lbl_server.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
        sb.addWidget(self.lbl_status, 1)
        sb.addPermanentWidget(self.lbl_xdb)
        sb.addPermanentWidget(self.lbl_geo)
        sb.addPermanentWidget(self.lbl_server)

    def _build_sidebar(self) -> QFrame:
        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(196)
        sl = QVBoxLayout(self.sidebar)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.setSpacing(0)

        logo = QLabel("  🛡 PortGuard")
        logo.setObjectName("sidebar_logo")
        sub = QLabel("端口访问防御工具")
        sub.setObjectName("sidebar_sub")
        sl.addWidget(logo)
        sl.addWidget(sub)

        sep = QFrame()
        sep.setFixedHeight(1)
        sep.setStyleSheet(f"background:{C.border_light};")
        sl.addWidget(sep)
        sl.addSpacing(6)

        self.nav_buttons = []
        for idx, (name, _) in enumerate(NAV_ITEMS):
            btn = QPushButton(name)
            btn.setObjectName("nav_btn")
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda _, i=idx: self._switch_page(i))
            sl.addWidget(btn)
            self.nav_buttons.append(btn)
        self.nav_buttons[0].setChecked(True)

        sl.addStretch(1)
        fsep = QFrame()
        fsep.setStyleSheet(f"background:{C.border_light};")
        fsep.setFixedHeight(1)
        sl.addWidget(fsep)

        self.lbl_ban_count = QLabel("已封禁 0")
        self.lbl_ban_count.setStyleSheet(
            f"color:{C.danger};font-size:12px;font-weight:600;padding:10px 16px 2px 16px;"
        )
        sl.addWidget(self.lbl_ban_count)

        ver = QLabel(f"v{APP_VERSION} · ip2region")
        ver.setObjectName("sidebar_footer")
        sl.addWidget(ver)
        return self.sidebar

    def _switch_page(self, idx: int) -> None:
        self.stack.setCurrentIndex(idx)
        for i, b in enumerate(self.nav_buttons):
            b.setChecked(i == idx)
        if idx == PAGE_EVENTS:
            self.page_events.refresh()
        elif idx == PAGE_BANS:
            self.page_bans.refresh()
        elif idx == PAGE_LOOKUP:
            self.page_iplookup._update_lib_info()
        elif idx == PAGE_SETTINGS:
            self.page_settings.refresh_xdb_state()

    # ═══════════════════════════════════════════════
    #  托盘
    # ═══════════════════════════════════════════════

    def _setup_tray(self) -> None:
        self.tray = QSystemTrayIcon(self._app_icon, self)
        self.tray.setToolTip(f"{APP_TITLE} v{APP_VERSION}")
        menu = QMenu()
        a_show = QAction("显示主窗口", self)
        a_show.triggered.connect(self._show_window)
        self.a_server = QAction("启动接收服务", self)
        self.a_server.triggered.connect(self._toggle_server)
        a_sync = QAction("立即同步离线 IP 库", self)
        a_sync.triggered.connect(lambda: self._sync_xdb_now(force=False))
        a_quit = QAction("退出", self)
        a_quit.triggered.connect(self._quit)
        menu.addAction(a_show)
        menu.addAction(self.a_server)
        menu.addSeparator()
        menu.addAction(a_sync)
        menu.addSeparator()
        menu.addAction(a_quit)
        self.tray.setContextMenu(menu)
        self.tray.activated.connect(
            lambda r: (
                self._show_window() if r == QSystemTrayIcon.ActivationReason.DoubleClick else None
            )
        )
        self.tray.show()

    def _show_window(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    # ═══════════════════════════════════════════════
    #  信号连线
    # ═══════════════════════════════════════════════

    def _wire_pages(self) -> None:
        self.page_monitor.ask_lookup.connect(self._goto_lookup)
        self.page_monitor.ask_blacklist.connect(self._add_blacklist)
        self.page_monitor.ask_ban.connect(self.request_ban)
        self.page_events.ask_ban.connect(self.request_ban)
        self.page_bans.ask_ban.connect(self.request_ban)
        self.page_bans.request_refresh_stats.connect(lambda: self._refresh_stats(force=True))
        self.page_rules.rules_saved.connect(self._on_rules_saved)
        self.page_settings.server_toggled.connect(self._toggle_server)
        self.page_settings.settings_saved.connect(self._on_settings_saved)
        self.page_settings.xdb_sync_requested.connect(self._sync_xdb_now)
        self.page_settings.xdb_check_requested.connect(self._check_xdb_now)
        self.page_settings.logs_open_requested.connect(self._open_logs_dir)
        self.page_iplookup.xdb_sync_requested.connect(self._sync_xdb_now)

    def _goto_lookup(self, ip: str) -> None:
        self._switch_page(PAGE_LOOKUP)
        self.page_iplookup.lookup_and_show(ip)

    def _add_blacklist(self, ip: str) -> None:
        if is_never_ban(ip):
            QMessageBox.warning(
                self, "无法加入", f"{ip} 属于内网 / 回环 / 保留地址，不能加入黑名单。"
            )
            return
        eng = get_engine()
        if ip in eng.blacklist:
            QMessageBox.information(self, "已存在", f"{ip} 已在黑名单中。")
            return
        if (
            QMessageBox.question(
                self,
                "加入黑名单",
                f"将 {ip} 加入黑名单，之后所有来自该 IP 的访问都会判为严重风险。\n\n继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        try:
            eng.blacklist.add(ip)
            eng.save_lists()
        except Exception as e:
            log.exception("保存黑名单失败 ip=%s", ip)
            QMessageBox.warning(self, "保存失败", str(e))
            return
        self.page_rules.reload()
        self._set_status(f"已把 {ip} 加入黑名单", C.success)

    def _on_rules_saved(self) -> None:
        self._set_status("规则配置已更新并生效", C.success)

    def _on_settings_saved(self) -> None:
        self._set_status("设置已保存（部分改动需重启服务）", C.success)

    def _open_logs_dir(self) -> None:
        import os

        try:
            from core.logger import logs_dir

            d = logs_dir()
            os.startfile(d)  # noqa: S606  Windows 专属
        except Exception as e:
            log.exception("打开日志目录失败")
            QMessageBox.warning(self, "打开失败", str(e))

    def _check_xdb_now(self) -> None:
        svc = get_xdb_service()
        if svc.busy:
            self._set_status("已有离线库任务在进行中", C.warning)
            return
        if svc.check_async():
            self._set_status("正在检查离线 IP 库更新…", C.text_secondary)

    # ═══════════════════════════════════════════════
    #  载入定位库
    # ═══════════════════════════════════════════════

    def _load_geo_async(self) -> None:
        def work():
            try:
                loc = get_locator()
                self._geo_info = (loc.available, loc.load_error, loc.cache_info(), loc.generation)
            except Exception as e:
                log.exception("加载定位库失败")
                self._geo_info = (False, str(e), {}, 0)

        threading.Thread(target=work, daemon=True, name="geo-load").start()
        self._geo_timer = QTimer(self)
        self._geo_timer.setInterval(300)
        self._geo_timer.timeout.connect(self._poll_geo)
        self._geo_timer.start()

    def _poll_geo(self) -> None:
        info = self._geo_info
        if info is None:
            return
        self._geo_timer.stop()
        ok, err, ci, gen = info
        if ok:
            self.lbl_geo.setText(f"定位库：已加载 v{gen}（缓存 {ci.get('size', 0)}）")
            self.lbl_geo.setStyleSheet(f"color:{C.success};font-size:12px;")
        else:
            self.lbl_geo.setText(f"定位库：不可用（{err}）")
            self.lbl_geo.setStyleSheet(f"color:{C.danger};font-size:12px;")
            QMessageBox.warning(
                self, "定位库加载失败", f"IP 归属地库加载失败，归属地将显示为未知。\n\n{err}"
            )

    # ═══════════════════════════════════════════════
    #  封禁
    # ═══════════════════════════════════════════════

    def request_ban(self, ip: str, score: int = 0, reason: str = "") -> None:
        """封禁入口：右键菜单 / 风险事件页 / 封禁页 / 手动输入"""
        if not ip:
            dlg = ManualBanDialog("", self)
            if dlg.exec() != QDialog.DialogCode.Accepted:
                return
            ip2, reason2, dur = dlg.values()
            self._do_ban(ip2, 0, reason2, dur)
            return

        # 唯一校验入口（同时挡掉命令注入与受保护地址）
        try:
            rec = ban_service.prepare(ip, score, reason, 0)
        except ban_service.BanError as e:
            QMessageBox.warning(self, "无法封禁", str(e))
            return

        if not firewall.is_admin():
            if (
                QMessageBox.question(
                    self,
                    "权限不足",
                    "封禁需要管理员权限。\n\n是否以管理员身份重启程序？",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                == QMessageBox.StandardButton.Yes
            ):
                self._restart_as_admin()
            return

        try:
            exists = find_active_ban_by_ip(rec.ip)
        except Exception:
            log.exception("查询已有封禁失败 ip=%s", rec.ip)
            exists = None
        if exists:
            QMessageBox.information(
                self, "已封禁", f"{rec.ip} 已处于封禁状态（记录 #{exists.id}）。"
            )
            return

        dur_dlg = BanDurationDialog(rec.ip, score, reason, self)
        if dur_dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self._do_ban(rec.ip, score, reason, dur_dlg.duration_sec())

    def _do_ban(self, ip: str, score: int, reason: str, duration_sec: int) -> None:
        """后台线程执行真实封禁（防火墙命令可能耗时数秒）"""
        self._set_status(f"正在封禁 {ip} …", C.warning)

        def work():
            ban_id, err = ban_service.execute(ip, score, reason, duration_sec)
            if ban_id is None:
                # 校验失败等前置错误不会走 ban_service 的事件投递，这里补一条
                bus.emit_ban(
                    {
                        "ip": ip,
                        "ok": False,
                        "rule_name": "",
                        "error": err,
                        "ban_id": None,
                        "source": "manual",
                    }
                )

        threading.Thread(target=work, daemon=True, name=f"ban-{ip}").start()

    def _restart_as_admin(self) -> None:
        ok, err = firewall.open_admin_restart()
        if ok:
            app = QApplication.instance()
            if app is not None:
                app.quit()
        else:
            QMessageBox.warning(self, "提权失败", f"{err}\n\n请手动右键程序 → 以管理员身份运行。")

    # ═══════════════════════════════════════════════
    #  安全提示
    # ═══════════════════════════════════════════════

    def _maybe_warn_insecure(self) -> None:
        """监听局域网但没设 Key 时主动提示（默认不会发生，防止用户手动改回危险组合）"""
        host = (cfg.get("listen_host", "127.0.0.1") or "").strip()
        key = (cfg.get("api_key", "") or "").strip()
        if host not in ("127.0.0.1", "localhost", "::1") and not key:
            QMessageBox.warning(
                self,
                "安全提示",
                f"当前监听地址为 {host}（非本机），但没有设置 API Key。\n\n"
                f"局域网内任意主机都能伪造上报记录，进而污染风险判定、"
                f"甚至在你开启自动封禁后封掉任意 IP。\n\n"
                f"请在「设置 → 上报接收服务」里设置 API Key，或把监听地址改回 127.0.0.1。",
            )

        if not firewall.is_admin():
            self._set_status("提示：以管理员身份运行才能执行封禁", C.warning)
        else:
            self._set_status("已以管理员身份运行，封禁功能可用", C.success)

    # ═══════════════════════════════════════════════
    #  退出
    # ═══════════════════════════════════════════════

    def closeEvent(self, event) -> None:
        if (
            self.tray is not None
            and self.tray.isVisible()
            and not getattr(self, "_really_quit", False)
        ):
            event.ignore()
            self.hide()
            self.tray.showMessage(
                "PortGuard 仍在运行",
                "程序已最小化到系统托盘，接收服务继续工作。",
                QSystemTrayIcon.MessageIcon.Information,
                3000,
            )
            return
        self._shutdown()
        event.accept()

    def _shutdown(self) -> None:
        log.info("PortGuard 退出：正在停止后台服务与批量写入器")
        try:
            server_ctl.stop()
        except Exception:
            log.exception("停止服务失败")
        try:
            from core.db_writer import stop_writer

            stop_writer(timeout=3.0)
        except Exception:
            log.exception("停止批量写入器失败")
        log.info("PortGuard 已退出")

    def _quit(self) -> None:
        self._really_quit = True
        self._shutdown()
        self.tray.hide()
        app = QApplication.instance()
        if app is not None:
            app.quit()
