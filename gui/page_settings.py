"""PortGuard — 设置页"""

import secrets

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFormLayout,
    QFrame,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLayout,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from app import maintenance
from core import firewall, report_server
from core import settings as cfg
from core.config import (
    DEFAULT_LISTEN_HOST,
    DEFAULT_LISTEN_PORT,
    LEVEL_CRITICAL,
    LEVEL_HIGH,
    LEVEL_LABEL,
    LEVEL_LOW,
    LEVEL_MEDIUM,
    WILDCARD_HOST,
    user_data_dir,
)
from core.database import clear_all_logs, delete_old_access
from core.logger import get_logger, log_file, set_retention
from core.models import ms_to_str
from gui.theme import C
from gui.widgets import ToggleSwitch

log = get_logger(__name__)

LEVEL_ITEMS = [LEVEL_LOW, LEVEL_MEDIUM, LEVEL_HIGH, LEVEL_CRITICAL]
LEVEL_LABELS = [LEVEL_LABEL[x] for x in LEVEL_ITEMS]


class SettingsPage(QWidget):
    server_toggled = Signal(bool)  # 请求主窗口启动/停止服务
    settings_saved = Signal()
    xdb_sync_requested = Signal(bool)  # 立即同步（True=强制重下）
    xdb_check_requested = Signal()  # 只检查
    logs_open_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build()
        self.load()

    # ═══════════════════════════════════════════════
    #  界面
    # ═══════════════════════════════════════════════

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(18, 16, 18, 12)
        outer.setSpacing(12)

        head = QHBoxLayout()
        t = QLabel("设置")
        t.setObjectName("page_title")
        d = QLabel("服务、离线库、封禁、告警与数据管理")
        d.setObjectName("page_desc")
        head.addWidget(t)
        head.addWidget(d)
        head.addStretch(1)
        self.btn_save = QPushButton("保存设置")
        self.btn_save.setObjectName("btn_primary")
        self.btn_save.clicked.connect(self.save)
        head.addWidget(self.btn_save)
        outer.addLayout(head)

        area = QScrollArea()
        area.setWidgetResizable(True)
        host = QWidget()
        lay = QVBoxLayout(host)
        lay.setContentsMargins(2, 4, 8, 8)
        lay.setSpacing(12)

        lay.addWidget(self._build_server_group())
        lay.addWidget(self._build_xdb_group())
        lay.addWidget(self._build_ban_group())
        lay.addWidget(self._build_alert_group())
        lay.addWidget(self._build_data_group())

        lay.addStretch(1)
        area.setWidget(host)
        outer.addWidget(area, 1)

    # ── 上报接收服务 ──
    def _build_server_group(self) -> QGroupBox:
        g = QGroupBox("上报接收服务")
        f = QFormLayout(g)
        f.setContentsMargins(14, 10, 14, 14)
        f.setSpacing(9)

        self.sp_port = QSpinBox()
        self.sp_port.setRange(1, 65535)
        self.sp_port.setValue(DEFAULT_LISTEN_PORT)
        self.sp_port.setFixedWidth(120)

        self.tg_lan = ToggleSwitch(False)
        self.tg_lan.toggled.connect(self._on_lan_toggle)
        lan_row = QHBoxLayout()
        lan_row.addWidget(self.tg_lan)
        self.lbl_lan = QLabel("")
        self.lbl_lan.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
        lan_row.addWidget(self.lbl_lan)
        lan_row.addStretch(1)

        self.ed_key = QLineEdit()
        self.ed_key.setPlaceholderText("留空表示不校验；监听局域网地址时会强制要求")
        self.ed_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.ed_key.setFixedWidth(300)
        b_show = QPushButton("显示")
        b_show.setObjectName("btn_outline")
        b_show.setFixedWidth(56)
        b_show.clicked.connect(self._toggle_key_echo)
        b_gen = QPushButton("生成")
        b_gen.setObjectName("btn_outline")
        b_gen.setFixedWidth(56)
        b_gen.clicked.connect(self._generate_key)
        b_copy = QPushButton("复制")
        b_copy.setObjectName("btn_outline")
        b_copy.setFixedWidth(56)
        b_copy.clicked.connect(self._copy_key)
        key_row = QHBoxLayout()
        key_row.addWidget(self.ed_key)
        key_row.addWidget(b_show)
        key_row.addWidget(b_gen)
        key_row.addWidget(b_copy)
        key_row.addStretch(1)

        self.lbl_server_state = QLabel("")
        self.btn_server = QPushButton("启动服务")
        self.btn_server.setObjectName("btn_success")
        self.btn_server.clicked.connect(self._toggle_server)
        row_state = QHBoxLayout()
        row_state.addWidget(self.btn_server)
        row_state.addWidget(self.lbl_server_state)
        row_state.addStretch(1)

        self.lbl_endpoint = QLabel("")
        self.lbl_endpoint.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
        self.lbl_endpoint.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        warn = QFrame()
        warn.setStyleSheet(
            f"QFrame{{background:{C.warning_light};border:1px solid {C.warning};border-radius:6px;}}"
        )
        wl = QHBoxLayout(warn)
        wl.setContentsMargins(10, 6, 10, 6)
        wlbl = QLabel(
            "⚠ 打开局域网访问后，程序会强制要求 API Key。"
            "没有 Key 时，局域网内任意主机都能伪造上报记录，"
            "进而污染风险判定、甚至借自动封禁之手封掉任意 IP。"
        )
        wlbl.setStyleSheet(f"color:{C.text_primary};font-size:12px;")
        wlbl.setWordWrap(True)
        wl.addWidget(wlbl)

        f.addRow("监听端口", self.sp_port)
        f.addRow("允许局域网访问", self._wrap(lan_row))
        f.addRow("", warn)
        f.addRow("API Key", self._wrap(key_row))
        f.addRow("服务状态", self._wrap(row_state))
        f.addRow("上报地址", self.lbl_endpoint)
        return g

    # ── 离线库在线同步 ──
    def _build_xdb_group(self) -> QGroupBox:
        g = QGroupBox("离线库在线同步（IP 归属地库）")
        f = QFormLayout(g)
        f.setContentsMargins(14, 10, 14, 14)
        f.setSpacing(9)

        self.lbl_xdb_state = QLabel("读取中…")
        self.lbl_xdb_state.setStyleSheet(f"color:{C.text_secondary};font-size:12px;")
        self.lbl_xdb_state.setWordWrap(True)
        self.lbl_xdb_state.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        self.tg_xdb_auto = ToggleSwitch(True)
        self.sp_xdb_interval = QSpinBox()
        self.sp_xdb_interval.setRange(1, 24 * 30)
        self.sp_xdb_interval.setValue(24)
        self.sp_xdb_interval.setSuffix(" 小时")
        self.sp_xdb_interval.setFixedWidth(140)
        self.tg_xdb_start = ToggleSwitch(True)
        self.tg_xdb_download = ToggleSwitch(True)

        self.ed_xdb_source = QLineEdit()
        self.ed_xdb_source.setPlaceholderText(
            "留空使用内置源（CDN / 官方 / 镜像 / Gitee 自动容错）；也可填自定义镜像，用 {path} 占位"
        )
        self.ed_xdb_source.setMinimumWidth(420)

        self.xdb_bar = QProgressBar()
        self.xdb_bar.setRange(0, 100)
        self.xdb_bar.setValue(0)
        self.xdb_bar.setFixedHeight(8)
        self.xdb_bar.setTextVisible(False)

        self.lbl_xdb_progress = QLabel("待命中")
        self.lbl_xdb_progress.setStyleSheet(f"color:{C.text_muted};font-size:12px;")

        # 存成属性便于自检/自动化测试直接触发
        self.btn_xdb_check = QPushButton("立即检查更新")
        self.btn_xdb_check.setObjectName("btn_outline")
        self.btn_xdb_check.clicked.connect(self.xdb_check_requested.emit)
        self.btn_xdb_sync = QPushButton("立即同步")
        self.btn_xdb_sync.setObjectName("btn_primary")
        self.btn_xdb_sync.clicked.connect(lambda: self.xdb_sync_requested.emit(False))
        self.btn_xdb_force = QPushButton("强制重新下载")
        self.btn_xdb_force.setObjectName("btn_outline")
        self.btn_xdb_force.clicked.connect(self._force_sync)
        btn_row = QHBoxLayout()
        btn_row.addWidget(self.btn_xdb_check)
        btn_row.addWidget(self.btn_xdb_sync)
        btn_row.addWidget(self.btn_xdb_force)
        btn_row.addStretch(1)

        tip = QLabel(
            "同步流程：版本指纹比对 → 多源下载 → 大小/内容指纹/xdb 结构/抽样查询四重校验 "
            "→ 备份旧库 → 原子替换 → 热加载（无需重启）。任一步失败都会回滚，不影响现有定位能力。"
        )
        tip.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
        tip.setWordWrap(True)

        f.addRow("当前库", self.lbl_xdb_state)
        f.addRow("自动检查更新", self._wrap(self.tg_xdb_auto))
        f.addRow("检查间隔", self.sp_xdb_interval)
        f.addRow("启动时检查", self._wrap(self.tg_xdb_start))
        f.addRow("自动下载并热换", self._wrap(self.tg_xdb_download))
        f.addRow("自定义镜像源", self.ed_xdb_source)
        f.addRow("", tip)
        f.addRow("同步进度", self.xdb_bar)
        f.addRow("", self.lbl_xdb_progress)
        f.addRow("", self._wrap(btn_row))
        return g

    # ── 封禁策略 ──
    def _build_ban_group(self) -> QGroupBox:
        g = QGroupBox("封禁策略")
        f = QFormLayout(g)
        f.setContentsMargins(14, 10, 14, 14)
        f.setSpacing(9)

        self.tg_auto = ToggleSwitch(False)
        auto_row = QHBoxLayout()
        auto_row.addWidget(self.tg_auto)
        self.lbl_auto = QLabel("")
        self.lbl_auto.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
        auto_row.addWidget(self.lbl_auto)
        auto_row.addStretch(1)
        self.tg_auto.toggled.connect(self._on_auto_toggle)

        self.sp_threshold = QSpinBox()
        self.sp_threshold.setRange(1, 100)
        self.sp_threshold.setValue(90)
        self.sp_threshold.setFixedWidth(120)

        self.sp_duration = QSpinBox()
        self.sp_duration.setRange(0, 365 * 24 * 60)
        self.sp_duration.setValue(60)
        self.sp_duration.setSuffix(" 分钟（0=永久）")
        self.sp_duration.setSpecialValueText("永久")
        self.sp_duration.setFixedWidth(180)

        self.sp_rate = QSpinBox()
        self.sp_rate.setRange(0, 100000)
        self.sp_rate.setValue(300)
        self.sp_rate.setSuffix(" 次/秒/IP（0=不限流）")
        self.sp_rate.setFixedWidth(220)

        warn = QFrame()
        warn.setStyleSheet(
            f"QFrame{{background:{C.danger_light};border:1px solid {C.danger};border-radius:6px;}}"
        )
        wl = QHBoxLayout(warn)
        wl.setContentsMargins(10, 6, 10, 6)
        wlbl = QLabel("⚠ 自动模式会跳过人工确认直接写入防火墙，请确认规则阈值后再开启。")
        wlbl.setStyleSheet(f"color:{C.text_primary};font-size:12px;")
        wlbl.setWordWrap(True)
        wl.addWidget(wlbl)

        perm = QLabel(
            "已以管理员身份运行，封禁功能可用。"
            if firewall.is_admin()
            else "当前为普通权限，封禁按钮不会生效，请以管理员身份重启程序。"
        )
        perm.setStyleSheet(
            f"color:{C.success if firewall.is_admin() else C.warning};font-size:12px;"
        )

        f.addRow("自动封禁模式", self._wrap(auto_row))
        f.addRow("", warn)
        f.addRow("自动封禁最低评分", self.sp_threshold)
        f.addRow("默认封禁时长", self.sp_duration)
        f.addRow("上报限流", self.sp_rate)
        f.addRow("权限状态", perm)
        return g

    # ── 告警 ──
    def _build_alert_group(self) -> QGroupBox:
        g = QGroupBox("告警通知")
        f = QFormLayout(g)
        f.setContentsMargins(14, 10, 14, 14)
        f.setSpacing(9)

        self.tg_sound = ToggleSwitch(True)
        self.cb_popup = QComboBox()
        self.cb_popup.addItems(["不弹窗", *LEVEL_LABELS])
        self.cb_popup.setFixedWidth(140)
        self.sp_merge = QSpinBox()
        self.sp_merge.setRange(0, 3600)
        self.sp_merge.setValue(60)
        self.sp_merge.setSuffix(" 秒")
        self.sp_merge.setFixedWidth(120)

        b_test = QPushButton("测试告警")
        b_test.setObjectName("btn_outline")
        b_test.clicked.connect(self._test_alert)

        f.addRow("声音提示", self._wrap(self.tg_sound))
        f.addRow("弹窗级别", self.cb_popup)
        f.addRow("同 IP 合并窗口", self.sp_merge)
        f.addRow("", self._wrap(b_test))
        return g

    # ── 数据 ──
    def _build_data_group(self) -> QGroupBox:
        g = QGroupBox("数据管理")
        f = QFormLayout(g)
        f.setContentsMargins(14, 10, 14, 14)
        f.setSpacing(9)

        self.sp_retention = QSpinBox()
        self.sp_retention.setRange(1, 3650)
        self.sp_retention.setValue(30)
        self.sp_retention.setSuffix(" 天")
        self.sp_retention.setFixedWidth(120)

        self.sp_buffer = QSpinBox()
        self.sp_buffer.setRange(500, 100000)
        self.sp_buffer.setSingleStep(500)
        self.sp_buffer.setValue(5000)
        self.sp_buffer.setFixedWidth(140)

        self.sp_cache = QSpinBox()
        self.sp_cache.setRange(1000, 500000)
        self.sp_cache.setSingleStep(2000)
        self.sp_cache.setValue(20000)
        self.sp_cache.setFixedWidth(140)

        # 定期清理的执行时刻（24 小时制）。默认凌晨 3 点，避开营业时段。
        self.sp_maint_hour = QSpinBox()
        self.sp_maint_hour.setRange(0, 23)
        self.sp_maint_hour.setValue(3)
        self.sp_maint_hour.setSuffix(" 点")
        self.sp_maint_hour.setFixedWidth(120)

        row_data = QHBoxLayout()
        b_clean = QPushButton("清理过期日志")
        b_clean.setObjectName("btn_outline")
        b_clean.clicked.connect(self._clean_logs)
        b_clear = QPushButton("清空全部日志")
        b_clear.setObjectName("btn_danger")
        b_clear.clicked.connect(self._clear_logs)
        b_logs = QPushButton("打开日志目录")
        b_logs.setObjectName("btn_outline")
        b_logs.clicked.connect(self.logs_open_requested.emit)
        row_data.addWidget(b_clean)
        row_data.addWidget(b_clear)
        row_data.addWidget(b_logs)
        row_data.addStretch(1)

        self.lbl_datadir = QLabel(user_data_dir())
        self.lbl_datadir.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
        self.lbl_datadir.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.lbl_logfile = QLabel(log_file())
        self.lbl_logfile.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
        self.lbl_logfile.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        f.addRow("日志保留", self.sp_retention)
        f.addRow("自动清理时刻", self.sp_maint_hour)
        f.addRow("监控缓冲行数", self.sp_buffer)
        f.addRow("归属地缓存条数", self.sp_cache)
        f.addRow("日志文件", self.lbl_logfile)
        f.addRow("数据目录", self.lbl_datadir)
        f.addRow("", self._wrap(row_data))
        return g

    @staticmethod
    def _wrap(*items, right: bool = False) -> QWidget:
        """把若干控件或布局包成一个 QWidget（供 QFormLayout.addRow 使用）"""
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        for x in items:
            if isinstance(x, QLayout) or (hasattr(x, "addWidget") and not isinstance(x, QWidget)):
                lay.addLayout(x)
            else:
                lay.addWidget(x)
        lay.addStretch(1)
        return w

    # ═══════════════════════════════════════════════
    #  数据
    # ═══════════════════════════════════════════════

    def load(self) -> None:
        # 服务
        self.sp_port.setValue(cfg.get_int("listen_port", DEFAULT_LISTEN_PORT))
        host = cfg.get("listen_host", DEFAULT_LISTEN_HOST)
        self.tg_lan.setChecked(host not in ("127.0.0.1", "localhost", "::1"))
        self.ed_key.setText(cfg.get("api_key", ""))
        self._on_lan_toggle(self.tg_lan.isChecked())

        # 离线库
        self.tg_xdb_auto.setChecked(cfg.get_bool("xdb_auto_sync", True))
        self.sp_xdb_interval.setValue(cfg.get_int("xdb_sync_interval_hours", 24))
        self.tg_xdb_start.setChecked(cfg.get_bool("xdb_sync_on_start", True))
        self.tg_xdb_download.setChecked(cfg.get_bool("xdb_auto_download", True))
        self.ed_xdb_source.setText(cfg.get("xdb_source", ""))

        # 封禁
        self.tg_auto.setChecked(cfg.get_bool("auto_mode", False))
        self.sp_threshold.setValue(cfg.get_int("auto_ban_threshold", 90))
        self.sp_duration.setValue(cfg.get_int("default_ban_duration_sec", 3600) // 60)
        self.sp_rate.setValue(cfg.get_int("rate_limit_per_sec", 300))

        # 告警
        self.tg_sound.setChecked(cfg.get_bool("alert_sound", True))
        popup = cfg.get("alert_popup_level", LEVEL_CRITICAL)
        idx = (
            0
            if popup == "none"
            else (LEVEL_ITEMS.index(popup) + 1 if popup in LEVEL_ITEMS else len(LEVEL_ITEMS))
        )
        self.cb_popup.setCurrentIndex(max(0, min(idx, self.cb_popup.count() - 1)))
        self.sp_merge.setValue(cfg.get_int("alert_merge_sec", 60))

        # 数据
        self.sp_retention.setValue(cfg.get_int("log_retention_days", 30))
        self.sp_maint_hour.setValue(cfg.get_int("maintenance_hour", 3))
        self.sp_buffer.setValue(cfg.get_int("monitor_buffer_size", 5000))
        self.sp_cache.setValue(cfg.get_int("geo_cache_size", 20000))

        self._on_auto_toggle(self.tg_auto.isChecked())
        self._refresh_server_state()
        self.refresh_xdb_state()

    def save(self) -> None:
        # 局域网监听 + 空 Key 是危险组合：保存时强制作出选择
        lan = self.tg_lan.isChecked()
        key = self.ed_key.text().strip()
        if lan and not key:
            key = secrets.token_urlsafe(24)
            self.ed_key.setText(key)
            QMessageBox.information(
                self,
                "已自动生成 API Key",
                "监听局域网地址必须设置 API Key，已自动生成一个：\n\n"
                f"{key}\n\n请复制到业务系统的 X-API-Key 请求头。",
            )

        cfg.set_many(
            {
                "listen_port": self.sp_port.value(),
                # 用户显式打开「允许局域网访问」时才监听全网卡；此时强制 API Key
                # （上面已自动生成），因此这是有意为之，不是配置疏漏。
                "listen_host": WILDCARD_HOST if lan else DEFAULT_LISTEN_HOST,
                "api_key": key,
                "auto_mode": "1" if self.tg_auto.isChecked() else "0",
                "auto_ban_threshold": self.sp_threshold.value(),
                "default_ban_duration_sec": self.sp_duration.value() * 60,
                "rate_limit_per_sec": self.sp_rate.value(),
                "alert_sound": "1" if self.tg_sound.isChecked() else "0",
                "alert_popup_level": (
                    "none"
                    if self.cb_popup.currentIndex() == 0
                    else LEVEL_ITEMS[self.cb_popup.currentIndex() - 1]
                ),
                "alert_merge_sec": self.sp_merge.value(),
                "log_retention_days": self.sp_retention.value(),
                "maintenance_hour": self.sp_maint_hour.value(),
                "monitor_buffer_size": self.sp_buffer.value(),
                "geo_cache_size": self.sp_cache.value(),
                "xdb_auto_sync": "1" if self.tg_xdb_auto.isChecked() else "0",
                "xdb_sync_interval_hours": self.sp_xdb_interval.value(),
                "xdb_sync_on_start": "1" if self.tg_xdb_start.isChecked() else "0",
                "xdb_auto_download": "1" if self.tg_xdb_download.isChecked() else "0",
                "xdb_source": self.ed_xdb_source.text().strip(),
            }
        )

        # 定位库缓存条数改动即时生效
        try:
            from core.geo_locator import get_locator

            get_locator().set_cache_size(self.sp_cache.value())
        except Exception:
            log.exception("应用归属地缓存条数失败")

        # 日志保留天数改动即时生效（滚动 handler 每次滚动时才读 backupCount）
        try:
            set_retention(self.sp_retention.value())
        except Exception:
            log.exception("应用日志保留天数失败")

        self.settings_saved.emit()
        QMessageBox.information(
            self,
            "已保存",
            "设置已保存。\n\n监听端口 / 监听地址的改动需要**重启接收服务**才会生效"
            "（可点上方「停止服务」再「启动服务」）。",
        )

    def _on_auto_toggle(self, on: bool) -> None:
        self.sp_threshold.setEnabled(on)
        self.lbl_auto.setText(
            "已开启：命中且评分达标将自动封禁"
            if on
            else "已关闭（推荐）：仅生成建议，人工确认后执行"
        )

    def _on_lan_toggle(self, on: bool) -> None:
        self.lbl_lan.setText(
            "已开启：局域网内其他主机可上报（需 API Key）" if on else "已关闭（推荐）：仅本机可上报"
        )

    def _toggle_key_echo(self) -> None:
        if self.ed_key.echoMode() == QLineEdit.EchoMode.Password:
            self.ed_key.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.ed_key.setEchoMode(QLineEdit.EchoMode.Password)

    def _generate_key(self) -> None:
        self.ed_key.setText(secrets.token_urlsafe(24))
        self.ed_key.setEchoMode(QLineEdit.EchoMode.Normal)

    def _copy_key(self) -> None:
        QApplication.clipboard().setText(self.ed_key.text().strip())
        QMessageBox.information(self, "已复制", "API Key 已复制到剪贴板。")

    # ═══════════════════════════════════════════════
    #  服务控制
    # ═══════════════════════════════════════════════

    def _toggle_server(self) -> None:
        self.server_toggled.emit(not report_server.is_running())

    def refresh_server_state(self) -> None:
        self._refresh_server_state()

    def _refresh_server_state(self) -> None:
        running = report_server.is_running()
        port = report_server.get_port() or self.sp_port.value()
        fallback = WILDCARD_HOST if self.tg_lan.isChecked() else DEFAULT_LISTEN_HOST
        host = report_server.get_host() if running else fallback
        if running:
            self.btn_server.setText("停止服务")
            self.btn_server.setObjectName("btn_danger")
            self.lbl_server_state.setText(f"运行中，监听 {host}:{port}")
            self.lbl_server_state.setStyleSheet(f"color:{C.success};font-size:12px;")
        else:
            self.btn_server.setText("启动服务")
            self.btn_server.setObjectName("btn_success")
            self.lbl_server_state.setText("未启动")
            self.lbl_server_state.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
        self.btn_server.style().unpolish(self.btn_server)
        self.btn_server.style().polish(self.btn_server)

        shown = "127.0.0.1" if host in ("127.0.0.1", "localhost", "::1") else host
        self.lbl_endpoint.setText(
            f"POST http://{shown}:{port}/api/v1/access/report\n"
            f"GET  http://{shown}:{port}/api/v1/health"
        )

    # ═══════════════════════════════════════════════
    #  离线库状态
    # ═══════════════════════════════════════════════

    def refresh_xdb_state(self) -> None:
        try:
            from app.xdb_service import get_service

            s = get_service().summary()
        except Exception:
            log.exception("读取离线库状态失败")
            return

        files = s.get("files", {})
        lines = []
        for name, d in files.items():
            label = "IPv4 库" if "_v4" in name else "IPv6 库"
            size = f"{d.get('size', 0) / 1048576:.1f} MB" if d.get("exists") else "缺失"
            when = ms_to_str(d.get("synced_at")) if d.get("synced_at") else "随程序内置"
            src = d.get("source", "")
            if src:
                try:
                    src = src.split("/")[2]
                except Exception:
                    src = ""
            lines.append(
                f"{label}：{size} · 本地文件 {ms_to_str(d.get('mtime'))} · "
                f"上次同步 {when}" + (f"（源 {src}）" if src else "")
            )
        last_check = ms_to_str(s.get("last_check_at")) if s.get("last_check_at") else "从未检查"
        lines.append(f"上次检查：{last_check}")
        if s.get("last_result"):
            lines.append(f"最近结果：{s['last_result']}")
        self.lbl_xdb_state.setText("\n".join(lines))

        self.tg_xdb_auto.setChecked(cfg.get_bool("xdb_auto_sync", True))
        self.sp_xdb_interval.setValue(cfg.get_int("xdb_sync_interval_hours", 24))
        self.tg_xdb_start.setChecked(cfg.get_bool("xdb_sync_on_start", True))
        self.tg_xdb_download.setChecked(cfg.get_bool("xdb_auto_download", True))
        if not s.get("busy"):
            self.lbl_xdb_progress.setText("待命中")

    def on_xdb_progress(self, stage: str, message: str, percent: int) -> None:
        """由主窗口事件泵调用（Qt 主线程）"""
        self.xdb_bar.setValue(max(0, min(100, int(percent))))
        self.lbl_xdb_progress.setText(f"[{stage}] {message}")
        color = C.text_muted
        if stage == "failed":
            color = C.danger
        elif stage == "done":
            color = C.success
        elif stage in ("download", "verify", "apply", "reload", "check"):
            color = C.warning
        self.lbl_xdb_progress.setStyleSheet(f"color:{color};font-size:12px;")
        if stage in ("done", "uptodate", "failed"):
            self.refresh_xdb_state()

    def _force_sync(self) -> None:
        if (
            QMessageBox.question(
                self,
                "强制重新下载",
                "将忽略版本指纹，重新下载全部离线库并覆盖本地文件。\n"
                "用于修复疑似损坏的库；下载前会自动备份，失败会回滚。\n\n继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        self.xdb_sync_requested.emit(True)

    # ═══════════════════════════════════════════════
    #  告警测试 / 数据操作
    # ═══════════════════════════════════════════════

    def _test_alert(self) -> None:
        from core.alerts import Alerter

        a = Alerter(tray=getattr(self.window(), "tray", None), parent_widget=self)
        a._last_alert.clear()
        a.notify(
            {
                "ip": "203.0.113.10",
                "level": "critical",
                "score": 95,
                "reason": "这是一条测试告警",
                "geo": "测试·测试·测试",
                "local_port": 8080,
            }
        )

    def _clean_logs(self) -> None:
        """手动立即清理：访问记录 + 磁盘上的过期日志文件"""
        days = self.sp_retention.value()
        n = delete_old_access(days)
        n_files = maintenance.cleanup_log_files(days)
        QMessageBox.information(
            self,
            "完成",
            f"已清理 {n} 条超过 {days} 天的访问记录，"
            f"以及 {n_files} 个过期日志文件。\n\n日志文件：{log_file()}",
        )

    def _clear_logs(self) -> None:
        if (
            QMessageBox.question(
                self,
                "清空日志",
                "将删除全部访问日志与风险事件（不影响封禁列表）。\n\n确认继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        clear_all_logs()
        QMessageBox.information(self, "完成", "日志已清空。")
