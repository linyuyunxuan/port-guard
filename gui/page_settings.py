"""PortGuard — 设置页

布局依据 _design/02_ux_spec.md：
  · 6 组竖排（约 1780px，要滚 2.4 屏）改成 **3 个下划线 tab** —— 服务与采集 /
    防护与告警 / 数据与离线库；
  · 标签列固定 128px 右对齐，所有控件左缘落在同一条竖线（P1-5）；
  · 局域网警告、自动封禁警告**只在对应开关打开时**出现在表单里，不常驻；
  · 「未保存」标记：任一控件改动即在标题区亮起，保存后熄灭（P1-12）。

不改任何判定逻辑与信号契约：sp_port / btn_xdb_check / tg_xdb_auto / lbl_watch_state
等属性名被 selftest 与主窗口直接引用，全部保留。
"""

import datetime
import secrets
from typing import Optional, Tuple

from app import maintenance
from core import firewall, report_server
from core import settings as cfg
from core.config import (
    BAN_DURATION_TIER_DEFAULTS,
    DEFAULT_ESCALATION_FACTOR,
    DEFAULT_ESCALATION_MAX_SEC,
    DEFAULT_LISTEN_HOST,
    DEFAULT_LISTEN_PORT,
    DEFAULT_TS_SKEW_SEC,
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
from gui.components import PageHeader
from gui.theme import C
from gui.widgets import ToggleSwitch, WarnBanner
from qtcompat import (
    QApplication,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLayout,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    Qt,
    QTabWidget,
    QTimer,
    QVBoxLayout,
    QWidget,
    Signal,
)

log = get_logger(__name__)

LEVEL_ITEMS = [LEVEL_LOW, LEVEL_MEDIUM, LEVEL_HIGH, LEVEL_CRITICAL]
LEVEL_LABELS = [LEVEL_LABEL[x] for x in LEVEL_ITEMS]

#: 表单标签列固定宽度。所有面板共用，保证控件左缘对齐（P1-5）
LABEL_W = 128


def _row_widget(*items, spacing: int = 8) -> QWidget:
    """把若干控件 / 子布局拼成一个横排 QWidget（供表格布局的字段列使用）"""
    w = QWidget()
    lay = QHBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(spacing)
    for x in items:
        if isinstance(x, QLayout):
            lay.addLayout(x)
        else:
            lay.addWidget(x)
    lay.addStretch(1)
    return w


class _Panel(QFrame):
    """设置分组面板：无边框卡片 + 128px 右对齐标签列。

    不用 QFormLayout —— 它没有「固定标签列宽」的接口，标签长度一不同控件左缘
    就参差。这里用 QGridLayout 手工排两列，标签列 `setColumnMinimumWidth(128)`。
    """

    def __init__(self, title: str = "", parent=None):
        super().__init__(parent)
        self.setObjectName("panel")
        box = QVBoxLayout(self)
        box.setContentsMargins(16, 12, 16, 14)
        box.setSpacing(8)

        self.title_label: Optional[QLabel] = None
        if title:
            t = QLabel(title)
            t.setObjectName("panel_title")
            box.addWidget(t)
            self.title_label = t

        self.grid = QGridLayout()
        self.grid.setHorizontalSpacing(12)
        self.grid.setVerticalSpacing(6)
        self.grid.setColumnMinimumWidth(0, LABEL_W)
        self.grid.setColumnStretch(1, 1)
        box.addLayout(self.grid)
        self._row = 0

    def add(self, label: str, field) -> None:
        """加一行「标签 + 字段」。field 可为控件、子布局或控件元组"""
        if label:
            lb = QLabel(label)
            lb.setFixedWidth(LABEL_W)
            lb.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            lb.setObjectName("form_label")
            self.grid.addWidget(lb, self._row, 0)
        if isinstance(field, QWidget):
            w = field
        elif isinstance(field, QLayout):
            w = _row_widget(field)
        else:
            w = _row_widget(*field)
        self.grid.addWidget(w, self._row, 1)
        self._row += 1

    def add_block(self, w: QWidget, span: bool = True) -> None:
        """整行块（横幅 / 多行只读文本 / 按钮条）。

        span=True 横跨标签列与字段列（横幅要占满），否则左缘与字段列对齐。
        """
        self.grid.addWidget(w, self._row, 0 if span else 1, 1, 2 if span else 1)
        self._row += 1


class SettingsPage(QWidget):
    server_toggled = Signal(bool)  # 请求主窗口启动/停止服务
    settings_saved = Signal()
    xdb_sync_requested = Signal(bool)  # 立即同步（True=强制重下）
    xdb_check_requested = Signal()  # 只检查
    logs_open_requested = Signal()
    watch_changed = Signal()  # 本机端口观察的开关/参数发生变化
    # Webhook 测试的结果由后台线程回调，用它跨线程回到主线程再改控件
    webhook_result = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._loading = True  # load() 期间不点亮「未保存」
        self._report_url = ""
        self._dirty = False
        self._hint_timer = QTimer(self)
        self._hint_timer.setSingleShot(True)
        self._hint_timer.timeout.connect(self._reset_hint)
        self.webhook_result.connect(self._on_webhook_result)
        self._build()
        self.load()
        self._wire_dirty()
        self._loading = False

    # ═══════════════════════════════════════════════
    #  界面
    # ═══════════════════════════════════════════════

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 16, 24, 12)
        outer.setSpacing(12)

        # ── 标题区（56，7 页统一用 PageHeader）──
        head = PageHeader("设置", "服务、采集、封禁、告警与离线库")
        self.lbl_dirty = QLabel("")
        self.lbl_dirty.setVisible(False)
        head.add_action(self.lbl_dirty)

        self.btn_save = QPushButton("保存设置")
        self.btn_save.setObjectName("btn_primary")
        self.btn_save.clicked.connect(self.save)
        head.add_action(self.btn_save)
        outer.addWidget(head)

        # ── 三个 tab ──
        self.tabs = QTabWidget()
        self.tabs.addTab(self._tab_service(), "服务与采集")
        self.tabs.addTab(self._tab_guard(), "防护与告警")
        self.tabs.addTab(self._tab_data(), "数据与离线库")
        outer.addWidget(self.tabs, 1)

    # ── Tab 1：服务与采集 ──
    def _tab_service(self) -> QWidget:
        page, page_layout = self._scroll_page()

        panel = _Panel("上报接收服务")
        self.sp_port = QSpinBox()
        self.sp_port.setRange(1, 65535)
        self.sp_port.setValue(DEFAULT_LISTEN_PORT)
        self.sp_port.setFixedWidth(120)

        self.tg_lan = ToggleSwitch(False)
        self.tg_lan.toggled.connect(self._on_lan_toggle)
        self.lbl_lan = QLabel("")
        self.lbl_lan.setObjectName("form_hint")
        panel.add("监听端口", self.sp_port)
        panel.add("允许局域网访问", _row_widget(self.tg_lan, self.lbl_lan, spacing=10))

        # 只在开关打开时出现（P1-4）：平时不占高度，也不制造「常驻警告疲劳」
        self.warn_lan = WarnBanner(
            "局域网内其他主机可伪造上报记录，进而污染风险判定、"
            "甚至借自动封禁之手封掉任意 IP —— 因此会强制要求 API Key。",
            level="warning",
        )
        self.warn_lan.setVisible(False)
        panel.add_block(self.warn_lan)

        self.ed_key = QLineEdit()
        self.ed_key.setPlaceholderText("留空表示不校验；监听局域网地址时会强制要求")
        self.ed_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.ed_key.setMaximumWidth(300)
        b_show = QPushButton("显示")
        b_show.setObjectName("btn_outline")
        b_show.setFixedWidth(52)
        b_show.clicked.connect(self._toggle_key_echo)
        b_gen = QPushButton("生成")
        b_gen.setObjectName("btn_outline")
        b_gen.setFixedWidth(52)
        b_gen.clicked.connect(self._generate_key)
        b_copy = QPushButton("复制")
        b_copy.setObjectName("btn_outline")
        b_copy.setFixedWidth(52)
        b_copy.clicked.connect(self._copy_key)
        panel.add("API Key", (self.ed_key, b_show, b_gen, b_copy))

        # ── 上报侧可信度 ──
        # body 里的 ip / timestamp 都是业务系统给的，能直接左右判定结果，
        # 所以这里给运维一个总闸与阈值，而不是让程序默默信任。
        self.tg_trust_ip = ToggleSwitch(True)
        self.sp_ts_skew = QSpinBox()
        self.sp_ts_skew.setRange(0, 3600)
        self.sp_ts_skew.setSuffix(" 秒")
        self.sp_ts_skew.setValue(DEFAULT_TS_SKEW_SEC)
        self.sp_ts_skew.setFixedWidth(120)
        panel.add(
            "上报来源 IP",
            _row_widget(self.tg_trust_ip, self._sw_label("信任上报中的来源 IP"), spacing=10),
        )
        panel.add("时间戳最大偏差", self.sp_ts_skew)

        hint_trust = QLabel(
            "勾掉后一律按 TCP 对端地址计；不勾时，仅回环来源或通过 API Key 校验的请求，"
            "其上报的 ip 才会被采信。时间戳与本机时间不符或超出偏差时，按本机时间计。"
        )
        hint_trust.setObjectName("hint")
        hint_trust.setWordWrap(True)
        hint_trust.setToolTip(
            "上报的 ip 与 timestamp 都来自业务系统，可被伪造：\n\n"
            "· ip 伪造 —— 给任意 IP 刷风险分，甚至借自动封禁封掉正常来源；\n"
            "· 时间戳伪造 —— 规则引擎用它推进滑动窗口，往回拨能让窗口永远累积不起来，"
            "往前拨会让清理逻辑把窗口清空，4 条窗口型规则全部失效。\n\n"
            "因此这两项由服务端按「来源可信度 + 偏差阈值」兜底。"
        )
        panel.add_block(hint_trust, span=False)

        self.lbl_server_state = QLabel("")
        self.lbl_server_state.setObjectName("form_hint")
        self.btn_server = QPushButton("启动服务")
        self.btn_server.setObjectName("btn_success")
        self.btn_server.clicked.connect(self._toggle_server)
        panel.add("服务状态", (self.btn_server, self.lbl_server_state))

        # 上报地址：只读可选中 + 一键复制（运维要把 URL 贴进业务系统，P2-5）
        self.lbl_endpoint = QLabel("")
        self.lbl_endpoint.setObjectName("mono_hint")
        self.lbl_endpoint.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        btn_ep = QPushButton("复制")
        btn_ep.setObjectName("btn_outline")
        btn_ep.setFixedWidth(52)
        btn_ep.setToolTip("复制上报地址（POST /api/v1/access/report）")
        btn_ep.clicked.connect(self._copy_endpoint)
        panel.add("上报地址", (self.lbl_endpoint, btn_ep))

        page_layout.addWidget(panel)

        # ── 本机端口访问观察 ──
        watch = _Panel("本机端口访问观察")

        self.tg_watch = ToggleSwitch(False)
        self.ed_watch_ports = QLineEdit()
        self.ed_watch_ports.setPlaceholderText("18080,3389,1433,3306,6379")
        self.ed_watch_ports.setMinimumWidth(240)
        self.ed_watch_ports.setMaximumWidth(560)

        self.cb_watch_method = QComboBox()
        self.cb_watch_method.addItems(["TCP 连接表轮询", "防火墙日志", "两者都要（推荐）"])
        self.cb_watch_method.setFixedWidth(180)

        self.sp_watch_interval = QSpinBox()
        self.sp_watch_interval.setRange(1, 3600)
        self.sp_watch_interval.setValue(5)
        self.sp_watch_interval.setSuffix(" 秒")
        self.sp_watch_interval.setFixedWidth(110)

        self.sp_watch_dedupe = QSpinBox()
        self.sp_watch_dedupe.setRange(0, 86400)
        self.sp_watch_dedupe.setValue(120)
        self.sp_watch_dedupe.setSuffix(" 秒")
        self.sp_watch_dedupe.setFixedWidth(110)

        self.ed_watch_log = QLineEdit()
        self.ed_watch_log.setPlaceholderText("留空使用系统默认位置")
        self.ed_watch_log.setMinimumWidth(240)
        self.ed_watch_log.setMaximumWidth(560)

        self.tg_watch_pid = ToggleSwitch(True)
        self.tg_watch_skip = ToggleSwitch(True)
        self.tg_watch_autoban = ToggleSwitch(False)

        watch.add("启用本机观察", self.tg_watch)
        watch.add("监控端口", self.ed_watch_ports)
        watch.add("采集通道", self.cb_watch_method)
        watch.add(
            "采样 / 去重",
            _row_widget(
                self.sp_watch_interval,
                self._sw_label("同来源"),
                self.sp_watch_dedupe,
                spacing=8,
            ),
        )
        watch.add("防火墙日志", self.ed_watch_log)
        # 三个开关同一行（P1-4）：它们都是「开关型」小项，竖排纯属浪费高度
        watch.add(
            "采集选项",
            _row_widget(
                self.tg_watch_pid,
                self._sw_label("解析进程名"),
                self.tg_watch_skip,
                self._sw_label("跳过历史日志"),
                self.tg_watch_autoban,
                self._sw_label("允许自动封禁"),
                spacing=8,
            ),
        )

        self.btn_watch_start = QPushButton("立即启用观察")
        self.btn_watch_start.setObjectName("btn_primary")
        self.btn_watch_start.clicked.connect(lambda: self._watch_apply(True))
        self.btn_watch_stop = QPushButton("停止观察")
        self.btn_watch_stop.setObjectName("btn_outline")
        self.btn_watch_stop.clicked.connect(lambda: self._watch_apply(False))
        self.btn_fwlog = QPushButton("启用防火墙日志记录")
        self.btn_fwlog.setObjectName("btn_outline")
        self.btn_fwlog.setToolTip(
            "开启 Windows 防火墙安全日志（需要管理员权限）。\n"
            "只记被丢弃的连接：能抓到扫描/爆破，又不会把日志文件写爆。"
        )
        self.btn_fwlog.clicked.connect(self._enable_fwlog)
        watch.add("", (self.btn_watch_start, self.btn_watch_stop, self.btn_fwlog))

        self.lbl_watch_state = QLabel("未启动")
        self.lbl_watch_state.setObjectName("form_hint")
        self.lbl_watch_state.setWordWrap(True)
        watch.add("运行状态", self.lbl_watch_state)

        hint = QLabel(
            "自采不依赖业务系统上报；两种通道可同时开启，事件按「本机端口 + 远端 IP」去重"
        )
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        hint.setToolTip(
            "程序自己观察本机端口，不依赖业务系统上报。\n\n"
            "· TCP 连接表轮询：免管理员权限，但只能看见当前仍连着的连接；\n"
            "· 防火墙日志：连被丢弃的扫描都看得见，需管理员开启一次日志记录。"
        )
        watch.add_block(hint, span=False)

        page_layout.addWidget(watch)
        page_layout.addStretch(1)
        return page

    # ── Tab 2：防护与告警 ──
    def _tab_guard(self) -> QWidget:
        page, lay = self._scroll_page()

        ban = _Panel("封禁策略")

        self.tg_auto = ToggleSwitch(False)
        self.tg_auto.toggled.connect(self._on_auto_toggle)
        self.lbl_auto = QLabel("")
        self.lbl_auto.setObjectName("form_hint")
        ban.add("自动封禁模式", _row_widget(self.tg_auto, self.lbl_auto, spacing=10))

        # 仅自动模式开启时出现（P1-4）
        self.warn_auto = WarnBanner(
            "自动模式会跳过人工确认直接写入 Windows 防火墙，请先确认规则阈值与默认时长再开启。",
            level="danger",
        )
        self.warn_auto.setVisible(False)
        ban.add_block(self.warn_auto)

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

        # ── 按风险等级分档的封禁时长 ──
        # 只对「走策略」的封禁生效（自动封禁 / 未指定时长的手动封禁）；
        # 手动封禁对话框里的默认值仍然是上面那个「默认封禁时长」。
        def _tier_spin(level: str) -> QSpinBox:
            sp = QSpinBox()
            sp.setRange(0, 365 * 24 * 60)
            sp.setValue(BAN_DURATION_TIER_DEFAULTS[level] // 60)
            sp.setSuffix(" 分钟（0=不分档）")
            sp.setSpecialValueText("不分档")
            sp.setFixedWidth(200)
            return sp

        self.sp_dur_critical = _tier_spin(LEVEL_CRITICAL)
        self.sp_dur_high = _tier_spin(LEVEL_HIGH)
        self.sp_dur_medium = _tier_spin(LEVEL_MEDIUM)
        self.sp_dur_low = _tier_spin(LEVEL_LOW)

        # ── 重复封禁递增 ──
        self.tg_escalation = ToggleSwitch(False)
        self.tg_escalation.toggled.connect(self._on_escalation_toggle)

        self.sp_esc_factor = QSpinBox()
        self.sp_esc_factor.setRange(1, 10)
        self.sp_esc_factor.setValue(DEFAULT_ESCALATION_FACTOR)
        self.sp_esc_factor.setSuffix(" 倍")
        self.sp_esc_factor.setFixedWidth(120)

        self.sp_esc_max = QSpinBox()
        self.sp_esc_max.setRange(1, 365 * 24)
        self.sp_esc_max.setValue(DEFAULT_ESCALATION_MAX_SEC // 3600)
        self.sp_esc_max.setSuffix(" 小时")
        self.sp_esc_max.setFixedWidth(160)

        self.sp_rate = QSpinBox()
        self.sp_rate.setRange(0, 100000)
        self.sp_rate.setValue(300)
        self.sp_rate.setSuffix(" 次/秒/IP（0=不限流）")
        self.sp_rate.setFixedWidth(220)

        ban.add("自动封禁最低评分", self.sp_threshold)
        ban.add("默认封禁时长", self.sp_duration)
        ban.add("严重档时长", self.sp_dur_critical)
        ban.add("高档时长", self.sp_dur_high)
        ban.add("中档时长", self.sp_dur_medium)
        ban.add("低档时长", self.sp_dur_low)
        ban.add("重复封禁递增", _row_widget(self.tg_escalation, spacing=10))
        ban.add("递增倍数", self.sp_esc_factor)
        ban.add("递增封顶", self.sp_esc_max)
        ban.add("上报限流", self.sp_rate)

        hint_strategy = QLabel(
            "时长优先级：规则指定 > 重复封禁递增 > 风险等级分档 > 默认封禁时长。"
            "「不分档」表示该等级沿用默认封禁时长；递增以等级档位为基准，"
            "同一 IP 每多一次历史封禁记录就乘一次倍数，直到封顶值。"
            "手动封禁对话框仍以「默认封禁时长」为初始值，可随时改。"
        )
        hint_strategy.setObjectName("hint")
        hint_strategy.setWordWrap(True)
        ban.add_block(hint_strategy, span=False)

        self.lbl_perm = QLabel("")
        self.lbl_perm.setWordWrap(True)
        ban.add("权限状态", self.lbl_perm)
        lay.addWidget(ban)

        alert = _Panel("告警通知")
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

        alert.add("声音提示", self.tg_sound)
        alert.add("弹窗级别", self.cb_popup)
        alert.add("同 IP 合并窗口", self.sp_merge)
        alert.add("", b_test)
        lay.addWidget(alert)

        note = QLabel(
            "弹窗级别选「不弹窗」时只写日志与发送托盘通知；同 IP 在合并窗口内的多次命中只提醒一次。"
        )
        note.setObjectName("hint")
        note.setWordWrap(True)
        lay.addWidget(note)

        # ── 外部告警通道 ──
        hook = _Panel("外部告警通道（Webhook）")
        self.tg_hook = ToggleSwitch(False)
        self.tg_hook.toggled.connect(self._on_hook_toggle)
        self.lbl_hook = QLabel("")
        self.lbl_hook.setObjectName("form_hint")
        hook.add("启用推送", _row_widget(self.tg_hook, self.lbl_hook, spacing=10))

        self.ed_hook_url = QLineEdit()
        self.ed_hook_url.setPlaceholderText("https://alert.example.com/hooks/portguard")
        self.ed_hook_url.setMaximumWidth(560)
        hook.add("接收地址", self.ed_hook_url)

        self.ed_hook_secret = QLineEdit()
        self.ed_hook_secret.setPlaceholderText("留空=不签名；填写后每条约附带 HMAC-SHA256 签名")
        self.ed_hook_secret.setEchoMode(QLineEdit.EchoMode.Password)
        self.ed_hook_secret.setMaximumWidth(420)
        b_secret = QPushButton("显示")
        b_secret.setObjectName("btn_outline")
        b_secret.setFixedWidth(52)
        b_secret.clicked.connect(self._toggle_secret_echo)
        hook.add("签名密钥", _row_widget(self.ed_hook_secret, b_secret, spacing=8))

        self.cb_hook_level = QComboBox()
        self.cb_hook_level.addItems(LEVEL_LABELS)
        self.cb_hook_level.setFixedWidth(140)

        self.sp_hook_timeout = QSpinBox()
        self.sp_hook_timeout.setRange(1, 30)
        self.sp_hook_timeout.setValue(10)
        self.sp_hook_timeout.setSuffix(" 秒")
        self.sp_hook_timeout.setFixedWidth(120)

        self.sp_hook_max = QSpinBox()
        self.sp_hook_max.setRange(1, 600)
        self.sp_hook_max.setValue(20)
        self.sp_hook_max.setSuffix(" 条/分钟")
        self.sp_hook_max.setFixedWidth(140)

        hook.add("推送级别", self.cb_hook_level)
        hook.add("请求超时", self.sp_hook_timeout)
        hook.add("推送限流", self.sp_hook_max)

        self.tg_hook_http = ToggleSwitch(False)
        hook.add(
            "允许内网 http",
            _row_widget(self.tg_hook_http, self._sw_label("仅内网 IP，域名仍拒绝"), spacing=10),
        )
        self.tg_hook_ssl = ToggleSwitch(True)
        self.tg_hook_ssl.toggled.connect(self._on_hook_ssl_toggle)
        hook.add(
            "校验 TLS 证书",
            _row_widget(self.tg_hook_ssl, self._sw_label("关闭后链路上可被窃听"), spacing=10),
        )

        # 只在关闭校验时出现（P1-4）：这是明确的安全降级，必须当场说清代价
        self.warn_hook = WarnBanner(
            "已关闭 TLS 证书校验：告警内容在链路上可能被中间人窃听或篡改。"
            "仅用于排查老旧服务器（如 Server 2008 R2 的 TLS 兼容问题），问题解决后请立即恢复。",
            level="danger",
        )
        self.warn_hook.setVisible(False)
        hook.add_block(self.warn_hook)

        self.lbl_hook_state = QLabel("未测试")
        self.lbl_hook_state.setObjectName("form_hint")
        self.lbl_hook_state.setWordWrap(True)
        b_hook_test = QPushButton("发送测试")
        b_hook_test.setObjectName("btn_outline")
        b_hook_test.clicked.connect(self._test_webhook)
        hook.add("连通性", _row_widget(self.lbl_hook_state, b_hook_test, spacing=10))
        lay.addWidget(hook)

        note_hook = QLabel(
            "告警以 JSON POST 送达：ip / level / score / reason / geo / local_port / ts / host；"
            "配置密钥后附带 X-PortGuard-Signature（对端用同一密钥复算即可验真伪）。"
            "推送在后台线程进行并按限流发送，不影响界面响应。"
        )
        note_hook.setObjectName("hint")
        note_hook.setWordWrap(True)
        lay.addWidget(note_hook)
        lay.addStretch(1)
        return page

    # ── Tab 3：数据与离线库 ──
    def _tab_data(self) -> QWidget:
        page, lay = self._scroll_page()

        xdb = _Panel("离线库在线同步（IP 归属地）")

        self.lbl_xdb_state = QLabel("读取中…")
        self.lbl_xdb_state.setObjectName("mono_hint")
        self.lbl_xdb_state.setWordWrap(True)
        self.lbl_xdb_state.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        xdb.add("当前库", self.lbl_xdb_state)

        self.tg_xdb_auto = ToggleSwitch(True)
        self.sp_xdb_interval = QSpinBox()
        self.sp_xdb_interval.setRange(1, 24 * 30)
        self.sp_xdb_interval.setValue(24)
        self.sp_xdb_interval.setSuffix(" 小时")
        self.sp_xdb_interval.setFixedWidth(120)
        self.tg_xdb_start = ToggleSwitch(True)
        self.tg_xdb_download = ToggleSwitch(True)

        self.ed_xdb_source = QLineEdit()
        self.ed_xdb_source.setPlaceholderText(
            "留空使用内置源（CDN / 官方 / 镜像 / Gitee 自动容错）；也可填自定义镜像，用 {path} 占位"
        )
        self.ed_xdb_source.setMaximumWidth(560)

        xdb.add("自动检查更新", self.tg_xdb_auto)
        xdb.add("检查间隔", self.sp_xdb_interval)
        xdb.add(
            "启动 / 换库",
            _row_widget(
                self.tg_xdb_start,
                self._sw_label("启动时检查"),
                self.tg_xdb_download,
                self._sw_label("自动下载并热换"),
                spacing=8,
            ),
        )
        xdb.add("自定义镜像源", self.ed_xdb_source)

        self.xdb_bar = QProgressBar()
        self.xdb_bar.setRange(0, 100)
        self.xdb_bar.setValue(0)
        self.xdb_bar.setFixedHeight(8)
        self.xdb_bar.setTextVisible(False)

        self.lbl_xdb_progress = QLabel("待命中")
        self.lbl_xdb_progress.setObjectName("form_hint")
        xdb.add("同步进度", (self.xdb_bar, self.lbl_xdb_progress))

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
        # 流程说明进 tooltip（P1-4）：它只在「想知道为什么这么慢」时才需要
        sync_tip = (
            "同步流程：版本指纹比对 → 多源下载 → 大小 / 内容指纹 / xdb 结构 / 抽样查询"
            "四重校验 → 备份旧库 → 原子替换 → 热加载（无需重启）。\n"
            "任一步失败都会回滚，不影响现有定位能力。"
        )
        for b in (self.btn_xdb_check, self.btn_xdb_sync, self.btn_xdb_force):
            b.setToolTip(sync_tip)
        xdb.add("", (self.btn_xdb_check, self.btn_xdb_sync, self.btn_xdb_force))
        lay.addWidget(xdb)

        data = _Panel("数据管理")
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

        data.add("日志保留", self.sp_retention)
        data.add("自动清理时刻", self.sp_maint_hour)
        data.add("监控缓冲行数", self.sp_buffer)
        data.add("归属地缓存条数", self.sp_cache)

        self.lbl_logfile = QLabel(log_file())
        self.lbl_logfile.setObjectName("mono_hint")
        self.lbl_logfile.setWordWrap(True)
        self.lbl_logfile.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.lbl_datadir = QLabel(user_data_dir())
        self.lbl_datadir.setObjectName("mono_hint")
        self.lbl_datadir.setWordWrap(True)
        self.lbl_datadir.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        data.add("日志文件", self.lbl_logfile)
        data.add("数据目录", self.lbl_datadir)

        b_clean = QPushButton("清理过期日志")
        b_clean.setObjectName("btn_outline")
        b_clean.clicked.connect(self._clean_logs)
        b_clear = QPushButton("清空全部日志")
        b_clear.setObjectName("btn_danger")
        b_clear.clicked.connect(self._clear_logs)
        b_logs = QPushButton("打开日志目录")
        b_logs.setObjectName("btn_outline")
        b_logs.clicked.connect(self.logs_open_requested.emit)
        data.add("", (b_clean, b_clear, b_logs))
        lay.addWidget(data)

        lay.addStretch(1)
        return page

    # ── 小工具 ──
    @staticmethod
    def _scroll_page() -> Tuple[QScrollArea, QVBoxLayout]:
        """tab 内容容器。窗口变矮时出现滚动条，而不是把控件压扁"""
        area = QScrollArea()
        area.setWidgetResizable(True)
        area.setFrameShape(QFrame.Shape.NoFrame)
        area.setStyleSheet(
            "QScrollArea{background:transparent;}QWidget#tab_host{background:transparent;}"
        )
        host = QWidget()
        host.setObjectName("tab_host")
        lay = QVBoxLayout(host)
        lay.setContentsMargins(0, 8, 8, 8)
        lay.setSpacing(12)
        area.setWidget(host)
        return area, lay

    @staticmethod
    def _sw_label(text: str) -> QLabel:
        """开关右侧的小字说明"""
        lb = QLabel(text)
        lb.setStyleSheet(f"color:{C.text_secondary};font-size:12.5px;")
        return lb

    def _wire_dirty(self) -> None:
        """把页面内所有可编辑控件的变更信号接到「未保存」标记上。

        逐个控件手工 connect 会漏（本页有 30+ 个），而 findChildren 一次性覆盖，
        以后加控件自动生效。
        """
        for sp in self.findChildren(QSpinBox):
            sp.valueChanged.connect(self._mark_dirty)
        for le in self.findChildren(QLineEdit):
            le.textChanged.connect(self._mark_dirty)
        for cb in self.findChildren(QComboBox):
            cb.currentIndexChanged.connect(self._mark_dirty)
        for tg in self.findChildren(ToggleSwitch):
            tg.toggled.connect(self._mark_dirty)

    def _mark_dirty(self, *_args) -> None:
        if not self._loading:
            self._set_dirty(True)

    def _set_dirty(self, dirty: bool) -> None:
        self._dirty = dirty
        if dirty:
            self._hint_timer.stop()
            self.lbl_dirty.setText("● 未保存")
            self.lbl_dirty.setStyleSheet(f"color:{C.warning};font-size:12px;")
            self.lbl_dirty.setVisible(True)
        else:
            self.lbl_dirty.setVisible(False)
            self.lbl_dirty.setText("")

    def _flash_saved(self) -> None:
        """保存成功后在原位显示 4 秒提示，不弹模态框（P1-12）"""
        stamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.lbl_dirty.setText(f"✓ 已保存 {stamp}")
        self.lbl_dirty.setStyleSheet(f"color:{C.success};font-size:12px;")
        self.lbl_dirty.setVisible(True)
        self._hint_timer.start(4000)

    def _reset_hint(self) -> None:
        if self._dirty:
            self._set_dirty(True)
        else:
            self.lbl_dirty.setVisible(False)
            self.lbl_dirty.setText("")

    # ═══════════════════════════════════════════════
    #  数据
    # ═══════════════════════════════════════════════

    def load(self) -> None:
        # 服务
        self.sp_port.setValue(cfg.get_int("listen_port", DEFAULT_LISTEN_PORT))
        host = cfg.get("listen_host", DEFAULT_LISTEN_HOST)
        self.tg_lan.setChecked(host not in ("127.0.0.1", "localhost", "::1"))
        self.ed_key.setText(cfg.get("api_key", ""))
        self.tg_trust_ip.setChecked(cfg.get_bool("trust_reported_ip", True))
        self.sp_ts_skew.setValue(cfg.get_int("report_max_ts_skew_sec", DEFAULT_TS_SKEW_SEC))
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
        self.sp_dur_critical.setValue(
            cfg.get_int("ban_duration_critical_sec", BAN_DURATION_TIER_DEFAULTS[LEVEL_CRITICAL])
            // 60
        )
        self.sp_dur_high.setValue(
            cfg.get_int("ban_duration_high_sec", BAN_DURATION_TIER_DEFAULTS[LEVEL_HIGH]) // 60
        )
        self.sp_dur_medium.setValue(
            cfg.get_int("ban_duration_medium_sec", BAN_DURATION_TIER_DEFAULTS[LEVEL_MEDIUM]) // 60
        )
        self.sp_dur_low.setValue(
            cfg.get_int("ban_duration_low_sec", BAN_DURATION_TIER_DEFAULTS[LEVEL_LOW]) // 60
        )
        self.tg_escalation.setChecked(cfg.get_bool("ban_escalation_enabled", False))
        self.sp_esc_factor.setValue(cfg.get_int("ban_escalation_factor", DEFAULT_ESCALATION_FACTOR))
        # 封顶按小时展示；库里是秒，老值可能不是整小时，向上取整避免「显示 7 天、实际 6 天」
        self.sp_esc_max.setValue(
            (cfg.get_int("ban_escalation_max_sec", DEFAULT_ESCALATION_MAX_SEC) + 3599) // 3600
        )
        self._on_escalation_toggle(self.tg_escalation.isChecked())
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

        # 外部告警通道（Webhook）
        self.tg_hook.setChecked(cfg.get_bool("webhook_enabled", False))
        self.ed_hook_url.setText(cfg.get("webhook_url", ""))
        self.ed_hook_secret.setText(cfg.get("webhook_secret", ""))
        lvl = (cfg.get("webhook_min_level", LEVEL_HIGH) or LEVEL_HIGH).strip().lower()
        self.cb_hook_level.setCurrentIndex(
            max(0, LEVEL_ITEMS.index(lvl)) if lvl in LEVEL_ITEMS else 2
        )
        self.sp_hook_timeout.setValue(cfg.get_int("webhook_timeout_sec", 10))
        self.sp_hook_max.setValue(cfg.get_int("webhook_max_per_min", 20))
        self.tg_hook_http.setChecked(cfg.get_bool("webhook_allow_http", False))
        self.tg_hook_ssl.setChecked(cfg.get_bool("webhook_verify_ssl", True))
        self._on_hook_toggle(self.tg_hook.isChecked())
        self._on_hook_ssl_toggle(self.tg_hook_ssl.isChecked())

        # 数据
        self.sp_retention.setValue(cfg.get_int("log_retention_days", 30))
        self.sp_maint_hour.setValue(cfg.get_int("maintenance_hour", 3))
        self.sp_buffer.setValue(cfg.get_int("monitor_buffer_size", 5000))
        self.sp_cache.setValue(cfg.get_int("geo_cache_size", 20000))

        self._on_auto_toggle(self.tg_auto.isChecked())
        self._refresh_server_state()
        self.refresh_xdb_state()

        # 本机端口访问观察
        self._watch_load()
        self._refresh_watch_state()
        self._set_dirty(False)

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
                "trust_reported_ip": "1" if self.tg_trust_ip.isChecked() else "0",
                "report_max_ts_skew_sec": self.sp_ts_skew.value(),
                "auto_mode": "1" if self.tg_auto.isChecked() else "0",
                "auto_ban_threshold": self.sp_threshold.value(),
                "default_ban_duration_sec": self.sp_duration.value() * 60,
                "ban_duration_critical_sec": self.sp_dur_critical.value() * 60,
                "ban_duration_high_sec": self.sp_dur_high.value() * 60,
                "ban_duration_medium_sec": self.sp_dur_medium.value() * 60,
                "ban_duration_low_sec": self.sp_dur_low.value() * 60,
                "ban_escalation_enabled": "1" if self.tg_escalation.isChecked() else "0",
                "ban_escalation_factor": self.sp_esc_factor.value(),
                # 上限 365 天 = app.ban_service.MAX_BAN_SECONDS，别改大：
                # 超出部分会被 prepare() 里的 clamp_int 静默截断
                "ban_escalation_max_sec": self.sp_esc_max.value() * 3600,
                "rate_limit_per_sec": self.sp_rate.value(),
                "alert_sound": "1" if self.tg_sound.isChecked() else "0",
                "alert_popup_level": (
                    "none"
                    if self.cb_popup.currentIndex() == 0
                    else LEVEL_ITEMS[self.cb_popup.currentIndex() - 1]
                ),
                "alert_merge_sec": self.sp_merge.value(),
                "webhook_enabled": "1" if self.tg_hook.isChecked() else "0",
                "webhook_url": self.ed_hook_url.text().strip(),
                "webhook_secret": self.ed_hook_secret.text().strip(),
                "webhook_min_level": LEVEL_ITEMS[max(0, self.cb_hook_level.currentIndex())],
                "webhook_timeout_sec": self.sp_hook_timeout.value(),
                "webhook_max_per_min": self.sp_hook_max.value(),
                "webhook_allow_http": "1" if self.tg_hook_http.isChecked() else "0",
                "webhook_verify_ssl": "1" if self.tg_hook_ssl.isChecked() else "0",
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

        # 本机端口访问观察：配置即时热更新到运行中的观察器
        self._watch_save_settings()
        try:
            from core import port_watcher

            if self.tg_watch.isChecked():
                port_watcher.reload_from_settings(restart=True)
            else:
                port_watcher.stop_watcher()
        except Exception:
            log.exception("应用本机观察配置失败")
        self._refresh_watch_state()

        # 日志保留天数改动即时生效（滚动 handler 每次滚动时才读 backupCount）
        try:
            set_retention(self.sp_retention.value())
        except Exception:
            log.exception("应用日志保留天数失败")

        self._set_dirty(False)
        self._flash_saved()
        self.settings_saved.emit()

    def _on_auto_toggle(self, on: bool) -> None:
        self.sp_threshold.setEnabled(on)
        self.lbl_auto.setText(
            "已开启：命中且评分达标将自动封禁"
            if on
            else "已关闭（推荐）：仅生成建议，人工确认后执行"
        )
        self.warn_auto.setVisible(bool(on))

    def _on_lan_toggle(self, on: bool) -> None:
        self.lbl_lan.setText(
            "已开启：局域网内其他主机可上报（需 API Key）" if on else "已关闭（推荐）：仅本机可上报"
        )
        self.warn_lan.setVisible(bool(on))

    def _on_escalation_toggle(self, on: bool) -> None:
        """递增关闭时倍数 / 封顶没有意义，置灰避免用户以为改了会生效"""
        self.sp_esc_factor.setEnabled(on)
        self.sp_esc_max.setEnabled(on)

    def _toggle_key_echo(self) -> None:
        if self.ed_key.echoMode() == QLineEdit.EchoMode.Password:
            self.ed_key.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.ed_key.setEchoMode(QLineEdit.EchoMode.Password)

    def _generate_key(self) -> None:
        self.ed_key.setText(secrets.token_urlsafe(24))
        self.ed_key.setEchoMode(QLineEdit.EchoMode.Normal)

    def _copy_key(self) -> None:
        """复制 Key：只改按钮文案做反馈，不弹模态框"""
        QApplication.clipboard().setText(self.ed_key.text().strip())
        self._flash_copied("API Key 已复制")

    def _copy_endpoint(self) -> None:
        QApplication.clipboard().setText(self._report_url)
        self._flash_copied("上报地址已复制")

    def _flash_copied(self, text: str) -> None:
        self.lbl_dirty.setText(f"✓ {text}")
        self.lbl_dirty.setStyleSheet(f"color:{C.success};font-size:12px;")
        self.lbl_dirty.setVisible(True)
        self._hint_timer.start(2500)

    # ═══════════════════════════════════════════════
    #  本机端口观察
    # ═══════════════════════════════════════════════

    # 采集通道下拉：索引 -> 设置值
    _METHOD_VALUES = ("table", "fwlog", "table,fwlog")

    def _watch_methods_text(self) -> str:
        i = max(0, min(self.cb_watch_method.currentIndex(), len(self._METHOD_VALUES) - 1))
        return self._METHOD_VALUES[i]

    def _set_watch_methods(self, text: str) -> None:
        norm = ",".join(sorted(x.strip() for x in str(text or "").split(",") if x.strip()))
        table = {"table": 0, "fwlog": 1, "fwlog,table": 2, "table,fwlog": 2}
        self.cb_watch_method.setCurrentIndex(table.get(norm, 2))

    def _watch_apply(self, start: bool) -> None:
        """
        立即启用 / 停止观察。

        启用前先把界面上当前的参数写进设置 —— 否则用户改了端口直接点「启用」，
        用的还是上一次保存的旧参数，行为很难理解。
        """
        if start:
            self._watch_save_settings()
        try:
            from core import port_watcher

            if start:
                c = port_watcher.WatchConfig.from_settings()
                if not c.ports:
                    QMessageBox.warning(
                        self, "无法启用", "请先填写至少一个合法的监控端口（1-65535）。"
                    )
                    return
                port_watcher.get_watcher().update_config(c, restart=False)
                port_watcher.start_watcher()
            else:
                port_watcher.stop_watcher()
        except Exception as e:
            log.exception("切换本机观察状态失败")
            QMessageBox.warning(self, "操作失败", str(e))
        self.watch_changed.emit()
        self._refresh_watch_state()

    def _enable_fwlog(self) -> None:
        from core import win_fwlog

        if not firewall.is_admin():
            QMessageBox.warning(
                self,
                "需要管理员权限",
                "开启防火墙日志记录需要管理员权限。\n\n请以管理员身份重新运行程序后再试。",
            )
            return
        ok, err = win_fwlog.enable_logging()
        if ok:
            QMessageBox.information(
                self,
                "已开启",
                "已开启 Windows 防火墙安全日志（记录被丢弃的连接）。\n\n"
                f"日志路径：{win_fwlog.DEFAULT_LOG_PATH}\n\n"
                "新的连接尝试会开始写入日志，「防火墙日志」通道即可看到数据。",
            )
        else:
            QMessageBox.warning(self, "开启失败", err or "未知错误")
        self._refresh_watch_state()

    def _refresh_watch_state(self) -> None:
        """刷新「运行状态」一行（也由主窗口统计定时器周期调用）"""
        try:
            from core import port_watcher, win_fwlog, win_net

            w = port_watcher.get_watcher()
            st = w.stats()
            if st.get("running"):
                ports = st.get("ports") or []
                self.lbl_watch_state.setText(
                    f"运行中 · 端口 {len(ports)} 个 · 已采集 {st.get('emitted', 0)} 条"
                    f" · 去重 {st.get('deduped', 0)} 条"
                )
                self.lbl_watch_state.setStyleSheet(f"color:{C.success};font-size:12.5px;")
            else:
                bits = ["未启动"]
                if not win_net.available():
                    bits.append(f"（TCP 连接表不可用：{win_net.unavailable_reason()}）")
                if not win_fwlog.logging_enabled():
                    bits.append("（防火墙日志未开启）")
                self.lbl_watch_state.setText(" ".join(bits))
                self.lbl_watch_state.setStyleSheet(f"color:{C.text_muted};font-size:12.5px;")
        except Exception:
            log.debug("刷新本机观察状态失败", exc_info=True)

    def _watch_save_settings(self) -> None:
        """把观察相关控件写进设置（保存设置 / 立即启用 共用）"""
        cfg.set_many(
            {
                "watch_enabled": "1" if self.tg_watch.isChecked() else "0",
                "watch_ports": self.ed_watch_ports.text().strip(),
                "watch_methods": self._watch_methods_text(),
                "watch_interval_sec": self.sp_watch_interval.value(),
                "watch_dedupe_sec": self.sp_watch_dedupe.value(),
                "watch_fwlog_path": self.ed_watch_log.text().strip(),
                "watch_resolve_pid": "1" if self.tg_watch_pid.isChecked() else "0",
                "watch_skip_history": "1" if self.tg_watch_skip.isChecked() else "0",
                "watch_auto_ban": "1" if self.tg_watch_autoban.isChecked() else "0",
            }
        )

    def _watch_load(self) -> None:
        self.tg_watch.setChecked(cfg.get_bool("watch_enabled", False))
        self.ed_watch_ports.setText(cfg.get("watch_ports", "3389,1433,3306,6379,18080"))
        self._set_watch_methods(cfg.get("watch_methods", "table,fwlog"))
        self.sp_watch_interval.setValue(max(1, cfg.get_int("watch_interval_sec", 5)))
        self.sp_watch_dedupe.setValue(max(0, cfg.get_int("watch_dedupe_sec", 120)))
        self.ed_watch_log.setText(cfg.get("watch_fwlog_path", ""))
        self.tg_watch_pid.setChecked(cfg.get_bool("watch_resolve_pid", True))
        self.tg_watch_skip.setChecked(cfg.get_bool("watch_skip_history", True))
        self.tg_watch_autoban.setChecked(cfg.get_bool("watch_auto_ban", False))

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
            self.lbl_server_state.setStyleSheet(f"color:{C.success};font-size:12.5px;")
        else:
            self.btn_server.setText("启动服务")
            self.btn_server.setObjectName("btn_success")
            self.lbl_server_state.setText("未启动")
            self.lbl_server_state.setStyleSheet(f"color:{C.text_muted};font-size:12.5px;")
        self.btn_server.style().unpolish(self.btn_server)
        self.btn_server.style().polish(self.btn_server)

        shown = "127.0.0.1" if host in ("127.0.0.1", "localhost", "::1") else host
        self._report_url = f"http://{shown}:{port}/api/v1/access/report"
        self.lbl_endpoint.setText(
            f"POST {self._report_url}\nGET  http://{shown}:{port}/api/v1/health"
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
        self.lbl_xdb_progress.setStyleSheet(f"color:{color};font-size:12.5px;")
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
                QMessageBox.StandardButton.No,
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

    # ═══════════════════════════════════
    #  外部告警通道（Webhook）
    # ═══════════════════════════════════

    def _on_hook_toggle(self, on: bool) -> None:
        self.lbl_hook.setText(
            "启用后按推送级别实时外发" if on else "关闭：仅本机托盘 / 声音 / 弹窗"
        )

    def _on_hook_ssl_toggle(self, on: bool) -> None:
        self.warn_hook.setVisible(not on)

    def _toggle_secret_echo(self) -> None:
        if self.ed_hook_secret.echoMode() == QLineEdit.EchoMode.Password:
            self.ed_hook_secret.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.ed_hook_secret.setEchoMode(QLineEdit.EchoMode.Password)

    def _webhook_form(self) -> dict:
        """表单当前值（含未保存的改动），供「发送测试」直接验证"""
        return {
            "url": self.ed_hook_url.text().strip(),
            "secret": self.ed_hook_secret.text().strip(),
            "timeout": self.sp_hook_timeout.value(),
            "allow_http": self.tg_hook_http.isChecked(),
            "verify_ssl": self.tg_hook_ssl.isChecked(),
        }

    def _test_webhook(self) -> None:
        from app import notify_service

        self.lbl_hook_state.setText("发送中…")
        self.lbl_hook_state.setStyleSheet(f"color:{C.text_secondary};font-size:12.5px;")
        notify_service.get_service().test(
            overrides=self._webhook_form(), on_done=self.webhook_result.emit
        )

    def _on_webhook_result(self, res) -> None:
        ok, kind, status, message = res
        if ok:
            text, color = f"✓ 已送达（HTTP {status}）", C.success
        else:
            text = f"✗ {message}"
            # 「配置不对」是提醒而不是故障，别用红色吓人
            color = C.warning if kind in ("invalid", "timeout") else C.danger
        self.lbl_hook_state.setText(text)
        self.lbl_hook_state.setStyleSheet(f"color:{color};font-size:12.5px;")

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
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        clear_all_logs()
        QMessageBox.information(self, "完成", "日志已清空。")
