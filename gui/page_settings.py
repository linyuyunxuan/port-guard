"""PortGuard — 设置页

布局依据 _design/02_ux_spec.md：
  · 6 组竖排（约 1780px，要滚 2.4 屏）改成 **3 个下划线 tab** —— 服务与采集 /
    防护与告警 / 数据与离线库；
  · 标签列固定 128px 右对齐，所有控件左缘落在同一条竖线（P1-5）；
  · 自动封禁警告**只在开关打开时**出现在表单里，不常驻；
  · 「未保存」标记：任一控件改动即在标题区亮起，保存后熄灭（P1-12）。

不改任何判定逻辑与信号契约：btn_xdb_check / tg_xdb_auto / lbl_watch_state
等属性名被 selftest 与主窗口直接引用，全部保留。
"""

import contextlib
import datetime
import json
import threading
from typing import Any, Dict, List, Optional, Tuple

from app import audit, maintenance
from core import firewall, xdb_updater
from core import settings as cfg
from core.config import (
    BAN_DURATION_TIER_DEFAULTS,
    DEFAULT_AUDIT_RETENTION_DAYS,
    DEFAULT_BAN_RETENTION_DAYS,
    DEFAULT_ESCALATION_FACTOR,
    DEFAULT_ESCALATION_MAX_SEC,
    DEFAULT_LOG_RETENTION_DAYS,
    DEFAULT_REPEAT_BLACKLIST_HITS,
    DEFAULT_RISK_RETENTION_DAYS,
    LEVEL_CRITICAL,
    LEVEL_HIGH,
    LEVEL_LABEL,
    LEVEL_LOW,
    LEVEL_MEDIUM,
    MAX_BAN_DURATION_DEFAULT_SEC,
    RETENTION_PRESETS,
    XDB_UPSTREAM,
    db_path,
    user_data_dir,
)
from core.database import clear_all_logs, count_audit, db_size, query_audit
from core.logger import get_logger, log_file, set_retention
from core.models import ms_to_str
from gui.background import run_in_background
from gui.components import PageHeader
from gui.theme import C
from gui.widgets import CONTENT_MAX_W, ToggleSwitch, WarnBanner, align_headers, make_item
from qtcompat import (
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLayout,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    Qt,
    QTableWidget,
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

#: 备份表：行高与列宽（库 / 备份文件 / 大小 / 备份时间）。文件列是唯一的拉伸列
BACKUP_ROW_H = 28
BACKUP_WIDTHS = [78, 345, 92, 170]

#: 数据库备份表：库只有一份，不需要「库」列
DB_BACKUP_WIDTHS = [368, 101, 170]

#: 后台任务进行中的提示语（VACUUM 可能几十秒，必须让用户知道程序没死）
DB_TASK_TEXT = {
    "vacuum": "正在整理数据库（VACUUM）…会把整库重写一遍，库越大越久，请勿关闭程序",
    "reindex": "正在重建全部索引…",
    "backup": "正在备份数据库…",
    "restore": "正在恢复数据库…写入器已暂停，期间不会记录新的访问",
}

#: 任务名（拼「✗ xx 失败」用）
DB_TASK_NAME = {"vacuum": "整理数据库", "reindex": "重建索引", "backup": "备份", "restore": "恢复"}

# ── 操作审计表 ──
AUDIT_HEADERS = ["时间", "操作者", "操作", "对象", "摘要", "结果"]
AUDIT_WIDTHS = [170, 150, 115, 104, 483, 69]
AUDIT_CENTER_COLS = [0, 2, 3, 5]
COL_AUDIT_SUMMARY = 4
AUDIT_RESULT_LABEL = {
    "ok": "成功",
    "fail": "失败",
    "skipped": "未执行",
}


def _audit_target(row: Dict[str, Any]) -> str:
    """审计记录的「对象」列：类型 + id，缺一补一，都没有就 `-`"""
    t = str(row.get("target_type") or "")
    i = row.get("target_id")
    i = "" if i is None else str(i)
    if t and i:
        return f"{t} #{i}"
    return t or i or "-"


def _xdb_label(name: str) -> str:
    """库文件名 -> 列表里的展示名。与 `refresh_xdb_state` 同一套口径"""
    return "IPv4 库" if "_v4" in name else "IPv6 库"


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
        # 内容列限宽（见 gui/widgets.CONTENT_MAX_W）：卡片不再横跨整个页面，
        # 与 _scroll_page 里的水平居中配合，表单落在一条 900px 的阅读线上
        self.setMaximumWidth(CONTENT_MAX_W)
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
    settings_saved = Signal()
    xdb_sync_requested = Signal(bool)  # 立即同步（True=强制重下）
    xdb_check_requested = Signal()  # 只检查
    logs_open_requested = Signal()
    watch_changed = Signal()  # 本机端口观察的开关/参数发生变化
    # 数据库维护（VACUUM / 重建索引 / 备份 / 恢复）在后台线程跑，结果同样经信号回主线程
    db_task_done = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._loading = True  # load() 期间不点亮「未保存」
        self._bak_rows: List[Dict] = []  # 备份表当前行 -> 备份条目（与表格行号同序）
        self._db_rows: List[Dict] = []  # 数据库备份表当前行 -> 备份条目
        self._db_busy = False
        self._db_cursor = False  # 是否压了 Busy 光标（只有压过才去 restore）
        self._dirty = False
        self._hint_timer = QTimer(self)
        self._hint_timer.setSingleShot(True)
        self._hint_timer.timeout.connect(self._reset_hint)
        self.db_task_done.connect(self._on_db_task_done)
        self._build()
        self.load()
        self._wire_dirty()
        self._loading = False
        self.refresh_db_state()

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

        # ── 四个 tab ──
        self.tabs = QTabWidget()
        self.tabs.addTab(self._tab_service(), "服务与采集")
        self.tabs.addTab(self._tab_guard(), "防护与告警")
        self.tabs.addTab(self._tab_data(), "数据与离线库")
        self.tabs.addTab(self._tab_audit(), "操作审计")
        # 审计表只在切到该 tab 时才查：它可能在别的 tab 上被大量写入
        # （封禁 / 保存设置都会记），常驻刷新是白烧 IO。
        self.tabs.currentChanged.connect(self._on_tab_changed)
        outer.addWidget(self.tabs, 1)

    # ── Tab 1：服务与采集 ──
    def _tab_service(self) -> QWidget:
        page, page_layout = self._scroll_page()

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

        hint = QLabel("两条通道可同时开启，事件按「本机端口 + 远端 IP + 远端端口」去重")
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        hint.setToolTip(
            "程序自己观察本机端口，不依赖任何外部数据源。\n\n"
            "· TCP 连接表轮询：免管理员权限，但只能看见当前仍连着的连接；\n"
            "· 防火墙日志：连被丢弃的扫描都看得见，需管理员开启一次日志记录。"
        )
        watch.add_block(hint, span=False)

        page_layout.addWidget(watch)
        page_layout.addWidget(self._build_runtime_panel())
        page_layout.addStretch(1)
        return page

    def _build_runtime_panel(self) -> _Panel:
        """「运行与守护」：开机自启 + 当前守护状态

        这一块回答的是「程序没在跑的时候，封禁会发生什么」。答案是：什么都不会
        发生 —— 防火墙规则没有到期时间，只有本程序的 60 秒巡检会去删。所以
        重启后能不能自动接上，直接决定「封禁会不会变成永久」。
        """
        run = _Panel("运行与守护")
        self.tg_autostart = ToggleSwitch(False)
        self.tg_autostart.toggled.connect(self._on_autostart_toggle)

        self.lbl_autostart = QLabel("读取中…")
        self.lbl_autostart.setObjectName("form_hint")
        self.lbl_autostart.setWordWrap(True)

        run.add("开机自动启动", self.tg_autostart)
        # 状态行**整行铺开**而不是走「标签 + 字段」两列：自动换行的 QLabel 放进
        # 字段列时只拿最小宽度（实测被压到 44px，一句话竖排成一长条，把卡片撑到
        # 800px 高）；给它 setMinimumWidth 又会让 QGridLayout 把余量塞给标签列，
        # 标签被推到列中间、和「离线库」那块的左缘对不齐。整行块没有这个问题。
        run.add_block(self.lbl_autostart, span=True)

        hint = QLabel(
            "封禁时长只记在本程序里，防火墙规则本身没有「到期时间」——"
            "程序没运行，到期的封禁就不会被解除。开启后每次登录会自动启动"
            "（会请求一次管理员权限），启动 1.5 秒内补跑到期巡检与黑名单补封。"
        )
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        # 同样整行铺开：放进字段列会被压成一条竖排文字（见上面状态行的注释）
        run.add_block(hint, span=True)
        return run

    def _on_autostart_toggle(self, on: bool) -> None:
        self._refresh_autostart_state(preview=on)

    def _refresh_autostart_state(self, preview: Optional[bool] = None) -> None:
        """把注册表里的真实状态写进说明行（读不到就说读不到，不猜）"""
        try:
            from core import autostart
        except Exception:
            self.lbl_autostart.setText("读不到当前状态（模块加载失败）")
            return
        if not autostart.supported():
            self.lbl_autostart.setText("当前系统不支持开机自启（仅 Windows）")
            self.tg_autostart.setEnabled(False)
            return
        if preview is not None:
            if preview:
                self.lbl_autostart.setText("保存后写入登录启动项：登录时自动启动并请求管理员权限")
            else:
                self.lbl_autostart.setText("保存后移除登录启动项：重启后需要手动启动")
            return

        enabled = autostart.is_enabled()
        if enabled is None:
            self.lbl_autostart.setText("读不到当前状态（注册表被策略限制），保存时会重试")
            return
        if not enabled:
            self.lbl_autostart.setText("未开启 —— 重启后需要手动启动，到期封禁不会自动解除")
            return
        if autostart.is_current_target() is False:
            self.lbl_autostart.setText(
                "已开启，但登记的是旧路径（程序换过目录或版本），保存后会指向当前程序"
            )
            return
        self.lbl_autostart.setText("已开启 —— 登录后自动启动，并立即补跑到期巡检")

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

        # ── 最大封禁时长（硬上限）──
        # 防火墙规则本身没有到期时间，到期完全靠程序内巡检删规则。程序长期不在
        # （关机 / 卸载 / 崩溃没人管）时，一条「封 365 天」就等于永久封掉一个可能
        # 无辜的地址。上限按天展示，永久封禁（0 分钟）不受它影响。
        self.sp_max_ban = QSpinBox()
        self.sp_max_ban.setRange(1, 365)
        self.sp_max_ban.setValue(MAX_BAN_DURATION_DEFAULT_SEC // 86400)
        self.sp_max_ban.setSuffix(" 天")
        self.sp_max_ban.setFixedWidth(120)

        ban.add("自动封禁最低评分", self.sp_threshold)
        ban.add("默认封禁时长", self.sp_duration)
        ban.add("严重档时长", self.sp_dur_critical)
        ban.add("高档时长", self.sp_dur_high)
        ban.add("中档时长", self.sp_dur_medium)
        ban.add("低档时长", self.sp_dur_low)
        ban.add("重复封禁递增", _row_widget(self.tg_escalation, spacing=10))
        ban.add("递增倍数", self.sp_esc_factor)
        ban.add("递增封顶", self.sp_esc_max)
        ban.add("最大封禁时长", self.sp_max_ban)

        # ── 惯犯升级：已封禁 IP 反复访问 → 直接列入黑名单（永久）──
        # 「封 1 小时 → 到期 → 再来 → 再封」是个无限循环，而「封了还在撞」
        # 本身已经是最明确的恶意信号，不需要人来判断。
        self.tg_escalate = ToggleSwitch(True)
        self.sp_escalate_hits = QSpinBox()
        self.sp_escalate_hits.setRange(1, 9999)
        self.sp_escalate_hits.setValue(DEFAULT_REPEAT_BLACKLIST_HITS)
        self.sp_escalate_hits.setSuffix(" 次")
        self.sp_escalate_hits.setFixedWidth(120)
        self.sp_escalate_hits.setToolTip(
            "封禁期间累计被拦下多少次后列入黑名单。\n"
            "升级后该 IP 变为永久封禁，并在黑名单里留档（重启仍然生效）。"
        )
        ban.add(
            "惯犯升级黑名单",
            _row_widget(self.tg_escalate, self._sw_label("封了还在撞就永久封"), spacing=10),
        )
        ban.add("升级阈值", self.sp_escalate_hits)

        hint_strategy = QLabel(
            "时长优先级：规则指定 > 重复封禁递增 > 风险等级分档 > 默认封禁时长。"
            "「不分档」表示该等级沿用默认封禁时长；递增以等级档位为基准，"
            "同一 IP 每多一次历史封禁记录就乘一次倍数，直到封顶值。"
            "手动封禁对话框仍以「默认封禁时长」为初始值，可随时改。"
            "「最大封禁时长」是硬上限：任何有限时长都会被截断到它以内"
            "（防火墙规则不会自己到期，程序长期不在时没人会解，所以别设太长）；"
            "「永久封禁」（时长填 0）不受这个上限影响。"
            "「惯犯升级」针对封了还在撞的 IP：达到阈值就直接写进黑名单（永久封禁），"
            "省掉到期重来的循环；次数记在封禁记录上，动作会进审计。"
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
        # 2026-10-27 用户要求「取消这个弹窗，保留右下角弹窗功能」：模态 QMessageBox
        # 已从 core/alerts.py 移除。这里不再提供「弹窗级别」下拉 —— 留一个改了没
        # 任何效果的控件，比没有这个控件更让人困惑，所以换成一句固定说明。
        self.lbl_popup_note = QLabel("仅托盘气泡（右下角），不再弹出窗口")
        self.lbl_popup_note.setObjectName("hint")
        self.sp_merge = QSpinBox()
        self.sp_merge.setRange(0, 3600)
        self.sp_merge.setValue(60)
        self.sp_merge.setSuffix(" 秒")
        self.sp_merge.setFixedWidth(120)

        # ── 已拦截（该 IP 已在封禁中）的重复命中 ──
        # 2026-10-22 用户反馈：「已拦截了还弹窗提示或者右下角窗口提示，影响电脑操作」。
        # 默认开启静默：重复命中只累加 ban_list.hit_count，不弹窗 / 不气泡 /
        # 不响铃。真正状态变化（升级黑名单）仍会提示一次。
        self.tg_block_silent = ToggleSwitch(True)
        self.tg_block_silent.setToolTip(
            "关闭后，已封禁 IP 的每一次命中都会照常提醒（攻击期会被刷屏）。"
        )

        b_test = QPushButton("测试告警")
        b_test.setObjectName("btn_outline")
        b_test.clicked.connect(self._test_alert)

        alert.add("声音提示", self.tg_sound)
        alert.add("提醒方式", self.lbl_popup_note)
        alert.add("同 IP 合并窗口", self.sp_merge)
        alert.add(
            "已拦截不再提醒",
            _row_widget(self.tg_block_silent, self._sw_label("只累计拦截次数"), spacing=10),
        )

        # ── 外部推送（Webhook）：无人值守时唯一能「送到人手上」的通道 ──
        self.tg_webhook = ToggleSwitch(False)
        self.tg_webhook.toggled.connect(self._on_webhook_toggle)
        self.cb_webhook_level = QComboBox()
        self.cb_webhook_level.addItems(LEVEL_LABELS)
        self.cb_webhook_level.setCurrentIndex(len(LEVEL_LABELS) - 1)  # 默认只推「严重」
        self.cb_webhook_level.setFixedWidth(110)

        self.ed_webhook = QLineEdit()
        self.ed_webhook.setPlaceholderText("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=…")
        self.ed_webhook.setMinimumWidth(320)
        self.ed_webhook.setMaximumWidth(560)
        self.ed_webhook.setToolTip(
            "企业微信 / 钉钉群机器人地址，或任意接受 "
            '{"msgtype":"text","text":{"content":"..."}} 的告警网关。\n'
            "只允许 http/https，且不允许指向本机 / 内网地址（防 SSRF）。\n"
            "地址里通常带密钥：日志与错误提示只会显示 scheme://host。"
        )
        self.btn_webhook_test = QPushButton("发送测试消息")
        self.btn_webhook_test.setObjectName("btn_outline")
        self.btn_webhook_test.clicked.connect(self._test_webhook)

        alert.add(
            "推送级别",
            _row_widget(
                self.tg_webhook,
                self._sw_label("启用外部推送"),
                self.cb_webhook_level,
                spacing=8,
            ),
        )
        alert.add("推送地址", _row_widget(self.ed_webhook, self.btn_webhook_test))
        alert.add("", b_test)
        lay.addWidget(alert)

        note = QLabel(
            "告警一律以托盘气泡（任务栏右下角）提示，不再弹出模态窗口打断操作；"
            "同 IP 在合并窗口内的多次命中只提醒一次。"
            "外部推送用于无人值守场景（企业微信 / 钉钉群机器人），默认关闭。"
        )
        note.setObjectName("hint")
        note.setWordWrap(True)
        lay.addWidget(note)

        lay.addStretch(1)
        return page

    # ── Tab 3：数据与离线库 ──
    def _tab_data(self) -> QWidget:
        page, lay = self._scroll_page()
        self.tab_data = page
        self._data_scroll = page  # WAL 提示条的「去整理」要滚到这里

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

        # 自定义镜像源：可编辑下拉框 + 增删。下拉里**全部条目都会保存**，
        # 同步时按列表顺序依次尝试，全挂才回落内置源 —— 所以「选中哪一条」
        # 不影响结果，只是一个待编辑的槽位（_wire_dirty 里对它豁免）。
        self.cb_xdb_source = QComboBox()
        self.cb_xdb_source.setEditable(True)
        # 回车不自动入列表：否则「打完字想先看看」就变成悄悄加了一条
        self.cb_xdb_source.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.cb_xdb_source.setMinimumWidth(400)
        self.cb_xdb_source.setMaximumWidth(600)
        self.cb_xdb_source.setToolTip(
            f"最多 {xdb_updater.MAX_CUSTOM_SOURCES} 条，按列表顺序依次尝试，全部失败才回落内置源。\n"
            "地址用 {path} 占位，例如 https://mirror.example.com/ip2region/{path}\n"
            "自定义域名不必加白名单，但不允许指向内网 / 回环地址（防 SSRF）。"
        )
        _le = self.cb_xdb_source.lineEdit()
        if _le is not None:
            _le.setPlaceholderText("留空用内置源；自定义镜像用 {path} 占位")
        self.lbl_xdb_src = QLabel("")
        self.lbl_xdb_src.setObjectName("form_hint")

        self.btn_xdb_src_add = QPushButton("添加")
        self.btn_xdb_src_add.setObjectName("btn_outline")
        self.btn_xdb_src_add.setToolTip("把输入框里的地址加入列表")
        self.btn_xdb_src_add.clicked.connect(self._add_xdb_source)

        self.btn_xdb_src_del = QPushButton("删除")
        self.btn_xdb_src_del.setObjectName("btn_outline")
        self.btn_xdb_src_del.setToolTip("从列表里移除当前选中 / 输入的地址")
        self.btn_xdb_src_del.clicked.connect(self._del_xdb_source)

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
        xdb.add(
            "自定义镜像源",
            _row_widget(
                self.cb_xdb_source,
                self.btn_xdb_src_add,
                self.btn_xdb_src_del,
                self.lbl_xdb_src,
                spacing=8,
            ),
        )

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

        # ── 备份与回滚（换库前自动备份，这里把它们列出来供手动回滚）──
        restore_tip = (
            "换库前会自动备份旧库，这里列出的是还能回滚到的版本"
            f"（每个库只保留最近 {maintenance.KEEP_BACKUPS_PER_FILE} 份）。\n"
            "回滚前会再备份一次当前库，所以回滚错了仍然可以再回滚回来。"
        )
        # 备份列表用 QTableWidget 而不是下拉框：_wire_dirty 会把页面里所有
        # QComboBox 的 currentIndexChanged 接到「未保存」标记上，而「选中哪份
        # 备份」不是一项设置，不该点亮未保存。
        self.tbl_bak = QTableWidget(0, 4)
        self.tbl_bak.setHorizontalHeaderLabels(["库", "备份文件", "大小", "备份时间"])
        self.tbl_bak.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl_bak.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tbl_bak.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tbl_bak.setAlternatingRowColors(True)
        self.tbl_bak.setShowGrid(False)
        self.tbl_bak.setWordWrap(False)
        self.tbl_bak.setTabKeyNavigation(False)
        self.tbl_bak.verticalHeader().setVisible(False)
        self.tbl_bak.verticalHeader().setDefaultSectionSize(BACKUP_ROW_H)
        hh = self.tbl_bak.horizontalHeader()
        for i, w in enumerate(BACKUP_WIDTHS):
            hh.resizeSection(i, w)
        hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        xdb.add_block(self.tbl_bak, span=False)

        self.lbl_bak = QLabel("")
        self.lbl_bak.setObjectName("form_hint")
        self.lbl_bak.setWordWrap(True)
        self.lbl_bak.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        xdb.add_block(self.lbl_bak, span=False)

        self.btn_bak_restore = QPushButton("回滚到此备份")
        self.btn_bak_restore.setObjectName("btn_outline")
        self.btn_bak_restore.setToolTip(restore_tip)
        self.btn_bak_restore.clicked.connect(self._restore_backup)
        xdb.add("", self.btn_bak_restore)
        lay.addWidget(xdb)

        data = _Panel("数据管理")
        # ── 自动清理总开关 + 保留期预设 ──
        # 用户要的是「1 天 / 3 天 / 7 天」这种一句话选完的档位（2026-10-22），
        # 而不是在下面四个 SpinBox 里逐个填。预设只是**一次写入四项**：
        # 四项仍是各自的真实取值，选「自定义」后仍可分表微调。
        self.tg_maint = ToggleSwitch(True)
        self.tg_maint.setToolTip("关闭后只有本页的「清理过期日志」按钮能触发清理。")
        self.cb_retention = QComboBox()
        self.cb_retention.addItems([f"{d} 天" for d in RETENTION_PRESETS] + ["自定义"])
        self.cb_retention.setFixedWidth(140)
        self.cb_retention.setToolTip(
            "一次设定四张表的保留期（访问流水 / 风险事件 / 封禁记录 / 操作审计）。\n"
            "选「自定义」后可在下面四项里分别调整。"
        )
        self.cb_retention.currentIndexChanged.connect(self._on_retention_preset)
        self._retention_preset_guard = False

        # 四张表各自的保留期。**不要合并成一个「统一保留 N 天」** ——
        # 见 core.config 的 DEFAULT_*_RETENTION_DAYS：流水最短、结论次之、
        # 封禁账本最长（要回答「是不是惯犯」），审计自己也要有期限。
        self.sp_retention = QSpinBox()
        self.sp_retention.setRange(1, 3650)
        self.sp_retention.setValue(DEFAULT_LOG_RETENTION_DAYS)
        self.sp_retention.setSuffix(" 天")
        self.sp_retention.setFixedWidth(120)
        self.sp_retention.setToolTip(
            "access_log 访问流水：原始事实，保留最短。\n同时决定磁盘日志文件的保留天数。"
        )

        self.sp_risk_retention = QSpinBox()
        self.sp_risk_retention.setRange(1, 3650)
        self.sp_risk_retention.setValue(DEFAULT_RISK_RETENTION_DAYS)
        self.sp_risk_retention.setSuffix(" 天")
        self.sp_risk_retention.setFixedWidth(120)
        self.sp_risk_retention.setToolTip(
            "risk_event 风险事件：规则算出的结论。\n"
            "刻意比流水长 —— 否则「这条访问曾被判严重风险」会比流水更早消失。"
        )

        self.sp_ban_retention = QSpinBox()
        self.sp_ban_retention.setRange(1, 3650)
        self.sp_ban_retention.setValue(DEFAULT_BAN_RETENTION_DAYS)
        self.sp_ban_retention.setSuffix(" 天")
        self.sp_ban_retention.setFixedWidth(120)
        self.sp_ban_retention.setToolTip(
            "ban_list 封禁账本：只清已解封 / 已到期 / 失败的终态记录。\n"
            "「已封禁」和「处理中」永不清理 —— 前者背后是一条真实存在的防火墙\n"
            "规则，删了记账规则就变成没人认领的无主规则。"
        )

        self.sp_audit_retention = QSpinBox()
        self.sp_audit_retention.setRange(1, 3650)
        self.sp_audit_retention.setValue(DEFAULT_AUDIT_RETENTION_DAYS)
        self.sp_audit_retention.setSuffix(" 天")
        self.sp_audit_retention.setFixedWidth(120)
        self.sp_audit_retention.setToolTip(
            "audit_log 操作审计：默认 180 天，够覆盖一次季度回溯。\n"
            "不给它期限的话，审计表自己就会变成新的无界增长表。"
        )

        # 四项里任意一项被手改 → 预设框回落到「自定义」（反之不成立）。
        # 用 valueChanged 而不是让预设框单向决定：否则用户改了其中一项，
        # 下拉框还停在「7 天」，保存时会把四项又拍回 7 —— 静默吞掉改动。
        for sp in (
            self.sp_retention,
            self.sp_risk_retention,
            self.sp_ban_retention,
            self.sp_audit_retention,
        ):
            sp.valueChanged.connect(self._sync_retention_combo)

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

        data.add(
            "自动清理",
            _row_widget(self.tg_maint, self._sw_label("每天到点执行一次"), spacing=10),
        )
        data.add("保留期预设", self.cb_retention)
        data.add("访问流水保留", self.sp_retention)
        data.add("风险事件保留", self.sp_risk_retention)
        data.add("封禁记录保留", self.sp_ban_retention)
        data.add("操作审计保留", self.sp_audit_retention)
        data.add("自动清理时刻", self.sp_maint_hour)
        data.add("监控缓冲行数", self.sp_buffer)
        data.add("归属地缓存条数", self.sp_cache)

        # 这里必须指向**真实入口**：用户清完日志发现空间没变小，得知道去哪儿解决，
        # 否则会以为「清理坏了」。「去整理」直接滚到本面板下方的数据库文件区。
        self.warn_wal = WarnBanner(
            "清理会批量删除数据，SQLite 的 WAL 文件会随之涨到与被删数据同量级，"
            "且这部分空间不会自动还给文件系统（只是留给后续写入复用）。"
            "要真正回收磁盘，需要执行一次数据库整理（VACUUM）"
            "—— 就在下方「数据库文件」区域里点「整理数据库」。",
            action_text="去整理",
            level="info",
        )
        self.warn_wal.action_clicked.connect(self._scroll_to_db_section)
        data.add_block(self.warn_wal)

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

        self._add_db_section(data)
        lay.addWidget(data)

        lay.addStretch(1)
        return page

    def _add_db_section(self, panel: "_Panel") -> None:
        """「数据管理」里追加数据库文件区：大小 / 整理 / 重建索引 / 备份与恢复。

        与上面的保留期是两件事：那边管「留多久」，这边管「文件本身」——清理只会
        把行标成可复用，磁盘不会因此变小，真正归还空间得靠 VACUUM。

        耗时操作（VACUUM / 恢复）一律丢后台线程，结果经 `db_task_done` 回到主线程，
        worker 绝不碰控件 —— 与离线库同步同一个套路。
        """
        div = QFrame()
        div.setObjectName("panel_divider")
        div.setFixedHeight(1)
        panel.add_block(div)

        title = QLabel("数据库文件（整理 · 备份 · 恢复）")
        title.setObjectName("panel_title")
        panel.add_block(title)
        #: 「去整理」滚动定位用（这个 tab 很高，提示条在上、入口在下）
        self._db_anchor = title

        self.lbl_dbsize = QLabel("读取中…")
        self.lbl_dbsize.setObjectName("mono_hint")
        self.lbl_dbsize.setWordWrap(True)
        self.lbl_dbsize.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        self.lbl_dbpath = QLabel(db_path())
        self.lbl_dbpath.setObjectName("mono_hint")
        self.lbl_dbpath.setWordWrap(True)
        self.lbl_dbpath.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        self.btn_db_vacuum = QPushButton("整理数据库")
        self.btn_db_vacuum.setObjectName("btn_outline")
        self.btn_db_vacuum.setToolTip(
            "VACUUM：把删掉的空间真正还给磁盘。\n"
            "会把整库重写一遍 —— 几百 MB 的库要几十秒，期间写入短暂排队；\n"
            "需要约等于数据库大小的空闲磁盘，空间不够会直接失败（数据不受影响）。"
        )
        self.btn_db_vacuum.clicked.connect(lambda: self._db_run("vacuum", maintenance.vacuum_db))

        self.btn_db_reindex = QPushButton("重建索引")
        self.btn_db_reindex.setObjectName("btn_outline")
        self.btn_db_reindex.setToolTip(
            "REINDEX：重建全部索引。\n"
            "长期增删之后索引 B 树会有空洞，重建后查询更快、体积更小；比整理快得多。"
        )
        self.btn_db_reindex.clicked.connect(lambda: self._db_run("reindex", maintenance.reindex_db))

        self.btn_db_backup = QPushButton("立即备份")
        self.btn_db_backup.setObjectName("btn_outline")
        self.btn_db_backup.setToolTip(
            "用 SQLite 在线备份打一份一致性快照。\n"
            "不需要停服务、不影响写入；最多保留最近 "
            f"{maintenance.KEEP_DB_BACKUPS} 份，更早的自动删除。"
        )
        self.btn_db_backup.clicked.connect(self._db_backup_now)

        self._db_buttons = [
            self.btn_db_vacuum,
            self.btn_db_reindex,
            self.btn_db_backup,
        ]

        panel.add("数据库大小", self.lbl_dbsize)
        panel.add("数据库文件", self.lbl_dbpath)
        panel.add("", (self.btn_db_vacuum, self.btn_db_reindex, self.btn_db_backup))

        self.lbl_db_state = QLabel("")
        self.lbl_db_state.setObjectName("form_hint")
        self.lbl_db_state.setWordWrap(True)
        self.lbl_db_state.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        panel.add_block(self.lbl_db_state, span=False)

        # 备份列表：与离线库那张表同样的取舍（QTableWidget 而不是下拉框，
        # 否则「选中哪份备份」会被 _wire_dirty 记成「未保存的设置」）
        self.tbl_db_bak = QTableWidget(0, 3)
        self.tbl_db_bak.setHorizontalHeaderLabels(["备份文件", "大小", "备份时间"])
        self.tbl_db_bak.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl_db_bak.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tbl_db_bak.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tbl_db_bak.setAlternatingRowColors(True)
        self.tbl_db_bak.setShowGrid(False)
        self.tbl_db_bak.setWordWrap(False)
        self.tbl_db_bak.setTabKeyNavigation(False)
        self.tbl_db_bak.verticalHeader().setVisible(False)
        self.tbl_db_bak.verticalHeader().setDefaultSectionSize(BACKUP_ROW_H)
        dhh = self.tbl_db_bak.horizontalHeader()
        for i, w in enumerate(DB_BACKUP_WIDTHS):
            dhh.resizeSection(i, w)
        dhh.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        panel.add_block(self.tbl_db_bak, span=False)

        self.lbl_db_bak = QLabel("")
        self.lbl_db_bak.setObjectName("form_hint")
        self.lbl_db_bak.setWordWrap(True)
        self.lbl_db_bak.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        panel.add_block(self.lbl_db_bak, span=False)

        self.btn_db_restore = QPushButton("恢复到选定备份")
        self.btn_db_restore.setObjectName("btn_danger")
        self.btn_db_restore.setToolTip(
            "用选中的备份整份覆盖当前数据库 —— 备份之后产生的数据会全部消失。\n"
            "恢复前会自动再备份一次当前库，所以反悔了还能再恢复回来；\n"
            "恢复期间数据库短暂不可用，完成后写入器自动重启。"
        )
        self.btn_db_restore.clicked.connect(self._db_restore)
        self._db_buttons.append(self.btn_db_restore)
        panel.add("", self.btn_db_restore)

    # ── Tab 4：操作审计 ──
    def _tab_audit(self) -> QWidget:
        """
        审计留痕查看：分页 + 按操作者 / 操作类型过滤。

        这个 tab **只读**，且刻意不放任何「删除 / 清空」按钮 —— 审计表的价值
        就在于它不能被使用者自己抹掉，想删只能靠保留期（`audit_retention_days`）
        到期被定期清理带走。
        """
        page = QWidget()
        self.tab_audit = page
        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 8, 8, 8)
        lay.setSpacing(8)

        self._audit_page = 0
        #: 每页条数。审计一次操作一条，量不大，但也别一次拉全表
        self._audit_size = 50

        # ── 过滤条 ──
        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.cb_audit_actor = QComboBox()
        self.cb_audit_actor.setFixedWidth(150)
        self.cb_audit_actor.currentIndexChanged.connect(self._on_audit_filter)

        self.cb_audit_action = QComboBox()
        self.cb_audit_action.setFixedWidth(150)
        self.cb_audit_action.addItem("全部操作", "")
        for act in audit.ACTIONS:
            self.cb_audit_action.addItem(audit.action_label(act), act)
        self.cb_audit_action.currentIndexChanged.connect(self._on_audit_filter)

        self.ed_audit_kw = QLineEdit()
        self.ed_audit_kw.setPlaceholderText("搜索摘要 / 对象 / 详情")
        self.ed_audit_kw.setFixedWidth(220)
        self.ed_audit_kw.returnPressed.connect(self._on_audit_filter)

        b_search = QPushButton("筛选")
        b_search.setObjectName("btn_outline")
        b_search.setFixedWidth(72)
        b_search.clicked.connect(self._on_audit_filter)

        b_refresh = QPushButton("刷新")
        b_refresh.setObjectName("btn_primary")
        b_refresh.setFixedWidth(72)
        b_refresh.clicked.connect(self._refresh_audit)

        bar.addWidget(QLabel("操作者"))
        bar.addWidget(self.cb_audit_actor)
        bar.addSpacing(6)
        bar.addWidget(QLabel("操作"))
        bar.addWidget(self.cb_audit_action)
        bar.addSpacing(6)
        bar.addWidget(self.ed_audit_kw)
        bar.addWidget(b_search)
        bar.addWidget(b_refresh)
        bar.addStretch(1)
        lay.addLayout(bar)

        # ── 表格 ──
        self.tbl_audit = QTableWidget(0, len(AUDIT_HEADERS))
        self.tbl_audit.setHorizontalHeaderLabels(AUDIT_HEADERS)
        self.tbl_audit.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl_audit.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tbl_audit.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tbl_audit.setAlternatingRowColors(True)
        self.tbl_audit.setShowGrid(False)
        self.tbl_audit.setWordWrap(False)
        self.tbl_audit.setTabKeyNavigation(False)
        self.tbl_audit.verticalHeader().setVisible(False)
        self.tbl_audit.verticalHeader().setDefaultSectionSize(30)
        self.tbl_audit.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        align_headers(self.tbl_audit, AUDIT_CENTER_COLS)
        hh = self.tbl_audit.horizontalHeader()
        for i, w in enumerate(AUDIT_WIDTHS):
            hh.resizeSection(i, w)
        # 摘要是唯一拉伸列：其余列都是定长（时间 / 人名 / 枚举），
        # 横向滚动是硬约束 —— 表格不许出现横向滚动条
        hh.setSectionResizeMode(COL_AUDIT_SUMMARY, QHeaderView.ResizeMode.Stretch)
        lay.addWidget(self.tbl_audit, 1)

        # ── 分页 ──
        pager = QHBoxLayout()
        pager.setSpacing(8)
        self.btn_audit_prev = QPushButton("上一页")
        self.btn_audit_prev.setObjectName("btn_outline")
        self.btn_audit_prev.setFixedWidth(80)
        self.btn_audit_prev.clicked.connect(lambda: self._goto_audit_page(self._audit_page - 1))
        self.btn_audit_next = QPushButton("下一页")
        self.btn_audit_next.setObjectName("btn_outline")
        self.btn_audit_next.setFixedWidth(80)
        self.btn_audit_next.clicked.connect(lambda: self._goto_audit_page(self._audit_page + 1))
        self.lbl_audit_page = QLabel("共 0 条，第 1/1 页")
        self.lbl_audit_page.setStyleSheet(f"color:{C.text_secondary};font-size:13.5px;")
        pager.addWidget(self.btn_audit_prev)
        pager.addWidget(self.btn_audit_next)
        pager.addSpacing(6)
        pager.addWidget(self.lbl_audit_page)
        pager.addStretch(1)
        lay.addLayout(pager)

        self.lbl_audit_hint = QLabel(
            "记录谁在何时做了什么：本机操作记 Windows 用户名，"
            "程序自动（到期巡检 / 定期清理 / 自动封禁）记 system，"
            "老库里还留着 1.1.0 之前 HTTP 上报触发的 http:<来源IP>。"
        )
        self.lbl_audit_hint.setObjectName("form_hint")
        self.lbl_audit_hint.setWordWrap(True)
        lay.addWidget(self.lbl_audit_hint)
        return page

    # ── 审计 tab 数据 ──
    def _on_tab_changed(self, idx: int) -> None:
        if self.tabs.widget(idx) is self.tab_audit:
            self._refresh_audit_actors()
            self._refresh_audit()
        elif self.tabs.widget(idx) is self.tab_data:
            # 数据库大小会随着运行一直变，切过来时重读一次（不常驻轮询：
            # 每次刷新都要 stat 三个文件 + 列一遍备份目录，白烧 IO）
            self.refresh_db_state()

    def _on_audit_filter(self, *_args: Any) -> None:
        # 条件变了必须回第 1 页：在第 7 页改过滤条件，原 offset 会指向空页
        self._audit_page = 0
        self._refresh_audit()

    def _goto_audit_page(self, page: int) -> None:
        self._audit_page = max(0, int(page))
        self._refresh_audit()

    def _refresh_audit(self) -> None:
        """按当前条件重查一页审计记录"""
        actor = self.cb_audit_actor.currentData() or ""
        action = self.cb_audit_action.currentData() or ""
        kw = self.ed_audit_kw.text().strip()
        try:
            total = count_audit(actor=actor, action=action, keyword=kw)
            rows = query_audit(
                limit=self._audit_size,
                offset=self._audit_page * self._audit_size,
                actor=actor,
                action=action,
                keyword=kw,
            )
        except Exception:
            log.exception("查询审计记录失败")
            self.lbl_audit_page.setText("查询失败")
            return

        # 末尾页被删空时退回最后一页（否则用户看到空表以为数据没了）
        pages = max(1, (total + self._audit_size - 1) // self._audit_size)
        if self._audit_page >= pages:
            self._audit_page = max(0, pages - 1)
            if self._audit_page and not rows:
                self._refresh_audit()
                return

        self.tbl_audit.setRowCount(len(rows))
        for i, r in enumerate(rows):
            self._set_audit_row(i, r)
        self.btn_audit_prev.setEnabled(self._audit_page > 0)
        self.btn_audit_next.setEnabled(self._audit_page + 1 < pages)
        self.lbl_audit_page.setText(f"共 {total} 条，第 {self._audit_page + 1}/{pages} 页")

    def _set_audit_row(self, row: int, r: Dict[str, Any]) -> None:
        result = str(r.get("result") or "")
        color = C.danger if result == audit.RESULT_FAIL else None
        cells = [
            make_item(audit.fmt_ts(r.get("ts")), mono=True),
            make_item(audit.actor_label(r.get("actor") or ""), tip=r.get("actor") or ""),
            make_item(audit.action_label(r.get("action") or "")),
            make_item(_audit_target(r)),
            make_item(r.get("summary") or "", color=color, tip=r.get("detail") or ""),
            make_item(AUDIT_RESULT_LABEL.get(result, result), color=color),
        ]
        for col, it in enumerate(cells):
            self.tbl_audit.setItem(row, col, it)

    def _refresh_audit_actors(self) -> None:
        """重载「操作者」下拉框。保留当前选中项，避免刷新把筛选条件打回全部"""
        from core.database import list_audit_actors

        current = self.cb_audit_actor.currentData() or ""
        try:
            actors = list_audit_actors()
        except Exception:
            log.exception("读取审计操作者列表失败")
            actors = []
        self.cb_audit_actor.blockSignals(True)
        self.cb_audit_actor.clear()
        self.cb_audit_actor.addItem("全部操作者", "")
        for a in actors:
            self.cb_audit_actor.addItem(audit.actor_label(a), a)
        idx = self.cb_audit_actor.findData(current)
        self.cb_audit_actor.setCurrentIndex(idx if idx >= 0 else 0)
        self.cb_audit_actor.blockSignals(False)

    # ── 小工具 ──
    @staticmethod
    def _scroll_page() -> Tuple[QScrollArea, QVBoxLayout]:
        """tab 内容容器。窗口变矮时出现滚动条，而不是把控件压扁。

        条目水平居中：面板自身限宽到 CONTENT_MAX_W（见 _Panel），
        不加这条对齐的话受限宽的卡片会全部贴左，右侧空出一大片。
        表格 / 横幅这类没限宽的控件仍是满宽，不受影响。
        """
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
        lay.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        area.setWidget(host)
        return area, lay

    @staticmethod
    def _sw_label(text: str) -> QLabel:
        """开关右侧的小字说明"""
        lb = QLabel(text)
        lb.setStyleSheet(f"color:{C.text_secondary};font-size:13.5px;")
        return lb

    def _wire_dirty(self) -> None:
        """把页面内所有可编辑控件的变更信号接到「未保存」标记上。

        逐个控件手工 connect 会漏（本页有 30+ 个），而 findChildren 一次性覆盖，
        以后加控件自动生效。
        """
        for sp in self.findChildren(QSpinBox):
            sp.valueChanged.connect(self._mark_dirty)
        for le in self.findChildren(QLineEdit):
            # 镜像源下拉自带的输入框：setCurrentIndex 会改写它的文本，
            # 但「选中哪一条」不改变保存结果（列表全部都会存），记成未保存
            # 会误导。它只在**用户真的打字**（textEdited）时算改动。
            if le is self.cb_xdb_source.lineEdit():
                continue
            le.textChanged.connect(self._mark_dirty)
        for cb in self.findChildren(QComboBox):
            if cb is self.cb_xdb_source:
                continue
            cb.currentIndexChanged.connect(self._mark_dirty)
        for tg in self.findChildren(ToggleSwitch):
            tg.toggled.connect(self._mark_dirty)
        # 镜像源：打字算改动，增删条目由 _add/_del_xdb_source 自己点亮；
        # 文本变化一律重算「已填 N 条」。
        _le = self.cb_xdb_source.lineEdit()
        if _le is not None:
            _le.textEdited.connect(self._mark_dirty)
            _le.textChanged.connect(self._refresh_xdb_src_hint)

    def _mark_dirty(self, *_args) -> None:
        if not self._loading:
            self._set_dirty(True)

    def _set_dirty(self, dirty: bool) -> None:
        self._dirty = dirty
        if dirty:
            self._hint_timer.stop()
            self.lbl_dirty.setText("● 未保存")
            self.lbl_dirty.setStyleSheet(f"color:{C.warning};font-size:13.5px;")
            self.lbl_dirty.setVisible(True)
        else:
            self.lbl_dirty.setVisible(False)
            self.lbl_dirty.setText("")

    def _flash_saved(self) -> None:
        """保存成功后在原位显示 4 秒提示，不弹模态框（P1-12）"""
        stamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.lbl_dirty.setText(f"✓ 已保存 {stamp}")
        self.lbl_dirty.setStyleSheet(f"color:{C.success};font-size:13.5px;")
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
        # 离线库
        self.tg_xdb_auto.setChecked(cfg.get_bool("xdb_auto_sync", True))
        self.sp_xdb_interval.setValue(cfg.get_int("xdb_sync_interval_hours", 24))
        self.tg_xdb_start.setChecked(cfg.get_bool("xdb_sync_on_start", True))
        self.tg_xdb_download.setChecked(cfg.get_bool("xdb_auto_download", True))
        self._set_xdb_sources(xdb_updater.custom_sources())

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
        # 最大封禁时长按天展示；老库没有这个键时用内置 7 天
        self.sp_max_ban.setValue(
            max(
                1,
                cfg.get_int("max_ban_duration_sec", MAX_BAN_DURATION_DEFAULT_SEC) // 86400,
            )
        )
        # 惯犯升级（封了还在撞 → 直接列入黑名单）
        self.tg_escalate.setChecked(cfg.get_bool("repeat_blacklist_enabled", True))
        self.sp_escalate_hits.setValue(
            cfg.get_int("repeat_blacklist_hits", DEFAULT_REPEAT_BLACKLIST_HITS)
        )
        self._on_escalation_toggle(self.tg_escalation.isChecked())

        # 告警
        self.tg_sound.setChecked(cfg.get_bool("alert_sound", True))
        self.sp_merge.setValue(cfg.get_int("alert_merge_sec", 60))
        self.tg_block_silent.setChecked(cfg.get_bool("alert_block_silent", True))

        # 外部推送（Webhook）
        self.tg_webhook.setChecked(cfg.get_bool("alert_webhook_enabled", False))
        self.ed_webhook.setText(cfg.get("alert_webhook_url", ""))
        hook_level = cfg.get("alert_webhook_level", LEVEL_CRITICAL)
        self.cb_webhook_level.setCurrentIndex(
            LEVEL_ITEMS.index(hook_level) if hook_level in LEVEL_ITEMS else len(LEVEL_ITEMS) - 1
        )
        self._on_webhook_toggle(self.tg_webhook.isChecked())

        # 数据（四张表各自的保留期）
        self.sp_retention.setValue(cfg.get_int("log_retention_days", DEFAULT_LOG_RETENTION_DAYS))
        self.sp_risk_retention.setValue(
            cfg.get_int("risk_retention_days", DEFAULT_RISK_RETENTION_DAYS)
        )
        self.sp_ban_retention.setValue(
            cfg.get_int("ban_retention_days", DEFAULT_BAN_RETENTION_DAYS)
        )
        self.sp_audit_retention.setValue(
            cfg.get_int("audit_retention_days", DEFAULT_AUDIT_RETENTION_DAYS)
        )
        self.sp_maint_hour.setValue(cfg.get_int("maintenance_hour", 3))
        self.tg_maint.setChecked(cfg.get_bool("maintenance_enabled", True))
        # 预设回显放在四项都读完之后：它是四项的组合结果
        self._sync_retention_combo()
        self.sp_buffer.setValue(cfg.get_int("monitor_buffer_size", 5000))
        self.sp_cache.setValue(cfg.get_int("geo_cache_size", 20000))

        self._on_auto_toggle(self.tg_auto.isChecked())
        self.refresh_xdb_state()

        # 本机端口访问观察
        self._watch_load()
        self._refresh_watch_state()

        # 运行与守护（开机自启读的是注册表，不是数据库）
        self.tg_autostart.setChecked(cfg.get_bool("autostart_enabled", False))
        self._refresh_autostart_state()

        # 操作审计：下拉框 + 首屏数据
        self._refresh_audit_actors()
        self._set_dirty(False)

    def save(self) -> None:
        cfg.set_many(
            {
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
                # 硬上限：所有有限时长都会被截断到它以内（0=永久的黑名单不受限）
                "max_ban_duration_sec": self.sp_max_ban.value() * 86400,
                # 惯犯升级：已封禁 IP 反复访问到阈值 → 直接列入黑名单（永久）
                "repeat_blacklist_enabled": "1" if self.tg_escalate.isChecked() else "0",
                "repeat_blacklist_hits": self.sp_escalate_hits.value(),
                "alert_sound": "1" if self.tg_sound.isChecked() else "0",
                # alert_popup_level 已废弃（弹窗取消），不再写入：旧值留在库里也无害
                "alert_merge_sec": self.sp_merge.value(),
                # 已封禁 IP 的重复命中：只累计次数，不再打扰
                "alert_block_silent": "1" if self.tg_block_silent.isChecked() else "0",
                "alert_webhook_enabled": "1" if self.tg_webhook.isChecked() else "0",
                "alert_webhook_url": self.ed_webhook.text().strip(),
                "alert_webhook_level": (
                    LEVEL_ITEMS[
                        max(0, min(self.cb_webhook_level.currentIndex(), len(LEVEL_ITEMS) - 1))
                    ]
                ),
                "log_retention_days": self.sp_retention.value(),
                # 另外三张表各自的保留期（语义见 core.config.DEFAULT_*_RETENTION_DAYS）
                "risk_retention_days": self.sp_risk_retention.value(),
                "ban_retention_days": self.sp_ban_retention.value(),
                "audit_retention_days": self.sp_audit_retention.value(),
                "maintenance_hour": self.sp_maint_hour.value(),
                "maintenance_enabled": "1" if self.tg_maint.isChecked() else "0",
                "monitor_buffer_size": self.sp_buffer.value(),
                "geo_cache_size": self.sp_cache.value(),
                "xdb_auto_sync": "1" if self.tg_xdb_auto.isChecked() else "0",
                "xdb_sync_interval_hours": self.sp_xdb_interval.value(),
                "xdb_sync_on_start": "1" if self.tg_xdb_start.isChecked() else "0",
                "xdb_auto_download": "1" if self.tg_xdb_download.isChecked() else "0",
                "xdb_source": "",  # 1.1.0 的单条字段：迁到 xdb_sources 后清空，避免两处打架
                "xdb_sources": json.dumps(self._xdb_sources(), ensure_ascii=False),
                # 开机自启：设置项只是「用户意愿」，真实状态在注册表里（见 core/autostart.py）
                "autostart_enabled": "1" if self.tg_autostart.isChecked() else "0",
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

        # 开机自启：写完设置立刻落到注册表，并回读真实状态（写失败必须让用户看见，
        # 否则他会以为「开了」而实际上重启后什么都没发生）
        try:
            from core import autostart

            ok, why = autostart.sync(self.tg_autostart.isChecked())
            if not ok:
                QMessageBox.warning(
                    self, "开机自启未生效", f"{why}\n\n设置已保存，但登录启动项没有写成功。"
                )
        except Exception:
            log.exception("应用开机自启失败")
        self._refresh_autostart_state()

        # 审计：只记「改了哪些键」，不记值 —— 把配置值抄进审计表等于
        # 把一份快照存到明文可查的地方，将来改了配置反而对不上。
        audit.record(
            audit.ACTION_SETTINGS_SAVE,
            target_type="setting",
            summary="保存设置",
            after={
                "auto_mode": self.tg_auto.isChecked(),
                "auto_ban_threshold": self.sp_threshold.value(),
                "log_retention_days": self.sp_retention.value(),
                "risk_retention_days": self.sp_risk_retention.value(),
                "ban_retention_days": self.sp_ban_retention.value(),
                "audit_retention_days": self.sp_audit_retention.value(),
            },
        )

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

    def _on_escalation_toggle(self, on: bool) -> None:
        """递增关闭时倍数 / 封顶没有意义，置灰避免用户以为改了会生效"""
        self.sp_esc_factor.setEnabled(on)
        self.sp_esc_max.setEnabled(on)
        # 惯犯升级的阈值同理由这个开关管：关着的时候改阈值不会有任何效果
        self.sp_escalate_hits.setEnabled(on)

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
                self.lbl_watch_state.setStyleSheet(f"color:{C.success};font-size:13.5px;")
            else:
                bits = ["未启动"]
                if not win_net.available():
                    bits.append(f"（TCP 连接表不可用：{win_net.unavailable_reason()}）")
                if not win_fwlog.logging_enabled():
                    bits.append("（防火墙日志未开启）")
                self.lbl_watch_state.setText(" ".join(bits))
                self.lbl_watch_state.setStyleSheet(f"color:{C.text_muted};font-size:13.5px;")
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
    #  离线库状态
    # ═══════════════════════════════════════════════

    def refresh_xdb_state(self) -> None:
        # 备份列表只依赖备份目录，不依赖 xdb_service —— 放在最前面刷新，
        # 即使离线库状态读不出来（服务还没起）它也照样列得出来
        self._refresh_backups()
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
        self.lbl_xdb_progress.setStyleSheet(f"color:{color};font-size:13.5px;")
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

    # ── 自定义镜像源（下拉多值） ──

    def _xdb_items(self) -> List[str]:
        """下拉列表里已确认的条目（不含输入框里尚未「添加」的那一条）。"""
        return [
            self.cb_xdb_source.itemText(i).strip()
            for i in range(self.cb_xdb_source.count())
            if self.cb_xdb_source.itemText(i).strip()
        ]

    def _xdb_sources(self) -> List[str]:
        """要落库的全部源：列表条目 + 当前输入框内容（用户随手打了没点「添加」也不丢）。"""
        out: List[str] = []
        seen = set()
        texts = self._xdb_items()
        texts.append(self.cb_xdb_source.currentText())
        for raw in texts:
            t = (raw or "").strip()
            if not t or t in seen:
                continue
            seen.add(t)
            out.append(t)
            if len(out) >= xdb_updater.MAX_CUSTOM_SOURCES:
                break
        return out

    def _set_xdb_sources(self, items: List[str]) -> None:
        """回填下拉（load 用）。屏蔽信号，否则会点亮「未保存」。"""
        self.cb_xdb_source.blockSignals(True)
        self.cb_xdb_source.clear()
        for t in list(items)[: xdb_updater.MAX_CUSTOM_SOURCES]:
            self.cb_xdb_source.addItem(t)
        if self.cb_xdb_source.count():
            self.cb_xdb_source.setCurrentIndex(0)
        else:
            self.cb_xdb_source.setCurrentIndex(-1)
            self.cb_xdb_source.setEditText("")
        self.cb_xdb_source.blockSignals(False)
        self._refresh_xdb_src_hint()

    def _refresh_xdb_src_hint(self, *_args) -> None:
        """右侧小字：告诉用户「填了几条、按什么顺序生效」。"""
        items = self._xdb_items()
        pending = self.cb_xdb_source.currentText().strip()
        extra = 1 if pending and pending not in items else 0
        n = len(items) + extra
        if n:
            self.lbl_xdb_src.setText(f"已填 {n} 条，按列表顺序依次尝试")
        else:
            self.lbl_xdb_src.setText("未填 → 只用内置源")
        # 只有「输入框里有字」或「列表非空」时才有东西可删
        self.btn_xdb_src_del.setEnabled(bool(pending) or bool(items))

    def _add_xdb_source(self) -> None:
        text = self.cb_xdb_source.currentText().strip()
        if not text:
            return
        if text in self._xdb_items():
            self._refresh_xdb_src_hint()
            return
        if self.cb_xdb_source.count() >= xdb_updater.MAX_CUSTOM_SOURCES:
            self._refresh_xdb_src_hint()
            return
        self.cb_xdb_source.addItem(text)
        self.cb_xdb_source.setCurrentIndex(self.cb_xdb_source.count() - 1)
        self._refresh_xdb_src_hint()
        self._mark_dirty()

    def _del_xdb_source(self) -> None:
        idx = self.cb_xdb_source.currentIndex()
        if idx < 0:
            # 只是打了字还没入列表：清空输入框即可
            self.cb_xdb_source.setEditText("")
        else:
            self.cb_xdb_source.removeItem(idx)
            if self.cb_xdb_source.count():
                self.cb_xdb_source.setCurrentIndex(min(idx, self.cb_xdb_source.count() - 1))
            else:
                self.cb_xdb_source.setCurrentIndex(-1)
                self.cb_xdb_source.setEditText("")
        self._refresh_xdb_src_hint()
        self._mark_dirty()

    # ═══════════════════════════════════════════════
    #  离线库备份与回滚
    # ═══════════════════════════════════════════════

    def _refresh_backups(self) -> None:
        """列出可回滚的备份：**按库分组**（IPv4 一段、IPv6 一段），组内新在前。

        组间顺序固定为 v4 → v6（`XDB_UPSTREAM` 的顺序），不按备份多少排 ——
        否则回滚过一次之后两组会互换位置，用户每次都得重新找。
        """
        try:
            groups = xdb_updater.group_backups()
        except Exception:
            log.exception("读取离线库备份失败")
            groups = {}

        rows: List[Dict] = []
        for name in XDB_UPSTREAM:
            rows.extend(groups.get(name, []))
        self._bak_rows = rows

        self.tbl_bak.setRowCount(0)
        self.tbl_bak.setRowCount(len(rows))
        for i, item in enumerate(rows):
            name = xdb_updater.backup_group(str(item.get("file", "")))
            size_mb = int(item.get("size", 0) or 0) / 1048576
            self.tbl_bak.setItem(i, 0, make_item(_xdb_label(name)))
            self.tbl_bak.setItem(i, 1, make_item(item.get("file", ""), mono=True))
            self.tbl_bak.setItem(
                i,
                2,
                make_item(f"{size_mb:.1f} MB", align=Qt.AlignmentFlag.AlignCenter, mono=True),
            )
            self.tbl_bak.setItem(i, 3, make_item(ms_to_str(item.get("mtime")), mono=True))

        has = bool(rows)
        self.tbl_bak.setVisible(has)
        self.tbl_bak.setFixedHeight(min(28 + BACKUP_ROW_H * len(rows), 176))
        self.btn_bak_restore.setEnabled(has)
        if has:
            self.tbl_bak.selectRow(0)
            counts = " · ".join(
                f"{_xdb_label(n)} {len(groups.get(n, []))} 份" for n in XDB_UPSTREAM if n in groups
            )
            text = (
                f"{counts}。回滚前会自动备份当前库，回滚错了还能再回滚回来"
                f"（每个库只保留最近 {maintenance.KEEP_BACKUPS_PER_FILE} 份）。"
            )
        else:
            text = "尚无备份。每次在线同步换库前都会自动备份，届时这里会列出可回滚的版本。"
        self.lbl_bak.setText(text)
        self.lbl_bak.setStyleSheet(f"color:{C.text_muted};font-size:13.5px;")

    def _restore_backup(self) -> None:
        row = self.tbl_bak.currentRow()
        if not 0 <= row < len(self._bak_rows):
            QMessageBox.information(self, "无法回滚", "请先在上方列表里选中一份备份。")
            return
        item = self._bak_rows[row]
        name = xdb_updater.backup_group(str(item.get("file", "")))
        path = str(item.get("path", ""))
        file_name = str(item.get("file", ""))
        label = _xdb_label(name)

        if (
            QMessageBox.question(
                self,
                "回滚离线库",
                f"将把{label}回滚到这份备份：\n{file_name}\n\n"
                "· 回滚前会自动备份当前库，回滚错了还能再回滚回来；\n"
                "· 回滚成功后热加载，不需要重启程序；\n"
                "· 若提示热加载失败，文件已经换掉，重启程序才生效。\n\n继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        try:
            ok, err = xdb_updater.restore_backup(name, path)
        except Exception as e:
            log.exception("回滚离线库失败")
            audit.record(
                audit.ACTION_XDB_ROLLBACK,
                target_type="xdb",
                target_id=file_name,
                summary=f"回滚{label}失败：{e}",
                result=audit.RESULT_FAIL,
            )
            QMessageBox.warning(self, "回滚失败", str(e))
            return

        # 回滚会换掉归属地库 —— 之后所有 IP 的判定结果都可能变，必须留痕
        audit.record(
            audit.ACTION_XDB_ROLLBACK,
            target_type="xdb",
            target_id=file_name,
            summary=f"回滚{label}到 {file_name}" + ("" if ok else f"（未完成：{err}）"),
            before={"lib": name},
            after={"lib": name, "file": file_name, "ok": ok},
            result=audit.RESULT_OK if ok else audit.RESULT_FAIL,
            detail=err or "",
        )

        # 回滚本身也产生了一份新备份，列表与「当前库」两处都要跟着变
        self._refresh_backups()
        self._refresh_lib_views()
        if ok:
            QMessageBox.information(self, "回滚完成", f"{label}已回滚到：\n{file_name}")
        else:
            # err 区分「当前库没动」与「文件已换但热加载失败」，必须原样展示 ——
            # 吞掉它用户就不知道自己现在用的是哪份库
            QMessageBox.warning(self, "回滚未完成", err or "未知错误")

    def _refresh_lib_views(self) -> None:
        """回滚后刷新两处「离线库状态」显示（本页 + IP 查询页）。

        IP 查询页的库信息由它自己持有（`page_iplookup._update_lib_info`），本轮
        不改那个文件；这里从主窗口拿到那个页面再调一次 —— 与切到查询页时的刷新
        是同一口径，否则回滚完切过去看到的还是回滚前的版本号。
        """
        self.refresh_xdb_state()
        with contextlib.suppress(Exception):
            page = getattr(self.window(), "page_iplookup", None)
            fn = getattr(page, "_update_lib_info", None)
            if callable(fn):
                fn()

    # ═══════════════════════════════════════════════
    #  数据库维护（整理 / 重建索引 / 备份 / 恢复）
    # ═══════════════════════════════════════════════

    def _scroll_to_db_section(self) -> None:
        """把数据库文件区滚进视野（WAL 提示条上的「去整理」）。

        提示条在「数据管理」顶部、入口在面板下半截，窗口矮的时候中间隔着
        六七个表单项 —— 只写「在下方」用户还要自己找，不如直接滚过去。
        """
        with contextlib.suppress(Exception):
            self.tabs.setCurrentWidget(self.tab_data)
            self._data_scroll.ensureWidgetVisible(self._db_anchor, 0, 12)
            self.btn_db_vacuum.setFocus()

    def refresh_db_state(self) -> None:
        """刷新「数据库大小」与备份列表（构造、切到本 tab、任务结束后各调一次）"""
        try:
            sz = db_size()
            self.lbl_dbsize.setText(
                f"总计 {maintenance.format_size(sz['total'])}"
                f"（主库 {maintenance.format_size(sz['main'])}"
                f" · WAL {maintenance.format_size(sz['wal'])}"
                f" · 共享索引 {maintenance.format_size(sz['shm'])}）"
            )
        except Exception:
            log.exception("读取数据库大小失败")
            self.lbl_dbsize.setText("读取失败")
        self._refresh_db_backups()

    def _refresh_db_backups(self) -> None:
        try:
            rows = maintenance.list_db_backups()
        except Exception:
            log.exception("读取数据库备份失败")
            rows = []
        self._db_rows = rows

        self.tbl_db_bak.setRowCount(0)
        self.tbl_db_bak.setRowCount(len(rows))
        for i, item in enumerate(rows):
            self.tbl_db_bak.setItem(i, 0, make_item(item.get("file", ""), mono=True))
            self.tbl_db_bak.setItem(
                i,
                1,
                make_item(
                    maintenance.format_size(int(item.get("size", 0) or 0)),
                    align=Qt.AlignmentFlag.AlignCenter,
                    mono=True,
                ),
            )
            self.tbl_db_bak.setItem(i, 2, make_item(ms_to_str(item.get("mtime")), mono=True))

        has = bool(rows)
        self.tbl_db_bak.setVisible(has)
        self.tbl_db_bak.setFixedHeight(min(28 + BACKUP_ROW_H * len(rows), 176))
        self.btn_db_restore.setEnabled(has and not self._db_busy)
        if has:
            self.tbl_db_bak.selectRow(0)
            text = (
                f"共 {len(rows)} 份，最多保留 {maintenance.KEEP_DB_BACKUPS} 份"
                "（更早的在下次备份时自动删除）。"
            )
        else:
            text = "尚无数据库备份。先点「立即备份」打一份快照，之后才能恢复。"
        self.lbl_db_bak.setText(text)
        self.lbl_db_bak.setStyleSheet(f"color:{C.text_muted};font-size:13.5px;")

    def _db_run(self, kind: str, fn) -> None:
        """把耗时任务丢到后台线程，同一时刻只允许一个。

        VACUUM 与「恢复」同时跑会互相踩（一个要排他锁、一个在换文件），
        所以用 `_db_busy` 做闸门：任务期间按钮全部禁用，连点也不会重复执行。

        worker 里只调不碰 Qt 的 `app.maintenance` 函数，结果经 `db_task_done`
        信号排队回主线程 —— 后台线程永远不碰控件。
        """
        if self._db_busy:
            return
        self._db_busy = True
        self._set_db_busy(True, DB_TASK_TEXT.get(kind, "处理中…"))

        def work() -> None:
            try:
                ok, msg = fn()
            except Exception as e:  # 兜底：绝不让异常死在后台线程里
                log.exception("数据库维护任务异常：%s", kind)
                ok, msg = False, str(e)
            self.db_task_done.emit((kind, ok, msg))

        threading.Thread(target=work, daemon=True, name=f"db-{kind}").start()

    def _set_db_busy(self, busy: bool, text: str = "") -> None:
        for b in self._db_buttons:
            b.setEnabled(not busy)
        if busy:
            self.lbl_db_state.setText(text)
            self.lbl_db_state.setStyleSheet(f"color:{C.warning};font-size:13.5px;")
            QApplication.setOverrideCursor(Qt.CursorShape.BusyCursor)
            self._db_cursor = True
        else:
            # 只还原自己压上去的那一个：无条件 restore 会把别处压的光标也弹掉
            if self._db_cursor:
                with contextlib.suppress(Exception):
                    QApplication.restoreOverrideCursor()
                self._db_cursor = False
            self.btn_db_restore.setEnabled(bool(self._db_rows))

    def _on_db_task_done(self, res: Any) -> None:
        """后台任务结束（Qt 主线程）：恢复按钮、刷新状态、留痕"""
        try:
            kind, ok, msg = res
        except Exception:
            log.exception("数据库维护结果格式异常：%r", res)
            self._db_busy = False
            self._set_db_busy(False)
            return

        self._db_busy = False
        self._set_db_busy(False)
        self.refresh_db_state()

        if ok:
            text = f"✓ 已备份：{msg}" if kind == "backup" else f"✓ {msg}"
        else:
            text = f"✗ {DB_TASK_NAME.get(kind, kind)}失败：{msg}"
        self.lbl_db_state.setText(text)
        self.lbl_db_state.setStyleSheet(f"color:{C.success if ok else C.danger};font-size:13.5px;")

        self._audit_db_task(kind, ok, msg)

        # 恢复换掉的是整份库，设置也可能跟着换（备份来自另一时刻的库）：
        # 表单按新库重读一遍，且不能因此点亮「未保存」
        if kind == "restore" and ok:
            self._loading = True
            try:
                self.load()
            finally:
                self._loading = False
            self._set_dirty(False)

    def _audit_db_task(self, kind: str, ok: bool, msg: str) -> None:
        """整理 / 备份 / 恢复都要留痕：事后能回答「库是哪天被换掉的」。"""
        result = audit.RESULT_OK if ok else audit.RESULT_FAIL
        if kind == "restore":
            audit.record(
                audit.ACTION_DB_RESTORE,
                target_type="database",
                target_id=db_path(),
                summary=("恢复数据库：" if ok else "恢复数据库失败：") + msg,
                result=result,
                detail=msg,
            )
        elif kind == "backup":
            audit.record(
                audit.ACTION_DB_BACKUP,
                target_type="database",
                target_id=msg if ok else "",
                summary="备份数据库" + ("成功" if ok else f"失败：{msg}"),
                result=result,
            )
        else:
            audit.record(
                audit.ACTION_DB_MAINTENANCE,
                target_type="database",
                summary=("整理数据库（VACUUM）：" if kind == "vacuum" else "重建索引：") + msg,
                result=result,
                detail=msg,
            )

    def _db_backup_now(self) -> None:
        self._db_run("backup", maintenance.backup_db)

    def _db_restore(self) -> None:
        row = self.tbl_db_bak.currentRow()
        if not 0 <= row < len(self._db_rows):
            QMessageBox.information(self, "无法恢复", "请先在上方列表里选中一份备份。")
            return
        item = self._db_rows[row]
        file_name = str(item.get("file", ""))
        size = maintenance.format_size(int(item.get("size", 0) or 0))
        when = ms_to_str(item.get("mtime"))

        # 默认按钮必须是「否」：这是全项目唯一一个「点错就永久丢数据」的按钮
        if (
            QMessageBox.question(
                self,
                "恢复数据库",
                f"将用这份备份整份覆盖当前数据库：\n{file_name}\n"
                f"大小 {size} · 备份于 {when}\n\n"
                "· 备份之后产生的数据会全部消失（访问记录、风险事件、封禁账本、操作审计）；\n"
                "· 恢复前会自动再备份一次当前库，所以反悔了还能再恢复回来；\n"
                "· 恢复期间数据库短暂不可用，完成后写入器自动重启。\n\n确认恢复？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        self._db_run("restore", lambda: maintenance.restore_db(str(item.get("path", ""))))

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

    # ── 保留期预设 ──
    def _on_retention_preset(self, idx: int) -> None:
        """选了某个档位 → 一次写进四个 SpinBox（保存时才落库）"""
        if self._retention_preset_guard or idx < 0 or idx >= len(RETENTION_PRESETS):
            return  # 「自定义」：保持四项现值，让用户自己调
        days = RETENTION_PRESETS[idx]
        self._retention_preset_guard = True
        try:
            for sp in (
                self.sp_retention,
                self.sp_risk_retention,
                self.sp_ban_retention,
                self.sp_audit_retention,
            ):
                sp.setValue(days)
        finally:
            self._retention_preset_guard = False

    def _sync_retention_combo(self, *_args: int) -> None:
        """四个 SpinBox 的组合值若等于某个档位就回显该档位，否则显示「自定义」

        `*_args` 是给 `valueChanged(int)` 用的：PySide2 对「槽的参数比信号少」
        的处理不如 PySide6 稳定，显式收下再丢掉最省心。
        """
        if getattr(self, "_retention_preset_guard", False):
            return
        values = {
            self.sp_retention.value(),
            self.sp_risk_retention.value(),
            self.sp_ban_retention.value(),
            self.sp_audit_retention.value(),
        }
        custom = len(RETENTION_PRESETS)
        if len(values) == 1:
            only = values.pop()
            if only in RETENTION_PRESETS:
                custom = RETENTION_PRESETS.index(only)
        guard = self._retention_preset_guard
        self._retention_preset_guard = True
        try:
            self.cb_retention.setCurrentIndex(custom)
        finally:
            self._retention_preset_guard = guard

    # ── 外部推送（Webhook）──
    def _on_webhook_toggle(self, on: bool) -> None:
        self.ed_webhook.setEnabled(on)
        self.cb_webhook_level.setEnabled(on)
        self.btn_webhook_test.setEnabled(on)

    def _test_webhook(self) -> None:
        """用**输入框里的地址**立即发一条测试消息（不必先保存）

        发送在后台线程：地址不可达时 urllib 会一直等到超时，界面线程里等就是假死。
        """
        from core import alert_webhook

        url = self.ed_webhook.text().strip()
        ok, why = alert_webhook.validate_url(url)
        if not ok:
            QMessageBox.warning(self, "推送地址不可用", why)
            return
        if getattr(self, "_webhook_testing", False):
            return
        self._webhook_testing = True
        self.btn_webhook_test.setEnabled(False)
        self.btn_webhook_test.setText("发送中…")

        level = LEVEL_ITEMS[max(0, min(self.cb_webhook_level.currentIndex(), len(LEVEL_ITEMS) - 1))]
        alert = {
            "ip": "203.0.113.10",
            "level": level,
            "score": 95,
            "reason": "这是一条测试消息（由用户在设置页手动触发）",
            "local_port": 3389,
            "disposition": "alert",
        }
        payload = alert_webhook.build_payload(alert)

        def work():
            return alert_webhook.post(url, payload)

        run_in_background(
            self,
            work,
            self._on_webhook_test_done,
            self._on_webhook_test_failed,
            name="webhook-test",
        )

    def _on_webhook_test_done(self, res) -> None:
        self._reset_webhook_test_button()
        ok, err = res if isinstance(res, tuple) else (False, "返回格式异常")
        from core import alert_webhook

        if ok:
            QMessageBox.information(
                self,
                "推送成功",
                f"测试消息已送达：\n{alert_webhook.mask_url(self.ed_webhook.text().strip())}",
            )
            return
        QMessageBox.warning(
            self,
            "推送失败",
            f"地址：{alert_webhook.mask_url(self.ed_webhook.text().strip())}\n原因：{err}\n\n"
            "常见原因：地址填错、机器人已停用、本机访问不了外网。",
        )

    def _on_webhook_test_failed(self, err: str) -> None:
        self._reset_webhook_test_button()
        log.error("Webhook 测试推送异常：%s", err)
        QMessageBox.warning(self, "推送失败", "发送时发生异常，详情见运行日志。")

    def _reset_webhook_test_button(self) -> None:
        self._webhook_testing = False
        self.btn_webhook_test.setText("发送测试消息")
        self.btn_webhook_test.setEnabled(self.tg_webhook.isChecked())

    def _clean_logs(self) -> None:
        """
        手动立即清理：四张表 + 磁盘上的过期日志文件。

        四张表走各自的保留期（不是同一个 days）—— 按钮叫「清理过期日志」，
        但漏掉 risk_event / ban_list / audit_log 才是之前真正的缺口：那三张表
        从来没有清理入口，只会在磁盘上一直长。
        """
        rows = maintenance.cleanup_logs()
        risk = maintenance.cleanup_risk()
        bans = maintenance.cleanup_bans()
        n_files = maintenance.cleanup_log_files()
        audit.record(
            audit.ACTION_DATA_CLEANUP,
            target_type="data",
            summary=f"手动清理：访问 {rows}、事件 {risk}、封禁 {bans}、日志文件 {n_files}",
            after={
                "access_log": rows,
                "risk_event": risk,
                "ban_list": bans,
                "log_files": n_files,
            },
        )
        QMessageBox.information(
            self,
            "完成",
            f"已清理访问记录 {rows} 条、风险事件 {risk} 条、终态封禁记录 {bans} 条，"
            f"以及 {n_files} 个过期日志文件。\n\n"
            f"保留期：访问 {self.sp_retention.value()} 天 / "
            f"事件 {self.sp_risk_retention.value()} 天 / "
            f"封禁 {self.sp_ban_retention.value()} 天。\n"
            f"「已封禁」和「处理中」的封禁记录不会被清理。\n\n"
            f"日志文件：{log_file()}",
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
        # 这是全项目破坏性最大的一个按钮，必须留痕：事后唯一能回答
        # 「数据是哪天没的、谁点的」的就是这条记录。
        audit.record(
            audit.ACTION_DATA_CLEAR,
            target_type="data",
            summary="清空全部访问日志与风险事件（封禁列表不受影响）",
        )
        QMessageBox.information(self, "完成", "日志已清空。")
