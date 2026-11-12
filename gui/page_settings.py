"""PortGuard — 设置页

布局依据 _design/02_ux_spec.md：
  · 6 组竖排（约 1780px，要滚 2.4 屏）改成 **4 个胶囊页签** —— 服务与采集 /
    防护与告警 / 数据与离线库 / 操作审计；
  · 标签列固定 128px 右对齐，所有控件左缘落在同一条竖线（P1-5）；
  · 自动封禁警告**只在开关打开时**出现在表单里，不常驻；
  · 「未保存」标记：任一控件改动即在标题区亮起，保存后熄灭（P1-12）。

不改任何判定逻辑与信号契约：btn_xdb_check / tg_xdb_auto / lbl_watch_state
等属性名被 selftest 与主窗口直接引用，全部保留。
"""

import datetime
import json
from typing import Any, ClassVar, List, Optional, Tuple

from app import audit
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
)
from core.logger import get_logger, set_retention
from gui.components import PageHeader, SectionIndex, capsule_tabs
from gui.page_common import (
    _add_section_index as _common_add_section_index,
)
from gui.page_common import (
    _backup_picker as _common_backup_picker,
)
from gui.page_common import (
    _fill_backup_picker as _common_fill_backup_picker,
)
from gui.page_common import (
    _Panel,
    _row_widget,
)
from gui.page_common import (
    _picker_index as _common_picker_index,
)
from gui.page_common import (
    _scroll_page as _common_scroll_page,
)
from gui.page_common import (
    _scroll_to_section as _common_scroll_to_section,
)
from gui.page_common import (
    _sw_label as _common_sw_label,
)
from gui.page_data import DataPage
from gui.page_guard import GuardPage
from gui.settings_audit import AuditPanel
from gui.theme import C
from gui.widgets import ToggleSwitch
from qtcompat import (
    QComboBox,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
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

#: 备份明细改成单行下拉（2026-11-10）：表格嵌在滚动区里，上下拖动时行会被
#: 卡片边缘遮住、也不好点中。下拉只占一行，选中项的完整明细放在下一行文字里。
BACKUP_PICKER_MIN_W = 460

#: 后台任务进行中的提示语（VACUUM 可能几十秒，必须让用户知道程序没死）
DB_TASK_TEXT = {
    "vacuum": "正在整理数据库（VACUUM）…会把整库重写一遍，库越大越久，请勿关闭程序",
    "reindex": "正在重建全部索引…",
    "backup": "正在备份数据库…",
    "restore": "正在恢复数据库…写入器已暂停，期间不会记录新的访问",
}

#: 任务名（拼「✗ xx 失败」用）
DB_TASK_NAME = {"vacuum": "整理数据库", "reindex": "重建索引", "backup": "备份", "restore": "恢复"}


class SettingsPage(QWidget):
    settings_saved = Signal()
    xdb_sync_requested = Signal(bool)  # 立即同步（True=强制重下）
    xdb_check_requested = Signal()  # 只检查
    geo_reload_requested = Signal()  # 不联网、不重启，重新读取本机离线库
    logs_open_requested = Signal()
    watch_changed = Signal()  # 本机端口观察的开关/参数发生变化
    # 数据库维护（VACUUM / 重建索引 / 备份 / 恢复）在后台线程跑，结果同样经信号回主线程
    db_task_done = Signal(object)

    # 「采集通道」下拉项顺序 → 持久化值。索引即下拉序号
    # （0=table, 1=fwlog, 2=fwlog,table），供 _watch_methods_text 反向映射。
    _METHOD_VALUES: ClassVar[List[str]] = ["table", "fwlog", "fwlog,table"]

    def __init__(self, parent=None):
        super().__init__(parent)
        self._loading = True  # load() 期间不点亮「未保存」
        self._dirty = False
        self._hint_timer = QTimer(self)
        self._hint_timer.setSingleShot(True)
        self._hint_timer.timeout.connect(self._reset_hint)
        self._build()
        # db 维护结果经父页信号回主线程（子页发出 `parent.db_task_done`），
        # 子页 `_on_db_task_done` 里 `_reload_cb()` 冒泡到父页 load 全量重载。
        self.db_task_done.connect(self.data_page._on_db_task_done)
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
        head = PageHeader(
            "设置",
            "按「采集与服务 → 防护与告警 → 数据与离线库 → 操作审计」分层，每类下再按分区展开",
        )
        self.lbl_dirty = QLabel("")
        self.lbl_dirty.setVisible(False)
        head.add_action(self.lbl_dirty)

        self.btn_save = QPushButton("保存设置")
        self.btn_save.setObjectName("btn_primary")
        self.btn_save.clicked.connect(self.save)
        head.add_action(self.btn_save)
        outer.addWidget(head)

        # ── 四个 tab ──
        self.tabs = capsule_tabs("设置")
        self.tabs.addTab(self._tab_service(), "服务与采集")
        self.guard_page = GuardPage(self, self._mark_dirty)
        self.tabs.addTab(self.guard_page, "防护与告警")
        self.data_page = DataPage(self, self._mark_dirty, self.load)
        self.tabs.addTab(self.data_page, "数据与离线库")
        self.audit_panel = AuditPanel()
        self.tabs.addTab(self.audit_panel, "操作审计")
        # 审计表只在切到该 tab 时才查：它可能在别的 tab 上被大量写入
        # （封禁 / 保存设置都会记），常驻刷新是白烧 IO。
        self.tabs.currentChanged.connect(self._on_tab_changed)
        outer.addWidget(self.tabs, 1)

    # ── 扁平属性转发：防护与告警 / 数据与离线库 两页自持控件与 handlers ──
    # 主窗 / 测试 / 旧代码仍按 page.tg_auto / page.refresh_xdb_state() 访问，
    # 找不到时统一转发到子页，父页只保留装配 + save/load 生命周期。
    def _subpages(self) -> Tuple["DataPage | None", "GuardPage | None"]:
        """读取已装配的子页实例。

        用 `object.__getattribute__` 而非 `getattr`，避免在子页尚未赋值的
        `__init__` 早期阶段触发 `__getattr__` 造成无限递归。
        """
        try:
            data = object.__getattribute__(self, "data_page")
        except AttributeError:
            data = None
        try:
            guard = object.__getattribute__(self, "guard_page")
        except AttributeError:
            guard = None
        return data, guard

    def __getattr__(self, name: str):
        for page in self._subpages():
            if page is None:
                continue
            try:
                target = getattr(page, name)
            except AttributeError:
                continue
            # methods 与属性都转发；Signal 对象经 getattr 取到的是 class 属性，
            # 原样返回（主窗需要 page.xdb_sync_requested 这个 Signal 类对象）
            return target
        raise AttributeError(f"{type(self).__name__!r} object has no attribute {name!r}")

    def __setattr__(self, name: str, value: Any) -> None:
        """运行期扁平状态（`page._bak_rows = ...` 这类测试 / 主窗写法）落到子页。

        子页已建且持有该名字时才转发；父页自身的生命周期属性（`_dirty` /
        `_loading` / `_hint_timer` …）子页没有同名，仍写本地。

        注意：非转发路径必须走 `super().__setattr__`（shiboken 的 native 路径），
        而不是 `object.__setattr__` —— __init__ 早期 shiboken2(PySide2) 会在
        QWidget subclass 上设置 C++ 持有的 attribute，绕过 native 路径会抛
        `TypeError: can't apply this __setattr__ to ...`（回归 F2）。
        """
        for page in self._subpages():
            if page is not None and hasattr(page, name):
                object.__setattr__(page, name, value)
                return
        super().__setattr__(name, value)

    # ── Tab 1：服务与采集 ──
    def _tab_service(self) -> QWidget:
        page, page_layout = self._scroll_page()
        self._section_service = self._add_section_index(
            page, page_layout, "① 采集与服务", ["本机端口访问观察", "运行与守护"]
        )

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
            "程序没运行，到期的封禁就不会被解除。开启后每次登录以观察模式自动启动"
            "（普通权限、不弹 UAC），启动 1.5 秒内补跑到期巡检与黑名单补封；"
            "需要开机即写防火墙，请用随包的 start-as-admin.bat 配置启动项。"
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
                self.lbl_autostart.setText(
                    "保存后写入登录启动项：登录时以观察模式自动启动（不弹 UAC）"
                )
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

    def _on_tab_changed(self, idx: int) -> None:
        if self.tabs.widget(idx) is self.audit_panel:
            self.audit_panel.refresh_actors()
            self.audit_panel.refresh()
        elif self.tabs.widget(idx) is self.tab_data:
            # 数据库大小会随着运行一直变，切过来时重读一次（不常驻轮询：
            # 每次刷新都要 stat 三个文件 + 列一遍备份目录，白烧 IO）
            self.refresh_db_state()

    # ── 小工具 ──
    @staticmethod
    def _scroll_page() -> Tuple[QScrollArea, QVBoxLayout]:
        """tab 内容容器。实现见 gui.page_common._scroll_page，这里仅转发。"""
        return _common_scroll_page()

    def _add_section_index(
        self, page: QScrollArea, lay: QVBoxLayout, group: str, labels: List[str]
    ) -> SectionIndex:
        """每个 tab 顶部一条二级分区导航，与卡片同宽、同款 QSS。"""
        return _common_add_section_index(page, lay, group, labels)

    @staticmethod
    def _scroll_to_section(page: QScrollArea, lay: QVBoxLayout, i: int) -> None:
        # 第 0 项是导航条自身，分区卡片从 1 开始；卡片在 host 里的 y 就是
        # QScrollArea 的内容坐标，直接交给滚动条即可。
        _common_scroll_to_section(page, lay, i)

    @staticmethod
    def _sw_label(text: str) -> QLabel:
        """开关右侧的小字说明"""
        return _common_sw_label(text)

    @staticmethod
    def _backup_picker() -> QComboBox:
        """两处备份明细共用的单行下拉：不随滚动区跑，也不会被卡片边缘遮住"""
        return _common_backup_picker()

    @staticmethod
    def _fill_backup_picker(cb: QComboBox, labels: List[str]) -> None:
        """重建下拉项并尽量保留当前选择（按显示文本匹配）。"""
        _common_fill_backup_picker(cb, labels)

    @staticmethod
    def _picker_index(cb: QComboBox) -> int:
        return _common_picker_index(cb)

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
        pickers = {
            getattr(self, "cb_bak", None),
            getattr(self, "cb_db_bak", None),
        }
        for cb in self.findChildren(QComboBox):
            # 备份版本选择器不是「设置」：选哪份不改变保存结果，
            # 不该像以前用表格时那样被 _mark_dirty 点亮「未保存」。
            if cb is self.cb_xdb_source or cb in pickers:
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

        # 操作审计：下拉框 + 首屏数据（AuditPanel 构造时已拉过一次 actors，
        # 这里在 load 链路末尾再刷一次，与拆分前行为一致）
        self.audit_panel.refresh_actors()
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
                methods = (cfg.get("watch_methods", "table,fwlog") or "").replace(" ", "")
                if "fwlog" in methods and not win_fwlog.is_dropped_logging_enabled():
                    bits.append(
                        "（防火墙日志未开启：丢弃连接记录未启用，扫描可能漏检，点「启用防火墙日志记录」）"
                    )
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
