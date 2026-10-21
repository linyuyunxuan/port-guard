"""
PortGuard — 主窗口

职责被刻意收窄为「界面组装 + 页面切换 + 信号连线 + 托盘」。
其它逻辑分别落在：
- gui/mixins.py   事件泵 / 统计 / 状态栏（Qt 胶水）
- app/*.py        封禁编排 / 维护 / 离线库同步（不依赖 Qt，可单测）
"""

import contextlib
import threading
from typing import Any, Callable, Dict, List, Optional

from app import audit, ban_service
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
from gui.about_dialog import AboutDialog, ClickableLabel, register_about_shortcut
from gui.components import ShieldMark, TopStatusBar
from gui.mixins import EventPumpMixin
from gui.page_access import AccessPage
from gui.page_bans import BansPage, ManualBanDialog
from gui.page_events import EventsPage
from gui.page_iplookup import IpLookupPage
from gui.page_logs import LogsPage
from gui.page_monitor import MonitorPage
from gui.page_rules import RulesPage
from gui.page_settings import SettingsPage
from gui.theme import GLOBAL_STYLE, C
from gui.widgets import Dot
from qtcompat import (
    QAction,
    QApplication,
    QColor,
    QDialog,
    QDialogButtonBox,
    QFont,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QIcon,
    QKeySequence,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPainter,
    QPixmap,
    QPushButton,
    QShortcut,
    QSpinBox,
    QStackedWidget,
    QStatusBar,
    QSystemTrayIcon,
    Qt,
    QTextEdit,
    QTimer,
    QVBoxLayout,
    QWidget,
    Signal,
)

log = get_logger(__name__)

NAV_ITEMS = [
    ("实时监控", "监控"),
    ("风险事件", "事件"),
    ("历史访问", "访问"),
    ("封禁管理", "封禁"),
    ("规则配置", "规则"),
    ("IP 查询", "查询"),
    ("运行日志", "日志"),
    ("设置", "设置"),
]

# 侧栏分组：(分组标题, [NAV_ITEMS 下标])
# 顺序即导航顺序，也是 Ctrl+1..8 的顺序 —— 只在这里维护一份下标表，
# _build_sidebar / _setup_shortcuts / _switch_page 都从 NAV_ITEMS 取名字。
# ⚠️ 页面栈下标 = NAV_ITEMS 下标（见 _build_ui 的 addWidget 顺序），
# 插入新页时必须同时改 gui/mixins.py 里那几处「当前页」判断。
NAV_GROUPS = [
    ("监控", (0, 1, 2)),
    ("处置", (3,)),
    ("配置", (4, 5, 6, 7)),
]

(
    PAGE_MONITOR,
    PAGE_EVENTS,
    PAGE_ACCESS,
    PAGE_BANS,
    PAGE_RULES,
    PAGE_LOOKUP,
    PAGE_LOGS,
    PAGE_SETTINGS,
) = range(8)


def _make_icon(color: Optional[str] = None, size: int = 64) -> QIcon:
    """生成内置盾牌图标（避免依赖外部资源文件）"""
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setBrush(QColor(color or C.primary))
    p.setPen(Qt.PenStyle.NoPen)
    from qtcompat import QPointF, QPolygonF

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
    """确认封禁对话框（时长由策略建议，用户可覆盖）

    为什么不直接读 `default_ban_duration_sec`：P2-8 起封禁时长是「策略」——
    按风险等级分档，同一 IP 反复被封还会递增。只给一个数字的话，用户改完分档
    设置也看不出有没有生效，所以这里把「建议值 + 为什么是这个值」一起摆出来，
    并允许当场改成别的值（改成 0 = 永久）。
    """

    def __init__(self, ip: str, score: int, reason: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("确认封禁")
        self.setMinimumWidth(420)
        form = QFormLayout(self)
        form.setContentsMargins(18, 18, 18, 12)
        form.setSpacing(10)

        form.addRow("IP 地址", QLabel(ip))
        form.addRow("风险评分", QLabel(str(score)))
        rl = QLabel(reason or "命中风险规则")
        rl.setWordWrap(True)
        form.addRow("封禁原因", rl)

        # 策略建议值。秒数恒 ≥ 1（见 app.ban_service 顶部「语义分界」），
        # 所以这里绝不会因为策略算出 0 而变成「永久」。
        decision = ban_service.resolve_duration_detail(score=score, ip=ip)

        self.sp = QSpinBox()
        self.sp.setRange(0, 365 * 24 * 60)
        self.sp.setSpecialValueText("永久")
        self.sp.setSuffix(" 分钟（0=永久）")
        # 秒 → 分钟**向上取整**：不足 1 分钟的档位若向下取整成 0，就成了永久封禁
        self.sp.setValue(max(1, (decision.seconds + 59) // 60))
        form.addRow("封禁时长", self.sp)

        why_lines = [
            f"策略建议 {ban_service.format_duration(decision.seconds)}"
            f"（{decision.source_label}）：{decision.detail}",
        ]
        # 「已被封过几次」放这里而不是加一列表格列：BAN_WIDTHS 已经排到极限，
        # 多一列就要牺牲 IP / 原因列的完整性；而只有真要封某个人时才关心这个数
        prior = ban_service.prior_ban_count(ip)
        if prior > 0:
            why_lines.append(f"该 IP 历史封禁 {prior} 次（不含本次）。")
        why_lines.append("如不接受，可直接改上面的分钟数；填 0 表示永久封禁。")

        why = QLabel("\n".join(why_lines))
        why.setWordWrap(True)
        why.setStyleSheet(f"color:{C.text_muted};font-size:13.5px;")
        form.addRow(why)

        note = QLabel("将执行 New-NetFirewallRule 创建入站阻止规则（需管理员权限）。")
        note.setStyleSheet(f"color:{C.text_muted};font-size:13.5px;")
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


class BatchBanDialog(QDialog):
    """批量封禁确认。

    为什么单独做一个而不是循环弹单条对话框：一次勾 30 条就要点 30 次确认，
    而「确认」在批量场景里已经退化成机械点击，等于没有确认。
    这里一次性把「封哪些、跳过哪些、为什么跳过、封多久」摆在同一屏，
    只让用户做一次真正的决定。
    """

    def __init__(self, ips: List[str], skipped: List[tuple], parent=None):
        super().__init__(parent)
        self.setWindowTitle("批量封禁确认")
        self.setMinimumWidth(460)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(18, 16, 18, 12)
        lay.setSpacing(10)

        head = QLabel(f"将封禁 {len(ips)} 个 IP（已按 IP 去重）")
        head.setStyleSheet(f"color:{C.text_primary};font-size:14.5px;font-weight:600;")
        lay.addWidget(head)

        box = QTextEdit()
        box.setReadOnly(True)
        box.setFixedHeight(150)
        shown = ips[:80]
        text = "、".join(shown)
        if len(ips) > len(shown):
            text += f" …（还有 {len(ips) - len(shown)} 个）"
        box.setPlainText(text)
        lay.addWidget(box)

        form = QFormLayout()
        form.setContentsMargins(0, 0, 0, 0)
        form.setSpacing(8)
        self.sp = QSpinBox()
        self.sp.setRange(0, 365 * 24 * 60)
        self.sp.setValue(max(1, cfg.get_int("default_ban_duration_sec", 3600) // 60))
        self.sp.setSpecialValueText("永久")
        self.sp.setSuffix(" 分钟（0=永久）")
        form.addRow("封禁时长", self.sp)
        lay.addLayout(form)

        if skipped:
            reasons = "；".join(f"{ip}（{why}）" for ip, why in skipped[:5])
            if len(skipped) > 5:
                reasons += f" 等 {len(skipped)} 个"
            note = QLabel(f"已自动跳过：{reasons}")
            note.setWordWrap(True)
            note.setStyleSheet(f"color:{C.warning};font-size:13.5px;")
            lay.addWidget(note)

        tip = QLabel(
            "将逐个执行 New-NetFirewallRule（需管理员权限），IP 较多时可能需要几十秒；"
            "过程中可继续操作界面，结果会写进运行日志与封禁管理。"
        )
        tip.setWordWrap(True)
        tip.setStyleSheet(f"color:{C.text_muted};font-size:13.5px;")
        lay.addWidget(tip)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.button(QDialogButtonBox.StandardButton.Ok).setText(f"确认封禁 {len(ips)} 个")
        btns.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

    def duration_sec(self) -> int:
        m = self.sp.value()
        return 0 if m == 0 else m * 60


class MainWindow(EventPumpMixin, QMainWindow):
    # 批量封禁在后台线程跑，结束后用信号把结果送回 GUI 线程
    # （直接在工作线程里改状态栏是跨线程操作控件，Qt 会随机崩）
    batch_ban_done = Signal(int, int)  # (成功数, 失败数)
    # 黑名单 → 防火墙联动的结果（写规则慢，必须后台跑完再回主线程提示）
    blacklist_sync_done = Signal(object)

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_TITLE}  v{APP_VERSION}")
        self.setMinimumSize(1240, 720)
        self.resize(1440, 900)
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
        self._maybe_start_watcher_on_launch()

        # 启动后延迟做一次离线库检查（后台线程，不阻塞界面）
        QTimer.singleShot(3000, lambda: self._maybe_sync_xdb(first_run=True))

        self._init_permission_hint()

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

        # 内容列 = 顶部状态条（44，持久健康态）+ 页面栈。
        # 健康态从前压在 26px 状态栏右端（等于没有），现在独立成一条（P0-8）。
        content = QWidget()
        col = QVBoxLayout(content)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(0)

        self.topbar = TopStatusBar()
        self.si_watch = self.topbar.add_item("本机观察")
        self.si_admin = self.topbar.add_item("权限")
        self.si_watch.set_state("本机观察 未启动", C.text_muted)
        self.si_admin.set_state("权限 检测中…", C.text_muted)
        # 只有「观察」可点（跳设置页），「权限」点不动 —— 权限无法在程序内提升，
        # 可点却不办事比不可点更糟，所以不给它手型光标与 tooltip。
        self.si_watch.setCursor(Qt.CursorShape.PointingHandCursor)
        self.si_watch.setToolTip("打开设置页")
        self.si_watch.clicked.connect(self._goto_settings)
        col.addWidget(self.topbar)

        self.stack = QStackedWidget()
        col.addWidget(self.stack, 1)
        root.addWidget(content, 1)

        # addWidget 的顺序必须与 NAV_ITEMS 一致：栈下标就是导航下标
        self.page_monitor = MonitorPage()
        self.page_events = EventsPage()
        self.page_access = AccessPage()
        self.page_bans = BansPage()
        self.page_rules = RulesPage()
        self.page_iplookup = IpLookupPage()
        self.page_logs = LogsPage()
        self.page_settings = SettingsPage()
        for p in (
            self.page_monitor,
            self.page_events,
            self.page_access,
            self.page_bans,
            self.page_rules,
            self.page_iplookup,
            self.page_logs,
            self.page_settings,
        ):
            self.stack.addWidget(p)

        # 底部状态栏只留「左瞬时消息 + 右 IP 库 / 定位库」：
        # 服务与观察的运行态已上移到顶部状态条，不再重复（P0-8）。
        sb = QStatusBar()
        sb.setSizeGripEnabled(False)
        sb.setFixedHeight(30)
        self.setStatusBar(sb)
        self.lbl_status = QLabel("正在初始化…")
        self.lbl_status.setStyleSheet(f"color:{C.text_secondary};font-size:12.5px;")
        # QSS 的 QStatusBar padding 不会作用到 permanent widget 的几何上，
        # 不补内缩时左右文字会贴到窗口边缘（实测左侧 x=2、右侧贴 1360）
        self.lbl_status.setContentsMargins(6, 0, 0, 0)
        self.lbl_geo = QLabel("定位库 加载中")
        self.lbl_geo.setStyleSheet(f"color:{C.text_muted};font-size:12.5px;")
        self.lbl_xdb = QLabel("IP 库 —")
        self.lbl_xdb.setStyleSheet(f"color:{C.text_muted};font-size:12.5px;")
        sb.addWidget(self.lbl_status, 1)
        for w in (self._status_sep(), self.lbl_xdb, self._status_sep(), self.lbl_geo):
            sb.addPermanentWidget(w)
        sb.addPermanentWidget(self._status_spacer(8))

        self._setup_shortcuts()

    @staticmethod
    def _status_spacer(width: int) -> QWidget:
        """状态栏边缘留白（permanent widget 不吃 QSS 的 padding）"""
        sp = QWidget()
        sp.setFixedWidth(width)
        return sp

    @staticmethod
    def _status_sep() -> QFrame:
        """状态栏右侧各组之间的 1px 竖线"""
        sep = QFrame()
        sep.setFixedWidth(1)
        sep.setFixedHeight(14)
        sep.setStyleSheet(f"background:{C.border_light};border:none;")
        return sep

    def _build_sidebar(self) -> QFrame:
        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(200)
        sl = QVBoxLayout(self.sidebar)
        sl.setContentsMargins(0, 0, 0, 0)
        sl.setSpacing(0)

        # ── 品牌区（高 64）：自绘盾牌 + 竖排两行 ──
        brand = QWidget()
        brand.setObjectName("sidebar_brand")
        brand.setFixedHeight(68)
        bl = QHBoxLayout(brand)
        bl.setContentsMargins(16, 0, 16, 0)
        bl.setSpacing(8)
        bl.addWidget(ShieldMark(20), 0, Qt.AlignmentFlag.AlignVCenter)

        # 两行文字用「上 stretch + 两行 + 下 stretch」在自己的竖排里居中：
        # QLabel 的纵向 policy 是 Preferred（可扩展），若只把它们塞进 QVBoxLayout，
        # 布局会把 64px 余量分给标签，文字贴顶 → 出现「盾牌偏低、文字偏高」
        # （视觉走查实测：盾牌中心 32、主名中心 9.5，偏差 22.5px）。
        names = QVBoxLayout()
        names.setContentsMargins(0, 0, 0, 0)
        names.setSpacing(0)
        names.addStretch(1)
        logo = QLabel("PortGuard")
        logo.setObjectName("sidebar_logo")
        sub = QLabel("端口访问防御工具")
        sub.setObjectName("sidebar_sub")
        names.addWidget(logo)
        names.addWidget(sub)
        names.addStretch(1)
        bl.addLayout(names)
        bl.addStretch(1)
        sl.addWidget(brand)
        sl.addSpacing(8)

        # ── 导航（分组标题 28 + 导航项 38）──
        # 槽一律走 _nav_slot() 工厂：带默认参数的 lambda 在 PySide2 上按 0 参调用，
        # 点击会静默失效（见 _nav_slot 文档）。
        self.nav_buttons: List[QPushButton] = []
        for group, indexes in NAV_GROUPS:
            # 分组标题上留 12px：否则 11px 的标题与 13px 的导航项视觉同级，
            # 7 个导航会被读成「8 个平级项」（视觉走查结论）。
            sl.addSpacing(12)
            gl = QLabel(group)
            gl.setObjectName("nav_group")
            gl.setFixedHeight(30)
            sl.addWidget(gl)
            for idx in indexes:
                name = NAV_ITEMS[idx][0]
                btn = QPushButton(name)
                btn.setObjectName("nav_btn")
                btn.setCheckable(True)
                btn.setCursor(Qt.CursorShape.PointingHandCursor)
                btn.setToolTip(f"{name}（Ctrl+{idx + 1}）")
                btn.clicked.connect(self._nav_slot(idx))
                sl.addWidget(btn)
                self.nav_buttons.append(btn)
        self.nav_buttons[0].setChecked(True)

        sl.addStretch(1)

        # ── 底部：已封禁 N（圆点承担语义）+ 版本 ──
        fsep = QFrame()
        fsep.setObjectName("sidebar_sep")
        fsep.setFixedHeight(1)
        sl.addWidget(fsep)

        ban_row = QWidget()
        brl = QHBoxLayout(ban_row)
        brl.setContentsMargins(16, 10, 16, 10)
        brl.setSpacing(8)
        self.ban_dot = Dot(C.success, 6)
        self.lbl_ban_count = QLabel("已封禁 0")
        self.lbl_ban_count.setObjectName("sidebar_ban")
        brl.addWidget(self.ban_dot, 0, Qt.AlignmentFlag.AlignVCenter)
        brl.addWidget(self.lbl_ban_count, 0, Qt.AlignmentFlag.AlignVCenter)
        brl.addStretch(1)
        sl.addWidget(ban_row)

        # 底部版本号 = 「关于 / 快捷键帮助」的入口之一。
        # 侧栏底部是全程序唯一还留着版本信息的地方，让它可点，
        # 用户不必再去托盘里找；QLabel 没有 clicked 信号，用子类（见 ClickableLabel）。
        self.lbl_version = ClickableLabel(f"v{APP_VERSION} · ip2region")
        self.lbl_version.setObjectName("sidebar_footer")
        self.lbl_version.setContentsMargins(16, 0, 16, 12)
        self.lbl_version.setCursor(Qt.CursorShape.PointingHandCursor)
        self.lbl_version.setToolTip("关于 PortGuard / 快捷键帮助（F1）")
        self.lbl_version.clicked.connect(self._show_about)
        sl.addWidget(self.lbl_version)
        return self.sidebar

    def _setup_shortcuts(self) -> None:
        """Ctrl+1…8 切页（与侧栏顺序一致，导航项 tooltip 已标出）+ F1 关于/帮助"""
        self._shortcuts: List[QShortcut] = []
        for idx in range(len(NAV_ITEMS)):
            sc = QShortcut(QKeySequence(f"Ctrl+{idx + 1}"), self)
            sc.setContext(Qt.ShortcutContext.ApplicationShortcut)
            sc.activated.connect(self._nav_slot(idx))
            self._shortcuts.append(sc)
        # F1：QShortcut 在 Qt5 属于 QtWidgets、Qt6 属于 QtGui，
        # 统一由 gui.about_dialog.register_about_shortcut 从 qtcompat 取。
        self._sc_help = register_about_shortcut(self)
        self._sc_help.activated.connect(self._show_about)

    def _show_about(self) -> None:
        """关于 / 快捷键帮助：侧栏版本号、托盘菜单、F1 三个入口共用这一种实现"""
        AboutDialog(NAV_ITEMS, self).exec()

    def _goto_settings(self) -> None:
        self._switch_page(PAGE_SETTINGS)

    # ═══════════════════════════════════════════════
    #  顶部状态条（由 mixins 驱动）
    # ═══════════════════════════════════════════════

    def _set_watch_state(self, text: str, color: str) -> None:
        self.si_watch.set_state(text, color)

    def _set_admin_state(self) -> None:
        if self._is_admin():
            self.si_admin.set_state("权限 管理员", C.success)
        else:
            self.si_admin.set_state("权限 普通权限", C.warning)

    def _set_ban_count(self, n: int) -> None:
        """侧栏「已封禁 N」：语义交给 6px 圆点（有数 danger / 0 时 success），
        文字保持 12/600 text_secondary —— 不再常亮红字（P2-1）。"""
        self.lbl_ban_count.setText(f"已封禁 {n}")
        self.ban_dot.set_color(C.danger if n > 0 else C.success)

    def _nav_slot(self, idx: int) -> Callable[..., None]:
        """导航按钮槽工厂。

        ⚠️ 不要改成 `lambda _, i=idx: self._switch_page(i)` 这种**带默认参数的
        lambda**：PySide2（shiboken2）会把它按 **0 参**调用，点击即抛
        `TypeError: <lambda>() missing 1 required positional argument: '_'`，
        且窗口化运行中该错误只写进 stderr、界面毫无反应 —— 交付线
        （Server 2008 R2）整个左侧导航会全部失灵，此前的测试全绿是因为
        selftest 只调 `_switch_page()` 从未真正点击过按钮。
        带默认参数的 def 槽在 PySide2 / PySide6 两条栈上均验证过
        （0 参或 1 参调用都正常）；回归锁见 selftest「导航按钮点击可切页」。
        """

        def slot(_checked: bool = False) -> None:
            self._switch_page(idx)

        return slot

    def _switch_page(self, idx: int) -> None:
        self.stack.setCurrentIndex(idx)
        for i, b in enumerate(self.nav_buttons):
            b.setChecked(i == idx)
        if idx == PAGE_EVENTS:
            self.page_events.refresh()
        elif idx == PAGE_ACCESS:
            self.page_access.refresh()
        elif idx == PAGE_BANS:
            self.page_bans.refresh()
        elif idx == PAGE_LOOKUP:
            self.page_iplookup._update_lib_info()
        elif idx == PAGE_SETTINGS:
            self.page_settings.refresh_xdb_state()
        # PAGE_LOGS 无需特殊处理：QStackedWidget 切页时会触发 showEvent，
        # 日志页在那里自己完成「铺底 + 重绘」

    # ═══════════════════════════════════════════════
    #  托盘
    # ═══════════════════════════════════════════════

    def _setup_tray(self) -> None:
        self.tray = QSystemTrayIcon(self._app_icon, self)
        self.tray.setToolTip(f"{APP_TITLE} v{APP_VERSION}")
        menu = QMenu()
        a_show = QAction("显示主窗口", self)
        a_show.triggered.connect(self._show_window)
        a_sync = QAction("立即同步离线 IP 库", self)
        a_sync.triggered.connect(lambda: self._sync_xdb_now(force=False))
        a_about = QAction("关于", self)
        a_about.triggered.connect(self._show_about)
        a_quit = QAction("退出", self)
        a_quit.triggered.connect(self._quit)
        menu.addAction(a_show)
        menu.addSeparator()
        menu.addAction(a_sync)
        menu.addSeparator()
        menu.addAction(a_about)
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
        self.page_events.ask_ban_many.connect(self.request_ban_many)
        self.page_access.ask_ban.connect(self.request_ban)
        self.page_access.ask_lookup.connect(self._goto_lookup)
        self.page_bans.ask_ban.connect(self.request_ban)
        self.page_bans.ask_ban_many.connect(self.request_ban_many)
        self.page_bans.ask_lookup.connect(self._goto_lookup)
        self.page_monitor.ask_settings.connect(self._goto_settings)
        self.page_bans.request_refresh_stats.connect(lambda: self._refresh_stats(force=True))
        self.page_rules.rules_saved.connect(self._on_rules_saved)
        self.page_settings.settings_saved.connect(self._on_settings_saved)
        self.page_settings.xdb_sync_requested.connect(self._sync_xdb_now)
        self.page_settings.xdb_check_requested.connect(self._check_xdb_now)
        self.page_settings.logs_open_requested.connect(self._open_logs_dir)
        self.page_settings.watch_changed.connect(self._on_watch_changed)
        self.batch_ban_done.connect(self._on_batch_ban_done)
        self.blacklist_sync_done.connect(self._on_blacklist_sync_done)
        self.page_logs.logs_open_requested.connect(self._open_logs_dir)
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
                f"将 {ip} 加入黑名单，并**立即在 Windows 防火墙拦截**该 IP 的所有入站访问"
                "（永久，直到移出黑名单）。\n\n继续？",
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
            audit.record(
                audit.ACTION_LIST_SAVE,
                target_type="blacklist",
                target_id=ip,
                summary=f"加入黑名单失败：{e}",
                result=audit.RESULT_FAIL,
                detail=str(e),
            )
            QMessageBox.warning(self, "保存失败", str(e))
            return
        # 这是「右键顺手加黑」的捷径入口，与设置页规则页的文本框保存是两条路径；
        # 不记的话，「这个 IP 什么时候被谁拉黑的」会出现查不到的空档。
        # target_type 用 blacklist 而不是 list：这里只动黑名单，没碰白名单。
        audit.record(
            audit.ACTION_LIST_SAVE,
            target_type="blacklist",
            target_id=ip,
            summary=f"右键加入黑名单：{ip}",
            before={"in_blacklist": False},
            after={"in_blacklist": True, "blacklist_size": len(eng.blacklist)},
        )
        self.page_rules.reload()
        self._set_status(f"已把 {ip} 加入黑名单", C.success)
        # 名单只是「意图」，拦截必须落到防火墙：名单保存后立刻封禁（后台线程，
        # 写规则可能要几秒）。非管理员时会被明确告知「未实际拦截」，不假成功。
        self._sync_blacklist_bans([ip], [])

    def _sync_blacklist_bans(self, added, removed) -> None:
        """把黑名单变更落到防火墙（后台线程 → 信号回主线程）。"""

        def work():
            from app import blacklist_service

            try:
                res = blacklist_service.apply_changes(added, removed)
            except Exception as e:
                log.exception("黑名单联动封禁失败")
                res = {"admin": False, "failed": [(ip, str(e)) for ip in added]}
            self.blacklist_sync_done.emit(res)

        threading.Thread(target=work, daemon=True, name="blacklist-sync").start()

    def _on_blacklist_sync_done(self, res) -> None:
        from app import blacklist_service

        self._refresh_stats(force=True)
        with contextlib.suppress(Exception):
            self.page_bans.refresh()
        summary = blacklist_service.format_summary(res)
        if res.get("admin") and not res.get("failed") and not res.get("unban_failed"):
            self._set_status(summary, C.success)
            return
        self._set_status(summary, C.warning)
        QMessageBox.warning(
            self,
            "黑名单未完全生效",
            summary + "\n\n" + blacklist_service.format_detail(res),
        )

    def _on_rules_saved(self) -> None:
        self._set_status("规则配置已更新并生效", C.success)

    def _on_settings_saved(self) -> None:
        self._set_status("设置已保存（部分改动需重启服务）", C.success)
        self._refresh_watch_label()

    # ═══════════════════════════════════════════════
    #  本机端口访问观察
    # ═══════════════════════════════════════════════

    def _maybe_start_watcher_on_launch(self) -> None:
        """设置里打开了「启用本机观察」就随程序自动开始采集"""
        try:
            from core import port_watcher

            if not cfg.get_bool("watch_enabled", False):
                self._refresh_watch_label()
                return
            c = port_watcher.WatchConfig.from_settings()
            if not c.ports:
                log.warning("已开启本机观察但没有配置合法端口，跳过自动启动")
                self._refresh_watch_label()
                return
            port_watcher.get_watcher().update_config(c, restart=False)
            port_watcher.start_watcher()
            self._set_status(
                f"本机端口观察已启动，正在观察 {len(c.ports)} 个端口",
                C.success,
            )
        except Exception:
            log.exception("自动启动本机端口观察失败")
        self._refresh_watch_label()

    def _on_watch_changed(self) -> None:
        self._refresh_watch_label()
        self.page_settings._refresh_watch_state()

    def _refresh_watch_label(self) -> None:
        """顶部状态条上的「本机观察」指示（由统计定时器周期调用）"""
        try:
            from core import port_watcher

            st = port_watcher.get_watcher().stats()
            if st.get("running"):
                self._set_watch_state(
                    f"本机观察 {len(st.get('ports') or [])} 端口",
                    C.success,
                )
            else:
                self._set_watch_state("本机观察 未启动", C.text_muted)
        except Exception:
            log.debug("刷新本机观察状态失败", exc_info=True)

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
            # 文案只留「已加载」：缓存条数是内部字段，露在 26px 状态栏里既挤又难懂，
            # 收到 tooltip 里（视觉走查：定位库：已加载 v0（缓存 0）读起来像异常）
            self.lbl_geo.setText("定位库 已加载")
            self.lbl_geo.setStyleSheet(f"color:{C.success};font-size:12.5px;")
            self.lbl_geo.setToolTip(f"离线定位库 v{gen} · 缓存 {ci.get('size', 0)} 条")
        else:
            self.lbl_geo.setText("定位库 不可用")
            self.lbl_geo.setStyleSheet(f"color:{C.danger};font-size:12.5px;")
            self.lbl_geo.setToolTip(f"定位库加载失败：{err}")
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

    def request_ban_many(self, items: List[Dict[str, Any]]) -> None:
        """批量封禁入口（风险事件页「一键封禁」）。

        流程与单条封禁一致，区别只在「确认」与「执行」被批量化：
        校验逐条做（唯一校验入口不能绕），确认只做一次，执行放在同一个
        后台线程里串行跑 —— 每个 IP 起一个线程会让 30 个 PowerShell 进程
        同时抢 CPU，反而更慢、也更容易触发杀软拦截。
        """
        if not items:
            return

        if not firewall.is_admin():
            if (
                QMessageBox.question(
                    self,
                    "权限不足",
                    f"批量封禁 {len(items)} 个 IP 需要管理员权限。\n\n是否以管理员身份重启程序？",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                )
                == QMessageBox.StandardButton.Yes
            ):
                self._restart_as_admin()
            return

        prepared = []
        skipped: List[tuple] = []
        for it in items:
            ip = str(it.get("ip") or "")
            try:
                rec = ban_service.prepare(
                    ip, int(it.get("score") or 0), str(it.get("reason") or ""), 0
                )
            except ban_service.BanError as e:
                skipped.append((ip or "?", str(e)))
                continue
            try:
                if find_active_ban_by_ip(rec.ip) is not None:
                    skipped.append((rec.ip, "已在封禁中"))
                    continue
            except Exception:
                log.exception("批量封禁：查询已有封禁失败 ip=%s", rec.ip)
            prepared.append(rec)

        if not prepared:
            detail = "\n".join(f"· {ip}：{why}" for ip, why in skipped[:10])
            QMessageBox.information(
                self,
                "无需封禁",
                "选中的 IP 全部被跳过：\n\n" + detail if detail else "没有可封禁的 IP。",
            )
            return

        dlg = BatchBanDialog([rec.ip for rec in prepared], skipped, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        duration = dlg.duration_sec()
        self._set_status(f"正在批量封禁 {len(prepared)} 个 IP …", C.warning)

        def work():
            ok = 0
            fail = 0
            # 事件状态不在这里回填：`ban_service.execute` 成功时已按 IP 把该 IP
            # 下所有「未处理」事件标成「已确认」，且是在投递封禁事件**之前**做的，
            # 所以界面收到结果时刷新到的就是最终状态。
            for rec in prepared:
                ban_id, err = ban_service.execute(
                    rec.ip, int(rec.risk_score or 0), rec.reason or "", duration
                )
                if ban_id is None:
                    fail += 1
                    # 前置校验失败不会走 ban_service 的事件投递，这里补一条，
                    # 否则界面上只会看到「正在批量封禁」，永远等不到结果
                    bus.emit_ban(
                        {
                            "ip": rec.ip,
                            "ok": False,
                            "rule_name": "",
                            "error": err,
                            "ban_id": None,
                            "source": "manual",
                        }
                    )
                else:
                    ok += 1
            self.batch_ban_done.emit(ok, fail)

        threading.Thread(target=work, daemon=True, name="ban-batch").start()

    def _on_batch_ban_done(self, ok: int, fail: int) -> None:
        if fail:
            self._set_status(
                f"批量封禁完成：成功 {ok} 个，失败 {fail} 个（详见运行日志）", C.warning
            )
        else:
            self._set_status(f"批量封禁完成：{ok} 个 IP 已封禁", C.success)
        # 状态栏改完必须把**当前页**重刷一遍：封禁顺带改了事件的处理状态与
        # 行内按钮的「已封禁」态，不刷新的话用户看到的还是封禁前的快照，
        # 会以为一键封禁没生效（这正是「状态不跟操作联动」的主诉）。
        self._refresh_current_page()

    def _refresh_current_page(self) -> None:
        """只重刷当前可见页 —— 隐藏页在切回来时本来就会 refresh（见 `_switch_page`）"""
        cur = self.stack.currentWidget()
        if cur is self.page_events:
            self.page_events.refresh()
        elif cur is self.page_bans:
            self.page_bans.refresh()
        elif cur is self.page_access:
            self.page_access.refresh()
        self._refresh_stats(force=True)

    def _restart_as_admin(self) -> None:
        ok, err = firewall.open_admin_restart()
        if ok:
            app = QApplication.instance()
            if app is not None:
                app.quit()
        else:
            QMessageBox.warning(self, "提权失败", f"{err}\n\n请手动右键程序 → 以管理员身份运行。")

    # ═══════════════════════════════════════════════
    #  启动提示
    # ═══════════════════════════════════════════════

    def _init_permission_hint(self) -> None:
        """启动时提示一次权限状态（封禁能力完全取决于它）"""
        if not firewall.is_admin():
            self._set_status("提示：以管理员身份运行才能执行封禁", C.warning)
        else:
            self._set_status("已以管理员身份运行，封禁功能可用", C.success)
        # 顶部状态条的「权限」项：启动时同步一次，之后不再变（提权需重启）
        self._set_admin_state()

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
                "程序已最小化到系统托盘，本机端口观察继续工作。",
                QSystemTrayIcon.MessageIcon.Information,
                3000,
            )
            return
        self._shutdown()
        event.accept()

    def _shutdown(self) -> None:
        log.info("PortGuard 退出：正在停止后台服务与批量写入器")
        try:
            from core import port_watcher

            port_watcher.stop_watcher()
        except Exception:
            log.exception("停止本机端口观察器失败")
        try:
            self.page_logs.shutdown()
        except Exception:
            log.exception("停止日志页定时器失败")
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
