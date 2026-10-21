"""
PortGuard — 关于页 / 快捷键帮助

**为什么是对话框而不是第 9 个导航页**：

· 导航结构刚稳定下来 —— `NAV_GROUPS` 的下标表、`PAGE_* = range(8)`、
  页面栈 addWidget 的顺序、`_setup_shortcuts` 的 Ctrl+1..8 四处互相对应，
  再插一项要同时改四份，而「关于」只是低频只读信息，收益配不上这个风险；
· 关于信息本来就该是弹窗（用户是在「想知道版本号」时按 F1，不是要去某个页面浏览）；
· 快捷键帮助更是天然的弹窗 —— 它要能随时呼出，而不是先跳到某个页。

**数据来源一律从代码取，不手写**：版本读 `core.config.APP_VERSION`、
Qt 绑定读 `qtcompat.BINDING_DESC`、路径读 `core.config` / `core.logger`、
快捷键列表由 `NAV_ITEMS` 动态生成 —— 手写的话以后加一个导航项，
帮助里就会少一行（Ctrl+9 悄悄不可用），而评审时看不出来。

**双栈**：Qt5 的 `QShortcut` 在 QtWidgets、Qt6 在 QtGui，本项目统一从
`qtcompat` 取（见 `register_about_shortcut`）。`QKeySequence` 用字符串构造，
与现有 Ctrl+1..8 的写法保持一致，不碰 StandardKey 枚举。
"""

import platform
import sys
from typing import List, Optional, Tuple

from core.config import APP_NAME, APP_TITLE, APP_VERSION, db_path, user_data_dir
from core.geo_locator import get_locator
from core.logger import log_file
from core.models import ms_to_str
from gui.components import ShieldMark
from gui.theme import C
from gui.widgets import align_headers
from qtcompat import (
    BINDING_DESC,
    QAbstractItemView,
    QApplication,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QKeySequence,
    QLabel,
    QPushButton,
    QScrollArea,
    QShortcut,
    QSizePolicy,
    Qt,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    Signal,
)

#: 帮助 / 关于页的全局快捷键
HELP_SHORTCUT_KEY = "F1"

#: 信息面板的标签列宽（与设置页面板对齐，控件左缘才落在同一条竖线上）
_LABEL_W = 96

#: 快捷键表格行高（两栈一致，避免 Qt5/Qt6 度量差异导致高度飘）
_ROW_H = 30

#: 表头高度下限。`horizontalHeader().sizeHint()` 在「还没上屏 / 样式表还没 polish」
#: 时只有 16px，套上 GLOBAL_STYLE 后才是 36px —— 用 16 算出来的表格高度
#: 正好少一行，F1 那条会被压到滚动条下面（离屏截图实测）。
_HEADER_H = 36


# ═══════════════════════════════════════════════════════════
#  可复用的小控件
# ═══════════════════════════════════════════════════════════


class ClickableLabel(QLabel):
    """可点击的 `QLabel`（侧栏底部版本号用）。

    QLabel 没有 `clicked` 信号，而侧栏底部那行「v1.2.0 · ip2region」是
    全程序唯一还留着版本信息的地方 —— 让它可点，用户不必再去托盘里找入口。

    ⚠️ 必须靠子类重写虚拟函数，不能实例级打补丁（`w.mouseReleaseEvent = ...`）：
    PySide 的 shiboken 不会因此改变 C++ 侧的事件分发（同 `gui.components.ClickableStatusItem`）。
    """

    clicked = Signal()

    def mouseReleaseEvent(self, e) -> None:
        if e.button() == Qt.MouseButton.LeftButton and self.isEnabled():
            self.clicked.emit()
        super().mouseReleaseEvent(e)


def register_about_shortcut(parent: QWidget) -> QShortcut:
    """
    把 `F1` 绑成「打开关于 / 快捷键帮助」，返回已注册的 QShortcut（激活信号由调用方接）。

    `QShortcut` 在 Qt6 属于 QtGui、在 Qt5 属于 QtWidgets —— 这里只从 `qtcompat` 取，
    直接 `from PySide6.QtGui import QShortcut` 会在交付栈（PySide2）上 import 即炸。
    """
    sc = QShortcut(QKeySequence(HELP_SHORTCUT_KEY), parent)
    sc.setContext(Qt.ShortcutContext.ApplicationShortcut)
    return sc


def build_shortcut_rows(nav_items: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """
    快捷键帮助的表格内容：`[(按键, 说明), ...]`。

    切页那几条**由导航项动态生成**：写死成 8 行的话，以后往导航里加一页，
    Ctrl+9 就是「能用但帮助里没写」，而代码评审时看不出来。

    ⚠️ 导航项由**调用方传入**，本模块不 import `gui.main_window`：
    `main_window` 会 import 本模块（三个入口都在它身上），反向 import 即成环；
    即便用函数内延迟导入绕开成环，也会把「关于页」和 8 个页面模块的 import
    链绑在一起 —— 任一页面模块 import 失败，关于页就打不开，而它跟那些页面毫无关系。
    """
    rows = [(f"Ctrl+{i + 1}", f"切换到「{item[0]}」") for i, item in enumerate(nav_items)]
    rows.append((HELP_SHORTCUT_KEY, "打开「关于 / 快捷键帮助」"))
    return rows


# ═══════════════════════════════════════════════════════════
#  纯数据：供界面与「复制」共用一套口径
# ═══════════════════════════════════════════════════════════


def python_text() -> str:
    """Python 版本 + 位数（排障时第一个被问到的就是它）"""
    bits = "64" if sys.maxsize > 2**32 else "32"
    return f"{platform.python_version()}（{bits} 位）"


def os_text() -> str:
    return f"{platform.system()} {platform.release()}（{platform.machine()}）"


def run_mode_text() -> str:
    return "打包 exe" if getattr(sys, "frozen", False) else "源码运行"


def library_text() -> str:
    """离线 IP 库当前生效的文件与同步时间（读不到时降级，不能让关于页打不开）"""
    try:
        info = get_locator().library_info()
    except Exception:
        return "不可用"
    man = info.get("manifest") or {}
    files = man.get("files") or {}
    parts: List[str] = []
    for key, fi in (("v4", info.get("v4") or {}), ("v6", info.get("v6") or {})):
        size = int(fi.get("size") or 0)
        parts.append(f"{key} {size / 1048576:.1f}MB" if size else f"{key} 缺失")
    synced = 0
    for name in ("ip2region_v4.xdb", "ip2region_v6.xdb"):
        synced = int((files.get(name) or {}).get("updated_at") or 0)
        if synced:
            break
    parts.append(f"同步于 {ms_to_str(synced)}" if synced else "随程序内置")
    return " · ".join(parts)


def about_summary_text() -> str:
    """「复制版本信息」的内容：纯文本，可直接贴进工单 / 对话窗口"""
    return "\n".join(
        [
            f"{APP_TITLE}",
            f"版本        : v{APP_VERSION}",
            f"图形界面    : {BINDING_DESC}",
            f"Python      : {python_text()}",
            f"操作系统    : {os_text()}",
            f"运行方式    : {run_mode_text()}",
            f"数据目录    : {user_data_dir()}",
            f"数据库      : {db_path()}",
            f"日志文件    : {log_file()}",
            f"离线 IP 库  : {library_text()}",
        ]
    )


def collect_diag_text() -> Tuple[str, str]:
    """
    环境自诊断全文：复用 `core.diag`（与命令行 `--diag` 完全一致的输出），
    返回 `(报告全文, 结论摘要)`。

    延迟导入 diag：它带着 PE 解析那套依赖，GUI 启动时没必要加载。
    诊断自己出错时也要给出可复制的文本 —— 用户正等着贴给支持方。
    """
    try:
        from core import diag

        code, report, summary = diag.run()
    except Exception as e:  # pragma: no cover - 仅在诊断模块本身故障时走到
        return (about_summary_text() + f"\n\n诊断执行失败：{e}"), f"诊断执行失败：{e}"
    return report, (summary or ("未发现阻塞性问题" if code == 0 else "发现阻塞性问题"))


# ═══════════════════════════════════════════════════════════
#  对话框
# ═══════════════════════════════════════════════════════════


def _scroll_page() -> Tuple[QScrollArea, QVBoxLayout]:
    """Tab 内容容器：内容比对话框高时出现滚动条，而不是把标签压扁。

    与 `gui/page_settings.py` 的 `_scroll_page` 同形。**不复用**那边的函数：
    关于页不该依赖设置页 —— 设置页一旦 import 失败，关于页就打不开，
    而两者毫无关系（这条在 `build_shortcut_rows` 的注释里也踩过一次）。

    为什么非滚动不可：本页有 9 行路径/版本信息，其中数据目录那条在 1280 宽的
    屏幕上要折成 3 行。QVBoxLayout 空间不够时的做法是**把所有子控件一起压到
    最小**——离屏量测过，`程序版本` 只剩 10px（需要 13）、数据目录只剩 14px
    （需要 42），文字被裁掉一半。滚动条是比裁字更好的失败方式。
    """
    area = QScrollArea()
    area.setWidgetResizable(True)
    area.setFrameShape(QFrame.Shape.NoFrame)
    # 只允许竖向滚动：横向能滚意味着内容比对话框宽，那种情况下右半边永远在视野外
    area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
    area.setStyleSheet(
        "QScrollArea{background:transparent;}QWidget#about_host{background:transparent;}"
    )
    host = QWidget()
    host.setObjectName("about_host")
    lay = QVBoxLayout(host)
    lay.setContentsMargins(2, 6, 8, 2)
    lay.setSpacing(10)
    area.setWidget(host)
    return area, lay


class _InfoPanel(QFrame):
    """只读信息面板：标题 + 固定宽标签列的两列网格（与设置页面板同形）。

    值一律 `mono_hint` + `TextSelectableByMouse`：这些是路径/版本号，
    用户多半是要复制下来贴进工单，不能只能看不能选。
    """

    def __init__(self, title: str, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("panel")
        box = QVBoxLayout(self)
        box.setContentsMargins(14, 10, 14, 12)
        box.setSpacing(6)

        t = QLabel(title)
        t.setObjectName("panel_title")
        box.addWidget(t)

        self.grid = QGridLayout()
        self.grid.setHorizontalSpacing(12)
        self.grid.setVerticalSpacing(6)
        self.grid.setColumnMinimumWidth(0, _LABEL_W)
        self.grid.setColumnStretch(1, 1)
        box.addLayout(self.grid)
        self._row = 0

    def add(self, label: str, value: str) -> None:
        lb = QLabel(label)
        lb.setFixedWidth(_LABEL_W)
        lb.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        lb.setObjectName("form_label")
        self.grid.addWidget(lb, self._row, 0)

        v = QLabel(value)
        v.setObjectName("mono_hint")
        v.setWordWrap(True)
        v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        # 横向策略设 Ignored：Windows 路径是一整串没有空格的「词」，QLabel 的
        # minimumSizeHint 会按它整串的宽度来算（本例 700+ px），面板于是顶得比
        # 对话框还宽 —— 滚动区只好横向滚动条，或把右边裁掉。设成 Ignored 后
        # 宽度由网格列决定，路径在自己那一列里折行，滚动条只可能是竖向的。
        v.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.grid.addWidget(v, self._row, 1)
        self._row += 1


class AboutDialog(QDialog):
    """关于 PortGuard：版本 / 运行环境 / 路径 + 快捷键帮助。

    三个入口共用同一个对话框（侧栏版本号、托盘菜单、F1），
    入口分散但实现只有一份 —— 否则三处迟早出现三个不同的「关于」。

    `nav_items` 是导航项清单（`gui.main_window.NAV_ITEMS`），由调用方传入，
    快捷键帮助据此生成切页条目（见 `build_shortcut_rows`）。
    """

    def __init__(self, nav_items: List[Tuple[str, str]], parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._nav_items = nav_items
        self.setWindowTitle(f"关于 {APP_NAME}")
        self.setMinimumSize(560, 470)
        # 初始尺寸按「运行环境 + 数据与文件两块完整可见」定：内容本身约 500px 高
        # （三行 Windows 路径撑起来的），若只给 sizeHint 的 486px，一打开就得滚。
        # 高度不够时仍有竖向滚动条兜底，见 `_scroll_page`。
        self.resize(620, 560)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 16, 20, 14)
        lay.setSpacing(12)
        lay.addLayout(self._header())

        tabs = QTabWidget()
        tabs.addTab(self._tab_about(), "关于")
        tabs.addTab(self._tab_shortcuts(), "快捷键")
        lay.addWidget(tabs, 1)

        lay.addLayout(self._buttons())

    # ── 头部 ──
    def _header(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(12)

        row.addWidget(ShieldMark(40), 0, Qt.AlignmentFlag.AlignVCenter)

        names = QVBoxLayout()
        names.setContentsMargins(0, 0, 0, 0)
        names.setSpacing(2)
        title = QLabel(APP_NAME)
        title.setStyleSheet(f"color:{C.text_on_dark};font-size:19px;font-weight:700;")
        desc = QLabel("端口访问防御工具 · 离线归属 · 规则打分 · 防火墙封禁")
        desc.setObjectName("hint")
        names.addWidget(title)
        names.addWidget(desc)
        row.addLayout(names)
        row.addStretch(1)

        ver = QLabel(f"v{APP_VERSION}")
        ver.setStyleSheet(
            f"color:{C.primary};font-size:13.5px;font-weight:600;"
            f"border:1px solid {C.primary_light};border-radius:4px;padding:2px 8px;"
        )
        row.addWidget(ver, 0, Qt.AlignmentFlag.AlignVCenter)
        return row

    # ── 关于 ──
    def _tab_about(self) -> QWidget:
        area, lay = _scroll_page()

        env = _InfoPanel("运行环境")
        env.add("程序版本", f"v{APP_VERSION}")
        env.add("图形界面", BINDING_DESC)
        env.add("Python", python_text())
        env.add("操作系统", os_text())
        env.add("运行方式", run_mode_text())
        lay.addWidget(env)

        files = _InfoPanel("数据与文件")
        files.add("数据目录", user_data_dir())
        files.add("数据库", db_path())
        files.add("日志文件", log_file())
        files.add("离线 IP 库", library_text())
        lay.addWidget(files)

        lay.addWidget(self._license())
        lay.addStretch(1)
        return area

    @staticmethod
    def _license() -> QWidget:
        w = QFrame()
        w.setObjectName("panel")
        box = QVBoxLayout(w)
        box.setContentsMargins(14, 10, 14, 12)
        box.setSpacing(6)
        t = QLabel("许可与声明")
        t.setObjectName("panel_title")
        box.addWidget(t)
        for line in (
            "· 离线 IP 归属地数据来自 ip2region（Apache-2.0），结果仅供技术参考，"
            "不作为任何行政、商业或法律意义上的依据。",
            "· 本工具会创建 / 删除 Windows 防火墙入站阻止规则，"
            "请仅在你有管理权限且获得授权的环境中使用。",
            "· 包含的第三方组件与许可见程序目录下的 NOTICE"
            "（Qt for Python LGPLv3、ip2region Apache-2.0 等）。",
        ):
            lb = QLabel(line)
            lb.setObjectName("hint")
            lb.setWordWrap(True)
            lb.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            box.addWidget(lb)
        return w

    # ── 快捷键 ──
    def _tab_shortcuts(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(2, 6, 2, 2)
        lay.setSpacing(10)

        rows = build_shortcut_rows(self._nav_items)
        table = QTableWidget(len(rows), 2)
        table.setHorizontalHeaderLabels(["快捷键", "说明"])
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(_ROW_H)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        table.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        table.setColumnWidth(0, 110)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        # 高度按内容算，且表头取 sizeHint 与 _HEADER_H 的较大值（见 _HEADER_H 注释：
        # 未 polish 时 sizeHint 偏小，会少算一行）。
        # 上限 360：以后导航项多到十几条时让表格自己滚动，别把对话框顶出屏幕。
        header_h = max(table.horizontalHeader().sizeHint().height(), _HEADER_H)
        table.setFixedHeight(min(header_h + _ROW_H * len(rows) + 2, 360))

        for i, (key, desc) in enumerate(rows):
            k = QTableWidgetItem(key)
            k.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            table.setItem(i, 0, k)
            table.setItem(i, 1, QTableWidgetItem(desc))
        align_headers(table, [0])
        lay.addWidget(table)

        note = QLabel("切页快捷键由导航项自动生成（与侧栏顺序一致），新增页面后本页会同步多一行。")
        note.setObjectName("hint")
        note.setWordWrap(True)
        lay.addWidget(note)
        lay.addStretch(1)
        return w

    # ── 按钮 ──
    def _buttons(self) -> QHBoxLayout:
        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)

        b_info = QPushButton("复制版本信息")
        b_info.setObjectName("btn_outline")
        b_info.setCursor(Qt.CursorShape.PointingHandCursor)
        b_info.setToolTip("把版本 / 环境 / 路径复制成纯文本（贴工单用）")
        b_info.clicked.connect(self._copy_info)

        b_diag = QPushButton("复制诊断信息")
        b_diag.setObjectName("btn_outline")
        b_diag.setCursor(Qt.CursorShape.PointingHandCursor)
        b_diag.setToolTip("执行环境自诊断（与命令行 --diag 同一套输出）并复制全文")
        b_diag.clicked.connect(self._copy_diag)

        b_close = QPushButton("关闭")
        b_close.setObjectName("btn_primary")
        b_close.setCursor(Qt.CursorShape.PointingHandCursor)
        b_close.clicked.connect(self.accept)

        self.lbl_hint = QLabel("")
        self.lbl_hint.setObjectName("form_hint")
        self.lbl_hint.setFixedHeight(30)

        row.addWidget(b_info)
        row.addWidget(b_diag)
        row.addSpacing(8)
        row.addWidget(self.lbl_hint, 1)
        row.addWidget(b_close)
        return row

    def _hint(self, text: str, color: str) -> None:
        self.lbl_hint.setText(text)
        self.lbl_hint.setStyleSheet(f"color:{color};font-size:13.5px;")

    def _copy_info(self) -> None:
        QApplication.clipboard().setText(about_summary_text())
        self._hint("版本信息已复制到剪贴板", C.success)

    def _copy_diag(self) -> None:
        report, summary = collect_diag_text()
        QApplication.clipboard().setText(report)
        ok = "失败" not in summary
        self._hint(f"诊断信息已复制（{summary}）", C.success if ok else C.warning)

    # 让调用方可以直接取到纯文本（供测试与以后「导出到日志」复用）
    def summary_text(self) -> str:
        return about_summary_text()
