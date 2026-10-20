"""PortGuard — 可复用控件

设计约束（详见 _design/01_visual_direction.md）：
- 颜色只表达语义；装饰性彩色一律不用。
- 容器靠明度分层，不靠描边；1px 只留给可交互对象。
- 自绘控件用 QPainter，不依赖 QSS 做不到的阴影/过渡。
"""

from typing import Callable, ClassVar, Optional, Union

from gui.table_sort import SortSpec, TableSort
from gui.theme import LEVEL_BADGE_BG, LEVEL_COLORS, C
from qtcompat import (
    Property,
    QApplication,
    QBrush,
    QColor,
    QEasingCurve,
    QFont,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPainter,
    QPen,
    QPropertyAnimation,
    QPushButton,
    QRect,
    QSize,
    QSizePolicy,
    QStyle,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    Qt,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    Signal,
)


def number_font(pixel_size: int = 12, bold: bool = False) -> QFont:
    """数字字体：Consolas 自带且等宽（Vista/2008 R2 起可用），
    保证端口、评分、时间在表格里竖向对齐。"""
    f = QFont("Consolas")
    f.setStyleHint(QFont.StyleHint.Monospace)
    f.setPixelSize(pixel_size)
    f.setBold(bold)
    return f


class Dot(QWidget):
    """6px 语义状态圆点（比文字更快被余光扫到）"""

    def __init__(self, color: Optional[str] = None, size: int = 6, parent=None):
        super().__init__(parent)
        self._color = color or C.text_muted
        self._size = size
        self.setFixedSize(size, size)

    def set_color(self, color: str) -> None:
        self._color = color
        self.update()

    def paintEvent(self, e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QBrush(QColor(self._color)))
        p.drawEllipse(QRect(0, 0, self._size, self._size))
        p.end()


class ToggleSwitch(QWidget):
    """开关控件（36×20）：轨道 primary / 关闭态 border_strong"""

    toggled = Signal(bool)

    def __init__(self, checked: bool = False, parent=None, width: int = 36, height: int = 20):
        super().__init__(parent)
        self._checked = checked
        self._w, self._h = width, height
        self.setFixedSize(width, height)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._pos = 1.0 if checked else 0.0
        self._anim = QPropertyAnimation(self, b"position", self)
        self._anim.setDuration(120)
        self._anim.setEasingCurve(QEasingCurve.Type.InOutQuad)

    def _get_pos(self):
        return self._pos

    def _set_pos(self, v):
        self._pos = v
        self.update()

    position = Property(float, fget=_get_pos, fset=_set_pos)

    def isChecked(self) -> bool:
        return self._checked

    def setChecked(self, v: bool) -> None:
        if v == self._checked:
            return
        self._checked = bool(v)
        self._animate()
        self.toggled.emit(self._checked)

    def _animate(self):
        self._anim.stop()
        self._anim.setStartValue(self._pos)
        self._anim.setEndValue(1.0 if self._checked else 0.0)
        self._anim.start()

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton and self.isEnabled():
            self.setChecked(not self._checked)
        super().mouseReleaseEvent(e)

    def sizeHint(self):
        return QSize(self._w, self._h)

    def paintEvent(self, e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = self._h / 2

        if not self.isEnabled():
            p.setOpacity(0.4)
        track = QColor(C.primary) if self._checked else QColor(C.border_strong)
        p.setBrush(QBrush(track))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(0, 0, self._w, self._h, r, r)

        pad = 2
        d = self._h - pad * 2
        x = pad + (self._w - pad * 2 - d) * self._pos
        p.setBrush(QBrush(QColor("#F4F7FA")))
        p.drawEllipse(QRect(int(x), pad, d, d))
        p.end()


class StatCard(QFrame):
    """统计卡：大数字 + 语义圆点 + 标签（无边框，靠明度分层）"""

    def __init__(self, label: str, value: str = "0", color: Optional[str] = None, parent=None):
        super().__init__(parent)
        self.setObjectName("stat_card")
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(76)
        self.setMaximumHeight(76)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(4)

        self.value_lbl = QLabel(value)
        self.value_lbl.setObjectName("stat_value")
        self.value_lbl.setFont(number_font(22, bold=True))
        self.value_lbl.setStyleSheet(
            f"font-family:Consolas,'Microsoft YaHei UI';font-size:26px;font-weight:700;"
            f"color:{color or C.text_on_dark};background:transparent;"
        )

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(8)
        self.dot = Dot(color or C.text_muted)
        self.label_lbl = QLabel(label)
        self.label_lbl.setObjectName("stat_label")
        self.label_lbl.setStyleSheet(
            f"font-size:11px;color:{C.text_secondary};background:transparent;"
        )
        row.addWidget(self.dot)
        row.addWidget(self.label_lbl)
        row.addStretch(1)

        lay.addWidget(self.value_lbl)
        lay.addLayout(row)

    def set_value(self, v) -> None:
        self.value_lbl.setText(str(v))

    def set_color(self, color: str) -> None:
        self.value_lbl.setStyleSheet(
            f"font-family:Consolas,'Microsoft YaHei UI';font-size:26px;font-weight:700;"
            f"color:{color};background:transparent;"
        )
        self.dot.set_color(color)


class RiskBadge(QLabel):
    """风险等级徽章（填充式：严重=实底，其余=淡底）"""

    def __init__(self, level: str = "normal", text: Optional[str] = None, parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_level(level, text)

    def set_level(self, level: str, text: Optional[str] = None) -> None:
        from core.config import LEVEL_LABEL

        label = text if text is not None else LEVEL_LABEL.get(level, level)
        fg = LEVEL_COLORS.get(level, C.text_secondary)
        bg = LEVEL_BADGE_BG.get(level, "#242A33")
        if level == "critical":
            fg = "#FFFFFF"
        self.setText(label)
        self.setFixedHeight(20)
        self.setStyleSheet(
            f"QLabel{{color:{fg};background:{bg};border:none;border-radius:4px;"
            f"padding:0 6px;font-size:11px;font-weight:600;}}"
        )


def _rgba(hex_color: str, alpha: float) -> str:
    c = QColor(hex_color)
    return f"rgba({c.red()},{c.green()},{c.blue()},{alpha:.2f})"


# ═══════════════════════════════════════════════════════════
#  表格内风险徽章（QSS 画不了单元格圆角底，用 delegate 自绘）
# ═══════════════════════════════════════════════════════════

BADGE_ROLE = Qt.ItemDataRole.UserRole + 1


def badge_item(level: str, text: Optional[str] = None) -> QTableWidgetItem:
    """构造一个「只显示徽章」的单元格：文字不画，等级存在自定义 role 里"""
    from core.config import LEVEL_LABEL

    it = QTableWidgetItem("")
    it.setData(BADGE_ROLE, level)
    it.setToolTip(text if text is not None else LEVEL_LABEL.get(level, level))
    return it


class RiskBadgeDelegate(QStyledItemDelegate):
    """在单元格中央绘制 18px 风险徽章；选中/斑马底仍由基类绘制"""

    HEIGHT = 18

    def paint(self, painter, option, index) -> None:
        level = index.data(BADGE_ROLE)
        if not level:
            super().paint(painter, option, index)
            return

        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        opt.text = ""
        widget = opt.widget
        style = widget.style() if widget is not None else QApplication.style()
        style.drawControl(QStyle.ControlElement.CE_ItemViewItem, opt, painter, widget)

        from core.config import LEVEL_LABEL

        text = LEVEL_LABEL.get(str(level), str(level))
        fg = "#FFFFFF" if level == "critical" else LEVEL_COLORS.get(str(level), C.text_secondary)
        bg = LEVEL_BADGE_BG.get(str(level), "#242A33")

        f = QFont(widget.font() if widget is not None else QFont())
        f.setPixelSize(11)
        f.setBold(True)
        painter.setFont(f)
        fm = painter.fontMetrics()
        w = max(34, fm.horizontalAdvance(text) + 12)
        r = QRect(
            option.rect.center().x() - w // 2,
            option.rect.center().y() - self.HEIGHT // 2,
            w,
            self.HEIGHT,
        )
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(bg)))
        painter.drawRoundedRect(r, 4, 4)
        painter.setPen(QPen(QColor(fg)))
        painter.drawText(r, Qt.AlignmentFlag.AlignCenter, text)
        painter.restore()

    def sizeHint(self, option, index):
        s = super().sizeHint(option, index)
        s.setHeight(max(s.height(), 30))
        return s


class Badge(QLabel):
    """通用小标签（淡色底 + 同色文字）"""

    def __init__(self, text: str = "", color: Optional[str] = None, parent=None):
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_color(color or C.text_secondary)

    def set_color(self, color: str) -> None:
        self.setFixedHeight(20)
        self.setStyleSheet(
            f"QLabel{{color:{color};background:{_rgba(color, 0.14)};border:none;"
            f"border-radius:4px;padding:0 6px;font-size:11px;font-weight:600;}}"
        )


class _AlertIcon(QWidget):
    """14px 线框警示图标（自绘，避免 emoji 在 Win10 变彩色、在 2008 R2 缺字形）"""

    def __init__(self, color: str, parent=None):
        super().__init__(parent)
        self._color = color
        self.setFixedSize(14, 14)

    def paintEvent(self, e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        pen = QPen(QColor(self._color))
        pen.setWidthF(1.2)
        p.setPen(pen)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(QRect(0, 0, 13, 13))
        f = QFont("Consolas")
        f.setPixelSize(9)
        f.setBold(True)
        p.setFont(f)
        p.drawText(QRect(0, 0, 14, 13), Qt.AlignmentFlag.AlignCenter, "!")
        p.end()


def labeled_toggle(toggle: QWidget, text: str) -> QWidget:
    """「文字 + 开关」横排。

    工具条与标题区右侧的开关都需要文字说明 —— 裸开关没人知道切开是什么意思
    （无障碍上也是硬伤：颜色/位置不作唯一语义通道）。
    """
    w = QWidget()
    lay = QHBoxLayout(w)
    lay.setContentsMargins(0, 0, 0, 0)
    lay.setSpacing(8)
    lb = QLabel(text)
    lb.setStyleSheet(f"color:{C.text_secondary};font-size:12.5px;")
    lay.addWidget(lb)
    lay.addWidget(toggle)
    return w


class WarnBanner(QFrame):
    """页面顶部横幅：左 3px 色条 + 淡底，整条不描边

    level: info | warning | danger（也可传 color 兼容旧调用）
    """

    action_clicked = Signal()

    LEVELS: ClassVar[dict] = {
        "info": (C.info, C.info_light),
        "warning": (C.warning, C.warning_light),
        "danger": (C.danger, C.danger_light),
    }

    def __init__(
        self,
        text: str = "",
        action_text: str = "",
        color: Optional[str] = None,
        parent=None,
        level: Optional[str] = None,
    ):
        super().__init__(parent)
        if level is None:
            level = "warning"
            if color == C.danger:
                level = "danger"
            elif color == C.info:
                level = "info"
        fg, bg = self.LEVELS.get(level, self.LEVELS["warning"])
        self._fg = fg

        self.setStyleSheet(f"QFrame{{background:{bg};border:none;border-radius:6px;}}")
        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 12, 0)
        outer.setSpacing(0)

        bar = QFrame()
        bar.setFixedWidth(3)
        bar.setStyleSheet(f"background:{fg};border:none;border-radius:0;")
        outer.addWidget(bar)

        inner = QHBoxLayout()
        inner.setContentsMargins(12, 10, 0, 10)
        inner.setSpacing(10)

        self.icon = _AlertIcon(fg)
        self.text = QLabel(text)
        self.text.setStyleSheet(f"color:{C.text_primary};font-size:12.5px;background:transparent;")
        self.text.setWordWrap(True)

        inner.addWidget(self.icon)
        inner.addWidget(self.text, 1)

        self.btn = None
        if action_text:
            self.btn = QPushButton(action_text)
            self.btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self.btn.setFixedHeight(26)
            self.btn.setStyleSheet(
                f"QPushButton{{background:transparent;color:{fg};border:1px solid {fg};"
                f"border-radius:4px;padding:0 10px;font-size:11.5px;font-weight:600;}}"
                f"QPushButton:hover{{background:{fg};color:{C.accent_on};}}"
            )
            self.btn.clicked.connect(self.action_clicked.emit)
            inner.addWidget(self.btn, 0, Qt.AlignmentFlag.AlignVCenter)

        outer.addLayout(inner, 1)

    def set_text(self, text: str) -> None:
        self.text.setText(text)


class EmptyState(QWidget):
    """统一空态：标题（4-8 字）+ 一句说明 + 可选动作"""

    def __init__(
        self,
        title: str = "暂无数据",
        desc: str = "",
        action_text: str = "",
        parent=None,
    ):
        super().__init__(parent)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 40, 16, 40)
        lay.setSpacing(6)
        lay.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.title = QLabel(title)
        self.title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title.setStyleSheet(
            f"color:{C.text_secondary};font-size:13px;font-weight:600;background:transparent;"
        )
        lay.addWidget(self.title)

        self.desc = QLabel(desc)
        self.desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.desc.setWordWrap(True)
        self.desc.setStyleSheet(f"color:{C.text_muted};font-size:12px;background:transparent;")
        self.desc.setVisible(bool(desc))
        lay.addWidget(self.desc)

        self.btn = None
        if action_text:
            self.btn = QPushButton(action_text)
            self.btn.setObjectName("btn_ghost")
            self.btn.setCursor(Qt.CursorShape.PointingHandCursor)
            lay.addWidget(self.btn, 0, Qt.AlignmentFlag.AlignCenter)

    def set_state(self, title: str, desc: str = "", action_text: Optional[str] = None) -> None:
        """就地换文案。

        同一个空态要能表达多种状态（监控页：等待访问 / 服务未启动 / 无匹配结果），
        各建一个控件既浪费也会让可见性互相打架。action_text=None 表示这一态没有出路按钮。
        """
        self.title.setText(title)
        self.desc.setText(desc)
        self.desc.setVisible(bool(desc))
        if self.btn is not None:
            if action_text is None:
                self.btn.setVisible(False)
            else:
                self.btn.setText(action_text)
                self.btn.setVisible(True)


class EmptyHint(EmptyState):
    """兼容旧调用的极简空态（只有一行说明）"""

    def __init__(self, text: str = "暂无数据", parent=None):
        super().__init__(title=text, desc="", parent=parent)


class StatusItem(QWidget):
    """顶部状态条的单项：6px 圆点 + 11px 标签"""

    def __init__(self, label: str, parent=None):
        super().__init__(parent)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)
        self.dot = Dot(C.text_muted)
        self.lbl = QLabel(label)
        self.lbl.setObjectName("topbar_item")
        lay.addWidget(self.dot)
        lay.addWidget(self.lbl)

    def set_state(self, label: str, color: str) -> None:
        self.lbl.setText(label)
        self.dot.set_color(color)


# ── 表格辅助 ──


def align_headers(table, columns, align=None) -> None:
    """让表头对齐方式跟数据一致。

    QTableWidget 的表头默认左对齐，而数字列的数据是居中的 —— 表头在左、数字在中间，
    一列数字会有两个视觉轴。凡是数据居中的列，表头也必须居中。
    """
    align = align if align is not None else Qt.AlignmentFlag.AlignCenter
    for i in columns:
        it = table.horizontalHeaderItem(i)
        if it is not None:
            it.setTextAlignment(align)


def make_item(
    text: Union[str, int, None],
    color: Optional[str] = None,
    align=None,
    bold: bool = False,
    mono: bool = False,
    tip: Optional[str] = None,
) -> QTableWidgetItem:
    it = QTableWidgetItem(str(text if text is not None else ""))
    if color:
        it.setForeground(QColor(color))
    if align is not None:
        it.setTextAlignment(align)
    if bold:
        f = QFont()
        f.setBold(True)
        it.setFont(f)
    if mono:
        it.setFont(number_font(12, bold=bold))
    if tip:
        # 单元格被省略号截断时，这是唯一还能看到完整值的地方。
        # 表格宽度是硬约束（不许横向滚动），所以宁可给 tooltip 也不加宽。
        it.setToolTip(tip)
    return it


def check_item(checked: bool = False) -> QTableWidgetItem:
    """带勾选框的单元格（批量选择用）。

    只放一个可勾选、不可编辑的空 item：勾选状态与「行选中」是两套独立语义，
    勾选用于批量操作、且翻页/筛选后依然能算清「我选了哪几条」；
    行选中只负责当前焦点（双击详情、右键菜单）。
    """
    it = QTableWidgetItem("")
    it.setFlags(
        Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsSelectable
    )
    it.setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
    it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
    return it


def center() -> Qt.AlignmentFlag:
    return Qt.AlignmentFlag.AlignCenter


def left() -> Qt.AlignmentFlag:
    return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter


class SortHeader:
    """表头点击 → 数据层重排（画 ▲/▼，但**不开** Qt 原生排序）

    排序键与三态切换本身在 `gui/table_sort.py`（纯 Python，可单测）；本类只做
    三件必须碰 Qt 的事：接 `sectionClicked`、把新顺序交回页面重渲染、画排序指示。

    刻意**不**调用 `table.setSortingEnabled(True)`：那会让表格行号脱离数据下标，
    而页面的批量封禁是按行号取记录再拿 IP 的 —— 排序后勾第 3 行会封错 IP。
    `setSortIndicator()` / `setSortIndicatorShown()` 只影响表头绘制，不触发排序。
    """

    def __init__(
        self,
        table: QTableWidget,
        sorter: TableSort,
        on_apply: Callable[[Optional[SortSpec]], None],
    ) -> None:
        self._table = table
        self._sorter = sorter
        self._on_apply = on_apply
        table.horizontalHeader().sectionClicked.connect(self._on_clicked)

    def _on_clicked(self, column: int) -> None:
        # 不可排序的列（勾选列 / 操作列）点了没反应，别把当前排序清掉
        if not self._sorter.handles(column):
            return
        state = self._sorter.click(column)
        self._on_apply(state)
        self._show_indicator(state)

    def _show_indicator(self, state: Optional[SortSpec]) -> None:
        header = self._table.horizontalHeader()
        if state is None:
            # 第三态：取消排序，指示箭头一并收掉
            header.setSortIndicatorShown(False)
            return
        order = Qt.SortOrder.DescendingOrder if state.descending else Qt.SortOrder.AscendingOrder
        header.setSortIndicator(state.column, order)
        header.setSortIndicatorShown(True)
