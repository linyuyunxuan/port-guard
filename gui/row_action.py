"""PortGuard — 表格行内按钮区的自绘 delegate

## 为什么不用 setCellWidget

原来的做法是每行一个 `QWidget` + 一个 QPushButton（封禁）+ 一个 QToolButton（⋯）。
这套写法在 200 行的表上就已经撑不住：离屏实测 `EventsPage._render` 200 行
358ms、500 行 936ms、2000 行 3426ms，而事件泵的节拍是 150ms —— 攻击高峰时风险
事件是成批到达的，每次都要整表重建，界面只会越刷越滞后，**正好在最需要看列表
的时候最卡**。裸表同规模 `setItem×11` 只要一百多毫秒，2000 个 `setCellWidget`
再 +580ms，剩下的两秒多全在「逐格构造 + 行内控件 + QSS 匹配」上 —— QSS 每建一个
按钮都要重新匹配一遍选择器，这是最贵的一块。

改成 delegate 之后，行内按钮只是一次 `drawRoundedRect` + 一次 `drawText`，
数据侧不用再建控件，渲染耗时降到只跟「构造 QTableWidgetItem」有关。

## 交互怎么保证不丢

自绘等于把「点击」也接过来，所以命中判定必须精确到「按钮矩形内」：

- `eventFilter` 装在表格的 viewport 上（不是 delegate 自己），只处理
  MouseMove / ButtonRelease / Leave / ButtonDblClick 四种；
- 点在按钮上才吞掉事件并派发，其余位置一律放行 —— 行选中、双击、右键菜单
  仍然是表格原生行为；
- 悬停在按钮上时把光标切成手型，否则自绘按钮看起来像纯文本，用户不会去点。

模块只负责「画」与「命中」，至于点下去做什么由页面传入的回调决定（见
`gui/page_events.py` 的 `_on_row_ban` / `_on_row_menu`）。
"""

from typing import Callable, Dict, Optional, Tuple

from gui.theme import C
from qtcompat import (
    QBrush,
    QColor,
    QEvent,
    QFont,
    QFontMetrics,
    QPainter,
    QPoint,
    QPointF,
    QRect,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    Qt,
    QToolTip,
    mouse_pos,
)

#: 行内按钮高（与原来 QSS 的 26px 一致，落在 34px 行高里上下各留 4px）
BTN_H = 26
#: 「⋯」的方形命中区（与 DotsButton 的 22px 一致）
DOTS_BOX = 22
#: 按钮与「⋯」之间的间距
DOTS_GAP = 6
#: 单元格左右留白
PAD_LEFT = 5
PAD_RIGHT = 5
#: 按钮最小宽度（两字按钮在 13px 字号下约 26px 文字 + 14px 内边距）
BTN_MIN_W = 46
#: 按钮文字左右内边距之和
TEXT_PAD_X = 14
#: 按钮文字字号（px）。原 QSS 是 12.5px，取 13 与 12.5 渲染宽度差 <1px
FONT_PX = 13

PART_NONE = 0
PART_PRIMARY = 1
PART_MENU = 2

#: kind -> (文字色, 描边色, 悬停填充色, 悬停文字色)
#: 与 `gui.theme.small_button_style()` 的 danger / success 两档逐色对齐，
#: 自绘和 QSS 必须长得一模一样 —— 同一张表里混两种按钮样式最刺眼。
_KINDS: Dict[str, Tuple[str, str, str, str]] = {
    "danger": (C.critical, "#E9B4B2", C.danger_solid, "#FFFFFF"),
    "success": (C.success, "#A9DCC5", C.success, C.accent_on),
}


class RowAction:
    """一行按钮区的数据描述（纯值对象，可单测）

    text 为空表示这一行只有「⋯」（如历史访问页）；enabled=False 时按钮置灰、
    点击无响应，但 tooltip 仍要能看到「为什么点不动」。
    """

    __slots__ = ("enabled", "kind", "text", "tip")

    def __init__(self, text: str = "", kind: str = "danger", enabled: bool = True, tip: str = ""):
        self.text = text
        self.kind = kind
        self.enabled = enabled
        self.tip = tip

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RowAction):
            return NotImplemented
        return (
            self.text == other.text
            and self.kind == other.kind
            and self.enabled == other.enabled
            and self.tip == other.tip
        )

    def __hash__(self) -> int:
        # 定义了 __eq__ 就必须一起定义 __hash__（否则放进 set/dict 会静默失效）
        return hash((self.text, self.kind, self.enabled, self.tip))

    def __repr__(self) -> str:  # pragma: no cover —— 只在调试里看得见
        return f"RowAction(text={self.text!r}, kind={self.kind!r}, enabled={self.enabled!r})"


class RowActionDelegate(QStyledItemDelegate):
    """把「主操作按钮 + ⋯」画在单元格里，并把点击派发给页面

    参数
    ----
    table    : QTableWidget（要用它的 viewport 装事件过滤器、用它的字体度量）
    column   : 按钮所在的列号
    provider : `(row) -> RowAction | None`，按**行号**给当前行的按钮状态；
               行号越界必须返回 None（渲染与重排之间存在窗口期）
    on_primary : `(row) -> None`，点主按钮
    on_menu    : `(row, global_pos) -> None`，点「⋯」
    """

    def __init__(
        self,
        table,
        column: int,
        provider: Callable[[int], Optional[RowAction]],
        on_primary: Optional[Callable[[int], None]] = None,
        on_menu: Optional[Callable[[int, QPoint], None]] = None,
        parent=None,
    ):
        super().__init__(parent if parent is not None else table)
        self._table = table
        self._column = column
        self._provider = provider
        self._on_primary = on_primary
        self._on_menu = on_menu
        self._hover: Tuple[int, int] = (-1, PART_NONE)
        self._font = QFont(table.font())
        self._font.setPixelSize(FONT_PX)
        self._width_cache: Dict[str, int] = {}

        # 悬停态要自己跟：delegate 拿不到「鼠标停在哪一行」，只能听 viewport 的移动事件
        viewport = table.viewport()
        viewport.setMouseTracking(True)
        viewport.installEventFilter(self)

    # ── 外部接口 ──
    def reset_hover(self) -> None:
        """行号已经换人（重排 / 重新加载）时必须清掉悬停态，否则高亮落在错行上"""
        self._hover = (-1, PART_NONE)

    def part_at(self, row: int, pos: QPoint) -> int:
        """命中判定：pos 是**视口坐标**，返回 PART_*。单测直接用它。"""
        if row < 0:
            return PART_NONE
        spec = self._spec(row)
        if spec is None:
            return PART_NONE
        rect = self._cell_rect(row)
        if not rect.isValid() or not rect.contains(pos):
            return PART_NONE
        primary, dots = self._rects(rect, spec)
        if not primary.isNull() and primary.contains(pos) and spec.enabled:
            return PART_PRIMARY
        if dots.contains(pos):
            return PART_MENU
        return PART_NONE

    # ── 绘制 ──
    def paint(self, painter, option, index) -> None:
        spec = self._spec(index.row())
        opt = QStyleOptionViewItem(option)
        self.initStyleOption(opt, index)
        # 清空文字：背景 / 斑马纹 / 选中 / 悬停底色仍交给基类，自己重画迟早走偏
        opt.text = ""
        opt.features = opt.features & ~QStyleOptionViewItem.ViewItemFeature.HasCheckIndicator
        super().paint(painter, opt, index)

        if spec is None or index.column() != self._column:
            return
        primary, dots = self._rects(option.rect, spec)
        hovered_row, hovered_part = self._hover
        is_hover = hovered_row == index.row()

        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
        if not primary.isNull():
            self._paint_button(painter, primary, spec, is_hover and hovered_part == PART_PRIMARY)
        self._paint_dots(painter, dots, is_hover and hovered_part == PART_MENU)
        painter.restore()

    def _paint_button(self, painter, rect: QRect, spec: RowAction, hovered: bool) -> None:
        fg, border, solid, on_solid = _KINDS.get(spec.kind, _KINDS["danger"])
        if not spec.enabled:
            border, fg = C.border_light, C.text_disabled
            fill = None
        elif hovered:
            fill, fg = solid, on_solid
        else:
            fill = None

        painter.setPen(QColor(border))
        painter.setBrush(QBrush(QColor(fill)) if fill else Qt.BrushStyle.NoBrush)
        # -1 是修 antialiasing 下右/下边被裁掉半像素
        painter.drawRoundedRect(rect.adjusted(0, 0, -1, -1), 4, 4)

        painter.setFont(self._font)
        painter.setPen(QColor(fg))
        text = spec.text
        fm = QFontMetrics(self._font)
        room = rect.width() - 8
        if fm.horizontalAdvance(text) > room:
            # 列被挤窄时宁可省略也不能溢出到「⋯」上：溢出会盖住菜单按钮的命中区
            text = fm.elidedText(text, Qt.TextElideMode.ElideRight, room)
        painter.drawText(rect, int(Qt.AlignmentFlag.AlignCenter), text)

    def _paint_dots(self, painter, rect: QRect, hovered: bool) -> None:
        color = C.text_primary if hovered else C.text_secondary
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(QColor(color)))
        cx = float(rect.center().x())
        cy = float(rect.center().y())
        for dx in (-5.0, 0.0, 5.0):
            painter.drawEllipse(QPointF(cx + dx, cy), 1.5, 1.5)

    # ── 命中 ──
    def eventFilter(self, obj, event) -> bool:
        et = event.type()
        if et == QEvent.Type.MouseMove:
            self._update_hover(mouse_pos(event))
        elif et == QEvent.Type.Leave:
            self._apply_hover(-1, PART_NONE)
        elif et in (QEvent.Type.MouseButtonRelease, QEvent.Type.MouseButtonDblClick):
            pos = mouse_pos(event)
            row = self._row_at(pos)
            part = self.part_at(row, pos)
            if part != PART_NONE:
                # 双击也吞掉：按键上双击等于连点两次，不能顺带弹详情框
                if et == QEvent.Type.MouseButtonRelease:
                    self._dispatch(row, part, event)
                return True
        return super().eventFilter(obj, event)

    def helpEvent(self, event, view, option, index) -> bool:
        spec = self._spec(index.row())
        if spec is not None and spec.tip and index.column() == self._column:
            QToolTip.showText(event.globalPos(), spec.tip, view)
            return True
        return super().helpEvent(event, view, option, index)

    def _dispatch(self, row: int, part: int, event) -> None:
        if part == PART_PRIMARY and self._on_primary is not None:
            self._on_primary(row)
        elif part == PART_MENU and self._on_menu is not None:
            self._on_menu(row, self._table.viewport().mapToGlobal(event.pos()))

    def _update_hover(self, pos: QPoint) -> None:
        row = self._row_at(pos)
        self._apply_hover(row, self.part_at(row, pos))

    def _apply_hover(self, row: int, part: int) -> None:
        new = (row, part) if part != PART_NONE else (-1, PART_NONE)
        self._table.viewport().setCursor(
            Qt.CursorShape.PointingHandCursor if part != PART_NONE else Qt.CursorShape.ArrowCursor
        )
        if new == self._hover:
            return
        old_row = self._hover[0]
        self._hover = new
        for r in {old_row, new[0]}:
            if r >= 0:
                self._table.viewport().update(self._cell_rect(r))

    # ── 几何 ──
    def _spec(self, row: int) -> Optional[RowAction]:
        try:
            return self._provider(row)
        except Exception:
            # 渲染期间的任何越界都不该让整张表画不出来
            return None

    def _row_at(self, pos: QPoint) -> int:
        idx = self._table.indexAt(pos)
        if not idx.isValid() or idx.column() != self._column:
            return -1
        return int(idx.row())

    def _cell_rect(self, row: int) -> QRect:
        model = self._table.model()
        if model is None:
            return QRect()
        return QRect(self._table.visualRect(model.index(row, self._column)))

    def _btn_width(self, text: str) -> int:
        cached = self._width_cache.get(text)
        if cached is not None:
            return cached
        fm = QFontMetrics(self._font)
        w = max(BTN_MIN_W, fm.horizontalAdvance(text) + TEXT_PAD_X)
        self._width_cache[text] = w
        return w

    def _rects(self, cell: QRect, spec: RowAction) -> Tuple[QRect, QRect]:
        """按钮与「⋯」的矩形。cell 是单元格矩形（视口坐标）。

        列宽是硬预算（106 / 101 / 129 三种），所以按钮宽度先按文字实测，
        再用「列宽 − 点按钮 − 间距」夹一次。真的放不下两个（列被拖到 60px 以下）
        时**只画「⋯」**：菜单里能找到同一个动作，而挤在按钮底下的「⋯」既点不准
        也看不见，等于功能消失。
        """
        cy = cell.center().y()
        left = cell.left() + PAD_LEFT
        avail = max(0, cell.width() - PAD_LEFT - PAD_RIGHT)
        primary = QRect()
        if spec.text and avail >= BTN_MIN_W + DOTS_GAP + DOTS_BOX:
            w = self._btn_width(spec.text)
            w = min(w, avail - DOTS_GAP - DOTS_BOX)
            primary = QRect(left, cy - BTN_H // 2, w, BTN_H)
            left = primary.right() + 1 + DOTS_GAP
        dots = QRect(left, cy - DOTS_BOX // 2, DOTS_BOX, DOTS_BOX)
        if dots.right() > cell.right() - PAD_RIGHT:
            dots.moveRight(cell.right() - PAD_RIGHT)
        return primary, dots
