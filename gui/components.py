"""PortGuard — 窗口外壳级组合控件

与 `gui/widgets.py`（通用原子控件：圆点 / 开关 / 徽章 / 空态 …）的分工：
本文件只放「一整个窗口外壳才会用到」的拼装件 —— 侧栏品牌盾牌、页面标题区、
顶部状态条、行内「更多操作」。这些部件的尺寸由设计规范直接钉死（56 / 44 / 22），
所以不提供自由布局参数。

约束（同 theme.py，见 _design/01_visual_direction.md §5、§7）：
- 颜色只从 `gui.theme.C` 取，不自造第 5 个色相；
- 图标一律 QPainter 自绘，不使用 emoji —— `🛡` 在 Win10 上是彩色字形（破坏
  「单一强调色」调性），在 Server 2008 R2 上可能缺字形显示成豆腐块；
- QSS 没有 box-shadow / transition，故需要「状态点 + 文字」的地方靠自绘；
- 注解必须写成 Python 3.8 当场可求值的形式（typing.List / Optional）。
"""

from typing import Any, Callable, Iterator, List, Optional, Sequence, Tuple

from app.export_csv import export_rows
from gui.theme import C, small_button_style
from gui.widgets import StatusItem
from qtcompat import (
    QColor,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMenu,
    QMessageBox,
    QPainter,
    QPen,
    QPointF,
    QPolygonF,
    QPushButton,
    Qt,
    QToolButton,
    QVBoxLayout,
    QWidget,
    Signal,
)

# 行内菜单项：(显示文字, 无参回调)。回调返回值被忽略，允许 ``int`` 之类的顺带返回。
# 回调传 ``None`` 表示「这个动作当前不可用」：菜单项照样显示但置灰。
# 选择置灰而不是删掉，是因为用户必须先**看见**「已在封禁中」才知道不用再点；
# 直接消失会让人以为这个功能出了 bug。
MenuEntry = Tuple[str, Optional[Callable[[], object]]]


class ShieldMark(QWidget):
    """20×20 自绘盾牌（侧栏品牌区图标）

    用自绘而不是 `🛡`/图标字体：emoji 在 Win10 上是彩色字形、无法着色，
    也违反「颜色只表达语义」；图标字体又会引入新依赖。
    """

    def __init__(self, size: int = 20, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self._size = size
        self.setFixedSize(size, size)

    def paintEvent(self, e) -> None:
        w = float(self._size)
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)

        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(C.primary))
        p.drawPolygon(
            QPolygonF(
                [
                    QPointF(w * 0.50, w * 0.04),
                    QPointF(w * 0.92, w * 0.20),
                    QPointF(w * 0.92, w * 0.52),
                    QPointF(w * 0.50, w * 0.96),
                    QPointF(w * 0.08, w * 0.52),
                    QPointF(w * 0.08, w * 0.20),
                ]
            )
        )

        # 对勾是「挖空」效果：用 bg_sidebar(白) 压 primary 得 5.2:1，
        # 比 accent_on 更实；笔画 2.4（20px 下 1px 会糊成灰线），RoundCap 保圆头。
        pen = QPen(QColor(C.bg_sidebar))
        pen.setWidthF(max(2.4, w * 0.12))
        pen.setCapStyle(Qt.PenCapStyle.RoundCap)
        pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
        p.setPen(pen)
        p.setBrush(Qt.BrushStyle.NoBrush)
        # 两段分别 ≈5.9px / ≈11.4px（20px 下），短臂再长就会戳出盾牌轮廓
        p.drawPolyline(
            QPolygonF(
                [
                    QPointF(w * 0.195, w * 0.485),
                    QPointF(w * 0.400, w * 0.700),
                    QPointF(w * 0.765, w * 0.260),
                ]
            )
        )
        p.end()


class PageHeader(QWidget):
    """页面标题区（高 62）

    结构：标题 23/600 `text_on_dark` + 说明 13.5 `text_muted`（同行、间距 10、
    与标题下缘对齐）+ 右侧动作区（间距 8、右对齐、垂直居中）。

    说明与标题在同一行而不是换行：`02_ux_spec.md` P1-1 要求 7 页标题基线一致，
    说明一旦换行，各页标题区的实际高度就会随文案长短浮动。
    """

    HEIGHT = 62

    def __init__(self, title: str, desc: str = "", parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setFixedHeight(self.HEIGHT)

        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)
        outer.addStretch(1)

        row = QHBoxLayout()
        row.setContentsMargins(0, 0, 0, 0)
        row.setSpacing(0)

        self.title_lbl = QLabel(title)
        self.title_lbl.setObjectName("page_title")
        self.title_lbl.setFixedHeight(30)
        row.addWidget(self.title_lbl, 0, Qt.AlignmentFlag.AlignVCenter)

        self.desc_lbl = QLabel(desc)
        self.desc_lbl.setObjectName("page_desc")
        self.desc_lbl.setFixedHeight(30)
        # 固定同高 + 底对齐 ≈ 同基线（20px 与 12px 的 descent 差约 2px）
        self.desc_lbl.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignBottom)
        self.desc_lbl.setVisible(bool(desc))
        row.addSpacing(10)
        row.addWidget(self.desc_lbl, 0, Qt.AlignmentFlag.AlignVCenter)

        row.addStretch(1)

        self._actions = QHBoxLayout()
        self._actions.setContentsMargins(0, 0, 0, 0)
        self._actions.setSpacing(8)
        self._actions.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        row.addLayout(self._actions)

        outer.addLayout(row)
        outer.addStretch(1)

    def add_action(self, w: QWidget) -> QWidget:
        """追加一个右侧动作控件（页面级按钮高 32，组内间距 8）"""
        self._actions.addWidget(w, 0, Qt.AlignmentFlag.AlignVCenter)
        return w

    def set_desc(self, text: str) -> None:
        self.desc_lbl.setText(text)
        self.desc_lbl.setVisible(bool(text))


class ClickableStatusItem(StatusItem):
    """可点击的顶部状态项 = `StatusItem` + `clicked` 信号

    `StatusItem` 在 `gui/widgets.py`（通用控件，本轮不动），这里只加一层点击
    能力：Qt 的虚拟函数必须靠子类重写才生效，实例级打补丁（`w.mouseReleaseEvent
    = ...`）在 PySide 上不会改变 C++ 侧的分发。
    """

    clicked = Signal()

    def mouseReleaseEvent(self, e) -> None:
        if e.button() == Qt.MouseButton.LeftButton and self.isEnabled():
            self.clicked.emit()
        super().mouseReleaseEvent(e)


class TopStatusBar(QFrame):
    """顶部持久健康态条（高 48）

    接收服务 / 本机观察 / 权限 三项 —— 这三个「是否真在防护」的状态原先被压在
    26px 状态栏最右端，等于没有（`02_ux_spec.md` P0-8）。项间的 1px 竖线由本控件
    负责插入，调用方只 `add_item()`，不用关心分隔线位置。
    """

    HEIGHT = 48

    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setObjectName("topbar")
        self.setFixedHeight(self.HEIGHT)

        self._lay = QHBoxLayout(self)
        self._lay.setContentsMargins(16, 0, 16, 0)
        self._lay.setSpacing(10)
        # 项一律左对齐：末尾留 stretch，insertWidget 时插在它前面
        self._lay.addStretch(1)

        self.items: List[ClickableStatusItem] = []

    def add_item(self, label: str) -> ClickableStatusItem:
        """追加一项，返回可继续 `set_state()` / 连 `clicked` 的项对象"""
        item = ClickableStatusItem(label)
        item.setAccessibleName(label)
        if self.items:
            sep = QFrame()
            sep.setObjectName("topbar_sep")
            sep.setFixedWidth(1)
            sep.setFixedHeight(14)
            self._lay.insertWidget(self._lay.count() - 1, sep, 0, Qt.AlignmentFlag.AlignVCenter)
        self._lay.insertWidget(self._lay.count() - 1, item, 0, Qt.AlignmentFlag.AlignVCenter)
        self.items.append(item)
        return item


class DotsButton(QToolButton):
    """三点「更多」按钮：三个 3px 圆点**自绘**，不依赖 `⋯` 字形

    U+22EF / U+22EE 在 Windows 7 / Server 2008 R2 的微软雅黑里**没有字形**，
    会渲染成方框；Win10 上是细窄的居中点，视觉重心偏高。三个小圆点既保证
    两代系统一致，也能自己控制直径与间距（22px 方按钮内：3 点 + 2 间距 = 15px 宽）。
    """

    def __init__(self, size: int = 22, parent: Optional[QWidget] = None):
        super().__init__(parent)
        self.setFixedSize(size, size)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setAccessibleName("更多操作")
        self.setToolTip("更多操作")
        self.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)

    def paintEvent(self, e) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        color = C.text_primary if (self.underMouse() or self.isDown()) else C.text_secondary
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(QColor(color))
        cx, cy = self.width() / 2, self.height() / 2
        r = 1.5
        gap = 5.0
        for i in (-1, 0, 1):
            p.drawEllipse(QPointF(cx + i * gap, cy), r, r)


def _menu_slot(callback: Callable[[], object]) -> Callable[..., None]:
    """把无参回调包成 Qt 槽。

    ⚠️ 不要用 `lambda _checked=False: cb()` 这种**带默认参数的 lambda**：
    shiboken2（PySide2）会按 0 参调用它并抛 TypeError，而窗口化运行时该错误
    只进看不见的 stderr，表现为「点了没反应」（详见 `MainWindow._nav_slot`）。
    带默认参数的 `def` 在 PySide2 / PySide6 上都已验证 0 参、1 参均可。
    """

    def slot(_checked: bool = False) -> None:
        callback()

    return slot


def export_table_csv(
    parent: Optional[QWidget],
    rows: Sequence[Any],
    headers: Sequence[str],
    row_builder: Callable[[Any], Iterator[Sequence[Any]]],
    default_name: str,
    dialog_title: str = "导出 CSV",
    scope_hint: str = "",
    empty_msg: str = "没有可导出的数据。",
) -> None:
    """「选路径 → 写文件 → 报结果」三段式，四个导出入口共用。

    文件对话框、异常弹框、结果弹框统一在这里兜住，业务页只负责给
    `rows`（页面数据缓存）和 `row_builder`（`app.export_csv` 里的行构造函数）：

    · `rows` 必须是**内存缓存**而不是 QTableWidget —— 表格里是被列宽截断的
      显示值，且 tooltip 里的完整值在导出场景取不到；
    · `rows` 是序列而不是生成器，就是为了在弹文件对话框之前先判断空数据，
      免得用户选完路径才被告知「没有数据」；
    · `scope_hint` 用来说明导出范围（导了多少条 / 是不是全量），
      这是「当前筛选结果」与「全量」唯一不会误导用户的交代方式。
    """
    if not rows:
        QMessageBox.information(parent, "提示", empty_msg)
        return
    path, _ = QFileDialog.getSaveFileName(parent, dialog_title, default_name, "CSV 文件 (*.csv)")
    if not path:
        return
    try:
        n = export_rows(path, headers, row_builder(rows), title=dialog_title)
    except Exception as e:  # 导出失败必须让用户看见，不能静默吞掉
        QMessageBox.warning(parent, "导出失败", str(e))
        return
    tail = f"\n\n{scope_hint}" if scope_hint else ""
    QMessageBox.information(parent, "导出成功", f"已导出 {n} 条到：\n{path}{tail}")


def build_menu(entries: List[Optional[MenuEntry]], parent: Optional[QWidget] = None) -> QMenu:
    """按 MenuEntry 列表建菜单（行内「⋯」与右键菜单共用同一份动作定义）。

    · 列表元素 `None` → 分隔线；
    · 元素里的回调 `None` → 该项置灰（「已在封禁中」这类状态化文案）。
    """
    menu = QMenu(parent)
    for entry in entries:
        if entry is None:
            menu.addSeparator()
            continue
        text, callback = entry
        act = menu.addAction(text)
        if callback is None:
            act.setEnabled(False)
            continue
        act.triggered.connect(_menu_slot(callback))
    return menu


def row_menu_button(
    entries: List[Optional[MenuEntry]], parent: Optional[QWidget] = None, size: int = 22
) -> DotsButton:
    """「更多操作」按钮：默认 22×22（表格行内），工具条传 size=32

    entries: [(菜单文字, 无参回调), ...]；列表里的 `None` 表示一条分隔线，
    回调为 `None` 表示该项当前不可点（见 `build_menu`）。
    纯图标按钮必须同时具备 accessibleName 与 tooltip（`02_ux_spec.md` §6 规则 ④）；
    但**不给它发明文字** —— 菜单里每一项才是有意义的动作名。
    """
    btn = DotsButton(size, parent)
    btn.setMenu(build_menu(entries, btn))
    btn.setEnabled(bool(entries))
    return btn


def ban_button(
    on_click: Callable[[], object],
    banned: bool = False,
    text: str = "封禁",
    tip: str = "",
) -> QPushButton:
    """行内主操作「封禁」按钮，**知道这个 IP 是不是已经在封禁中**。

    已封禁 → 文案改「已封禁」并置灰。不这么做的话，用户对着同一行再点一次
    只会弹一句「已处于封禁状态」，看上去跟「上次没生效」一模一样 —— 这是
    「操作后状态不联动」里最容易被当成 bug 的那一处。

    `tip` 用来补一句到期时间之类的上下文；置灰态下 tooltip 是唯一能看到
    原因的地方，所以文案必须自带结论。
    """
    btn = QPushButton("已封禁" if banned else text)
    btn.setFixedHeight(30)
    btn.setStyleSheet(small_button_style("danger"))
    btn.setToolTip(tip or ("该 IP 已在封禁中，解封请到「封禁管理」页" if banned else ""))
    if banned:
        btn.setEnabled(False)
    else:
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(_menu_slot(on_click))
    return btn
