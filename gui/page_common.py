"""PortGuard — 设置页可复用 UI 构件

设置页拆成装配器 + 子页（GuardPage / DataPage）后，两处共用的「分组面板 /
标签列 / 分区导航 / 备份下拉」等 helper 集中到这里，避免各自复制一份。

拆出前这些都在 `gui.page_settings` 模块级；为兼容既有测试（`.py` 直接
`from gui.page_settings import _Panel`、`SettingsPage._scroll_page()` 静态调用），
`page_settings` 会从这里 re-export `_Panel`，并让 `SettingsPage._scroll_page()`
静态方法转发到本模块实现。子页与装配器统一从本模块取 helper。
"""

from typing import List, Optional, Tuple

from gui.components import SectionIndex
from gui.theme import C
from gui.widgets import CONTENT_MAX_W
from qtcompat import (
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLayout,
    QScrollArea,
    Qt,
    QVBoxLayout,
    QWidget,
)

LABEL_W = 128
BACKUP_PICKER_MIN_W = 460


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


def _sw_label(text: str) -> QLabel:
    """开关右侧的小字说明"""
    lb = QLabel(text)
    lb.setStyleSheet(f"color:{C.text_secondary};font-size:13.5px;")
    return lb


def _scroll_page() -> Tuple[QScrollArea, QVBoxLayout]:
    """tab 内容容器。窗口变矮时出现滚动条，而不是把控件压扁。

    条目水平居中：面板自身限宽到 CONTENT_MAX_W（见 gui.page_common._Panel），
    不加这条对齐的话受限宽的卡片会全部贴左，右侧空出一大片。
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


def _add_section_index(
    page: QScrollArea,
    lay: QVBoxLayout,
    group: str,
    labels: List[str],
) -> SectionIndex:
    """每个 tab 顶部一条二级分区导航，与卡片同宽、同款 QSS。"""
    idx = SectionIndex(group, labels)
    idx.setMaximumWidth(CONTENT_MAX_W)
    lay.addWidget(idx, 0, Qt.AlignmentFlag.AlignHCenter)

    # 普通 def 槽 + 默认值：PySide2 有时按 0 参调用，两栈都能接住
    def on_click(i: int = 0) -> None:
        _scroll_to_section(page, lay, i)

    idx.section_clicked.connect(on_click)
    return idx


def _scroll_to_section(page: QScrollArea, lay: QVBoxLayout, i: int) -> None:
    """滚动 QScrollArea 内第 i+1 项（第 0 项是分区导航条自身）到视野顶部。"""
    item = lay.itemAt(i + 1)
    w = item.widget() if item is not None else None
    if w is None:
        return
    bar = page.verticalScrollBar()
    if bar is not None:
        bar.setValue(max(0, w.y() - 8))


def _backup_picker() -> QComboBox:
    """两处备份明细共用的单行下拉：不随滚动区跑，也不会被卡片边缘遮住"""
    cb = QComboBox()
    cb.setMinimumWidth(BACKUP_PICKER_MIN_W)
    cb.setMaxVisibleItems(10)
    cb.setToolTip("下拉选择备份版本；选中后在下方查看该份的完整明细")
    return cb


def _fill_backup_picker(cb: QComboBox, labels: List[str]) -> None:
    """重建下拉项并尽量保留当前选择（按显示文本匹配）。"""
    prev = cb.currentText()
    cb.blockSignals(True)
    try:
        cb.clear()
        if not labels:
            cb.addItem("（暂无可用备份）", -1)
        for i, label in enumerate(labels):
            cb.addItem(label, i)
    finally:
        cb.blockSignals(False)
    if not labels:
        return
    idx = cb.findText(prev)
    cb.setCurrentIndex(idx if idx >= 0 else 0)


def _picker_index(cb: QComboBox) -> int:
    try:
        return int(cb.currentData())
    except (TypeError, ValueError):
        return -1
