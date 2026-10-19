"""表格勾选列：给 QTableWidget 加「勾选框列 + 表头全选」，三张表共用一份实现。

为什么单独抽出来：
- 风险事件表、封禁建议表、封禁记录表都需要同一套东西。三处各写一遍，
  迟早出现「这张表能全选、那张表全选后计数不对」的分歧。
- 有两个坑必须收在一处：
  1. **渲染时要屏蔽 itemChanged**：`setItem()` 会逐格发信号，不挡的话每加一行
     都会触发一次「勾选数变化」，几千行就是几千次回调；
  2. **表头勾选态要跟着行状态走**：全勾 → Checked，部分 → PartiallyChecked
     （表头用三态，用户才能看出「我只勾了一半」）。

与「行选中」的关系：勾选是批量语义，跨筛选保留意图；行选中只服务当前焦点
（双击详情、右键菜单）。两者互不干扰。
"""

from typing import Callable, List, Optional

from gui.widgets import check_item
from qtcompat import Qt, QTableWidget, QTableWidgetItem


class CheckColumn:
    """挂在某张表的第 col 列上，维护勾选状态与计数回调。"""

    def __init__(self, table: QTableWidget, col: int, tip: str = "全选本页 / 取消全选") -> None:
        self.table = table
        self.col = col
        self._loading = False
        self._on_change: Optional[Callable[[int], None]] = None

        hdr = QTableWidgetItem("")
        hdr.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsUserCheckable)
        hdr.setCheckState(Qt.CheckState.Unchecked)
        hdr.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        hdr.setToolTip(tip)
        table.setHorizontalHeaderItem(col, hdr)

        table.itemChanged.connect(self._on_item_changed)
        table.horizontalHeader().sectionClicked.connect(self._on_section_clicked)

    # ── 对外 ──
    def bind(self, callback: Callable[[int], None]) -> None:
        """勾选数量变化时回调（参数为当前勾选行数）。"""
        self._on_change = callback

    def begin_render(self) -> None:
        self._loading = True

    def end_render(self) -> None:
        self._loading = False
        self._sync_header()
        self._emit()

    def fill(self, row: int) -> None:
        """在渲染循环里给第 row 行放一个未勾选的格子。"""
        self.table.setItem(row, self.col, check_item())

    def checked_rows(self) -> List[int]:
        out: List[int] = []
        for i in range(self.table.rowCount()):
            it = self.table.item(i, self.col)
            if it is not None and it.checkState() == Qt.CheckState.Checked:
                out.append(i)
        return out

    def count(self) -> int:
        return len(self.checked_rows())

    def set_all(self, checked: bool) -> None:
        state = Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked
        self._loading = True
        try:
            for i in range(self.table.rowCount()):
                it = self.table.item(i, self.col)
                if it is not None:
                    it.setCheckState(state)
        finally:
            self._loading = False
        self._sync_header()
        self._emit()

    def toggle_all(self) -> None:
        # 只要不是「全勾」就变成全勾（部分勾选时点全选，符合直觉）
        self.set_all(self.count() != self.table.rowCount() or self.table.rowCount() == 0)

    def clear(self) -> None:
        """渲染前调用：勾选态随行一起重置，避免上一轮的行号错位。"""
        self.set_all(False)

    # ── 内部 ──
    def _on_item_changed(self, item: QTableWidgetItem) -> None:
        if self._loading or item.column() != self.col:
            return
        # 单格勾选后表头可能是「部分勾选」，需要同步一次
        self._sync_header()
        self._emit()

    def _on_section_clicked(self, section: int) -> None:
        if section != self.col:
            return
        self.toggle_all()

    def _sync_header(self) -> None:
        hdr = self.table.horizontalHeaderItem(self.col)
        if hdr is None:
            return
        n = self.count()
        total = self.table.rowCount()
        if n == 0 or total == 0:
            hdr.setCheckState(Qt.CheckState.Unchecked)
        elif n == total:
            hdr.setCheckState(Qt.CheckState.Checked)
        else:
            hdr.setCheckState(Qt.CheckState.PartiallyChecked)

    def _emit(self) -> None:
        if self._on_change is not None:
            self._on_change(self.count())
