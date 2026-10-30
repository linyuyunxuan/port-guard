"""PortGuard — BaseTablePage：带勾选列 + 表头排序的表格页公共基类（P2-7）。

封禁页的两张表（建议表 / 记录表）与事件页各自维护着同一套「表格设置 +
双击切换勾选 + 勾选回放排序」逻辑，四份拷贝已经漂移出过两次不一致。
这里把公共部分收敛到一个基类，页面只保留各自的差异（列定义 / 渲染）。

设计取舍：**基类只收敛「行为」，不碰「装配」**。列宽、委托、布局仍由各页
自己搭 —— 那部分差异太大（界面预算是逐列实测钉死的），硬抽象反而会把
差异藏进参数里。收敛的是三段逐字重复的逻辑：

1. `setup_table`：QTableWidget 的通用观感设置（无编辑 / 整行选中 / 隔行
   变色 / 无网格 / 常显竖滚动条……）；
2. `toggle_row_check`：双击整行切换勾选态（操作列不接管）；
3. `sort_and_replay`：按新排序重渲染后，勾选按**业务 key**（记录 id）回放，
   绝不按行号 —— 排序后行号已经换人，按行号回放会把勾选落到别的记录上，
   紧接着的批量封禁就封错了。
"""

from typing import Any, Callable, List, Sequence

from gui.table_select import CheckColumn
from gui.table_sort import TableSort
from qtcompat import (
    QAbstractItemView,
    Qt,
    QTableWidget,
    QWidget,
)


class BaseTablePage(QWidget):
    """表格页基类。子类：BansPage（双表）、EventsPage。"""

    # ══════════ 表格通用观感 ══════════

    @staticmethod
    def setup_table(table: QTableWidget) -> None:
        """QTableWidget 的通用观感。列宽 / 行高微调由各页在调用后再叠加。"""
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.setWordWrap(False)
        table.setTabKeyNavigation(False)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(34)
        # 常显竖滚动条：滚动条出现/消失会让可视宽在 15↔25px 之间跳，列宽跟着抖
        table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)

    # ══════════ 双击切换勾选 ══════════

    @staticmethod
    def toggle_row_check(table: QTableWidget, sel: CheckColumn, index, action_col: int) -> None:
        """双击整行切换勾选态（2026-10-27 用户要求「增加双击选择功能」）。

        勾选框只有 14px，在 34px 行高里要瞄准它才能选中；而「勾几条 → 批量
        解封」是高频路径。双击任意单元格都能切换，鼠标不用精确定位。

        两个细节：
        · **操作列不接管**：那一列自绘了「解封」按钮，双击的第一下已经算一次
          点击（delegate 自己会处理），再叠加一次勾选会让人以为解封没点中；
        · 直接改 `CheckState` 而不是调 `CheckColumn.set_checked_rows`：单行改动能
          顺着 `itemChanged` 自动同步表头三态与「已选 N 条」计数，不用重建整列。
        """
        if index is None:
            return
        row = index.row()
        if index.column() == action_col or not 0 <= row < table.rowCount():
            return
        it = table.item(row, sel.col)
        if it is None:
            return
        checked = it.checkState() == Qt.CheckState.Checked
        it.setCheckState(Qt.CheckState.Unchecked if checked else Qt.CheckState.Checked)

    # ══════════ 勾选 / 排序回放 ══════════

    @staticmethod
    def checked_rows(sel: CheckColumn, rows: Sequence[Any]) -> List[Any]:
        """勾选行对应的业务对象。防御行号越界：渲染与数据短暂错位时不炸。"""
        return [rows[i] for i in sel.checked_rows() if i < len(rows)]

    def sort_and_replay(
        self,
        sel: CheckColumn,
        sort: TableSort,
        current_rows: Sequence[Any],
        rows_src: Sequence[Any],
        render: Callable[[List[Any]], None],
        key: Callable[[Any], Any],
    ) -> List[Any]:
        """按新排序重渲染，勾选按业务 key 回放。返回新的显示顺序。

        调用方把返回值赋回自己的显示顺序属性（`self._xx_rows = ...`）。
        `render(new_rows)` 在数据切换之后调用；渲染函数内部自己从页面属性读
        数据的（如 BansPage），传一个吃掉参数的包装即可。
        """
        keys = {key(r) for r in self.checked_rows(sel, current_rows)}
        rows = sort.apply(rows_src)
        render(rows)
        sel.set_checked_rows(i for i, r in enumerate(rows) if key(r) in keys)
        return rows
