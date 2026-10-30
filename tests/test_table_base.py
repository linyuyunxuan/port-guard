"""BaseTablePage（gui/table_base.py）的回归锁。

收敛前的历史教训：封禁页双表 + 事件页各自维护同一套「勾选 / 排序回放」，
其中「按行号回放勾选」的变体出过真事故 —— 排序后行号换人，批量封禁封错
IP。这里钉死基类的三个契约：勾选取行防越界、双击切换不碰操作列、排序
回放必须按业务 key。
"""

import os
from typing import Any, Dict, List

import pytest


def _qapp():
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from qtcompat import QApplication

    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication([])
    return app


class _FakeSort:
    """sort_and_replay 只依赖 apply()。用固定 key 的排序代替 TableSort，
    让「行号换人」可控可断言。"""

    def __init__(self, key) -> None:
        self._key = key

    def apply(self, rows):
        return sorted(rows, key=self._key)


def _mk_table(n_rows: int):
    _qapp()
    from gui.table_select import CheckColumn
    from qtcompat import Qt, QTableWidget, QTableWidgetItem

    table = QTableWidget(n_rows, 3)
    sel = CheckColumn(table, 0)
    for r in range(n_rows):
        it = QTableWidgetItem()
        it.setCheckState(Qt.CheckState.Unchecked)
        table.setItem(r, 0, it)
    return table, sel


def test_checked_rows_guards_stale_rows() -> None:
    """渲染与数据短暂错位（表格行多于数据）时不得越界、不得映射错行"""
    from gui.table_base import BaseTablePage

    rows = [{"id": 1}, {"id": 2}]
    # 表格里勾了 0/1/2 三行，但数据只有 2 条：越界行必须被丢弃
    table, sel = _mk_table(3)
    from qtcompat import Qt

    for r in range(3):
        table.item(r, 0).setCheckState(Qt.CheckState.Checked)
    assert BaseTablePage.checked_rows(sel, rows) == [{"id": 1}, {"id": 2}]
    # 空数据也不炸
    assert BaseTablePage.checked_rows(sel, []) == []


def test_toggle_row_check_skips_action_column_and_bad_index() -> None:
    """双击切换：操作列不接管、None/越界索引静默返回（原 _toggle_row_check 语义）"""
    from gui.table_base import BaseTablePage
    from qtcompat import Qt

    table, sel = _mk_table(2)

    def state(r: int) -> "Qt.CheckState":
        return table.item(r, 0).checkState()

    # None 索引：不炸、不变
    BaseTablePage.toggle_row_check(table, sel, None, action_col=2)
    assert state(0) == Qt.CheckState.Unchecked
    # 普通单元格：切换
    idx = table.model().index(0, 1)
    BaseTablePage.toggle_row_check(table, sel, idx, action_col=2)
    assert state(0) == Qt.CheckState.Checked
    # 操作列：不接管
    idx = table.model().index(0, 2)
    BaseTablePage.toggle_row_check(table, sel, idx, action_col=2)
    assert state(0) == Qt.CheckState.Checked
    # 越界行：静默
    idx = table.model().index(99, 1)
    BaseTablePage.toggle_row_check(table, sel, idx, action_col=2)
    # 再切一次：回到未勾
    idx = table.model().index(0, 1)
    BaseTablePage.toggle_row_check(table, sel, idx, action_col=2)
    assert state(0) == Qt.CheckState.Unchecked


def test_sort_and_replay_replays_by_key_not_rownum() -> None:
    """核心契约：排序后勾选跟着业务 key 走。

    变异：把 sort_and_replay 改成按行号回放（keys 从 enumerate 取）→ 本例变红
    （勾选落到别的记录上）。
    """
    from gui.table_base import BaseTablePage

    rows: List[Dict[str, Any]] = [{"id": "c"}, {"id": "a"}, {"id": "b"}]
    table, sel = _mk_table(3)
    from qtcompat import Qt

    # 勾住第 0 行（id="c"）
    table.item(0, 0).setCheckState(Qt.CheckState.Checked)
    page = BaseTablePage()
    rendered: List[Any] = []

    # 按 id 升序排：id="c" 从第 0 行挪到第 2 行
    new_rows = page.sort_and_replay(
        sel,
        _FakeSort(lambda r: r["id"]),
        rows,
        rows,
        rendered.append,
        lambda r: r["id"],
    )
    assert [r["id"] for r in new_rows] == ["a", "b", "c"]
    assert rendered == [new_rows]
    # 勾选必须还在 id="c"（现在是第 2 行），而不是留在第 0 行
    assert sel.checked_rows() == [2]


def test_pages_still_subclass_base() -> None:
    """BansPage / EventsPage 必须挂在基类上：防止未来有人复制粘贴回旧实现"""
    _qapp()
    from gui.page_bans import BansPage
    from gui.page_events import EventsPage
    from gui.table_base import BaseTablePage

    assert issubclass(BansPage, BaseTablePage)
    assert issubclass(EventsPage, BaseTablePage)
    # 旧名字不得回潮（防止两套实现并存）
    for cls in (BansPage, EventsPage):
        assert not hasattr(cls, "_setup_table")
        assert not hasattr(cls, "_toggle_row_check")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
