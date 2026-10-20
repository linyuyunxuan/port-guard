"""PortGuard — 表格列排序（gui/table_sort.py）

每条用例都对应一个「改回错误实现就会红」的具体回归，写之前先想清楚：
把实现改成错的，这条会红吗？不会红的就是无效用例，不该留在这里。

| 用例                       | 挡住的回归                                            |
|----------------------------|-------------------------------------------------------|
| 数值列 100 vs 20           | 退回字符串比较（`make_item` 写的是 `str(text)`）       |
| 空值升序降序都排最后       | 空格子霸占第一屏                                       |
| 时间列按 epoch 毫秒        | 时间被当字符串比（"9…" 会排在 "17…" 后面）             |
| 三态：升 → 降 → 取消       | 第三态不还原，用户再也回不到后端原序                   |
| 稳定性                     | 相同键值相对顺序被打乱，用户找不到刚看过的那两条       |
| 不改动传入序列             | 就地排序会让「取消排序」拿到的源数据也被排过           |
"""

from typing import Any, Dict, List

from gui.table_sort import (
    KIND_DATETIME,
    KIND_MS,
    KIND_NUM,
    KIND_TEXT,
    ColumnSpec,
    SortSpec,
    TableSort,
)


def row(rid: int, **fields: Any) -> Dict[str, Any]:
    d = {"id": rid}
    d.update(fields)
    return d


def ids(rows: List[Dict[str, Any]]) -> List[int]:
    return [int(r["id"]) for r in rows]


# 数值 / 文本 / 时间各一列，够覆盖四种比较类型
SPECS = {
    1: ColumnSpec(KIND_NUM, lambda r: r.get("score")),
    2: ColumnSpec(KIND_MS, lambda r: r.get("ts")),
    3: ColumnSpec(KIND_TEXT, lambda r: r.get("ip")),
    4: ColumnSpec(KIND_DATETIME, lambda r: r.get("created")),
}


def sorter() -> TableSort:
    return TableSort(SPECS)


# ═══════════════════════════════════════════════════════════
#  数值列：必须按数值比，不能按字符串比
# ═══════════════════════════════════════════════════════════


def test_numeric_column_orders_by_value_not_by_text() -> None:
    """20 < 100：字符串比较会得出 "100" < "20"，这正是 `make_item` 的默认值陷阱。"""
    rows = [row(1, score=100), row(2, score=20), row(3, score=9)]
    s = sorter()
    s.click(1)  # 升序
    assert ids(s.apply(rows)) == [3, 2, 1], "数值列升序必须按数值，不是按字符串"

    s.click(1)  # 降序
    assert ids(s.apply(rows)) == [1, 2, 3], "数值列降序必须按数值，不是按字符串"


def test_numeric_column_accepts_numeric_strings() -> None:
    """库里取出来的端口 / ID 有时是字符串，`"8080"` 要能当数字排。"""
    rows = [row(1, score="100"), row(2, score="20")]
    s = sorter()
    s.click(1)
    assert ids(s.apply(rows)) == [2, 1]


# ═══════════════════════════════════════════════════════════
#  空值：升序降序都排最后
# ═══════════════════════════════════════════════════════════


def test_missing_values_go_last_in_both_directions() -> None:
    """空值在两个方向都排最后。

    改成「按 (是否为空, 值) 单键 + reverse=True」的写法，降序时空值会被反到
    最前面 —— 用户按评分降序想看最危险的，结果第一屏全是「-」。
    """
    rows = [row(1, score=None), row(2, score=50), row(3), row(4, score=80)]
    s = sorter()

    s.click(1)  # 升序
    assert ids(s.apply(rows))[2:] == [1, 3], "升序：空值必须排在最后（且保持原相对顺序）"
    assert ids(s.apply(rows))[:2] == [2, 4]

    s.click(1)  # 降序
    assert ids(s.apply(rows)) == [4, 2, 1, 3], "降序：空值仍然必须排在最后"


def test_placeholder_texts_count_as_missing() -> None:
    """`-` / `未知` / 空串是显示层的占位符，不是真实取值。"""
    rows = [row(1, ip="未知"), row(2, ip=""), row(3, ip="-"), row(4, ip="8.8.8.8")]
    s = sorter()
    s.click(3)
    assert ids(s.apply(rows)) == [4, 1, 2, 3]


def test_time_zero_counts_as_missing() -> None:
    """epoch 毫秒 0 是「没写时间」，不是 1970-01-01。"""
    rows = [row(1, ts=0), row(2, ts=1700000000000), row(3, ts=None)]
    s = sorter()
    s.click(2)
    assert ids(s.apply(rows)) == [2, 1, 3]


# ═══════════════════════════════════════════════════════════
#  时间列
# ═══════════════════════════════════════════════════════════


def test_epoch_ms_column_orders_by_time_not_by_text() -> None:
    """9e11 与 1.7e12：按字符串比 "17…" < "9…"，会得出完全相反的顺序。"""
    rows = [row(1, ts=1700000000000), row(2, ts=900000000000)]
    s = sorter()
    s.click(2)
    assert ids(s.apply(rows)) == [2, 1], "epoch 毫秒必须按数值比"


def test_datetime_string_column_orders_by_time() -> None:
    """`YYYY-MM-DD HH:MM:SS` 字符串按时间排，秒数参与比较。"""
    rows = [
        row(1, created="2026-10-20 09:00:00"),
        row(2, created="2026-10-19 23:59:59"),
        row(3, created="2025-01-01 00:00:00"),
        row(4, created=""),
    ]
    s = sorter()
    s.click(4)
    assert ids(s.apply(rows)) == [3, 2, 1, 4]

    s.click(4)
    assert ids(s.apply(rows)) == [1, 2, 3, 4]


def test_unparsable_datetime_goes_last() -> None:
    """解析不了的时间串归入空值排最后。

    这条同时挡住「把 DATETIME 列当文本排」：`1970-13-45` 不是合法日期，
    按文本比它最小、会霸占第一行，按时间比它该跟空值一起沉底。
    """
    rows = [
        row(1, created="2026-10-20 09:00:00"),
        row(2, created="1970-13-45 00:00:00"),
        row(3, created="2025-01-01 00:00:00"),
    ]
    s = sorter()
    s.click(4)
    assert ids(s.apply(rows)) == [3, 1, 2]


# ═══════════════════════════════════════════════════════════
#  三态切换
# ═══════════════════════════════════════════════════════════


def test_three_state_cycle_restores_original_order() -> None:
    """升序 → 降序 → 取消，第三态必须真的回到后端原序。

    少了「取消」这态，用户点三下还是在降序里出不来。
    """
    rows = [row(1, score=50), row(2, score=100), row(3, score=20)]
    s = sorter()

    assert s.click(1) == SortSpec(1, False)
    assert ids(s.apply(rows)) == [3, 1, 2]

    assert s.click(1) == SortSpec(1, True)
    assert ids(s.apply(rows)) == [2, 1, 3]

    assert s.click(1) is None, "第三次点击必须取消排序"
    assert ids(s.apply(rows)) == [1, 2, 3], "取消排序后必须恢复后端原序"


def test_clicking_another_column_starts_from_ascending() -> None:
    """换一列点，从头开始（升序）—— 不是延续上一列的降序。"""
    rows = [row(1, score=50, ip="b"), row(2, score=100, ip="a")]
    s = sorter()
    s.click(1)
    s.click(1)  # 数值列降序
    assert s.click(3) == SortSpec(3, False)
    assert ids(s.apply(rows)) == [2, 1]


def test_column_without_spec_is_not_sortable() -> None:
    """勾选列 / 操作列点了不该有反应（也不该清掉当前排序）。"""
    s = sorter()
    s.click(1)
    assert s.handles(0) is False
    assert s.click(0) == SortSpec(1, False), "不可排序的列点了必须保持原状态"
    assert s.state == SortSpec(1, False)


# ═══════════════════════════════════════════════════════════
#  稳定性与副作用
# ═══════════════════════════════════════════════════════════


def test_sort_is_stable_for_equal_keys() -> None:
    """相同键值保持原相对顺序（升序与降序都要）。

    为了「空值排最后」而给键里塞原始下标做次级键，在 reverse=True 时会把
    相同键值的记录也反过来 —— 这条会红。
    """
    rows = [row(1, score=50), row(2, score=50), row(3, score=10), row(4, score=50)]
    s = sorter()

    s.click(1)
    assert ids(s.apply(rows)) == [3, 1, 2, 4]

    s.click(1)
    assert ids(s.apply(rows)) == [1, 2, 4, 3], "降序下相同键值的相对顺序也不能反"


def test_apply_does_not_mutate_input() -> None:
    """`apply` 必须返回新列表：页面靠未排序的源数据做「取消排序」，
    就地排序会让源数据也被排过，第三态就还原不回去了。
    """
    rows = [row(1, score=50), row(2, score=10)]
    s = sorter()
    s.click(1)
    out = s.apply(rows)
    assert ids(out) == [2, 1]
    assert ids(rows) == [1, 2], "apply 不能就地排序"

    s.click(1)
    s.click(1)  # 取消
    assert ids(s.apply(rows)) == [1, 2]


def test_unsorted_apply_returns_all_rows_as_is() -> None:
    rows = [row(1, score=50), row(2, score=10)]
    s = sorter()
    assert ids(s.apply(rows)) == [1, 2]
    assert s.apply(rows) is not rows, "即便不排序也返回副本，免得调用方拿到同一份列表"


# ═══════════════════════════════════════════════════════════
#  取值函数的健壮性
# ═══════════════════════════════════════════════════════════


def test_unparsable_numeric_text_goes_last() -> None:
    """「2 小时」这种带单位的显示文本解析不了，归入空值排最后，而不是抛异常。"""
    rows = [row(1, score="2 小时"), row(2, score=60), row(3, score="abc")]
    s = sorter()
    s.click(1)
    assert ids(s.apply(rows)) == [2, 1, 3]


def test_boolean_is_not_treated_as_number() -> None:
    """`isinstance(True, int)` 为真，但布尔不是可排序的量。"""
    rows = [row(1, score=True), row(2, score=1)]
    s = sorter()
    s.click(1)
    assert ids(s.apply(rows)) == [2, 1]


def test_text_column_is_case_insensitive() -> None:
    """国家码 `CN` / `cn` 不该因为大小写分裂成两段。"""
    rows = [row(1, ip="cn"), row(2, ip="BR"), row(3, ip="AU")]
    s = sorter()
    s.click(3)
    assert ids(s.apply(rows)) == [3, 2, 1]


def test_empty_table_is_fine() -> None:
    s = sorter()
    s.click(1)
    assert s.apply([]) == []


def test_state_defaults_to_none() -> None:
    """初始不排序：默认行为与接入前一致（后端返回什么顺序就显示什么顺序）。"""
    assert sorter().state is None
