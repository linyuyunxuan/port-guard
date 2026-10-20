"""PortGuard — 表格列排序（数据层，纯 Python，不 import Qt）

为什么**不能**用 Qt 原生排序（`QTableWidget.setSortingEnabled(True)`）：

    `gui/table_select.py` 的 `checked_rows()` 返回的是**表格行号**，页面再拿这个
    行号当数据下标去取记录（`gui/page_events.py` 的 `_checked_rows()`、封禁页的
    `_checked_bans()`），批量封禁就是从这里拿 IP 的。Qt 原生排序只重排视图、
    不动数据缓存 —— 一旦启用，「第 3 行」就不再是 `self._rows[2]`。用户勾了
    排序后的第 3 行去「一键封禁」，写进 Windows 防火墙的是**另一条记录**的 IP。
    这是会封错 IP 的安全事故，不是显示瑕疵。

所以排序必须落在数据层：点表头 → 对数据缓存排序 → 整表重渲染。行号与数据
下标由此永远一致，顺带还绕开另外两个坑：

    · `setCellWidget` 放的行内按钮（封禁 / 解封 / 更多）在排序后是否跟着行走，
      Qt5 与 Qt6 行为有差异，不赌它；
    · `gui/widgets.py` 的 `make_item()` 写进单元格的是 `str(text)`，走 Qt 默认
      的**字符串**比较 —— `100` 会排在 `20` 前面。所以排序键必须按列声明类型
      （数值 / 时间 / 文本），而不是拿显示文本去比。

三条排序口径（缺一不可）：

    1. 空值 / 无法解析的值**升序降序都排最后**。空格子不许霸占第一屏 ——
       按评分降序时如果前 20 行全是「-」，这一列就白排了。
    2. 排序**稳定**：相同键值的记录保持后端返回的相对顺序，用户才能靠
       「上一次看到的相邻两条」定位。
    3. 三态：升序 → 降序 → 取消（回到后端原序）。取消必须能真正还原，
       所以页面要留一份未排序的源数据（`_rows_src` 之类）。

本模块不 import Qt：排序键与三态切换是纯逻辑，脱离界面即可单测（见
`tests/test_table_sort.py`）。Qt 侧的胶水在 `gui/widgets.py` 的 `SortHeader`。
"""

import datetime
from typing import Any, Callable, Dict, List, NamedTuple, Optional, Sequence, Tuple

# ── 比较类型 ──
KIND_NUM = "num"  # 数值：评分 / 端口 / ID / 次数 / 状态码
KIND_MS = "ms"  # epoch 毫秒
KIND_DATETIME = "datetime"  # `YYYY-MM-DD HH:MM[:SS]` 字符串
KIND_TEXT = "text"  # 文本：按显示（本地化后）的串比

#: 显示层用来占位「没有值」的文本。它们不是真实取值，排序时一律当空值处理。
#: `未知` 是归属地的占位（GeoInfo.region_short 在没命中时返回它），
#: 排在最前会让人以为「未知」是一个具体地区。
EMPTY_TEXTS = frozenset({"", "-", "—", "–", "未知", "N/A", "n/a"})

#: `created_at` 这类库里字符串时间的候选格式，从长到短试
_DATETIME_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d")


# ═══════════════════════════════════════════════════════════
#  取值 -> 可比较的排序键（None 表示「这条没有值」）
# ═══════════════════════════════════════════════════════════


def _as_number(value: Any) -> Optional[float]:
    """数值列。int / float / 纯数字字符串 -> float；其余（None / 空串 / 带单位）-> None。

    `bool` 显式排除：`isinstance(True, int)` 为真，但 True/False 不是可排序的量。
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        return float(text)
    except ValueError:
        return None


def _as_ms(value: Any) -> Optional[float]:
    """epoch 毫秒。`0` 视为「没有时间」：1970 不是业务上会出现的时间点，
    库里没写上的时间戳一律是 0，按 0 排会让这批记录挤在最前面。
    """
    number = _as_number(value)
    if number is None or number == 0:
        return None
    return number


def _as_datetime(value: Any) -> Optional[float]:
    """`YYYY-MM-DD HH:MM[:SS]` -> 时间戳（秒）。

    只为了排序，所以转成数字就够；不做时区换算 —— 同一列的值同源同格式，
    换算与否不改变顺序，猜错时区反而可能改变顺序。
    """
    text = str(value or "").strip()
    if not text:
        return None
    for fmt in _DATETIME_FORMATS:
        try:
            return datetime.datetime.strptime(text, fmt).timestamp()
        except ValueError:
            continue
    return None


def _as_text(value: Any) -> Optional[str]:
    """文本列：按本地化后的显示文本比（casefold 让中英文混排列不至于大小写分裂）"""
    text = str(value if value is not None else "").strip()
    if text in EMPTY_TEXTS:
        return None
    return text.casefold()


_PARSERS: Dict[str, Callable[[Any], Any]] = {
    KIND_NUM: _as_number,
    KIND_MS: _as_ms,
    KIND_DATETIME: _as_datetime,
    KIND_TEXT: _as_text,
}


# ═══════════════════════════════════════════════════════════
#  列规则与排序状态
# ═══════════════════════════════════════════════════════════


class ColumnSpec(NamedTuple):
    """一列的排序规则。

    kind   比较类型（KIND_*），决定取值怎么变成可比较的键
    get    从一行数据里取值；拿不到就返回 None / 空串（该行会排到最后）

    只对「有排序意义」的列建规则：勾选列（点了是全选）与操作列（无值）
    一律不建，点了表头也不会有反应。
    """

    kind: str
    get: Callable[[Any], Any]


class SortSpec(NamedTuple):
    """当前排序状态。`None` 表示「不排序，保持后端返回顺序」。"""

    column: int
    descending: bool


class TableSort:
    """一张表的排序状态机：点表头三态切换 + 对数据缓存排序。

    页面持有它，并把 `apply()` 的结果当作**新的数据缓存**重新渲染 ——
    这样表格行号与数据下标永远一致（见本文件开头的说明）。
    """

    def __init__(self, specs: Dict[int, ColumnSpec]) -> None:
        self._specs: Dict[int, ColumnSpec] = dict(specs)
        self.state: Optional[SortSpec] = None

    def handles(self, column: int) -> bool:
        """这一列可排序吗（不可排序的列点表头应当是「没反应」）"""
        return column in self._specs

    def click(self, column: int) -> Optional[SortSpec]:
        """点一次表头：升序 → 降序 → 取消。返回切换后的状态。

        换一列点则从头开始（升序）：用户点另一列时心里想的是「按这个重排」，
        而不是「延续上一列的升降序」。没建规则的列（勾选列 / 操作列）点了
        原样返回，不会把当前排序搞丢。
        """
        if not self.handles(column):
            return self.state
        cur = self.state
        if cur is None or cur.column != column:
            self.state = SortSpec(column, False)
        elif not cur.descending:
            self.state = SortSpec(column, True)
        else:
            self.state = None
        return self.state

    def apply(self, rows: Sequence[Any]) -> List[Any]:
        """按当前状态返回**新的行顺序**；不改动传入的序列。

        空值单独走一趟：先排有值的、再把没值的按原相对顺序接在后面 ——
        这样「空值排最后」不受升降序影响（`reverse=True` 是把整列反过来，
        单靠它做不到）。`list.sort` 本身稳定，相同键值保持原顺序。
        """
        state = self.state
        spec = None if state is None else self._specs.get(state.column)
        if state is None or spec is None:
            return list(rows)

        parse = _PARSERS[spec.kind]
        decorated: List[Tuple[int, Any]] = [(i, parse(spec.get(row))) for i, row in enumerate(rows)]
        filled = [d for d in decorated if d[1] is not None]
        missing = [d for d in decorated if d[1] is None]
        filled.sort(key=lambda d: d[1], reverse=state.descending)
        return [rows[i] for i, _ in filled] + [rows[i] for i, _ in missing]
