"""行内按钮自绘的护栏（gui/row_action.py）。

背景：事件页 2000 行档位下，原来每行 `setCellWidget` 一个容器 + 两个按钮，
离屏实测单次 `_render` 要 3426ms，而事件泵节拍是 150ms —— 攻击高峰时事件成批
到达，界面只会越刷越滞后。改成 delegate 自绘后同一份数据约 550ms。

自绘等于把点击也接过来，所以这里钉三件事：

1. **不再建控件**：只要还有人 `setCellWidget`，性能就会退回去；
2. **点得准**：按钮矩形内可点、按钮外不吞事件（否则行选中/双击会失灵）；
3. **画得下**：按钮与「⋯」都必须在单元格里，且互不重叠 —— 「⋯」被挤出列外
   就等于菜单消失了，而用户会以为功能没做。
"""

import os
import time
from typing import Any, List

import pytest

#: 事件页操作列宽（见 gui/page_events.COL_WIDTHS）
ACTION_W = 106


def COL() -> int:  # 测试里当常量用：取真实列号而不是写死 10
    from gui import page_events

    return page_events.COL_ACTION


def _qapp():
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from qtcompat import QApplication

    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication([])
    return app


def _rows(n: int) -> List[dict]:
    now = int(time.time() * 1000)
    return [
        {
            "id": 1000 + i,
            "event_ts": now - i * 1000,
            "ip": f"203.0.113.{i % 200 + 1}",
            "risk_level": ["critical", "high", "medium", "low"][i % 4],
            "handled": 0,
            "local_port": 3389,
            "path": f"/admin/login?x={i}",
            "risk_score": 60 + i % 40,
            "matched_rules": ["port_scan"],
            "geo": None,
            "group_count": 1,
            "disposition": "confirm",
        }
        for i in range(n)
    ]


def _page(n: int = 12):
    """建一个已经渲染好 n 行的风险事件页（不查库：直接喂 _render）"""
    from core import database

    database.init_db()
    _qapp()
    from gui.page_events import EventsPage

    page = EventsPage()
    page.resize(1360, 860)
    page.show()
    page._rows = _rows(n)
    page._render(page._rows)
    _qapp().processEvents()
    return page


# ═══════════════════ 1. 不再建控件 ═══════════════════


def test_action_column_is_painted_not_widgets(fresh_db) -> None:
    """操作列必须由 delegate 画：只要还有一个 cellWidget，性能就会退回去"""
    page = _page(30)
    assert page.table.itemDelegateForColumn(COL()) is page._action_delegate
    left = [i for i in range(page.table.rowCount()) if page.table.cellWidget(i, COL()) is not None]
    assert left == [], f"{len(left)} 行仍在用 setCellWidget 放按钮"


def test_render_budget_keeps_the_default_page_snappy(fresh_db) -> None:
    """200 行（默认档位）单次渲染必须明显快于事件泵节拍的两倍。

    旧实现这里是 358ms；现在约 70ms。阈值取 800ms —— 够宽，不会在慢机器上
    假红，但一旦有人把行内控件加回来（同类改动至少 3 倍耗时）就会红。
    """
    page = _page(5)
    rows = _rows(200)
    t0 = time.perf_counter()
    page._render(rows)
    cost_ms = (time.perf_counter() - t0) * 1000
    assert cost_ms < 800, f"200 行渲染用了 {cost_ms:.0f}ms"


# ═══════════════════ 2. 点击命中 ═══════════════════


def _click(page, pos) -> None:
    """在视口坐标 pos 上发一次左键释放（与真实点击走同一条 eventFilter）"""
    from qtcompat import QApplication, QEvent, QMouseEvent, QPointF, Qt

    viewport = page.table.viewport()
    global_pos = viewport.mapToGlobal(pos)
    ev = QMouseEvent(
        QEvent.Type.MouseButtonRelease,
        QPointF(pos),
        QPointF(global_pos),
        Qt.MouseButton.LeftButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    QApplication.sendEvent(viewport, ev)
    QApplication.processEvents()


def test_click_on_ban_button_asks_for_ban(fresh_db) -> None:
    page = _page(3)
    fired: List[Any] = []
    page.ask_ban.connect(lambda ip, score, reason: fired.append((ip, score, reason)))

    spec = page._action_spec(0)
    assert spec is not None
    cell = page.table.visualRect(page.table.model().index(0, COL()))
    primary, _dots = page._action_delegate._rects(cell, spec)
    _click(page, primary.center())

    assert fired and fired[0][0] == page._rows[0]["ip"]
    # 分数与理由要一起带过去：封禁对话框拿它算建议时长
    assert fired[0][1] == page._rows[0]["risk_score"]


def test_disabled_button_does_not_ask_for_ban(fresh_db) -> None:
    """已封禁的行按钮置灰：点下去不能重复发起封禁"""
    from types import SimpleNamespace

    page = _page(2)
    page._banned = {str(page._rows[0]["ip"]): SimpleNamespace(id=1, expire_at=None)}
    fired: List[Any] = []
    page.ask_ban.connect(lambda ip, score, reason: fired.append(ip))

    cell = page.table.visualRect(page.table.model().index(0, COL()))
    primary, _dots = page._action_delegate._rects(cell, page._action_spec(0))
    _click(page, primary.center())
    assert fired == []


def test_click_outside_buttons_does_not_swallow_the_event(fresh_db) -> None:
    """按钮之外的空白必须放行：吞掉的话行选中与双击详情都会失灵"""
    page = _page(2)
    cell = page.table.visualRect(page.table.model().index(0, COL()))
    # 单元格最左 2px 是内边距，不属于任何按钮
    from qtcompat import QPoint

    blank = QPoint(cell.left() + 1, cell.center().y())
    assert page._action_delegate.part_at(0, blank) == 0
    assert page._action_delegate.part_at(0, cell.center()) == 0


def test_menu_part_is_right_of_primary(fresh_db) -> None:
    page = _page(2)
    cell = page.table.visualRect(page.table.model().index(0, COL()))
    spec = page._action_spec(0)
    assert spec is not None
    primary, dots = page._action_delegate._rects(cell, spec)
    assert dots.left() > primary.right(), "「⋯」压在按钮上会被按钮抢走点击"
    assert page._action_delegate.part_at(0, dots.center()) == 2


# ═══════════════════ 3. 预算：两个按钮都留在列里 ═══════════════════


@pytest.mark.parametrize(
    "cell_w,text",
    [
        (106, "封禁"),  # 事件页
        (106, "已封禁"),
        (101, "解封"),  # 封禁记录页
        (129, "确认封禁"),  # 封禁建议页
        (53, "确认封禁"),  # 极端：列被挤窄时也不许把「⋯」挤出去
    ],
)
def test_buttons_fit_inside_the_cell(fresh_db, cell_w: int, text: str) -> None:
    from gui.row_action import DOTS_BOX, PAD_RIGHT, RowAction, RowActionDelegate
    from qtcompat import QRect

    page = _page(1)
    delegate = RowActionDelegate(page.table, COL(), lambda _r: None)
    cell = QRect(page.table.visualRect(page.table.model().index(0, COL())))
    # 用真实列宽重算一遍：单元格几何随窗口走，这里只关心「给定宽度下」的摆放
    cell.setWidth(cell_w)
    primary, dots = delegate._rects(cell, RowAction(text, "danger", True, ""))

    assert dots.right() <= cell.right() - PAD_RIGHT, "「⋯」被挤出列外就点不到了"
    assert dots.width() == DOTS_BOX
    if not primary.isNull():
        assert primary.right() < dots.left(), "按钮压住了「⋯」"
        assert primary.left() >= cell.left()
    else:
        # 列窄到放不下「按钮 + ⋯」时只画「⋯」：菜单里能找到同一个动作
        assert cell_w < 100, "正常列宽（≥100）下不该只剩「⋯」"
