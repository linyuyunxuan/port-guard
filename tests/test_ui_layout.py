"""界面预算与刷新反馈的护栏。

用户主诉过两句：「表单页右边一大片空白」「表格里路径被截成 `POST /admi…`」。
这类问题不是配色问题，是**预算问题** —— 列宽合计超过表格视口、内容列没有
上限，肉眼看只是「有点空 / 有点挤」，改错了不会有任何用例变红。所以这里把
三件事钉成数字：

1. 表格「固定列合计」必须留得下唯一的拉伸列 —— 它被挤到 20px 时，右上角的
   路径就只剩三个字符，而 tooltip 之外没有任何补救；
2. 表单类页面（规则 / 设置）的内容列有上限，不再铺满整页；
3. 列表页刷新要给出「正在刷新…」与「更新于 HH:MM:SS」两种状态，且不吞异常。

数字来源：1360×860（README 配图尺寸）下表格视口实测 1099（监控 / 事件）
与 1097（封禁记录）。窗口尺寸一动，这些预算就要跟着改 —— 所以断言写成
「视口 − 固定列」，而不是写死某列宽。
"""

import os
from typing import Any, List

import pytest

#: 1360×860 下表格视口宽（去掉侧栏 194、页边距、竖滚动条后实测）
VIEWPORT = 1099


def _qapp():
    """GUI 用例统一入口：离屏 + 复用同一个 QApplication"""
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from qtcompat import QApplication

    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication([])
    return app


def _stretch_width(widths: List[int], idx: int, viewport: int = VIEWPORT) -> int:
    """Stretch 列实际能拿到的宽度 = 视口 − 其它列之和"""
    return viewport - (sum(widths) - widths[idx])


# ═══════════════════ 1. 列宽预算：拉伸列必须留得住 ═══════════════════


def test_monitor_request_column_holds_full_path() -> None:
    """监控页「请求」列要放得下 `POST /api/v1/orders/search`（实测需 205）。

    旧配置固定列合计 1151 > 视口 1099，请求列只剩 121，
    `POST /admin/login` 直接显示成 `POST /admi…` —— 除了右键菜单，
    界面上根本看不出这次访问请求了什么。
    """
    from gui import page_monitor

    got = _stretch_width(page_monitor.COL_WIDTHS, page_monitor.COL_REQUEST)
    assert got >= 200, f"请求列只剩 {got}px，又会把方法+路径截成省略号"


def test_monitor_disposition_column_fits_three_chars() -> None:
    """处置列要放得下「仅提醒 / 已拦截 / 待确认」（三字 + 内边距约 65）。

    56 与 62 都被截成「仅…」过 —— Qt 的 item 内边距比 QSS 写的 10px 更大，
    所以这里按 65 卡下限，别再手调到 60 附近。
    """
    from gui import page_monitor

    assert page_monitor.COL_WIDTHS[page_monitor.COL_DISPOSITION] >= 65


def test_events_path_and_action_columns_keep_their_content() -> None:
    """事件页：路径列 ≥ 110（`/api/v1/orders/search` 的正文），
    操作列 ≥ 100（行内「封禁」+「⋯」两个按钮，96 时第二个被裁掉）。"""
    from gui import page_events

    path_w = _stretch_width(page_events.COL_WIDTHS, page_events.COL_PATH)
    assert path_w >= 110, f"路径列只剩 {path_w}px"
    assert page_events.COL_WIDTHS[page_events.COL_ACTION] >= 100


def test_bans_reason_column_fits_auto_reason() -> None:
    """封禁记录：原因列要放得下 `[自动] 命中规则：判定风险：1024`（实测需 234）"""
    from gui import page_bans

    reason_w = _stretch_width(page_bans.BAN_WIDTHS, page_bans.COL_BAN_REASON, 1097)
    assert reason_w >= 240, f"原因列只剩 {reason_w}px，每条记录的原因都会被截"
    # 2026-10-23 加归属地列后，「时长」列被删掉腾空间（它是到期-创建的冗余）；
    # 这两条钉住新增列与邻居的宽度，别在后续调列时把归属地挤成省略号。
    assert page_bans.BAN_HEADERS[page_bans.COL_BAN_GEO] == "归属地"
    assert page_bans.BAN_WIDTHS[page_bans.COL_BAN_GEO] >= 110, "归属地列放不下「河南省 焦作市」"
    # 来源列 50 时「自动」被渲染成「自…」：QFontMetrics 量出来够，
    # 实际还差省略号的位置，所以按 56 卡（列索引随归属地列右移）
    assert page_bans.BAN_WIDTHS[5] >= 56


# ═══════════════════ 2. 表单内容列限宽 ═══════════════════


def test_form_cards_are_capped_to_content_column(fresh_db) -> None:
    """规则卡与设置面板都必须限宽，否则 1360 下右侧空出三四百像素。

    限宽之后还要靠 `AlignHCenter` 才会居中 —— 只限宽不居中的话卡片全部贴左，
    看起来像「少画了一半」，比原来更糟。这里一并钉住对齐方式。
    """
    from gui.page_rules import RuleCard
    from gui.page_settings import _Panel
    from gui.widgets import CONTENT_MAX_W

    _qapp()
    assert RuleCard("port_scan", {}).maximumWidth() == CONTENT_MAX_W
    assert _Panel("测试面板").maximumWidth() == CONTENT_MAX_W


def test_scroll_page_centers_its_children(fresh_db) -> None:
    """设置页每个 tab 的内容容器必须水平居中，否则限宽卡片会全部贴左"""
    from gui.page_settings import SettingsPage
    from qtcompat import Qt

    _qapp()
    # _scroll_page 是静态方法，直接调用即可拿到 (area, layout)
    _area, lay = SettingsPage._scroll_page()
    assert lay.alignment() == Qt.AlignmentFlag.AlignHCenter


# ═══════════════════ 3. 刷新中间态 ═══════════════════


def test_refresh_guard_shows_busy_then_stamps_time(fresh_db) -> None:
    """刷新期间显示「正在刷新…」，结束后在结果文案后补「更新于 HH:MM:SS」"""
    from gui.widgets import RefreshGuard
    from qtcompat import QLabel

    _qapp()
    lbl = QLabel("")
    guard = RefreshGuard(lbl)
    with guard:
        assert guard.busy is True
        assert lbl.text() == "正在刷新…"
        lbl.setText("共 3 条")
    assert guard.busy is False
    assert lbl.text().startswith("共 3 条 · 更新于 ")
    # 时间戳是 HH:MM:SS（8 字符），一眼能看出「刚刷过」
    assert len(lbl.text().rsplit(" ", 1)[-1]) == 8


def test_refresh_guard_stamps_even_if_body_wrote_nothing(fresh_db) -> None:
    """页面没写结果文案时只挂时间戳，不能留下「正在刷新…」变成永久状态"""
    from gui.widgets import RefreshGuard
    from qtcompat import QLabel

    _qapp()
    lbl = QLabel("")
    with RefreshGuard(lbl):
        pass
    assert lbl.text().startswith("更新于 ")
    assert "正在刷新" not in lbl.text()


def test_refresh_guard_does_not_swallow_exceptions(fresh_db) -> None:
    """查询抛异常时必须继续往上抛：吞掉会变成「界面没反应」，查不出根因"""
    from gui.widgets import RefreshGuard
    from qtcompat import QLabel

    _qapp()
    guard = RefreshGuard(QLabel(""))
    with pytest.raises(ValueError), guard:
        raise ValueError("boom")
    assert guard.busy is False


def test_list_pages_reuse_one_guard(fresh_db, monkeypatch) -> None:
    """三个列表页的 refresh 都要有守卫：重入时直接返回，不再叠一次查询"""
    from core import database

    database.init_db()
    _qapp()

    from gui.page_access import AccessPage
    from gui.page_bans import BansPage
    from gui.page_events import EventsPage

    for cls in (AccessPage, EventsPage, BansPage):
        page = cls()
        assert hasattr(page, "_refresh"), f"{cls.__name__} 没有接刷新守卫"
        page._refresh.busy = True
        calls: List[Any] = []
        # busy 状态下 refresh 必须直接返回：内部查询一次都不该发生
        # 默认参数绑住 calls：否则闭包捕获的是循环变量（ruff B023）。
        # 这里不是 Qt 槽，默认参数不会踩「PySide2 只传 0 参」那个坑。
        if cls is AccessPage or cls is EventsPage:
            monkeypatch.setattr(page, "_load", lambda _c=calls: _c.append(1))
        else:
            monkeypatch.setattr(page, "_load_suggestions", lambda _c=calls: _c.append(1))
        page.refresh()
        assert calls == [], f"{cls.__name__} 在 busy 状态下仍然发起了查询"


# ═══════════════════ 4. IP 查询的单条结果 ═══════════════════


def test_iplookup_single_result_is_a_field_grid(fresh_db) -> None:
    """单条查询结果必须是四个固定字段，不是一句拼起来的长文本。

    拼长文本时字段边界全靠全角空格，长 IPv6 归属地一超宽整句换行，
    读的时候要拿手指对位置；拆成固定格后位置稳定、值能单独选中复制。
    """
    _qapp()

    from gui.page_iplookup import IpLookupPage

    page = IpLookupPage()
    assert set(page._single_vals) == {"region", "iso", "isp", "scope"}
    # 私有标签与 selftest 用的 single_result 是同一个对象（主值 = 归属地）
    assert page.single_result is page._single_vals["region"]
    # 没查之前四格都是占位符，不是残留上一次的结果
    assert all(v.text() == "—" for v in page._single_vals.values())

    page.single.setText("10.0.0.1")
    page._query_single()
    # 内置库把 10.0.0.0/8 归成 Reserved 而不是「未命中」，
    # 所以这里只钉「四格都被填上了」与「范围是二选一」
    assert page._single_vals["region"].text() not in ("", "—")
    assert page._single_vals["scope"].text() in ("境内", "境外")


# ═══════════════════ 4. 封禁记录归属地列 ═══════════════════


def test_ban_geo_is_attached_for_ip_and_network() -> None:
    """封禁记录渲染前必须算好归属地：IP 按自身查、网段按网段地址查。

    没这一步，「归属地」列会整列空白 —— 而空白看起来像「这列还没做」，
    用户不会想到去查是不是数据没接上。
    """
    from core.models import BanRecord
    from gui import page_bans

    rows = [BanRecord(ip="203.0.113.7"), BanRecord(ip="198.51.100.0/24")]
    page_bans.BansPage._attach_geo(rows)

    assert rows[0].geo is not None
    assert rows[0].geo_is_network is False
    # 网段条目：按网段地址查，并标记出来（tooltip 里会说明）
    assert rows[1].geo is not None
    assert rows[1].geo_is_network is True
    # 渲染取的是 region_short；查不到时它给「未知」而不是空串
    assert isinstance(rows[0].geo.region_short, str) and rows[0].geo.region_short
