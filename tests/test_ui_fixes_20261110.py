"""2026-11-10 五项界面缺陷修复的护栏。

用户原话要点：① 角标别挡功能名 + 规则触发/自动拦截要看得出来；
② 封禁管理待确认与封禁记录分页、到期/解封消息自动清理；
③ 状态栏「有 N 条待处理」在已自动拦截时改口；
④ 设置页备份明细改下拉；⑤ 子菜单分层归类统一。

这里只钉「能在无人工干预下判定」的语义：数据口径、纯文案函数、控件结构。
真实观感（列宽、遮挡、tab 视觉）由 _design/ 离屏截图另行验证。
"""

import os

from core import database
from core.models import DISPOSITION_BLOCK, DISPOSITION_CONFIRM, now_ms
from gui.mixins import STATUS_TRANSIENT_MS, risk_status_text


def _qapp():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from qtcompat import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _db():
    database.init_db()


def _insert_event(ip: str, disposition: str, handled: int = 0, level: str = "high") -> None:
    conn = database._connect()
    try:
        conn.execute(
            "INSERT INTO risk_event "
            "(ip, risk_score, risk_level, handled, disposition, event_ts) "
            "VALUES (?, 90, ?, ?, ?, ?)",
            (ip, level, handled, disposition, now_ms()),
        )
        conn.commit()
    finally:
        conn.close()


# ══════════ ③ 状态栏文案：已自动拦截不再说成待处理 ══════════


def test_status_text_all_auto_blocked():
    assert risk_status_text(30276, 0) == "已自动拦截 30276 条风险事件"


def test_status_text_auto_blocked_plus_real_pending():
    assert risk_status_text(30000, 276) == "已自动拦截 30000 条风险事件 · 另有 276 条待处理"


def test_status_text_only_pending_keeps_old_wording():
    assert risk_status_text(0, 12) == "有 12 条风险事件待处理"


def test_status_text_nothing_to_say():
    assert risk_status_text(0, 0) == ""


# ══════════ ① 数据层：自动拦截与真正待办分开统计 ══════════


def test_stats_snapshot_splits_auto_blocked_from_pending(fresh_db):
    _db()
    _insert_event("1.1.1.1", DISPOSITION_BLOCK, 0)  # 规则自动拦截，未人工确认
    _insert_event("1.1.1.2", DISPOSITION_CONFIRM, 0)  # 真正待办
    _insert_event("1.1.1.3", DISPOSITION_BLOCK, 1)  # 人工封禁后回填，不算待办
    s = database.stats_snapshot()
    assert s["unhandled"] == 2
    assert s["auto_blocked"] == 1
    assert s["pending"] == 1
    assert s["pending"] == s["unhandled"] - s["auto_blocked"]


def test_disposition_filters_are_pushed_into_sql(fresh_db):
    """筛选必须下推：limit=1 且最近一条是自动拦截时，仍能查到待处理那条。

    若在 GUI 层对结果再筛，「最近 1 条」被自动拦截占满就会得到空列表 ——
    攻击期最近 200 条可能全是自动拦截的，待办会整片消失。
    """
    _db()
    _insert_event("2.2.2.2", DISPOSITION_CONFIRM, 0)
    _insert_event("2.2.2.1", DISPOSITION_BLOCK, 0)  # 时间更晚，排在最前
    assert [r["ip"] for r in database.query_risk_events(disposition=DISPOSITION_BLOCK)] == [
        "2.2.2.1"
    ]
    assert [r["ip"] for r in database.query_risk_events(pending_only=True)] == ["2.2.2.2"]
    assert [r["ip"] for r in database.query_risk_events(limit=1, pending_only=True)] == ["2.2.2.2"]


# ══════════ ① 导航角标：为角标预留宽度，不压功能名 ══════════


def test_nav_badge_reserves_width_and_never_covers_text():
    _qapp()
    from gui.widgets import NavButton

    btn = NavButton("风险")
    base_w = btn.sizeHint().width()
    btn.set_badge(99)
    grown_w = btn.sizeHint().width()
    assert grown_w - base_w >= btn.BADGE_H + btn.BADGE_GAP

    btn.resize(btn.sizeHint())
    badge = btn.badge_rect()
    # QSS #nav_btn 是 text-align:left + padding 0 16px，文字从左边 16px 起
    text_right = 16 + btn.fontMetrics().horizontalAdvance(btn.text())
    assert badge.left() >= text_right, (badge.left(), text_right)

    btn.set_badge(0)
    assert btn.sizeHint().width() == base_w


def test_nav_badge_caps_at_99plus():
    _qapp()
    from gui.widgets import NavButton

    btn = NavButton("封禁")
    btn.set_badge(30276)
    assert btn._badge_text() == "99+"
    btn.set_badge(7)
    assert btn._badge_text() == "7"


# ══════════ ① 风险事件页：自动拦截写明状态、可单独筛出来校验 ══════════


def test_disposition_cell_distinguishes_auto_block_from_manual():
    from gui.page_events import _disposition_cell

    auto, _color, tip = _disposition_cell({"disposition": DISPOSITION_BLOCK, "handled": 0}, 0)
    assert auto == "自动拦截"
    assert "规则" in tip and "防火墙" in tip

    manual, _, _ = _disposition_cell({"disposition": DISPOSITION_BLOCK, "handled": 1}, 1)
    assert manual == "已拦截"
    pending, _, _ = _disposition_cell({"disposition": DISPOSITION_CONFIRM, "handled": 0}, 0)
    assert pending == "待确认"


def test_events_page_exposes_rule_and_pending_filters(fresh_db):
    _qapp()
    _db()
    from gui.page_events import EventsPage

    page = EventsPage()
    items = [page.handled.itemText(i) for i in range(page.handled.count())]
    assert "待人工处理" in items and "规则自动拦截" in items

    page.handled.setCurrentText("规则自动拦截")
    assert page._disposition_filter() == DISPOSITION_BLOCK
    assert page._pending_only_filter() is False
    assert page._handled_filter() == 0

    page.handled.setCurrentText("待人工处理")
    assert page._pending_only_filter() is True
    assert page._disposition_filter() == ""


# ══════════ ② 封禁管理：两块独立分页 + 一次性提示自动清理 ══════════


def test_bans_page_uses_two_tabs_not_splitter(fresh_db):
    _qapp()
    _db()
    from gui.page_bans import BansPage

    page = BansPage()
    assert page.tabs.count() == 2
    assert page.tabs.widget(0) is page.sug_panel
    assert page.tabs.widget(1) is page.ban_panel
    assert "待确认建议" in page.tabs.tabText(0)
    assert "封禁记录" in page.tabs.tabText(1)
    assert not hasattr(page, "split")


def test_bans_transient_info_restores_statistics(fresh_db):
    _qapp()
    _db()
    from gui.page_bans import BansPage

    page = BansPage()
    stats = getattr(page, "_stats_info_text", "")
    page._flash_info("已自动解封 3 个到期 IP")
    assert "已自动解封" in page.lbl_info.text()
    page._restore_info(page._info_token)
    assert page._info_token == 0
    assert page.lbl_info.text() == stats


def test_transient_status_uses_timer_and_clears(monkeypatch):
    from gui import mixins

    assert STATUS_TRANSIENT_MS > 0
    calls = {}

    def fake_single_shot(ms, fn):
        calls["ms"] = ms
        calls["fn"] = fn

    monkeypatch.setattr(mixins.QTimer, "singleShot", fake_single_shot)

    class _Label:
        def __init__(self):
            self._text = ""
            self._css = ""

        def setText(self, t):
            self._text = t

        def text(self):
            return self._text

        def setStyleSheet(self, css):
            self._css = css

    class _Host(mixins.EventPumpMixin):
        def __init__(self):
            self.lbl_status = _Label()  # type: ignore

    host = _Host()
    host._set_status("已自动解封 3 个到期 IP", auto_clear_ms=8000)
    assert calls["ms"] == 8000
    calls["fn"]()
    assert host.lbl_status.text() == "就绪"


# ══════════ ④ 设置页备份明细：下拉而不是滚动区里的表格 ══════════


def test_settings_backups_are_dropdowns(fresh_db):
    _qapp()
    _db()
    from gui.page_settings import SettingsPage
    from qtcompat import QComboBox

    page = SettingsPage()
    assert isinstance(page.cb_bak, QComboBox)
    assert isinstance(page.cb_db_bak, QComboBox)
    assert not hasattr(page, "tbl_bak")
    assert not hasattr(page, "tbl_db_bak")


def test_backup_picker_shows_selected_detail(fresh_db):
    _qapp()
    _db()
    from gui.page_settings import SettingsPage

    page = SettingsPage()
    rows = [
        {"file": "ipv4_a.bak", "path": "/a", "size": 1048576, "mtime": now_ms()},
        {"file": "ipv4_b.bak", "path": "/b", "size": 2097152, "mtime": now_ms()},
    ]
    page._bak_rows = rows
    page._bak_summary = "共 2 份"
    page._fill_backup_picker(page.cb_bak, [str(r["file"]) for r in rows])
    page.cb_bak.setCurrentIndex(1)
    page._show_bak_detail()
    assert page._picker_index(page.cb_bak) == 1
    assert "ipv4_b.bak" in page.lbl_bak.text()
    assert "共 2 份" in page.lbl_bak.text()


def test_selecting_backup_does_not_mark_settings_dirty(fresh_db):
    """选哪份备份不是设置项，不该点亮「未保存」"""
    _qapp()
    _db()
    from gui.page_settings import SettingsPage

    page = SettingsPage()
    assert page._dirty is False
    page.cb_bak.addItem("new.bak", 0)
    page.cb_bak.setCurrentIndex(page.cb_bak.count() - 1)
    assert page._dirty is False


# ══════════ ⑤ 子菜单：三层归类、统一组件与样式 ══════════


def test_settings_tabs_have_grouped_section_index(fresh_db):
    _qapp()
    _db()
    from gui.page_settings import SettingsPage

    page = SettingsPage()
    assert page._section_service.labels() == ["本机端口访问观察", "运行与守护"]
    assert page._section_guard.labels() == ["封禁策略", "告警通知"]
    assert page._section_data.labels() == ["离线库在线同步", "数据管理"]
    assert page._section_service.objectName() == "section_index"


def test_section_index_click_selects_and_emits():
    _qapp()
    from gui.components import SectionIndex

    idx = SectionIndex("① 采集与服务", ["A", "B"])
    seen = []

    def on_click(i):
        seen.append(i)

    idx.section_clicked.connect(on_click)
    idx._buttons[1].click()
    assert seen == [1]
    assert idx._buttons[1].isChecked()
    assert not idx._buttons[0].isChecked()


def test_theme_defines_unified_section_index_style():
    from gui.theme import GLOBAL_STYLE

    assert "#section_index {" in GLOBAL_STYLE
    assert "#section_index_btn:checked {" in GLOBAL_STYLE
