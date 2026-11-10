"""2026-11-10 四个页面一级页签统一「胶囊分组导航」的护栏。

用户要求把设置页那种纯文字下划线 tab（图3）改成「① 分组名 + 胶囊按钮、
选中蓝底白字」（图4），并让其他带页签的页面一起统一。

实现上刻意保留原生 QTabWidget：addTab / setTabText / tabText / indexOf /
widget / setCurrentWidget / currentChanged 在四个页面、既有护栏和离屏探针里
都在用。这里钉住三件事：风格标记、分组名、以及原生接口没被弄丢。
"""

import os

from core import database
from gui.components import CapsuleTabs, capsule_tabs
from gui.theme import GLOBAL_STYLE
from qtcompat import QFrame, QLabel, QPushButton, QTabWidget, QWidget


def _qapp():
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from qtcompat import QApplication

    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    return app


def _db() -> None:
    database.init_db()


def _assert_capsule(tabs, group: str) -> None:
    assert isinstance(tabs, CapsuleTabs)
    assert tabs.objectName() == "capsule_tabs"
    # 分组名必须在圆角胶囊「框内」，不能像 corner widget 那样掉到框外
    bar = tabs.findChild(QFrame, "capsule_tabs_bar")
    assert bar is not None
    label = tabs.findChild(QLabel, "capsule_tabs_group")
    assert label is not None, "胶囊条里要有「① 分组名」"
    assert group in label.text()
    assert label.parent() is bar
    btns = tabs.findChildren(QPushButton, "capsule_tabs_btn")
    assert len(btns) == tabs.count() >= 2, "每个页签都要有对应按钮"
    # 页面管理仍由 QTabWidget 承担：既有 findChildren(QTabWidget) 的探针不用改
    assert tabs.findChildren(QTabWidget, "capsule_tabs_pages")
    assert tabs.widget(0) is not None
    assert tabs.tabText(0), "页签文字要能读"
    # 动态改标题（封禁页页签计数、规则页脏标记都靠它）必须照旧可用
    old = tabs.tabText(0)
    tabs.setTabText(0, old + "（9）")
    assert tabs.tabText(0) == old + "（9）"
    assert btns[0].text() == old + "（9）", "按钮文字要跟着 setTabText 走"
    tabs.setTabText(0, old)
    tabs.setCurrentIndex(1)
    assert tabs.currentIndex() == 1
    assert btns[1].isChecked() and not btns[0].isChecked(), "选中态要跟着页面走"


def test_capsule_tabs_factory_keeps_native_api():
    _qapp()
    tabs = capsule_tabs("设置")
    tabs.addTab(QWidget(), "服务与采集")
    tabs.addTab(QWidget(), "防护与告警")
    _assert_capsule(tabs, "设置")


def test_theme_has_capsule_qss():
    assert "#capsule_tabs_bar" in GLOBAL_STYLE
    assert "#capsule_tabs_btn:checked" in GLOBAL_STYLE
    assert "border-radius: 14px" in GLOBAL_STYLE


def test_settings_page_uses_capsule_tabs(fresh_db):
    _qapp()
    _db()
    from gui.page_settings import SettingsPage

    page = SettingsPage()
    _assert_capsule(page.tabs, "设置")


def test_bans_page_uses_capsule_tabs(fresh_db):
    _qapp()
    _db()
    from gui.page_bans import BansPage

    page = BansPage()
    _assert_capsule(page.tabs, "封禁管理")


def test_rules_page_uses_capsule_tabs(fresh_db):
    _qapp()
    _db()
    from gui.page_rules import RulesPage

    page = RulesPage()
    _assert_capsule(page.tabs, "规则配置")


def test_about_dialog_uses_capsule_tabs():
    _qapp()
    from gui.about_dialog import AboutDialog
    from gui.main_window import NAV_ITEMS

    dlg = AboutDialog(NAV_ITEMS)
    try:
        tabs = dlg.findChild(CapsuleTabs)
        assert tabs is not None
        _assert_capsule(tabs, "关于")
    finally:
        dlg.close()
