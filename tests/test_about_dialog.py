"""关于页 / 快捷键帮助（gui/about_dialog.py + gui/main_window.py 的三个入口）

GUI 层此前没有单测，这里用「离屏 QApplication + 最小宿主」的方式打开一个口子：

· **不构造 MainWindow**：主窗口会连带 8 个页面、托盘图标、定时器与定位库加载
  线程，构造一次要十几秒，还会把本文件跟其他页面的改动绑在一起（它们正被
  并行修改）。三个接入点（`_build_sidebar` / `_setup_shortcuts` / `_setup_tray`）
  的方法体只用到宿主的少数回调，因此用一个最小 QWidget 替身直接调用 ——
  既真的跑到了接线代码，又不拖家带口。

· **快捷键列表必须抓得住「加页忘更新」**：`build_shortcut_rows()` 由
  `NAV_ITEMS` 动态生成，这里往 NAV_ITEMS 临时加一项，断言帮助里多一行
  （见 `test_shortcut_rows_grow_when_nav_grows`）。若哪天有人把它写死成 8 行，
  这条会红。

⚠️ 未覆盖的一处：`ClickableLabel.mouseReleaseEvent` 的真实鼠标事件没有模拟
（构造 QMouseEvent 要碰 Qt5/Qt6 构造器差异），用例走的是 `clicked` 信号
本身与它的连接 —— 事件分发那一层靠 `gui.components.ClickableStatusItem`
这个同款写法已在窗口化运行中验证。
"""

import os
from typing import Any

import pytest

from core.config import APP_VERSION, db_path, user_data_dir
from gui.about_dialog import (
    HELP_SHORTCUT_KEY,
    AboutDialog,
    ClickableLabel,
    about_summary_text,
    build_shortcut_rows,
    collect_diag_text,
    register_about_shortcut,
)
from gui.main_window import NAV_ITEMS, MainWindow
from qtcompat import (
    QApplication,
    QFont,
    QIcon,
    QKeySequence,
    QLabel,
    QPushButton,
    QShortcut,
    Qt,
    QTabWidget,
    QWidget,
)

# 这三个方法体只用到宿主的少数回调，这里刻意把它们当普通函数调用
# （标注成 Any 是告诉 mypy：不走 MainWindow 自身的 self 类型）
_BUILD_SIDEBAR: Any = MainWindow._build_sidebar
_SETUP_SHORTCUTS: Any = MainWindow._setup_shortcuts
_SETUP_TRAY: Any = MainWindow._setup_tray


@pytest.fixture(scope="module")
def qapp():
    """离屏 QApplication（GUI 用例共用；两栈都必须是 offscreen，否则 CI 无显示器）"""
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    assert isinstance(app, QApplication)
    # 与窗口化运行同一套字体度量，否则测出来的布局跟实际是两个样子
    app.setFont(QFont("Microsoft YaHei UI", 9))
    yield app


class _Host(QWidget):
    """MainWindow 的最小替身：只提供三个接入点方法体里用到的回调。"""

    # 这两个属性由三个接入点的方法体赋值（MainWindow 自身也是这个用法）。
    # 这里显式声明，是让 mypy 认得它们 —— 替身不会走 MainWindow 的 __init__。
    lbl_version: ClickableLabel
    tray: Any

    def __init__(self):
        super().__init__()
        self._app_icon = QIcon()
        self.about_opens = 0

    def _nav_slot(self, idx: int):
        return lambda _checked=False: None

    def _show_window(self) -> None:
        pass

    def _toggle_server(self) -> None:
        pass

    def _sync_xdb_now(self, force: bool = False) -> None:
        pass

    def _quit(self) -> None:
        pass

    def _show_about(self) -> None:
        self.about_opens += 1


# ═══════════════════ 纯数据层 ═══════════════════


def test_summary_text_carries_the_facts_support_asks_for():
    text = about_summary_text()
    assert APP_VERSION in text
    assert user_data_dir() in text
    assert db_path() in text
    assert "Python" in text and "图形界面" in text


def test_shortcut_rows_match_nav_items():
    rows = build_shortcut_rows(NAV_ITEMS)

    # N 个导航项 + F1 帮助
    assert len(rows) == len(NAV_ITEMS) + 1
    for i, (name, _short) in enumerate(NAV_ITEMS):
        assert rows[i] == (f"Ctrl+{i + 1}", f"切换到「{name}」")
    assert rows[-1][0] == HELP_SHORTCUT_KEY


def test_shortcut_rows_grow_when_nav_grows():
    """回归锁：加一页 → 帮助里多一行。写死成 8 行的话这条会红。"""
    base = build_shortcut_rows(NAV_ITEMS)
    grown = build_shortcut_rows([*NAV_ITEMS, ("审计日志", "审计")])

    assert len(grown) == len(base) + 1
    assert grown[-2] == ("Ctrl+9", "切换到「审计日志」")
    assert grown[-1][0] == HELP_SHORTCUT_KEY, "F1 必须留在最后一条"


def test_diag_text_is_reusable():
    report, summary = collect_diag_text()
    assert "PortGuard 环境自诊断" in report
    assert summary


# ═══════════════════ 界面层 ═══════════════════


def test_about_dialog_builds(qapp):
    dlg = AboutDialog(NAV_ITEMS)
    try:
        assert "关于" in dlg.windowTitle()
        # 两栏：关于 / 快捷键
        tab_widgets = dlg.findChildren(QTabWidget)
        assert len(tab_widgets) == 1
        assert [tab_widgets[0].tabText(i) for i in range(tab_widgets[0].count())] == [
            "关于",
            "快捷键",
        ]
        assert APP_VERSION in dlg.summary_text()
    finally:
        dlg.close()


def test_about_tabs_never_squeeze_labels(qapp):
    """回归锁：内容比对话框高时要出滚动条，而不是把文字压扁。

    离屏量测过的旧故障（最小尺寸 560x470）：`程序版本` 只剩 10px（需要 13）、
    数据目录只剩 14px（需要 42）—— QVBoxLayout 空间不够时会把所有子控件一起
    压到最小。修法是把 Tab 内容放进 QScrollArea（见 `about_dialog._scroll_page`），
    把「裁字」换成「滚动」。
    """
    dlg = AboutDialog(NAV_ITEMS)
    try:
        dlg.resize(560, 470)  # 最小尺寸＝最容易被压扁的情形
        dlg.show()
        qapp.processEvents()

        tabs = dlg.findChildren(QTabWidget)[0]
        squeezed = []
        for i in range(tabs.count()):
            tabs.setCurrentIndex(i)
            qapp.processEvents()
            page = tabs.widget(i)
            assert page is not None
            for lb in page.findChildren(QLabel):
                if not lb.text() or not lb.isVisible():
                    continue
                need = lb.heightForWidth(lb.width()) if lb.wordWrap() else lb.sizeHint().height()
                # 容 2px 度量误差：两栈字体度量差 1~2px 是常态，被压扁时差的是数量级
                if lb.height() + 2 < need:
                    squeezed.append((lb.text()[:20], lb.height(), need))
        assert not squeezed, f"被压扁的标签（文本, 实际高, 需要高）：{squeezed}"
    finally:
        dlg.close()


def test_about_dialog_copy_buttons_do_not_explode(qapp):
    """两个复制按钮：一个走纯文本，一个走 core.diag（真实执行，不 mock）"""
    dlg = AboutDialog(NAV_ITEMS)
    try:
        btns = {b.text(): b for b in dlg.findChildren(QPushButton)}
        assert "复制版本信息" in btns and "复制诊断信息" in btns

        btns["复制版本信息"].click()
        assert APP_VERSION in QApplication.clipboard().text()

        btns["复制诊断信息"].click()
        assert "PortGuard 环境自诊断" in QApplication.clipboard().text()
        assert dlg.lbl_hint.text().startswith("诊断信息已复制")
    finally:
        dlg.close()


def test_help_shortcut_is_f1(qapp):
    """F1 通过 qtcompat 注册（Qt5 在 QtWidgets、Qt6 在 QtGui，直接 import 会炸）"""
    host = QWidget()
    sc = register_about_shortcut(host)

    assert isinstance(sc, QShortcut)
    assert sc.key() == QKeySequence(HELP_SHORTCUT_KEY)

    fired = []
    sc.activated.connect(lambda: fired.append(1))
    sc.activated.emit()
    assert fired == [1]


# ═══════════════════ 三个接入点 ═══════════════════


def test_sidebar_version_label_opens_about(qapp):
    """接入点 1：侧栏底部版本号可点击"""
    host = _Host()
    _BUILD_SIDEBAR(host)

    assert isinstance(host.lbl_version, ClickableLabel)
    assert APP_VERSION in host.lbl_version.text()
    assert host.lbl_version.cursor().shape() == Qt.CursorShape.PointingHandCursor

    host.lbl_version.clicked.emit()
    assert host.about_opens == 1


def test_f1_shortcut_is_wired_in_main_window(qapp):
    """接入点 2：F1 注册在主窗口上，且触发后打开关于页"""
    host = _Host()
    _SETUP_SHORTCUTS(host)

    keys = [sc.key().toString() for sc in host.findChildren(QShortcut)]
    assert HELP_SHORTCUT_KEY in keys, f"主窗口快捷键里没有 {HELP_SHORTCUT_KEY}：{keys}"

    for sc in host.findChildren(QShortcut):
        if sc.key().toString() == HELP_SHORTCUT_KEY:
            sc.activated.emit()
    assert host.about_opens == 1


def test_tray_menu_has_about_entry(qapp):
    """接入点 3：托盘菜单里的「关于」"""
    host = _Host()
    _SETUP_TRAY(host)

    menu = host.tray.contextMenu()
    texts = [a.text() for a in menu.actions() if not a.isSeparator()]
    assert "关于" in texts, f"托盘菜单项：{texts}"

    for a in menu.actions():
        if a.text() == "关于":
            a.trigger()
    assert host.about_opens == 1
