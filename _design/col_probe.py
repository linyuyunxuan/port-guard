"""列宽实测探针：打印三张主表在 1360/1200 宽度下的实际列宽与表头最小宽

目的：定位「端口 18080 显示成 18…」与「请求 stretch 只有 155px」的真因，
而不是继续按设计稿猜数字。
"""

import os
import sys

REPO = r"C:\Users\Administrator\WorkBuddy\ip2region-3.18.0\port-guard"
sys.path.insert(0, REPO)
os.chdir(REPO)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from qtcompat import QT_API, QApplication  # noqa: E402

if QT_API == "PySide6":
    from PySide6.QtGui import QFontDatabase
else:
    from PySide2.QtGui import QFontDatabase

app = QApplication([])
QFontDatabase.addApplicationFont("C:/Windows/Fonts/msyh.ttc")
QFontDatabase.addApplicationFont("C:/Windows/Fonts/msyhbd.ttc")

from gui.main_window import MainWindow  # noqa: E402

win = MainWindow()
win.show()


def report(tag: str) -> None:
    for _ in range(25):
        app.processEvents()
    print(f"\n===== {tag} 窗口={win.width()}x{win.height()} =====")
    pages = [
        ("监控", win.page_monitor, win.page_monitor.table),
        ("事件", win.page_events, win.page_events.table),
        ("封禁记录", win.page_bans, win.page_bans.table),
        ("封禁建议", win.page_bans, win.page_bans.sug_table),
    ]
    for name, page, table in pages:
        if not table.isVisible():
            print(f"-- {name}: 不可见，跳过")
            continue
        t = table
        hh = t.horizontalHeader()
        vp = t.viewport().width()
        sizes = [hh.sectionSize(i) for i in range(hh.count())]
        mins = [hh.sectionSizeHint(i) for i in range(hh.count())]
        print(f"-- {name}: viewport={vp} 合计={sum(sizes)} 横滚={t.horizontalScrollBar().isVisible()}")
        print(f"   实际 {sizes}")
        print(f"   表头最小建议 {mins}")


for idx, (tag, w) in enumerate([("1360", 1360), ("1200", 1200)]):
    win.resize(w, 820)
    win.page_monitor.table.parentWidget()
    # 逐页切过去，让每张表都完成布局
    for i in range(7):
        win._switch_page(i)
    report(tag)
    # 逐表单独测（切页后其它表不可见，尺寸仍有效）
    for i, nm in enumerate(["监控", "事件", "封禁", "规则", "查询", "日志", "设置"]):
        win._switch_page(i)
        for _ in range(25):
            app.processEvents()
        t = None
        if i == 0:
            t = win.page_monitor.table
        elif i == 1:
            t = win.page_events.table
        elif i == 2:
            t = win.page_bans.table
        if t is not None:
            hh = t.horizontalHeader()
            sizes = [hh.sectionSize(k) for k in range(hh.count())]
            print(f"   [{tag}] {nm}: vp={t.viewport().width()} 合计={sum(sizes)} {sizes}")

win.hide()
print("\nOK")
