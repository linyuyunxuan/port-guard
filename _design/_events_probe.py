"""风险事件页新功能的离屏验证：勾选列 / 全选 / 批量条 / 时间筛选。

用法：python _design/_events_probe.py
输出：_design/after/8_events_batch_1360.png / 1200.png + 控制台断言
"""

import os
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
os.chdir(REPO)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from qtcompat import QT_API, QApplication, QFont, QtGui  # noqa: E402

if QT_API == "PySide6":
    from PySide6.QtGui import QFontDatabase
else:
    from PySide2.QtGui import QFontDatabase

app = QApplication([])

# 与 main.py 同款字体：不设的话量出来的是 Qt 默认字体，两栈差 40%
app.setFont(QFont("Microsoft YaHei UI", 9))
QFontDatabase.addApplicationFont("C:/Windows/Fonts/msyh.ttc")
QFontDatabase.addApplicationFont("C:/Windows/Fonts/msyhbd.ttc")

import gui.page_events as pe  # noqa: E402
from core.models import GeoInfo  # noqa: E402
from gui.main_window import MainWindow  # noqa: E402

OUT = os.path.join(REPO, "_design", "after")
os.makedirs(OUT, exist_ok=True)

NOW = int(time.time() * 1000)
CALLS = []


def fake_query(**kwargs):
    CALLS.append(kwargs)
    rows = []
    for i in range(28):
        foreign = i % 3 != 0
        rows.append(
            {
                "id": 1000 + i,
                "event_ts": NOW - i * 3_600_000,
                "risk_level": "critical" if foreign else "medium",
                "risk_score": 100 if foreign else 45,
                "ip": "133.118.113.177" if i % 2 else "113.118.113.77",
                "local_port": 3000 if i % 2 else 3389,
                "path": "/admin/login" if i % 2 else "/api/orders/1024",
                "matched_rules": ["geo_sensitive_port"],
                "handled": 0 if i % 4 else 2,
                "summary": "境外来源访问管理端口（境内范围）" if foreign else "扫描器特征",
                "geo": GeoInfo(
                    ip="133.118.113.177",
                    country="美国" if foreign else "中国",
                    province="加利福尼亚州" if foreign else "广东省",
                    city="弗里蒙特" if foreign else "深圳市",
                    isp="Linode",
                    iso="US" if foreign else "CN",
                    found=True,
                ),
            }
        )
    return rows


pe.query_risk_events = fake_query

win = MainWindow()
win.show()
win._switch_page(1)
page = win.page_events
page.refresh()
for _ in range(15):
    app.processEvents()

rows = page.table.rowCount()
assert rows == 28, f"行数不对：{rows}"
assert page.table.columnCount() == 11, page.table.columnCount()
assert page.table.item(0, pe.COL_CHECK) is not None, "勾选列没有 item"
assert page.table.horizontalHeaderItem(pe.COL_CHECK) is not None, "表头没有全选方框"

# 默认：一个都没勾，批量按钮必须禁用
assert page.lbl_sel.text() == "已选 0 条", page.lbl_sel.text()
assert not page.btn_ban.isEnabled(), "没勾选时「一键封禁」应为禁用"

# 勾一条 → 计数与可用状态跟着变
page.table.item(3, pe.COL_CHECK).setCheckState(pe.Qt.CheckState.Checked)
app.processEvents()
assert page.lbl_sel.text() == "已选 1 条", page.lbl_sel.text()
assert page.btn_ban.isEnabled(), "勾选后批量按钮应可用"

# 全选 / 取消全选
page.sel.set_all(True)
app.processEvents()
assert len(page._checked_rows()) == rows, "全选失败"
assert page.btn_sel_all.text() == "取消全选", page.btn_sel_all.text()
page.sel.set_all(False)
app.processEvents()
assert len(page._checked_rows()) == 0, "取消全选失败"
assert page.btn_sel_all.text() == "全选本页", page.btn_sel_all.text()

# 批量封禁按 IP 去重：28 行只有 2 个不同 IP
# 必须先断掉到 MainWindow 的连线——真实槽在非管理员时会弹模态框，离屏下会挂死
captured = {}
page.ask_ban_many.disconnect()
page.ask_ban_many.connect(lambda items: captured.setdefault("items", items))
page.sel.set_all(True)
page._batch_ban()
items = captured.get("items") or []
assert len(items) == 2, f"应按 IP 去重成 2 个，实际 {len(items)}"
assert {it["ip"] for it in items} == {"133.118.113.177", "113.118.113.77"}, items

# 时间筛选：切到「近 7 天」必须把 since/until 传下去，且是左闭右开
CALLS.clear()
page.range.setCurrentIndex(pe.RANGE_CHOICES.index(pe.RANGE_7D))
app.processEvents()
since, until = page._range_ms()
assert since is not None and until is not None, (since, until)
assert until - since == 7 * 86400 * 1000, (until - since) / 86400000
assert CALLS and CALLS[-1].get("since_ts") == since, CALLS[-1]

# 自定义：日期填反要自动纠正，不能返回空区间
CALLS.clear()
page.range.setCurrentIndex(pe.RANGE_CHOICES.index(pe.RANGE_CUSTOM))
app.processEvents()
assert page.dt_from.isVisible() or not win.isVisible(), "自定义应显示日期框"
page.dt_to.setDate(page.dt_to.date().addDays(-10))
page.dt_from.setDate(page.dt_from.date())
app.processEvents()
s2, u2 = page._range_ms()
assert s2 is not None and u2 is not None and s2 < u2, (s2, u2)

# 自定义日期要能看见两个日期框，且 1200 宽下工具栏不能溢出
win.resize(1200, 820)
for _ in range(20):
    app.processEvents()
page.range.setCurrentIndex(pe.RANGE_CHOICES.index(pe.RANGE_CUSTOM))
for _ in range(20):
    app.processEvents()
assert page.dt_from.isVisible(), "自定义模式应显示开始日期框"
assert page.dt_to.isVisible(), "自定义模式应显示结束日期框"
filters_right = page.dt_to.mapTo(win, page.dt_to.rect().bottomRight()).x()
assert filters_right <= win.width() - 24, f"工具栏溢出：{filters_right} > {win.width() - 24}"
custom_shot = os.path.join(OUT, "1200_8b_events_custom.png")
win.grab().save(custom_shot)
print("saved", custom_shot)

# 回到「全部时间」再截图（截图里要看到完整数据 + 勾选态）
page.range.setCurrentIndex(0)
page.sel.set_all(True)
for _ in range(15):
    app.processEvents()

def report_cols(tbl, label: str) -> int:
    """逐列比对「最大文字宽 + padding + 余量」与列宽，返回「不该截却截了」的列数。

    余量 8px 是实测出来的：文字宽刚好等于「列宽-16」时 Qt 仍会画省略号
    （focus 边框与 item margin 还各要几个像素），只减 16 会漏判。
    内容无界的列（路径 / 命中规则）允许省略号——但前提是每格都带 tooltip，
    否则用户没有别的办法看到完整值，那才是真缺陷。
    """
    pad = 16
    safety = 8
    bad = 0
    print(f"-- {label}: 表宽={tbl.width()} 视口={tbl.viewport().width()}")
    for c in range(tbl.columnCount()):
        widest, sample, tips = 0, "", []
        for r in range(tbl.rowCount()):
            it = tbl.item(r, c)
            if it is None:
                continue
            tips.append(bool(it.toolTip()))
            w = QtGui.QFontMetrics(it.font()).horizontalAdvance(it.text())
            if w > widest:
                widest, sample = w, it.text()
        avail = tbl.columnWidth(c) - pad
        truncated = widest > avail - safety
        elide_ok = c in pe.ELIDE_OK_COLS
        if truncated and elide_ok and not all(tips):
            bad += 1
            flag = "NOTIP"
        elif truncated and elide_ok:
            flag = "elide"
        elif truncated:
            bad += 1
            flag = "TRUNC"
        else:
            flag = "ok"
        print(
            f"   col{c:2d} 列宽={tbl.columnWidth(c):3d} 可用={avail:3d} "
            f"最宽={widest:3d} {flag:5s} {sample[:26]}"
        )
    print("   横向滚动条:", tbl.horizontalScrollBar().isVisible())
    return bad


for tag, width in (("", 1360), ("1200_", 1200)):
    win.resize(width, 820)
    for _ in range(20):
        app.processEvents()
    bad = report_cols(page.table, f"{width}px")
    assert bad == 0, f"{width}px 下有 {bad} 列内容被截断且没有 tooltip 兜底"
    assert not page.table.horizontalScrollBar().isVisible(), f"{width}px 出现横向滚动条"
    path = os.path.join(OUT, f"{tag}8_events_batch.png")
    win.grab().save(path)
    print("saved", path)

win.hide()
print("OK 事件页批量功能自检通过")
