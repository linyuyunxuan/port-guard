"""封禁管理页批量处理的离屏验证：勾选列 / 全选 / 批量封禁去重 / 批量忽略 / 批量删除。

用法：python _design/_bans_probe.py
输出：_design/after/9_bans_batch_1360.png / 1200_9_bans_batch.png + 控制台断言
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

import gui.page_bans as pb  # noqa: E402
from core.models import (  # noqa: E402
    STATUS_ACTIVE,
    STATUS_FAILED,
    STATUS_UNBANNED,
    BanRecord,
    GeoInfo,
)
from gui.main_window import MainWindow  # noqa: E402

OUT = os.path.join(REPO, "_design", "after")
os.makedirs(OUT, exist_ok=True)
NOW = int(time.time() * 1000)


def fake_suggestions(**kwargs):
    rows = []
    for i in range(9):
        rows.append(
            {
                "id": 2000 + i,
                "event_ts": NOW - i * 600_000,
                "risk_level": "critical" if i % 2 else "high",
                "risk_score": 100 - i,
                # 9 条建议只落 3 个 IP：批量封禁必须去重
                "ip": ["133.118.113.177", "113.118.113.77", "8.8.8.8"][i % 3],
                "local_port": 3389 if i % 2 else 3000,
                "summary": "境外来源访问管理端口 · 累计 12 次命中",
                "handled": 0,
                "geo": GeoInfo(
                    ip="45.33.32.156",
                    country="美国",
                    province="加利福尼亚州",
                    city="弗里蒙特",
                    isp="Linode",
                    iso="US",
                    found=True,
                ),
            }
        )
    return rows


def fake_bans(**kwargs):
    out = []
    for i in range(14):
        status = [STATUS_ACTIVE, STATUS_UNBANNED, STATUS_FAILED][i % 3]
        out.append(
            BanRecord(
                id=500 + i,
                ip=["133.118.113.177", "113.118.113.77", "8.8.8.8"][i % 3],
                rule_name="geo_sensitive_port",
                reason="管理端口归属地检测 · 评分 100",
                risk_score=100 - i,
                source=["auto", "manual", "suggest"][i % 3],
                status=status,
                duration_sec=None if i % 2 else 86400 * 365,
                expire_at=None if i % 2 else NOW + 86400 * 1000,
                created_at="2026-10-19 16:29:57",
            )
        )
    return out


pb.query_risk_events = fake_suggestions
pb.query_bans = fake_bans
pb.count_active_bans = lambda: 5

# 批量解封会真的去动防火墙，离屏下没有管理员权限 → 整套替身
UNBAN_CALLS = []
pb.firewall.is_admin = lambda: True
pb.ban_service.unban = lambda b: (UNBAN_CALLS.append(b.id) or (True, ""))

HANDLED = []
pb.set_risk_handled_batch = lambda ids, h: (HANDLED.append((list(ids), h)) or len(ids))

DELETED = []


def fake_delete(ids):
    DELETED.append(list(ids))
    return len(ids)


pb.delete_ban_records = fake_delete

# 批量删除 / 批量解封都会弹确认框，离屏下模态框会挂死 → 一律自动「是」
pb.QMessageBox.question = staticmethod(lambda *a, **k: pb.QMessageBox.StandardButton.Yes)
pb.QMessageBox.information = staticmethod(lambda *a, **k: None)
pb.QMessageBox.warning = staticmethod(lambda *a, **k: None)

win = MainWindow()
win.show()
win._switch_page(2)
for _ in range(10):
    app.processEvents()
page = win.page_bans
page.refresh()
for _ in range(20):
    app.processEvents()

sug_rows = page.sug_table.rowCount()
ban_rows = page.table.rowCount()
assert sug_rows == 9, f"建议行数不对：{sug_rows}"
assert ban_rows == 14, f"封禁行数不对：{ban_rows}"

# ── 结构断言 ──
assert page.sug_table.columnCount() == len(pb.SUG_HEADERS), page.sug_table.columnCount()
assert page.table.columnCount() == len(pb.BAN_HEADERS), page.table.columnCount()
assert page.sug_table.item(0, pb.COL_SUG_CHECK) is not None, "建议表没有勾选格子"
assert page.table.item(0, pb.COL_BAN_CHECK) is not None, "记录表没有勾选格子"
assert page.sug_table.horizontalHeaderItem(pb.COL_SUG_CHECK) is not None, "建议表头缺全选框"
assert page.table.horizontalHeaderItem(pb.COL_BAN_CHECK) is not None, "记录表头缺全选框"

# ── 未勾选：动作按钮禁用，「全选」必须始终可点 ──
assert page.lbl_sug_sel.text() == "已选 0 条", page.lbl_sug_sel.text()
assert page.lbl_ban_sel.text() == "已选 0 条", page.lbl_ban_sel.text()
assert not page.btn_sug_ban.isEnabled(), "未勾选时「批量封禁」应禁用"
assert not page.btn_sug_ignore.isEnabled(), "未勾选时「批量忽略」应禁用"
assert not page.btn_ban_unban.isEnabled(), "未勾选时「批量解封」应禁用"
assert not page.btn_ban_del.isEnabled(), "未勾选时「删除记录」应禁用"
assert page.btn_sug_all.isEnabled(), "「全选」不该跟着勾选态被禁用"
assert page.btn_ban_all.isEnabled(), "「全选本页」不该跟着勾选态被禁用"

# ── 点「全选」按钮（不是直接调 API）：计数、表头三态、按钮可用 ──
page.btn_sug_all.click()
for _ in range(4):
    app.processEvents()
assert len(page._checked_suggestions()) == sug_rows, len(page._checked_suggestions())
assert page.lbl_sug_sel.text() == f"已选 {sug_rows} 条", page.lbl_sug_sel.text()
assert page.btn_sug_ban.isEnabled(), "全选后「批量封禁」应可用"
assert page.btn_sug_all.text() == "取消全选", page.btn_sug_all.text()
assert (
    page.sug_table.horizontalHeaderItem(0).checkState() == pb.Qt.CheckState.Checked
), "全选后表头方框应为已勾"

page.btn_sug_all.click()
for _ in range(4):
    app.processEvents()
assert len(page._checked_suggestions()) == 0, "再点一次应取消全选"
assert (
    page.sug_table.horizontalHeaderItem(0).checkState() == pb.Qt.CheckState.Unchecked
), "取消全选后表头方框应为未勾"

# 勾一半：表头必须是「部分勾选」，不能假装成已全选
page.sug_table.item(2, pb.COL_SUG_CHECK).setCheckState(pb.Qt.CheckState.Checked)
for _ in range(4):
    app.processEvents()
assert (
    page.sug_table.horizontalHeaderItem(0).checkState() == pb.Qt.CheckState.PartiallyChecked
), "只勾了一部分时表头应为半选态"

# ── 批量封禁：9 条建议 → 3 个 IP ──
captured = {}
page.ask_ban_many.disconnect()
page.ask_ban_many.connect(lambda items: captured.setdefault("items", items))
page.btn_sug_all.click()
for _ in range(4):
    app.processEvents()
page.btn_sug_ban.click()
for _ in range(4):
    app.processEvents()
items = captured.get("items") or []
assert len(items) == 3, f"应按 IP 去重成 3 个，实际 {len(items)}"
assert {it["ip"] for it in items} == {"133.118.113.177", "113.118.113.77", "8.8.8.8"}, items
assert sum(len(it["event_ids"]) for it in items) == sug_rows, "封禁后要能回填全部事件状态"

# ── 批量忽略：一次事务里把选中 id 全标成 2 ──
HANDLED.clear()
page.btn_sug_ignore.click()
for _ in range(4):
    app.processEvents()
assert HANDLED and sorted(HANDLED[0][0]) == sorted(2000 + i for i in range(sug_rows)), HANDLED
assert HANDLED[0][1] == 2, "批量忽略的 handled 值应为 2"

# ── 记录表：全选后批量删除，只删数据库记录 ──
page.btn_ban_all.click()
for _ in range(4):
    app.processEvents()
assert len(page._checked_bans()) == ban_rows, len(page._checked_bans())
assert page.btn_ban_del.isEnabled(), "全选后「删除记录」应可用"
DELETED.clear()
page.btn_ban_del.click()
for _ in range(4):
    app.processEvents()
assert DELETED and sorted(DELETED[0]) == sorted(500 + i for i in range(ban_rows)), DELETED

# ── 批量解封：只有「已封禁」的记录参与，且不碰别的状态 ──
page.refresh()
for _ in range(10):
    app.processEvents()
page.btn_ban_all.click()
for _ in range(4):
    app.processEvents()
active = [b for b in page._checked_bans() if b.status == STATUS_ACTIVE]
expect_active = [500 + i for i in range(ban_rows) if i % 3 == 0]
UNBAN_CALLS.clear()
page._batch_unban()
# 解封在后台线程串行跑，轮询等它把结果发回来
for _ in range(120):
    app.processEvents()
    if len(UNBAN_CALLS) >= len(expect_active):
        break
    time.sleep(0.05)
assert len(active) == len(expect_active), (len(active), len(expect_active))
assert sorted(UNBAN_CALLS) == expect_active, UNBAN_CALLS


def report_cols(tbl, label, elide_ok=()):
    """逐列比对「最大文字宽 + padding + 余量」与列宽。"""
    pad, safety = 16, 8
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
        if truncated and c in elide_ok and all(tips):
            flag = "elide"
        elif truncated:
            flag = "TRUNC"
            bad += 1
        else:
            flag = "ok"
        print(
            f"   col{c:2d} 列宽={tbl.columnWidth(c):3d} 可用={avail:3d} "
            f"最宽={widest:3d} {flag:5s} {sample[:24]}"
        )
    print("   横向滚动条:", tbl.horizontalScrollBar().isVisible())
    return bad


for tag, width in (("", 1360), ("1200_", 1200)):
    win.resize(width, 820)
    for _ in range(20):
        app.processEvents()
    bad = report_cols(page.sug_table, f"{width}px 建议表", elide_ok=(pb.COL_SUG_REASON,))
    bad += report_cols(page.table, f"{width}px 记录表", elide_ok=(pb.COL_BAN_REASON,))
    assert bad == 0, f"{width}px 下有 {bad} 列内容被截断且没有 tooltip 兜底"
    assert not page.table.horizontalScrollBar().isVisible()
    assert not page.sug_table.horizontalScrollBar().isVisible()
    path = os.path.join(OUT, f"{tag}9_bans_batch.png")
    win.grab().save(path)
    print("saved", path)

win.hide()
print("OK 封禁页批量功能自检通过")
