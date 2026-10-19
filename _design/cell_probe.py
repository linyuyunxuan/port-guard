"""单元格截断实测：把「文字宽度 + 内边距」和列宽逐个比对

QSS 里 `QTableView::item { padding: 0 10px }`，所以每列可用宽 = 列宽 - 20。
这里按真实字体（Consolas 12 / 雅黑 12，取单元格实际字体）算最大文字宽度，
只要 max_text + 20 > 列宽 就会出省略号 —— 不再靠看截图猜。
"""

import os
import random
import sys
import time

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

from PySide6.QtGui import QFontMetrics  # noqa: E402

from core.models import AccessRecord, GeoInfo  # noqa: E402
from qtcompat import Qt  # noqa: E402
from gui.main_window import MainWindow  # noqa: E402

PAD = 20

win = MainWindow()
win.resize(1360, 820)
win.show()
for _ in range(20):
    app.processEvents()

GEO = [
    ("113.118.113.77", "中国", "广东省", "深圳市", "电信"),
    ("223.5.5.5", "中国", "浙江省", "杭州市", "阿里云"),
    ("45.33.32.156", "美国", "加利福尼亚州", "弗里蒙特", "Linode"),
    ("185.220.101.4", "德国", "黑森州", "法兰克福", "Tor"),
]
PATHS = ["/api/products", "/admin/login", "/.env", "/wp-login.php"]
recs = []
now = int(time.time() * 1000)
for i in range(40):
    ip, c, p, ci, isp = random.choice(GEO)
    score = random.choice([0, 45, 70, 95])
    recs.append(
        AccessRecord(
            ip=ip,
            remote_port=random.randint(30000, 65000),
            local_port=random.choice([3000, 18080, 3389]),
            protocol="tcp",
            method=random.choice(["GET", "POST"]),
            path=random.choice(PATHS),
            status_code=random.choice([200, 404]),
            size=random.randint(120, 98000),
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            geo=GeoInfo(ip=ip, country=c, province=p, city=ci, isp=isp, iso="CN", found=True),
            risk_score=score,
            risk_level=("critical" if score >= 90 else "high" if score >= 65 else "medium"),
            matched_rules=["geo_sensitive_port"] if score else [],
            event_ts=now - (40 - i) * 6000,
        )
    )
win.page_monitor.append_records(recs)
for _ in range(10):
    app.processEvents()


def scan(tag: str, table, headers) -> None:
    hh = table.horizontalHeader()
    fm_cache = {}
    print(f"\n-- {tag}  vp={table.viewport().width()}")
    for c in range(hh.count()):
        width = hh.sectionSize(c)
        worst = ("", 0)
        for r in range(table.model().rowCount() if hasattr(table, "model") else table.rowCount()):
            if hasattr(table, "model"):
                idx = table.model().index(r, c)
                text = str(table.model().data(idx) or "")
                font = table.model().data(idx, Qt.ItemDataRole.FontRole)
            else:
                it = table.item(r, c)
                text = it.text() if it else ""
                font = it.font() if it else None
            if font is None:
                font = table.font()
            key = (font.pointSizeF(), font.pixelSize(), font.family())
            fm = fm_cache.get(key)
            if fm is None:
                fm = QFontMetrics(font)
                fm_cache[key] = fm
            w = fm.horizontalAdvance(text) if text else 0
            if w > worst[1]:
                worst = (text, w)
        need = worst[1] + PAD
        flag = "❌ 会截断" if need > width else "✅"
        print(f"   {headers[c]:<6} 宽={width:<4} 需={need:<4} {flag}  最长={worst[0]!r}")


for width in (1360, 1200):
    win.resize(width, 820)
    for _ in range(20):
        app.processEvents()
    print(f"\n===== 窗口 {width} =====")
    win._switch_page(0)
    for _ in range(15):
        app.processEvents()
    from gui.page_monitor import HEADERS as MH

    scan("实时监控", win.page_monitor.table, MH)

win.hide()
print("\nOK")
