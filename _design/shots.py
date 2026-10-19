"""离屏渲染全部页面（1360 与 1200 两档），用于设计复核与截断检查

用法：QT_QPA_PLATFORM=offscreen python _design/shots.py
输出：_design/after/<n>_<page>.png 与 _design/after/1200_<n>_<page>.png
"""

import os
import random
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
os.chdir(REPO)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from qtcompat import QT_API, QApplication  # noqa: E402

if QT_API == "PySide6":
    from PySide6.QtGui import QFontDatabase
else:
    from PySide2.QtGui import QFontDatabase

app = QApplication([])
# 必须在 QApplication 之后加载字体，否则离屏下中文全是方块
QFontDatabase.addApplicationFont("C:/Windows/Fonts/msyh.ttc")
QFontDatabase.addApplicationFont("C:/Windows/Fonts/msyhbd.ttc")

from core.models import AccessRecord, GeoInfo  # noqa: E402
from gui.main_window import MainWindow  # noqa: E402

OUT = os.path.join(REPO, "_design", "after")
os.makedirs(OUT, exist_ok=True)

GEO = [
    ("113.118.113.77", "中国", "广东省", "深圳市", "电信"),
    ("223.5.5.5", "中国", "浙江省", "杭州市", "阿里云"),
    ("1.192.0.1", "中国", "河南省", "郑州市", "联通"),
    ("45.33.32.156", "美国", "加利福尼亚州", "弗里蒙特", "Linode"),
    ("185.220.101.4", "德国", "黑森州", "法兰克福", "Tor"),
    ("103.21.244.1", "中国", "香港", "香港", "Cloudflare"),
    ("203.0.113.9", "澳大利亚", "昆士兰州", "布里斯班", "Telstra"),
]
PATHS = ["/api/products", "/admin/login", "/api/orders/1024", "/.env", "/wp-login.php", "/"]
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0",
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "",
    "curl/8.4.0",
]
PORTS = [3000, 3000, 3000, 18080, 3389, 22, 443]

records = []
now = int(time.time() * 1000)
for i in range(46):
    ip, country, prov, city, isp = random.choice(GEO)
    risky = country != "中国" or random.random() < 0.18
    score = random.randint(65, 100) if risky else random.choice([0, 0, 0, 45])
    if score >= 90:
        level = "critical"
    elif score >= 65:
        level = "high"
    elif score >= 40:
        level = "medium"
    elif score > 0:
        level = "low"
    else:
        level = "normal"
    records.append(
        AccessRecord(
            ip=ip,
            remote_port=random.randint(30000, 65000),
            local_port=random.choice(PORTS),
            protocol=random.choice(["tcp", "tcp", "https", "udp"]),
            method=random.choice(["GET", "POST", "GET"]),
            path=random.choice(PATHS),
            status_code=random.choice([200, 200, 302, 401, 404, 500]),
            size=random.randint(120, 98000),
            user_agent=random.choice(UAS),
            geo=GeoInfo(
                ip=ip, country=country, province=prov, city=city, isp=isp, iso="CN", found=True
            ),
            risk_score=score,
            risk_level=level,
            matched_rules=(
                ["scanner_ua"] if "sqlmap" in (UAS[1]) and risky else ["geo_sensitive_port"]
            )
            if risky
            else [],
            event_ts=now - (46 - i) * 6400,
        )
    )

NAMES = ["monitor", "events", "bans", "rules", "iplookup", "logs", "settings"]

win = MainWindow()
win.show()
win.page_monitor.append_records(records)

for tag, width in (("", 1360), ("1200_", 1200)):
    win.resize(width, 820)
    for _ in range(20):
        app.processEvents()
    for idx, name in enumerate(NAMES):
        win._switch_page(idx)
        for _ in range(20):
            app.processEvents()
        if name == "settings":
            for t, tab in enumerate(["service", "guard", "data"]):
                win.page_settings.tabs.setCurrentIndex(t)
                for _ in range(15):
                    app.processEvents()
                path = os.path.join(OUT, f"{tag}7_settings_{t + 1}_{tab}.png")
                win.grab().save(path)
                print("saved", path)
            win.page_settings.tabs.setCurrentIndex(0)
            continue
        path = os.path.join(OUT, f"{tag}{idx + 1}_{name}.png")
        win.grab().save(path)
        print("saved", path)

win.hide()
print("OK")
