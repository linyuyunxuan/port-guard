"""离屏渲染各页截图，用于人工核对浅色主题与字号。

用法：envs\\portguard\\Scripts\\python.exe tools\\shot.py <输出目录>
"""

import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "_shots")
os.makedirs(OUT, exist_ok=True)

from core import database, db_writer
from core import settings as cfg
from core.models import AccessRecord
from core.pipeline import process_record
from qtcompat import QApplication


def main() -> int:
    database.init_db()
    cfg.warm()

    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication([])
    from gui.main_window import MainWindow
    from gui.theme import GLOBAL_STYLE

    app.setStyleSheet(GLOBAL_STYLE)
    win = MainWindow()
    win.resize(1360, 860)
    win.show()
    app.processEvents()

    # 造点数据，否则各页都是空态看不出版式
    for i in range(6):
        rec = AccessRecord(
            ip=f"203.0.113.{10 + i}",
            local_port=1433 + i,
            remote_port=51000 + i,
            protocol="TCP",
            path="/admin/login" if i % 2 else "/",
            method="POST" if i % 2 else "GET",
            status_code=401 if i % 2 else 200,
            user_agent="sqlmap/1.7" if i % 3 == 0 else "Mozilla/5.0",
            tags={"channel": "table"},
        )
        process_record(rec, allow_auto_ban=False, actor="system")
    db_writer.get_writer().flush(timeout=5)

    names = ["monitor", "events", "access", "bans", "lookup", "rules", "settings", "logs"]
    for idx, name in enumerate(names):
        if idx < len(win.nav_buttons):
            win.nav_buttons[idx].click()
            app.processEvents()
            win._drain_events()
            app.processEvents()
        pix = win.grab()
        path = os.path.join(OUT, f"{idx}_{name}.png")
        pix.save(path)
        print("saved", path, pix.width(), "x", pix.height())

    # 设置页三个 tab 各来一张（默认只截第一个）
    win.page_settings.tabs.setCurrentIndex(1)
    app.processEvents()
    win.grab().save(os.path.join(OUT, "6_settings_b.png"))
    win.page_settings.tabs.setCurrentIndex(2)
    app.processEvents()
    win.grab().save(os.path.join(OUT, "6_settings_c.png"))
    print("settings tabs saved")
    return 0


if __name__ == "__main__":
    sys.exit(main())
