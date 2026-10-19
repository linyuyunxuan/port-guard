import os
import sys

REPO = r"C:\Users\Administrator\WorkBuddy\ip2region-3.18.0\port-guard"
sys.path.insert(0, REPO)
os.chdir(REPO)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from qtcompat import (
    QT_API,
    QApplication,
    QFormLayout,
    QGroupBox,
    QLabel,
    QLineEdit,
    QVBoxLayout,
    QWidget,
)

if QT_API == "PySide6":
    from PySide6.QtGui import QFontDatabase
else:
    from PySide2.QtGui import QFontDatabase

app = QApplication([])
QFontDatabase.addApplicationFont("C:/Windows/Fonts/msyh.ttc")

BASE = """
QWidget { background: #0F1115; color: #E4E8ED; font-family: "Microsoft YaHei UI"; font-size: 13px; }
"""

V1 = """
QGroupBox { background:#1A1F27; border:none; border-radius:8px; margin-top:26px; padding:16px; }
QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; left:2px; top:0; color:#F4F7FA; font-size:14px; font-weight:600; }
"""

V2 = """
QGroupBox { background:#1A1F27; border:1px solid #1E242C; border-radius:8px; margin-top:12px; padding:14px; }
QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; left:12px; padding:0 6px; color:#F4F7FA; font-size:14px; font-weight:600; }
"""

V3 = """
QGroupBox { background:#1A1F27; border:none; border-radius:8px; margin-top:0px; padding:44px 16px 16px 16px; }
QGroupBox::title { subcontrol-origin: padding; subcontrol-position: top left; left:16px; top:14px; color:#F4F7FA; font-size:14px; font-weight:600; }
"""

w = QWidget()
w.setStyleSheet(BASE + V1 + V2 + V3)
lay = QVBoxLayout(w)
lay.setContentsMargins(24, 24, 24, 24)
lay.setSpacing(24)

for i, (name, extra) in enumerate(
    [("V1 no-border margin", V1), ("V2 border margin", V2), ("V3 padding title", V3)]
):
    g = QGroupBox(f"{name}")
    f = QFormLayout(g)
    f.setContentsMargins(14, 10, 14, 14)
    f.addRow("启用本机观察", QLabel("开关位置"))
    f.addRow("监控端口", QLineEdit("18080,3389"))
    lay.addWidget(g)

lay.addStretch(1)
w.resize(560, 620)
w.show()
for _ in range(20):
    app.processEvents()
out = os.path.join(REPO, "_design", "groupbox_test.png")
w.grab().save(out)
print("saved", out)
