"""把事件页截图的关键区域放大，确认到底是不是真的省略了。"""

import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
os.chdir(REPO)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from qtcompat import QApplication, Qt, QtCore, QtGui  # noqa: E402

app = QApplication([])
QtGui.QFontDatabase.addApplicationFont("C:/Windows/Fonts/msyh.ttc")

src = os.path.join(REPO, "_design", "after", "8_events_batch.png")
pm = QtGui.QPixmap(src)
print("原图", pm.width(), "x", pm.height())

# 评分 / 命中规则 / 状态 / 操作 四列，取三行
crop = pm.copy(QtCore.QRect(930, 195, 300, 90))
big = crop.scaled(crop.width() * 3, crop.height() * 3, Qt.AspectRatioMode.KeepAspectRatio,
                  Qt.TransformationMode.SmoothTransformation)
out = os.path.join(REPO, "_design", "after", "_zoom_score.png")
big.save(out)
print("saved", out, big.width(), "x", big.height())
