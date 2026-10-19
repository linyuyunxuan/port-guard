"""量出事件页各列真实文字宽度（不是估），用于定列宽。"""

import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
os.chdir(REPO)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from qtcompat import QApplication, QtGui  # noqa: E402

app = QApplication([])
QtGui.QFontDatabase.addApplicationFont("C:/Windows/Fonts/msyh.ttc")
QtGui.QFontDatabase.addApplicationFont("C:/Windows/Fonts/msyhbd.ttc")

from gui.widgets import number_font  # noqa: E402

body = QtGui.QFont("Microsoft YaHei UI", 9)
hdr = QtGui.QFont("Microsoft YaHei UI", 9)


def w(font, text):
    return QtGui.QFontMetrics(font).horizontalAdvance(text)


mono = number_font(12)
mono_bold = number_font(12, bold=True)

print("== 等宽（Consolas 12）==")
for t in ["10-19 16:29:57", "45.33.32.156", "18080", "3389"]:
    print(f"  {t!r:22} {w(mono, t)}")
print("== 等宽加粗 ==")
for t in ["100", "45", "0"]:
    print(f"  {t!r:22} {w(mono_bold, t)}  <- 评分列")
print("== 正文（YaHei 9pt）==")
for t in ["美国 弗里蒙特", "广东省 深圳市", "中国香港", "管理端口归属地检测", "管理端口归属地检测（旧）",
          "扫描器特征", "已忽略", "未处理", "已确认", "严重", "低"]:
    print(f"  {t!r:26} {w(body, t)}")
print("== 表头（YaHei 9pt 600）==")
for t in ["时间", "等级", "来源 IP", "归属地", "端口", "路径", "评分", "命中规则", "状态", "操作"]:
    print(f"  {t!r:12} {w(hdr, t)}")
