"""封禁页列宽实测：把模型真实输出的文案量一遍，两栈对照。

只量不写。用于判断 BAN_WIDTHS / SUG_WIDTHS 是否会截断。
"""

import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
os.chdir(REPO)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from qtcompat import IS_QT6, QApplication, QtGui  # noqa: E402

app = QApplication([])
for f in ("msyh.ttc", "msyhbd.ttc", "consola.ttf"):
    QtGui.QFontDatabase.addApplicationFont(f"C:/Windows/Fonts/{f}")

from gui.widgets import number_font  # noqa: E402

print(f"binding = {'Qt6' if IS_QT6 else 'Qt5'}")
body = QtGui.QFont("Microsoft YaHei UI", 9)
mono = number_font(12)
mono_b = number_font(12, bold=True)


def w(font, text):
    return QtGui.QFontMetrics(font).horizontalAdvance(str(text))


def row(name, font, text, width):
    px = w(font, text)
    need = px + 24
    mark = "OK " if width >= need else "TRUNC"
    print(f"  {mark} {name:12} 列宽={width:4} 需要={need:4} 文字={px:4}  {text}")


print("== 封禁记录 ==")
W = [36, 48, 108, 180, 72, 44, 64, 70, 126, 126, 92]
row("1 ID", mono, 99999, W[1])
row("2 IP", mono, "113.118.113.77", W[2])
row("2 IP(v6)", mono, "2408:8207:78a3:3b1::1", W[2])
row("4 来源", body, "建议", W[4])
row("5 评分", mono, 100, W[5])
row("6 状态", body, "已到期", W[6])
row("7 时长", mono, "365 天", W[7])
row("8 到期时间", mono, "2026-10-19 16:29", W[8])
row("9 创建时间", mono, "2026-10-19 16:29", W[9])

print("== 封禁建议 ==")
S = [36, 110, 60, 114, 132, 58, 44, 160, 112]
row("1 时间", mono, "10-19 16:29:57", S[1])
row("2 等级", body, "严重", S[2])
row("3 IP", mono, "113.118.113.77", S[3])
row("3 IP(v6)", mono, "2408:8207:78a3:3b1::1", S[3])
row("4 归属地", body, "广东省 深圳市", S[4])
row("5 端口", mono, "18080", S[5])
row("6 评分", mono_b, 100, S[6])
