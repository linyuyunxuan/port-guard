"""封禁记录表：量「最宽内容」需要多少像素，用来定 IP / 归属地 / 时间列宽。

只量不写。封禁表的四类文本（IP / 归属地 / 时间 / 状态）都比注释里早先
预估的宽：`182.118.236.126` 是 15 个等宽字符，而列宽 124 减掉 QSS 左右
8px（共 16）后只剩 108 —— 实测裁掉了末尾两位，界面上根本看不出封的是谁。
"""

import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
os.chdir(REPO)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from qtcompat import IS_QT6, QApplication, QtGui  # noqa: E402

app = QApplication([])
for f in ("msyh.ttc", "consola.ttf"):
    QtGui.QFontDatabase.addApplicationFont("C:/Windows/Fonts/" + f)

from gui.widgets import number_font  # noqa: E402

body = QtGui.QFont("Microsoft YaHei UI", 9)
mono = number_font(12)


def w(font, text):
    return QtGui.QFontMetrics(font).horizontalAdvance(text)


CASES = [
    ("IP（IPv4 最长）", mono, ["182.118.236.126", "255.255.255.255", "113.118.113.77"]),
    ("IP（IPv6 典型）", mono, ["2408:8207:78a3:3b1::1"]),
    ("归属地", body, ["河南省 洛阳市", "广东省 深圳市", "黑龙江省 齐齐哈尔市", "未知"]),
    ("时间", mono, ["2026-10-20 09:27", "2099-12-31 23:59", "永久"]),
    ("状态", body, ["已封禁 ×128", "已到期", "处理中", "已解封"]),
    ("来源", body, ["黑名单", "自动", "手动", "规则"]),
]

print(f"binding = {'Qt6 (开发栈)' if IS_QT6 else 'Qt5 (交付栈)'}")
for name, font, texts in CASES:
    print(f"\n{name}: 字体={font.family()} {font.pixelSize()}px")
    for t in texts:
        px = w(font, t)
        # 列宽 = 文字 + 16(QSS padding) + 4(Qt 渲染损耗) + 4(余量)
        print(f"  「{t}」 需 {px}px → 建议列宽 {px + 24}px")
