"""量出事件页 / 封禁页各列「最宽内容」的真实像素宽，两栈通用。

列宽 = 最宽文字 + QSS padding(16) + 余量(8)。
本脚本只量不写，用于在 PySide2（交付栈）与 PySide6（开发栈）之间做对照。
"""

import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
os.chdir(REPO)
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from qtcompat import IS_QT6, QApplication, QtGui  # noqa: E402

app = QApplication([])
QtGui.QFontDatabase.addApplicationFont("C:/Windows/Fonts/msyh.ttc")
QtGui.QFontDatabase.addApplicationFont("C:/Windows/Fonts/msyhbd.ttc")
QtGui.QFontDatabase.addApplicationFont("C:/Windows/Fonts/consola.ttf")

from gui.widgets import number_font  # noqa: E402

print(f"binding = {'Qt6 (PySide6 开发栈)' if IS_QT6 else 'Qt5 (PySide2 交付栈)'}")
print(f"platform = {app.platformName()}")

body = QtGui.QFont("Microsoft YaHei UI", 9)
mono = number_font(12)
mono_bold = number_font(12, bold=True)


def w(font, text):
    return QtGui.QFontMetrics(font).horizontalAdvance(text)


#: (列名, 字体, [候选文本...]) —— 取其中最宽的一条作为「最宽内容」
EVENT_COLS = [
    ("0 勾选", None, []),
    ("1 时间", mono, ["10-19 16:29:57", "2026-10-19 16:29"]),
    ("2 等级", body, ["严重", "高", "中", "低"]),
    ("3 来源IP", mono, ["45.33.32.156", "2408:8207:78a3:3b1::1"]),
    ("4 归属地", body, ["广东省 深圳市", "美国 弗里蒙特", "中国香港"]),
    ("5 端口", mono, ["3389", "65535"]),
    ("6 路径", mono, ["/api/orders/1024", "/admin/login", "/index.php"]),
    ("7 评分", mono_bold, ["100"]),
    ("8 命中规则", body, ["管理端口归属地检测", "管理端口归属地检测（旧）", "扫描器特征"]),
    ("9 状态", body, ["已忽略", "未处理", "已确认"]),
    ("10 操作", None, []),
]

BAN_COLS = [
    ("0 勾选", None, []),
    ("1 ID", mono, ["99999"]),
    ("2 IP", mono, ["2408:8207:78a3:3b1::1", "45.33.32.156"]),
    ("3 原因", body, ["管理端口归属地检测 · 评分 100"]),
    ("4 方式", body, ["自动", "手动"]),
    ("5 时长", body, ["永久", "600s"]),
    ("6 状态", body, ["已封禁", "已解封", "失败"]),
    ("7 创建时间", mono, ["10-19 16:29:57"]),
    ("8 到期时间", mono, ["10-19 16:29:57", "永久"]),
    ("9 操作", None, []),
]

SUG_COLS = [
    ("0 勾选", None, []),
    ("1 时间", mono, ["10-19 16:29:57"]),
    ("2 等级", body, ["严重"]),
    ("3 来源IP", mono, ["2408:8207:78a3:3b1::1", "45.33.32.156"]),
    ("4 归属地", body, ["广东省 深圳市"]),
    ("5 端口", mono, ["3389"]),
    ("6 评分", mono_bold, ["100"]),
    ("7 原因", body, ["管理端口归属地检测 · 累计 12 次命中"]),
    ("8 操作", None, []),
]


def dump(title, cols):
    print(f"\n== {title} ==")
    total = 0
    for name, font, texts in cols:
        if font is None or not texts:
            print(f"  {name:10} -- 内容为控件/复选框，按固定值 --")
            continue
        widest = max(texts, key=lambda t: w(font, t))
        px = w(font, widest)
        print(f"  {name:10} {px:4}  ({widest})")
        total += px + 24
    print(f"  ---- 文字+padding+余量 合计（不含固定列）≈ {total}")


dump("事件页", EVENT_COLS)
dump("封禁记录", BAN_COLS)
dump("封禁建议", SUG_COLS)
