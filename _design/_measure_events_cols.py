"""量事件页各列「最宽内容」的真实像素宽（开发栈 / 交付栈通用，只量不写）。

用途：把「命中规则」并进「等级」列之前，先算出等级列到底要留多宽、
路径列能从别处借到多少余量。判据与 gui/page_events.py 的列宽注释一致：
列宽 = 最宽文字 + 20（QSS 左右各 8 + 渲染损耗 4）。
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
QtGui.QFontDatabase.addApplicationFont("C:/Windows/Fonts/consola.ttf")

from gui.widgets import number_font  # noqa: E402

print(f"binding = {'Qt6 (PySide6 开发栈)' if IS_QT6 else 'Qt5 (PySide2 交付栈)'}")

body = QtGui.QFont("Microsoft YaHei UI", 9)
body_small = QtGui.QFont("Microsoft YaHei UI", 9)
body_small.setPixelSize(12)
mono = number_font(12)
mono_bold = number_font(12, bold=True)
PAD = 20


def w(font, text):
    return QtGui.QFontMetrics(font).horizontalAdvance(text)


def dump(title, cols):
    print(f"\n== {title} ==")
    for name, font, texts in cols:
        if font is None:
            print(f"  {name:12} -- 控件自绘 --")
            continue
        widest = max(texts, key=lambda t: w(font, t))
        px = w(font, widest)
        print(f"  {name:12} {px:4} + {PAD} = {px + PAD:4}   ({widest})")


#: 事件页「等级」列：徽章（单字「严重」时 34px 宽）+ 8 间隙 + 规则名
BADGE_PILL = 34
BADGE_GAP = 8
BADGE_LEFT = 10
BADGE_RIGHT = 8


def badge_need(note):
    """等级列需要多宽：左内距 + 徽章 + 间隙 + 规则名 + 右内距"""
    text_px = w(body_small, note) if note else 0
    return BADGE_LEFT + BADGE_PILL + (BADGE_GAP + text_px if note else 0) + BADGE_RIGHT


dump(
    "等级列（徽章 + 规则名）",
    [(f"规则「{t}」", body_small, [t]) for t in (
        "管理端口归属地检测",
        "异常 HTTP 方法",
        "扫描器特征",
        "端口扫描 +2",
        "管理端口归属地检测 +3",
    )],
)
for t in (
    "管理端口归属地检测",
    "异常 HTTP 方法",
    "管理端口归属地检测 +3",
):
    print(f"  等级列含「{t}」需 {badge_need(t)}px")

dump(
    "路径列（mono 12）",
    [
        ("路径", mono, [
            "/api/v1/orders/search",
            "/wp-admin/setup-config.php",
            "/api/v1/orders/search?page=2&size=50",
            "/../../etc/passwd",
        ])
    ],
)

dump(
    "其余各列",
    [
        ("时间", mono, ["10-27 09:30:45", "10-27 09:30:45 ×27", "10-27 09:30:45 ×999"]),
        ("来源IP", mono, ["182.118.236.126", "2400:3200:baba::1"]),
        ("归属地", body, ["河南省 焦作市", "黑龙江省 齐齐哈尔市", "美国 弗里蒙特"]),
        ("端口", mono, ["18080", "65535"]),
        ("评分", mono_bold, ["100"]),
        ("处置", body, ["仅提醒", "已拦截", "待确认"]),
    ],
)
