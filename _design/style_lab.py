"""PortGuard 设计样张（Style Lab）：把设计体系里的所有控件放进一屏，离屏截图用。

用法：
    QT_QPA_PLATFORM=offscreen python _design/style_lab.py
产物：_design/lab.png
"""

import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
os.chdir(REPO)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from qtcompat import (  # noqa: E402
    QT_API,
    QAbstractItemView,
    QApplication,
    QComboBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

if QT_API == "PySide6":
    from PySide6.QtGui import QFontDatabase
    from PySide6.QtWidgets import QCheckBox
else:
    from PySide2.QtGui import QFontDatabase
    from PySide2.QtWidgets import QCheckBox

app = QApplication([])
QFontDatabase.addApplicationFont("C:/Windows/Fonts/msyh.ttc")
QFontDatabase.addApplicationFont("C:/Windows/Fonts/msyhbd.ttc")

from gui.theme import GLOBAL_STYLE, C, small_button_style  # noqa: E402
from gui.widgets import (  # noqa: E402
    Badge,
    EmptyState,
    RiskBadge,
    StatCard,
    StatusItem,
    ToggleSwitch,
    WarnBanner,
)


def panel(title: str, body: QWidget) -> QFrame:
    f = QFrame()
    f.setObjectName("panel")
    v = QVBoxLayout(f)
    v.setContentsMargins(16, 14, 16, 16)
    v.setSpacing(10)
    t = QLabel(title)
    t.setObjectName("panel_title")
    v.addWidget(t)
    v.addWidget(body)
    return f


class Lab(QWidget):
    def __init__(self):
        super().__init__()
        self.setObjectName("lab_root")
        self.setStyleSheet(GLOBAL_STYLE + f"#lab_root{{background:{C.bg_body};}}")
        self.setWindowTitle("PortGuard Style Lab")
        self.resize(1360, 900)

        root = QVBoxLayout(self)
        root.setContentsMargins(20, 18, 20, 18)
        root.setSpacing(14)

        head = QHBoxLayout()
        t = QLabel("设计样张")
        t.setObjectName("page_title")
        d = QLabel("PortGuard 组件与排版基准")
        d.setObjectName("page_desc")
        head.addWidget(t)
        head.addWidget(d)
        head.addStretch(1)
        head.addWidget(QLabel("样式版本"))
        root.addLayout(head)

        # 统计卡
        cards = QHBoxLayout()
        cards.setSpacing(12)
        for label, value, color in [
            ("今日访问", "12,842", None),
            ("今日风险", "37", C.warning),
            ("当前封禁", "4", C.danger),
            ("接收服务", "运行中 :18080", C.success),
        ]:
            cards.addWidget(StatCard(label, value, color))
        root.addLayout(cards)

        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(14)
        root.addLayout(grid, 1)

        # 按钮
        btns = QWidget()
        bl = QVBoxLayout(btns)
        bl.setContentsMargins(0, 0, 0, 0)
        bl.setSpacing(10)
        row = QHBoxLayout()
        row.setSpacing(8)
        b1 = QPushButton("保存并生效")
        b1.setObjectName("btn_primary")
        b2 = QPushButton("重新载入")
        b2.setObjectName("btn_outline")
        b3 = QPushButton("确认封禁")
        b3.setObjectName("btn_danger")
        b4 = QPushButton("启动服务")
        b4.setObjectName("btn_success")
        for b in (b1, b2, b3, b4):
            row.addWidget(b)
        row.addStretch(1)
        bl.addLayout(row)

        row2 = QHBoxLayout()
        row2.setSpacing(8)
        small = QPushButton("忽略")
        small.setFixedHeight(22)
        small.setStyleSheet(small_button_style("outline"))
        small2 = QPushButton("确认封禁")
        small2.setFixedHeight(22)
        small2.setStyleSheet(small_button_style("danger"))
        dis = QPushButton("不可用")
        dis.setEnabled(False)
        row2.addWidget(small2)
        row2.addWidget(small)
        row2.addWidget(dis)
        row2.addStretch(1)
        bl.addLayout(row2)

        # 输入
        form = QWidget()
        fl = QVBoxLayout(form)
        fl.setContentsMargins(0, 0, 0, 0)
        fl.setSpacing(10)
        e1 = QLineEdit()
        e1.setPlaceholderText("搜索 IP / 路径 / User-Agent…")
        e2 = QLineEdit("18080")
        e2.setFixedWidth(140)
        cb = QComboBox()
        cb.addItems(["全部", "中国", "境外", "有风险", "高风险"])
        sp = QSpinBox()
        sp.setRange(0, 65535)
        sp.setSpecialValueText("全部端口")
        sp.setFixedWidth(140)
        chk = QCheckBox("记录被丢弃的连接")
        chk.setChecked(True)
        tg = ToggleSwitch(True)
        trow = QHBoxLayout()
        trow.addWidget(chk)
        trow.addStretch(1)
        trow.addWidget(QLabel("启用观察"))
        trow.addWidget(tg)
        fl.addWidget(e1)
        fl.addWidget(e2)
        fl.addWidget(cb)
        fl.addWidget(sp)
        fl.addLayout(trow)
        bl.addWidget(form)
        grid.addWidget(panel("按钮 / 输入控件", btns), 0, 0)

        # 徽章
        badges = QWidget()
        bal = QVBoxLayout(badges)
        bal.setContentsMargins(0, 0, 0, 0)
        bal.setSpacing(12)
        brow = QHBoxLayout()
        brow.setSpacing(8)
        for lv in ("normal", "low", "medium", "high", "critical"):
            brow.addWidget(RiskBadge(lv))
        brow.addStretch(1)
        bal.addLayout(brow)
        brow2 = QHBoxLayout()
        brow2.setSpacing(8)
        brow2.addWidget(Badge("本机采集", C.info))
        brow2.addWidget(Badge("业务上报", C.success))
        brow2.addWidget(Badge("已确认", C.text_secondary))
        brow2.addStretch(1)
        bal.addLayout(brow2)
        bal.addWidget(WarnBanner("当前以普通权限运行，无法写入防火墙规则。", "以管理员身份重启"))
        st = QHBoxLayout()
        st.setSpacing(16)
        for label in ("接收服务", "本机观察", "权限"):
            st.addWidget(StatusItem(label))
        st.addStretch(1)
        bal.addLayout(st)
        bal.addWidget(EmptyState("暂无风险事件", "规则引擎未发现需要处理的高风险访问"))
        grid.addWidget(panel("徽章 / 横幅 / 空态", badges), 0, 1)

        # 表格
        tw = QTableWidget(6, 6)
        tw.setHorizontalHeaderLabels(["时间", "来源 IP", "归属地", "端口", "风险", "命中规则"])
        tw.verticalHeader().setVisible(False)
        tw.setShowGrid(False)
        tw.setAlternatingRowColors(True)
        tw.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        tw.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        tw.verticalHeader().setDefaultSectionSize(34)
        hh = tw.horizontalHeader()
        for i, w in enumerate([110, 140, 150, 70, 70, 200]):
            hh.resizeSection(i, w)
        hh.setStretchLastSection(True)
        rows = [
            ("14:02:11", "113.118.113.77", "广东省 深圳市", "3000", "正常", "-"),
            ("14:02:09", "45.33.32.156", "美国 加利福尼亚", "3389", "高", "管理端口归属地检测"),
            ("14:01:58", "185.220.101.4", "德国 黑森州", "18080", "严重", "扫描器特征"),
            ("14:01:52", "223.5.5.5", "浙江省 杭州市", "3000", "中", "敏感路径探测"),
            ("14:01:40", "1.192.0.1", "河南省 郑州市", "22", "低", "-"),
            ("14:01:31", "103.21.244.1", "香港 香港", "3000", "正常", "-"),
        ]
        for r, row in enumerate(rows):
            for c, val in enumerate(row):
                tw.setItem(r, c, QTableWidgetItem(val))
        tab = QWidget()
        tl = QVBoxLayout(tab)
        tl.setContentsMargins(0, 0, 0, 0)
        tl.addWidget(tw)
        grid.addWidget(panel("数据表格", tab), 1, 0)

        # 标签页
        tabs = QTabWidget()
        p1 = QWidget()
        p1l = QVBoxLayout(p1)
        p1l.addWidget(QLabel("风险规则内容"))
        p1l.addWidget(WarnBanner("这条规则的说明文字会出现在这里。"))
        p1l.addStretch(1)
        p2 = QWidget()
        p2l = QVBoxLayout(p2)
        p2l.addWidget(QLabel("区域访问白名单内容"))
        p2l.addStretch(1)
        tabs.addTab(p1, "风险规则")
        tabs.addTab(p2, "区域访问白名单")
        grid.addWidget(panel("标签页 / 分组", tabs), 1, 1)

        grid.setColumnStretch(0, 3)
        grid.setColumnStretch(1, 2)


lab = Lab()
lab.show()
for _ in range(30):
    app.processEvents()
out = os.path.join(REPO, "_design", "lab.png")
lab.grab().save(out)
print("saved", out)
