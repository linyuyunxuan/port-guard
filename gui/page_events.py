"""PortGuard — 风险事件页"""
import datetime
from typing import Dict, List

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core.config import LEVEL_LABEL
from core.database import query_risk_events, set_risk_handled
from core.models import ms_to_str
from core.rules_meta import rule_label
from gui.theme import LEVEL_BG, LEVEL_COLORS, C

HEADERS = ["时间", "来源 IP", "归属地", "端口", "路径", "评分", "等级",
           "命中规则", "摘要", "状态", "操作"]

HANDLED_LABEL = {0: "未处理", 1: "已确认", 2: "已忽略"}


class EventDetailDialog(QDialog):
    def __init__(self, row: Dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("风险事件详情")
        self.setMinimumSize(560, 420)
        lay = QVBoxLayout(self)
        txt = QTextEdit()
        txt.setReadOnly(True)
        geo = row.get("geo")
        lines = [
            f"事件 ID：#{row.get('id')}",
            f"时间：{ms_to_str(row.get('event_ts'))}",
            f"来源 IP：{row.get('ip')}",
            f"归属地：{geo.display if geo else '未知'}",
            f"目标端口：{row.get('local_port')}",
            f"请求路径：{row.get('path') or '/'}",
            f"风险评分：{row.get('risk_score')}",
            f"风险等级：{LEVEL_LABEL.get(row.get('risk_level'), row.get('risk_level'))}",
            f"命中规则：{'、'.join(rule_label(r) for r in row.get('matched_rules', [])) or '-'}",
            f"处理状态：{HANDLED_LABEL.get(row.get('handled', 0), '-')}",
            "",
            "摘要：",
            row.get("summary") or "-",
        ]
        if geo and geo.found:
            lines += ["", "归属地明细：",
                      f"  国家：{geo.country}  省份：{geo.province}",
                      f"  城市：{geo.city}  ISP：{geo.isp}  国家码：{geo.iso}"]
        txt.setPlainText("\n".join(lines))
        lay.addWidget(txt)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.reject)
        btns.accepted.connect(self.accept)
        lay.addWidget(btns)


class EventsPage(QWidget):
    """风险事件列表"""
    ask_ban = pyqtSignal(str, int, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: List[Dict] = []
        self._build()
        self.refresh()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 12)
        root.setSpacing(12)

        head = QHBoxLayout()
        t = QLabel("风险事件")
        t.setObjectName("page_title")
        d = QLabel("命中风险规则才会进入本列表")
        d.setObjectName("page_desc")
        head.addWidget(t)
        head.addWidget(d)
        head.addStretch(1)
        root.addLayout(head)

        bar = QHBoxLayout()
        bar.setSpacing(8)

        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索 IP / 摘要…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.refresh)

        self.level = QComboBox()
        self.level.addItems(["全部等级", "严重", "高", "中", "低"])
        self.level.currentIndexChanged.connect(self.refresh)

        self.handled = QComboBox()
        self.handled.addItems(["全部状态", "未处理", "已确认", "已忽略"])
        self.handled.currentIndexChanged.connect(self.refresh)

        self.limit = QComboBox()
        self.limit.addItems(["最近 200 条", "最近 500 条", "最近 2000 条"])
        self.limit.currentIndexChanged.connect(self.refresh)

        btn_refresh = QPushButton("刷新")
        btn_refresh.setObjectName("btn_outline")
        btn_refresh.clicked.connect(self.refresh)

        self.lbl_info = QLabel("")
        self.lbl_info.setStyleSheet(f"color:{C.text_muted};font-size:12px;")

        bar.addWidget(self.search, 1)
        bar.addWidget(self.level)
        bar.addWidget(self.handled)
        bar.addWidget(self.limit)
        bar.addWidget(btn_refresh)
        bar.addWidget(self.lbl_info)
        root.addLayout(bar)

        self.table = QTableWidget(0, len(HEADERS))
        self.table.setHorizontalHeaderLabels(HEADERS)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(34)
        self.table.doubleClicked.connect(self._on_double_click)

        hh = self.table.horizontalHeader()
        widths = [126, 118, 108, 58, 148, 48, 48, 168, 118, 66, 156]
        for i, w in enumerate(widths):
            hh.resizeSection(i, w)
        hh.setSectionResizeMode(8, QHeaderView.ResizeMode.Stretch)
        root.addWidget(self.table, 1)

    # ── 数据 ──
    def _level_filter(self) -> str:
        m = {"严重": "critical", "高": "high", "中": "medium", "低": "low"}
        return m.get(self.level.currentText(), "")

    def _handled_filter(self):
        m = {"未处理": 0, "已确认": 1, "已忽略": 2}
        return m.get(self.handled.currentText())

    def refresh(self) -> None:
        try:
            limit = int(self.limit.currentText().replace("最近 ", "").replace(" 条", ""))
        except Exception:
            limit = 200
        rows = query_risk_events(limit=limit, level=self._level_filter(),
                                 handled=self._handled_filter(),
                                 keyword=self.search.text().strip())
        self._rows = rows
        self._render(rows)
        self.lbl_info.setText(f"共 {len(rows)} 条")

    def _render(self, rows: List[Dict]) -> None:
        self.table.setRowCount(0)
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            geo = r.get("geo")
            level = r.get("risk_level", "normal")
            bg = LEVEL_BG.get(level)
            color = LEVEL_COLORS.get(level, C.text_secondary)

            def mk(text, col=None, align=None, bold=False, _bg=bg):
                it = QTableWidgetItem(str(text))
                if col:
                    it.setForeground(QColor(col))
                if align:
                    it.setTextAlignment(align)
                if bold:
                    f = QFont()
                    f.setBold(True)
                    it.setFont(f)
                if _bg:
                    it.setBackground(QColor(_bg))
                return it

            ts = r.get("event_ts")
            time_str = (datetime.datetime.fromtimestamp(ts / 1000).strftime("%m-%d %H:%M:%S")
                        if ts else "-")
            matched = "、".join(rule_label(x) for x in r.get("matched_rules", [])) or "-"

            self.table.setItem(i, 0, mk(time_str))
            self.table.setItem(i, 1, mk(r.get("ip", ""), C.text_link))
            self.table.setItem(i, 2, mk(geo.region_short if geo else "未知"))
            self.table.setItem(i, 3, mk(r.get("local_port") or "-",
                                        align=Qt.AlignmentFlag.AlignCenter))
            self.table.setItem(i, 4, mk(r.get("path") or "/"))
            self.table.setItem(i, 5, mk(r.get("risk_score", 0),
                                        align=Qt.AlignmentFlag.AlignCenter))
            self.table.setItem(i, 6, mk(LEVEL_LABEL.get(level, level), color,
                                        Qt.AlignmentFlag.AlignCenter, True))
            self.table.setItem(i, 7, mk(matched))
            self.table.setItem(i, 8, mk(r.get("summary") or "-"))
            handled = r.get("handled", 0)
            hcolor = {0: C.warning, 1: C.success, 2: C.text_muted}.get(handled, C.text_secondary)
            self.table.setItem(i, 9, mk(HANDLED_LABEL.get(handled, "-"), hcolor,
                                        Qt.AlignmentFlag.AlignCenter))

            self.table.setCellWidget(i, 10, self._row_actions(i, r))

    def _row_actions(self, row_idx: int, r: Dict) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(4, 2, 4, 2)
        lay.setSpacing(4)

        ip = r.get("ip", "")
        score = r.get("risk_score", 0)
        reason = r.get("summary") or "命中风险规则"

        b_ban = QPushButton("封禁")
        b_ban.setObjectName("btn_danger")
        b_ban.setProperty("class", "btn_sm")
        b_ban.setFixedHeight(24)
        b_ban.setStyleSheet(
            f"QPushButton{{background:{C.danger};color:#fff;border:none;border-radius:4px;"
            f"padding:2px 10px;font-size:12px;}}QPushButton:hover{{background:#DC2626;}}")
        b_ban.setCursor(Qt.CursorShape.PointingHandCursor)
        b_ban.clicked.connect(lambda: self.ask_ban.emit(ip, score, reason))

        b_ok = QPushButton("确认")
        b_ok.setFixedHeight(24)
        b_ok.setStyleSheet(
            f"QPushButton{{background:{C.success};color:#fff;border:none;border-radius:4px;"
            f"padding:2px 10px;font-size:12px;}}QPushButton:hover{{background:#0EA271;}}")
        b_ok.setCursor(Qt.CursorShape.PointingHandCursor)
        b_ok.clicked.connect(lambda: self._set_handled(r, 1))

        b_ig = QPushButton("忽略")
        b_ig.setFixedHeight(24)
        b_ig.setStyleSheet(
            f"QPushButton{{background:transparent;color:{C.text_secondary};"
            f"border:1px solid {C.border};border-radius:4px;padding:2px 10px;font-size:12px;}}"
            f"QPushButton:hover{{border-color:{C.text_muted};}}")
        b_ig.setCursor(Qt.CursorShape.PointingHandCursor)
        b_ig.clicked.connect(lambda: self._set_handled(r, 2))

        lay.addWidget(b_ban)
        lay.addWidget(b_ok)
        lay.addWidget(b_ig)
        lay.addStretch(1)
        return w

    def _set_handled(self, r: Dict, handled: int) -> None:
        try:
            set_risk_handled(int(r["id"]), handled)
        except Exception as e:
            QMessageBox.warning(self, "操作失败", str(e))
        self.refresh()

    def _on_double_click(self, index) -> None:
        if 0 <= index.row() < len(self._rows):
            EventDetailDialog(self._rows[index.row()], self).exec()
