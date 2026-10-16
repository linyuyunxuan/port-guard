"""PortGuard — 实时监控页"""
import datetime
from collections import deque
from typing import List, Optional

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    Qt,
    Signal,
)
from PySide6.QtGui import QAction, QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from core import settings as cfg
from core.config import (
    LEVEL_CRITICAL,
    LEVEL_HIGH,
    LEVEL_LABEL,
)
from core.models import AccessRecord
from gui.theme import LEVEL_BG, LEVEL_COLORS, C
from gui.widgets import StatCard, ToggleSwitch

HEADERS = ["时间", "来源 IP", "归属地", "端口", "协议", "方法", "路径",
           "状态", "大小", "User-Agent", "命中规则", "风险", "服务器"]


class AccessTableModel(QAbstractTableModel):
    """实时访问记录模型

    两层结构：
      _all  —— 环形缓冲，存放全部记录（用于切换筛选时重建）
      _view —— 当前筛选后的视图，表格只显示它
    这样切换筛选条件不会丢失原始数据。
    """

    def __init__(self, capacity: int = 5000, parent=None):
        super().__init__(parent)
        self._all: deque = deque(maxlen=max(500, capacity))
        self._view: List[AccessRecord] = []
        self._filters = {"keyword": "", "scope": "全部", "port": None}

    # ── Qt 接口 ──
    # QModelIndex() 是 Qt 覆写方法的标准默认值（不可变、无副作用），保持签名一致
    def rowCount(self, parent=QModelIndex()):      # noqa: B008
        return 0 if parent.isValid() else len(self._view)

    def columnCount(self, parent=QModelIndex()):   # noqa: B008
        return len(HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return HEADERS[section]
        return None

    def data(self, index: "QModelIndex | QPersistentModelIndex",
             role: int = Qt.ItemDataRole.DisplayRole):
        # 基类签名允许 QPersistentModelIndex，但 QAbstractTableModel 实际只会传
        # QModelIndex（两者并无继承关系），非 QModelIndex 一律按无效索引处理。
        if not isinstance(index, QModelIndex) or not index.isValid():
            return None
        rec: AccessRecord = self._view[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            return self._cell_text(rec, col)

        if role == Qt.ItemDataRole.ForegroundRole:
            if col in (11,):
                return QBrush(QColor(LEVEL_COLORS.get(rec.risk_level, C.text_secondary)))
            if col == 1:
                return QBrush(QColor(C.text_link))
            return None

        if role == Qt.ItemDataRole.BackgroundRole:
            bg = LEVEL_BG.get(rec.risk_level)
            return QBrush(QColor(bg)) if bg else None

        if role == Qt.ItemDataRole.FontRole and col == 11:
            f = QFont()
            f.setBold(rec.risk_level in (LEVEL_HIGH, LEVEL_CRITICAL))
            return f

        if role == Qt.ItemDataRole.ToolTipRole:
            return self._tooltip(rec)

        if role == Qt.ItemDataRole.UserRole:
            return rec

        if role == Qt.ItemDataRole.TextAlignmentRole and col in (3, 7, 8, 11):
            return int(Qt.AlignmentFlag.AlignCenter)

        return None

    @staticmethod
    def _cell_text(rec: AccessRecord, col: int) -> str:
        if col == 0:
            return datetime.datetime.fromtimestamp(rec.event_ts / 1000).strftime("%H:%M:%S")
        if col == 1:
            return rec.ip
        if col == 2:
            return rec.geo.region_short if rec.geo else "未知"
        if col == 3:
            return str(rec.local_port or "-")
        if col == 4:
            return rec.protocol.upper()
        if col == 5:
            return rec.method or "-"
        if col == 6:
            return rec.path or "/"
        if col == 7:
            return str(rec.status_code) if rec.status_code else "-"
        if col == 8:
            return _fmt_size(rec.size)
        if col == 9:
            ua = rec.user_agent or "(空)"
            return ua if len(ua) <= 60 else ua[:57] + "..."
        if col == 10:
            return rec.matched_str or "-"
        if col == 11:
            return LEVEL_LABEL.get(rec.risk_level, rec.risk_level)
        if col == 12:
            return rec.server_name or rec.host or "-"
        return ""

    @staticmethod
    def _tooltip(rec: AccessRecord) -> str:
        lines = [
            f"时间：{rec.time_str}",
            f"来源：{rec.ip}" + (f":{rec.remote_port}" if rec.remote_port else ""),
            f"归属地：{rec.geo.display if rec.geo else '未知'}",
            f"目标端口：{rec.local_port}  协议：{rec.protocol}",
            f"方法/路径：{rec.method or '-'} {rec.path or '/'}",
            f"状态码：{rec.status_code if rec.status_code else '-'}",
            f"大小：{_fmt_size(rec.size)}",
            f"User-Agent：{rec.user_agent or '(空)'}",
            f"风险：{rec.risk_score} 分 / {LEVEL_LABEL.get(rec.risk_level, rec.risk_level)}",
        ]
        if rec.matched_rules:
            lines.append(f"命中规则：{rec.matched_str}")
        if rec.tags:
            lines.append(f"标签：{rec.tags}")
        return "\n".join(lines)

    # ── 数据操作 ──
    def append_many(self, records: List[AccessRecord]) -> int:
        """批量追加，返回实际显示（匹配筛选）的行数"""
        if not records:
            return 0

        removed = 0
        added: List[AccessRecord] = []
        cap = self._all.maxlen

        for r in records:
            # 环形缓冲溢出：丢弃最旧的一条，若它正在视图中则同步移除
            if cap is not None and len(self._all) == cap:
                old = self._all[0]
                self._all.popleft()
                if self._view and self._view[0] is old:
                    removed += 1
            self._all.append(r)
            if self._match(r):
                added.append(r)

        if removed:
            self.beginRemoveRows(QModelIndex(), 0, removed - 1)
            del self._view[:removed]
            self.endRemoveRows()

        if added:
            start = len(self._view)
            self.beginInsertRows(QModelIndex(), start, start + len(added) - 1)
            self._view.extend(added)
            self.endInsertRows()

        return len(added)

    def clear(self) -> None:
        self.beginResetModel()
        self._all.clear()
        self._view.clear()
        self.endResetModel()

    def record_at(self, row: int) -> Optional[AccessRecord]:
        if 0 <= row < len(self._view):
            return self._view[row]
        return None

    @property
    def total(self) -> int:
        return len(self._all)

    def clear_view(self) -> None:
        """仅清空显示，不清空缓冲"""
        self.beginResetModel()
        self._view.clear()
        self.endResetModel()

    # ── 过滤 ──
    def set_filters(self, keyword: str | None = None, scope: str | None = None, port=None) -> None:
        if keyword is not None:
            self._filters["keyword"] = keyword.lower().strip()
        if scope is not None:
            self._filters["scope"] = scope
        if port is not None:
            self._filters["port"] = port
        self._reapply()

    def _reapply(self) -> None:
        """按当前条件从全量缓冲重建视图（不丢失数据）"""
        self.beginResetModel()
        self._view = [r for r in self._all if self._match(r)]
        self.endResetModel()

    def _match(self, rec: AccessRecord) -> bool:
        kw = self._filters["keyword"]
        if kw:
            hay = " ".join([rec.ip, rec.path or "", rec.user_agent or "",
                            rec.server_name or "", rec.host or ""]).lower()
            if kw not in hay:
                return False
        port = self._filters["port"]
        if port and rec.local_port != port:
            return False
        scope = self._filters["scope"] or ""
        if scope == "中国":
            if not (rec.geo and rec.geo.is_china):
                return False
        elif scope == "境外":
            if not rec.geo or not rec.geo.found or rec.geo.is_china:
                return False
        elif scope == "有风险":
            if rec.risk_score <= 0:
                return False
        elif scope == "高风险":
            if rec.risk_level not in (LEVEL_HIGH, LEVEL_CRITICAL):
                return False
        elif scope.startswith("省:"):
            province = scope[2:]
            if not rec.geo or rec.geo.province != province:
                return False
        return True


def _fmt_size(n: int) -> str:
    if not n:
        return "-"
    if n < 1024:
        return f"{n}B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f}KB"
    return f"{n / 1024 / 1024:.1f}MB"


class MonitorPage(QWidget):
    """实时监控页面"""
    ask_lookup = Signal(str)         # 请求切到 IP 查询页并查询
    ask_blacklist = Signal(str)      # 请求把 IP 加入黑名单
    ask_ban = Signal(str, int, str)  # 请求封禁 ip / score / reason

    def __init__(self, parent=None):
        super().__init__(parent)
        self._paused = False
        self._capacity = cfg.get_int("monitor_buffer_size", 5000)
        self._provinces = set()
        self._build()

    # ── UI ──
    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 12)
        root.setSpacing(12)

        # 标题
        head = QHBoxLayout()
        t = QLabel("实时监控")
        t.setObjectName("page_title")
        d = QLabel("业务系统上报的每一次端口访问")
        d.setObjectName("page_desc")
        head.addWidget(t)
        head.addWidget(d)
        head.addStretch(1)

        self.toggle_pause = ToggleSwitch(False)
        self.toggle_pause.toggled.connect(self._on_pause)
        lbl_pause = QLabel("暂停滚动")
        lbl_pause.setStyleSheet(f"color:{C.text_secondary};font-size:12.5px;")
        head.addWidget(lbl_pause)
        head.addWidget(self.toggle_pause)
        root.addLayout(head)

        # 统计卡片
        cards = QHBoxLayout()
        cards.setSpacing(12)
        self.card_total = StatCard("今日访问", "0")
        self.card_risk = StatCard("今日风险", "0", C.warning)
        self.card_ban = StatCard("当前封禁", "0", C.danger)
        self.card_status = StatCard("接收服务", "未启动", C.text_muted)
        for c in (self.card_total, self.card_risk, self.card_ban, self.card_status):
            cards.addWidget(c)
        root.addLayout(cards)

        # 过滤栏
        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索 IP / 路径 / User-Agent / 服务器…")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(260)
        self.search.textChanged.connect(self._on_filter)

        self.scope = QComboBox()
        self.scope.addItems(["全部", "中国", "境外", "有风险", "高风险"])
        self.scope.currentTextChanged.connect(self._on_filter)

        self.port_filter = QSpinBox()
        self.port_filter.setRange(0, 65535)
        self.port_filter.setSpecialValueText("全部端口")
        self.port_filter.setFixedWidth(120)
        self.port_filter.valueChanged.connect(self._on_filter)

        self.btn_clear = QPushButton("清空列表")
        self.btn_clear.setObjectName("btn_outline")
        self.btn_clear.clicked.connect(self._clear_view)

        self.lbl_count = QLabel("共 0 条")
        self.lbl_count.setStyleSheet(f"color:{C.text_muted};font-size:12px;")

        bar.addWidget(self.search, 1)
        bar.addWidget(self.scope)
        bar.addWidget(self.port_filter)
        bar.addWidget(self.btn_clear)
        bar.addWidget(self.lbl_count)
        root.addLayout(bar)

        # 表格
        self.model = AccessTableModel(self._capacity, self)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(30)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._ctx_menu)
        self.table.doubleClicked.connect(self._on_double_click)

        hh = self.table.horizontalHeader()
        widths = [70, 116, 116, 52, 50, 54, 150, 48, 60, 170, 166, 54, 96]
        for i, w in enumerate(widths):
            hh.resizeSection(i, w)
        hh.setStretchLastSection(False)
        hh.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(9, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(12, QHeaderView.ResizeMode.Interactive)

        root.addWidget(self.table, 1)

    # ── 交互 ──
    def _on_pause(self, checked: bool) -> None:
        self._paused = checked

    def _on_filter(self) -> None:
        port = self.port_filter.value() or None
        self.model.set_filters(keyword=self.search.text(),
                               scope=self.scope.currentText(), port=port)
        self._update_count()

    def _clear_view(self) -> None:
        self.model.clear()
        self._update_count()

    def _ctx_menu(self, pos) -> None:
        idx = self.table.indexAt(pos)
        if not idx.isValid():
            return
        rec = self.model.record_at(idx.row())
        if not rec:
            return
        menu = QMenu(self)
        a_lookup = QAction("查询该 IP 归属地", self)
        a_copy = QAction("复制 IP", self)
        a_copy_ua = QAction("复制 User-Agent", self)
        a_black = QAction("加入黑名单", self)
        a_ban = QAction("封禁该 IP…", self)
        menu.addAction(a_lookup)
        menu.addAction(a_copy)
        menu.addAction(a_copy_ua)
        menu.addSeparator()
        menu.addAction(a_black)
        menu.addAction(a_ban)

        a_lookup.triggered.connect(lambda: self.ask_lookup.emit(rec.ip))
        a_copy.triggered.connect(lambda: self._copy(rec.ip))
        a_copy_ua.triggered.connect(lambda: self._copy(rec.user_agent or ""))
        a_black.triggered.connect(lambda: self.ask_blacklist.emit(rec.ip))
        a_ban.triggered.connect(
            lambda: self.ask_ban.emit(rec.ip, rec.risk_score,
                                      rec.matched_str or "手动封禁"))
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _copy(self, text: str) -> None:
        from PySide6.QtWidgets import QApplication
        QApplication.clipboard().setText(text or "")

    def _on_double_click(self, index) -> None:
        rec = self.model.record_at(index.row())
        if rec:
            QMessageBox.information(self, "访问详情", AccessTableModel._tooltip(rec))

    # ── 外部驱动 ──
    def append_records(self, records: List[AccessRecord]) -> int:
        """由主窗口事件泵调用（Qt 主线程）"""
        if self._paused:
            self._update_count()
            return 0
        n = self.model.append_many(records)
        if n:
            self._auto_scroll()
            self._update_count()
            self._learn_provinces(records)
        return n

    def _auto_scroll(self) -> None:
        """
        只在「用户本来就在底部」时才自动滚动。
        原实现每 150ms 无条件 scrollToBottom()，用户往回翻历史会被强行拽回底部。
        """
        sb = self.table.verticalScrollBar()
        at_bottom = sb.value() >= sb.maximum() - 4
        # 首行数据时 maximum 仍为 0，同样视为在底部
        if at_bottom or sb.maximum() <= 0:
            self.table.scrollToBottom()

    def _learn_provinces(self, records: List[AccessRecord]) -> None:
        """
        省份下拉「增量」更新。
        原实现每次都 clear() + addItems() 重建整个 QComboBox，
        会丢失当前选中项并触发整控件重绘（高频下明显闪烁）。
        """
        current = self.scope.currentText()
        new_provs = set()
        for r in records:
            geo = r.geo
            if not (geo and geo.is_china and geo.province and geo.province != "0"):
                continue
            if geo.province not in self._provinces:
                new_provs.add(geo.province)
        if not new_provs:
            return

        self._provinces |= new_provs
        self.scope.blockSignals(True)
        for p in sorted(new_provs):
            self.scope.addItem(f"省:{p}")
        # 恢复用户原本的选择（addItem 不改变 currentIndex，但保险起见显式设置）
        idx = self.scope.findText(current)
        if idx >= 0:
            self.scope.setCurrentIndex(idx)
        self.scope.blockSignals(False)

    def _update_count(self) -> None:
        view, total = self.model.rowCount(), self.model.total
        if view == total:
            self.lbl_count.setText(f"共 {total} 条")
        else:
            self.lbl_count.setText(f"显示 {view} / 共 {total} 条")

    def set_stats(self, total: int, risk: int, bans: int, server_on: bool, port: int = 0) -> None:
        self.card_total.set_value(total)
        self.card_risk.set_value(risk)
        self.card_ban.set_value(bans)
        if server_on:
            self.card_status.set_value(f"运行中 :{port}")
            self.card_status.set_color(C.success)
        else:
            self.card_status.set_value("未启动")
            self.card_status.set_color(C.text_muted)
