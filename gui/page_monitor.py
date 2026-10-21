"""PortGuard — 实时监控页"""

import datetime
from collections import deque
from typing import List, Optional

from core import settings as cfg
from core.config import (
    LEVEL_CRITICAL,
    LEVEL_HIGH,
    LEVEL_LABEL,
)
from core.database import find_active_ban_by_ip
from core.models import (
    DISPOSITION_ALERT,
    DISPOSITION_ALLOW,
    DISPOSITION_BLOCK,
    DISPOSITION_CONFIRM,
    DISPOSITION_HINT,
    DISPOSITION_IGNORED,
    AccessRecord,
    disposition_label,
)
from gui.components import PageHeader
from gui.theme import C
from gui.widgets import (
    BADGE_ROLE,
    EmptyState,
    RiskBadgeDelegate,
    StatCard,
    ToggleSwitch,
    WarnBanner,
    labeled_toggle,
    number_font,
)
from qtcompat import (
    QAbstractItemView,
    QAbstractTableModel,
    QAction,
    QBrush,
    QColor,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QModelIndex,
    QPersistentModelIndex,
    QPushButton,
    QSpinBox,
    Qt,
    QTableView,
    QVBoxLayout,
    QWidget,
    Signal,
)

HEADERS = [
    "时间",
    "风险",
    "来源 IP",
    "归属地",
    "端口",
    "协议",
    "请求",
    "状态",
    "命中规则",
    "处置",
    "服务器",
]

# 列宽基线：1360 下固定列合计 788，请求列吃掉剩余（@1360≈312 / @1200≈152）。
# 每个宽度都用 _design/cell_probe.py 按「文字宽 + 单元格内边距 16」实测过，
# 不再按设计稿估数：归属地要装下「加利福尼亚州 弗里蒙特」(140)，
# 端口要装下 5 位数 18080 (51)，协议要装下 HTTPS (37+16=53)，
# 命中规则要装下「管理端口归属地检测」(108+16=124)。
# 处置列 62：装「已放行/已拦截/仅提醒/待确认」四个三字词（实测 39 + 内边距 16）。
COL_WIDTHS = [83, 69, 138, 168, 67, 69, 173, 60, 161, 71, 92]
COL_REQUEST = 6
COL_DISPOSITION = 9

#: 处置结论 → 文字色（与风险事件页同一套口径，改一处就两边一起变）
_DISPOSITION_COLOR = {
    DISPOSITION_ALLOW: C.text_muted,
    DISPOSITION_ALERT: C.text_secondary,
    DISPOSITION_CONFIRM: C.warning,
    DISPOSITION_BLOCK: C.success,
    DISPOSITION_IGNORED: C.text_muted,
}


def _disposition_color(disposition: str) -> str:
    return _DISPOSITION_COLOR.get(disposition, C.text_secondary)


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
    def rowCount(self, parent=QModelIndex()):  # noqa: B008
        return 0 if parent.isValid() else len(self._view)

    def columnCount(self, parent=QModelIndex()):  # noqa: B008
        return len(HEADERS)

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if orientation != Qt.Orientation.Horizontal:
            return None
        if role == Qt.ItemDataRole.DisplayRole:
            return HEADERS[section]
        # 表头跟数据同轴：居中列的列头也居中
        if role == Qt.ItemDataRole.TextAlignmentRole and section in (1, 4, 5, 7):
            return int(Qt.AlignmentFlag.AlignCenter)
        return None

    def data(
        self, index: "QModelIndex | QPersistentModelIndex", role: int = Qt.ItemDataRole.DisplayRole
    ):
        # 基类签名允许 QPersistentModelIndex，但 QAbstractTableModel 实际只会传
        # QModelIndex（两者并无继承关系），非 QModelIndex 一律按无效索引处理。
        if not isinstance(index, QModelIndex) or not index.isValid():
            return None
        rec: AccessRecord = self._view[index.row()]
        col = index.column()

        if role == Qt.ItemDataRole.DisplayRole:
            return self._cell_text(rec, col)

        if role == BADGE_ROLE and col == 1:
            return rec.risk_level

        if role == Qt.ItemDataRole.ForegroundRole:
            if col == 2:
                return QBrush(QColor(C.text_link))
            if col == COL_DISPOSITION:
                return QBrush(QColor(_disposition_color(rec.disposition)))
            return None

        if role == Qt.ItemDataRole.FontRole:
            if col in (0, 4, 5, 7):
                return number_font(12)
            return None

        if role == Qt.ItemDataRole.ToolTipRole:
            return self._tooltip(rec)

        if role == Qt.ItemDataRole.UserRole:
            return rec

        if role == Qt.ItemDataRole.TextAlignmentRole and col in (1, 4, 5, 7, COL_DISPOSITION):
            return int(Qt.AlignmentFlag.AlignCenter)

        return None

    @staticmethod
    def _cell_text(rec: AccessRecord, col: int) -> str:
        if col == 0:
            return datetime.datetime.fromtimestamp(rec.event_ts / 1000).strftime("%H:%M:%S")
        if col == 1:
            return ""  # 风险列由 RiskBadgeDelegate 自绘徽章
        if col == 2:
            return rec.ip
        if col == 3:
            return rec.geo.region_short if rec.geo else "未知"
        if col == 4:
            return str(rec.local_port or "-")
        if col == 5:
            return rec.protocol.upper()
        if col == 6:
            method = rec.method or ""
            path = rec.path or "/"
            return f"{method} {path}".strip()
        if col == 7:
            return str(rec.status_code) if rec.status_code else "-"
        if col == 8:
            return rec.matched_str or "-"
        if col == 9:
            # 空表示这条记录没经过处置判定（历史缓冲 / 手工构造），显示 "-"
            # 而不是硬编「已放行」—— 没判定过和判定为放行是两件事
            return disposition_label(rec.disposition) if rec.disposition else "-"
        if col == 10:
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
        if rec.disposition:
            hint = DISPOSITION_HINT.get(rec.disposition)
            lines.append(
                f"处置结果：{disposition_label(rec.disposition)}" + (f"（{hint}）" if hint else "")
            )
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
    def set_filters(
        self, keyword: Optional[str] = None, scope: Optional[str] = None, port=None
    ) -> None:
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
            hay = " ".join(
                [
                    rec.ip,
                    rec.path or "",
                    rec.user_agent or "",
                    rec.server_name or "",
                    rec.host or "",
                ]
            ).lower()
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

    ask_lookup = Signal(str)  # 请求切到 IP 查询页并查询
    ask_blacklist = Signal(str)  # 请求把 IP 加入黑名单
    ask_ban = Signal(str, int, str)  # 请求封禁 ip / score / reason
    ask_settings = Signal()  # 请求跳到设置页（空态「去启动」）

    def __init__(self, parent=None):
        super().__init__(parent)
        self._paused = False
        self._empty_kind = ""
        self._capacity = cfg.get_int("monitor_buffer_size", 5000)
        self._provinces = set()
        self._build()

    # ── UI ──
    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 16, 24, 12)
        root.setSpacing(12)

        # 标题区（56，7 页统一）
        head = PageHeader("实时监控", "本机采集到的每一次端口访问")
        self.toggle_pause = ToggleSwitch(False)
        self.toggle_pause.toggled.connect(self._on_pause)
        head.add_action(labeled_toggle(self.toggle_pause, "暂停滚动"))
        root.addWidget(head)

        # 统计卡片（3 张等宽；「接收服务」健康态已上移到顶部状态条）
        cards = QHBoxLayout()
        cards.setSpacing(12)
        self.card_total = StatCard("今日访问", "0")
        self.card_risk = StatCard("今日风险", "0", C.warning)
        self.card_ban = StatCard("当前封禁", "0", C.danger)
        for c in (self.card_total, self.card_risk, self.card_ban):
            cards.addWidget(c, 1)
        root.addLayout(cards)

        # 过滤栏
        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索 IP / 路径 / User-Agent / 服务器…")
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(330)
        self.search.textChanged.connect(self._on_filter)

        self.scope = QComboBox()
        self.scope.addItems(["全部", "中国", "境外", "有风险", "高风险"])
        self.scope.setFixedWidth(132)
        self.scope.currentTextChanged.connect(self._on_filter)

        self.port_filter = QSpinBox()
        self.port_filter.setRange(0, 65535)
        self.port_filter.setSpecialValueText("全部端口")
        self.port_filter.setFixedWidth(132)
        self.port_filter.valueChanged.connect(self._on_filter)

        self.btn_clear = QPushButton("清空列表")
        self.btn_clear.setObjectName("btn_outline")
        self.btn_clear.clicked.connect(self._clear_view)

        self.lbl_count = QLabel("共 0 条")
        self.lbl_count.setStyleSheet(f"color:{C.text_muted};font-size:12.5px;")

        bar.addWidget(self.search)
        bar.addWidget(self.scope)
        bar.addWidget(self.port_filter)
        bar.addWidget(self.btn_clear)
        bar.addStretch(1)
        bar.addWidget(self.lbl_count)
        root.addLayout(bar)

        # 暂停提示（仅暂停时出现）
        self.pause_banner = WarnBanner(
            "已暂停：新访问暂不进入列表（判定与入库不受影响）", level="info"
        )
        self.pause_banner.setVisible(False)
        root.addWidget(self.pause_banner)

        # 表格
        self.model = AccessTableModel(self._capacity, self)
        self.table = QTableView()
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setTabKeyNavigation(False)
        self.table.verticalHeader().setVisible(False)
        # 常显竖滚动条：滚动条出现/消失会让表格可视宽在 15↔25px 之间跳，
        # 结果列宽度每次翻页都变，读数时眼睛要重新找位置
        self.table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.table.verticalHeader().setDefaultSectionSize(34)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._ctx_menu)
        self.table.doubleClicked.connect(self._on_double_click)
        self.table.setItemDelegateForColumn(1, RiskBadgeDelegate(self.table))

        # 两态空态（无流量 / 筛选无结果）——之前这里只有一行灰字
        self.empty = EmptyState("暂无访问", "开启「本机端口观察」后，命中的连接会实时出现在这里")
        self.empty.setVisible(False)
        if self.empty.btn is not None:
            self.empty.btn.clicked.connect(self._on_empty_action)
        root.addWidget(self.empty, 1)

        hh = self.table.horizontalHeader()
        for i, w in enumerate(COL_WIDTHS):
            hh.resizeSection(i, w)
        hh.setStretchLastSection(False)
        hh.setSectionResizeMode(COL_REQUEST, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(9, QHeaderView.ResizeMode.Interactive)

        root.addWidget(self.table, 1)
        self._update_count()

    # ── 交互 ──
    def _on_pause(self, checked: bool) -> None:
        self._paused = checked
        self.pause_banner.setVisible(checked)
        self._update_count()

    def _on_filter(self) -> None:
        port = self.port_filter.value() or None
        self.model.set_filters(
            keyword=self.search.text(), scope=self.scope.currentText(), port=port
        )
        self._update_count()

    def _clear_view(self) -> None:
        if self.model.total == 0:
            return
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("清空列表")
        box.setText("清空列表后将无法恢复。")
        box.setInformativeText("只清空界面显示，不影响已入库的记录与风险判定。")
        btn_yes = box.addButton("清空", QMessageBox.ButtonRole.DestructiveRole)
        btn_no = box.addButton("取消", QMessageBox.ButtonRole.RejectRole)
        box.setDefaultButton(btn_no)
        box.exec()
        if box.clickedButton() is not btn_yes:
            return
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
        # 已封禁的 IP 把封禁项置灰并说明原因：不然点下去只会弹「已处于封禁状态」，
        # 看上去跟「上次点了没生效」一模一样
        try:
            ban = find_active_ban_by_ip(rec.ip)
        except Exception:
            ban = None
        if ban is not None:
            a_ban.setText("已在封禁中")
            a_ban.setEnabled(False)
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
            lambda: self.ask_ban.emit(rec.ip, rec.risk_score, rec.matched_str or "手动封禁")
        )
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _copy(self, text: str) -> None:
        from qtcompat import QApplication

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
        prefix = "已暂停 · " if self._paused else ""
        if view == total:
            self.lbl_count.setText(f"{prefix}共 {total} 条")
        else:
            self.lbl_count.setText(f"{prefix}显示 {view} / 共 {total} 条")
        self.btn_clear.setEnabled(total > 0)
        self._update_empty()

    def _on_empty_action(self) -> None:
        """空态按钮分流：去设置页开观察 / 重置筛选"""
        if self._empty_kind == "norisk":
            self.search.clear()
            self.scope.setCurrentIndex(0)
            self.port_filter.setValue(0)
        elif self._empty_kind == "stopped":
            self.ask_settings.emit()

    def _update_empty(self, *_args) -> None:
        """表格与空态互斥：有行就显示表格。

        两种「空」的原因不同，混成一句「暂无数据」等于什么都没说：
          · 一条都没收到 —— 观察器没开或确实没人访问，引导去设置页开观察
          · 有数据但筛不出来 —— 引导重置筛选
        """
        total = self.model.total
        view = self.model.rowCount()
        if view > 0:
            self.table.setVisible(True)
            self.empty.setVisible(False)
            return

        self.table.setVisible(False)
        if total > 0:
            self._empty_kind = "norisk"
            self.empty.set_state("没有匹配记录", "换个关键字，或把范围改回「全部」", "重置筛选")
        else:
            self._empty_kind = "stopped"
            self.empty.set_state(
                "暂无访问", "开启「本机端口观察」后，命中的连接会实时出现在这里", "去开启"
            )
        self.empty.setVisible(True)

    def set_stats(self, total: int, risk: int, bans: int):
        self.card_total.set_value(total)
        self.card_risk.set_value(risk)
        self.card_ban.set_value(bans)
        # 计数为 0 时不染色：红色 0 是纯噪声，留着会削弱真正有数时的语义
        self.card_risk.set_color(C.warning if risk else C.text_on_dark)
        self.card_ban.set_color(C.danger if bans else C.text_on_dark)
        self.card_risk.dot.set_color(C.warning if risk else C.text_muted)
        self.card_ban.dot.set_color(C.danger if bans else C.text_muted)
        self._update_empty()
