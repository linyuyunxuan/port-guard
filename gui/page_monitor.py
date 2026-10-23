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
from gui.event_detail import AccessDetailDialog
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
    QCheckBox,
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

# 列宽基线：固定列合计 890，请求列（唯一 Stretch 列）吃掉剩余 ——
# 1360 窗口下表视口 1099，请求列拿到 209，够放 `POST /api/v1/orders/search`。
# 每个数字都由 _design/measure_cols.py 按「文字宽 + 单元格内边距 20」实测，
# 不是按设计稿估的（改完要重跑一次，别再手调）：
#   时间 96（装 `14:06:06×27`：合并行要带次数后缀，需 92 —— 旧值 72 只够 HH:MM:SS，
#           实测会被截成 `14:06:06…`，次数直接看不见）
#   来源 IP 138（装 IPv6 `2400:3200:baba::1`，需 138 —— 一点都不能省）
#   归属地 112（装「河南省 焦作市」需 108；境外「加利福尼亚州 弗里蒙特」需 164，
#              超出的靠 tooltip 看全称。从 132 压到 112 是给时间列腾字数后缀）
#   端口 58（5 位数 18080 需 55）· 协议 52（HTTPS 需 45）· 状态 52（3 位数需 41）
#   命中规则 152（「管理端口归属地检测」需 146）
#   处置 70（装「仅提醒 / 已拦截 / 待确认」三个三字词；56 与 62 都会被截成
#            「仅…」—— Qt 的 item 内边距比 QSS 写的 10px 更大，按实测需求 + 10 才稳）
#   服务器 112（`web-prod-01` 需 108 —— 旧版 92 一直在截断）
# 请求列宽度是这里最贵的一格：旧配置固定列合计 1151 > 视口 1099，请求列被挤到
# 121px，`POST /admin/login` 显示成 `POST /admi…`，右键菜单之外根本看不出访问了什么。
COL_WIDTHS = [96, 52, 138, 112, 58, 52, 209, 52, 152, 70, 112]
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

    合并显示（2026-10-22 用户要求）：同 IP + 同端口 + 同协议的多次连接只占一行，
    时间列标 `×N`，双击该行看组内每一次的明细。所以 _view 存的是**每组的代表**
    （最新一条），_members[i] 是第 i 行对应的组成员（未合并时长度恒为 1）。
    合并键不含路径 / 命中规则 —— 扫描器打同一端口会换路径，那样等于没合并。

    这些结构在合并关闭时依然维护（_members 每条一行），只是 _view 变成全量列表 ——
    这样开关来回切不需要两套代码路径。
    """

    def __init__(self, capacity: int = 5000, parent=None):
        super().__init__(parent)
        self._all: deque = deque(maxlen=max(500, capacity))
        self._view: List[AccessRecord] = []
        self._members: List[List[AccessRecord]] = []
        self._row_of: dict = {}
        self._merge = True
        self._filters = {"keyword": "", "scope": "全部", "port": None}

    @staticmethod
    def group_key(rec: AccessRecord) -> tuple:
        """同类判据：来源 IP + 目标端口 + 协议。

        协议必须进键：同一端口的 TCP 与 UDP 是两种服务，合成一行后协议列
        只能显示其中一个，那就是在撒谎。
        """
        return (rec.ip, rec.local_port, rec.protocol)

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
            return self._cell_text(rec, col, index.row())

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
            return self._tooltip(rec, index.row())

        if role == Qt.ItemDataRole.UserRole:
            return rec

        if role == Qt.ItemDataRole.TextAlignmentRole and col in (1, 4, 5, 7, COL_DISPOSITION):
            return int(Qt.AlignmentFlag.AlignCenter)

        return None

    def _cell_text(self, rec: AccessRecord, col: int, row: int = -1) -> str:
        if col == 0:
            text = datetime.datetime.fromtimestamp(rec.event_ts / 1000).strftime("%H:%M:%S")
            n = self.count_at(row) if row >= 0 else 1
            # ×N 是「这一行代表 N 次」的唯一提示，不能省 —— 否则用户会以为
            # 攻击只发生了一次，而时间列显示的是最后一次。不带空格是为了
            # 在 96px 的列宽里塞得下 `14:06:06×27`
            return f"{text}×{n}" if n > 1 else text
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

    def _tooltip(self, rec: AccessRecord, row: int = -1) -> str:
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
        # 合并行：说清「这一行代表 N 次」，并把最近几次的时间点列出来
        n = self.count_at(row) if row >= 0 else 1
        if n > 1:
            members = self._members[row]
            first_ts = int(members[0].event_ts or 0)
            lines += [
                "",
                f"共 {n} 次同类连接（同 IP + 同端口 + 同协议），此处显示最近一次：",
                f"  首次 {datetime.datetime.fromtimestamp(first_ts / 1000):%m-%d %H:%M:%S}"
                f"  最近 {datetime.datetime.fromtimestamp(rec.event_ts / 1000):%m-%d %H:%M:%S}",
                "双击该行查看每一次的明细",
            ]
        return "\n".join(lines)

    # ── 数据操作 ──
    def append_many(self, records: List[AccessRecord]) -> int:
        """批量追加，返回**新增的行数**（合并模式下同组记录不新增行）"""
        if not records:
            return 0

        cap = self._all.maxlen
        overflowed = False
        fresh: List[AccessRecord] = []
        for r in records:
            if cap is not None and len(self._all) == cap:
                self._all.popleft()
                overflowed = True
            self._all.append(r)
            if self._match(r):
                fresh.append(r)

        # 环形缓冲溢出时整表重建：合并模式下最旧那条可能是某个组的中间成员，
        # 增量删除要挪行号、要修 _row_of，反而比一次性重建（几千条几毫秒）更脆。
        # 每秒最多重建一次（一次 append_many 就是一拍）。
        if overflowed:
            self._reapply()
            return len(fresh)

        if not self._merge:
            if not fresh:
                return 0
            start = len(self._view)
            self.beginInsertRows(QModelIndex(), start, start + len(fresh) - 1)
            for r in fresh:
                self._view.append(r)
                self._members.append([r])
            self.endInsertRows()
            return len(fresh)

        # 合并模式：已在视图里的组 → 追加成员并更新代表（最后一行是这次的时间）；
        # 新组 → 追加一行。组间顺序 = 首次出现顺序，所以已存在的组不会跳行。
        # 同一批里也要合并（一次 append_many 常常就是同一 IP 的几十条），
        # 所以「本批新增的组」先攒进 new_groups 再统一插行。
        new_groups: List[List[AccessRecord]] = []
        new_index: dict = {}
        touched: List[int] = []
        for r in fresh:
            key = self.group_key(r)
            row = self._row_of.get(key)
            if row is not None:
                self._members[row].append(r)
                self._view[row] = r
                if row not in touched:
                    touched.append(row)
                continue
            gi = new_index.get(key)
            if gi is None:
                new_index[key] = len(new_groups)
                new_groups.append([r])
            else:
                new_groups[gi].append(r)

        if new_groups:
            start = len(self._view)
            self.beginInsertRows(QModelIndex(), start, start + len(new_groups) - 1)
            for group in new_groups:
                self._row_of[self.group_key(group[-1])] = len(self._view)
                self._view.append(group[-1])
                self._members.append(group)
            self.endInsertRows()

        # 已有组刷新：×N 与时间都变了，整行重画
        last_col = len(HEADERS) - 1
        for row in touched:
            if 0 <= row < len(self._view):
                self.dataChanged.emit(self.index(row, 0), self.index(row, last_col))

        return len(new_groups)

    def clear(self) -> None:
        self.beginResetModel()
        self._all.clear()
        self._view.clear()
        self._members.clear()
        self._row_of.clear()
        self.endResetModel()

    def record_at(self, row: int) -> Optional[AccessRecord]:
        if 0 <= row < len(self._view):
            return self._view[row]
        return None

    def members_at(self, row: int) -> List[AccessRecord]:
        """第 row 行对应的全部原始记录（未合并时就是 1 条）——详情弹窗用"""
        if 0 <= row < len(self._members):
            return list(self._members[row])
        return []

    def count_at(self, row: int) -> int:
        if 0 <= row < len(self._members):
            return len(self._members[row])
        return 0

    def set_merge(self, enabled: bool) -> None:
        """切换合并显示。结构两边都维护，切换只是重建一次视图。"""
        enabled = bool(enabled)
        if enabled == self._merge:
            return
        self._merge = enabled
        self._reapply()

    @property
    def merging(self) -> bool:
        return self._merge

    @property
    def total(self) -> int:
        return len(self._all)

    def clear_view(self) -> None:
        """仅清空显示，不清空缓冲"""
        self.beginResetModel()
        self._view.clear()
        self._members.clear()
        self._row_of.clear()
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
        """按当前条件从全量缓冲重建视图（不丢失数据）。

        合并模式下同时重建分组索引：_view[i] 是第 i 组的最新代表，
        _members[i] 是该组全部成员（按时间升序，末尾最新）。
        """
        self.beginResetModel()
        self._view = []
        self._members = []
        self._row_of = {}
        for r in self._all:
            if not self._match(r):
                continue
            if not self._merge:
                self._view.append(r)
                self._members.append([r])
                continue
            key = self.group_key(r)
            row = self._row_of.get(key)
            if row is None:
                self._row_of[key] = len(self._view)
                self._view.append(r)
                self._members.append([r])
            else:
                self._members[row].append(r)
                self._view[row] = r
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
    ask_blacklist = Signal(str)  # 请求把 IP 加进「拦截」规则（原黑名单入口）
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
        self.card_total = StatCard("今日访问", "0", unit="次")
        self.card_risk = StatCard("今日风险", "0", C.warning, unit="条")
        self.card_ban = StatCard("当前封禁", "0", C.danger, unit="个")
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

        # 合并显示开关：同 IP + 同端口 + 同协议只占一行（时间列标 ×N）。
        # 默认开 —— 扫描器一分钟就能把列表刷成几十行一模一样的东西，
        # 那时用户要的是「谁在打我」，不是「打了第几十次」。
        self.chk_merge = QCheckBox("同 IP 端口合并")
        self.chk_merge.setChecked(True)
        self.chk_merge.setToolTip(
            "同一来源 IP、同一目标端口、同一协议的多条访问折叠成一行，\n"
            "时间列显示最近一次并标 ×N；双击该行查看每一次的明细"
        )
        self.chk_merge.toggled.connect(self._on_merge_toggled)

        self.lbl_count = QLabel("共 0 条")
        self.lbl_count.setStyleSheet(f"color:{C.text_muted};font-size:12.5px;")

        bar.addWidget(self.search)
        bar.addWidget(self.scope)
        bar.addWidget(self.port_filter)
        bar.addWidget(self.btn_clear)
        bar.addWidget(self.chk_merge)
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

    def _on_merge_toggled(self, checked: bool) -> None:
        self.model.set_merge(bool(checked))
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
        n = self.model.count_at(idx.row())
        menu = QMenu(self)
        a_detail = QAction(f"查看详情（{n} 次连接）" if n > 1 else "查看详情", self)
        a_lookup = QAction("查询该 IP 归属地", self)
        a_copy = QAction("复制 IP", self)
        a_copy_ua = QAction("复制 User-Agent", self)
        a_black = QAction("加入拦截规则", self)
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
        menu.addAction(a_detail)
        menu.addSeparator()
        menu.addAction(a_lookup)
        menu.addAction(a_copy)
        menu.addAction(a_copy_ua)
        menu.addSeparator()
        menu.addAction(a_black)
        menu.addAction(a_ban)

        a_detail.triggered.connect(lambda: self._show_detail(idx.row()))
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

    def _show_detail(self, row: int) -> None:
        """双击 / 右键「查看详情」：列出该行代表的每一次连接"""
        recs = self.model.members_at(row)
        if recs:
            AccessDetailDialog(recs, self).exec()

    def _on_double_click(self, index) -> None:
        if index.isValid():
            self._show_detail(index.row())

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
        rows, total = self.model.rowCount(), self.model.total
        prefix = "已暂停 · " if self._paused else ""
        if rows == total:
            self.lbl_count.setText(f"{prefix}共 {total} 条")
        elif self.model.merging:
            # 合并开着时「显示 3 行 / 共 27 条」要说明白：不然后台明明收到 27 条，
            # 列表只有 3 行，看着像丢数据
            self.lbl_count.setText(f"{prefix}共 {total} 条 · 合并显示 {rows} 行")
        else:
            self.lbl_count.setText(f"{prefix}显示 {rows} / 共 {total} 条")
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
