"""PortGuard — 封禁管理页"""

import datetime
import threading
from typing import Any, Dict, List, Optional

from app import audit, ban_service
from app.export_csv import BAN_CSV_HEADERS, SUG_CSV_HEADERS, iter_ban_rows, iter_sug_rows
from core import firewall
from core import settings as cfg
from core.config import LEVEL_CRITICAL, LEVEL_HIGH, LEVEL_ORDER
from core.database import (
    count_active_bans,
    delete_ban_records,
    query_bans,
    query_risk_events,
    set_risk_handled,
    set_risk_handled_batch,
)
from core.logger import get_logger
from core.models import (
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_UNBANNED,
    ms_to_str,
)
from core.validators import InvalidIP, normalize_ip
from gui.components import PageHeader, export_table_csv, row_menu_button
from gui.table_select import CheckColumn
from gui.table_sort import (
    KIND_DATETIME,
    KIND_MS,
    KIND_NUM,
    KIND_TEXT,
    ColumnSpec,
    SortSpec,
    TableSort,
)
from gui.theme import C, small_button_style
from gui.widgets import (
    EmptyState,
    RiskBadgeDelegate,
    SortHeader,
    WarnBanner,
    align_headers,
    badge_item,
    make_item,
)
from qtcompat import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QSplitter,
    Qt,
    QTableWidget,
    QVBoxLayout,
    QWidget,
    Signal,
)

log = get_logger(__name__)

BAN_HEADERS = [
    "",
    "ID",
    "IP",
    "原因",
    "来源",
    "评分",
    "状态",
    "时长",
    "到期时间",
    "创建时间",
    "操作",
]
SUG_HEADERS = ["", "时间", "等级", "IP", "归属地", "端口", "评分", "原因", "操作"]

# 第 0 列都是勾选框（32px）。列宽按「实测文字 + 16 padding + 6 余量」定，
# 两栈取大的那套（PySide2 的 YaHei / Consolas 度量比 PySide6 宽 6~20%）。
# IP 列 120：`113.118.113.77` 实测 98px，早期给 108 已经开始截断；
# IPv6 完整地址（147px）放不下，走 tooltip —— 但 IPv4 必须完整。
# 到期 / 创建列 136：模型输出的是 `YYYY-MM-DD HH:MM`（112px），不能省年份，
# 封禁最长 365 天会跨年。
# 原因列是唯一的拉伸列。
BAN_WIDTHS = [32, 48, 130, 180, 50, 46, 64, 66, 128, 128, 88]
SUG_WIDTHS = [32, 120, 60, 130, 106, 56, 46, 160, 112]
COL_SUG_CHECK = 0
COL_SUG_LEVEL = 2
COL_SUG_REASON = 7
COL_BAN_CHECK = 0
COL_BAN_REASON = 3

# 列排序规则（数据层，见 gui/table_sort.py 开头为什么不用 setSortingEnabled）。
# 两张表各一套：都不给勾选列（点了是全选）与操作列（无值）建规则。
# 等级按严重度（LEVEL_ORDER）而不是中文笔画；封禁状态按「已封禁 → 处理中 →
# 失败 → 已解封」的业务序，按本地化文本排会把它排成无意义的顺序。
# 时长用 duration_sec：显示的是「2 小时」这种带单位的文本，比不了大小。
SUG_SORT_SPECS = {
    1: ColumnSpec(KIND_MS, lambda r: r.get("event_ts")),
    COL_SUG_LEVEL: ColumnSpec(KIND_NUM, lambda r: LEVEL_ORDER.get(str(r.get("risk_level") or ""))),
    3: ColumnSpec(KIND_TEXT, lambda r: r.get("ip")),
    4: ColumnSpec(KIND_TEXT, lambda r: r.get("geo").region_short if r.get("geo") else ""),
    5: ColumnSpec(KIND_NUM, lambda r: r.get("local_port")),
    6: ColumnSpec(KIND_NUM, lambda r: r.get("risk_score")),
    COL_SUG_REASON: ColumnSpec(KIND_TEXT, lambda r: r.get("summary")),
}

#: 「已封禁」最需要先看到，所以它的序号最小
BAN_STATUS_ORDER = {
    STATUS_ACTIVE: 0,
    STATUS_PENDING: 1,
    STATUS_FAILED: 2,
    STATUS_EXPIRED: 3,
    STATUS_UNBANNED: 4,
}

BAN_SORT_SPECS = {
    1: ColumnSpec(KIND_NUM, lambda b: b.id),
    2: ColumnSpec(KIND_TEXT, lambda b: b.ip),
    COL_BAN_REASON: ColumnSpec(KIND_TEXT, lambda b: b.reason),
    4: ColumnSpec(KIND_TEXT, lambda b: b.source_label),
    5: ColumnSpec(KIND_NUM, lambda b: b.risk_score),
    6: ColumnSpec(KIND_NUM, lambda b: BAN_STATUS_ORDER.get(b.status)),
    # duration_sec 为 None / 0 都是「永久」（见 BanRecord.duration_label），
    # 归到空值排最后 —— 永久是最长的时长，不该出现在升序的第一屏
    7: ColumnSpec(KIND_NUM, lambda b: b.duration_sec or None),
    8: ColumnSpec(KIND_MS, lambda b: b.expire_at),
    9: ColumnSpec(KIND_DATETIME, lambda b: b.created_at),
}


class ManualBanDialog(QDialog):
    """手动封禁对话框"""

    def __init__(self, ip: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("手动封禁 IP")
        self.setMinimumWidth(420)
        form = QFormLayout(self)
        form.setContentsMargins(18, 18, 18, 12)
        form.setSpacing(10)

        self.ip = QLineEdit(ip)
        self.ip.setPlaceholderText("例如 203.0.113.10 或 2408:8000::1")
        self.reason = QLineEdit("手动封禁")
        self.duration = QSpinBox()
        self.duration.setRange(0, 365 * 24 * 60)
        # 默认取「默认封禁时长」设置（原来硬编码 60 分钟：用户在设置页改过默认值，
        # 这里仍然显示 1 小时，两边对不上）。0 在设置里表示永久，直接映射成「永久」。
        self.duration.setValue(max(0, cfg.get_int("default_ban_duration_sec", 3600) // 60))
        self.duration.setSuffix(" 分钟（0=永久）")
        self.duration.setSpecialValueText("永久")

        form.addRow("IP 地址", self.ip)
        form.addRow("封禁原因", self.reason)
        form.addRow("封禁时长", self.duration)

        tip = QLabel("提示：内网、回环与保留地址会被自动拒绝封禁。")
        tip.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
        form.addRow(tip)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.button(QDialogButtonBox.StandardButton.Ok).setText("确认封禁")
        btns.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        form.addRow(btns)

    def accept(self) -> None:
        """
        前置校验：把显然的非法输入挡在对话框里，用户立即得到反馈。

        注意这只是**体验优化**；真正的安全防线在 `core.validators`
        与 `core.firewall`，即使有人绕过这里的校验也不会产生命令注入。
        """
        raw = self.ip.text().strip()
        try:
            normalize_ip(raw)
        except InvalidIP as e:
            QMessageBox.warning(
                self, "IP 格式错误", f"{e}\n\n请输入形如 203.0.113.10 或 2408:8000::1 的地址。"
            )
            self.ip.setFocus()
            self.ip.selectAll()
            return
        super().accept()

    def values(self):
        mins = self.duration.value()
        return (
            self.ip.text().strip(),
            self.reason.text().strip() or "手动封禁",
            0 if mins == 0 else mins * 60,
        )


class BansPage(QWidget):
    """封禁建议 + 封禁列表（两张表都支持勾选批量处理）"""

    ask_ban = Signal(str, int, str)
    # [(ip, score, reason, event_ids), ...] —— 批量确认封禁交给主窗口统一执行
    ask_ban_many = Signal(list)
    ask_lookup = Signal(str)
    request_refresh_stats = Signal()
    # 批量解封在后台线程跑，结束后把结果送回 GUI 线程
    batch_unban_done = Signal(int, int)  # (成功数, 失败数)

    # 显式声明：勾选列在两个面板里各建一次，且建在按钮之后
    sug_sel: CheckColumn
    ban_sel: CheckColumn

    def __init__(self, parent=None):
        super().__init__(parent)
        # *_rows 是当前**显示顺序**（点表头后会被重排），行号 == 数据下标；
        # *_src 是后端返回的原序，只用于「取消排序」时还原
        self._sug_rows = []
        self._sug_rows_src = []
        self._ban_rows = []
        self._ban_rows_src = []
        self.sug_sort = TableSort(SUG_SORT_SPECS)
        self.ban_sort = TableSort(BAN_SORT_SPECS)
        # 到期但解不掉的条数（普通权限下由主窗口巡检回报），供权限条展示
        self._expired_backlog = 0
        self._build()
        self.batch_unban_done.connect(self._on_batch_unban_done)
        self.refresh()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 16, 24, 12)
        root.setSpacing(12)

        head = PageHeader("封禁管理", "规则引擎给出建议，确认后才写入 Windows 防火墙")
        root.addWidget(head)

        # 权限警示条（仅普通权限时出现）
        self.banner = WarnBanner("", "以管理员身份重启", C.warning)
        self.banner.action_clicked.connect(self._restart_as_admin)
        root.addWidget(self.banner)
        self._refresh_perm_banner()

        # 结果区：上「待确认建议」/ 下「封禁记录」，可拖拽分配高度
        self.split = QSplitter(Qt.Orientation.Vertical)
        self.split.setChildrenCollapsible(False)
        self.split.addWidget(self._build_sug_panel())
        self.split.addWidget(self._build_records_area())
        self.split.setStretchFactor(0, 0)
        self.split.setStretchFactor(1, 1)
        self.split.setSizes([268, 386])
        root.addWidget(self.split, 1)

    def _refresh_perm_banner(self) -> None:
        """
        普通权限时的常驻提示。

        除了「封禁不会生效」，还带上「有 N 条已到期但解不掉」—— 到期巡检要管理员
        权限，没权限时它什么都做不了。不在这里说清楚，用户会以为封禁到期自动消失。
        """
        if firewall.is_admin():
            self.banner.setVisible(False)
            return
        text = (
            "当前以普通权限运行，无法修改 Windows 防火墙。"
            "监控与规则判定正常，但「确认封禁」不会生效。"
        )
        if self._expired_backlog > 0:
            text += (
                f"另有 {self._expired_backlog} 条封禁已到期，需管理员权限才能删除对应"
                "防火墙规则 —— 这些规则仍在生效。"
            )
        self.banner.set_text(text)
        self.banner.setVisible(True)

    def set_expired_backlog(self, n: int) -> None:
        """由主窗口的到期巡检回报「到期但解不掉」的条数（普通权限下才有值）"""
        n = max(0, int(n or 0))
        if n == self._expired_backlog:
            return
        self._expired_backlog = n
        self._refresh_perm_banner()

    @staticmethod
    def _setup_table(table: QTableWidget) -> None:
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.setWordWrap(False)
        table.setTabKeyNavigation(False)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(30)
        # 常显竖滚动条：滚动条出现/消失会让可视宽在 15↔25px 之间跳，列宽跟着抖
        table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)

    def _build_sug_panel(self) -> QFrame:
        """待确认建议：有数据时 216 高，0 条时折叠成 56 的一行提示"""
        self.sug_panel = QFrame()
        self.sug_panel.setObjectName("panel")
        lay = QVBoxLayout(self.sug_panel)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        head = QHBoxLayout()
        head.setContentsMargins(16, 12, 16, 8)
        head.setSpacing(8)
        self.sug_title = QLabel("待确认的封禁建议")
        self.sug_title.setObjectName("panel_title")
        self.sug_hint = QLabel("规则引擎建议，需人工确认")
        self.sug_hint.setStyleSheet(f"color:{C.text_muted};font-size:11px;")
        head.addWidget(self.sug_title)
        head.addWidget(self.sug_hint)
        head.addStretch(1)

        # 批量操作放在面板标题行里：不额外占高度，上下面板的高度预算不用重算
        self.lbl_sug_sel = QLabel("已选 0 条")
        self.lbl_sug_sel.setStyleSheet(f"color:{C.text_muted};font-size:11px;")
        self.btn_sug_all = self._mini_button("全选", enabled=True)
        self.btn_sug_ban = self._mini_button("批量封禁", "danger")
        self.btn_sug_ignore = self._mini_button("批量忽略")
        # 建议面板没有独立的批量条，导出放标题行末尾：既不额外占高度，
        # 也与「批量忽略」同属「对这批建议整体做点什么」
        self.btn_sug_export = self._mini_button("导出 CSV", enabled=True)
        self.btn_sug_export.setToolTip("导出当前待确认建议，不受勾选影响")
        # 勾选列建在表格之后，lambda 延迟取值（不能提前绑定方法）
        self.btn_sug_all.clicked.connect(lambda: self.sug_sel.toggle_all())  # noqa: PLW0108
        self.btn_sug_ban.clicked.connect(self._batch_ban_suggestions)
        self.btn_sug_ignore.clicked.connect(self._batch_ignore_suggestions)
        self.btn_sug_export.clicked.connect(self._export_sug_csv)
        for w in (
            self.lbl_sug_sel,
            self.btn_sug_all,
            self.btn_sug_ban,
            self.btn_sug_ignore,
            self.btn_sug_export,
        ):
            head.addWidget(w)
        lay.addLayout(head)

        self.sug_empty = QLabel("没有待确认建议 · 规则引擎未发现需要封禁的高危 IP")
        self.sug_empty.setStyleSheet(
            f"color:{C.text_muted};font-size:12px;padding:0 16px 14px 16px;"
        )
        self.sug_empty.setVisible(False)
        lay.addWidget(self.sug_empty)

        self.sug_table = QTableWidget(0, len(SUG_HEADERS))
        self.sug_table.setHorizontalHeaderLabels(SUG_HEADERS)
        align_headers(self.sug_table, (2, 5, 6))
        self._setup_table(self.sug_table)
        self.sug_table.setItemDelegateForColumn(COL_SUG_LEVEL, RiskBadgeDelegate(self.sug_table))
        self.sug_sel = CheckColumn(self.sug_table, COL_SUG_CHECK)
        self.sug_sel.bind(self._on_sug_sel_changed)
        sh = self.sug_table.horizontalHeader()
        for i, width in enumerate(SUG_WIDTHS):
            sh.resizeSection(i, width)
        sh.setSectionResizeMode(COL_SUG_REASON, QHeaderView.ResizeMode.Stretch)
        # 点表头排序（数据层重排 + 重渲染，见 gui/table_sort.py）
        self.sug_sort_header = SortHeader(self.sug_table, self.sug_sort, self._apply_sug_sort)
        lay.addWidget(self.sug_table, 1)
        return self.sug_panel

    @staticmethod
    def _mini_button(text: str, kind: str = "", enabled: bool = False) -> QPushButton:
        """标题行 / 批量条里的小按钮。

        默认禁用：动作类按钮必须「先勾选才能点」，否则用户会点到一个什么都不做的
        按钮。「全选」这类不依赖勾选的按钮要显式传 enabled=True。
        """
        b = QPushButton(text)
        b.setFixedHeight(24)
        b.setStyleSheet(small_button_style(kind or "outline"))
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        b.setEnabled(enabled)
        return b

    def _build_records_area(self) -> QWidget:
        box = QWidget()
        lay = QVBoxLayout(box)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(12)

        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索 IP / 原因…")
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(280)
        self.search.textChanged.connect(self.refresh)

        self.status_filter = QComboBox()
        self.status_filter.addItems(["全部状态", "已封禁", "已解封", "失败", "处理中"])
        self.status_filter.setFixedWidth(110)
        self.status_filter.currentIndexChanged.connect(self.refresh)

        btn_manual = QPushButton("手动封禁")
        btn_manual.setObjectName("btn_primary")
        btn_manual.clicked.connect(lambda: self.ask_ban.emit("", 0, "手动封禁"))

        btn_refresh = QPushButton("刷新")
        btn_refresh.setObjectName("btn_outline")
        btn_refresh.clicked.connect(self.refresh)

        self.btn_more = row_menu_button(
            [("与防火墙对账", self._sync), ("一键全部解封", self._unban_all)], self, size=32
        )
        self.btn_more.setToolTip("更多操作：与防火墙对账 / 一键全部解封")

        self.lbl_info = QLabel("")
        self.lbl_info.setStyleSheet(f"color:{C.text_muted};font-size:11px;")

        bar.addWidget(self.search)
        bar.addWidget(self.status_filter)
        bar.addWidget(btn_manual)
        bar.addWidget(btn_refresh)
        bar.addWidget(self.btn_more)
        bar.addStretch(1)
        bar.addWidget(self.lbl_info)
        lay.addLayout(bar)

        # 记录表的批量条：只对已解封/已封禁的记录生效，与上面建议表互不影响
        bb = QHBoxLayout()
        bb.setSpacing(8)
        self.lbl_ban_sel = QLabel("已选 0 条")
        self.lbl_ban_sel.setStyleSheet(f"color:{C.text_secondary};font-size:12px;")
        self.lbl_ban_sel.setFixedWidth(84)
        self.btn_ban_all = self._mini_button("全选本页", enabled=True)
        self.btn_ban_unban = self._mini_button("批量解封")
        self.btn_ban_del = self._mini_button("删除记录")
        self.btn_ban_all.clicked.connect(lambda: self.ban_sel.toggle_all())  # noqa: PLW0108
        self.btn_ban_unban.clicked.connect(self._batch_unban)
        self.btn_ban_del.clicked.connect(self._batch_delete_bans)
        self.btn_ban_del.setToolTip("仅删除数据库记录，不会改动已生效的防火墙规则")
        self.btn_ban_export = self._mini_button("导出 CSV", enabled=True)
        self.btn_ban_export.setToolTip("导出当前筛选的封禁记录，不受勾选影响")
        self.btn_ban_export.clicked.connect(self._export_ban_csv)
        bb.addWidget(self.lbl_ban_sel)
        bb.addWidget(self.btn_ban_all)
        bb.addSpacing(6)
        bb.addWidget(self.btn_ban_unban)
        bb.addWidget(self.btn_ban_del)
        bb.addWidget(self.btn_ban_export)
        bb.addStretch(1)
        lay.addLayout(bb)

        self.empty = EmptyState("尚无封禁记录", "确认封禁后，记录会出现在这里")
        self.empty.setVisible(False)
        lay.addWidget(self.empty)

        self.table = QTableWidget(0, len(BAN_HEADERS))
        self.table.setHorizontalHeaderLabels(BAN_HEADERS)
        align_headers(self.table, (1, 4, 5, 6, 7, 8, 9))
        self._setup_table(self.table)
        self.ban_sel = CheckColumn(self.table, COL_BAN_CHECK)
        self.ban_sel.bind(self._on_ban_sel_changed)
        h = self.table.horizontalHeader()
        for i, width in enumerate(BAN_WIDTHS):
            h.resizeSection(i, width)
        h.setSectionResizeMode(COL_BAN_REASON, QHeaderView.ResizeMode.Stretch)
        # 点表头排序（数据层重排 + 重渲染，见 gui/table_sort.py）
        self.ban_sort_header = SortHeader(self.table, self.ban_sort, self._apply_ban_sort)
        lay.addWidget(self.table, 1)
        return box

    # ── 数据 ──
    def _status_filter(self) -> str:
        m = {
            "已封禁": STATUS_ACTIVE,
            "已解封": STATUS_UNBANNED,
            "失败": STATUS_FAILED,
            "处理中": STATUS_PENDING,
        }
        return m.get(self.status_filter.currentText(), "")

    def refresh(self) -> None:
        self._load_suggestions()
        self._load_bans()

    def _load_suggestions(self) -> None:
        rows = [
            r
            for r in query_risk_events(limit=200, handled=0)
            if r.get("risk_level") in (LEVEL_HIGH, LEVEL_CRITICAL)
        ]
        # 排序状态跨刷新保留：用户按评分降序看建议，封完一条回来还想是降序
        self._sug_rows_src = rows
        self._sug_rows = self.sug_sort.apply(rows)
        self._render_suggestions()

    def _apply_sug_sort(self, _state: Optional[SortSpec]) -> None:
        """按新排序重渲染建议表：勾选按业务 key（事件 id）回放，不是按行号"""
        keys = {r.get("id") for r in self._checked_suggestions()}
        self._sug_rows = self.sug_sort.apply(self._sug_rows_src)
        self._render_suggestions()
        self.sug_sel.set_checked_rows(
            i for i, r in enumerate(self._sug_rows) if r.get("id") in keys
        )

    def _render_suggestions(self) -> None:
        rows = self._sug_rows
        self.sug_title.setText(f"待确认的封禁建议（{len(rows)}）")

        empty = not rows
        self.sug_empty.setVisible(empty)
        self.sug_table.setVisible(not empty)
        if empty:
            # 0 条时整区折叠成一行提示，把高度让给封禁记录表
            # 折叠态也要装得下「标题行 40 + 一句空态 26 + 下留白 14」
            self.sug_panel.setMinimumHeight(80)
            self.sug_panel.setMaximumHeight(80)
        else:
            # 208 / 328 = 面板开销 88 + 4 行 / 8 行，正好不露半行
            self.sug_panel.setMinimumHeight(208)
            self.sug_panel.setMaximumHeight(328)

        self.sug_sel.begin_render()
        try:
            self.sug_table.setRowCount(0)
            self.sug_table.setRowCount(len(rows))
            for i, r in enumerate(rows):
                ts = r.get("event_ts")
                time_str = (
                    datetime.datetime.fromtimestamp(ts / 1000).strftime("%m-%d %H:%M:%S")
                    if ts
                    else "-"
                )
                geo = r.get("geo")
                level = r.get("risk_level", "normal")
                reason = r.get("summary") or "命中风险规则"
                ip_text = str(r.get("ip") or "")

                self.sug_sel.fill(i)
                self.sug_table.setItem(i, 1, make_item(time_str, mono=True, tip=ms_to_str(ts)))
                self.sug_table.setItem(i, 2, badge_item(level))
                self.sug_table.setItem(i, 3, make_item(ip_text, C.text_link, tip=ip_text))
                geo_text = geo.display if geo else "未知"
                self.sug_table.setItem(
                    i, 4, make_item(geo.region_short if geo else "未知", tip=geo_text)
                )
                self.sug_table.setItem(
                    i,
                    5,
                    make_item(
                        r.get("local_port") or "-",
                        align=Qt.AlignmentFlag.AlignCenter,
                        mono=True,
                    ),
                )
                self.sug_table.setItem(
                    i,
                    6,
                    make_item(
                        r.get("risk_score", 0),
                        align=Qt.AlignmentFlag.AlignCenter,
                        bold=True,
                        mono=True,
                    ),
                )
                self.sug_table.setItem(i, COL_SUG_REASON, make_item(reason, tip=reason))
                self.sug_table.setCellWidget(i, 8, self._sug_actions(r, reason))
        finally:
            self.sug_sel.end_render()

    def _sug_actions(self, r, reason: str) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(2, 2, 2, 2)
        lay.setSpacing(4)
        ip = r.get("ip", "")
        score = r.get("risk_score", 0)

        b_ban = QPushButton("确认封禁")
        b_ban.setFixedHeight(22)
        b_ban.setStyleSheet(small_button_style("danger"))
        b_ban.setCursor(Qt.CursorShape.PointingHandCursor)
        b_ban.clicked.connect(lambda: self.ask_ban.emit(ip, score, reason))

        more = row_menu_button(
            [
                ("忽略该建议", lambda: self._ignore(r)),
                ("查询该 IP 归属地", lambda: self.ask_lookup.emit(ip)),
            ]
        )

        lay.addWidget(b_ban)
        lay.addWidget(more)
        lay.addStretch(1)
        return w

    def _ignore(self, r) -> None:
        try:
            set_risk_handled(int(r["id"]), 2)
        except Exception:
            log.exception("忽略风险事件失败 id=%s", r.get("id"))
        self.refresh()

    # ── 勾选与批量处理 ──
    def _on_sug_sel_changed(self, n: int) -> None:
        self.lbl_sug_sel.setText(f"已选 {n} 条")
        self.lbl_sug_sel.setStyleSheet(f"color:{C.primary if n else C.text_muted};font-size:11px;")
        for b in (self.btn_sug_ban, self.btn_sug_ignore):
            b.setEnabled(n > 0)
        self.btn_sug_all.setText("取消全选" if n and n == len(self._sug_rows) else "全选")

    def _on_ban_sel_changed(self, n: int) -> None:
        self.lbl_ban_sel.setText(f"已选 {n} 条")
        self.lbl_ban_sel.setStyleSheet(
            f"color:{C.primary if n else C.text_secondary};font-size:12px;"
            f"font-weight:{'600' if n else '400'};"
        )
        for b in (self.btn_ban_unban, self.btn_ban_del):
            b.setEnabled(n > 0)
        self.btn_ban_all.setText("取消全选" if n and n == len(self._ban_rows) else "全选本页")

    def _checked_suggestions(self) -> list:
        return [self._sug_rows[i] for i in self.sug_sel.checked_rows() if i < len(self._sug_rows)]

    def _checked_bans(self) -> list:
        return [self._ban_rows[i] for i in self.ban_sel.checked_rows() if i < len(self._ban_rows)]

    def _batch_ban_suggestions(self) -> None:
        rows = self._checked_suggestions()
        if not rows:
            return
        # 与风险事件页同一套去重口径：一个 IP 可能命中几十条事件，
        # 但防火墙只该多一条规则
        uniq: Dict[str, Any] = {}
        ids_by_ip: Dict[str, List[int]] = {}
        for r in rows:
            ip = str(r.get("ip") or "")
            if not ip:
                continue
            ids_by_ip.setdefault(ip, []).append(int(r["id"]))
            old = uniq.get(ip)
            if old is None or int(r.get("risk_score") or 0) > int(old.get("risk_score") or 0):
                uniq[ip] = r
        items = [
            {
                "ip": ip,
                "score": int(r.get("risk_score") or 0),
                "reason": r.get("summary") or "命中风险规则",
                "event_ids": ids_by_ip.get(ip, []),
            }
            for ip, r in uniq.items()
        ]
        if items:
            self.ask_ban_many.emit(items)

    def _batch_ignore_suggestions(self) -> None:
        rows = self._checked_suggestions()
        if not rows:
            return
        ids = [int(r["id"]) for r in rows]
        try:
            n = set_risk_handled_batch(ids, 2)
        except Exception as e:
            QMessageBox.warning(self, "操作失败", str(e))
            return
        self.refresh()
        # 不弹模态框：列表当场变短就是最好的反馈
        self.sug_hint.setText(f"已忽略 {n} 条建议")

    def _batch_unban(self) -> None:
        rows = [b for b in self._checked_bans() if b.status == STATUS_ACTIVE]
        if not rows:
            QMessageBox.information(self, "无需解封", "选中的记录里没有处于「已封禁」状态的记录。")
            return
        if not firewall.is_admin():
            QMessageBox.warning(
                self, "权限不足", "批量解封需要管理员权限，请以管理员身份重启程序。"
            )
            return
        if (
            QMessageBox.question(
                self,
                "批量解封",
                f"将删除这 {len(rows)} 条记录对应的防火墙规则，并把记录标记为已解封。\n\n确认继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return

        self.btn_ban_unban.setEnabled(False)
        self.lbl_info.setText(f"正在解封 {len(rows)} 条…")
        targets = list(rows)

        def work():
            ok = 0
            fail = 0
            for b in targets:
                good, err = ban_service.unban(b)
                if good:
                    ok += 1
                else:
                    fail += 1
                    log.warning("批量解封失败 id=%s ip=%s err=%s", b.id, b.ip, err)
            self.batch_unban_done.emit(ok, fail)

        threading.Thread(target=work, daemon=True, name="unban-batch").start()

    def _on_batch_unban_done(self, ok: int, fail: int) -> None:
        self.refresh()
        self.request_refresh_stats.emit()
        if fail:
            QMessageBox.warning(
                self, "批量解封完成", f"成功 {ok} 条，失败 {fail} 条。\n详情见运行日志。"
            )
        else:
            QMessageBox.information(self, "批量解封完成", f"已解封 {ok} 条记录。")

    def _batch_delete_bans(self) -> None:
        rows = self._checked_bans()
        if not rows:
            return
        if (
            QMessageBox.question(
                self,
                "删除封禁记录",
                f"仅从数据库删除选中的 {len(rows)} 条记录，"
                "**不会**改动已生效的防火墙规则。\n\n确认删除？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        ids = [int(b.id) for b in rows if b.id is not None]
        # 删除前把关键字段整条留档：封禁记录是**记账**，删掉之后「这个 IP 曾经
        # 被封过、封的是什么状态」就再也查不到了（防火墙规则不受影响，反而更
        # 需要这条记录来解释现存规则是谁加的）。只记条数等于什么都没记。
        snapshot = [
            {
                "id": b.id,
                "ip": b.ip,
                "status": b.status,
                "source": b.source,
                "rule_name": b.rule_name,
            }
            for b in rows
        ]
        try:
            n = delete_ban_records(ids)
        except Exception as e:
            audit.record(
                audit.ACTION_BAN_DELETE,
                target_type="ban",
                summary=f"删除 {len(ids)} 条封禁记录失败：{e}",
                result=audit.RESULT_FAIL,
                detail=str(e),
            )
            QMessageBox.warning(self, "删除失败", str(e))
            return
        audit.record(
            audit.ACTION_BAN_DELETE,
            target_type="ban",
            summary=f"删除 {n} 条封禁记录（仅删库记录，未改动防火墙规则）",
            before={"bans": snapshot},
            after={"count": n},
            detail="防火墙规则未改动",
        )
        self.refresh()
        self.request_refresh_stats.emit()
        self.lbl_info.setText(f"已删除 {n} 条记录 · 共 {len(self._ban_rows)} 条")

    # ── 导出 ──
    def _export_sug_csv(self) -> None:
        """导出当前待确认建议。

        建议表的数据源是「未处理 + 高危」的前 200 条风险事件（见
        `_load_suggestions`），所以导出的是**当前这批建议**，不是全库事件。
        """
        export_table_csv(
            self,
            self._sug_rows,
            SUG_CSV_HEADERS,
            iter_sug_rows,
            default_name="ban_suggestions.csv",
            dialog_title="导出封禁建议",
            scope_hint=f"导出范围：当前待确认建议，共 {len(self._sug_rows)} 条。",
        )

    def _export_ban_csv(self) -> None:
        """导出当前筛选的封禁记录（搜索词 + 状态筛选后的结果）"""
        export_table_csv(
            self,
            self._ban_rows,
            BAN_CSV_HEADERS,
            iter_ban_rows,
            default_name="ban_records.csv",
            dialog_title="导出封禁记录",
            scope_hint=f"导出范围：当前筛选结果，共 {len(self._ban_rows)} 条。",
        )

    def _load_bans(self) -> None:
        rows = query_bans(status=self._status_filter(), keyword=self.search.text().strip())
        # 排序状态跨刷新保留：搜索词变了，用户期望的排序方向不变
        self._ban_rows_src = rows
        self._ban_rows = self.ban_sort.apply(rows)
        self._render_bans()

    def _apply_ban_sort(self, _state: Optional[SortSpec]) -> None:
        """按新排序重渲染封禁记录表：勾选按业务 key（记录 id）回放，不是按行号"""
        keys = {b.id for b in self._checked_bans()}
        self._ban_rows = self.ban_sort.apply(self._ban_rows_src)
        self._render_bans()
        self.ban_sel.set_checked_rows(i for i, b in enumerate(self._ban_rows) if b.id in keys)

    def _render_bans(self) -> None:
        rows = self._ban_rows
        self.empty.setVisible(not rows)
        self.table.setVisible(bool(rows))

        self.ban_sel.begin_render()
        try:
            self.table.setRowCount(0)
            self.table.setRowCount(len(rows))
            for i, b in enumerate(rows):
                status_color = {
                    STATUS_ACTIVE: C.danger,
                    STATUS_UNBANNED: C.text_muted,
                    STATUS_FAILED: C.danger,
                    STATUS_PENDING: C.info,
                }.get(b.status, C.text_secondary)

                self.ban_sel.fill(i)
                self.table.setItem(
                    i, 1, make_item(b.id, align=Qt.AlignmentFlag.AlignCenter, mono=True)
                )
                self.table.setItem(i, 2, make_item(b.ip, C.text_link, tip=b.ip))
                self.table.setItem(
                    i, COL_BAN_REASON, make_item(b.reason or "-", tip=b.reason or "")
                )
                self.table.setItem(
                    i, 4, make_item(b.source_label, align=Qt.AlignmentFlag.AlignCenter)
                )
                self.table.setItem(
                    i, 5, make_item(b.risk_score, align=Qt.AlignmentFlag.AlignCenter, mono=True)
                )
                self.table.setItem(
                    i, 6, make_item(b.status_label, status_color, Qt.AlignmentFlag.AlignCenter)
                )
                self.table.setItem(
                    i,
                    7,
                    make_item(b.duration_label, align=Qt.AlignmentFlag.AlignCenter, mono=True),
                )
                self.table.setItem(
                    i, 8, make_item(b.expire_min, align=Qt.AlignmentFlag.AlignCenter, mono=True)
                )
                self.table.setItem(
                    i, 9, make_item(b.created_min, align=Qt.AlignmentFlag.AlignCenter, mono=True)
                )

                self.table.setCellWidget(i, 10, self._ban_actions(b))
        finally:
            self.ban_sel.end_render()

        self.lbl_info.setText(f"共 {len(rows)} 条 · 当前生效 {count_active_bans()} 条")

    def _ban_actions(self, b) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(2, 2, 2, 2)
        lay.setSpacing(4)

        b_unban = QPushButton("解封")
        b_unban.setFixedHeight(22)
        b_unban.setStyleSheet(small_button_style("success"))
        b_unban.setCursor(Qt.CursorShape.PointingHandCursor)
        b_unban.setEnabled(b.status == STATUS_ACTIVE)
        b_unban.clicked.connect(lambda: self._unban(b))

        more = row_menu_button(
            [
                ("查询该 IP 归属地", lambda: self.ask_lookup.emit(b.ip)),
                ("复制 IP", lambda: self._copy(b.ip)),
                None,
                ("删除记录…", lambda: self._delete(b)),
            ]
        )

        lay.addWidget(b_unban)
        lay.addWidget(more)
        lay.addStretch(1)
        return w

    @staticmethod
    def _copy(text: str) -> None:
        from qtcompat import QApplication

        QApplication.clipboard().setText(text or "")

    def _unban(self, b) -> None:
        ok, err = ban_service.unban(b)
        if ok:
            self.refresh()
            self.request_refresh_stats.emit()
        else:
            QMessageBox.warning(self, "解封失败", err or "未知错误")

    def _delete(self, b) -> None:
        from core.database import delete_ban_record

        if (
            QMessageBox.question(
                self,
                "删除记录",
                f"仅从数据库删除封禁记录 #{b.id}（IP {b.ip}），"
                f"不会影响已生效的防火墙规则。\n\n确认删除？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        delete_ban_record(b.id)
        self.refresh()

    def _unban_all(self) -> None:
        if not firewall.is_admin():
            QMessageBox.warning(
                self, "权限不足", "批量解封需要管理员权限，请以管理员身份重启程序。"
            )
            return
        if (
            QMessageBox.question(
                self,
                "一键全部解封",
                "将删除所有以 PortGuard_Block_ 开头的防火墙规则，并把这些封禁记录标记为已解封。\n\n确认继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        ok, n, err = ban_service.unban_all()
        if not ok:
            QMessageBox.warning(self, "解封失败", err or "未知错误")
            return
        self.refresh()
        self.request_refresh_stats.emit()
        QMessageBox.information(self, "完成", f"已解封 {n} 条防火墙规则。")

    def _sync(self) -> None:
        """与防火墙对账：把已不存在的规则对应的记录标记为已解封"""
        if not firewall.is_admin():
            QMessageBox.information(
                self,
                "提示",
                "对账需要查询防火墙规则，请以管理员身份运行以获取完整信息。\n"
                "普通权限下仍会尝试按规则名核对。",
            )
        try:
            existing = firewall.list_rule_names()
        except Exception as e:
            log.exception("读取防火墙规则失败")
            QMessageBox.warning(self, "对账失败", str(e))
            return
        # 「读到空列表」有两种含义：规则真的都不在了，或者压根没读到
        # （netsh-only 环境 / 权限不足）。reconcile 只会按前者处理 —— 它会把库里
        # 所有 active 记录标成已解封，而防火墙规则还在系统里，从此无人巡检解封。
        try:
            active = count_active_bans()
        except Exception:
            active = 0
        if (
            not existing
            and active > 0
            and QMessageBox.question(
                self,
                "对账确认",
                f"没有从防火墙读到任何 PortGuard 规则，但库里有 {active} 条「已封禁」记录。\n\n"
                "这通常意味着本机读不到防火墙规则（旧系统 / 权限不足），"
                "而不是规则真的不存在。\n"
                f"继续对账会把 {active} 条记录全部标记为已解封，"
                "**防火墙规则不会被删除，仍将继续拦截**。\n\n"
                "确实要对账吗？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        fixed = ban_service.reconcile(existing)
        self.refresh()
        QMessageBox.information(
            self,
            "对账完成",
            f"防火墙中现存 PortGuard 规则：{len(existing)} 条\n已修正 {fixed} 条失效记录。",
        )

    def _restart_as_admin(self) -> None:
        if (
            QMessageBox.question(
                self,
                "以管理员身份重启",
                "将重新启动程序并请求管理员权限。\n\n继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        ok, err = firewall.open_admin_restart()
        if not ok:
            QMessageBox.warning(self, "提权失败", f"{err}\n\n请手动右键程序 → 以管理员身份运行。")
        else:
            from qtcompat import QApplication

            app = QApplication.instance()
            if app is not None:
                app.quit()
