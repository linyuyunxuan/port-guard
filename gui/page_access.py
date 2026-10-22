"""PortGuard — 历史访问检索页

与「风险事件页」的分工先说清楚，否则两个页面会被来回改混：

- 风险事件页回答「哪些访问**值得处理**」（规则命中的派生结论，可删、可确认）；
- 本页回答「这台机器上**到底发生过什么**」——access_log 是原始流水，
  只提供检索、翻页、看详情、导出，以及**一个**受控的清空入口（见第 5 条）。

五条实现取舍：

1. **分页而不是「最近 N 条」**：访问流水是唯一会涨到几十万行的表，
   事件页那个「最近 2000 条」的下拉在这里会变成「永远翻不到昨天」。
   代价是要多一次 COUNT，收益是「共 N 条 / 第 x/y 页」是可信的。
2. **关键词是 `%kw%` 前缀通配，走不了索引**：所以每页条数上限压在 500，
   并在筛选栏右侧写明「模糊匹配，建议先用时间范围收窄」——不写这句，
   用户在大库里输一个字符就会以为程序卡死。
3. **筛选条件变化一律回到第 1 页**：翻到第 7 页再改关键词，
   原来的 offset 会指向一个不存在的页，界面就变成空表。
4. **导出的是当前筛选结果，不是全库**，也不是当前页 —— 逐页查询拼起来，
   最多 `EXPORT_MAX_ROWS` 条，触顶时在结果框里说清楚。
5. **「清空列表」删的是当前筛选范围内的全部记录，不受分页限制**。这是本页
   唯一的破坏性操作，所以三道闸门都要有：确认框里写明「要删 N 条 / 当前页
   只显示 M 条」、无筛选时额外强调「等于清空全部访问流水」、删完写审计
   （`data.clear`）。风险事件与封禁记录一律不动 —— 流水没了不等于当时没发生。
   页面级删除只提供这一种：不做行级删除，否则「删掉一条看着碍眼的记录」和
   「这台机器到底被访问过什么」就说不清了。
"""

import datetime
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from app import audit
from core.config import LEVEL_LABEL
from core.database import (
    active_ban_ip_map,
    count_access_logs,
    delete_access_logs,
    query_access_logs,
)
from core.logger import get_logger
from core.models import AccessRecord, ms_to_str
from core.rules_meta import rule_label
from gui.components import (
    MenuEntry,
    PageHeader,
    build_menu,
    export_table_csv,
    row_menu_button,
)
from gui.theme import C
from gui.widgets import (
    EmptyState,
    RefreshGuard,
    RiskBadgeDelegate,
    align_headers,
    badge_item,
    make_item,
)
from qtcompat import (
    QAbstractItemView,
    QComboBox,
    QDate,
    QDateEdit,
    QDialog,
    QDialogButtonBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    Qt,
    QTableWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    Signal,
)

log = get_logger(__name__)

HEADERS = [
    "时间",
    "等级",
    "来源 IP",
    "归属地",
    "端口",
    "路径",
    "状态码",
    "用户代理",
    "评分",
    "操作",
]

# 列宽取「实测最宽文字 + 16px 内边距 + 24px 余量」，两条 Qt 栈各量一遍取大者
# （PySide2 的字体度量比 PySide6 宽 6~20%，按开发栈定宽会在客户机上截断）。
# 有界内容（时间 / 等级 / IP / 归属地 / 端口 / 状态码 / 评分）一律给足，不许截断。
# 无界内容（路径 / 用户代理）交给省略号 + tooltip：把它们给足会把有界列挤没。
# 实测（1200 宽窗口，视口 940）：固定列合计 777，路径列拿到 163；
# 1360 宽时路径列 323。
# ⚠️ 归属地是唯一「半有界」列：`region_short` 会把超过 16 字的境外名压成国家名，
# 但国家名本身没有上限（United Arab Emirates），极端长名仍会省略 —— 完整值在
# tooltip 与详情弹窗里，与风险事件页同一口径。
COL_TIME = 0
COL_LEVEL = 1
COL_IP = 2
COL_GEO = 3
COL_PORT = 4
COL_PATH = 5
COL_STATUS = 6
COL_UA = 7
COL_SCORE = 8
COL_ACTION = 9

COL_WIDTHS = [144, 64, 150, 133, 87, 207, 71, 120, 71, 53]

#: 内容无界的列：允许省略号，但必须有 tooltip 兜底
ELIDE_OK_COLS = (COL_PATH, COL_UA)

# 居中对齐的列（表头与数据必须一致，否则一列会被读成两根轴）
CENTER_COLS = (COL_LEVEL, COL_PORT, COL_STATUS, COL_SCORE)

# 时间筛选：右端一律取「次日零点」的左闭右开区间（与风险事件页同口径）
RANGE_ALL = "全部时间"
RANGE_TODAY = "今天"
RANGE_7D = "近 7 天"
RANGE_30D = "近 30 天"
RANGE_CUSTOM = "自定义"
RANGE_CHOICES = [RANGE_ALL, RANGE_TODAY, RANGE_7D, RANGE_30D, RANGE_CUSTOM]

#: 每页条数上限。关键词是 `%kw%` 前缀通配，不走索引，
#: 给太大等于让一个字符的搜索去扫几十万行
PAGE_SIZES = [100, 200, 500]
DEFAULT_PAGE_SIZE = 100

#: 一次导出的行数上限（防「筛选条件很宽 + 手滑确认」导出几十万行把界面冻住）
EXPORT_MAX_ROWS = 5000

ACCESS_CSV_HEADERS = [
    "记录ID",
    "时间",
    "风险等级",
    "来源IP",
    "归属地",
    "目标端口",
    "协议",
    "方法",
    "请求路径",
    "状态码",
    "响应大小",
    "评分",
    "命中规则",
    "标签",
    "用户代理",
]


def iter_access_rows(rows: Sequence[Any]) -> Iterator[List[Any]]:
    """访问记录（`AccessRecord`）-> CSV 行。

    放在本文件而不是 `app/export_csv.py`：那三张表的行构造是 P2-1 一次性
    抽出来的，本页不并入同一次改动，避免和并行开发的工人抢同一个文件。
    口径与那边保持一致（时间用完整 `YYYY-MM-DD HH:MM:SS`、规则 ID 转中文）。
    """
    for r in rows:
        geo = getattr(r, "geo", None)
        yield [
            r.id,
            ms_to_str(r.event_ts),
            LEVEL_LABEL.get(r.risk_level, r.risk_level),
            r.ip,
            (geo.display if geo is not None else "未知"),
            r.local_port,
            r.protocol,
            r.method,
            r.path or "/",
            r.status_code,
            r.size,
            r.risk_score,
            "、".join(rule_label(x) for x in (r.matched_rules or [])),
            r.tags or {},
            r.user_agent,
        ]


def _day_start(d: datetime.date) -> datetime.datetime:
    return datetime.datetime(d.year, d.month, d.day)


class AccessDetailDialog(QDialog):
    """访问记录详情：表格里放不下的字段（协议 / 方法 / UA / 标签 / 命中规则）"""

    def __init__(self, rec: AccessRecord, parent=None):
        super().__init__(parent)
        self.setWindowTitle(f"访问记录详情 #{rec.id}")
        self.setMinimumSize(560, 460)
        lay = QVBoxLayout(self)
        txt = QTextEdit()
        txt.setReadOnly(True)
        geo = rec.geo
        lines = [
            f"记录 ID：#{rec.id}",
            f"时间：{rec.time_str}",
            f"来源 IP：{rec.ip}",
            f"归属地：{geo.display if geo else '未知'}",
            f"目标端口：{rec.local_port}（对端端口 {rec.remote_port or '-'}）",
            f"协议 / 方法：{rec.protocol or '-'} / {rec.method or '-'}",
            f"请求路径：{rec.path or '/'}",
            f"状态码：{rec.status_code if rec.status_code is not None else '-'}",
            f"响应大小：{rec.size} 字节",
            f"主机名：{rec.host or '-'}",
            f"风险评分：{rec.risk_score}",
            f"风险等级：{rec.level_label}",
            f"命中规则：{rec.matched_str or '-'}",
            "",
            "用户代理：",
            rec.user_agent or "-",
        ]
        if rec.tags:
            lines += ["", "标签："]
            lines += [f"  {k}：{v}" for k, v in rec.tags.items()]
        if geo is not None and geo.found:
            lines += [
                "",
                "归属地明细：",
                f"  国家：{geo.country}  省份：{geo.province}",
                f"  城市：{geo.city}  ISP：{geo.isp}  国家码：{geo.iso}",
            ]
        txt.setPlainText("\n".join(lines))
        lay.addWidget(txt)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.reject)
        btns.accepted.connect(self.accept)
        lay.addWidget(btns)


class AccessPage(QWidget):
    """历史访问记录检索（关键词 / 等级 / 端口 / 时间范围 + 分页）"""

    ask_ban = Signal(str, int, str)
    ask_lookup = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: List[AccessRecord] = []
        self._total = 0
        # 生效中的封禁（IP → 记录）：行内菜单据此把「封禁该 IP」置灰
        self._banned: Dict[str, Any] = {}
        self._page = 0
        self._build()
        self.refresh()

    # ── 构建 ──
    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 16, 24, 12)
        root.setSpacing(12)

        head = PageHeader("历史访问", "全部访问流水，可按 IP / 路径 / 浏览器特征回溯")
        self.btn_refresh = QPushButton("刷新")
        self.btn_refresh.setObjectName("btn_outline")
        self.btn_refresh.clicked.connect(self.refresh)
        head.add_action(self.btn_refresh)

        # 破坏性按钮用 outline 而不是实心红：本页的日常操作是「回溯查看」，
        # 头部常驻一颗红色实心按钮会天天抢注意力；风险由确认框与审计承担。
        self.btn_clear = QPushButton("清空列表")
        self.btn_clear.setObjectName("btn_outline")
        self.btn_clear.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_clear.setToolTip(
            "清空当前筛选范围内的全部访问记录（不受分页限制）。\n"
            "风险事件与封禁记录不受影响；操作不可恢复，建议先导出 CSV。"
        )
        self.btn_clear.clicked.connect(self._clear_list)
        head.add_action(self.btn_clear)
        root.addWidget(head)

        root.addLayout(self._build_filters())

        self.empty = EmptyState("暂无访问记录", "还没有收到任何访问上报")
        self.empty.setVisible(False)
        root.addWidget(self.empty)

        root.addWidget(self._build_table(), 1)
        root.addLayout(self._build_pager())

    def _build_filters(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(8)

        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索 IP / 路径 / UA…")
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(260)
        self.search.setToolTip(
            "模糊匹配 IP / 路径 / 用户代理（%kw% 前缀通配，不走索引）。\n"
            "数据量大时建议先用时间范围收窄再搜。"
        )
        self.search.textChanged.connect(self._on_filter_changed)

        self.level = QComboBox()
        self.level.addItems(["全部等级", "严重", "高", "中", "低", "正常"])
        self.level.setFixedWidth(118)
        self.level.currentIndexChanged.connect(self._on_filter_changed)

        self.port = QLineEdit()
        self.port.setPlaceholderText("端口")
        self.port.setClearButtonEnabled(True)
        self.port.setFixedWidth(92)
        self.port.setToolTip("按目标端口精确筛选（留空为全部）")
        self.port.textChanged.connect(self._on_filter_changed)

        self.range = QComboBox()
        self.range.addItems(RANGE_CHOICES)
        self.range.setFixedWidth(122)
        self.range.currentIndexChanged.connect(self._on_range_changed)

        self.dt_from = QDateEdit()
        self.dt_from.setCalendarPopup(True)
        self.dt_from.setDisplayFormat("yyyy-MM-dd")
        self.dt_from.setFixedWidth(128)
        self.dt_from.setDate(QDate.currentDate().addDays(-6))
        self.dt_from.dateChanged.connect(self._on_filter_changed)

        self.lbl_to = QLabel("至")
        self.lbl_to.setStyleSheet(f"color:{C.text_muted};font-size:13.5px;")

        self.dt_to = QDateEdit()
        self.dt_to.setCalendarPopup(True)
        self.dt_to.setDisplayFormat("yyyy-MM-dd")
        self.dt_to.setFixedWidth(128)
        self.dt_to.setDate(QDate.currentDate())
        self.dt_to.dateChanged.connect(self._on_filter_changed)

        for widget in (self.dt_from, self.lbl_to, self.dt_to):
            widget.setVisible(False)

        self.limit = QComboBox()
        self.limit.addItems([f"每页 {n} 条" for n in PAGE_SIZES])
        self.limit.setFixedWidth(128)
        self.limit.currentIndexChanged.connect(self._on_filter_changed)

        self.btn_export = QPushButton("导出 CSV")
        self.btn_export.setObjectName("btn_outline")
        self.btn_export.setFixedHeight(30)
        self.btn_export.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_export.clicked.connect(self._export_csv)
        self.btn_export.setToolTip("导出当前筛选结果，不受分页影响")

        # 筛选栏的宽度在 1200 窗口下只够放一句短提示（实测放长句会被裁掉），
        # 完整解释放在 tooltip 与搜索框 tooltip 里。
        self.lbl_hint = QLabel("关键词为模糊匹配")
        self.lbl_hint.setStyleSheet(f"color:{C.text_muted};font-size:12.5px;")
        self.lbl_hint.setToolTip(
            "关键词按「包含」匹配 IP / 路径 / 用户代理三列（%kw% 前缀通配，走不了索引），\n"
            "数据量大时建议先用时间范围收窄再搜，单页条数上限也因此在 "
            f"{max(PAGE_SIZES)} 条。"
        )

        for w in (self.search, self.level, self.port, self.range):
            bar.addWidget(w)
        bar.addWidget(self.dt_from)
        bar.addWidget(self.lbl_to)
        bar.addWidget(self.dt_to)
        bar.addWidget(self.limit)
        bar.addWidget(self.btn_export)
        bar.addStretch(1)
        bar.addWidget(self.lbl_hint)
        return bar

    def _build_table(self) -> QTableWidget:
        self.table = QTableWidget(0, len(HEADERS))
        self.table.setHorizontalHeaderLabels(HEADERS)

        align_headers(self.table, CENTER_COLS)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.setWordWrap(False)
        self.table.setTabKeyNavigation(False)
        self.table.verticalHeader().setVisible(False)
        # 常显竖滚动条：滚动条出现/消失会让表格可视宽在 15↔25px 之间跳，
        # 结果列宽度每次翻页都变（与风险事件页同一条理由）
        self.table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.table.verticalHeader().setDefaultSectionSize(34)
        self.table.doubleClicked.connect(self._on_double_click)
        self.table.setItemDelegateForColumn(COL_LEVEL, RiskBadgeDelegate(self.table))
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._ctx_menu)

        hh = self.table.horizontalHeader()
        for i, w in enumerate(COL_WIDTHS):
            hh.resizeSection(i, w)
        # 路径是唯一的拉伸列：它和 UA 都是无界内容，但路径才是「这条访问是谁」
        hh.setSectionResizeMode(COL_PATH, QHeaderView.ResizeMode.Stretch)
        return self.table

    def _build_pager(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(8)

        self.btn_prev = self._pager_button("上一页")
        self.btn_prev.clicked.connect(lambda: self._goto_page(self._page - 1))

        self.btn_next = self._pager_button("下一页")
        self.btn_next.clicked.connect(lambda: self._goto_page(self._page + 1))

        self.lbl_page = QLabel("共 0 条，第 1/1 页")
        self.lbl_page.setStyleSheet(f"color:{C.text_secondary};font-size:13.5px;")
        # 「正在刷新…」与「更新于」复用分页信息这行（见 widgets.RefreshGuard）
        self._refresh = RefreshGuard(self.lbl_page)

        bar.addWidget(self.btn_prev)
        bar.addWidget(self.btn_next)
        bar.addSpacing(6)
        bar.addWidget(self.lbl_page)
        bar.addStretch(1)
        return bar

    @staticmethod
    def _pager_button(text: str) -> QPushButton:
        b = QPushButton(text)
        b.setFixedHeight(30)
        b.setFixedWidth(80)
        b.setObjectName("btn_outline")
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        return b

    # ── 筛选 ──
    def _on_filter_changed(self, *_args: Any) -> None:
        # 条件变了必须回到第 1 页：在第 7 页改关键词，原 offset 会指向空页
        self._page = 0
        self.refresh()

    def _on_range_changed(self, _idx: int) -> None:
        custom = self.range.currentText() == RANGE_CUSTOM
        for w in (self.dt_from, self.lbl_to, self.dt_to):
            w.setVisible(custom)
        self._on_filter_changed()

    def _range_ms(self) -> Tuple[Optional[int], Optional[int]]:
        """返回 (since_ts, until_ts)，左闭右开；None 表示该端不限。"""
        text = self.range.currentText()
        now = datetime.datetime.now()
        today = datetime.date(now.year, now.month, now.day)
        start: Optional[datetime.datetime] = None
        end: Optional[datetime.datetime] = None

        if text == RANGE_TODAY:
            start, end = _day_start(today), _day_start(today) + datetime.timedelta(days=1)
        elif text == RANGE_7D:
            start, end = (
                _day_start(today) - datetime.timedelta(days=6),
                _day_start(today) + datetime.timedelta(days=1),
            )
        elif text == RANGE_30D:
            start, end = (
                _day_start(today) - datetime.timedelta(days=29),
                _day_start(today) + datetime.timedelta(days=1),
            )
        elif text == RANGE_CUSTOM:
            d1 = self.dt_from.date()
            d2 = self.dt_to.date()
            a = datetime.date(d1.year(), d1.month(), d1.day())
            b = datetime.date(d2.year(), d2.month(), d2.day())
            if a > b:  # 用户把起止填反了就自动纠正，不弹框打断
                a, b = b, a
            start = _day_start(a)
            end = _day_start(b) + datetime.timedelta(days=1)

        since = int(start.timestamp() * 1000) if start else None
        until = int(end.timestamp() * 1000) if end else None
        return since, until

    def _level_filter(self) -> str:
        m = {"严重": "critical", "高": "high", "中": "medium", "低": "low", "正常": "normal"}
        return m.get(self.level.currentText(), "")

    def _port_filter(self) -> Optional[int]:
        text = self.port.text().strip()
        if not text:
            return None
        try:
            return int(text)
        except ValueError:
            # 输到一半（"8" 之外的字符）不该把列表清空，按「不限端口」处理
            return None

    def _page_size(self) -> int:
        idx = self.limit.currentIndex()
        if 0 <= idx < len(PAGE_SIZES):
            return PAGE_SIZES[idx]
        return DEFAULT_PAGE_SIZE

    def _filters_active(self) -> bool:
        return bool(
            self.search.text().strip()
            or self.port.text().strip()
            or self.level.currentIndex() > 0
            or self.range.currentText() != RANGE_ALL
        )

    # ── 数据 ──
    def refresh(self) -> None:
        # 翻页也走这里：连点「下一页」会叠查询，守卫一并挡住
        if self._refresh.busy:
            return
        with self._refresh:
            self._load()

    def _load(self) -> None:
        since, until = self._range_ms()
        size = self._page_size()
        try:
            total = count_access_logs(
                keyword=self.search.text().strip(),
                level=self._level_filter(),
                port=self._port_filter(),
                since_ts=since,
                until_ts=until,
            )
        except Exception as e:  # 库被占用 / 损坏时不能让整个页面白屏
            self._render([])
            self._total = 0
            self._page = 0
            self._update_pager()
            self.empty.set_state("读取失败", str(e))
            self.empty.setVisible(True)
            self.lbl_page.setText("读取失败")
            return

        pages = max(1, (total + size - 1) // size)
        # 总数变小（换了筛选条件 / 期间被清理）时把页码夹回最后一页
        if self._page >= pages:
            self._page = max(0, pages - 1)

        rows = query_access_logs(
            limit=size,
            offset=self._page * size,
            keyword=self.search.text().strip(),
            level=self._level_filter(),
            port=self._port_filter(),
            since_ts=since,
            until_ts=until,
        )
        self._rows = rows
        self._total = total
        # 行内菜单里的「封禁该 IP」要知道这个 IP 是不是已经在封禁中；
        # 一次查询给整页用（逐行查 = 每页 N 次建连）
        try:
            self._banned = active_ban_ip_map()
        except Exception:
            log.exception("加载生效中的封禁失败（菜单将按「未封禁」渲染）")
            self._banned = {}
        self._render(rows)
        self._update_pager()

    def _page_count(self) -> int:
        size = self._page_size()
        return max(1, (self._total + size - 1) // size)

    def _goto_page(self, page: int) -> None:
        if page < 0 or page >= self._page_count():
            return
        self._page = page
        self.refresh()

    def _update_pager(self) -> None:
        pages = self._page_count()
        self.lbl_page.setText(f"共 {self._total} 条，第 {self._page + 1}/{pages} 页")
        self.btn_prev.setEnabled(self._page > 0)
        self.btn_next.setEnabled(self._page + 1 < pages)
        self.btn_export.setToolTip(f"导出当前筛选结果（{self._total} 条）")
        # 一条都没有时「清空列表」无处可点：留着只会让人怀疑按钮坏了
        self.btn_clear.setEnabled(self._total > 0)

    def _render(self, rows: List[AccessRecord]) -> None:
        if rows:
            self.empty.setVisible(False)
        else:
            self.empty.set_state(
                "没有符合条件的访问记录" if self._filters_active() else "暂无访问记录",
                "试试放宽时间范围、清空搜索或换一个端口"
                if self._filters_active()
                else "还没有收到任何访问上报",
            )
            self.empty.setVisible(True)
        self.table.setVisible(bool(rows))

        self.table.setRowCount(0)
        self.table.setRowCount(len(rows))
        for i, r in enumerate(rows):
            geo = r.geo
            time_str = datetime.datetime.fromtimestamp(r.event_ts / 1000).strftime("%m-%d %H:%M:%S")
            ip_text = str(r.ip or "")
            path_text = str(r.path or "/")
            ua_text = str(r.user_agent or "")

            self.table.setItem(i, COL_TIME, make_item(time_str, mono=True, tip=r.time_str))
            self.table.setItem(i, COL_LEVEL, badge_item(r.risk_level))
            self.table.setItem(i, COL_IP, make_item(ip_text, C.text_link, tip=ip_text))
            self.table.setItem(
                i,
                COL_GEO,
                make_item(geo.region_short if geo else "未知", tip=geo.display if geo else "未知"),
            )
            self.table.setItem(
                i,
                COL_PORT,
                make_item(r.local_port or "-", align=Qt.AlignmentFlag.AlignCenter, mono=True),
            )
            self.table.setItem(i, COL_PATH, make_item(path_text, tip=path_text))
            self.table.setItem(
                i,
                COL_STATUS,
                make_item(
                    r.status_code if r.status_code is not None else "-",
                    align=Qt.AlignmentFlag.AlignCenter,
                    mono=True,
                ),
            )
            self.table.setItem(i, COL_UA, make_item(ua_text or "-", tip=ua_text))
            self.table.setItem(
                i,
                COL_SCORE,
                make_item(r.risk_score, align=Qt.AlignmentFlag.AlignCenter, bold=True, mono=True),
            )
            self.table.setCellWidget(i, COL_ACTION, self._row_actions(r))

    # ── 导出 ──
    def _export_csv(self) -> None:
        """导出**当前筛选结果**（不是当前页），上限 EXPORT_MAX_ROWS 条。

        逐页查询而不是一次 LIMIT 全量：一次拉几万行会在主线程里把界面冻住，
        而分页复用的是页面已有的查询，条件天然一致。
        """
        since, until = self._range_ms()
        kw = self.search.text().strip()
        lvl = self._level_filter()
        port = self._port_filter()
        rows = query_access_logs(
            limit=EXPORT_MAX_ROWS,
            offset=0,
            keyword=kw,
            level=lvl,
            port=port,
            since_ts=since,
            until_ts=until,
        )
        scope = f"导出范围：当前筛选结果，共 {len(rows)} 条。"
        if len(rows) >= EXPORT_MAX_ROWS:
            scope += f"\n已达单次导出上限 {EXPORT_MAX_ROWS} 条，请收窄筛选条件后分次导出。"
        export_table_csv(
            self,
            rows,
            ACCESS_CSV_HEADERS,
            iter_access_rows,
            default_name="access_logs.csv",
            dialog_title="导出历史访问记录",
            scope_hint=scope,
        )

    # ── 清空 ──
    def _filter_scope_text(self) -> str:
        """当前筛选条件的中文描述（确认框与审计共用，避免「弹窗说 A、审计记 B」）"""
        parts: List[str] = []
        kw = self.search.text().strip()
        if kw:
            parts.append(f"关键词「{kw}」")
        if self.level.currentIndex() > 0:
            parts.append(f"等级={self.level.currentText()}")
        port = self.port.text().strip()
        if port:
            parts.append(f"端口={port}")
        text = self.range.currentText()
        if text == RANGE_CUSTOM:
            parts.append(
                f"时间 {self.dt_from.date().toString('yyyy-MM-dd')}"
                f" 至 {self.dt_to.date().toString('yyyy-MM-dd')}"
            )
        elif text != RANGE_ALL:
            parts.append(f"时间={text}")
        return "、".join(parts)

    def _clear_list(self) -> None:
        """清空当前筛选范围内的访问记录（不受分页限制）。

        为什么要先 count 再删：确认框里必须给出**要删多少条**，而这个数字来自
        与列表查询同一个 `_access_where`。只写「确认清空？」的话，用户看到的
        是每页 50 条，很容易以为只删这一页。

        确认与执行之间仍可能有新记录落库（同一个筛选条件会被它们命中），所以
        结果框和审计都用**实际删除条数**，同时把确认时的 `matched` 一并记下 ——
        两个数字不一致时，能看出是「期间又来了新记录」而不是程序算错了。
        """
        since, until = self._range_ms()
        kw = self.search.text().strip()
        lvl = self._level_filter()
        port = self._port_filter()
        try:
            total = count_access_logs(
                keyword=kw, level=lvl, port=port, since_ts=since, until_ts=until
            )
        except Exception as e:
            self._notify("读取失败", f"统计待清空的记录数失败：\n{e}", warn=True)
            return
        if total <= 0:
            self._notify("没有可清空的记录", "当前筛选条件下没有访问记录，无需清空。")
            return

        scoped = self._filters_active()
        if scoped:
            scope_desc = self._filter_scope_text()
            head = f"将清空「{scope_desc}」范围内的 {total} 条访问记录。"
        else:
            scope_desc = "全部时间、全部等级、全部端口（无筛选）"
            head = f"当前没有任何筛选条件，将清空全部 {total} 条访问记录。"

        if not self._confirm_clear(head, total):
            return

        try:
            deleted = delete_access_logs(
                keyword=kw,
                level=lvl,
                port=port,
                since_ts=since,
                until_ts=until,
                # 无筛选时才是「清空全部」；数据层要求这种调用显式声明意图
                all_rows=not scoped,
            )
        except Exception as e:
            audit.record(
                audit.ACTION_DATA_CLEAR,
                target_type="access",
                summary=f"清空访问列表失败（{scope_desc}）：{e}",
                result=audit.RESULT_FAIL,
                detail=str(e),
            )
            self._notify("清空失败", f"未能清空访问记录：\n{e}", warn=True)
            return

        # 破坏性操作必须留痕：事后唯一能回答「数据哪天没的、删了多少」的就是这条
        audit.record(
            audit.ACTION_DATA_CLEAR,
            target_type="access",
            summary=f"清空访问列表：{scope_desc}，删除 {deleted} 条",
            before={"scope": scope_desc, "matched": total},
            after={"deleted": deleted},
        )
        self._page = 0
        self.refresh()
        self._notify("已清空", f"已删除 {deleted} 条访问记录。")

    def _confirm_clear(self, head: str, total: int) -> bool:
        """清空前的确认框。单独成方法是为了让用例能稳定地「点取消 / 点清空」——

        离屏环境下 `exec()` 会一直等到有人点按钮，用例没法测这条路径。
        """
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle("清空访问列表")
        box.setText(head)
        box.setInformativeText(
            f"· 不受分页限制：当前页只显示 {len(self._rows)} 条，实际删除 {total} 条；\n"
            "· 风险事件、封禁记录、黑白名单都不受影响；\n"
            "· 删除后无法恢复，需要留档请先导出 CSV。"
        )
        btn_yes = box.addButton("清空", QMessageBox.ButtonRole.DestructiveRole)
        btn_no = box.addButton("取消", QMessageBox.ButtonRole.RejectRole)
        # 默认焦点给「取消」：这是不可逆操作，回车不该等于确认
        box.setDefaultButton(btn_no)
        box.exec()
        return box.clickedButton() is btn_yes

    def _notify(self, title: str, text: str, warn: bool = False) -> None:
        if warn:
            QMessageBox.warning(self, title, text)
        else:
            QMessageBox.information(self, title, text)

    # ── 行内操作 ──
    def _row_actions(self, r: AccessRecord) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(2, 2, 2, 2)
        lay.setSpacing(2)
        more = row_menu_button(self._menu_entries(r))
        lay.addWidget(more)
        lay.addStretch(1)
        return w

    def _menu_entries(self, r: AccessRecord) -> List[Optional[MenuEntry]]:
        """行内「⋯」与右键菜单共用同一份动作定义"""
        ip = r.ip or ""
        banned = ip in self._banned
        return [
            ("查看详情", lambda: AccessDetailDialog(r, self).exec()),
            None,
            ("查询该 IP 归属地", lambda: self.ask_lookup.emit(ip)),
            ("复制 IP", lambda: self._copy(ip)),
            ("复制路径", lambda: self._copy(r.path or "/")),
            None,
            # 已封禁的 IP 保留这一项但置灰：删掉会让人以为「回溯封禁」功能没了
            (
                "已在封禁中" if banned else "封禁该 IP",
                None
                if banned
                else (
                    lambda: self.ask_ban.emit(
                        ip, int(r.risk_score or 0), r.matched_str or "人工回溯"
                    )
                ),
            ),
        ]

    def _row_menu(self, r: AccessRecord, parent=None) -> QMenu:
        return build_menu(self._menu_entries(r), parent)

    @staticmethod
    def _copy(text: str) -> None:
        from qtcompat import QApplication

        QApplication.clipboard().setText(text or "")

    def _ctx_menu(self, pos) -> None:
        idx = self.table.indexAt(pos)
        if not idx.isValid() or idx.row() >= len(self._rows):
            return
        self.table.selectRow(idx.row())
        menu = self._row_menu(self._rows[idx.row()], parent=self)
        menu.exec(self.table.viewport().mapToGlobal(pos))

    def _on_double_click(self, index) -> None:
        if 0 <= index.row() < len(self._rows):
            AccessDetailDialog(self._rows[index.row()], self).exec()
