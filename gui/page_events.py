"""PortGuard — 风险事件页

本页承担「事后复盘」而不是「实时盯屏」，所以三条设计取舍先写清楚，
免得后人把这里改回单行操作：

1. **勾选框（第 0 列）与行选中是两套语义**：勾选用于批量、跨筛选保留意图；
   行选中只服务当前焦点（双击详情、右键菜单）。不合并成 ExtendedSelection，
   因为「选中行」在键盘操作下太容易误改，而批量误封是不可逆的。
2. **批量操作条常驻，不做「有勾选才浮出」的浮层**：浮层会让表格上下跳 30~40px，
   连续滚读时最丢位置。代价是常占一行高度，收益是位置永远稳定。
3. **删除只删 risk_event，不动 access_log**：访问流水是原始事实，
   事件是规则算出来的派生结论。删事件表示「这条结论我不认」，
   不应该连带把「这台机器确实来过」的原始记录也抹掉。
4. **不设「状态」列**：操作列已经写明封没封（「封禁」/「已封禁」），
   再摆一列「未处理/已确认/已忽略」等于同一件事说两遍，还容易被误读成
   「已确认 = 已拦截」。人工处理状态收敛进「处置」列，见 `_disposition_cell`。
"""

import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from app import audit
from app.export_csv import EVENT_CSV_HEADERS, iter_event_rows
from core.config import LEVEL_LABEL, LEVEL_ORDER
from core.database import (
    delete_risk_events,
    risk_events_page,
    set_risk_handled_batch,
)
from core.logger import get_logger
from core.models import (
    DISPOSITION_ALERT,
    DISPOSITION_ALLOW,
    DISPOSITION_BLOCK,
    DISPOSITION_CONFIRM,
    DISPOSITION_HINT,
    DISPOSITION_IGNORED,
    DISPOSITION_ORDER,
    HANDLED_LABEL,
    disposition_label,
    disposition_of,
    ms_to_str,
)
from core.rules_meta import rule_label
from gui.components import (
    MenuEntry,
    PageHeader,
    build_menu,
    export_table_csv,
)
from gui.event_group import flatten_rows, merge_rows
from gui.row_action import RowAction, RowActionDelegate
from gui.table_select import CheckColumn
from gui.table_sort import KIND_MS, KIND_NUM, KIND_TEXT, ColumnSpec, SortSpec, TableSort
from gui.theme import C, small_button_style
from gui.widgets import (
    CheckMarkDelegate,
    EmptyState,
    RefreshGuard,
    RiskBadgeDelegate,
    SortHeader,
    align_headers,
    badge_item,
    make_item,
)
from qtcompat import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDate,
    QDateEdit,
    QDialog,
    QDialogButtonBox,
    QFrame,
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
    "",
    "时间",
    "等级",
    "来源 IP",
    "归属地",
    "端口",
    "路径",
    "评分",
    "命中规则",
    "处置",
    "操作",
]

# 列宽取「实测最宽文字 + 16px padding + 8px 余量」，按 PySide2（交付栈）的字体
# 度量算——它比 PySide6 宽 6~20%，按开发栈定宽会在客户机上截断。
# 有界内容（时间 / 等级 / IP / 归属地 / 端口 / 评分 / 处置）一律给足，不许截断：
# 截了用户就分不清是哪条记录。无界内容（路径 / 命中规则）交给 tooltip 兜底，
# 第 6 列（路径）同时是唯一的拉伸列。
# 时间列用 `MM-DD HH:MM:SS`：事件页是事后复盘，同一分钟可能有十几条爆破记录，
# 秒数是排序的唯一依据，不能省成分钟。同类合并开启时该列还会带 ` ×N` 后缀
# （N 最大按三位数留量），所以比裸时间戳宽 40px。
# 评分列 46px：`100` 在等宽加粗下要 21px，太窄会被省略成「1…」—— 分数直接被
# 读错一个数量级，比列宽值钱。
COL_CHECK = 0
COL_TIME = 1
COL_LEVEL = 2
COL_IP = 3
COL_GEO = 4
COL_PORT = 5
COL_PATH = 6
COL_SCORE = 7
COL_RULE = 8
COL_DISPOSITION = 9
COL_ACTION = 10

COL_WIDTHS = [37, 138, 62, 142, 124, 58, 125, 52, 178, 80, 106]

# 列排序规则（数据层，见 gui/table_sort.py 开头为什么不用 setSortingEnabled）。
# 勾选列（点了是全选）与操作列（无值）不给规则 —— 点这两列表头不排序。
# 等级按**语义序**排而不是按中文笔画：等级取 LEVEL_ORDER 的严重度，按本地化
# 文本排的话「严/高/中/低」是乱序；处置同样按 DISPOSITION_ORDER 的处置先后排。
SORT_SPECS = {
    COL_TIME: ColumnSpec(KIND_MS, lambda r: r.get("event_ts")),
    COL_LEVEL: ColumnSpec(KIND_NUM, lambda r: LEVEL_ORDER.get(str(r.get("risk_level") or ""))),
    COL_IP: ColumnSpec(KIND_TEXT, lambda r: r.get("ip")),
    COL_GEO: ColumnSpec(KIND_TEXT, lambda r: r.get("geo").region_short if r.get("geo") else ""),
    COL_PORT: ColumnSpec(KIND_NUM, lambda r: r.get("local_port")),
    COL_PATH: ColumnSpec(KIND_TEXT, lambda r: r.get("path") or "/"),
    COL_SCORE: ColumnSpec(KIND_NUM, lambda r: r.get("risk_score")),
    COL_RULE: ColumnSpec(
        KIND_TEXT, lambda r: "、".join(rule_label(x) for x in r.get("matched_rules", [])) or ""
    ),
    COL_DISPOSITION: ColumnSpec(KIND_NUM, lambda r: DISPOSITION_ORDER.get(disposition_of(r))),
}

#: 内容无界的列：允许省略号，但必须有 tooltip 兜底
ELIDE_OK_COLS = (COL_PATH, COL_RULE)

# 居中对齐的列（表头与数据必须一致，否则一列会被读成两根轴）
CENTER_COLS = (COL_CHECK, COL_LEVEL, COL_PORT, COL_SCORE, COL_DISPOSITION)

# 时间筛选：右端一律取「次日零点」的左闭右开区间
RANGE_ALL = "全部时间"
RANGE_TODAY = "今天"
RANGE_7D = "近 7 天"
RANGE_30D = "近 30 天"
RANGE_CUSTOM = "自定义"
RANGE_CHOICES = [RANGE_ALL, RANGE_TODAY, RANGE_7D, RANGE_30D, RANGE_CUSTOM]


def _day_start(d: datetime.date) -> datetime.datetime:
    return datetime.datetime(d.year, d.month, d.day)


#: 处置结论 → 文字颜色。
# 红色刻意不在这里出现：红色留给等级徽章（一屏几十行时红色必须稀缺）。
# 「待确认」用琥珀色表达「等你来决定」，「已拦截」用绿色表达「已处置完」。
_DISPOSITION_COLOR = {
    DISPOSITION_ALLOW: C.text_muted,
    DISPOSITION_ALERT: C.text_secondary,
    DISPOSITION_CONFIRM: C.warning,
    DISPOSITION_BLOCK: C.success,
    DISPOSITION_IGNORED: C.text_muted,
}


def _disposition_cell(row: Dict, handled: int) -> Tuple[str, str, str]:
    """处置列 = 这条事件的**最终结论**（文本, 颜色, tooltip）。

    本页没有独立的「状态」列：操作列已经写明封没封（「封禁」/「已封禁」），
    再放一列「未处理/已确认/已忽略」就是同一件事说两遍，而且两张表对着看时
    容易把「状态=已确认」误读成「已拦截」。所以人工处理状态收敛进本列：

    · 已忽略 —— 直接盖掉系统判定。人主动放弃的事件必须一眼可见，
      否则「这条我不管了」在表里彻底隐形；
    · 已确认 且系统判定仍是「待确认」—— 显示「已确认」。保留「待确认」会
      自相矛盾：用户刚点过确认，回来还看到它在等自己确认；
    · 其余已确认（已拦截 / 仅提醒 / 已放行）—— 结论本身比「人看过」重要，
      文案不动，只在 tooltip 里补一句。
    """
    disp = disposition_of(row)
    text = disposition_label(disp)
    tip = DISPOSITION_HINT.get(disp, "")
    if handled == 2:
        return (
            disposition_label(DISPOSITION_IGNORED),
            C.text_muted,
            f"{DISPOSITION_HINT.get(DISPOSITION_IGNORED, '')}（系统判定：{text}）",
        )
    if handled == 1 and disp == DISPOSITION_CONFIRM:
        return HANDLED_LABEL.get(1, text), C.text_link, f"{tip}（已人工确认）"
    if handled == 1:
        tip = f"{tip}（已人工确认）"
    return text, _DISPOSITION_COLOR.get(disp, C.text_secondary), tip


#: handled 值 → 审计 action。0 是「未处理」，不会被写进审计（没有这个动作）。
_HANDLED_ACTION = {
    1: audit.ACTION_EVENT_CONFIRM,
    2: audit.ACTION_EVENT_IGNORE,
}


def _handled_action(handled: int) -> str:
    """确认/忽略共用一个入口，按目标状态分流到两个 action"""
    return _HANDLED_ACTION.get(handled, audit.ACTION_EVENT_CONFIRM)


def _handled_entries(handled: int, set_handled: Callable[[int], object]) -> List[MenuEntry]:
    """「确认处理 / 忽略」两项随当前处理状态变：状态那项置灰、文案改成状态名。

    `handled`：0 未处理 / 1 已确认 / 2 已忽略（见 `core.models.HANDLED_LABEL`）。
    两个动作互为反向保留 —— 误点了「确认」还能在同一个菜单里改回「忽略」，
    这是全页唯一能纠正误操作的地方。
    """
    if handled == 1:
        return [("已确认", None), ("改为忽略", lambda: set_handled(2))]
    if handled == 2:
        return [("改为确认处理", lambda: set_handled(1)), ("已忽略", None)]
    return [("确认处理", lambda: set_handled(1)), ("忽略", lambda: set_handled(2))]


def _ban_tip(ban: Optional[Any]) -> str:
    """已封禁行的按钮 tooltip：「到什么时候」比「已封禁」三个字更有用"""
    if ban is None:
        return ""
    bid = getattr(ban, "id", "-")
    exp = getattr(ban, "expire_at", None)
    if not exp:
        return f"该 IP 已永久封禁（记录 #{bid}）；解封请到「封禁管理」页"
    return f"该 IP 已封禁，{ms_to_str(exp)} 到期（记录 #{bid}）；解封请到「封禁管理」页"


def _event_snapshot(rows: List[Dict]) -> List[Dict]:
    """
    被操作事件的审计快照。

    只取事后真要回溯的字段：id 用于定位、ip 用于「删了谁的记录」、
    handled 用于「删的时候是已确认还是未处理」、等级与分数用于「这条结论有多严重」。
    地理/路径/规则明细不取 —— 它们能被 access_log 还原，且会让 JSON 膨胀几倍。
    """
    return [
        {
            "id": r.get("id"),
            "ip": r.get("ip") or "",
            "handled": r.get("handled", 0),
            "level": r.get("risk_level") or "",
            "score": r.get("risk_score") or 0,
        }
        for r in rows
    ]


class EventDetailDialog(QDialog):
    def __init__(self, row: Dict, parent=None):
        super().__init__(parent)
        self.setWindowTitle("风险事件详情")
        self.setMinimumSize(560, 420)
        lay = QVBoxLayout(self)
        txt = QTextEdit()
        txt.setReadOnly(True)
        geo = row.get("geo")
        # row 取出的值类型是 Any|None，先归一化成 str 再查表，避免把 None 当字典键
        risk_level = str(row.get("risk_level") or "")
        disp = disposition_of(row)
        lines = [
            f"事件 ID：#{row.get('id')}",
            f"时间：{ms_to_str(row.get('event_ts'))}",
            f"来源 IP：{row.get('ip')}",
            f"归属地：{geo.display if geo else '未知'}",
            f"目标端口：{row.get('local_port')}",
            f"请求路径：{row.get('path') or '/'}",
            f"风险评分：{row.get('risk_score')}",
            f"风险等级：{LEVEL_LABEL.get(risk_level, risk_level)}",
            f"命中规则：{'、'.join(rule_label(r) for r in row.get('matched_rules', [])) or '-'}",
            # 处置放在「处理状态」之前：用户更关心「拦没拦」，再关心「人看过没有」
            f"处置结果：{disposition_label(disp)}"
            + (f"（{DISPOSITION_HINT[disp]}）" if DISPOSITION_HINT.get(disp) else ""),
            f"处理状态：{HANDLED_LABEL.get(row.get('handled', 0), '-')}",
            "",
            "摘要：",
            row.get("summary") or "-",
        ]
        if geo and geo.found:
            lines += [
                "",
                "归属地明细：",
                f"  国家：{geo.country}  省份：{geo.province}",
                f"  城市：{geo.city}  ISP：{geo.isp}  国家码：{geo.iso}",
            ]
        # 同类合并的折叠行：列出组内每一次发生（成员已按时间倒序）
        members = row.get("members") or []
        if len(members) > 1:
            lines += [
                "",
                f"同类事件：共 {len(members)} 次（每次连接的远端端口不同，故各记一条）",
            ]
            lines += [f"  · {ms_to_str(m.get('event_ts'))}  #{m.get('id')}" for m in members[:50]]
            if len(members) > 50:
                lines.append(f"  … 其余 {len(members) - 50} 次见导出的 CSV")
        txt.setPlainText("\n".join(lines))
        lay.addWidget(txt)
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        btns.rejected.connect(self.reject)
        btns.accepted.connect(self.accept)
        lay.addWidget(btns)


class EventsPage(QWidget):
    """风险事件列表（支持勾选批量处理与时间筛选）"""

    ask_ban = Signal(str, int, str)
    # [(ip, score, reason), ...] —— 批量封禁交给主窗口统一确认与执行
    ask_ban_many = Signal(list)
    ask_lookup = Signal(str)
    ask_settings = Signal()
    #: 用户手动刷新过（主窗口据此解除「自动刷新暂停」，见 gui/mixins.py）
    refreshed_manually = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        # _rows 是当前**显示顺序**（点表头后会被重排），行号 == 数据下标；
        # _rows_src 是后端返回的原序，只用于「取消排序」时还原；
        # _src 是「参与排序的源」（合并开关决定它是合并组还是原始行）
        self._rows: List[Dict] = []
        self._rows_src: List[Dict] = []
        self._src: List[Dict] = []
        # 生效中的封禁（IP → BanRecord），刷新时整体换一次；行内按钮据此
        # 显示「已封禁」并置灰，避免用户对着同一条记录反复点
        self._banned: Dict[str, Any] = {}
        #: 自动刷新是否被暂停（事件激增 / 单次渲染过慢时由主窗口置位）
        self.auto_paused = False
        #: 是否已被自动降到更小的条数档位（只影响计数行文案，不改用户选择）
        self.auto_downgraded = False
        #: 自动降档时落到的那一档条数（用于判断提示是否还成立）
        self._downgraded_to = 0
        self.sort = TableSort(SORT_SPECS)
        self._build()
        self.refresh()

    # ── 构建 ──
    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 16, 24, 12)
        root.setSpacing(12)

        head = PageHeader("风险事件", "命中风险规则才会进入本列表")
        self.btn_refresh = QPushButton("刷新")
        self.btn_refresh.setObjectName("btn_outline")
        self.btn_refresh.clicked.connect(self._on_refresh_clicked)
        head.add_action(self.btn_refresh)
        root.addWidget(head)

        # 筛选 + 批量动作合成**一张**工具卡：两行都是「对整张表做点什么」，
        # 但性质不同（筛选是看哪些、批量是改哪些），中间用一条极淡的横线隔开。
        # 原来两行都直接铺在灰底上，与下面的表格卡片并列时像三段互不相干的东西。
        root.addWidget(self._build_toolbar_card())

        self.empty = EmptyState("暂无风险事件", "当前规则未命中任何访问，这是正常状态")
        self.empty.setVisible(False)
        root.addWidget(self.empty)

        root.addWidget(self._build_table(), 1)

    def _build_toolbar_card(self) -> QFrame:
        """筛选行 + 批量行装进一张卡片，两行之间一条 1px 分隔线"""
        card = QFrame()
        card.setObjectName("panel")
        lay = QVBoxLayout(card)
        lay.setContentsMargins(14, 10, 14, 10)
        lay.setSpacing(8)
        lay.addLayout(self._build_filters())

        div = QFrame()
        div.setObjectName("panel_divider")
        div.setFixedHeight(1)
        lay.addWidget(div)

        lay.addWidget(self._build_batch_bar())
        return card

    def _build_filters(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(8)

        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索 IP / 摘要…")
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(260)
        self.search.textChanged.connect(self._on_filter_changed)

        self.level = QComboBox()
        self.level.addItems(["全部等级", "严重", "高", "中", "低"])
        self.level.setFixedWidth(118)
        self.level.currentIndexChanged.connect(self._on_filter_changed)

        self.handled = QComboBox()
        self.handled.addItems(["全部状态", "未处理", "已确认", "已忽略"])
        self.handled.setFixedWidth(122)
        self.handled.currentIndexChanged.connect(self._on_filter_changed)

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
        self.limit.addItems(["最近 200 条", "最近 500 条", "最近 2000 条"])
        self.limit.setFixedWidth(140)
        self.limit.currentIndexChanged.connect(self._on_filter_changed)

        self.merge = QCheckBox("同类合并")
        self.merge.setChecked(True)
        self.merge.setToolTip(
            "同一「IP + 端口 + 路径 + 等级 + 评分 + 命中规则 + 处理状态」的多条事件"
            "折叠成一行，时间列标 ×N。\n"
            "对方每次新建连接都会各记一条（远端端口不同），不是重复显示；\n"
            "批量确认 / 忽略 / 删除会作用于组内全部事件，导出仍逐条展开。"
        )
        self.merge.stateChanged.connect(self.refresh)

        self.lbl_info = QLabel("")
        self.lbl_info.setStyleSheet(f"color:{C.text_muted};font-size:12.5px;")
        # 刷新中的提示 + 「更新于」时间戳都落在这行小字上（见 widgets.RefreshGuard）
        self._refresh = RefreshGuard(self.lbl_info)

        for combo in (self.search, self.level, self.handled, self.range):
            bar.addWidget(combo)
        bar.addWidget(self.dt_from)
        bar.addWidget(self.lbl_to)
        bar.addWidget(self.dt_to)
        bar.addWidget(self.limit)
        bar.addWidget(self.merge)
        bar.addStretch(1)
        return bar

    def _build_batch_bar(self) -> QWidget:
        wrap = QWidget()
        lay = QHBoxLayout(wrap)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        self.lbl_sel = QLabel("已选 0 条")
        self.lbl_sel.setStyleSheet(f"color:{C.text_secondary};font-size:13.5px;")
        self.lbl_sel.setFixedWidth(92)

        self.btn_sel_all = self._batch_button("全选本页", "")
        # 勾选列在表格建好后才有，这里延迟到点击时再取
        self.btn_sel_all.clicked.connect(lambda: self.sel.toggle_all())  # noqa: PLW0108

        self.btn_ban = self._batch_button("一键封禁", "danger")
        self.btn_ban.clicked.connect(self._batch_ban)

        self.btn_ok = self._batch_button("确认处理", "")
        self.btn_ok.clicked.connect(lambda: self._batch_handled(1))

        self.btn_ignore = self._batch_button("忽略", "")
        self.btn_ignore.clicked.connect(lambda: self._batch_handled(2))

        # 一屏里只留一个红色的批量动作：删除虽然更危险，但频率极低，
        # 又已经有一道默认「否」的确认框，再和「一键封禁」抢红色只会让红色失效
        self.btn_del = self._batch_button("删除", "")
        self.btn_del.setToolTip("删除选中的事件记录（不影响访问流水，删除后不可恢复）")
        self.btn_del.clicked.connect(self._batch_delete)

        # 导出不依赖勾选：它导的是「当前筛选结果」而不是「选中的行」，
        # 所以不能放进 _batch_buttons（那批按钮是按勾选数启停的）
        self.btn_export = self._batch_button("导出 CSV", "")
        self.btn_export.setToolTip("导出当前筛选结果，不受勾选影响")
        self.btn_export.clicked.connect(self._export_csv)

        lay.addWidget(self.lbl_sel)
        lay.addWidget(self.btn_sel_all)
        lay.addSpacing(6)
        lay.addWidget(self.btn_ban)
        lay.addWidget(self.btn_ok)
        lay.addWidget(self.btn_ignore)
        lay.addWidget(self.btn_del)
        lay.addWidget(self.btn_export)
        lay.addStretch(1)
        # 计数与「更新于」放批量行右端：这行左侧只有按钮，右半本来就空着；
        # 放筛选行会被 5 个控件挤出去（实测超出卡片右边缘被裁掉）
        lay.addWidget(self.lbl_info)

        self._batch_buttons = [self.btn_ban, self.btn_ok, self.btn_ignore, self.btn_del]
        for b in self._batch_buttons:
            b.setEnabled(False)
        return wrap

    @staticmethod
    def _batch_button(text: str, kind: str) -> QPushButton:
        b = QPushButton(text)
        b.setFixedHeight(30)
        b.setStyleSheet(small_button_style(kind or "outline"))
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        return b

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
        # 结果列宽度每次翻页都变，读数时眼睛要重新找位置
        self.table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        self.table.verticalHeader().setDefaultSectionSize(34)
        self.table.doubleClicked.connect(self._on_double_click)
        self.table.setItemDelegateForColumn(COL_LEVEL, RiskBadgeDelegate(self.table))
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._ctx_menu)

        # 勾选列 + 表头全选（三张表共用一份实现，见 gui/table_select.py）
        self.sel = CheckColumn(self.table, COL_CHECK)
        self.sel.bind(self._on_sel_changed)
        # 勾选框自绘（与工具条上的 QSS 勾选框同一套视觉，见 CheckMarkDelegate）
        self._check_delegate = CheckMarkDelegate(self.table)
        self.table.setItemDelegateForColumn(COL_CHECK, self._check_delegate)

        # 操作列自绘：2000 行档位下 setCellWidget 每行两个控件，实测单次重建 3.4 秒，
        # 而事件泵节拍是 150ms（见 gui/row_action.py 开头的实测数据）
        self._action_delegate = RowActionDelegate(
            self.table,
            COL_ACTION,
            self._action_spec,
            self._on_row_ban,
            self._on_row_menu,
        )
        self.table.setItemDelegateForColumn(COL_ACTION, self._action_delegate)

        hh = self.table.horizontalHeader()
        for i, w in enumerate(COL_WIDTHS):
            hh.resizeSection(i, w)
        hh.setSectionResizeMode(COL_PATH, QHeaderView.ResizeMode.Stretch)

        # 点表头排序（数据层重排 + 重渲染，见 gui/table_sort.py）
        self.sort_header = SortHeader(self.table, self.sort, self._apply_sort)
        return self.table

    # ── 时间筛选 ──
    def _on_range_changed(self, _idx: int) -> None:
        custom = self.range.currentText() == RANGE_CUSTOM
        for w in (self.dt_from, self.lbl_to, self.dt_to):
            w.setVisible(custom)
        self.refresh()

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

    # ── 数据 ──
    def _level_filter(self) -> str:
        m = {"严重": "critical", "高": "high", "中": "medium", "低": "low"}
        return m.get(self.level.currentText(), "")

    def _handled_filter(self):
        m = {"未处理": 0, "已确认": 1, "已忽略": 2}
        return m.get(self.handled.currentText())

    def _limit_value(self) -> int:
        try:
            return int(self.limit.currentText().replace("最近 ", "").replace(" 条", ""))
        except Exception:
            return 200

    def _filters_active(self) -> bool:
        return bool(
            self.search.text().strip()
            or self.level.currentIndex() > 0
            or self.handled.currentIndex() > 0
            or self.range.currentText() != RANGE_ALL
        )

    def _on_filter_changed(self, *_args: Any) -> None:
        """筛选控件（搜索框 / 下拉 / 日期 / 条数）改动后的刷新入口。

        为什么不让它们直接连 `refresh`：这些信号都带参数（`textChanged(str)`、
        `currentIndexChanged(int)`、`dateChanged(QDate)`），Qt 会把参数当位置参数
        传给 `refresh(auto)` —— 于是「用户改了筛选」被当成「事件泵自动刷新」：
        暂停期间改条件会被静默忽略，改条数也不解除暂停。必须走这个零参数槽。
        """
        self.refresh()

    def refresh(self, auto: bool = False) -> None:
        """重新加载列表。

        `auto=True` 表示由事件泵自动触发（见 `gui/mixins._flush_events_refresh`）。
        自动刷新在暂停期间直接返回，把「什么时候看」的决定权留给用户；手动刷新
        （按钮 / 改筛选 / 批量操作后）永远有效，并顺手解除暂停。
        """
        if auto:
            if self.auto_paused:
                return
        elif self.auto_paused:
            self.set_auto_paused(False)
            self.refreshed_manually.emit()
        # 重入会叠两次查询 + 两次重排；守卫同时也负责「正在刷新…」这行提示
        if self._refresh.busy:
            return
        with self._refresh:
            self._load()

    def downgrade_rows(self) -> bool:
        """攻击期把显示条数降一档（2000 → 500 → 200），降了返回 True。

        为什么不直接暂停自动刷新：事件激增正是最需要盯着列表的时刻，停刷等于把
        最该看的东西藏起来。实测（离屏，1 秒灌 200 条）2000 行档位单次刷新要
        1.37 秒 —— 界面每秒只有不到一半时间是活的；而 200 行档位只要约 80ms，
        降档后仍然可以每秒刷一次，界面对点击的响应（心跳 P95 18ms）不受影响。

        ⚠️ 已经是最小档位时返回 False，由调用方退化成「暂停自动刷新」。
        """
        idx = self.limit.currentIndex()
        lower = [i for i in (1, 0) if i < idx]
        if not lower:
            return False
        self.limit.blockSignals(True)  # 别触发 _on_filter_changed（那会把标记清掉）
        self.limit.setCurrentIndex(lower[0])
        self.limit.blockSignals(False)
        self.auto_downgraded = True
        self._downgraded_to = self._limit_value()
        return True

    def _info_text(self, total: int, merged_groups: int) -> str:
        """计数行文案。降档状态要写在这里 —— 否则「列表怎么只剩 200 条」= bug

        判据里带 `_downgraded_to` 是为了自愈：用户自己把条数改回更大档位后，
        「已临时降到 N 条」这句话自动消失，不需要额外的清理状态。
        """
        info = f"共 {total} 条事件"
        if merged_groups:
            info += f"（同类合并为 {merged_groups} 组）"
        if self.auto_downgraded and self._limit_value() == self._downgraded_to:
            info += f" · 事件激增，已临时降到最近 {self._downgraded_to} 条"
        return info

    def set_auto_paused(self, paused: bool) -> None:
        """暂停 / 恢复自动刷新，并在计数行明说原因（否则「列表不动了」= bug）

        文案刻意写在计数行：它是这张表上唯一常驻的一行小字，用户看条数时
        必然会扫到。暂停不是错误状态，所以用次要色，不用红色。
        """
        paused = bool(paused)
        if paused == self.auto_paused:
            return
        self.auto_paused = paused
        if paused:
            self.lbl_info.setText("事件激增，已暂停自动刷新 · 点右上「刷新」看最新")
            self.lbl_info.setToolTip(
                "单次刷新耗时超过 0.8 秒时会自动停刷，避免界面一直在重建。\n"
                "手动「刷新」不受影响；改筛选条件也会立即重新加载。"
            )
            self.lbl_info.setStyleSheet(f"color:{C.warning};font-size:12.5px;")
        else:
            self.lbl_info.setStyleSheet(f"color:{C.text_muted};font-size:12.5px;")
            self.lbl_info.setToolTip("")

    def _on_refresh_clicked(self) -> None:
        """「刷新」按钮：不带参数，避免 clicked(bool) 的 checked 落到 auto 上"""
        self.refresh()

    def _load(self) -> None:
        since, until = self._range_ms()
        # 事件列表与「行内按钮的封禁态」共用一条连接：省一次建连（15~20ms/次），
        # 也让两者是同一时刻的快照（否则按钮说已封禁、列表里还看不到那条封禁）
        rows, banned = risk_events_page(
            limit=self._limit_value(),
            level=self._level_filter(),
            handled=self._handled_filter(),
            keyword=self.search.text().strip(),
            since_ts=since,
            until_ts=until,
        )
        # 排序状态跨刷新保留：用户在「按评分降序」下改筛选条件，期望的还是降序
        self._rows_src = rows
        # 行内按钮要知道「这个 IP 是不是已经封了」：一次查询给整张表用。
        # 逐行查在 200 行的表上就是 200 次建连，渲染直接掉到秒级。
        self._banned = banned
        # 同类合并：同一「IP+端口+路径+等级+评分+规则+状态」折叠成一行（×N）。
        # 合并的是展示层，_rows_src 始终是后端原序原条数，导出/审计走 flatten 还原。
        merged = self.merge.isChecked()
        src = merge_rows(rows) if merged else rows
        self._src = src
        self._rows = self.sort.apply(src)
        self._render(self._rows)
        # 只有真的折叠掉了行才提「合并为 N 组」，否则是废话
        groups = len(src) if (merged and len(src) < len(rows)) else 0
        self.lbl_info.setText(self._info_text(len(rows), groups))
        self.btn_export.setToolTip(f"导出当前筛选结果（{len(rows)} 条事件）")

    def _render(self, rows: List[Dict]) -> None:
        if rows:
            self.empty.setVisible(False)
        else:
            self.empty.set_state(
                "没有符合条件的事件" if self._filters_active() else "暂无风险事件",
                "试试放宽时间范围、清空搜索或切换状态筛选"
                if self._filters_active()
                else "当前规则未命中任何访问，这是正常状态",
            )
            self.empty.setVisible(True)
        self.table.setVisible(bool(rows))

        self.sel.begin_render()
        self._action_delegate.reset_hover()
        # 渲染期间关重绘：逐格 setItem 每次都会调度一遍重绘，2000 行 × 10 列
        # 就是两万次调度，而中间态一秒都看不到。
        self.table.setUpdatesEnabled(False)
        try:
            self.table.setRowCount(0)
            self.table.setRowCount(len(rows))
            for i, r in enumerate(rows):
                geo = r.get("geo")
                level = r.get("risk_level", "normal")
                handled = r.get("handled", 0)

                ts = r.get("event_ts")
                time_str = (
                    datetime.datetime.fromtimestamp(ts / 1000).strftime("%m-%d %H:%M:%S")
                    if ts
                    else "-"
                )
                matched = "、".join(rule_label(x) for x in r.get("matched_rules", [])) or "-"

                n = int(r.get("group_count") or 1)
                if n > 1:
                    # 折叠行：时间列标 ×N，tooltip 列出组内每一次发生的时间
                    time_text = f"{time_str} ×{n}"
                    times = r.get("members") or []
                    tip_lines = [f"共 {n} 次同类事件（每次连接的远端端口不同，故各记一条）："]
                    tip_lines += ["· " + ms_to_str(m.get("event_ts")) for m in times[:20]]
                    if n > 20:
                        tip_lines.append(f"… 其余 {n - 20} 次见导出的 CSV")
                    time_tip = "\n".join(tip_lines)
                else:
                    time_text = time_str
                    time_tip = ms_to_str(r.get("event_ts"))

                self.sel.fill(i)
                self.table.setItem(i, COL_TIME, make_item(time_text, mono=True, tip=time_tip))
                self.table.setItem(i, COL_LEVEL, badge_item(level))
                ip_text = str(r.get("ip") or "")
                self.table.setItem(i, COL_IP, make_item(ip_text, C.text_link, tip=ip_text))
                geo_text = geo.display if geo else "未知"
                self.table.setItem(
                    i,
                    COL_GEO,
                    make_item(geo.region_short if geo else "未知", tip=geo_text),
                )
                self.table.setItem(
                    i,
                    COL_PORT,
                    make_item(
                        r.get("local_port") or "-",
                        align=Qt.AlignmentFlag.AlignCenter,
                        mono=True,
                    ),
                )
                path_text = str(r.get("path") or "/")
                self.table.setItem(i, COL_PATH, make_item(path_text, tip=path_text))
                self.table.setItem(
                    i,
                    COL_SCORE,
                    make_item(
                        r.get("risk_score", 0),
                        align=Qt.AlignmentFlag.AlignCenter,
                        bold=True,
                        mono=True,
                    ),
                )
                self.table.setItem(i, COL_RULE, make_item(matched, tip=matched))
                disp_text, disp_color, disp_tip = _disposition_cell(r, handled)
                self.table.setItem(
                    i,
                    COL_DISPOSITION,
                    make_item(disp_text, disp_color, Qt.AlignmentFlag.AlignCenter, tip=disp_tip),
                )
                # 操作列由 RowActionDelegate 自绘，这里不再建控件
        finally:
            self.sel.end_render()
            self.table.setUpdatesEnabled(True)

    # ── 勾选 ──
    def _on_sel_changed(self, n: int) -> None:
        self.lbl_sel.setText(f"已选 {n} 条")
        self.lbl_sel.setStyleSheet(
            f"color:{C.primary if n else C.text_secondary};font-size:13.5px;"
            f"font-weight:{'600' if n else '400'};"
        )
        for b in self._batch_buttons:
            b.setEnabled(n > 0)
        self.btn_sel_all.setText("取消全选" if n and n == len(self._rows) else "全选本页")

    def _checked_rows(self) -> List[Dict]:
        return [self._rows[i] for i in self.sel.checked_rows() if i < len(self._rows)]

    def _apply_sort(self, _state: Optional[SortSpec]) -> None:
        """按新排序重渲染：行号与数据下标始终一致，勾选按业务 key（事件 id）回放。

        key 必须是 id 而不是行号 —— 排序后行号已经换人，按行号回放会把勾选
        落到别的记录上，紧接着的「一键封禁」就封错了。
        """
        keys = {r.get("id") for r in self._checked_rows()}
        self._rows = self.sort.apply(self._src)
        self._render(self._rows)
        self.sel.set_checked_rows(i for i, r in enumerate(self._rows) if r.get("id") in keys)

    # ── 批量动作 ──
    def _batch_handled(self, handled: int) -> None:
        # 折叠行代表一组：必须摊开成原始事件再操作，否则「勾一行确认」
        # 只有代表那条被确认，其余 N-1 条还挂在未处理里。
        # 用模块级 flatten_rows 而不是 self 的方法 —— 测试用替身宿主
        # 只实现被点名的成员函数，多一个 self 依赖就多一个假红。
        rows = flatten_rows(self._checked_rows())
        if not rows:
            return
        ids = [int(r["id"]) for r in rows]
        action = _handled_action(handled)
        verb = HANDLED_LABEL.get(handled, "处理")
        try:
            n = set_risk_handled_batch(ids, handled)
        except Exception as e:
            audit.record(
                action,
                target_type="event",
                summary=f"批量{verb} {len(ids)} 条事件失败：{e}",
                result=audit.RESULT_FAIL,
                detail=str(e),
            )
            QMessageBox.warning(self, "操作失败", str(e))
            return
        # before 记「每条原来的状态」：确认/忽略是可来回切的，只记条数无法事后
        # 判断某条事件是被确认过、还是被忽略过又改回来。
        audit.record(
            action,
            target_type="event",
            summary=f"批量{verb} {n} 条风险事件",
            before={"events": _event_snapshot(rows)},
            after={"handled": handled, "count": n},
        )
        self.refresh()
        self.lbl_info.setText(
            f"已{HANDLED_LABEL.get(handled, '处理')} {n} 条 · 当前列表共 {len(self._rows)} 条"
        )

    def _batch_delete(self) -> None:
        rows = flatten_rows(self._checked_rows())
        if not rows:
            return
        ids = [int(r["id"]) for r in rows]
        if (
            QMessageBox.question(
                self,
                "删除风险事件",
                f"确认删除选中的 {len(ids)} 条事件记录？\n\n"
                "· 只删事件，不影响访问流水与统计；\n"
                "· 删除后无法恢复（审计要求留档的请改用「忽略」）。",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        # 删除是不可逆的（弹窗里也写了「审计要求留档的请改用忽略」），
        # 所以 before 必须把被删记录的关键字段整条存下来 —— 只记条数的话，
        # 事后既答不出「删了哪些 IP」，也答不出「删的时候它们是什么状态」。
        snapshot = _event_snapshot(rows)
        try:
            n = delete_risk_events(ids)
        except Exception as e:
            audit.record(
                audit.ACTION_EVENT_DELETE,
                target_type="event",
                summary=f"删除 {len(ids)} 条风险事件失败：{e}",
                result=audit.RESULT_FAIL,
                detail=str(e),
            )
            QMessageBox.warning(self, "删除失败", str(e))
            return
        audit.record(
            audit.ACTION_EVENT_DELETE,
            target_type="event",
            summary=f"删除 {n} 条风险事件",
            before={"events": snapshot},
            after={"count": n},
        )
        self.refresh()
        self.lbl_info.setText(f"已删除 {n} 条 · 当前列表共 {len(self._rows)} 条")

    def _batch_ban(self) -> None:
        rows = flatten_rows(self._checked_rows())
        if not rows:
            return
        # 同一 IP 在选定区间里常有多条事件（爆破就是几十条），按 IP 去重、
        # 取最高分那条作为封禁理由，避免把 20 条记录变成 20 次防火墙操作
        uniq: Dict[str, Dict] = {}
        for r in rows:
            ip = r.get("ip") or ""
            if not ip:
                continue
            old = uniq.get(ip)
            if old is None or int(r.get("risk_score") or 0) > int(old.get("risk_score") or 0):
                uniq[ip] = r
        # 不再传事件 id：封禁成功时由 `ban_service.execute` 按 IP 把**所有**
        # 未处理事件标成「已确认」。只回填勾选的那几条，会让筛选范围之外、
        # 同一 IP 的其它待处理记录继续挂在「未处理」里 —— 用户看到的还是
        # 「封了但状态没变」。
        items = [
            {
                "ip": ip,
                "score": int(r.get("risk_score") or 0),
                "reason": r.get("summary") or "命中风险规则",
            }
            for ip, r in uniq.items()
        ]
        if items:
            self.ask_ban_many.emit(items)

    def _export_csv(self) -> None:
        """导出**当前筛选结果**，不是全库。

        页面一次最多只取 `self.limit` 条（默认 200），所以这里必须把「导了
        多少条」说清楚 —— 否则用户会以为手里的 CSV 是全量，据此下的结论是错的。
        触到上限时额外提示一句，让人知道该把上限调大再来一次。
        """
        # 合并开启时 _rows 是折叠组，导出必须摊平 —— CSV 要逐条事实
        rows = flatten_rows(self._rows)
        cap = self._limit_value()
        scope = f"导出范围：当前筛选结果，共 {len(rows)} 条事件。"
        if len(self._rows) < len(rows):
            scope += f"\n（列表中同类合并显示为 {len(self._rows)} 组，CSV 按逐条展开。）"
        if len(rows) >= cap:
            scope += f"\n当前列表已达「最近 {cap} 条」上限，可能还有更早的事件未导出。"
        export_table_csv(
            self,
            rows,
            EVENT_CSV_HEADERS,
            iter_event_rows,
            default_name="risk_events.csv",
            dialog_title="导出风险事件",
            scope_hint=scope,
        )

    # ── 行内操作 ──
    def _action_spec(self, row: int) -> Optional[RowAction]:
        """操作列的按钮状态（自绘 delegate 的回调，返回 None 表示不画）

        「已封禁」必须置灰：不这么做的话，用户对着同一行再点一次只会弹一句
        「已处于封禁状态」，看上去跟「上次没生效」一模一样。
        """
        if not 0 <= row < len(self._rows):
            return None
        r = self._rows[row]
        ban = self._banned.get(str(r.get("ip") or ""))
        if ban is not None:
            # 置灰态下 tooltip 是唯一能看到「为什么点不动、什么时候到期」的地方
            return RowAction("已封禁", "danger", False, _ban_tip(ban))
        return RowAction("封禁", "danger", True, "封禁该 IP（弹窗里确认时长）")

    def _on_row_ban(self, row: int) -> None:
        if not 0 <= row < len(self._rows):
            return
        r = self._rows[row]
        self.ask_ban.emit(
            str(r.get("ip") or ""),
            int(r.get("risk_score") or 0),
            r.get("summary") or "命中风险规则",
        )

    def _on_row_menu(self, row: int, global_pos) -> None:
        if not 0 <= row < len(self._rows):
            return
        self._row_menu(self._rows[row], parent=self).exec(global_pos)

    def _menu_entries(self, r: Dict) -> List[Optional[MenuEntry]]:
        """行内「⋯」与右键菜单共用同一份动作定义（P1-10 三表一致）

        处理状态直接体现在菜单文案上：「确认处理」在已确认的行里变成不可点的
        「已确认」，用户不需要点进去才知道当前状态。
        """
        ip = r.get("ip", "")
        handled = int(r.get("handled") or 0)
        return [
            *_handled_entries(handled, lambda v: self._set_handled(r, v)),
            None,
            ("查询该 IP 归属地", lambda: self.ask_lookup.emit(ip)),
            ("复制 IP", lambda: self._copy(ip)),
            None,
            ("查看详情", lambda: EventDetailDialog(r, self).exec()),
        ]

    def _row_menu(self, r: Dict, parent=None) -> QMenu:
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

    def _set_handled(self, r: Dict, handled: int) -> None:
        action = _handled_action(handled)
        verb = HANDLED_LABEL.get(handled, "处理")
        # 折叠行的行内「确认/忽略」作用于整组：用户看到的是一行 ×N，
        # 只改代表那条的话，刷新回来还有 N-1 条挂在未处理，等于操作没生效
        members = flatten_rows([r])
        before = _event_snapshot(members)
        ids = [int(m["id"]) for m in members]
        try:
            n = set_risk_handled_batch(ids, handled)
        except Exception as e:
            audit.record(
                action,
                target_type="event",
                target_id=r.get("id"),
                summary=f"{verb} {r.get('ip', '')} 的事件失败：{e}",
                result=audit.RESULT_FAIL,
                detail=str(e),
            )
            QMessageBox.warning(self, "操作失败", str(e))
            self.refresh()
            return
        audit.record(
            action,
            target_type="event",
            target_id=r.get("id"),
            summary=f"{verb}事件：{r.get('ip', '')}" + (f"（同类 {n} 条）" if n > 1 else ""),
            before={"events": before},
            after={"handled": handled, "count": n},
        )
        self.refresh()

    def _on_double_click(self, index) -> None:
        # 双击勾选框只是「想连点两下确认勾上」，不该弹详情
        if index.column() == COL_CHECK:
            return
        if 0 <= index.row() < len(self._rows):
            EventDetailDialog(self._rows[index.row()], self).exec()
