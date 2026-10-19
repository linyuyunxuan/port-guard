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
"""

import datetime
from typing import Dict, List, Optional, Tuple

from core.config import LEVEL_LABEL
from core.database import (
    delete_risk_events,
    query_risk_events,
    set_risk_handled,
    set_risk_handled_batch,
)
from core.models import ms_to_str
from core.rules_meta import rule_label
from gui.components import MenuEntry, PageHeader, _menu_slot, row_menu_button
from gui.table_select import CheckColumn
from gui.theme import C, small_button_style
from gui.widgets import (
    EmptyState,
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
    "状态",
    "操作",
]

# 列宽取「实测最宽文字 + 16px padding + 8px 余量」，按 PySide2（交付栈）的字体
# 度量算——它比 PySide6 宽 6~20%，按开发栈定宽会在客户机上截断。
# 有界内容（时间 / 等级 / IP / 归属地 / 端口 / 评分 / 状态）一律给足，不许截断：
# 截了用户就分不清是哪条记录。无界内容（路径 / 命中规则）交给 tooltip 兜底，
# 第 6 列（路径）同时是唯一的拉伸列。
# 时间列用 `MM-DD HH:MM:SS`：事件页是事后复盘，同一分钟可能有十几条爆破记录，
# 秒数是排序的唯一依据，不能省成分钟。
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
COL_STATUS = 9
COL_ACTION = 10

COL_WIDTHS = [32, 110, 56, 130, 108, 52, 109, 46, 141, 68, 88]

#: 内容无界的列：允许省略号，但必须有 tooltip 兜底
ELIDE_OK_COLS = (COL_PATH, COL_RULE)

# 居中对齐的列（表头与数据必须一致，否则一列会被读成两根轴）
CENTER_COLS = (COL_CHECK, COL_LEVEL, COL_PORT, COL_SCORE, COL_STATUS)

HANDLED_LABEL = {0: "未处理", 1: "已确认", 2: "已忽略"}

# 时间筛选：右端一律取「次日零点」的左闭右开区间
RANGE_ALL = "全部时间"
RANGE_TODAY = "今天"
RANGE_7D = "近 7 天"
RANGE_30D = "近 30 天"
RANGE_CUSTOM = "自定义"
RANGE_CHOICES = [RANGE_ALL, RANGE_TODAY, RANGE_7D, RANGE_30D, RANGE_CUSTOM]


def _day_start(d: datetime.date) -> datetime.datetime:
    return datetime.datetime(d.year, d.month, d.day)


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

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: List[Dict] = []
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
        self.btn_refresh.clicked.connect(self.refresh)
        head.add_action(self.btn_refresh)
        root.addWidget(head)

        root.addLayout(self._build_filters())
        root.addWidget(self._build_batch_bar())

        self.empty = EmptyState("暂无风险事件", "当前规则未命中任何访问，这是正常状态")
        self.empty.setVisible(False)
        root.addWidget(self.empty)

        root.addWidget(self._build_table(), 1)

    def _build_filters(self) -> QHBoxLayout:
        bar = QHBoxLayout()
        bar.setSpacing(8)

        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索 IP / 摘要…")
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(220)
        self.search.textChanged.connect(self.refresh)

        self.level = QComboBox()
        self.level.addItems(["全部等级", "严重", "高", "中", "低"])
        self.level.setFixedWidth(96)
        self.level.currentIndexChanged.connect(self.refresh)

        self.handled = QComboBox()
        self.handled.addItems(["全部状态", "未处理", "已确认", "已忽略"])
        self.handled.setFixedWidth(104)
        self.handled.currentIndexChanged.connect(self.refresh)

        self.range = QComboBox()
        self.range.addItems(RANGE_CHOICES)
        self.range.setFixedWidth(104)
        self.range.currentIndexChanged.connect(self._on_range_changed)

        self.dt_from = QDateEdit()
        self.dt_from.setCalendarPopup(True)
        self.dt_from.setDisplayFormat("yyyy-MM-dd")
        self.dt_from.setFixedWidth(112)
        self.dt_from.setDate(QDate.currentDate().addDays(-6))
        self.dt_from.dateChanged.connect(self.refresh)

        self.lbl_to = QLabel("至")
        self.lbl_to.setStyleSheet(f"color:{C.text_muted};font-size:12px;")

        self.dt_to = QDateEdit()
        self.dt_to.setCalendarPopup(True)
        self.dt_to.setDisplayFormat("yyyy-MM-dd")
        self.dt_to.setFixedWidth(112)
        self.dt_to.setDate(QDate.currentDate())
        self.dt_to.dateChanged.connect(self.refresh)

        for widget in (self.dt_from, self.lbl_to, self.dt_to):
            widget.setVisible(False)

        self.limit = QComboBox()
        self.limit.addItems(["最近 200 条", "最近 500 条", "最近 2000 条"])
        self.limit.setFixedWidth(124)
        self.limit.currentIndexChanged.connect(self.refresh)

        self.lbl_info = QLabel("")
        self.lbl_info.setStyleSheet(f"color:{C.text_muted};font-size:11px;")

        for combo in (self.search, self.level, self.handled, self.range):
            bar.addWidget(combo)
        bar.addWidget(self.dt_from)
        bar.addWidget(self.lbl_to)
        bar.addWidget(self.dt_to)
        bar.addWidget(self.limit)
        bar.addStretch(1)
        bar.addWidget(self.lbl_info)
        return bar

    def _build_batch_bar(self) -> QWidget:
        wrap = QWidget()
        lay = QHBoxLayout(wrap)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(8)

        self.lbl_sel = QLabel("已选 0 条")
        self.lbl_sel.setStyleSheet(f"color:{C.text_secondary};font-size:12px;")
        self.lbl_sel.setFixedWidth(84)

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

        lay.addWidget(self.lbl_sel)
        lay.addWidget(self.btn_sel_all)
        lay.addSpacing(6)
        lay.addWidget(self.btn_ban)
        lay.addWidget(self.btn_ok)
        lay.addWidget(self.btn_ignore)
        lay.addWidget(self.btn_del)
        lay.addStretch(1)

        self._batch_buttons = [self.btn_ban, self.btn_ok, self.btn_ignore, self.btn_del]
        for b in self._batch_buttons:
            b.setEnabled(False)
        return wrap

    @staticmethod
    def _batch_button(text: str, kind: str) -> QPushButton:
        b = QPushButton(text)
        b.setFixedHeight(26)
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
        self.table.verticalHeader().setDefaultSectionSize(30)
        self.table.doubleClicked.connect(self._on_double_click)
        self.table.setItemDelegateForColumn(COL_LEVEL, RiskBadgeDelegate(self.table))
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._ctx_menu)

        # 勾选列 + 表头全选（三张表共用一份实现，见 gui/table_select.py）
        self.sel = CheckColumn(self.table, COL_CHECK)
        self.sel.bind(self._on_sel_changed)

        hh = self.table.horizontalHeader()
        for i, w in enumerate(COL_WIDTHS):
            hh.resizeSection(i, w)
        hh.setSectionResizeMode(COL_PATH, QHeaderView.ResizeMode.Stretch)
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

    def refresh(self) -> None:
        since, until = self._range_ms()
        rows = query_risk_events(
            limit=self._limit_value(),
            level=self._level_filter(),
            handled=self._handled_filter(),
            keyword=self.search.text().strip(),
            since_ts=since,
            until_ts=until,
        )
        self._rows = rows
        self._render(rows)
        self.lbl_info.setText(f"共 {len(rows)} 条")

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

                self.sel.fill(i)
                self.table.setItem(
                    i, COL_TIME, make_item(time_str, mono=True, tip=ms_to_str(r.get("event_ts")))
                )
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
                hcolor = {0: C.text_secondary, 1: C.success, 2: C.text_muted}.get(
                    handled, C.text_secondary
                )
                self.table.setItem(
                    i,
                    COL_STATUS,
                    make_item(
                        HANDLED_LABEL.get(handled, "-"), hcolor, Qt.AlignmentFlag.AlignCenter
                    ),
                )
                self.table.setCellWidget(i, COL_ACTION, self._row_actions(r))
        finally:
            self.sel.end_render()

    # ── 勾选 ──
    def _on_sel_changed(self, n: int) -> None:
        self.lbl_sel.setText(f"已选 {n} 条")
        self.lbl_sel.setStyleSheet(
            f"color:{C.primary if n else C.text_secondary};font-size:12px;"
            f"font-weight:{'600' if n else '400'};"
        )
        for b in self._batch_buttons:
            b.setEnabled(n > 0)
        self.btn_sel_all.setText("取消全选" if n and n == len(self._rows) else "全选本页")

    def _checked_rows(self) -> List[Dict]:
        return [self._rows[i] for i in self.sel.checked_rows() if i < len(self._rows)]

    # ── 批量动作 ──
    def _batch_handled(self, handled: int) -> None:
        rows = self._checked_rows()
        if not rows:
            return
        ids = [int(r["id"]) for r in rows]
        try:
            n = set_risk_handled_batch(ids, handled)
        except Exception as e:
            QMessageBox.warning(self, "操作失败", str(e))
            return
        self.refresh()
        self.lbl_info.setText(
            f"已{HANDLED_LABEL.get(handled, '处理')} {n} 条 · 当前列表共 {len(self._rows)} 条"
        )

    def _batch_delete(self) -> None:
        rows = self._checked_rows()
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
        try:
            n = delete_risk_events(ids)
        except Exception as e:
            QMessageBox.warning(self, "删除失败", str(e))
            return
        self.refresh()
        self.lbl_info.setText(f"已删除 {n} 条 · 当前列表共 {len(self._rows)} 条")

    def _batch_ban(self) -> None:
        rows = self._checked_rows()
        if not rows:
            return
        # 同一 IP 在选定区间里常有多条事件（爆破就是几十条），按 IP 去重、
        # 取最高分那条作为封禁理由，避免把 20 条记录变成 20 次防火墙操作
        uniq: Dict[str, Dict] = {}
        ids_by_ip: Dict[str, List[int]] = {}
        for r in rows:
            ip = r.get("ip") or ""
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
                # 封禁成功后主窗口会把这些事件标为「已确认」，
                # 否则用户封完回来看，事件还挂在「未处理」里
                "event_ids": ids_by_ip.get(ip, []),
            }
            for ip, r in uniq.items()
        ]
        if items:
            self.ask_ban_many.emit(items)

    # ── 行内操作 ──
    def _row_actions(self, r: Dict) -> QWidget:
        """一个主操作 + 一个「⋯」菜单：一屏几十行时红色必须稀缺"""
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(2, 2, 2, 2)
        lay.setSpacing(4)

        ip = r.get("ip", "")
        score = r.get("risk_score", 0)
        reason = r.get("summary") or "命中风险规则"

        b_ban = QPushButton("封禁")
        b_ban.setFixedHeight(22)
        b_ban.setStyleSheet(small_button_style("danger"))
        b_ban.setCursor(Qt.CursorShape.PointingHandCursor)
        b_ban.clicked.connect(lambda: self.ask_ban.emit(ip, score, reason))

        more = row_menu_button(self._menu_entries(r))

        lay.addWidget(b_ban)
        lay.addWidget(more)
        lay.addStretch(1)
        return w

    def _menu_entries(self, r: Dict) -> List[Optional[MenuEntry]]:
        """行内「⋯」与右键菜单共用同一份动作定义（P1-10 三表一致）"""
        ip = r.get("ip", "")
        return [
            ("确认处理", lambda: self._set_handled(r, 1)),
            ("忽略", lambda: self._set_handled(r, 2)),
            None,
            ("查询该 IP 归属地", lambda: self.ask_lookup.emit(ip)),
            ("复制 IP", lambda: self._copy(ip)),
            None,
            ("查看详情", lambda: EventDetailDialog(r, self).exec()),
        ]

    def _row_menu(self, r: Dict, parent=None) -> QMenu:
        menu = QMenu(parent)
        for entry in self._menu_entries(r):
            if entry is None:
                menu.addSeparator()
                continue
            text, callback = entry
            menu.addAction(text).triggered.connect(_menu_slot(callback))
        return menu

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
        try:
            set_risk_handled(int(r["id"]), handled)
        except Exception as e:
            QMessageBox.warning(self, "操作失败", str(e))
        self.refresh()

    def _on_double_click(self, index) -> None:
        # 双击勾选框只是「想连点两下确认勾上」，不该弹详情
        if index.column() == COL_CHECK:
            return
        if 0 <= index.row() < len(self._rows):
            EventDetailDialog(self._rows[index.row()], self).exec()
