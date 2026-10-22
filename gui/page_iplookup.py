"""PortGuard — IP 归属地查询工具"""

from typing import Any, Iterator, List, Optional

from core.geo_locator import get_locator
from core.logger import get_logger
from core.models import ms_to_str
from gui.components import PageHeader, export_table_csv
from gui.table_sort import KIND_NUM, KIND_TEXT, ColumnSpec, SortSpec, TableSort
from gui.theme import C
from gui.widgets import EmptyState, SortHeader
from qtcompat import (
    QAbstractItemView,
    QColor,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    Qt,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
    Signal,
)

log = get_logger(__name__)

HEADERS = ["IP", "是否命中", "国家", "省份", "城市", "ISP", "国家码", "是否中国"]

# 列排序规则（数据层，见 gui/table_sort.py）。本表没有勾选列，8 列全部可排。
# 「是否命中」按 0/1 排（命中在前），按「是 / 否」的文本比是笔画序、没有意义；
# ISP 把库里的占位 "0" 归成空值，与表格里显示的 "-" 一致 —— 未命中的行
# 在各列上都会落到最后，而不是霸占第一屏。
SORT_SPECS = {
    0: ColumnSpec(KIND_TEXT, lambda g: g.ip),
    1: ColumnSpec(KIND_NUM, lambda g: 0 if g.found else 1),
    2: ColumnSpec(KIND_TEXT, lambda g: g.country),
    3: ColumnSpec(KIND_TEXT, lambda g: g.province),
    4: ColumnSpec(KIND_TEXT, lambda g: g.city),
    5: ColumnSpec(KIND_TEXT, lambda g: g.isp if g.isp != "0" else ""),
    6: ColumnSpec(KIND_TEXT, lambda g: g.iso),
    7: ColumnSpec(KIND_TEXT, lambda g: "中国" if g.is_china else "境外"),
}


def iter_geo_rows(results: List[Any]) -> Iterator[List[Any]]:
    """GeoInfo 列表 -> CSV 行。

    取的是 `self._results` 里的**完整值**，不是表格单元格里的显示值：
    表格里 ISP 为 "0" 会显示成 "-"，导出保留库里原样，方便二次加工。
    """
    for g in results:
        yield [
            g.ip,
            "是" if g.found else "否",
            g.country,
            g.province,
            g.city,
            g.isp,
            g.iso,
            "中国" if g.is_china else "境外",
        ]


class IpLookupPage(QWidget):
    xdb_sync_requested = Signal(bool)  # 请求主窗口同步离线库

    def __init__(self, parent=None):
        super().__init__(parent)
        # _results 是当前**显示顺序**（点表头后会被重排）；
        # _results_src 是查询返回的原序，只用于「取消排序」时还原
        self._results: List = []
        self._results_src: List = []
        self.sort = TableSort(SORT_SPECS)
        self._build()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 16, 24, 12)
        root.setSpacing(12)

        head = PageHeader("IP 查询工具", "离线 ip2region 库（IPv4 + IPv6），10 微秒级查询")
        b_sync = QPushButton("同步离线库")
        b_sync.setObjectName("btn_outline")
        b_sync.clicked.connect(lambda: self.xdb_sync_requested.emit(False))
        head.add_action(b_sync)
        root.addWidget(head)

        # 库信息单独一行：原先塞在 PageHeader 的 action 区里，和标题、按钮抢同一条
        # 横向空间，1360 下就被压成「… · 缓存 0/20000 · 命中 0 次…」的半截话。
        self.lbl_lib = QLabel("")
        self.lbl_lib.setStyleSheet(f"color:{C.text_muted};font-size:12.5px;")
        self.lbl_lib.setToolTip("离线库版本与缓存命中情况")
        root.addWidget(self.lbl_lib)

        # 单条查询
        grp1 = QGroupBox("单条查询")
        l1 = QVBoxLayout(grp1)
        l1.setContentsMargins(16, 8, 16, 16)
        l1.setSpacing(10)
        row1 = QHBoxLayout()
        row1.setSpacing(8)
        self.single = QLineEdit()
        self.single.setPlaceholderText("输入 IP，例如 113.118.113.77 或 2400:3200::1，回车查询")
        self.single.returnPressed.connect(self._query_single)
        b1 = QPushButton("查询")
        b1.setObjectName("btn_primary")
        b1.clicked.connect(self._query_single)
        row1.addWidget(self.single, 1)
        row1.addWidget(b1)
        l1.addLayout(row1)
        l1.addWidget(self._build_single_fields())
        root.addWidget(grp1)

        # 批量查询
        grp2 = QGroupBox("批量查询")
        l2 = QVBoxLayout(grp2)
        l2.setContentsMargins(12, 8, 12, 12)
        l2.setSpacing(8)

        split = QSplitter(Qt.Orientation.Horizontal)
        left_w = QWidget()
        ll = QVBoxLayout(left_w)
        ll.setContentsMargins(0, 0, 0, 0)
        ll.setSpacing(6)
        ll.addWidget(QLabel("每行一个 IP（支持 IPv4 / IPv6）"))
        self.batch_input = QPlainTextEdit()
        self.batch_input.setPlaceholderText("113.118.113.77\n8.8.8.8\n2400:3200::1")
        ll.addWidget(self.batch_input, 1)
        bl = QHBoxLayout()
        b2 = QPushButton("开始查询")
        b2.setObjectName("btn_primary")
        b2.clicked.connect(self._query_batch)
        b_clear = QPushButton("清空")
        b_clear.setObjectName("btn_outline")
        b_clear.clicked.connect(self._clear)
        b_export = QPushButton("导出 CSV")
        b_export.setObjectName("btn_outline")
        b_export.clicked.connect(self._export)
        bl.addWidget(b2)
        bl.addWidget(b_clear)
        bl.addWidget(b_export)
        bl.addStretch(1)
        ll.addLayout(bl)

        right_w = QWidget()
        rl = QVBoxLayout(right_w)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(6)
        rl.addWidget(QLabel("查询结果"))
        self.table = QTableWidget(0, len(HEADERS))
        self.table.setHorizontalHeaderLabels(HEADERS)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(32)
        h = self.table.horizontalHeader()
        # 右栏只分到约 590px（split 2:5），15px 字号下按内容重排过：
        # 四个汉字的表头（是否命中 / 是否中国）至少要 72px，否则表头会竖排折断。
        for i, w in enumerate([92, 72, 78, 72, 64, 58, 56, 72]):
            h.resizeSection(i, w)
        h.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        # 点表头排序（数据层重排 + 重渲染，见 gui/table_sort.py）
        self.sort_header = SortHeader(self.table, self.sort, self._apply_sort)
        rl.addWidget(self.table, 1)

        self.empty = EmptyState("尚未查询", "输入 IP 后点查询，结果会显示在这里")
        self.empty.setVisible(self.table.rowCount() == 0)
        rl.addWidget(self.empty, 1)

        split.addWidget(left_w)
        split.addWidget(right_w)
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 5)
        split.setSizes([300, 800])
        l2.addWidget(split)
        root.addWidget(grp2, 1)

        self._update_lib_info()
        # 初始就是「没查过」，表格要收起：否则表头 + 空态同时出现，
        # 页面下半截白白留着一块只有表头的空表格
        self._toggle_empty()

    #: 单条查询结果的字段：(key, 标签)。四格等宽，不区分长值短值
    SINGLE_FIELDS = (
        ("region", "归属地"),
        ("iso", "国家码"),
        ("isp", "ISP"),
        ("scope", "范围"),
    )

    def _build_single_fields(self) -> QWidget:
        """单条查询结果：固定四格「标签 → 值」。

        旧版把结果拼成一句「归属地：…　·　国家码 …　·　ISP …　·　境内」挤在一行，
        字段边界全靠全角空格，长 IPv6 归属地一超宽就整句换行，读的时候要拿手指
        去对位置。拆成固定四格后位置稳定，值也能单独选中复制。
        """
        box = QWidget()
        grid = QGridLayout(box)
        grid.setContentsMargins(0, 2, 0, 0)
        grid.setHorizontalSpacing(28)
        grid.setVerticalSpacing(2)
        self._single_vals: dict = {}
        for col, (key, label) in enumerate(self.SINGLE_FIELDS):
            lb = QLabel(label)
            lb.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
            val = QLabel("—")
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            val.setStyleSheet(f"color:{C.text_secondary};font-size:13.5px;")
            grid.addWidget(lb, 0, col)
            grid.addWidget(val, 1, col)
            # 归属地占两份宽，其余各一份：四格等宽时「United States·California·
            # Google LLC」这种长名会顶满整格并压到相邻字段；反过来只让归属地
            # 拉伸、其它按 sizeHint 走，短值又会被推到最右，中间空出一条 400px 的缝
            grid.setColumnStretch(col, 2 if key == "region" else 1)
            self._single_vals[key] = val
        # selftest 与本页「跳转查询」都读 single_result，指向主值（归属地）
        self.single_result = self._single_vals["region"]
        return box

    def _set_single(self, key: str, text: str, color: str) -> None:
        val = self._single_vals[key]
        val.setText(text)
        val.setStyleSheet(f"color:{color};font-size:13.5px;")

    def _clear_single(self) -> None:
        for key in self._single_vals:
            self._set_single(key, "—", C.text_secondary)

    def _update_lib_info(self) -> None:
        try:
            loc = get_locator()
            if not loc.available:
                self.lbl_lib.setText(f"定位库不可用：{loc.load_error}")
                return
            ci = loc.cache_info()
            info = loc.library_info()
            v4 = info.get("v4", {})
            v6 = info.get("v6", {})
            man = info.get("manifest", {}) or {}
            files = man.get("files", {}) or {}
            synced = files.get("ip2region_v4.xdb", {}).get("updated_at") or files.get(
                "ip2region_v6.xdb", {}
            ).get("updated_at")
            parts = [
                f"v4 {v4.get('size', 0) / 1048576:.1f}MB",
                f"v6 {v6.get('size', 0) / 1048576:.1f}MB",
                f"换库第 {info.get('generation', 0)} 代",
                f"缓存 {ci['size']}/{ci['capacity']}",
                f"命中 {ci['hit']} 次",
            ]
            if synced:
                parts.append(f"在线同步于 {ms_to_str(synced)}")
            else:
                parts.append("随程序内置")
            self.lbl_lib.setText(" · ".join(parts))
        except Exception as e:
            log.exception("刷新定位库信息失败")
            self.lbl_lib.setText(f"定位库异常：{e}")

    def _query_single(self) -> None:
        ip = self.single.text().strip()
        if not ip:
            return
        try:
            geo = get_locator().lookup(ip)
        except Exception as e:
            self._clear_single()
            self._set_single("region", f"查询失败：{e}", C.danger)
            return
        if geo.found:
            self._set_single("region", geo.display, C.text_primary)
            self._set_single("iso", geo.iso or "—", C.text_secondary)
            self._set_single(
                "isp", geo.isp if geo.isp and geo.isp != "0" else "—", C.text_secondary
            )
            self._set_single(
                "scope",
                "境内" if geo.is_china else "境外",
                C.primary if geo.is_china else C.warning,
            )
        else:
            self._clear_single()
            self._set_single("region", "未命中数据段（内网 / 保留 / 未收录）", C.text_muted)

    def _query_batch(self) -> None:
        lines = [x.strip() for x in self.batch_input.toPlainText().splitlines()]
        ips = [x for x in lines if x]
        if not ips:
            QMessageBox.information(self, "提示", "请先输入至少一个 IP。")
            return
        # 去重保序
        seen = set()
        uniq = []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                uniq.append(ip)

        loc = get_locator()
        results = []
        for ip in uniq:
            try:
                results.append(loc.lookup(ip))
            except Exception:
                from core.models import GeoInfo

                results.append(GeoInfo(ip=ip))

        self._results_src = results
        self._results = self.sort.apply(results)
        self._render(self._results)
        self._update_lib_info()

    def _apply_sort(self, _state: Optional[SortSpec]) -> None:
        """按新排序重渲染结果表。

        本表没有勾选列，能对应用户意图的只有「当前高亮的那一行」，所以按 IP
        （这里的业务 key）把高亮放回原来那条记录 —— 排序后眼睛要能接着看。
        """
        current = self._current_ip()
        self._results = self.sort.apply(self._results_src)
        self._render(self._results)
        for i, g in enumerate(self._results):
            if g.ip == current:
                self.table.selectRow(i)
                break

    def _current_ip(self) -> Optional[str]:
        row = self.table.currentRow()
        if 0 <= row < len(self._results):
            return str(self._results[row].ip)
        return None

    def _toggle_empty(self) -> None:
        """结果区在「没查」和「查了」之间切换时，空态与表格互斥显示"""
        has = self.table.rowCount() > 0
        self.table.setVisible(has)
        self.empty.setVisible(not has)

    def _render(self, results) -> None:
        self.table.setRowCount(0)
        self.table.setRowCount(len(results))
        self._toggle_empty()
        for i, g in enumerate(results):

            def mk(text, color=None, align=None):
                it = QTableWidgetItem(str(text))
                if color:
                    it.setForeground(QColor(color))
                if align:
                    it.setTextAlignment(align)
                return it

            if g.found:
                self.table.setItem(i, 0, mk(g.ip, C.text_link))
                self.table.setItem(i, 1, mk("是", C.success, Qt.AlignmentFlag.AlignCenter))
                self.table.setItem(i, 2, mk(g.country))
                self.table.setItem(i, 3, mk(g.province))
                self.table.setItem(i, 4, mk(g.city))
                self.table.setItem(i, 5, mk(g.isp if g.isp != "0" else "-"))
                self.table.setItem(i, 6, mk(g.iso or "-", align=Qt.AlignmentFlag.AlignCenter))
                self.table.setItem(
                    i,
                    7,
                    mk(
                        "中国" if g.is_china else "境外",
                        C.primary if g.is_china else C.warning,
                        Qt.AlignmentFlag.AlignCenter,
                    ),
                )
            else:
                self.table.setItem(i, 0, mk(g.ip, C.text_link))
                self.table.setItem(i, 1, mk("否", C.text_muted, Qt.AlignmentFlag.AlignCenter))
                for c in range(2, 8):
                    self.table.setItem(i, c, mk("-", C.text_muted))

    def _clear(self) -> None:
        self.batch_input.clear()
        self.table.setRowCount(0)
        self._results = []
        self._results_src = []
        self._toggle_empty()

    def _export(self) -> None:
        """批量查询结果导出。编码 / 列名 / 对话框默认值沿用原实现。"""
        export_table_csv(
            self,
            self._results,
            HEADERS,
            iter_geo_rows,
            default_name="ip_lookup.csv",
            dialog_title="导出查询结果",
            empty_msg="没有可导出的查询结果。",
        )

    def lookup_and_show(self, ip: str) -> None:
        """供其他页面跳转调用"""
        self.single.setText(ip)
        self._query_single()
