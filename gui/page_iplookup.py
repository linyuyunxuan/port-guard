"""PortGuard — IP 归属地查询工具"""
import csv
from typing import List

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.geo_locator import get_locator
from core.logger import get_logger
from core.models import ms_to_str
from gui.theme import C

log = get_logger(__name__)

HEADERS = ["IP", "是否命中", "国家", "省份", "城市", "ISP", "国家码", "是否中国"]


class IpLookupPage(QWidget):
    xdb_sync_requested = Signal(bool)   # 请求主窗口同步离线库

    def __init__(self, parent=None):
        super().__init__(parent)
        self._results: List = []
        self._build()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 12)
        root.setSpacing(12)

        head = QHBoxLayout()
        t = QLabel("IP 查询工具")
        t.setObjectName("page_title")
        d = QLabel("离线 ip2region 库（IPv4 + IPv6），10 微秒级查询")
        d.setObjectName("page_desc")
        head.addWidget(t)
        head.addWidget(d)
        head.addStretch(1)

        self.lbl_lib = QLabel("")
        self.lbl_lib.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
        head.addWidget(self.lbl_lib)

        b_sync = QPushButton("同步离线库")
        b_sync.setObjectName("btn_outline")
        b_sync.clicked.connect(lambda: self.xdb_sync_requested.emit(False))
        head.addWidget(b_sync)
        root.addLayout(head)

        # 单条查询
        grp1 = QGroupBox("单条查询")
        l1 = QHBoxLayout(grp1)
        l1.setContentsMargins(12, 8, 12, 12)
        self.single = QLineEdit()
        self.single.setPlaceholderText("输入 IP，例如 113.118.113.77 或 2400:3200::1，回车查询")
        self.single.returnPressed.connect(self._query_single)
        b1 = QPushButton("查询")
        b1.setObjectName("btn_primary")
        b1.clicked.connect(self._query_single)
        self.single_result = QLabel("—")
        self.single_result.setStyleSheet(f"color:{C.text_on_dark};font-size:13px;")
        l1.addWidget(self.single, 3)
        l1.addWidget(b1)
        l1.addWidget(self.single_result, 4)
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
        self.table.verticalHeader().setDefaultSectionSize(28)
        h = self.table.horizontalHeader()
        for i, w in enumerate([140, 62, 104, 100, 92, 118, 60, 66]):
            h.resizeSection(i, w)
        h.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        rl.addWidget(self.table, 1)

        split.addWidget(left_w)
        split.addWidget(right_w)
        split.setStretchFactor(0, 2)
        split.setStretchFactor(1, 5)
        split.setSizes([300, 800])
        l2.addWidget(split)
        root.addWidget(grp2, 1)

        self._update_lib_info()

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
            synced = files.get("ip2region_v4.xdb", {}).get("updated_at") \
                or files.get("ip2region_v6.xdb", {}).get("updated_at")
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
            self.single_result.setText(f"查询失败：{e}")
            return
        if geo.found:
            self.single_result.setText(
                f"{geo.display}　（{geo.country}/{geo.province}/{geo.city}/{geo.isp}/"
                f"{geo.iso or '-'}）")
        else:
            self.single_result.setText("未命中任何数据段（可能是内网 / 保留 / 未收录地址）")

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

        self._results = results
        self._render(results)
        self._update_lib_info()

    def _render(self, results) -> None:
        self.table.setRowCount(0)
        self.table.setRowCount(len(results))
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
                self.table.setItem(i, 7, mk("中国" if g.is_china else "境外",
                                            C.primary if g.is_china else C.warning,
                                            Qt.AlignmentFlag.AlignCenter))
            else:
                self.table.setItem(i, 0, mk(g.ip, C.text_link))
                self.table.setItem(i, 1, mk("否", C.text_muted, Qt.AlignmentFlag.AlignCenter))
                for c in range(2, 8):
                    self.table.setItem(i, c, mk("-", C.text_muted))

    def _clear(self) -> None:
        self.batch_input.clear()
        self.table.setRowCount(0)
        self._results = []

    def _export(self) -> None:
        if not self._results:
            QMessageBox.information(self, "提示", "没有可导出的查询结果。")
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出查询结果", "ip_lookup.csv", "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(HEADERS)
                for g in self._results:
                    w.writerow([g.ip, "是" if g.found else "否", g.country, g.province,
                                g.city, g.isp, g.iso, "中国" if g.is_china else "境外"])
            QMessageBox.information(self, "导出成功", f"已导出到：\n{path}")
        except Exception as e:
            QMessageBox.warning(self, "导出失败", str(e))

    def lookup_and_show(self, ip: str) -> None:
        """供其他页面跳转调用"""
        self.single.setText(ip)
        self._query_single()
