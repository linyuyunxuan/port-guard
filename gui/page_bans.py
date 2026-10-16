"""PortGuard — 封禁管理页"""
import datetime

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app import ban_service
from core import firewall
from core.config import LEVEL_CRITICAL, LEVEL_HIGH, LEVEL_LABEL
from core.database import (
    count_active_bans,
    query_bans,
    query_risk_events,
    set_risk_handled,
)
from core.logger import get_logger
from core.models import STATUS_ACTIVE, STATUS_FAILED, STATUS_PENDING, STATUS_UNBANNED
from core.validators import InvalidIP, normalize_ip
from gui.theme import C, small_button_style
from gui.widgets import WarnBanner

log = get_logger(__name__)

BAN_HEADERS = ["ID", "IP", "防火墙规则名", "来源", "原因", "评分",
               "状态", "时长", "到期时间", "创建时间", "操作"]
SUG_HEADERS = ["时间", "IP", "归属地", "端口", "评分", "等级", "原因", "操作"]


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
        self.duration.setValue(60)
        self.duration.setSuffix(" 分钟（0=永久）")
        self.duration.setSpecialValueText("永久")

        form.addRow("IP 地址", self.ip)
        form.addRow("封禁原因", self.reason)
        form.addRow("封禁时长", self.duration)

        tip = QLabel("提示：内网、回环与保留地址会被自动拒绝封禁。")
        tip.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
        form.addRow(tip)

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                                | QDialogButtonBox.StandardButton.Cancel)
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
            QMessageBox.warning(self, "IP 格式错误",
                                f"{e}\n\n请输入形如 203.0.113.10 或 2408:8000::1 的地址。")
            self.ip.setFocus()
            self.ip.selectAll()
            return
        super().accept()

    def values(self):
        mins = self.duration.value()
        return (self.ip.text().strip(),
                self.reason.text().strip() or "手动封禁",
                0 if mins == 0 else mins * 60)


class BansPage(QWidget):
    """封禁建议 + 封禁列表"""
    ask_ban = Signal(str, int, str)
    request_refresh_stats = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._build()
        self.refresh()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 12)
        root.setSpacing(10)

        head = QHBoxLayout()
        t = QLabel("封禁管理")
        t.setObjectName("page_title")
        d = QLabel("规则引擎给出建议，确认后才写入 Windows 防火墙")
        d.setObjectName("page_desc")
        head.addWidget(t)
        head.addWidget(d)
        head.addStretch(1)
        root.addLayout(head)

        # 权限警示条
        self.banner = WarnBanner("", "以管理员身份重启", C.warning)
        self.banner.action_clicked.connect(self._restart_as_admin)
        self.banner.setVisible(not firewall.is_admin())
        if not firewall.is_admin():
            self.banner.set_text(
                "当前以普通权限运行，无法修改 Windows 防火墙。"
                "监控与规则判定正常，但「确认封禁」不会生效。")
        root.addWidget(self.banner)

        # 待确认建议
        self.grp_sug = QGroupBox("待确认的封禁建议")
        sug_lay = QVBoxLayout(self.grp_sug)
        sug_lay.setContentsMargins(12, 8, 12, 12)
        self.sug_hint = QLabel("暂无待确认建议")
        self.sug_hint.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
        self.sug_table = QTableWidget(0, len(SUG_HEADERS))
        self.sug_table.setHorizontalHeaderLabels(SUG_HEADERS)
        self.sug_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.sug_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.sug_table.setShowGrid(False)
        self.sug_table.verticalHeader().setVisible(False)
        self.sug_table.verticalHeader().setDefaultSectionSize(32)
        self.sug_table.setMaximumHeight(232)
        sh = self.sug_table.horizontalHeader()
        for i, w in enumerate([130, 130, 130, 60, 56, 56, 300, 170]):
            sh.resizeSection(i, w)
        sh.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        sug_lay.addWidget(self.sug_hint)
        sug_lay.addWidget(self.sug_table)
        root.addWidget(self.grp_sug)

        # 工具栏
        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索 IP / 原因…")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self.refresh)

        self.status_filter = QComboBox()
        self.status_filter.addItems(["全部状态", "已封禁", "已解封", "失败", "处理中"])
        self.status_filter.currentIndexChanged.connect(self.refresh)

        btn_manual = QPushButton("＋ 手动封禁")
        btn_manual.setObjectName("btn_primary")
        btn_manual.clicked.connect(lambda: self.ask_ban.emit("", 0, "手动封禁"))

        btn_unban_all = QPushButton("一键全部解封")
        btn_unban_all.setObjectName("btn_outline")
        btn_unban_all.clicked.connect(self._unban_all)

        btn_sync = QPushButton("与防火墙对账")
        btn_sync.setObjectName("btn_outline")
        btn_sync.clicked.connect(self._sync)

        btn_refresh = QPushButton("刷新")
        btn_refresh.setObjectName("btn_outline")
        btn_refresh.clicked.connect(self.refresh)

        self.lbl_info = QLabel("")
        self.lbl_info.setStyleSheet(f"color:{C.text_muted};font-size:12px;")

        bar.addWidget(self.search, 1)
        bar.addWidget(self.status_filter)
        bar.addWidget(btn_manual)
        bar.addWidget(btn_unban_all)
        bar.addWidget(btn_sync)
        bar.addWidget(btn_refresh)
        bar.addWidget(self.lbl_info)
        root.addLayout(bar)

        # 封禁列表
        self.table = QTableWidget(0, len(BAN_HEADERS))
        self.table.setHorizontalHeaderLabels(BAN_HEADERS)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(32)
        h = self.table.horizontalHeader()
        for i, w in enumerate([44, 118, 190, 52, 190, 48, 66, 70, 116, 128, 148]):
            h.resizeSection(i, w)
        h.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        h.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        root.addWidget(self.table, 1)

    # ── 数据 ──
    def _status_filter(self) -> str:
        m = {"已封禁": STATUS_ACTIVE, "已解封": STATUS_UNBANNED,
             "失败": STATUS_FAILED, "处理中": STATUS_PENDING}
        return m.get(self.status_filter.currentText(), "")

    def refresh(self) -> None:
        self._load_suggestions()
        self._load_bans()

    def _load_suggestions(self) -> None:
        rows = [r for r in query_risk_events(limit=200, handled=0)
                if r.get("risk_level") in (LEVEL_HIGH, LEVEL_CRITICAL)]
        self.sug_table.setRowCount(0)
        self.sug_table.setRowCount(len(rows))
        self.grp_sug.setTitle(f"待确认的封禁建议（{len(rows)}）")
        self.sug_hint.setVisible(not rows)
        if not rows:
            self.sug_hint.setText("暂无待确认建议 — 规则引擎未发现需要封禁的风险 IP")

        for i, r in enumerate(rows):
            ts = r.get("event_ts")
            time_str = (datetime.datetime.fromtimestamp(ts / 1000).strftime("%m-%d %H:%M:%S")
                        if ts else "-")
            geo = r.get("geo")
            level = r.get("risk_level", "normal")
            reason = r.get("summary") or "命中风险规则"

            self.sug_table.setItem(i, 0, QTableWidgetItem(time_str))
            self.sug_table.setItem(i, 1, QTableWidgetItem(r.get("ip", "")))
            self.sug_table.setItem(i, 2, QTableWidgetItem(geo.region_short if geo else "未知"))
            self.sug_table.setItem(i, 3, QTableWidgetItem(str(r.get("local_port") or "-")))
            self.sug_table.setItem(i, 4, QTableWidgetItem(str(r.get("risk_score", 0))))
            self.sug_table.setItem(i, 5, QTableWidgetItem(LEVEL_LABEL.get(level, level)))
            self.sug_table.setItem(i, 6, QTableWidgetItem(reason))
            self.sug_table.setCellWidget(i, 7, self._sug_actions(r, reason))

    def _sug_actions(self, r, reason: str) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(4, 2, 4, 2)
        lay.setSpacing(4)
        ip = r.get("ip", "")
        score = r.get("risk_score", 0)

        b_ban = QPushButton("确认封禁")
        b_ban.setFixedHeight(24)
        b_ban.setStyleSheet(small_button_style("danger"))
        b_ban.setCursor(Qt.CursorShape.PointingHandCursor)
        b_ban.clicked.connect(lambda: self.ask_ban.emit(ip, score, reason))

        b_ig = QPushButton("忽略")
        b_ig.setFixedHeight(24)
        b_ig.setStyleSheet(small_button_style("outline"))
        b_ig.setCursor(Qt.CursorShape.PointingHandCursor)
        b_ig.clicked.connect(lambda: self._ignore(r))

        lay.addWidget(b_ban)
        lay.addWidget(b_ig)
        lay.addStretch(1)
        return w

    def _ignore(self, r) -> None:
        try:
            set_risk_handled(int(r["id"]), 2)
        except Exception:
            log.exception("忽略风险事件失败 id=%s", r.get("id"))
        self.refresh()

    def _load_bans(self) -> None:
        rows = query_bans(status=self._status_filter(), keyword=self.search.text().strip())
        self.table.setRowCount(0)
        self.table.setRowCount(len(rows))
        for i, b in enumerate(rows):
            def mk(text, color=None, align=None):
                it = QTableWidgetItem(str(text))
                if color:
                    it.setForeground(QColor(color))
                if align:
                    it.setTextAlignment(align)
                return it

            status_color = {
                STATUS_ACTIVE: C.danger, STATUS_UNBANNED: C.text_muted,
                STATUS_FAILED: C.warning, STATUS_PENDING: C.info,
            }.get(b.status, C.text_secondary)

            self.table.setItem(i, 0, mk(b.id, align=Qt.AlignmentFlag.AlignCenter))
            self.table.setItem(i, 1, mk(b.ip, C.text_link))
            self.table.setItem(i, 2, mk(b.rule_name or "-"))
            self.table.setItem(i, 3, mk(b.source_label, align=Qt.AlignmentFlag.AlignCenter))
            self.table.setItem(i, 4, mk(b.reason or "-"))
            self.table.setItem(i, 5, mk(b.risk_score, align=Qt.AlignmentFlag.AlignCenter))
            self.table.setItem(i, 6, mk(b.status_label, status_color,
                                        Qt.AlignmentFlag.AlignCenter))
            self.table.setItem(i, 7, mk(b.duration_label, align=Qt.AlignmentFlag.AlignCenter))
            self.table.setItem(i, 8, mk(b.expire_label, align=Qt.AlignmentFlag.AlignCenter))
            self.table.setItem(i, 9, mk(b.created_at or "-"))

            self.table.setCellWidget(i, 10, self._ban_actions(b))

        self.lbl_info.setText(f"共 {len(rows)} 条 · 当前生效 {count_active_bans()} 条")

    def _ban_actions(self, b) -> QWidget:
        w = QWidget()
        lay = QHBoxLayout(w)
        lay.setContentsMargins(4, 2, 4, 2)
        lay.setSpacing(4)

        b_unban = QPushButton("解封")
        b_unban.setFixedHeight(24)
        b_unban.setStyleSheet(small_button_style("success"))
        b_unban.setCursor(Qt.CursorShape.PointingHandCursor)
        b_unban.setEnabled(b.status == STATUS_ACTIVE)
        b_unban.clicked.connect(lambda: self._unban(b))

        b_del = QPushButton("删记录")
        b_del.setFixedHeight(24)
        b_del.setStyleSheet(small_button_style("outline"))
        b_del.setCursor(Qt.CursorShape.PointingHandCursor)
        b_del.clicked.connect(lambda: self._delete(b))

        lay.addWidget(b_unban)
        lay.addWidget(b_del)
        lay.addStretch(1)
        return w

    def _unban(self, b) -> None:
        ok, err = ban_service.unban(b)
        if ok:
            self.refresh()
            self.request_refresh_stats.emit()
        else:
            QMessageBox.warning(self, "解封失败", err or "未知错误")

    def _delete(self, b) -> None:
        from core.database import delete_ban_record
        if QMessageBox.question(self, "删除记录",
                                f"仅从数据库删除封禁记录 #{b.id}（IP {b.ip}），"
                                f"不会影响已生效的防火墙规则。\n\n确认删除？",
                                QMessageBox.StandardButton.Yes
                                | QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        delete_ban_record(b.id)
        self.refresh()

    def _unban_all(self) -> None:
        if not firewall.is_admin():
            QMessageBox.warning(self, "权限不足", "批量解封需要管理员权限，请以管理员身份重启程序。")
            return
        if QMessageBox.question(self, "一键全部解封",
                                "将删除所有以 PortGuard_Block_ 开头的防火墙规则，并把这些封禁记录标记为已解封。\n\n确认继续？",
                                QMessageBox.StandardButton.Yes
                                | QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
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
            QMessageBox.information(self, "提示",
                                    "对账需要查询防火墙规则，请以管理员身份运行以获取完整信息。\n"
                                    "普通权限下仍会尝试按规则名核对。")
        try:
            existing = firewall.list_rule_names()
        except Exception as e:
            log.exception("读取防火墙规则失败")
            QMessageBox.warning(self, "对账失败", str(e))
            return
        fixed = ban_service.reconcile(existing)
        self.refresh()
        QMessageBox.information(self, "对账完成",
                                f"防火墙中现存 PortGuard 规则：{len(existing)} 条\n"
                                f"已修正 {fixed} 条失效记录。")

    def _restart_as_admin(self) -> None:
        if QMessageBox.question(self, "以管理员身份重启",
                                "将重新启动程序并请求管理员权限。\n\n继续？",
                                QMessageBox.StandardButton.Yes
                                | QMessageBox.StandardButton.No) != QMessageBox.StandardButton.Yes:
            return
        ok, err = firewall.open_admin_restart()
        if not ok:
            QMessageBox.warning(self, "提权失败",
                                f"{err}\n\n请手动右键程序 → 以管理员身份运行。")
        else:
            from PySide6.QtWidgets import QApplication
            QApplication.instance().quit()
