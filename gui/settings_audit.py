"""PortGuard — 设置页「操作审计」tab。

从 page_settings.py 拆出的第一个试点面板（P2-6）：这个 tab 完全自包含
（只读查询 + 分页 + 过滤），与设置页的 save()/load() 持久化链路零耦合，
拆出去不碰任何保存语义。

这个 tab **只读**，且刻意不放任何「删除 / 清空」按钮 —— 审计表的价值
就在于它不能被使用者自己抹掉，想删只能靠保留期（`audit_retention_days`）
到期被定期清理带走。
"""

from typing import Any, Dict

from app import audit
from core.database import count_audit, query_audit
from core.logger import get_logger
from gui.theme import C
from gui.widgets import align_headers, make_item
from qtcompat import (
    QAbstractItemView,
    QComboBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    Qt,
    QTableWidget,
    QVBoxLayout,
    QWidget,
)

log = get_logger(__name__)

AUDIT_HEADERS = ["时间", "操作者", "操作", "对象", "摘要", "结果"]
AUDIT_WIDTHS = [170, 150, 115, 104, 483, 69]
AUDIT_CENTER_COLS = [0, 2, 3, 5]
COL_AUDIT_SUMMARY = 4
AUDIT_RESULT_LABEL = {
    "ok": "成功",
    "fail": "失败",
    "skipped": "未执行",
}


def _audit_target(row: Dict[str, Any]) -> str:
    """审计记录的「对象」列：类型 + id，缺一补一，都没有就 `-`"""
    t = str(row.get("target_type") or "")
    i = row.get("target_id")
    i = "" if i is None else str(i)
    if t and i:
        return f"{t} #{i}"
    return t or i or "-"


class AuditPanel(QWidget):
    """审计留痕查看：分页 + 按操作者 / 操作类型过滤。对外只暴露两个动作：
    `refresh()`（按当前条件重查一页）和 `refresh_actors()`（重载操作者下拉）。
    """

    def __init__(self, parent=None):
        super().__init__(parent)
        self._page = 0
        #: 每页条数。审计一次操作一条，量不大，但也别一次拉全表
        self._size = 50
        self._build()
        self.refresh_actors()

    # ── 界面装配 ──

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 8, 8, 8)
        lay.setSpacing(8)

        # ── 过滤条 ──
        bar = QHBoxLayout()
        bar.setSpacing(8)
        self.cb_actor = QComboBox()
        self.cb_actor.setFixedWidth(150)
        self.cb_actor.currentIndexChanged.connect(self._on_filter)

        self.cb_action = QComboBox()
        self.cb_action.setFixedWidth(150)
        self.cb_action.addItem("全部操作", "")
        for act in audit.ACTIONS:
            self.cb_action.addItem(audit.action_label(act), act)
        self.cb_action.currentIndexChanged.connect(self._on_filter)

        self.ed_kw = QLineEdit()
        self.ed_kw.setPlaceholderText("搜索摘要 / 对象 / 详情")
        self.ed_kw.setFixedWidth(220)
        self.ed_kw.returnPressed.connect(self._on_filter)

        b_search = QPushButton("筛选")
        b_search.setObjectName("btn_outline")
        b_search.setFixedWidth(72)
        b_search.clicked.connect(self._on_filter)

        b_refresh = QPushButton("刷新")
        b_refresh.setObjectName("btn_primary")
        b_refresh.setFixedWidth(72)
        b_refresh.clicked.connect(self.refresh)

        bar.addWidget(QLabel("操作者"))
        bar.addWidget(self.cb_actor)
        bar.addSpacing(6)
        bar.addWidget(QLabel("操作"))
        bar.addWidget(self.cb_action)
        bar.addSpacing(6)
        bar.addWidget(self.ed_kw)
        bar.addWidget(b_search)
        bar.addWidget(b_refresh)
        bar.addStretch(1)
        lay.addLayout(bar)

        # ── 表格 ──
        self.tbl = QTableWidget(0, len(AUDIT_HEADERS))
        self.tbl.setHorizontalHeaderLabels(AUDIT_HEADERS)
        self.tbl.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.tbl.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tbl.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tbl.setAlternatingRowColors(True)
        self.tbl.setShowGrid(False)
        self.tbl.setWordWrap(False)
        self.tbl.setTabKeyNavigation(False)
        self.tbl.verticalHeader().setVisible(False)
        self.tbl.verticalHeader().setDefaultSectionSize(30)
        self.tbl.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)
        align_headers(self.tbl, AUDIT_CENTER_COLS)
        hh = self.tbl.horizontalHeader()
        for i, w in enumerate(AUDIT_WIDTHS):
            hh.resizeSection(i, w)
        # 摘要是唯一拉伸列：其余列都是定长（时间 / 人名 / 枚举），
        # 横向滚动是硬约束 —— 表格不许出现横向滚动条
        hh.setSectionResizeMode(COL_AUDIT_SUMMARY, QHeaderView.ResizeMode.Stretch)
        lay.addWidget(self.tbl, 1)

        # ── 分页 ──
        pager = QHBoxLayout()
        pager.setSpacing(8)
        self.btn_prev = QPushButton("上一页")
        self.btn_prev.setObjectName("btn_outline")
        self.btn_prev.setFixedWidth(80)
        self.btn_prev.clicked.connect(lambda: self._goto_page(self._page - 1))
        self.btn_next = QPushButton("下一页")
        self.btn_next.setObjectName("btn_outline")
        self.btn_next.setFixedWidth(80)
        self.btn_next.clicked.connect(lambda: self._goto_page(self._page + 1))
        self.lbl_page = QLabel("共 0 条，第 1/1 页")
        self.lbl_page.setStyleSheet(f"color:{C.text_secondary};font-size:13.5px;")
        pager.addWidget(self.btn_prev)
        pager.addWidget(self.btn_next)
        pager.addSpacing(6)
        pager.addWidget(self.lbl_page)
        pager.addStretch(1)
        lay.addLayout(pager)

        self.lbl_hint = QLabel(
            "记录谁在何时做了什么：本机操作记 Windows 用户名，"
            "程序自动（到期巡检 / 定期清理 / 自动封禁）记 system，"
            "老库里还留着 1.1.0 之前 HTTP 上报触发的 http:<来源IP>。"
        )
        self.lbl_hint.setObjectName("form_hint")
        self.lbl_hint.setWordWrap(True)
        lay.addWidget(self.lbl_hint)

    # ── 数据 ──

    def _on_filter(self, *_args: Any) -> None:
        # 条件变了必须回第 1 页：在第 7 页改过滤条件，原 offset 会指向空页
        self._page = 0
        self.refresh()

    def _goto_page(self, page: int) -> None:
        self._page = max(0, int(page))
        self.refresh()

    def refresh(self) -> None:
        """按当前条件重查一页审计记录"""
        actor = self.cb_actor.currentData() or ""
        action = self.cb_action.currentData() or ""
        kw = self.ed_kw.text().strip()
        try:
            total = count_audit(actor=actor, action=action, keyword=kw)
            rows = query_audit(
                limit=self._size,
                offset=self._page * self._size,
                actor=actor,
                action=action,
                keyword=kw,
            )
        except Exception:
            log.exception("查询审计记录失败")
            self.lbl_page.setText("查询失败")
            return

        # 末尾页被删空时退回最后一页（否则用户看到空表以为数据没了）
        pages = max(1, (total + self._size - 1) // self._size)
        if self._page >= pages:
            self._page = max(0, pages - 1)
            if self._page and not rows:
                self.refresh()
                return

        self.tbl.setRowCount(len(rows))
        for i, r in enumerate(rows):
            self._set_row(i, r)
        self.btn_prev.setEnabled(self._page > 0)
        self.btn_next.setEnabled(self._page + 1 < pages)
        self.lbl_page.setText(f"共 {total} 条，第 {self._page + 1}/{pages} 页")

    def _set_row(self, row: int, r: Dict[str, Any]) -> None:
        result = str(r.get("result") or "")
        color = C.danger if result == audit.RESULT_FAIL else None
        cells = [
            make_item(audit.fmt_ts(r.get("ts")), mono=True),
            make_item(audit.actor_label(r.get("actor") or ""), tip=r.get("actor") or ""),
            make_item(audit.action_label(r.get("action") or "")),
            make_item(_audit_target(r)),
            make_item(r.get("summary") or "", color=color, tip=r.get("detail") or ""),
            make_item(AUDIT_RESULT_LABEL.get(result, result), color=color),
        ]
        for col, it in enumerate(cells):
            self.tbl.setItem(row, col, it)

    def refresh_actors(self) -> None:
        """重载「操作者」下拉框。保留当前选中项，避免刷新把筛选条件打回全部"""
        from core.database import list_audit_actors

        current = self.cb_actor.currentData() or ""
        try:
            actors = list_audit_actors()
        except Exception:
            log.exception("读取审计操作者列表失败")
            actors = []
        self.cb_actor.blockSignals(True)
        self.cb_actor.clear()
        self.cb_actor.addItem("全部操作者", "")
        for a in actors:
            self.cb_actor.addItem(audit.actor_label(a), a)
        idx = self.cb_actor.findData(current)
        self.cb_actor.setCurrentIndex(idx if idx >= 0 else 0)
        self.cb_actor.blockSignals(False)
