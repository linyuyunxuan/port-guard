"""PortGuard — 事件 / 访问记录「详情」对话框（组内逐条明细）

背景（2026-10-22 用户反馈）：列表把「同 IP + 同端口」的 N 次访问折叠成一行（×N），
用户要求「点详情看详细信息」。所以详情不能只是一段摘要文本，而是两层：

1. **摘要**：这个聚合体是什么（来源、归属地、端口、时间范围、最高水位、处理状态）；
2. **逐条明细表**：组内每一次发生的时间、路径、等级、评分、命中规则、处置。

两个入口共用同一套版式：
- `EventDetailDialog`  —— 风险事件（`risk_event` 字典，可带 `members` 合并组）
- `AccessDetailDialog` —— 实时访问流水（一组 `AccessRecord`）

设计约束：
- 明细表**不做分页**，但成员超过 `MAX_ROWS_SHOWN` 时只渲染前若干条并在末尾提示，
  避免「一次攻击 800 条」时弹窗自己要几百毫秒才打开。
- 表格里每一格都带 tooltip（长文本不换行时靠它看全）。
- 「复制全部」把整张表按 TSV 复制出去 —— 用户下一步基本都是贴到工单或 IM 里。
"""

from typing import Any, Dict, List, Sequence

from core.config import LEVEL_LABEL
from core.models import (
    DISPOSITION_HINT,
    HANDLED_LABEL,
    disposition_label,
    disposition_of,
    ms_to_str,
)
from core.rules_meta import rule_label
from gui.theme import C
from gui.widgets import RiskBadgeDelegate, badge_item, make_item
from qtcompat import (
    QAbstractItemView,
    QApplication,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    Qt,
    QTableWidget,
    QTextEdit,
    QVBoxLayout,
)

#: 明细表最多渲染多少行（超出只提示条数，不渲染 —— 一次攻击几千条时弹窗会卡）
MAX_ROWS_SHOWN = 300

#: 摘要区最大高度（把余下高度全给明细表）
SUMMARY_MAX_H = 190


def _text_block(lines: Sequence[str], parent=None) -> QTextEdit:
    """只读摘要区：能选中复制，但看起来像普通文字块"""
    txt = QTextEdit(parent)
    txt.setReadOnly(True)
    txt.setFrameShape(QFrame.Shape.NoFrame)
    txt.setStyleSheet(
        f"QTextEdit{{background:transparent;color:{C.text_secondary};"
        f"font-size:12.5px;line-height:1.6;}}"
    )
    txt.setPlainText("\n".join(lines))
    txt.setMaximumHeight(SUMMARY_MAX_H)
    txt.setMinimumHeight(80)
    return txt


def _build_table(
    headers: Sequence[str], rows: Sequence[Sequence[str]], stretch_col: int
) -> QTableWidget:
    """明细表：每格是显示文字（tooltip 与显示文字相同 —— 截断时能看全）"""
    table = QTableWidget(len(rows), len(headers))
    table.setHorizontalHeaderLabels(list(headers))
    table.verticalHeader().setVisible(False)
    table.setShowGrid(False)
    table.setAlternatingRowColors(True)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setWordWrap(False)
    table.verticalHeader().setDefaultSectionSize(30)

    table.setUpdatesEnabled(False)
    try:
        for r, cells in enumerate(rows):
            for c, text in enumerate(cells):
                if c == 1 and headers[1] == "等级":
                    table.setItem(r, c, badge_item(text))
                else:
                    mono = c in (0, 3)
                    center = c in (1, 3, len(headers) - 1)
                    table.setItem(
                        r,
                        c,
                        make_item(
                            text,
                            align=Qt.AlignmentFlag.AlignCenter if center else None,
                            mono=mono,
                            tip=text,
                        ),
                    )
    finally:
        table.setUpdatesEnabled(True)

    if len(headers) > 1 and headers[1] == "等级":
        table.setItemDelegateForColumn(1, RiskBadgeDelegate(table))

    hh = table.horizontalHeader()
    hh.setStretchLastSection(False)
    hh.setSectionResizeMode(stretch_col, QHeaderView.ResizeMode.Stretch)
    for c in range(len(headers)):
        if c != stretch_col:
            table.resizeColumnToContents(c)
    return table


def _copy_table(table: QTableWidget) -> None:
    lines: List[str] = []
    headers = []
    for c in range(table.columnCount()):
        h = table.horizontalHeaderItem(c)
        headers.append(h.text() if h is not None else "")
    lines.append("\t".join(headers))
    for r in range(table.rowCount()):
        cells = []
        for c in range(table.columnCount()):
            item = table.item(r, c)
            cells.append(item.text() if item is not None else "")
        lines.append("\t".join(cells))
    QApplication.clipboard().setText("\n".join(lines))


def _footer(dialog: QDialog, table: QTableWidget) -> QHBoxLayout:
    row = QHBoxLayout()
    hint = QLabel("可拖动选中摘要文字；「复制全部」按 TSV 复制整张明细表")
    hint.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
    row.addWidget(hint)
    row.addStretch(1)
    # 不用标准按钮 QDialogButtonBox.Close：它的文案跟随系统语言，中文系统上
    # 也可能显示英文 "Close"，跟全中文的界面放一起很扎眼
    btns = QDialogButtonBox()
    close_btn = btns.addButton("关闭", QDialogButtonBox.ButtonRole.RejectRole)
    close_btn.clicked.connect(dialog.reject)
    copy_btn = btns.addButton("复制全部", QDialogButtonBox.ButtonRole.ActionRole)
    copy_btn.clicked.connect(lambda: _copy_table(table))
    row.addWidget(btns)
    return row


class EventDetailDialog(QDialog):
    """风险事件详情（支持合并组：members 有多少条就列多少条）"""

    def __init__(self, row: Dict[str, Any], parent=None):
        super().__init__(parent)
        members: List[Dict[str, Any]] = list(row.get("members") or [])
        n = len(members) if members else 1
        ip = str(row.get("ip") or "")
        port = row.get("local_port")
        title = f"风险事件详情 — {ip}:{port}" if ip else "风险事件详情"
        if n > 1:
            title += f"（{n} 次）"
        self.setWindowTitle(title)
        self.setMinimumSize(820, 520)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 12)
        lay.setSpacing(10)

        geo = row.get("geo")
        risk_level = str(row.get("risk_level") or "")
        disp = disposition_of(row)
        # 合并行的等级 / 评分 / 规则是组内最高水位，摘要里要说清「这是最高的一条」
        peak_level = str(row.get("peak_level") or risk_level)
        peak_score = row.get("peak_score", row.get("risk_score"))
        peak_rules = list(row.get("peak_rules") or row.get("matched_rules") or [])

        lines = [
            f"来源 IP：{ip}    目标端口：{port}    归属地：{geo.display if geo else '未知'}",
            f"最高风险：{peak_score} 分 / {LEVEL_LABEL.get(peak_level, peak_level)}"
            f"    处理状态：{HANDLED_LABEL.get(int(row.get('handled') or 0), '-')}",
            f"处置结果：{disposition_label(disp)}"
            + (f"（{DISPOSITION_HINT[disp]}）" if DISPOSITION_HINT.get(disp) else ""),
            f"命中规则（最高水位那条）：{'、'.join(rule_label(x) for x in peak_rules) or '-'}",
        ]
        if n > 1:
            lines.append(
                f"发生次数：{n} 次    首次：{ms_to_str(row.get('first_ts'))}"
                f"    最近：{ms_to_str(row.get('last_ts'))}"
            )
        else:
            lines.append(f"发生时间：{ms_to_str(row.get('event_ts'))}")
        if geo is not None and getattr(geo, "found", False):
            lines.append(f"归属地明细：{geo.country} {geo.province} {geo.city} · ISP {geo.isp}")
        summary = row.get("summary")
        if summary:
            lines.append(f"摘要：{summary}")
        lay.addWidget(_text_block(lines, self))

        src = members if members else [row]
        shown = src[:MAX_ROWS_SHOWN]
        rows: List[List[str]] = []
        for m in shown:
            ml = str(m.get("risk_level") or "")
            mdisp = disposition_of(m)
            rows.append(
                [
                    ms_to_str(m.get("event_ts")),
                    ml,
                    str(m.get("path") or "/"),
                    str(m.get("risk_score") or 0),
                    "、".join(rule_label(x) for x in (m.get("matched_rules") or [])) or "-",
                    disposition_label(mdisp),
                ]
            )
        table = _build_table(
            ["时间", "等级", "路径", "评分", "命中规则", "处置"], rows, stretch_col=2
        )
        lay.addWidget(table, 1)

        if len(src) > MAX_ROWS_SHOWN:
            more = QLabel(
                f"仅列出最近 {MAX_ROWS_SHOWN} 条，其余 {len(src) - MAX_ROWS_SHOWN} 条"
                "请在「风险事件」页导出 CSV 查看"
            )
            more.setStyleSheet(f"color:{C.warning};font-size:12px;")
            lay.addWidget(more)

        lay.addLayout(_footer(self, table))


class AccessDetailDialog(QDialog):
    """实时访问详情：同一 IP + 端口的 N 次连接逐条列出"""

    def __init__(self, records: List[Any], parent=None):
        super().__init__(parent)
        # 组内成员在模型里是「按发生顺序」存的（旧的在前），而弹窗标题与「仅列出最近
        # N 条」都承诺的是**最近** —— 所以这里倒序，否则截出来的 300 条是最老的 300 条。
        recs = sorted(
            records,
            key=lambda r: (
                int(getattr(r, "event_ts", 0) or 0),
                int(getattr(r, "remote_port", 0) or 0),
            ),
            reverse=True,
        )
        first = recs[0] if recs else None
        ip = getattr(first, "ip", "") if first is not None else ""
        port = getattr(first, "local_port", "") if first is not None else ""
        title = f"访问详情 — {ip}:{port}" if ip else "访问详情"
        if len(recs) > 1:
            title += f"（{len(recs)} 次）"
        self.setWindowTitle(title)
        self.setMinimumSize(860, 520)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 12)
        lay.setSpacing(10)

        if first is None:
            lay.addWidget(_text_block(["没有可显示的记录"], self))
            table = _build_table(["时间"], [], stretch_col=0)
            lay.addWidget(table, 1)
            lay.addLayout(_footer(self, table))
            return

        geo = getattr(first, "geo", None)
        peak = max(recs, key=lambda r: int(getattr(r, "risk_score", 0) or 0))
        peak_level = str(getattr(peak, "risk_level", "") or "")
        peak_score = int(getattr(peak, "risk_score", 0) or 0)
        disp_set = {str(getattr(r, "disposition", "") or "") for r in recs}
        disp_text = "、".join(sorted(disposition_label(d) for d in disp_set if d)) or "-"
        ts_list = [int(getattr(r, "event_ts", 0) or 0) for r in recs]

        lines = [
            f"来源 IP：{ip}    目标端口：{port}    协议："
            f"{(getattr(first, 'protocol', '') or '').upper() or '-'}",
            f"归属地：{geo.display if geo else '未知'}",
            f"最高风险：{peak_score} 分 / {LEVEL_LABEL.get(peak_level, peak_level)}",
            f"处置结果：{disp_text}",
            f"发生次数：{len(recs)} 次    首次：{ms_to_str(min(ts_list))}"
            f"    最近：{ms_to_str(max(ts_list))}",
        ]
        lay.addWidget(_text_block(lines, self))

        shown = recs[:MAX_ROWS_SHOWN]
        rows: List[List[str]] = []
        for r in shown:
            ua = str(getattr(r, "user_agent", "") or "")
            rows.append(
                [
                    ms_to_str(getattr(r, "event_ts", 0)),
                    str(getattr(r, "risk_level", "") or ""),
                    f"{getattr(r, 'method', '') or ''} {getattr(r, 'path', '') or '/'}".strip(),
                    str(getattr(r, "risk_score", 0) or 0),
                    str(getattr(r, "matched_str", "") or getattr(r, "matched_rules", "") or "-"),
                    disposition_label(str(getattr(r, "disposition", "") or "")),
                    ua[:60] or "-",
                ]
            )
        table = _build_table(
            ["时间", "等级", "请求", "评分", "命中规则", "处置", "User-Agent"],
            rows,
            stretch_col=2,
        )
        lay.addWidget(table, 1)

        if len(recs) > MAX_ROWS_SHOWN:
            more = QLabel(f"仅列出最近 {MAX_ROWS_SHOWN} 条，共 {len(recs)} 条")
            more.setStyleSheet(f"color:{C.warning};font-size:12px;")
            lay.addWidget(more)

        lay.addLayout(_footer(self, table))
