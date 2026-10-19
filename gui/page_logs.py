"""PortGuard — 运行日志页（在**程序内**显示日志）

用户明确要求：日志要在程序里显示，**不是**「打开日志保存位置」。
本页提供两个日志流，都像终端一样在程序内滚动：

  1. 程序运行日志 —— 跟读 data/logs/portguard.log（含 uvicorn 的日志），
     支持级别过滤（INFO 及以上 / WARNING 及以上 / ERROR 及以上）与关键字搜索
  2. 端口访问日志 —— 实时监控收到的每一条访问记录（业务系统上报 + 本机采集），
     按风险等级着色，带归属地、命中规则、采集通道

实现要点：
· 程序日志用 core.logtail.LogTailer **增量**读取，只读新增字节，不卡 UI
· 访问日志由主窗口事件泵 push 进来（同样只走 Qt 主线程）
· 只保留最近 N 行（设置项 log_view_max_lines），几十万行也不会把界面拖死
· 切换筛选 / 搜索时从缓冲区整体重绘，**不会丢数据**

「打开日志文件夹」按钮保留为**次要入口**（偶发需要在资源管理器里翻原始文件），
但默认路径是页内直接显示。
"""

import contextlib
import datetime
from collections import deque
from dataclasses import dataclass
from typing import Deque, List

from core import settings as cfg
from core.config import LEVEL_LABEL
from core.logger import get_logger, log_file
from core.logtail import LogLine, LogTailer
from core.models import AccessRecord
from gui.components import PageHeader, row_menu_button
from gui.theme import LEVEL_COLORS, C
from gui.widgets import ToggleSwitch
from qtcompat import (
    QComboBox,
    QFont,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    Qt,
    QTimer,
    QVBoxLayout,
    QWidget,
    Signal,
)

log = get_logger(__name__)

# 日志级别 -> 颜色
LEVEL_COLOR = {
    "DEBUG": C.text_muted,
    "INFO": C.text_secondary,
    "WARNING": C.warning,
    "ERROR": C.danger,
    "CRITICAL": C.critical,
}

# 级别过滤下拉：标签 -> 最低级别序号（-1 表示不过滤）
LEVEL_FILTERS = [
    ("全部级别", -1),
    ("INFO 及以上", 1),
    ("WARNING 及以上", 2),
    ("ERROR 及以上", 3),
]

SOURCE_APP = 0
SOURCE_ACCESS = 1


@dataclass
class _Row:
    """日志视图里的一行（与 QPlainTextEdit 解耦，便于重绘 / 过滤 / 导出）"""

    kind: str  # "app" | "access"
    ts: str
    color: str
    text: str
    level_rank: int = 1
    hay: str = ""


def _esc(s: str) -> str:
    """
    转义成可安全塞进 HTML 的文本。

    空格转 &nbsp; 是必须的：日志里大量用空格对齐，HTML 默认会把连续空格折叠成一个，
    不转的话日志看起来会糊成一团，完全失去可读性。
    """
    return (
        (s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace(" ", "&nbsp;")
    )


class LogsPage(QWidget):
    """运行日志页"""

    logs_open_requested = Signal()  # 次要入口：请求主窗口打开日志目录

    def __init__(self, parent=None):
        super().__init__(parent)
        self._max_lines = max(200, cfg.get_int("log_view_max_lines", 2000))
        self._rows: Deque[_Row] = deque(maxlen=self._max_lines)
        self._paused = False
        self._dirty = False  # 缓冲里有尚未反映到界面的行
        self._tailer = LogTailer(log_file(), max_lines=self._max_lines)
        self._seeded = False
        self._build()

    # ═══════════════════════════════════════════════
    #  界面
    # ═══════════════════════════════════════════════
    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 16, 24, 12)
        root.setSpacing(12)

        head = PageHeader("运行日志", "日志直接显示在程序内，可过滤、搜索、暂停")
        root.addWidget(head)

        # ── 工具条（左：筛选簇 / 右：查看簇，簇间 24、簇内 8）──
        bar = QHBoxLayout()
        bar.setSpacing(0)

        left = QHBoxLayout()
        left.setSpacing(8)
        self.source = QComboBox()
        self.source.addItems(["程序运行日志", "端口访问日志"])
        self.source.setFixedWidth(140)
        self.source.currentIndexChanged.connect(self._on_source_changed)

        self.level = QComboBox()
        self.level.addItems([x[0] for x in LEVEL_FILTERS])
        self.level.setFixedWidth(150)
        self.level.currentIndexChanged.connect(self._render)

        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索关键字（IP / 端口 / 规则 / 异常信息）…")
        self.search.setClearButtonEnabled(True)
        self.search.setMinimumWidth(240)
        self.search.textChanged.connect(self._render)

        left.addWidget(self.source)
        left.addWidget(self.level)
        left.addWidget(self.search, 1)

        right = QHBoxLayout()
        right.setSpacing(8)
        self.toggle_pause = ToggleSwitch(False)
        self.toggle_pause.toggled.connect(self._on_pause)
        right.addWidget(self.toggle_pause)
        right.addWidget(self._sub_label("暂停"))

        self.toggle_scroll = ToggleSwitch(True)
        right.addWidget(self.toggle_scroll)
        right.addWidget(self._sub_label("自动滚动"))

        btn_clear = QPushButton("清空显示")
        btn_clear.setObjectName("btn_outline")
        btn_clear.clicked.connect(self.clear_view)
        right.addWidget(btn_clear)

        # 「打开日志文件夹」是次要入口 —— 收进「⋯」，工具条不再平铺 9 个控件
        self.btn_more = row_menu_button(
            [
                ("打开日志文件夹", self.logs_open_requested.emit),
                ("跳到最新一行", self._scroll_to_end),
            ],
            self,
            size=32,
        )
        right.addWidget(self.btn_more)

        bar.addLayout(left, 1)
        bar.addSpacing(24)
        bar.addLayout(right)
        root.addLayout(bar)

        # ── 日志视图 ──
        self.view = QPlainTextEdit()
        self.view.setReadOnly(True)
        self.view.setUndoRedoEnabled(False)
        self.view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        # 不换行就必须有横向滚动条：日志对常用空格对齐，折行会彻底破坏可读性
        self.view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        f = QFont("Consolas")
        f.setStyleHint(QFont.StyleHint.Monospace)
        f.setPixelSize(12)
        self.view.setFont(f)
        self.view.setStyleSheet(
            f"QPlainTextEdit{{background:{C.bg_input};color:{C.text_primary};"
            f"border:1px solid {C.border};border-radius:8px;padding:8px;}}"
            f"QPlainTextEdit:focus{{border-color:{C.primary};}}"
        )
        root.addWidget(self.view, 1)

        # ── 页脚（11px 单行，只放页内统计）──
        self.lbl_info = QLabel("")
        self.lbl_info.setObjectName("hint")
        root.addWidget(self.lbl_info)

        self._timer = QTimer(self)
        self._timer.setInterval(max(200, cfg.get_int("log_view_tail_ms", 1000)))
        self._timer.timeout.connect(self._poll_file)
        self._timer.start()

    @staticmethod
    def _sub_label(text: str) -> QLabel:
        lb = QLabel(text)
        lb.setStyleSheet(f"color:{C.text_secondary};font-size:12.5px;")
        return lb

    def _scroll_to_end(self) -> None:
        sb = self.view.verticalScrollBar()
        sb.setValue(sb.maximum())

    # ═══════════════════════════════════════════════
    #  外部驱动：端口访问日志（来自主窗口事件泵）
    # ═══════════════════════════════════════════════
    def append_access(self, records: List[AccessRecord]) -> None:
        if not records or self._paused:
            return
        live = self.isVisible()
        for rec in records:
            self._add(_access_row(rec), live=live)
        self._flush()

    # ═══════════════════════════════════════════════
    #  内部驱动：程序日志（增量跟读文件）
    # ═══════════════════════════════════════════════
    def _ensure_seeded(self) -> None:
        """首次进入时先把已有日志的尾部铺上，并把读取位置推到文件末尾"""
        if self._seeded:
            return
        self._seeded = True
        for line in self._tailer.seed_from_tail(self._max_lines):
            self._add(_app_row(line), live=False)
        self._render()

    def _poll_file(self) -> None:
        if self._paused:
            return
        self._ensure_seeded()
        try:
            new = self._tailer.read_new()
        except Exception:
            log.debug("跟读程序日志失败", exc_info=True)
            return
        if not new:
            return
        live = self.isVisible()
        for line in new:
            self._add(_app_row(line), live=live)
        self._flush()
        self._update_info()

    # ═══════════════════════════════════════════════
    #  缓冲与渲染
    # ═══════════════════════════════════════════════
    def _add(self, row: _Row, live: bool = True) -> None:
        """
        往缓冲区追加一行。

        live=True  —— 立刻增量反映到界面（逐条到来的常规路径）
        live=False —— 只进缓冲区，稍后统一 _render()（批量铺底，避免 N 次重绘）

        缓冲满了（环形缓冲挤掉最旧一行）时只**打个标记**，不做整体重绘：
        否则流量一上来就是「每来一行全量重绘 2000 行」，界面会直接卡死。
        真正的重绘由 _flush() 在每个批次结束时合并成一次。
        """
        overflow = self._rows.maxlen is not None and len(self._rows) == self._rows.maxlen
        self._rows.append(row)
        if overflow or not live:
            self._dirty = True
            return
        if self._match(row):
            self._append_html(row)

    def _flush(self) -> None:
        """把「需要整体重绘」的标记兑现成一次渲染（批次结束时调用）"""
        if self._dirty and self.isVisible():
            self._render()

    def _current_level_min(self) -> int:
        try:
            return LEVEL_FILTERS[self.level.currentIndex()][1]
        except IndexError:
            return -1

    def _match(self, row: _Row) -> bool:
        src = self.source.currentIndex()
        if src == SOURCE_APP and row.kind != "app":
            return False
        if src == SOURCE_ACCESS and row.kind != "access":
            return False
        if row.kind == "app":
            mn = self._current_level_min()
            if mn >= 0 and row.level_rank < mn:
                return False
        kw = self.search.text().strip().lower()
        return not (kw and kw not in row.hay)

    def _at_bottom(self) -> bool:
        sb = self.view.verticalScrollBar()
        # 首行数据时 maximum 仍为 0，同样视为在底部
        return sb.value() >= sb.maximum() - 4 or sb.maximum() <= 0

    def _autoscroll(self, was_at_bottom: bool) -> None:
        """
        只在「用户本来就在底部」时才滚到底。
        无条件 scrollToBottom 会把正在往回翻历史的用户强行拽回底部。
        """
        if self.toggle_scroll.isChecked() and was_at_bottom:
            sb = self.view.verticalScrollBar()
            sb.setValue(sb.maximum())

    def _append_html(self, row: _Row) -> None:
        was_at_bottom = self._at_bottom()
        self.view.appendHtml(f'<span style="color:{row.color};">{_esc(row.text)}</span>')
        self._autoscroll(was_at_bottom)

    def _render(self) -> None:
        """
        按当前筛选条件从缓冲区整体重绘。

        用 `document().setHtml()` 而不是 `setHtml()` —— **QPlainTextEdit 根本没有
        setHtml**（只有 appendHtml / setPlainText），直接把大段 HTML 交给它会在
        运行时抛 AttributeError。document() 是 QTextDocument，它有 setHtml，
        而且一次调用就完成，比逐行 appendHtml 快一个数量级。
        """
        parts = [
            f'<span style="color:{r.color};">{_esc(r.text)}</span>'
            for r in self._rows
            if self._match(r)
        ]
        was_at_bottom = self._at_bottom()
        self.view.document().setHtml("<br>".join(parts))
        self._autoscroll(was_at_bottom)
        self._dirty = False
        self._update_info()

    # ═══════════════════════════════════════════════
    #  交互
    # ═══════════════════════════════════════════════
    def _on_source_changed(self, idx: int) -> None:
        # 级别过滤只对程序日志有意义
        self.level.setEnabled(idx == SOURCE_APP)
        self._render()

    def _on_pause(self, checked: bool) -> None:
        self._paused = checked
        if not checked and self._dirty:
            self._render()
        self._update_info()

    def clear_view(self) -> None:
        self._rows.clear()
        self.view.clear()
        self._update_info()

    def _update_info(self) -> None:
        shown = sum(1 for r in self._rows if self._match(r))
        total = len(self._rows)
        is_app = self.source.currentIndex() == SOURCE_APP
        src = "程序运行日志" if is_app else "端口访问日志"
        bits = [f"{src}：显示 {shown} / 缓冲 {total} 行"]
        if is_app:
            st = self._tailer.stats()
            bits.append(f"文件 {st['path']}")
            bits.append("本次已读取 %.1f KB" % (st["read_bytes"] / 1024))
            if st["rotations"]:
                bits.append(f"日志滚动 {st['rotations']} 次")
            if not st["exists"]:
                bits.append("（文件尚未生成）")
        if self._paused:
            bits.append("已暂停")
        self.lbl_info.setText(" · ".join(bits))

    # ═══════════════════════════════════════════════
    #  生命周期
    # ═══════════════════════════════════════════════
    def showEvent(self, event) -> None:
        super().showEvent(event)
        self._ensure_seeded()
        if self._dirty:
            self._render()
        else:
            self._update_info()

    def set_max_lines(self, n: int) -> None:
        self._max_lines = max(200, int(n))
        self._rows = deque(self._rows, maxlen=self._max_lines)
        self._tailer.set_max_lines(self._max_lines)
        self._render()

    def shutdown(self) -> None:
        with contextlib.suppress(Exception):
            self._timer.stop()


# 供 _autoscroll 读取；挂在类上而不是实例属性，避免 __init__ 里漏初始化
# ═══════════════════════════════════════════════════════════
#  行格式化
# ═══════════════════════════════════════════════════════════


def _app_row(line: LogLine) -> _Row:
    level = line.level or "INFO"
    return _Row(
        kind="app",
        ts=line.ts,
        color=LEVEL_COLOR.get(level, C.text_secondary),
        text=line.raw,
        level_rank=line.level_rank,
        hay=line.raw.lower(),
    )


def _access_row(rec: AccessRecord) -> _Row:
    """把一条访问记录渲染成一行「终端日志」"""
    ts = datetime.datetime.fromtimestamp(rec.event_ts / 1000).strftime("%Y-%m-%d %H:%M:%S")
    src = f"{rec.ip}:{rec.remote_port}" if rec.remote_port else rec.ip
    geo = rec.geo.display if rec.geo else "未知"
    level_label = LEVEL_LABEL.get(rec.risk_level, rec.risk_level)

    tags = rec.tags or {}
    channel = str(tags.get("channel") or "")
    if channel == "table":
        origin = "本机采集·TCP 连接表"
    elif channel == "fwlog":
        origin = f"本机采集·防火墙日志({tags.get('action', '')})"
    else:
        origin = "业务系统上报"
    proc = tags.get("process")
    if proc:
        origin += f"·{proc}"

    parts = [
        ts,
        f"{src} → 本机:{rec.local_port}",
        geo,
        f"{level_label}({rec.risk_score})",
        f"[{origin}]",
    ]
    if rec.matched_str:
        parts.append(rec.matched_str)
    if rec.path:
        parts.append(rec.path)

    text = "  |  ".join(parts)
    return _Row(
        kind="access",
        ts=ts,
        color=LEVEL_COLORS.get(rec.risk_level, C.text_secondary),
        text=text,
        level_rank=0,
        hay=text.lower(),
    )


def format_access_line(rec: AccessRecord) -> str:
    """供其它页面 / 导出复用的一行文本"""
    return _access_row(rec).text
