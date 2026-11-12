"""
PortGuard — 总览台（Overview Grid）首页

③ 方案第一阶段：把「现在安不安全、有没有事等我处理」压成 3 列 × 2 行六张卡，
作为默认落地页。①②④ 三张卡的主数字只认**一次** core.database.stats_snapshot，
其余查询都是只读；不在 paintEvent 里查库、构造期不做重活。24 格状态条是纯
QPainter.fillRect 自绘的等宽等高格，不用 QtCharts（交付栈 Server 2008 R2 上
ANGLE/OpenGL 会白屏，还要多带 DLL）。

防火墙结论由主窗通过 set_fw_state() 推送：profiles_state() 会起 netsh 子进程，
绝不在 UI 线程同步调，unknown 绝不判 off。

下钻目标页下标与 gui/main_window.py 的 PAGE_* 一致；这里刻意不 import MainWindow
（会成环），由主窗把 _switch_page 作为 on_navigate 回调传入。
"""

import datetime
from typing import Callable, Dict, List, Optional, Tuple

from gui.theme import C
from qtcompat import (
    QColor,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPainter,
    QPushButton,
    Qt,
    QVBoxLayout,
    QWidget,
)

# 下钻目标：与 gui/main_window.py 的 PAGE_* 下标一致（不 import MainWindow 以免成环）。
PAGE_MONITOR = 0
PAGE_EVENTS = 1
PAGE_BANS = 3
PAGE_RULES = 4
PAGE_SETTINGS = 7

_BUCKETS = 24
_BAR_GAP = 2
_BAR_LIMIT = 10000  # 24 格明细取数上限：只判各小时最高风险等级，不追求全量精确


def _make_slot(on_navigate: Callable[[int], None], idx: int) -> Callable[..., None]:
    """按钮槽工厂：吞掉 clicked 带来的 checked 参数。

    不能用带默认参数的 lambda —— PySide2/shiboken2 会按 0 参调用它，
    点击静默失灵（见 gui/main_window.py 的 _nav_slot 文档）。
    """

    def slot(_checked: bool = False) -> None:
        on_navigate(idx)

    return slot


class BarStripWidget(QWidget):
    """24 格等宽等高状态格：纯 fillRect 自绘，Qt5/Qt6 枚举统一走 qtcompat。

    颜色只表示该时间片的**最高风险等级**，不表达访问量、不画成趋势图：
      无事件 / 仅 normal·low → C.bg_card_alt
      medium                  → C.warning
      high / critical         → C.danger_solid
    红是稀缺资源：全条红格最多 3 个；红格总数 >3 或连续 ≥4 格红判为数据异常，
    超额红格降级为橙，由调用方在脚注提示（见 OverviewPage._refresh_traffic）。
    """

    # 等级 ID 来自 core.config.LEVEL_*，这里只做字面量比较，保持 widget 不依赖 core。
    _SEVERE = ("high", "critical")
    _MEDIUM = "medium"

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("barstrip_container")
        self.setMinimumHeight(48)
        self._counts: List[int] = [0] * _BUCKETS  # 仅留作 tooltip 数据，不决定高度/颜色
        self._colors: List[str] = [C.bg_card_alt] * _BUCKETS
        self._anomaly = False
        self.setToolTip("24 格 = 今日各小时；颜色表示该小时最高风险等级")

    @property
    def anomaly(self) -> bool:
        return self._anomaly

    def set_data(self, levels: List[str], counts: List[int]) -> None:
        self._counts = list(counts)[:_BUCKETS] + [0] * max(0, _BUCKETS - len(counts))
        lv = list(levels)[:_BUCKETS] + ["normal"] * max(0, _BUCKETS - len(levels))
        reds = [v in self._SEVERE for v in lv]
        keep = [False] * _BUCKETS
        kept = 0
        run = 0
        self._anomaly = False
        for i, is_red in enumerate(reds):
            if is_red:
                run += 1
                if run >= 4:
                    self._anomaly = True
                if kept < 3:
                    keep[i] = True
                    kept += 1
            else:
                run = 0
        if sum(reds) > 3:
            self._anomaly = True
        colors = []
        for i, level in enumerate(lv):
            if keep[i]:
                colors.append(C.danger_solid)
            elif level in self._SEVERE:
                colors.append(C.warning)  # 超额红格降级，守住「全条红格 ≤3」
            elif level == self._MEDIUM:
                colors.append(C.warning)
            else:
                colors.append(C.bg_card_alt)
        self._colors = colors
        self.update()

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        p.setPen(Qt.PenStyle.NoPen)
        w, h = self.width(), self.height()
        cw = (w - _BAR_GAP * (_BUCKETS - 1)) / float(_BUCKETS)
        pad = 6
        bh = max(4, h - 2 * pad)  # 所有格子等高
        for i in range(_BUCKETS):
            x = int(i * (cw + _BAR_GAP))
            p.fillRect(x, pad, max(1, int(cw)), bh, QColor(self._colors[i]))
        p.end()


class OverviewPage(QWidget):
    """③ 总览台：3 列 × 2 行六张卡。refresh() 由主窗切到本页时调用。"""

    def __init__(
        self, on_navigate: Callable[[int], None], parent: Optional[QWidget] = None
    ) -> None:
        super().__init__(parent)
        self._on_navigate = on_navigate
        # 空串 = 防火墙状态还没由主窗推送过来，界面显示「检测中…」。
        self._fw_verdict = ""

        outer = QVBoxLayout(self)
        outer.setContentsMargins(24, 18, 24, 20)
        outer.setSpacing(14)

        head = QLabel("总览台 · 端口访问防御")
        head.setObjectName("page_title")
        outer.addWidget(head)
        sub = QLabel("一眼看清当前防护状态与待办，点「查看」下钻到对应页面。")
        sub.setObjectName("hint")
        outer.addWidget(sub)

        self._barstrip = BarStripWidget()

        grid = QGridLayout()
        grid.setSpacing(16)
        grid.setContentsMargins(0, 0, 0, 0)
        for col in range(3):
            grid.setColumnStretch(col, 1)
        for row in range(2):
            grid.setRowStretch(row, 1)

        specs = [
            ("traffic", "实时流", PAGE_MONITOR, "今日总访问数 / 风险数", "正在刷新…"),
            ("todo", "风险待办", PAGE_EVENTS, "当前未处理风险事件数", "正在刷新…"),
            ("protection", "防护状态", PAGE_SETTINGS, "防火墙 / 本机观察 / 权限", "正在刷新…"),
            ("bans", "封禁概览", PAGE_BANS, "当前生效封禁数 / 已到期数", "正在刷新…"),
            ("rules", "规则引擎", PAGE_RULES, "启用规则条数", "正在刷新…"),
            ("system", "系统与离线库", PAGE_SETTINGS, "离线 xdb 版本 / 加载状态", "正在刷新…"),
        ]
        self._refs: Dict[str, Tuple[QLabel, QLabel, QLabel]] = {}
        self._detail_refs: Dict[str, QLabel] = {}
        for i, (key, title, target, note, foot) in enumerate(specs):
            extra = self._barstrip if key == "traffic" else None
            card, num, note_lbl, foot_lbl = self._make_card(key, title, target, note, foot, extra)
            grid.addWidget(card, i // 3, i % 3)
            self._refs[key] = (num, note_lbl, foot_lbl)

        outer.addLayout(grid, 1)

    def _make_card(
        self,
        key: str,
        title: str,
        target: int,
        note: str,
        foot: str,
        extra: Optional[QWidget],
    ) -> Tuple[QFrame, QLabel, QLabel, QLabel]:
        card = QFrame()
        card.setObjectName("panel")
        card.setMinimumSize(340, 250)
        lay = QVBoxLayout(card)
        lay.setContentsMargins(20, 12, 20, 14)
        lay.setSpacing(8)

        # 顶部一条主色细条 + 标题前的小锚点：六张卡长得一样，靠这两笔把
        # 「卡片」和「卡片里的层级」分开，不需要引入图标字体或 emoji。
        accent = QFrame()
        accent.setObjectName("overview_accent")
        accent.setFixedHeight(3)
        lay.addWidget(accent)

        head_row = QHBoxLayout()
        head_row.setSpacing(8)
        dot = QFrame()
        dot.setObjectName("overview_dot")
        dot.setFixedSize(8, 8)
        head_row.addWidget(dot, 0, Qt.AlignmentFlag.AlignVCenter)
        t = QLabel(title)
        t.setObjectName("overview_card_title")
        head_row.addWidget(t, 0, Qt.AlignmentFlag.AlignVCenter)
        head_row.addStretch(1)
        lay.addLayout(head_row)

        num = QLabel("—")
        num.setObjectName("card_number")
        lay.addWidget(num)

        note_lbl = QLabel(note)
        note_lbl.setObjectName("hint")
        note_lbl.setWordWrap(True)
        lay.addWidget(note_lbl)

        if extra is not None:
            lay.addWidget(extra)

        detail = QLabel("")
        detail.setObjectName("card_detail")
        detail.setWordWrap(True)
        lay.addWidget(detail)
        self._detail_refs[key] = detail

        lay.addStretch(1)

        foot_lbl = QLabel(foot)
        foot_lbl.setObjectName("overview_card_foot")
        foot_lbl.setWordWrap(True)
        lay.addWidget(foot_lbl)

        btn = QPushButton("查看 →")
        btn.setObjectName("overview_link")
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.clicked.connect(_make_slot(self._on_navigate, target))
        lay.addWidget(btn, 0, Qt.AlignmentFlag.AlignRight)

        return card, num, note_lbl, foot_lbl

    def _set_detail(self, key: str, text: str) -> None:
        lbl = self._detail_refs.get(key)
        if lbl is not None:
            lbl.setText(text)

    # ── 数据（只读；任何查询失败都降级为「— 占位」并在脚注写明原因）──

    @staticmethod
    def _fail(num: QLabel, note: QLabel, foot: QLabel, label: str, exc: Exception) -> None:
        # 真实异常（可能含数据源路径、SQL 与调用栈）仅用于排障，不进界面脚注；
        # 保留 exc 形参以维持各 refresh 分支的降级调用结构不变。
        num.setText("—")
        note.setText(f"{label}数据暂不可用")
        foot.setText(f"{label}数据源暂不可用：后台读取失败，请稍后切回本页重试")

    @staticmethod
    def _today_start_ms() -> int:
        today = datetime.date.today()
        return int(datetime.datetime(today.year, today.month, today.day).timestamp() * 1000)

    def set_fw_state(self, verdict: str) -> None:
        """由主窗 fw_state_ready 信号推来防火墙结论。

        profiles_state() 起 netsh/PowerShell 子进程，主窗已在后台线程读完并
        经 fw_state_ready 回主线程；这里只接收结论，绝不在 UI 线程同步重读。
        """
        self._fw_verdict = verdict
        if self._refs:
            self._refresh_protection()

    def refresh(self) -> None:
        """切到总览时由主窗调用：一次 stats_snapshot 供 ①②④，其余各自只读。

        构造期不做重活；24 格明细是切页时的低频单独查询。
        """
        for key in self._detail_refs:
            self._set_detail(key, "")
        try:
            from core.database import stats_snapshot

            snap = stats_snapshot(include_today=True)
        except Exception:
            snap = {}
        self._refresh_traffic(snap)
        self._refresh_todo(snap)
        self._refresh_protection()
        self._refresh_bans(snap)
        self._refresh_rules()
        self._refresh_system()

    def _refresh_traffic(self, snap: Dict[str, int]) -> None:
        # 数据源：主数字与今日风险取自 core.database.stats_snapshot(include_today=True)；
        # 24 格明细另取 core.database.query_access_logs，仅判各小时最高风险等级。
        num, note, foot = self._refs["traffic"]
        try:
            from core.config import LEVEL_NORMAL, LEVEL_ORDER
            from core.database import query_access_logs

            total = int(snap["today_total"])
            risk = int(snap["today_risk"])
            num.setText(f"{total}")
            note.setText(f"今日风险 {risk} 条 · 今日总访问 {total} 条")

            # 24 格明细单独低频取：颜色只看该小时最高风险等级，不表达访问量。
            rows = query_access_logs(limit=_BAR_LIMIT, since_ts=self._today_start_ms())
            levels = [LEVEL_NORMAL] * _BUCKETS
            counts = [0] * _BUCKETS
            for rec in rows:
                hour = datetime.datetime.fromtimestamp(rec.event_ts / 1000.0).hour
                if 0 <= hour < _BUCKETS:
                    counts[hour] += 1
                    lv = rec.risk_level or LEVEL_NORMAL
                    if LEVEL_ORDER.get(lv, 0) > LEVEL_ORDER.get(levels[hour], 0):
                        levels[hour] = lv
            self._barstrip.set_data(levels, counts)
            if self._barstrip.anomaly:
                foot.setText(
                    "⚠ 24 格风险数据异常密集（红格 >3 或连续 ≥4），请复核事件数据 · "
                    "数据来自今日统计快照 · 点击查看实时监控"
                )
            else:
                foot.setText(
                    "数据来自今日统计快照 · 色块为今日各时段最高风险等级 · 点击查看实时监控"
                )
            pct = risk * 100.0 / total if total else 0.0
            severe = sum(1 for lv in levels if lv in ("high", "critical"))
            self._set_detail("traffic", f"今日风险占比：{pct:.1f}%\n高风险时段：{severe} / 24 格")
        except Exception as exc:
            self._fail(num, note, foot, "实时流", exc)

    def _refresh_todo(self, snap: Dict[str, int]) -> None:
        # 数据源：stats_snapshot 的 pending（未处理 - 规则自动拦截）。
        # 自动拦截的事件已经写进防火墙生效，混进「风险待办」会把 3 万条已处置
        # 记录显示成待办；明细行单独报出自动拦截数，用来校验规则有没有在拦。
        num, note, foot = self._refs["todo"]
        try:
            n = int(snap.get("pending", snap.get("unhandled", 0)))
            auto_blocked = int(snap.get("auto_blocked", 0))
            num.setText(f"{n}")
            note.setText("当前待人工处理的风险事件")
            foot.setText("统计口径：未处理且未被规则自动拦截 · 点击查看风险事件")
            # 「待确认封禁建议」为 0 时整行不显示：自动拦截过的重复 IP 事件已经
            # 不再计入建议，挂一行 0 只会让用户以为还有东西没处理、点进去又是空的。
            detail = f"规则已自动拦截：{auto_blocked} 条"
            sug = int(snap.get("suggestions", 0))
            if sug:
                detail += f"\n待确认封禁建议：{sug} 条"
            self._set_detail("todo", detail)
        except Exception as exc:
            self._fail(num, note, foot, "风险待办", exc)

    def _refresh_protection(self) -> None:
        # 数据源：防火墙结论为主窗 fw_state_ready 推来的 core.firewall.state_verdict；
        # 本机观察 core.port_watcher.get_watcher().running（property）；权限 core.firewall.is_admin()。
        num, note, foot = self._refs["protection"]
        try:
            from core import firewall, port_watcher

            verdict = self._fw_verdict
            fw_txt = {
                firewall.STATE_OK: "过滤中",
                firewall.STATE_PARTIAL: "部分开启",
                firewall.STATE_OFF: "未开启",
                firewall.STATE_UNKNOWN: "未知",
            }.get(verdict, "检测中…")
            watching = port_watcher.get_watcher().running  # running 是 @property
            admin = firewall.is_admin()
            # 权限不参与健康分：v1.9.5 起普通权限是默认形态，若仍算扣分项，
            # 每个观察模式客户都会看到「2/3」并误判防护没生效。
            checks = (verdict == firewall.STATE_OK, watching)
            ok = sum(1 for v in checks if v)
            num.setText(f"{ok}/2")
            mode = "管理员（可封禁）" if admin else "观察模式（只读）"
            note.setText(
                f"防火墙 {fw_txt} · 本机观察 {'运行中' if watching else '未启动'} · {mode}"
            )
            foot.setText(
                "健康分只看防火墙与本机观察 · 权限是运行模式说明，不参与评分 · "
                "未知状态不判为关闭 · 点击查看设置"
            )
            st = port_watcher.get_watcher().stats()
            self._set_detail(
                "protection",
                "观察端口：{} 个\n自动封禁：{}".format(
                    len(st.get("ports", []) or []), "开" if st.get("allow_auto_ban") else "关"
                ),
            )
        except Exception as exc:
            self._fail(num, note, foot, "防护状态", exc)

    def _refresh_bans(self, snap: Dict[str, int]) -> None:
        # 数据源：主数字 core.database.stats_snapshot(include_today=True)["active_bans"]；
        # 已到期未解封数 app.ban_service.expired_backlog()。
        num, note, foot = self._refs["bans"]
        try:
            from app.ban_service import expired_backlog
            from core.database import sum_ban_hits

            n = int(snap["active_bans"])
            expired = expired_backlog()
            num.setText(f"{n}")
            note.setText(f"当前生效封禁 {n} 条 · 已到期未解封 {expired} 条")
            foot.setText("统计口径：当前生效且未到期的封禁 · 含已到期未解封提示 · 点击查看封禁管理")
            hits = sum_ban_hits()
            backlog = expired * 100.0 / (n + expired) if (n + expired) else 0.0
            self._set_detail("bans", f"生效累计拦截：{hits} 次\n到期积压占比：{backlog:.1f}%")
        except Exception as exc:
            self._fail(num, note, foot, "封禁概览", exc)

    def _refresh_rules(self) -> None:
        # 数据源：core.rule_engine.get_engine().get_config()["rules"]，
        # 口径同规则配置页，统计启用条数时排除 blacklist。
        num, note, foot = self._refs["rules"]
        try:
            from core.rule_engine import get_engine

            rules = get_engine().get_config().get("rules", {})
            enabled = sum(
                1
                for rid, body in rules.items()
                if rid != "blacklist" and isinstance(body, dict) and body.get("enabled")
            )
            num.setText(f"{enabled}")
            note.setText(f"共 {len(rules)} 条引擎规则，其中 {enabled} 条启用")
            foot.setText("统计口径：当前启用的引擎规则（与规则配置页一致）· 点击查看规则配置")
            region_n = len(get_engine().region_rules())
            scope = sum(1 for rid in rules if rid != "blacklist")
            disabled = max(0, scope - enabled)
            self._set_detail("rules", f"区域规则：{region_n} 条\n未启用：{disabled} 条")
        except Exception as exc:
            self._fail(num, note, foot, "规则引擎", exc)

    def _refresh_system(self) -> None:
        # 数据源：版本 core.config.APP_VERSION；离线库状态 core.xdb_updater.status_summary()。
        num, note, foot = self._refs["system"]
        try:
            from core import xdb_updater
            from core.config import APP_VERSION

            s = xdb_updater.status_summary()
            files = s.get("files", {})
            ready = sum(1 for d in files.values() if d.get("exists"))
            n_files = len(files) or 2  # XDB_UPSTREAM 至少 v4/v6 两份
            auto = "开" if s.get("auto_sync") else "关"
            # 主数字保持「统计值」语气（与其余五卡一致）：就绪的离线库文件数；
            # 版本号属于标识属性，改放进明细行，不放主数字区（见 04_ui_review Q3）。
            num.setText(f"{ready}/{n_files}")
            note.setText(f"离线 IP 库就绪 {ready}/{n_files} 个文件 · 自动同步{auto}")
            foot.setText("点击查看离线库更新 · 版本 v" + APP_VERSION)
            last = int(s.get("last_update_at", 0) or 0)
            last_txt = (
                datetime.datetime.fromtimestamp(last / 1000.0).strftime("%m-%d %H:%M")
                if last > 0
                else "从未同步"
            )
            self._set_detail(
                "system",
                "上次同步：{}\n自动下载：{} · 版本 v{}".format(
                    last_txt, "开" if s.get("auto_download") else "关", APP_VERSION
                ),
            )
        except Exception as exc:
            self._fail(num, note, foot, "系统与离线库", exc)
