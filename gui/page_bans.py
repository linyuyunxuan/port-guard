"""PortGuard — 封禁管理页"""

import datetime
import threading
import time
from typing import Any, Dict, Optional

from app import audit, ban_service
from app.export_csv import BAN_CSV_HEADERS, SUG_CSV_HEADERS, iter_ban_rows, iter_sug_rows
from core import firewall
from core import settings as cfg
from core.config import LEVEL_CRITICAL, LEVEL_HIGH, LEVEL_ORDER
from core.database import (
    active_ban_ip_map,
    count_active_bans,
    delete_ban_records,
    query_bans,
    query_risk_events,
    set_risk_handled,
    set_risk_handled_batch,
    sum_ban_hits,
)
from core.logger import get_logger
from core.models import (
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_PENDING,
    STATUS_UNBANNED,
    ms_to_str,
)
from core.validators import InvalidIP, normalize_ip
from gui.background import BusyGuard, run_in_background
from gui.components import PageHeader, build_menu, export_table_csv
from gui.event_detail import EventDetailDialog
from gui.event_group import flatten_rows, merge_rows
from gui.row_action import RowAction, RowActionDelegate
from gui.table_select import CheckColumn
from gui.table_sort import (
    KIND_DATETIME,
    KIND_MS,
    KIND_NUM,
    KIND_TEXT,
    ColumnSpec,
    SortSpec,
    TableSort,
)
from gui.theme import C, small_button_style
from gui.widgets import (
    CheckMarkDelegate,
    EmptyState,
    RefreshGuard,
    RiskBadgeDelegate,
    SortHeader,
    WarnBanner,
    align_headers,
    badge_item,
    make_item,
)
from qtcompat import (
    QAbstractItemView,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QSplitter,
    Qt,
    QTableWidget,
    QTimer,
    QVBoxLayout,
    QWidget,
    Signal,
)

log = get_logger(__name__)

BAN_HEADERS = [
    "",
    "IP",
    "原因",
    "归属地",
    "来源",
    "评分",
    "状态",
    "到期时间",
    "创建时间",
    "操作",
]
SUG_HEADERS = ["", "时间", "等级", "IP", "归属地", "端口", "评分", "原因", "操作"]

# 第 0 列都是勾选框（32px）。列宽按「实测文字 + 16 padding + 6 余量」定，
# 两栈取大的那套（PySide2 的 YaHei / Consolas 度量比 PySide6 宽 6~20%）。
#
# 2026-10-27 重排（实测数据见 _design/_measure_ban_cols.py）：
#   · IP  124→136：`182.118.236.126` 实测 105px，124 的列只剩 108 可用，
#     渲染成 `182.118.236…` —— IP 是这张表的判断依据，看不全等于没封对人。
#   · 到期/创建 124→136：`2026-10-20 09:27` 实测 112px，124 会裁成 `09…`，
#     「哪天到期」只能去猜。
#   · 归属地 122 保持不动：压到 110 时真机渲染成 `河南省 洛阳…`（实测 76px
#     的文本在 Qt item 内边距下仍被裁），腾空间不能拿它开刀。
#   · 操作 100→96、状态 84→88（「已封禁 ×128」实测 86）、评分 42→46。
#   · **删掉「ID」列（48px）**：它是数据库主键，不是用户概念 —— 既不参与搜索
#     （搜索框只搜 IP / 原因），也不会被口头引用。48px 换回「IP 与时序可读」，
#     记录号改挂在 IP 单元格的 tooltip 里，信息没丢，只是不再占位。
# 固定列合计 1089，原因列（唯一 Stretch）吃掉剩余的 248（下限 240）。
BAN_WIDTHS = [33, 136, 240, 122, 56, 46, 88, 136, 136, 96]

#: 防火墙开关状态的刷新间隔（秒）。netsh 一次 100~300ms，只在后台探测，
#: 缓存期间页面刷新直接复用上一次结论（见 _probe_fw_state）
FW_PROBE_SEC = 20.0

SUG_WIDTHS = [37, 138, 69, 150, 122, 64, 53, 184, 129]
COL_SUG_CHECK = 0
COL_SUG_LEVEL = 2
COL_SUG_REASON = 7
COL_SUG_ACTION = 8
COL_BAN_CHECK = 0
COL_BAN_REASON = 2
COL_BAN_GEO = 3
COL_BAN_SOURCE = 4
COL_BAN_SCORE = 5
COL_BAN_STATUS = 6
COL_BAN_EXPIRE = 7
COL_BAN_CREATED = 8
COL_BAN_ACTION = 9

# 列排序规则（数据层，见 gui/table_sort.py 开头为什么不用 setSortingEnabled）。
# 两张表各一套：都不给勾选列（点了是全选）与操作列（无值）建规则。
# 等级按严重度（LEVEL_ORDER）而不是中文笔画；封禁状态按「已封禁 → 处理中 →
# 失败 → 已解封」的业务序，按本地化文本排会把它排成无意义的顺序。
SUG_SORT_SPECS = {
    1: ColumnSpec(KIND_MS, lambda r: r.get("event_ts")),
    COL_SUG_LEVEL: ColumnSpec(KIND_NUM, lambda r: LEVEL_ORDER.get(str(r.get("risk_level") or ""))),
    3: ColumnSpec(KIND_TEXT, lambda r: r.get("ip")),
    4: ColumnSpec(KIND_TEXT, lambda r: r.get("geo").region_short if r.get("geo") else ""),
    5: ColumnSpec(KIND_NUM, lambda r: r.get("local_port")),
    6: ColumnSpec(KIND_NUM, lambda r: r.get("risk_score")),
    COL_SUG_REASON: ColumnSpec(KIND_TEXT, lambda r: r.get("summary")),
}

#: 「已封禁」最需要先看到，所以它的序号最小
BAN_STATUS_ORDER = {
    STATUS_ACTIVE: 0,
    STATUS_PENDING: 1,
    STATUS_FAILED: 2,
    STATUS_EXPIRED: 3,
    STATUS_UNBANNED: 4,
}

BAN_SORT_SPECS = {
    1: ColumnSpec(KIND_TEXT, lambda b: b.ip),
    COL_BAN_REASON: ColumnSpec(KIND_TEXT, lambda b: b.reason),
    # 归属地按 `region_short` 文本排（与单元格显示的是同一串字）：
    # 按 geo 对象排就得在排序层认识 GeoInfo，而排序层只该处理「显示的文本」。
    COL_BAN_GEO: ColumnSpec(
        KIND_TEXT,
        lambda b: b.geo.region_short if b.geo else "",
    ),
    COL_BAN_SOURCE: ColumnSpec(KIND_TEXT, lambda b: b.source_label),
    COL_BAN_SCORE: ColumnSpec(KIND_NUM, lambda b: b.risk_score),
    COL_BAN_STATUS: ColumnSpec(KIND_NUM, lambda b: BAN_STATUS_ORDER.get(b.status)),
    COL_BAN_EXPIRE: ColumnSpec(KIND_MS, lambda b: b.expire_at),
    COL_BAN_CREATED: ColumnSpec(KIND_DATETIME, lambda b: b.created_at),
}


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
        # 默认取「默认封禁时长」设置（原来硬编码 60 分钟：用户在设置页改过默认值，
        # 这里仍然显示 1 小时，两边对不上）。0 在设置里表示永久，直接映射成「永久」。
        self.duration.setValue(max(0, cfg.get_int("default_ban_duration_sec", 3600) // 60))
        self.duration.setSuffix(" 分钟（0=永久）")
        self.duration.setSpecialValueText("永久")

        form.addRow("IP 地址", self.ip)
        form.addRow("封禁原因", self.reason)
        form.addRow("封禁时长", self.duration)

        tip = QLabel("提示：内网、回环与保留地址会被自动拒绝封禁。")
        tip.setStyleSheet(f"color:{C.text_muted};font-size:13.5px;")
        form.addRow(tip)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
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
            QMessageBox.warning(
                self, "IP 格式错误", f"{e}\n\n请输入形如 203.0.113.10 或 2408:8000::1 的地址。"
            )
            self.ip.setFocus()
            self.ip.selectAll()
            return
        super().accept()

    def values(self):
        mins = self.duration.value()
        return (
            self.ip.text().strip(),
            self.reason.text().strip() or "手动封禁",
            0 if mins == 0 else mins * 60,
        )


class BansPage(QWidget):
    """封禁建议 + 封禁列表（两张表都支持勾选批量处理）"""

    ask_ban = Signal(str, int, str)
    # [(ip, score, reason, event_ids), ...] —— 批量确认封禁交给主窗口统一执行
    ask_ban_many = Signal(list)
    ask_lookup = Signal(str)
    request_refresh_stats = Signal()
    # 批量解封在后台线程跑，结束后把结果送回 GUI 线程
    batch_unban_done = Signal(int, int)  # (成功数, 失败数)
    # 「安全启用防火墙 + 对齐封禁」在后台线程跑，结束后把摘要送回 GUI 线程
    firewall_ready = Signal(object)

    # 显式声明：勾选列在两个面板里各建一次，且建在按钮之后
    sug_sel: CheckColumn
    ban_sel: CheckColumn

    def __init__(self, parent=None):
        super().__init__(parent)
        # *_rows 是当前**显示顺序**（点表头后会被重排），行号 == 数据下标；
        # *_src 是后端返回的原序，只用于「取消排序」时还原
        self._sug_rows = []
        self._sug_rows_src = []
        self._ban_rows = []
        self._ban_rows_src = []
        # 生效中的封禁（IP → 记录），建议表按钮据此显示「已封禁」
        self._banned: Dict[str, Any] = {}
        self.sug_sort = TableSort(SUG_SORT_SPECS)
        self.ban_sort = TableSort(BAN_SORT_SPECS)
        # 到期但解不掉的条数（普通权限下由主窗口巡检回报），供权限条展示
        self._expired_backlog = 0
        # 会起 netsh 进程的动作一律后台跑，用忙标记避免重复点击起第二个进程
        self._busy = BusyGuard()
        # 防火墙开关状态的缓存：netsh 要 100~300ms，不能每次刷新页面都问一次。
        # None = 还没探测过（**读不出就当未知，绝不判成「已关闭」**）。
        self._fw_enabled: Optional[bool] = None
        self._fw_profiles: Optional[Dict[str, bool]] = None
        self._fw_probe_at = 0.0
        self._build()
        self.batch_unban_done.connect(self._on_batch_unban_done)
        self.firewall_ready.connect(self._on_firewall_ready)
        self.refresh()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 16, 24, 12)
        root.setSpacing(12)

        head = PageHeader("封禁管理", "规则引擎给出建议，确认后才写入 Windows 防火墙")
        root.addWidget(head)

        # 权限警示条（仅普通权限时出现）
        self.banner = WarnBanner("", "以管理员身份重启", C.warning)
        self.banner.action_clicked.connect(self._restart_as_admin)
        root.addWidget(self.banner)
        self._refresh_perm_banner()

        # 防火墙开关警示条（防火墙关闭时出现 —— 关闭时所有封禁规则都不生效）
        self.fw_banner = WarnBanner("", "安全启用防火墙", C.danger)
        self.fw_banner.action_clicked.connect(self._enable_firewall)
        root.addWidget(self.fw_banner)
        self._refresh_fw_banner()

        # 结果区：上「待确认建议」/ 下「封禁记录」，可拖拽分配高度
        self.split = QSplitter(Qt.Orientation.Vertical)
        self.split.setChildrenCollapsible(False)
        self.split.addWidget(self._build_sug_panel())
        self.split.addWidget(self._build_records_area())
        self.split.setStretchFactor(0, 0)
        self.split.setStretchFactor(1, 1)
        # 初始 264 = 面板开销 94（卡头 46 + 表头 44 + 边 4）+ 5 行 × 34；
        # 拖完再吸附到整数行（见 _snap_sug_rows），否则 268 这种高度会让表格
        # 底部露出 4px 的下一行 —— 看起来像半行被切掉。
        self.split.setSizes([264, 390])
        self.split.splitterMoved.connect(lambda *_: self._snap_sug_rows())
        root.addWidget(self.split, 1)

    # ══════════ 建议区高度：吸附到整数行 ══════════

    def _sug_chrome(self) -> int:
        """建议面板里除表格可视区以外的固定开销（卡头 + 表头 + 边框）。

        不用写死 94：卡头高度随字体走，两栈（雅黑 9pt / PySide2 度量偏大）
        差两三个像素就够让吸附算错。布局没完成时返回 0，调用方据此跳过。
        """
        lay = self.sug_panel.layout()
        item = lay.itemAt(0) if lay is not None else None
        head = item.geometry().height() if item is not None else 0
        return head + self.sug_table.horizontalHeader().height() + 4

    def _snap_sug_rows(self) -> None:
        """把建议面板高度对齐到「开销 + 整数行」。

        拖分隔条时用户只想要「多看几行」，结果露半行反而显得界面没对齐。
        只在可视化状态下做（空态折叠时表格是隐藏的，行高无意义）。
        """
        if not self.sug_table.isVisible():
            return
        row = self.sug_table.verticalHeader().defaultSectionSize()
        chrome = self._sug_chrome()
        if row <= 0 or chrome <= row:
            return
        rows = max(1, round((self.sug_panel.height() - chrome) / row))
        target = chrome + rows * row
        sizes = self.split.sizes()
        delta = target - self.sug_panel.height()
        if delta == 0 or sizes[1] - delta < 120:
            return
        self.split.setSizes([target, sizes[1] - delta])

    def _fit_sug_hint(self) -> None:
        """卡头宽度够就显示说明，不够就收起来。

        卡头一行要装「标题 + 说明 + 已选 + 4 个按钮」，sizeHint 实测 655px。
        说明是补充信息（页头已经有一句同样的解释），按钮是操作入口 ——
        挤的时候先牺牲说明。阈值按**页面**宽算（= 窗口宽 - 侧栏，1360 窗口下
        约 1166），留 240px 余量给按钮在不同字体下的膨胀。
        """
        self.sug_hint.setVisible(self.width() >= 900)

    def showEvent(self, event) -> None:
        super().showEvent(event)
        # 首次显示时卡头还没几何，等这一轮布局跑完再吸附
        self._fit_sug_hint()
        QTimer.singleShot(0, self._snap_sug_rows)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        self._fit_sug_hint()

    def _refresh_perm_banner(self) -> None:
        """
        普通权限时的常驻提示。

        除了「封禁不会生效」，还带上「有 N 条已到期但解不掉」—— 到期巡检要管理员
        权限，没权限时它什么都做不了。不在这里说清楚，用户会以为封禁到期自动消失。
        """
        if firewall.is_admin():
            self.banner.setVisible(False)
            return
        text = (
            "当前以普通权限运行，无法修改 Windows 防火墙。"
            "监控与规则判定正常，但「确认封禁」不会生效。"
        )
        if self._expired_backlog > 0:
            text += (
                f"另有 {self._expired_backlog} 条封禁已到期，需管理员权限才能删除对应"
                "防火墙规则 —— 这些规则仍在生效。"
            )
        self.banner.set_text(text)
        self.banner.setVisible(True)

    def set_expired_backlog(self, n: int) -> None:
        """由主窗口的到期巡检回报「到期但解不掉」的条数（普通权限下才有值）"""
        n = max(0, int(n or 0))
        if n == self._expired_backlog:
            return
        self._expired_backlog = n
        self._refresh_perm_banner()

    def _refresh_fw_banner(self) -> None:
        """
        Windows 防火墙关闭时的常驻红条。

        为什么单独一条、而且用 danger：防火墙关闭时**所有封禁规则都不参与过滤**，
        界面却照样显示「已封禁」—— 用户以为封住了，实际一个包都没挡住。真机复现过：
        规则 Enabled / Inbound / Block / RemoteAddress 全对，创建 24 分钟后攻击者
        仍然能建连。所以这条提示是「已封禁」三个字成立的前提，不能藏起来。

        **状态值走缓存，探测放后台**：`netsh advfirewall show allprofiles state`
        要 100~300ms，而本页每次刷新（封禁事件、批量操作后）都会调用到这里 ——
        放在界面线程里就是每刷一次卡一下。缓存过期后由后台线程补一次探测，
        回来再重画；探测失败保持原值，绝不当成「已关闭」。
        """
        if not firewall.is_admin():
            self.fw_banner.setVisible(False)
            return
        self._probe_fw_state()
        self._render_fw_banner()

    def _render_fw_banner(self) -> None:
        enabled = self._fw_enabled
        if enabled is not False:
            # True = 开着；None = 读不出来。读不出来不能当成关闭去吓人。
            self.fw_banner.setVisible(False)
            return
        self.fw_banner.set_text(
            "Windows 防火墙处于关闭状态（"
            + firewall.format_profiles(self._fw_profiles)
            + "）：规则写得再对也不会拦截任何流量，当前所有封禁都未生效。"
            "点右侧按钮会先为「此刻正在监听」的端口建放行规则、再开启防火墙，"
            "避免把正在用的服务挡在外面。"
        )
        self.fw_banner.setVisible(True)

    def _probe_fw_state(self) -> None:
        """后台探测防火墙开关（节流 FW_PROBE_SEC），结果回主线程重画横幅"""
        if not self._busy.enter("fw-probe"):
            return
        if time.monotonic() - self._fw_probe_at < FW_PROBE_SEC:
            self._busy.leave("fw-probe")
            return
        self._fw_probe_at = time.monotonic()

        def work() -> Dict[str, Any]:
            # force=True：用户可能刚点了「启用防火墙」，5 秒缓存会让他看到旧结论
            state = firewall.profiles_state(force=True)
            return {"enabled": None if state is None else any(state.values()), "profiles": state}

        run_in_background(
            self, work, self._on_fw_state, self._on_fw_state_failed, name="fw-banner-probe"
        )

    def _on_fw_state(self, res: Dict[str, Any]) -> None:
        self._busy.leave("fw-probe")
        self._fw_enabled = res.get("enabled")
        self._fw_profiles = res.get("profiles")
        self._render_fw_banner()

    def _on_fw_state_failed(self, err: str) -> None:
        self._busy.leave("fw-probe")
        log.debug("读取防火墙开关状态失败（保持上一次结论）：%s", err)

    def _enable_firewall(self) -> None:
        """安全启用防火墙：先放行现有监听端口，再开总开关，最后对齐封禁（后台线程）"""
        if not firewall.is_admin():
            QMessageBox.warning(
                self, "权限不足", "修改防火墙需要管理员权限，请以管理员身份重启程序。"
            )
            return
        if (
            QMessageBox.question(
                self,
                "安全启用 Windows 防火墙",
                "将执行以下操作：\n\n"
                "1. 读取本机当前正在监听的 TCP / UDP 端口\n"
                "2. 为这些端口建立放行规则（PortGuard_Allow_*）\n"
                "3. 打开 Windows 防火墙（域 / 专用 / 公用）\n"
                "4. 重新对齐封禁记录（补建缺失规则、清理历史重复规则）\n\n"
                "放行范围是「此刻正在监听」的快照，之后新起的服务需要再点一次本按钮。\n"
                "确认继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return

        if self.fw_banner.btn is not None:
            self.fw_banner.btn.setEnabled(False)
        self.fw_banner.set_text("正在启用防火墙并放行现有监听端口，请稍候…")

        def work():
            ok, err, detail = firewall.enable_firewall()
            res: Dict[str, Any] = {"ok": ok, "error": err, "detail": detail}
            if ok:
                # 开关打开后立刻对齐：库里 failed 的记录多半就是「当时防火墙没开」
                res["reenforce"] = ban_service.reenforce_all()
            self.firewall_ready.emit(res)

        threading.Thread(target=work, daemon=True, name="enable-firewall").start()

    def _on_firewall_ready(self, res: Dict[str, Any]) -> None:
        if self.fw_banner.btn is not None:
            self.fw_banner.btn.setEnabled(True)
        self._refresh_fw_banner()
        if not res.get("ok"):
            QMessageBox.warning(self, "启用防火墙失败", str(res.get("error") or "未知错误"))
            return
        detail = res.get("detail") or {}
        allowed = len(detail.get("created") or [])
        lines = [f"防火墙已启用，本次新放行 {allowed} 个监听端口。"]
        tcp = [str(p) for p in (detail.get("tcp") or [])]
        udp = [str(p) for p in (detail.get("udp") or [])]
        if tcp:
            lines.append("放行 TCP: " + ", ".join(tcp[:20]) + (" …" if len(tcp) > 20 else ""))
        if udp:
            lines.append("放行 UDP: " + ", ".join(udp[:20]) + (" …" if len(udp) > 20 else ""))
        lines.append("封禁对齐：" + ban_service.format_reenforce(res.get("reenforce") or {}))
        self.refresh()
        self.request_refresh_stats.emit()
        QMessageBox.information(self, "防火墙已启用", "\n".join(lines))

    @staticmethod
    def _setup_table(table: QTableWidget) -> None:
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setAlternatingRowColors(True)
        table.setShowGrid(False)
        table.setWordWrap(False)
        table.setTabKeyNavigation(False)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(34)
        # 常显竖滚动条：滚动条出现/消失会让可视宽在 15↔25px 之间跳，列宽跟着抖
        table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOn)

    def _build_sug_panel(self) -> QFrame:
        """待确认建议：有数据时 216 高，0 条时折叠成 56 的一行提示"""
        self.sug_panel = QFrame()
        self.sug_panel.setObjectName("panel")
        lay = QVBoxLayout(self.sug_panel)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        head = QHBoxLayout()
        head.setContentsMargins(16, 12, 16, 8)
        head.setSpacing(8)
        self.sug_title = QLabel("待确认的封禁建议")
        self.sug_title.setObjectName("panel_title")
        self.sug_hint = QLabel("规则引擎建议，需人工确认")
        self.sug_hint.setStyleSheet(f"color:{C.text_muted};font-size:12.5px;")
        # 卡头一行要装「标题 + 本条说明 + 已选 + 4 个按钮」。说明是可有可无的
        # （页头已经有一句同样的解释），所以让它做唯一可压缩项：Ignored 策略下
        # 先压它，不会把按钮挤到换行；真的放不下时由 resizeEvent 直接收起来。
        self.sug_hint.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        self.sug_hint.setToolTip("规则引擎建议，需人工确认")
        head.addWidget(self.sug_title)
        head.addWidget(self.sug_hint)
        head.addStretch(1)

        # 批量操作放在面板标题行里：不额外占高度，上下面板的高度预算不用重算
        self.lbl_sug_sel = QLabel("已选 0 条")
        self.lbl_sug_sel.setStyleSheet(f"color:{C.text_muted};font-size:12.5px;")
        self.btn_sug_all = self._mini_button("全选", enabled=True)
        # 「封禁选中」= 勾了才可用；「全部封禁」= 一键封禁当前列表全部（用户
        # 2026-10-27 要求直接显示）。两个都叫「批量封禁」时分不清谁需要先勾选，
        # 所以文案按「操作对象」命名。
        self.btn_sug_ban = self._mini_button("封禁选中", "danger")
        self.btn_sug_ban.setToolTip("封禁已勾选的建议（先勾选，或在行上双击）")
        self.btn_sug_ignore = self._mini_button("忽略选中")
        self.btn_sug_ignore.setToolTip("把已勾选的事件标记为已忽略，不再出现在本页")
        # 建议面板没有独立的批量条，导出放标题行末尾：既不额外占高度，
        # 也与「忽略选中」同属「对这批建议整体做点什么」
        self.btn_sug_export = self._mini_button("导出 CSV", enabled=True)
        self.btn_sug_export.setToolTip("导出当前待确认建议，不受勾选影响")
        # 全部封禁放在最右：它一次动全部 IP，离「勾选 → 封禁选中」这条常用路径
        # 远一点，滑手误点的机会就少一点（且仍然有批量确认对话框兜底）
        self.btn_sug_ban_all = self._mini_button("全部封禁", "danger")
        self.btn_sug_ban_all.setToolTip("一键封禁当前列表里的全部建议 IP（会先弹确认与时长选择）")
        # 勾选列建在表格之后，lambda 延迟取值（不能提前绑定方法）
        self.btn_sug_all.clicked.connect(lambda: self.sug_sel.toggle_all())  # noqa: PLW0108
        self.btn_sug_ban.clicked.connect(self._batch_ban_suggestions)
        self.btn_sug_ignore.clicked.connect(self._batch_ignore_suggestions)
        self.btn_sug_export.clicked.connect(self._export_sug_csv)
        self.btn_sug_ban_all.clicked.connect(self._ban_all_suggestions)
        for w in (
            self.lbl_sug_sel,
            self.btn_sug_all,
            self.btn_sug_ban,
            self.btn_sug_ignore,
            self.btn_sug_export,
            self.btn_sug_ban_all,
        ):
            head.addWidget(w)
        lay.addLayout(head)

        self.sug_empty = QLabel("没有待确认建议 · 规则引擎未发现需要封禁的高危 IP")
        self.sug_empty.setStyleSheet(
            f"color:{C.text_muted};font-size:13.5px;padding:0 16px 14px 16px;"
        )
        self.sug_empty.setVisible(False)
        lay.addWidget(self.sug_empty)

        self.sug_table = QTableWidget(0, len(SUG_HEADERS))
        self.sug_table.setHorizontalHeaderLabels(SUG_HEADERS)
        align_headers(self.sug_table, (2, 5, 6))
        self._setup_table(self.sug_table)
        self.sug_table.setItemDelegateForColumn(COL_SUG_LEVEL, RiskBadgeDelegate(self.sug_table))
        self.sug_sel = CheckColumn(self.sug_table, COL_SUG_CHECK)
        self.sug_sel.bind(self._on_sug_sel_changed)
        self._sug_check_delegate = CheckMarkDelegate(self.sug_table)
        self.sug_table.setItemDelegateForColumn(COL_SUG_CHECK, self._sug_check_delegate)
        # 操作列自绘（见 gui/row_action.py）：建议表刷新频率不低，
        # 每行两个控件的老做法在批量刷新时会连界面一起拖慢
        self._sug_action_delegate = RowActionDelegate(
            self.sug_table,
            COL_SUG_ACTION,
            self._sug_spec,
            self._on_sug_ban,
            self._on_sug_menu,
        )
        self.sug_table.setItemDelegateForColumn(COL_SUG_ACTION, self._sug_action_delegate)
        sh = self.sug_table.horizontalHeader()
        for i, width in enumerate(SUG_WIDTHS):
            sh.resizeSection(i, width)
        sh.setSectionResizeMode(COL_SUG_REASON, QHeaderView.ResizeMode.Stretch)
        # 点表头排序（数据层重排 + 重渲染，见 gui/table_sort.py）
        self.sug_sort_header = SortHeader(self.sug_table, self.sug_sort, self._apply_sug_sort)
        # 双击行 = 勾选 / 取消勾选（用户 2026-10-27 要求）
        self.sug_table.doubleClicked.connect(self._on_sug_double_click)
        lay.addWidget(self.sug_table, 1)
        return self.sug_panel

    @staticmethod
    def _mini_button(text: str, kind: str = "", enabled: bool = False) -> QPushButton:
        """标题行 / 批量条里的小按钮。

        默认禁用：动作类按钮必须「先勾选才能点」，否则用户会点到一个什么都不做的
        按钮。「全选」这类不依赖勾选的按钮要显式传 enabled=True。
        """
        b = QPushButton(text)
        b.setFixedHeight(30)
        b.setStyleSheet(small_button_style(kind or "outline"))
        b.setCursor(Qt.CursorShape.PointingHandCursor)
        b.setEnabled(enabled)
        return b

    def _build_records_area(self) -> QWidget:
        """封禁记录区：与上面「待确认建议」完全同一套卡片外壳。

        原来这一区是「裸工具栏 + 裸表格」，而上面是白卡片 —— 两块并排时不像同一类
        东西，用户看到的是「下面那张表不知道属于谁」。现在统一成卡片：标题行
        （标题 + 一句说明 + 右侧动作）、筛选行、批量行、表格，四段自上而下。
        """
        self.ban_panel = QFrame()
        self.ban_panel.setObjectName("panel")
        lay = QVBoxLayout(self.ban_panel)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # ── 标题行（与建议面板同为 16/12/16/8，两个卡片标题基线才会对齐）──
        head = QHBoxLayout()
        head.setContentsMargins(16, 12, 16, 8)
        head.setSpacing(8)
        self.ban_title = QLabel("封禁记录")
        self.ban_title.setObjectName("panel_title")
        self.ban_hint = QLabel("写入 Windows 防火墙的历史记录")
        self.ban_hint.setStyleSheet(f"color:{C.text_muted};font-size:12.5px;")
        head.addWidget(self.ban_title)
        head.addWidget(self.ban_hint)
        head.addStretch(1)

        btn_manual = QPushButton("手动封禁")
        btn_manual.setObjectName("btn_primary")
        btn_manual.setFixedHeight(30)
        btn_manual.setStyleSheet(small_button_style("primary"))
        btn_manual.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_manual.clicked.connect(lambda: self.ask_ban.emit("", 0, "手动封禁"))

        # 2026-10-27 用户要求「与防火墙对账、一键全部封禁直接显示在界面中」：
        # 这两个动作原来塞在「更多 ⋯」菜单里，等于二级入口 —— 对账是「界面说的
        # 和防火墙真实状态不一致」时唯一的修复手段，藏起来等于没有。
        # 顺序按「读屏终点」排：刷新（无状态）→ 对账（只读修复）→ 全部解封
        # （破坏性）→ 手动封禁（主操作，最右）。
        btn_refresh = self._mini_button("刷新", enabled=True)
        btn_refresh.clicked.connect(self.refresh)

        self.btn_sync = self._mini_button("与防火墙对账", enabled=True)
        self.btn_sync.setToolTip(
            "读回 Windows 防火墙里实际存在的 PortGuard 规则，把对不上的记录改成「已解封」。\n"
            "规则被手动删掉、或换了机器恢复数据库之后，用它对一次。"
        )
        self.btn_sync.clicked.connect(self._sync)

        self.btn_unban_all = self._mini_button("一键全部解封", "danger", enabled=True)
        self.btn_unban_all.setToolTip("删除所有 PortGuard_Block_ 规则并标记为已解封（会二次确认）")
        self.btn_unban_all.clicked.connect(self._unban_all)

        for w in (btn_refresh, self.btn_sync, self.btn_unban_all, btn_manual):
            head.addWidget(w)
        lay.addLayout(head)

        # ── 筛选行 ──
        bar = QHBoxLayout()
        bar.setContentsMargins(16, 0, 16, 8)
        bar.setSpacing(8)
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索 IP / 原因…")
        self.search.setClearButtonEnabled(True)
        self.search.setFixedWidth(300)
        self.search.textChanged.connect(self.refresh)

        self.status_filter = QComboBox()
        # 顺序按「用户此刻最想找什么」排：生效中 → 刚到期（该不该续封） → 终态。
        # 「已到期」是 2026-10-27 用户点名要的：到期但规则没删掉的记录原来只能
        # 在「全部状态」里翻，而它恰恰是最需要复查的一类（防火墙规则没有到期
        # 时间，巡检没跑就等于永久封禁）。
        self.status_filter.addItems(["全部状态", "已封禁", "已到期", "已解封", "失败", "处理中"])
        self.status_filter.setFixedWidth(132)
        self.status_filter.currentIndexChanged.connect(self.refresh)

        self.lbl_info = QLabel("")
        self.lbl_info.setStyleSheet(f"color:{C.text_muted};font-size:12.5px;")
        # 刷新提示与「更新于」时间戳复用这行小字（见 widgets.RefreshGuard）
        self._refresh = RefreshGuard(self.lbl_info)

        bar.addWidget(self.search)
        bar.addWidget(self.status_filter)
        bar.addStretch(1)
        bar.addWidget(self.lbl_info)
        lay.addLayout(bar)

        # ── 批量行：只对已解封/已封禁的记录生效，与上面建议表互不影响 ──
        bb = QHBoxLayout()
        bb.setContentsMargins(16, 0, 16, 8)
        bb.setSpacing(8)
        self.lbl_ban_sel = QLabel("已选 0 条")
        self.lbl_ban_sel.setStyleSheet(f"color:{C.text_secondary};font-size:13.5px;")
        self.lbl_ban_sel.setFixedWidth(92)
        self.btn_ban_all = self._mini_button("全选本页", enabled=True)
        self.btn_ban_unban = self._mini_button("批量解封")
        self.btn_ban_del = self._mini_button("删除记录")
        self.btn_ban_all.clicked.connect(lambda: self.ban_sel.toggle_all())  # noqa: PLW0108
        self.btn_ban_unban.clicked.connect(self._batch_unban)
        self.btn_ban_del.clicked.connect(self._batch_delete_bans)
        self.btn_ban_del.setToolTip("仅删除数据库记录，不会改动已生效的防火墙规则")
        self.btn_ban_export = self._mini_button("导出 CSV", enabled=True)
        self.btn_ban_export.setToolTip("导出当前筛选的封禁记录，不受勾选影响")
        self.btn_ban_export.clicked.connect(self._export_ban_csv)
        bb.addWidget(self.lbl_ban_sel)
        bb.addWidget(self.btn_ban_all)
        bb.addSpacing(6)
        bb.addWidget(self.btn_ban_unban)
        bb.addWidget(self.btn_ban_del)
        bb.addWidget(self.btn_ban_export)
        bb.addStretch(1)
        # 双击勾选是个「藏起来的功能」：不给提示的话没人会去试。
        self.lbl_dbl_hint = QLabel("双击行可勾选")
        self.lbl_dbl_hint.setStyleSheet(f"color:{C.text_muted};font-size:12.5px;")
        self.lbl_dbl_hint.setToolTip(
            "双击任意一行 = 勾选 / 取消勾选（操作列除外，那里有自己的按钮）"
        )
        bb.addWidget(self.lbl_dbl_hint)
        lay.addLayout(bb)

        self.empty = EmptyState("尚无封禁记录", "确认封禁后，记录会出现在这里")
        self.empty.setVisible(False)
        lay.addWidget(self.empty)

        self.table = QTableWidget(0, len(BAN_HEADERS))
        self.table.setHorizontalHeaderLabels(BAN_HEADERS)
        align_headers(
            self.table,
            (
                COL_BAN_SOURCE,
                COL_BAN_SCORE,
                COL_BAN_STATUS,
                COL_BAN_EXPIRE,
                COL_BAN_CREATED,
                COL_BAN_ACTION,
            ),
        )
        self._setup_table(self.table)
        self.ban_sel = CheckColumn(self.table, COL_BAN_CHECK)
        self.ban_sel.bind(self._on_ban_sel_changed)
        self._ban_check_delegate = CheckMarkDelegate(self.table)
        self.table.setItemDelegateForColumn(COL_BAN_CHECK, self._ban_check_delegate)
        self._ban_action_delegate = RowActionDelegate(
            self.table,
            COL_BAN_ACTION,
            self._ban_spec,
            self._on_ban_unban,
            self._on_ban_menu,
        )
        self.table.setItemDelegateForColumn(COL_BAN_ACTION, self._ban_action_delegate)
        h = self.table.horizontalHeader()
        for i, width in enumerate(BAN_WIDTHS):
            h.resizeSection(i, width)
        h.setSectionResizeMode(COL_BAN_REASON, QHeaderView.ResizeMode.Stretch)
        # 点表头排序（数据层重排 + 重渲染，见 gui/table_sort.py）
        self.ban_sort_header = SortHeader(self.table, self.ban_sort, self._apply_ban_sort)
        # 双击行 = 勾选 / 取消勾选（与建议表同一套语义）
        self.table.doubleClicked.connect(self._on_ban_double_click)
        lay.addWidget(self.table, 1)
        return self.ban_panel

    # ── 数据 ──
    def _status_filter(self) -> str:
        m = {
            "已封禁": STATUS_ACTIVE,
            "已解封": STATUS_UNBANNED,
            "失败": STATUS_FAILED,
            "处理中": STATUS_PENDING,
        }
        # 「已到期」刻意不在这里映射成 STATUS_EXPIRED：那只是「到期后已成功解封」
        # 的记录，而用户真正要找的是「到期时间已过、现在还在封着」的那批
        # （普通权限下巡检跑不了，它们的状态仍是 active）—— 见 _load_bans。
        return m.get(self.status_filter.currentText(), "")

    def _is_expired_filter(self) -> bool:
        return self.status_filter.currentText() == "已到期"

    def refresh(self) -> None:
        # 重入会叠两次查询 + 两次重排；守卫同时负责「正在刷新…」这行提示。
        # 注意横幅刷新放在守卫**之前**：它是纯本地判断（权限 / netsh 缓存），
        # 不走数据库，不需要为它等一次事件循环。
        if self._refresh.busy:
            return
        with self._refresh:
            self._refresh_perm_banner()
            self._refresh_fw_banner()
            self._load_suggestions()
            self._load_bans()

    def _load_suggestions(self) -> None:
        rows = [
            r
            for r in query_risk_events(limit=200, handled=0)
            if r.get("risk_level") in (LEVEL_HIGH, LEVEL_CRITICAL)
        ]
        # 同 IP + 同端口 = 一件事（2026-10-22 用户反馈：一个 IP 打同一端口占了 27 行）。
        # 27 条建议对应的其实只有一条防火墙规则，逐条列出来除了淹没别的 IP 没有任何作用。
        # 合并后时间列标 ×N，操作列仍是「封禁该 IP」，详情里逐条看。
        try:
            rows = merge_rows(rows)
        except Exception:
            # 合并只是展示优化，失败就退回逐条展示，不能让整页刷不出来
            log.exception("封禁建议合并失败，退回逐条展示")
        # 建议表里可能混着「已经从别的页面封过、但事件还没回填」的 IP，
        # 按钮要据此显示「已封禁」而不是让人再点一次
        try:
            self._banned = active_ban_ip_map()
        except Exception:
            log.exception("加载生效中的封禁失败（建议表按钮将按「未封禁」渲染）")
            self._banned = {}
        # 已经封掉的 IP 不再出现在「待确认的封禁建议」里（2026-10-22 用户反馈）。
        # 建议表的语义是「等你拿主意」，而这类 IP 的主意已经拿完了 —— 留着只会
        # 让人再点一次「确认封禁」，然后被告知「该 IP 已在封禁中」。
        # 隐藏条数要说出来：静默少几行，用户会以为建议丢了。
        self._sug_hidden = 0
        if self._banned:
            before = len(rows)
            rows = [r for r in rows if str(r.get("ip") or "") not in self._banned]
            self._sug_hidden = before - len(rows)
        # 排序状态跨刷新保留：用户按评分降序看建议，封完一条回来还想是降序
        self._sug_rows_src = rows
        self._sug_rows = self.sug_sort.apply(rows)
        self._render_suggestions()

    def _apply_sug_sort(self, _state: Optional[SortSpec]) -> None:
        """按新排序重渲染建议表：勾选按业务 key（事件 id）回放，不是按行号"""
        keys = {r.get("id") for r in self._checked_suggestions()}
        self._sug_rows = self.sug_sort.apply(self._sug_rows_src)
        self._render_suggestions()
        self.sug_sel.set_checked_rows(
            i for i, r in enumerate(self._sug_rows) if r.get("id") in keys
        )

    def _render_suggestions(self) -> None:
        rows = self._sug_rows
        # 合并后「27 条」变成「1 项」：标题要把两个数都说出来，否则用户会以为
        # 建议被吞了 26 条
        total_events = sum(int(r.get("group_count") or 1) for r in rows)
        # 已封禁的 IP 不进这张表（见 _load_suggestions），但**必须**把「还藏着
        # N 项」写出来：平白少几行，用户第一反应是「建议被吞了」。
        hidden = int(getattr(self, "_sug_hidden", 0) or 0)
        tail = f"，另有 {hidden} 项已封禁未显示" if hidden else ""
        if total_events != len(rows):
            self.sug_title.setText(
                f"待确认的封禁建议（{len(rows)} 项 / {total_events} 条事件{tail}）"
            )
        else:
            self.sug_title.setText(f"待确认的封禁建议（{len(rows)}{tail}）")

        empty = not rows
        self.sug_empty.setVisible(empty)
        self.sug_table.setVisible(not empty)
        # 「全部封禁」的可用性跟着列表走：没有建议时它是死按钮，点亮只会误导。
        # 文案带上 IP 数（不是行数：合并行里几行事件可能只是同一个 IP）——
        # 按下去会动多少条防火墙规则，点之前就该看得见。
        ips = {str(r.get("ip") or "") for r in rows} - {""}
        self.btn_sug_ban_all.setEnabled(not empty)
        self.btn_sug_ban_all.setText(f"全部封禁（{len(ips)}）" if ips else "全部封禁")
        if empty:
            # 0 条时整区折叠成一行提示，把高度让给封禁记录表
            # 折叠态也要装得下「标题行 40 + 一句空态 26 + 下留白 14」
            self.sug_panel.setMinimumHeight(80)
            self.sug_panel.setMaximumHeight(80)
        else:
            # 196 / 366 = 面板开销 94 + 3 行 / 8 行（34px 一行）。
            # 这两个数只是上下夹逼，精确吸附在 _snap_sug_rows 里按实际开销算。
            self.sug_panel.setMinimumHeight(196)
            self.sug_panel.setMaximumHeight(366)

        self.sug_sel.begin_render()
        self._sug_action_delegate.reset_hover()
        self.sug_table.setUpdatesEnabled(False)
        try:
            self.sug_table.setRowCount(0)
            self.sug_table.setRowCount(len(rows))
            for i, r in enumerate(rows):
                ts = r.get("event_ts")
                time_str = (
                    datetime.datetime.fromtimestamp(ts / 1000).strftime("%m-%d %H:%M:%S")
                    if ts
                    else "-"
                )
                n = int(r.get("group_count") or 1)
                if n > 1:
                    # 合并行：时间列标 ×N（显示最近一次），否则「怎么只有一条建议」
                    # 与「监控页明明 27 次」对不上
                    time_str = f"{time_str} ×{n}"
                geo = r.get("geo")
                # 等级 / 评分取组内最高水位：一组的危险程度由最严重的那次决定
                level = r.get("peak_level") or r.get("risk_level", "normal")
                reason = r.get("summary") or "命中风险规则"
                ip_text = str(r.get("ip") or "")

                self.sug_sel.fill(i)
                self.sug_table.setItem(i, 1, make_item(time_str, mono=True, tip=ms_to_str(ts)))
                self.sug_table.setItem(i, 2, badge_item(level))
                self.sug_table.setItem(i, 3, make_item(ip_text, C.text_link, tip=ip_text))
                geo_text = geo.display if geo else "未知"
                self.sug_table.setItem(
                    i, 4, make_item(geo.region_short if geo else "未知", tip=geo_text)
                )
                self.sug_table.setItem(
                    i,
                    5,
                    make_item(
                        r.get("local_port") or "-",
                        align=Qt.AlignmentFlag.AlignCenter,
                        mono=True,
                    ),
                )
                self.sug_table.setItem(
                    i,
                    6,
                    make_item(
                        r.get("peak_score", r.get("risk_score", 0)),
                        align=Qt.AlignmentFlag.AlignCenter,
                        bold=True,
                        mono=True,
                    ),
                )
                self.sug_table.setItem(i, COL_SUG_REASON, make_item(reason, tip=reason))
        finally:
            self.sug_sel.end_render()
            self.sug_table.setUpdatesEnabled(True)

    def _sug_spec(self, row: int) -> Optional[RowAction]:
        """建议表操作列：主按钮「确认封禁」+ ⋯"""
        if not 0 <= row < len(self._sug_rows):
            return None
        r = self._sug_rows[row]
        if self._banned.get(str(r.get("ip") or "")) is not None:
            return RowAction("已封禁", "danger", False, "该 IP 已在封禁中")
        return RowAction("确认封禁", "danger", True, "按封禁策略封禁该 IP（弹窗里确认时长）")

    def _on_sug_ban(self, row: int) -> None:
        if not 0 <= row < len(self._sug_rows):
            return
        r = self._sug_rows[row]
        self.ask_ban.emit(
            str(r.get("ip") or ""),
            # 按组内最高分算时长：这组里最严重的那次决定了该封多久
            int(r.get("peak_score", r.get("risk_score")) or 0),
            r.get("summary") or "命中风险规则",
        )

    def _on_sug_menu(self, row: int, global_pos) -> None:
        if not 0 <= row < len(self._sug_rows):
            return
        r = self._sug_rows[row]
        ip = str(r.get("ip") or "")
        n = int(r.get("group_count") or 1)
        build_menu(
            [
                (f"查看详情（{n} 条事件）" if n > 1 else "查看详情", lambda: self._sug_detail(r)),
                ("忽略该建议", lambda: self._ignore(r)),
                ("查询该 IP 归属地", lambda: self.ask_lookup.emit(ip)),
            ],
            self,
        ).exec(global_pos)

    def _sug_detail(self, r: Dict[str, Any]) -> None:
        EventDetailDialog(r, self).exec()

    def _ignore(self, r) -> None:
        # 合并行代表一组：忽略必须落到组内每一条事件，否则「忽略」完刷新一下
        # 剩下的 26 条又以同一条建议冒出来（用户会以为忽略根本没生效）
        ids = [int(m["id"]) for m in (r.get("members") or [r]) if m.get("id") is not None]
        try:
            if len(ids) > 1:
                set_risk_handled_batch(ids, 2)
            elif ids:
                set_risk_handled(ids[0], 2)
        except Exception:
            log.exception("忽略风险事件失败 id=%s", r.get("id"))
        self.refresh()

    # ── 勾选与批量处理 ──
    def _on_sug_sel_changed(self, n: int) -> None:
        self.lbl_sug_sel.setText(f"已选 {n} 条")
        self.lbl_sug_sel.setStyleSheet(
            f"color:{C.primary if n else C.text_muted};font-size:12.5px;"
        )
        for b in (self.btn_sug_ban, self.btn_sug_ignore):
            b.setEnabled(n > 0)
        self.btn_sug_all.setText("取消全选" if n and n == len(self._sug_rows) else "全选")

    def _on_ban_sel_changed(self, n: int) -> None:
        self.lbl_ban_sel.setText(f"已选 {n} 条")
        self.lbl_ban_sel.setStyleSheet(
            f"color:{C.primary if n else C.text_secondary};font-size:13.5px;"
            f"font-weight:{'600' if n else '400'};"
        )
        for b in (self.btn_ban_unban, self.btn_ban_del):
            b.setEnabled(n > 0)
        self.btn_ban_all.setText("取消全选" if n and n == len(self._ban_rows) else "全选本页")

    # ── 双击勾选 ──
    def _on_sug_double_click(self, index) -> None:
        self._toggle_row_check(self.sug_table, self.sug_sel, index, COL_SUG_ACTION)

    def _on_ban_double_click(self, index) -> None:
        self._toggle_row_check(self.table, self.ban_sel, index, COL_BAN_ACTION)

    @staticmethod
    def _toggle_row_check(table: QTableWidget, sel: CheckColumn, index, action_col: int) -> None:
        """双击整行切换勾选态（2026-10-27 用户要求「增加双击选择功能」）。

        勾选框只有 14px，在 34px 行高里要瞄准它才能选中；而「勾几条 → 批量解封」
        是这一页最常走的路径。双击任意单元格都能切换，鼠标不用精确定位。

        两个细节：
        · **操作列不接管**：那一列自绘了「解封」按钮，双击的第一下已经算一次
          点击（delegate 自己会处理），再叠加一次勾选会让人以为解封没点中；
        · 直接改 `CheckState` 而不是调 `CheckColumn.set_checked_rows`：单行改动能
          顺着 `itemChanged` 自动同步表头三态与「已选 N 条」计数，不用重建整列。
        """
        if index is None:
            return
        row = index.row()
        if index.column() == action_col or not 0 <= row < table.rowCount():
            return
        it = table.item(row, sel.col)
        if it is None:
            return
        checked = it.checkState() == Qt.CheckState.Checked
        it.setCheckState(Qt.CheckState.Unchecked if checked else Qt.CheckState.Checked)

    def _checked_suggestions(self) -> list:
        return [self._sug_rows[i] for i in self.sug_sel.checked_rows() if i < len(self._sug_rows)]

    def _checked_bans(self) -> list:
        return [self._ban_rows[i] for i in self.ban_sel.checked_rows() if i < len(self._ban_rows)]

    def _batch_ban_suggestions(self) -> None:
        rows = self._checked_suggestions()
        if not rows:
            return
        self._emit_ban_many(rows)

    def _ban_all_suggestions(self) -> None:
        """一键封禁当前列表里的全部建议 IP（不需要逐条勾选）。

        2026-10-27 用户要求这个入口直接显示在界面上。攻击期「逐条勾选 → 批量封禁」
        每一步都在浪费时间，看到列表就该能一把封掉。

        刻意**复用**同一条通道（`ask_ban_many` → 主窗口 `request_ban_many`）：
        校验逐条做、确认只弹一次、执行串行在同一个后台线程里。这里不自己起线程、
        不自己弹确认框 —— 封禁入口只能有一处，否则「校验绕不过去」这条前提就破了。
        """
        rows = list(self._sug_rows)
        if rows:
            self._emit_ban_many(rows)

    def _emit_ban_many(self, rows: list) -> None:
        # 与风险事件页同一套去重口径：一个 IP 可能命中几十条事件，
        # 但防火墙只该多一条规则
        uniq: Dict[str, Any] = {}
        for r in rows:
            ip = str(r.get("ip") or "")
            if not ip:
                continue
            score = int(r.get("peak_score", r.get("risk_score")) or 0)
            old = uniq.get(ip)
            if old is None or score > int(old.get("peak_score", old.get("risk_score")) or 0):
                uniq[ip] = r
        # 事件状态由 `ban_service.execute` 按 IP 统一回填（见 page_events._batch_ban）
        items = [
            {
                "ip": ip,
                "score": int(r.get("peak_score", r.get("risk_score")) or 0),
                "reason": r.get("summary") or "命中风险规则",
            }
            for ip, r in uniq.items()
        ]
        if items:
            self.ask_ban_many.emit(items)

    def _batch_ignore_suggestions(self) -> None:
        rows = self._checked_suggestions()
        if not rows:
            return
        # 合并行代表一组：忽略必须摊平到组内每一条，否则刷新后剩下的
        # 26 条又会以同一条建议冒出来
        ids = [int(m["id"]) for m in flatten_rows(rows) if m.get("id") is not None]
        if not ids:
            return
        try:
            n = set_risk_handled_batch(ids, 2)
        except Exception as e:
            QMessageBox.warning(self, "操作失败", str(e))
            return
        self.refresh()
        # 不弹模态框：列表当场变短就是最好的反馈
        self.sug_hint.setText(f"已忽略 {n} 条建议")

    def _batch_unban(self) -> None:
        rows = [b for b in self._checked_bans() if b.status == STATUS_ACTIVE]
        if not rows:
            QMessageBox.information(self, "无需解封", "选中的记录里没有处于「已封禁」状态的记录。")
            return
        if not firewall.is_admin():
            QMessageBox.warning(
                self, "权限不足", "批量解封需要管理员权限，请以管理员身份重启程序。"
            )
            return
        if (
            QMessageBox.question(
                self,
                "批量解封",
                f"将删除这 {len(rows)} 条记录对应的防火墙规则，并把记录标记为已解封。\n\n确认继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return

        self.btn_ban_unban.setEnabled(False)
        self.lbl_info.setText(f"正在解封 {len(rows)} 条…")
        targets = list(rows)

        def work():
            ok = 0
            fail = 0
            for b in targets:
                good, err = ban_service.unban(b)
                if good:
                    ok += 1
                else:
                    fail += 1
                    log.warning("批量解封失败 id=%s ip=%s err=%s", b.id, b.ip, err)
            self.batch_unban_done.emit(ok, fail)

        threading.Thread(target=work, daemon=True, name="unban-batch").start()

    def _on_batch_unban_done(self, ok: int, fail: int) -> None:
        self.refresh()
        self.request_refresh_stats.emit()
        if fail:
            QMessageBox.warning(
                self, "批量解封完成", f"成功 {ok} 条，失败 {fail} 条。\n详情见运行日志。"
            )
        else:
            QMessageBox.information(self, "批量解封完成", f"已解封 {ok} 条记录。")

    def _batch_delete_bans(self) -> None:
        rows = self._checked_bans()
        if not rows:
            return
        if (
            QMessageBox.question(
                self,
                "删除封禁记录",
                f"仅从数据库删除选中的 {len(rows)} 条记录，"
                "**不会**改动已生效的防火墙规则。\n\n确认删除？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        ids = [int(b.id) for b in rows if b.id is not None]
        # 删除前把关键字段整条留档：封禁记录是**记账**，删掉之后「这个 IP 曾经
        # 被封过、封的是什么状态」就再也查不到了（防火墙规则不受影响，反而更
        # 需要这条记录来解释现存规则是谁加的）。只记条数等于什么都没记。
        snapshot = [
            {
                "id": b.id,
                "ip": b.ip,
                "status": b.status,
                "source": b.source,
                "rule_name": b.rule_name,
            }
            for b in rows
        ]
        try:
            n = delete_ban_records(ids)
        except Exception as e:
            audit.record(
                audit.ACTION_BAN_DELETE,
                target_type="ban",
                summary=f"删除 {len(ids)} 条封禁记录失败：{e}",
                result=audit.RESULT_FAIL,
                detail=str(e),
            )
            QMessageBox.warning(self, "删除失败", str(e))
            return
        audit.record(
            audit.ACTION_BAN_DELETE,
            target_type="ban",
            summary=f"删除 {n} 条封禁记录（仅删库记录，未改动防火墙规则）",
            before={"bans": snapshot},
            after={"count": n},
            detail="防火墙规则未改动",
        )
        self.refresh()
        self.request_refresh_stats.emit()
        self.lbl_info.setText(f"已删除 {n} 条记录 · 共 {len(self._ban_rows)} 条")

    # ── 导出 ──
    def _export_sug_csv(self) -> None:
        """导出当前待确认建议。

        建议表的数据源是「未处理 + 高危」的前 200 条风险事件（见
        `_load_suggestions`），所以导出的是**当前这批建议**，不是全库事件。
        列表里合并了同 IP 同端口，但 CSV 要逐条事实 —— 走 flatten 摊平。
        """
        flat = flatten_rows(self._sug_rows)
        export_table_csv(
            self,
            flat,
            SUG_CSV_HEADERS,
            iter_sug_rows,
            default_name="ban_suggestions.csv",
            dialog_title="导出封禁建议",
            scope_hint=(
                f"导出范围：当前待确认建议，共 {len(self._sug_rows)} 项"
                f"（{len(flat)} 条事件，按逐条导出）。"
            ),
        )

    def _export_ban_csv(self) -> None:
        """导出当前筛选的封禁记录（搜索词 + 状态筛选后的结果）"""
        export_table_csv(
            self,
            self._ban_rows,
            BAN_CSV_HEADERS,
            iter_ban_rows,
            default_name="ban_records.csv",
            dialog_title="导出封禁记录",
            scope_hint=f"导出范围：当前筛选结果，共 {len(self._ban_rows)} 条。",
        )

    def _load_bans(self) -> None:
        kw = self.search.text().strip()
        if self._is_expired_filter():
            rows = self._query_expired(kw)
        else:
            rows = query_bans(status=self._status_filter(), keyword=kw)
        self._attach_geo(rows)
        # 排序状态跨刷新保留：搜索词变了，用户期望的排序方向不变
        self._ban_rows_src = rows
        self._ban_rows = self.ban_sort.apply(rows)
        self._render_bans()

    @staticmethod
    def _query_expired(keyword: str = "") -> list:
        """「已到期」= 到期时间已过，且这条封禁还在系统里说得上话。

        `status = expired` 只是**到期巡检成功删掉规则之后**的状态。普通权限运行时
        巡检根本跑不了，所以「已经到期、但防火墙规则还在拦」的记录状态依旧是
        `active` —— 界面上写着「已封禁」，左下角却提示「有 N 条已到期」。若筛选只
        认 `expired`，用户点进去只会看到 0 条，正好漏掉最需要处理的那批。

        所以这里按 expire_at 判定，收 `active`（到期未解封，排最前）与 `expired`
        （到期且已解封）两类；`unbanned` 是人工主动解封，跟「到期」无关，不收。
        """
        now_ms = int(time.time() * 1000)
        out = []
        for b in query_bans(keyword=keyword):
            if b.status not in (STATUS_ACTIVE, STATUS_EXPIRED):
                continue
            if not b.expire_at or b.expire_at > now_ms:
                continue  # 永久封禁（expire_at=0）永远不会「到期」
            out.append(b)
        # 还在拦着的排前面：这才是要动手的那批，已解封的是历史
        out.sort(key=lambda b: (b.status != STATUS_ACTIVE, -(b.expire_at or 0)))
        return out

    @staticmethod
    def _attach_geo(rows) -> None:
        """给每条封禁记录挂上归属地（渲染与排序共用这一次查询结果）。

        为什么要挂到对象上而不是在 `_render_bans` 里现查：渲染会被排序、
        勾选、解封反复触发，每渲染一次就重查一遍纯属浪费；而且排序层需要
        拿到同一个值，两边各查一次还有可能拿到不同结果（离线库正在热更新时）。

        网段记录（`1.2.3.0/24`）按**网段地址**查：离线库只吃单个 IP。
        展示上不加「网段」二字 —— IP 列本身就写着 `/24`，加字会把
        归属地列挤到省略号；tooltip 里说明清楚即可。

        查询失败（离线库损坏 / 非法字符串）一律按「未知」处理：
        归属地只是辅助信息，不能因为它让整页刷不出来。
        """
        import ipaddress

        from core.geo_locator import get_locator

        loc = get_locator()
        for b in rows:
            ip = str(getattr(b, "ip", "") or "")
            probe = ip
            if "/" in ip:
                try:
                    probe = str(ipaddress.ip_network(ip, strict=False).network_address)
                except Exception:
                    probe = ""
            try:
                geo = loc.lookup(probe) if probe else None
            except Exception:
                log.exception("查询封禁记录归属地失败 ip=%s", ip)
                geo = None
            b.geo = geo
            b.geo_is_network = "/" in ip

    def _apply_ban_sort(self, _state: Optional[SortSpec]) -> None:
        """按新排序重渲染封禁记录表：勾选按业务 key（记录 id）回放，不是按行号"""
        keys = {b.id for b in self._checked_bans()}
        self._ban_rows = self.ban_sort.apply(self._ban_rows_src)
        self._render_bans()
        self.ban_sel.set_checked_rows(i for i, b in enumerate(self._ban_rows) if b.id in keys)

    def _render_bans(self) -> None:
        rows = self._ban_rows
        # 空态文案要认得筛选项：筛「已到期」却提示「尚无封禁记录」，
        # 等于告诉用户「你库是空的」，而事实是「这个筛选下没有」。
        if self._is_expired_filter():
            self.empty.title.setText("没有已到期的封禁")
            self.empty.desc.setText("当前筛选下没有到期时间已过的记录")
        else:
            self.empty.title.setText("尚无封禁记录")
            self.empty.desc.setText("确认封禁后，记录会出现在这里")
        self.empty.setVisible(not rows)
        self.table.setVisible(bool(rows))
        # 计数写在卡片标题里：两块卡片并排上下时，「这块有几条」是定位的第一步
        self.ban_title.setText(f"封禁记录（{len(rows)}）")

        self.ban_sel.begin_render()
        self._ban_action_delegate.reset_hover()
        self.table.setUpdatesEnabled(False)
        try:
            self.table.setRowCount(0)
            self.table.setRowCount(len(rows))
            for i, b in enumerate(rows):
                status_color = {
                    STATUS_ACTIVE: C.danger,
                    STATUS_UNBANNED: C.text_muted,
                    STATUS_FAILED: C.danger,
                    STATUS_PENDING: C.info,
                }.get(b.status, C.text_secondary)

                self.ban_sel.fill(i)
                # ID 列已删（列宽预算见 BAN_WIDTHS 注释）：记录号挂进 IP 的
                # tooltip 与右键菜单，需要引用审计条目时仍然查得到。
                self.table.setItem(
                    i, 1, make_item(b.ip, C.text_link, tip=f"{b.ip}（记录 #{b.id}）")
                )
                self.table.setItem(
                    i, COL_BAN_REASON, make_item(b.reason or "-", tip=b.reason or "")
                )
                # 归属地：与建议表同一套 `region_short`（省 市 / 国家 城市）。
                # 查不到（内网、保留段、库未收录）一律写「未知」而不是留空 ——
                # 空白格会被当成"这一列没数据"，而「未知」说明是**查了没查到**。
                geo = getattr(b, "geo", None)
                geo_tip = geo.display if geo else "未知"
                if getattr(b, "geo_is_network", False):
                    geo_tip += "（网段记录，按网段地址查询）"
                self.table.setItem(
                    i,
                    COL_BAN_GEO,
                    make_item(geo.region_short if geo else "未知", tip=geo_tip),
                )
                self.table.setItem(
                    i,
                    COL_BAN_SOURCE,
                    make_item(b.source_label, align=Qt.AlignmentFlag.AlignCenter),
                )
                self.table.setItem(
                    i,
                    COL_BAN_SCORE,
                    make_item(b.risk_score, align=Qt.AlignmentFlag.AlignCenter, mono=True),
                )
                # 拦截次数跟在状态后面：封了还在撞的 IP 一眼能看出来
                # （例：已封禁 ×7）。完整说明进 tooltip（见 BanRecord.hit_hint）
                status_text = b.status_label
                if b.hit_label:
                    status_text = f"{b.status_label} {b.hit_label}"
                self.table.setItem(
                    i,
                    COL_BAN_STATUS,
                    make_item(
                        status_text,
                        status_color,
                        Qt.AlignmentFlag.AlignCenter,
                        tip=b.hit_hint if b.hit_label else b.status_label,
                    ),
                )
                # 时间列 136 才装得下 `2026-10-20 09:27`（实测 112 + padding）。
                # tooltip 仍给到秒：判断「是不是刚封的」时差几秒有意义。
                self.table.setItem(
                    i,
                    COL_BAN_EXPIRE,
                    make_item(
                        b.expire_min,
                        align=Qt.AlignmentFlag.AlignCenter,
                        mono=True,
                        tip=ms_to_str(b.expire_at) if b.expire_at else "永久封禁（不会自动解封）",
                    ),
                )
                self.table.setItem(
                    i,
                    COL_BAN_CREATED,
                    make_item(
                        b.created_min,
                        align=Qt.AlignmentFlag.AlignCenter,
                        mono=True,
                        tip=b.created_at or "",
                    ),
                )
        finally:
            self.ban_sel.end_render()
            self.table.setUpdatesEnabled(True)

        # 累计拦截次数：已封禁的重复命中不再弹窗，这个数字是它们唯一的去处 ——
        # 「这堵墙到底挡了多少次」必须能在这里看到，否则静默就变成了「什么都不说」
        hits = sum_ban_hits()
        text = f"共 {len(rows)} 条 · 当前生效 {count_active_bans()} 条"
        if hits:
            text += f" · 封禁期间累计拦截 {hits} 次"
        self.lbl_info.setText(text)

    def _ban_spec(self, row: int) -> Optional[RowAction]:
        """封禁记录表操作列：「解封」只在生效中的记录上可点"""
        if not 0 <= row < len(self._ban_rows):
            return None
        b = self._ban_rows[row]
        if b.ip in self._busy:
            return RowAction("解封中", "success", False, "正在删除防火墙规则，请稍候…")
        if b.status != STATUS_ACTIVE:
            return RowAction(
                "解封", "success", False, f"该记录状态为「{b.status_label}」，无需解封"
            )
        return RowAction("解封", "success", True, "删除这条记录对应的防火墙规则")

    def _on_ban_unban(self, row: int) -> None:
        if 0 <= row < len(self._ban_rows):
            self._unban(self._ban_rows[row])

    def _on_ban_menu(self, row: int, global_pos) -> None:
        if not 0 <= row < len(self._ban_rows):
            return
        b = self._ban_rows[row]
        build_menu(
            [
                ("查询该 IP 归属地", lambda: self.ask_lookup.emit(b.ip)),
                ("复制 IP", lambda: self._copy(b.ip)),
                None,
                ("删除记录…", lambda: self._delete(b)),
            ],
            self,
        ).exec(global_pos)

    @staticmethod
    def _copy(text: str) -> None:
        from qtcompat import QApplication

        QApplication.clipboard().setText(text or "")

    def _unban(self, b) -> None:
        """单条解封（后台线程）：`unban` 要起 netsh 删规则，还会逐条列出全量规则

        放界面线程里跑的表现是「点了没反应」，几秒后才跳结果；用户在这几秒里
        再点一次就会起第二个进程。所以用忙标记挡住重复点击，按钮当场变「解封中」。
        """
        key = b.ip
        if not self._busy.enter(key):
            return
        self._render_bans()  # 让按钮立刻变「解封中」

        def work():
            return ban_service.unban(b)

        def on_done(res):
            self._on_unban_done(key, res)

        run_in_background(self, work, on_done, self._on_unban_failed, name="unban")

    def _on_unban_done(self, key: str, res) -> None:
        self._busy.leave(key)
        ok, err = res if isinstance(res, tuple) else (False, "解封返回格式异常")
        if ok:
            self.refresh()
            self.request_refresh_stats.emit()
            return
        self._render_bans()
        QMessageBox.warning(self, "解封失败", err or "未知错误")

    def _on_unban_failed(self, err: str) -> None:
        # 异常文本里没有 IP（线程是被逐个点击起的），这里整体刷新即可：
        # 失败的那条记录状态没变，按钮会回到「解封」
        log.error("解封失败：%s", err)
        self._busy.clear()
        self.refresh()
        QMessageBox.warning(self, "解封失败", "解封时发生异常，详情见运行日志。")

    def _delete(self, b) -> None:
        from core.database import delete_ban_record

        if (
            QMessageBox.question(
                self,
                "删除记录",
                f"仅从数据库删除封禁记录 #{b.id}（IP {b.ip}），"
                f"不会影响已生效的防火墙规则。\n\n确认删除？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        delete_ban_record(b.id)
        self.refresh()

    def _unban_all(self) -> None:
        if not firewall.is_admin():
            QMessageBox.warning(
                self, "权限不足", "批量解封需要管理员权限，请以管理员身份重启程序。"
            )
            return
        if (
            QMessageBox.question(
                self,
                "一键全部解封",
                "将删除所有以 PortGuard_Block_ 开头的防火墙规则，并把这些封禁记录标记为已解封。\n\n确认继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        if not self._busy.enter("unban-all"):
            return
        self.lbl_info.setText("正在解封全部规则…")

        def work():
            return ban_service.unban_all()

        run_in_background(
            self, work, self._on_unban_all_done, self._on_unban_all_failed, name="unban-all"
        )

    def _on_unban_all_done(self, res) -> None:
        self._busy.leave("unban-all")
        ok, n, err = res if isinstance(res, tuple) else (False, 0, "解封返回格式异常")
        if not ok:
            self.refresh()
            QMessageBox.warning(self, "解封失败", err or "未知错误")
            return
        self.refresh()
        self.request_refresh_stats.emit()
        QMessageBox.information(self, "完成", f"已解封 {n} 条防火墙规则。")

    def _on_unban_all_failed(self, err: str) -> None:
        self._busy.leave("unban-all")
        log.error("一键全部解封失败：%s", err)
        self.refresh()
        QMessageBox.warning(self, "解封失败", "解封时发生异常，详情见运行日志。")

    def _sync(self) -> None:
        """与防火墙对账：把已不存在的规则对应的记录标记为已解封

        读规则要起 netsh 列全量（几百条规则时能到几百毫秒），所以先放后台读，
        读回来再在主线程弹确认框、跑对账。
        """
        if not firewall.is_admin():
            QMessageBox.information(
                self,
                "提示",
                "对账需要查询防火墙规则，请以管理员身份运行以获取完整信息。\n"
                "普通权限下仍会尝试按规则名核对。",
            )
        if not self._busy.enter("sync"):
            return

        run_in_background(
            self,
            firewall.list_rule_names,
            self._on_sync_rules,
            self._on_sync_failed,
            name="fw-sync",
        )

    def _on_sync_rules(self, existing) -> None:
        self._busy.leave("sync")
        # 「读到空列表」有两种含义：规则真的都不在了，或者压根没读到
        # （netsh-only 环境 / 权限不足）。reconcile 只会按前者处理 —— 它会把库里
        # 所有 active 记录标成已解封，而防火墙规则还在系统里，从此无人巡检解封。
        try:
            active = count_active_bans()
        except Exception:
            active = 0
        if (
            not existing
            and active > 0
            and QMessageBox.question(
                self,
                "对账确认",
                f"没有从防火墙读到任何 PortGuard 规则，但库里有 {active} 条「已封禁」记录。\n\n"
                "这通常意味着本机读不到防火墙规则（旧系统 / 权限不足），"
                "而不是规则真的不存在。\n"
                f"继续对账会把 {active} 条记录全部标记为已解封，"
                "**防火墙规则不会被删除，仍将继续拦截**。\n\n"
                "确实要对账吗？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        fixed = ban_service.reconcile(existing)
        self.refresh()
        QMessageBox.information(
            self,
            "对账完成",
            f"防火墙中现存 PortGuard 规则：{len(existing)} 条\n已修正 {fixed} 条失效记录。",
        )

    def _on_sync_failed(self, err: str) -> None:
        self._busy.leave("sync")
        log.error("读取防火墙规则失败：%s", err)
        QMessageBox.warning(self, "对账失败", "读取防火墙规则失败，详情见运行日志。")

    def _restart_as_admin(self) -> None:
        if (
            QMessageBox.question(
                self,
                "以管理员身份重启",
                "将重新启动程序并请求管理员权限。\n\n继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        ok, err = firewall.open_admin_restart()
        if not ok:
            QMessageBox.warning(self, "提权失败", f"{err}\n\n请手动右键程序 → 以管理员身份运行。")
        else:
            from qtcompat import QApplication

            app = QApplication.instance()
            if app is not None:
                app.quit()
