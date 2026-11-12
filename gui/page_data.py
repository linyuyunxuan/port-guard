"""PortGuard — 设置页「数据与离线库」子页

从 `gui.page_settings` 拆出（P2⑤）：负责『数据维护』tab 的控件构建与展示。
save/load 生命周期仍由父页 `SettingsPage` 统一持有；本页控件改动经构造时注入的
`dirty_cb` 点亮父页「●未保存」。

本页涉及的「跨页动作」通过参数从父页拿到：
- `reload_cb`：db 恢复成功换掉的是一整份库，设置也可能跟着换 —— 结果必须冒泡到
  父页做全量重载，不把整页重载逻辑复制进本页（见 `_on_db_task_done`）。
- `xdb_check_requested` / `xdb_sync_requested` / `geo_reload_requested` /
  `logs_open_requested`：这些信号由主窗口连在父页 `SettingsPage` 上，本页这些
  tab 里发出请求时直接转发父页同名信号。

对外扁平属性面（`page.cb_xdb_source` / `page.refresh_xdb_state()` …）由父页
`__getattr__` 转发到本页实例，测试与主窗口的既有引用保持不变。
"""

import contextlib
import datetime
import threading
from typing import Any, Callable, Dict, List, Optional

from app import audit, data_service, maintenance
from core import policy_snapshot, xdb_updater
from core import settings as cfg
from core.config import (
    DEFAULT_AUDIT_RETENTION_DAYS,
    DEFAULT_BAN_RETENTION_DAYS,
    DEFAULT_LOG_RETENTION_DAYS,
    DEFAULT_RISK_RETENTION_DAYS,
    RETENTION_PRESETS,
    XDB_UPSTREAM,
    db_path,
    user_data_dir,
)
from core.database import db_size
from core.logger import get_logger, log_file
from core.models import ms_to_str
from gui.page_common import (
    _add_section_index,
    _backup_picker,
    _fill_backup_picker,
    _Panel,
    _picker_index,
    _row_widget,
    _scroll_page,
    _sw_label,
)
from gui.theme import C
from gui.widgets import ToggleSwitch, WarnBanner
from qtcompat import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSpinBox,
    Qt,
    QVBoxLayout,
    QWidget,
)

log = get_logger(__name__)


#: 位置库文件名 -> 展示名（与父页 `_xdb_label` 同一套口径）
def _xdb_label(name: str) -> str:
    return "IPv4 库" if "_v4" in name else "IPv6 库"


#: 后台任务进行中的提示语（VACUUM 可能几十秒，必须让用户知道程序没死）
DB_TASK_TEXT = {
    "vacuum": "正在整理数据库（VACUUM）…会把整库重写一遍，库越大越久，请勿关闭程序",
    "reindex": "正在重建全部索引…",
    "backup": "正在备份数据库…",
    "restore": "正在恢复数据库…写入器已暂停，期间不会记录新的访问",
}

#: 任务名（拼「✗ xx 失败」用）
DB_TASK_NAME = {"vacuum": "整理数据库", "reindex": "重建索引", "backup": "备份", "restore": "恢复"}


def _policy_export(parent) -> None:
    """导出策略快照：只带规则 / 名单 / 策略设置，不含运行数据与凭据。"""
    name = "portguard-policy-" + datetime.datetime.now().strftime("%Y%m%d") + ".json"
    path, _ = QFileDialog.getSaveFileName(parent, "导出策略快照", name, "JSON 文件 (*.json)")
    if not path:
        return
    try:
        data = policy_snapshot.export_to(path)
    except Exception as e:
        QMessageBox.warning(parent, "导出失败", f"策略快照导出失败：{e}")
        return
    with contextlib.suppress(Exception):
        audit.record(audit.ACTION_SETTINGS_SAVE, summary="导出策略快照", detail=path)
    QMessageBox.information(
        parent,
        "导出完成",
        f"已导出 {len(data['settings'])} 项策略设置、"
        f"{len(data['blacklist'])} 条黑名单、{len(data['whitelist'])} 条白名单。\n\n{path}",
    )


def _policy_import(parent) -> None:
    """导入策略快照：先确认，再备份；失败自动回滚（见 core.policy_snapshot）。"""
    path, _ = QFileDialog.getOpenFileName(parent, "导入策略快照", "", "JSON 文件 (*.json)")
    if not path:
        return
    if (
        QMessageBox.question(
            parent,
            "导入策略快照",
            "将用快照里的规则、黑白名单与策略设置覆盖本机配置。\n"
            "导入前会自动备份当前配置，失败可回滚；运行数据（事件 / 封禁 / 审计）不受影响。\n\n继续？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        != QMessageBox.StandardButton.Yes
    ):
        return
    res = policy_snapshot.import_from(path)
    if res["ok"]:
        applied = res["applied"]
        with contextlib.suppress(Exception):
            audit.record(
                audit.ACTION_SETTINGS_SAVE,
                summary=f"导入策略快照（设置 {applied['settings']} 项）",
                detail=res["backup_dir"],
            )
        loader = getattr(parent, "load", None)
        if callable(loader):
            with contextlib.suppress(Exception):
                loader()
        QMessageBox.information(
            parent,
            "导入完成",
            f"策略已导入：设置 {applied['settings']} 项、"
            f"黑名单 {applied['blacklist']} 条、白名单 {applied['whitelist']} 条。\n"
            f"导入前备份：{res['backup_dir']}\n"
            "部分设置可能需重启服务后完全生效。",
        )
    else:
        QMessageBox.warning(parent, "导入未完成", res["error"] or "未知错误")


class DataPage(QWidget):
    """『数据与离线库』tab：离线库同步 + 数据管理 + 数据库维护的控件构建与展示。

    Args:
        parent: 父页 SettingsPage。控件改动经 `dirty_cb` 点亮父页「未保存」；
            脚本/测试把 `parent` 设为 None 纯构造也行（仅供自检）。
        dirty_cb: 控件改动回调（父页 `_mark_dirty`）。
        reload_cb: db 恢复成功后触发父页全量重载（父页 `load`）。
    """

    def __init__(
        self,
        parent: Optional[QWidget] = None,
        dirty_cb: Optional[Callable] = None,
        reload_cb: Optional[Callable] = None,
    ):
        super().__init__(parent)
        self._parent = parent
        self._dirty_cb: Callable = dirty_cb or (lambda *_a: None)
        self._reload_cb: Callable = reload_cb or (lambda: None)
        # 与父页 `__init__` 保持同一批状态（db 维护闸门 / 保留期预设守卫）
        self._bak_rows: List[Dict] = []
        self._db_rows: List[Dict] = []
        self._db_busy = False
        self._db_cursor = False
        self._retention_preset_guard = False
        self._db_buttons: List[QPushButton] = []
        self.build()

    # ── 信号转发（这些信号由主窗口连在父页上，本页发出请求时转发）──
    @property
    def xdb_check_requested(self):
        return getattr(self._parent, "xdb_check_requested", None)

    @property
    def xdb_sync_requested(self):
        return getattr(self._parent, "xdb_sync_requested", None)

    @property
    def geo_reload_requested(self):
        return getattr(self._parent, "geo_reload_requested", None)

    @property
    def logs_open_requested(self):
        return getattr(self._parent, "logs_open_requested", None)

    @property
    def db_task_done(self):
        return getattr(self._parent, "db_task_done", None)

    # ── 控件构建 ──
    def build(self) -> QScrollArea:
        page, lay = _scroll_page()
        self._section_data = _add_section_index(
            page, lay, "③ 数据与离线库", ["离线库在线同步", "数据管理"]
        )
        self.tab_data = (
            self  # addTab 的成员是 DataPage 自身，供父页 identity 判断 / setCurrentWidget
        )
        self._data_scroll = page  # WAL 提示条的「去整理」要滚到这里

        xdb = _Panel("离线库在线同步（IP 归属地）")

        self.lbl_xdb_state = QLabel("读取中…")
        self.lbl_xdb_state.setObjectName("mono_hint")
        self.lbl_xdb_state.setWordWrap(True)
        self.lbl_xdb_state.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        xdb.add("当前库", self.lbl_xdb_state)

        self.tg_xdb_auto = ToggleSwitch(True)
        self.sp_xdb_interval = QSpinBox()
        self.sp_xdb_interval.setRange(1, 24 * 30)
        self.sp_xdb_interval.setValue(24)
        self.sp_xdb_interval.setSuffix(" 小时")
        self.sp_xdb_interval.setFixedWidth(120)
        self.tg_xdb_start = ToggleSwitch(True)
        self.tg_xdb_download = ToggleSwitch(True)

        # 自定义镜像源：可编辑下拉框 + 增删。下拉里**全部条目都会保存**，
        # 同步时按列表顺序依次尝试，全挂才回落内置源 —— 所以「选中哪一条」
        # 不影响结果，只是一个待编辑的槽位（_wire_dirty 里对它豁免）。
        self.cb_xdb_source = QComboBox()
        self.cb_xdb_source.setEditable(True)
        # 回车不自动入列表：否则「打完字想先看看」就变成悄悄加了一条
        self.cb_xdb_source.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        self.cb_xdb_source.setMinimumWidth(400)
        self.cb_xdb_source.setMaximumWidth(600)
        self.cb_xdb_source.setToolTip(
            f"最多 {xdb_updater.MAX_CUSTOM_SOURCES} 条，按列表顺序依次尝试，全部失败才回落内置源。\n"
            "地址用 {path} 占位，例如 https://mirror.example.com/ip2region/{path}\n"
            "自定义域名不必加白名单，但不允许指向内网 / 回环地址（防 SSRF）。"
        )
        _le = self.cb_xdb_source.lineEdit()
        if _le is not None:
            _le.setPlaceholderText("留空用内置源；自定义镜像用 {path} 占位")
        self.lbl_xdb_src = QLabel("")
        self.lbl_xdb_src.setObjectName("form_hint")

        self.btn_xdb_src_add = QPushButton("添加")
        self.btn_xdb_src_add.setObjectName("btn_outline")
        self.btn_xdb_src_add.setToolTip("把输入框里的地址加入列表")
        self.btn_xdb_src_add.clicked.connect(self._add_xdb_source)

        self.btn_xdb_src_del = QPushButton("删除")
        self.btn_xdb_src_del.setObjectName("btn_outline")
        self.btn_xdb_src_del.setToolTip("从列表里移除当前选中 / 输入的地址")
        self.btn_xdb_src_del.clicked.connect(self._del_xdb_source)

        xdb.add("自动检查更新", self.tg_xdb_auto)
        xdb.add("检查间隔", self.sp_xdb_interval)
        xdb.add(
            "启动 / 换库",
            _row_widget(
                self.tg_xdb_start,
                _sw_label("启动时检查"),
                self.tg_xdb_download,
                _sw_label("自动下载并热换"),
                spacing=8,
            ),
        )
        xdb.add(
            "自定义镜像源",
            _row_widget(
                self.cb_xdb_source,
                self.btn_xdb_src_add,
                self.btn_xdb_src_del,
                self.lbl_xdb_src,
                spacing=8,
            ),
        )

        self.xdb_bar = QProgressBar()
        self.xdb_bar.setRange(0, 100)
        self.xdb_bar.setValue(0)
        self.xdb_bar.setFixedHeight(8)
        self.xdb_bar.setTextVisible(False)

        self.lbl_xdb_progress = QLabel("待命中")
        self.lbl_xdb_progress.setObjectName("form_hint")
        xdb.add("同步进度", (self.xdb_bar, self.lbl_xdb_progress))

        # 存成属性便于自检/自动化测试直接触发
        self.btn_xdb_check = QPushButton("检查离线库更新")
        self.btn_xdb_check.setObjectName("btn_outline")
        self.btn_xdb_check.clicked.connect(self._emit_xdb_check)
        self.btn_xdb_sync = QPushButton("立即同步")
        self.btn_xdb_sync.setObjectName("btn_primary")
        self.btn_xdb_sync.clicked.connect(self._emit_xdb_sync)
        self.btn_xdb_force = QPushButton("强制重新下载")
        self.btn_xdb_force.setObjectName("btn_outline")
        self.btn_xdb_force.clicked.connect(self._force_sync)
        # 启动期加载失败的自助重试：不联网、不重启，纯本地热重载
        self.btn_geo_reload = QPushButton("重新加载定位库")
        self.btn_geo_reload.setObjectName("btn_outline")
        self.btn_geo_reload.setToolTip(
            "不联网、不重启：重新读取本机离线库文件。\n"
            "用于修复启动期「定位库 读取失败」，不影响现有配置。"
        )
        self.btn_geo_reload.clicked.connect(self._emit_geo_reload)
        # 流程说明进 tooltip（P1-4）：它只在「想知道为什么这么慢」时才需要
        sync_tip = (
            "同步流程：版本指纹比对 → 多源下载 → 大小 / 内容指纹 / xdb 结构 / 抽样查询"
            "四重校验 → 备份旧库 → 原子替换 → 热加载（无需重启）。\n"
            "任一步失败都会回滚，不影响现有定位能力。"
        )
        for b in (self.btn_xdb_check, self.btn_xdb_sync, self.btn_xdb_force):
            b.setToolTip(sync_tip)
        xdb.add(
            "",
            (self.btn_xdb_check, self.btn_xdb_sync, self.btn_xdb_force, self.btn_geo_reload),
        )

        # ── 备份与回滚（换库前自动备份，这里把它们列出来供手动回滚）──
        restore_tip = (
            "换库前会自动备份旧库，这里列出的是还能回滚到的版本"
            f"（每个库只保留最近 {maintenance.KEEP_BACKUPS_PER_FILE} 份）。\n"
            "回滚前会再备份一次当前库，所以回滚错了仍然可以再回滚回来。"
        )
        # 备份明细改成下拉选择：原来 4 列表格夹在滚动区里，上下拖动时被卡片
        # 边缘遮挡、行也不好点中。现在下拉只占一行，选中那份的完整明细写在
        # 下一行文字里；_wire_dirty 会跳过这个选择器（它不是设置项）。
        self.cb_bak = _backup_picker()
        self.cb_bak.currentIndexChanged.connect(self._show_bak_detail)
        xdb.add("可回滚备份", self.cb_bak)

        self.lbl_bak = QLabel("")
        self.lbl_bak.setObjectName("form_hint")
        self.lbl_bak.setWordWrap(True)
        self.lbl_bak.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        xdb.add_block(self.lbl_bak, span=False)

        self.btn_bak_restore = QPushButton("回滚到此备份")
        self.btn_bak_restore.setObjectName("btn_outline")
        self.btn_bak_restore.setToolTip(restore_tip)
        self.btn_bak_restore.clicked.connect(self._restore_backup)
        xdb.add("", self.btn_bak_restore)
        lay.addWidget(xdb)

        data = _Panel("数据管理")
        # ── 自动清理总开关 + 保留期预设 ──
        self.tg_maint = ToggleSwitch(True)
        self.tg_maint.setToolTip("关闭后只有本页的「清理过期日志」按钮能触发清理。")
        self.cb_retention = QComboBox()
        self.cb_retention.addItems([f"{d} 天" for d in RETENTION_PRESETS] + ["自定义"])
        self.cb_retention.setFixedWidth(140)
        self.cb_retention.setToolTip(
            "一次设定四张表的保留期（访问流水 / 风险事件 / 封禁记录 / 操作审计）。\n"
            "选「自定义」后可在下面四项里分别调整。"
        )
        self.cb_retention.currentIndexChanged.connect(self._on_retention_preset)

        # 四张表各自的保留期。**不要合并成一个「统一保留 N 天」** ——
        # 见 core.config 的 DEFAULT_*_RETENTION_DAYS：流水最短、结论次之、
        # 封禁账本最长（要回答「是不是惯犯」），审计自己也要有期限。
        self.sp_retention = QSpinBox()
        self.sp_retention.setRange(1, 3650)
        self.sp_retention.setValue(DEFAULT_LOG_RETENTION_DAYS)
        self.sp_retention.setSuffix(" 天")
        self.sp_retention.setFixedWidth(120)
        self.sp_retention.setToolTip(
            "access_log 访问流水：原始事实，保留最短。\n同时决定磁盘日志文件的保留天数。"
        )

        self.sp_risk_retention = QSpinBox()
        self.sp_risk_retention.setRange(1, 3650)
        self.sp_risk_retention.setValue(DEFAULT_RISK_RETENTION_DAYS)
        self.sp_risk_retention.setSuffix(" 天")
        self.sp_risk_retention.setFixedWidth(120)
        self.sp_risk_retention.setToolTip(
            "risk_event 风险事件：规则算出的结论。\n"
            "刻意比流水长 —— 否则「这条访问曾被判严重风险」会比流水更早消失。"
        )

        self.sp_ban_retention = QSpinBox()
        self.sp_ban_retention.setRange(1, 3650)
        self.sp_ban_retention.setValue(DEFAULT_BAN_RETENTION_DAYS)
        self.sp_ban_retention.setSuffix(" 天")
        self.sp_ban_retention.setFixedWidth(120)
        self.sp_ban_retention.setToolTip(
            "ban_list 封禁账本：只清已解封 / 已到期 / 失败的终态记录。\n"
            "「已封禁」和「处理中」永不清理 —— 前者背后是一条真实存在的防火墙\n"
            "规则，删了记账规则就变成没人认领的无主规则。"
        )

        self.sp_audit_retention = QSpinBox()
        self.sp_audit_retention.setRange(1, 3650)
        self.sp_audit_retention.setValue(DEFAULT_AUDIT_RETENTION_DAYS)
        self.sp_audit_retention.setSuffix(" 天")
        self.sp_audit_retention.setFixedWidth(120)
        self.sp_audit_retention.setToolTip(
            "audit_log 操作审计：默认 180 天，够覆盖一次季度回溯。\n"
            "不给它期限的话，审计表自己就会变成新的无界增长表。"
        )

        # 四项里任意一项被手改 → 预设框回落到「自定义」（反之不成立）。
        for sp in (
            self.sp_retention,
            self.sp_risk_retention,
            self.sp_ban_retention,
            self.sp_audit_retention,
        ):
            sp.valueChanged.connect(self._sync_retention_combo)

        self.sp_buffer = QSpinBox()
        self.sp_buffer.setRange(500, 100000)
        self.sp_buffer.setSingleStep(500)
        self.sp_buffer.setValue(5000)
        self.sp_buffer.setFixedWidth(140)

        self.sp_cache = QSpinBox()
        self.sp_cache.setRange(1000, 500000)
        self.sp_cache.setSingleStep(2000)
        self.sp_cache.setValue(20000)
        self.sp_cache.setFixedWidth(140)

        # 定期清理的执行时刻（24 小时制）。默认凌晨 3 点，避开营业时段。
        self.sp_maint_hour = QSpinBox()
        self.sp_maint_hour.setRange(0, 23)
        self.sp_maint_hour.setValue(3)
        self.sp_maint_hour.setSuffix(" 点")
        self.sp_maint_hour.setFixedWidth(120)

        data.add(
            "自动清理",
            _row_widget(self.tg_maint, _sw_label("每天到点执行一次"), spacing=10),
        )
        data.add("保留期预设", self.cb_retention)
        data.add("访问流水保留", self.sp_retention)
        data.add("风险事件保留", self.sp_risk_retention)
        data.add("封禁记录保留", self.sp_ban_retention)
        data.add("操作审计保留", self.sp_audit_retention)
        data.add("自动清理时刻", self.sp_maint_hour)
        data.add("监控缓冲行数", self.sp_buffer)
        data.add("归属地缓存条数", self.sp_cache)

        # 这里必须指向**真实入口**：用户清完日志发现空间没变小，得知道去哪儿解决，
        # 否则会以为「清理坏了」。「去整理」直接滚到本面板下方的数据库文件区。
        self.warn_wal = WarnBanner(
            "清理会批量删除数据，SQLite 的 WAL 文件会随之涨到与被删数据同量级，"
            "且这部分空间不会自动还给文件系统（只是留给后续写入复用）。"
            "要真正回收磁盘，需要执行一次数据库整理（VACUUM）"
            "—— 就在下方「数据库文件」区域里点「整理数据库」。",
            action_text="去整理",
            level="info",
        )
        self.warn_wal.action_clicked.connect(self._scroll_to_db_section)
        data.add_block(self.warn_wal)

        self.lbl_logfile = QLabel(log_file())
        self.lbl_logfile.setObjectName("mono_hint")
        self.lbl_logfile.setWordWrap(True)
        self.lbl_logfile.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        self.lbl_datadir = QLabel(user_data_dir())
        self.lbl_datadir.setObjectName("mono_hint")
        self.lbl_datadir.setWordWrap(True)
        self.lbl_datadir.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        data.add("日志文件", self.lbl_logfile)
        data.add("数据目录", self.lbl_datadir)

        b_clean = QPushButton("清理过期日志")
        b_clean.setObjectName("btn_outline")
        b_clean.clicked.connect(self._clean_logs)
        b_clear = QPushButton("清空全部日志")
        b_clear.setObjectName("btn_danger")
        b_clear.clicked.connect(self._clear_logs)
        b_logs = QPushButton("打开日志目录")
        b_logs.setObjectName("btn_outline")
        b_logs.clicked.connect(self._emit_logs_open)
        data.add("", (b_clean, b_clear, b_logs))

        self._add_db_section(data)
        lay.addWidget(data)

        lay.addStretch(1)
        # 挂进本页：父页 addTab(data_page) 使用本 widget
        _root = QVBoxLayout(self)
        _root.setContentsMargins(0, 0, 0, 0)
        _root.addWidget(page)
        self.setLayout(_root)
        return page

    def _add_db_section(self, panel: "_Panel") -> None:
        """「数据管理」里追加数据库文件区：大小 / 整理 / 重建索引 / 备份与恢复。"""
        div = QFrame()
        div.setObjectName("panel_divider")
        div.setFixedHeight(1)
        panel.add_block(div)

        title = QLabel("数据库文件（整理 · 备份 · 恢复）")
        title.setObjectName("panel_title")
        panel.add_block(title)
        #: 「去整理」滚动定位用（这个 tab 很高，提示条在上、入口在下）
        self._db_anchor = title

        self.lbl_dbsize = QLabel("读取中…")
        self.lbl_dbsize.setObjectName("mono_hint")
        self.lbl_dbsize.setWordWrap(True)
        self.lbl_dbsize.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        self.lbl_dbpath = QLabel(db_path())
        self.lbl_dbpath.setObjectName("mono_hint")
        self.lbl_dbpath.setWordWrap(True)
        self.lbl_dbpath.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        self.btn_db_vacuum = QPushButton("整理数据库")
        self.btn_db_vacuum.setObjectName("btn_outline")
        self.btn_db_vacuum.setToolTip(
            "VACUUM：把删掉的空间真正还给磁盘。\n"
            "会把整库重写一遍 —— 几百 MB 的库要几十秒，期间写入短暂排队；\n"
            "需要约等于数据库大小的空闲磁盘，空间不够会直接失败（数据不受影响）。"
        )
        self.btn_db_vacuum.clicked.connect(lambda: self._db_run("vacuum", maintenance.vacuum_db))

        self.btn_db_reindex = QPushButton("重建索引")
        self.btn_db_reindex.setObjectName("btn_outline")
        self.btn_db_reindex.setToolTip(
            "REINDEX：重建全部索引。\n"
            "长期增删之后索引 B 树会有空洞，重建后查询更快、体积更小；比整理快得多。"
        )
        self.btn_db_reindex.clicked.connect(lambda: self._db_run("reindex", maintenance.reindex_db))

        self.btn_db_backup = QPushButton("立即备份")
        self.btn_db_backup.setObjectName("btn_outline")
        self.btn_db_backup.setToolTip(
            "用 SQLite 在线备份打一份一致性快照。\n"
            "不需要停服务、不影响写入；最多保留最近 "
            f"{maintenance.KEEP_DB_BACKUPS} 份，更早的自动删除。"
        )
        self.btn_db_backup.clicked.connect(self._db_backup_now)

        self._db_buttons = [
            self.btn_db_vacuum,
            self.btn_db_reindex,
            self.btn_db_backup,
        ]

        panel.add("数据库大小", self.lbl_dbsize)
        panel.add("数据库文件", self.lbl_dbpath)
        panel.add("", (self.btn_db_vacuum, self.btn_db_reindex, self.btn_db_backup))

        # 策略快照：逐台交付时用一份 JSON 复制规则 / 名单 / 策略设置。
        snap_title = QLabel("策略快照（逐台复制配置）")
        snap_title.setObjectName("panel_title")
        panel.add_block(snap_title)
        self.btn_policy_export = QPushButton("导出策略快照")
        self.btn_policy_export.setObjectName("btn_outline")
        self.btn_policy_export.setToolTip(
            "导出规则配置、黑白名单与策略设置。不含事件 / 封禁 / 审计等运行数据，"
            "也不含 Webhook 地址、镜像代理等本机凭据。"
        )
        self.btn_policy_export.clicked.connect(lambda: _policy_export(self))
        self.btn_policy_import = QPushButton("导入策略快照")
        self.btn_policy_import.setObjectName("btn_outline")
        self.btn_policy_import.setToolTip(
            "导入前自动备份当前配置，失败可回滚；导入后建议重启服务使全部设置生效。"
        )
        self.btn_policy_import.clicked.connect(lambda: _policy_import(self))
        panel.add("", (self.btn_policy_export, self.btn_policy_import))

        self.lbl_db_state = QLabel("")
        self.lbl_db_state.setObjectName("form_hint")
        self.lbl_db_state.setWordWrap(True)
        self.lbl_db_state.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        panel.add_block(self.lbl_db_state, span=False)

        # 数据库备份明细同样改成下拉：与离线库那张同款，避免滚动区里表格被遮挡
        self.cb_db_bak = _backup_picker()
        self.cb_db_bak.currentIndexChanged.connect(self._show_db_bak_detail)
        panel.add("可恢复备份", self.cb_db_bak)

        self.lbl_db_bak = QLabel("")
        self.lbl_db_bak.setObjectName("form_hint")
        self.lbl_db_bak.setWordWrap(True)
        self.lbl_db_bak.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        panel.add_block(self.lbl_db_bak, span=False)

        self.btn_db_restore = QPushButton("恢复到选定备份")
        self.btn_db_restore.setObjectName("btn_danger")
        self.btn_db_restore.setToolTip(
            "用选中的备份整份覆盖当前数据库 —— 备份之后产生的数据会全部消失。\n"
            "恢复前会自动再备份一次当前库，所以反悔了还能再恢复回来；\n"
            "恢复期间数据库短暂不可用，完成后写入器自动重启。"
        )
        self.btn_db_restore.clicked.connect(self._db_restore)
        self._db_buttons.append(self.btn_db_restore)
        panel.add("", self.btn_db_restore)

    # ── 若干 helper delegate（父页旧用法直接调用本页实例方法）──
    def _scroll_to_section(self, page, lay, i):
        from gui.page_common import _scroll_to_section as _impl

        return _impl(page, lay, i)

    def _sw_label(self, text: str) -> QLabel:
        return _sw_label(text)

    # ── 信号转发桩：父页为 None（纯构造自检）时不炸 ──
    def _emit_xdb_check(self) -> None:
        sig = self.xdb_check_requested
        if sig is not None:
            sig.emit()

    def _emit_xdb_sync(self) -> None:
        sig = self.xdb_sync_requested
        if sig is not None:
            sig.emit(False)

    def _emit_geo_reload(self) -> None:
        sig = self.geo_reload_requested
        if sig is not None:
            sig.emit()

    def _emit_logs_open(self) -> None:
        sig = self.logs_open_requested
        if sig is not None:
            sig.emit()

    # ── 自定义镜像源 ──
    def _xdb_items(self) -> List[str]:
        """下拉列表里已确认的条目（不含输入框里尚未「添加」的那一条）。"""
        return [
            self.cb_xdb_source.itemText(i).strip()
            for i in range(self.cb_xdb_source.count())
            if self.cb_xdb_source.itemText(i).strip()
        ]

    def _xdb_sources(self) -> List[str]:
        """要落库的全部源：列表条目 + 当前输入框内容（用户随手打了没点「添加」也不丢）。"""
        out: List[str] = []
        seen = set()
        texts = self._xdb_items()
        texts.append(self.cb_xdb_source.currentText())
        for raw in texts:
            t = (raw or "").strip()
            if not t or t in seen:
                continue
            seen.add(t)
            out.append(t)
            if len(out) >= xdb_updater.MAX_CUSTOM_SOURCES:
                break
        return out

    def _set_xdb_sources(self, items: List[str]) -> None:
        """回填下拉（load 用）。屏蔽信号，否则会点亮「未保存」。"""
        self.cb_xdb_source.blockSignals(True)
        self.cb_xdb_source.clear()
        for t in list(items)[: xdb_updater.MAX_CUSTOM_SOURCES]:
            self.cb_xdb_source.addItem(t)
        if self.cb_xdb_source.count():
            self.cb_xdb_source.setCurrentIndex(0)
        else:
            self.cb_xdb_source.setCurrentIndex(-1)
            self.cb_xdb_source.setEditText("")
        self.cb_xdb_source.blockSignals(False)
        self._refresh_xdb_src_hint()

    def _refresh_xdb_src_hint(self, *_args) -> None:
        """右侧小字：告诉用户「填了几条、按什么顺序生效」。"""
        items = self._xdb_items()
        pending = self.cb_xdb_source.currentText().strip()
        extra = 1 if pending and pending not in items else 0
        n = len(items) + extra
        if n:
            self.lbl_xdb_src.setText(f"已填 {n} 条，按列表顺序依次尝试")
        else:
            self.lbl_xdb_src.setText("未填 → 只用内置源")
        # 只有「输入框里有字」或「列表非空」时才有东西可删
        self.btn_xdb_src_del.setEnabled(bool(pending) or bool(items))

    def _add_xdb_source(self) -> None:
        text = self.cb_xdb_source.currentText().strip()
        if not text:
            return
        if text in self._xdb_items():
            self._refresh_xdb_src_hint()
            return
        if self.cb_xdb_source.count() >= xdb_updater.MAX_CUSTOM_SOURCES:
            self._refresh_xdb_src_hint()
            return
        self.cb_xdb_source.addItem(text)
        self.cb_xdb_source.setCurrentIndex(self.cb_xdb_source.count() - 1)
        self._refresh_xdb_src_hint()
        self._dirty_cb()

    def _del_xdb_source(self) -> None:
        idx = self.cb_xdb_source.currentIndex()
        if idx < 0:
            # 只是打了字还没入列表：清空输入框即可
            self.cb_xdb_source.setEditText("")
        else:
            self.cb_xdb_source.removeItem(idx)
            if self.cb_xdb_source.count():
                self.cb_xdb_source.setCurrentIndex(min(idx, self.cb_xdb_source.count() - 1))
            else:
                self.cb_xdb_source.setCurrentIndex(-1)
                self.cb_xdb_source.setEditText("")
        self._refresh_xdb_src_hint()
        self._dirty_cb()

    # ── 离线库备份与回滚 ──
    def refresh_xdb_state(self) -> None:
        # 备份列表只依赖备份目录，不依赖 xdb_service —— 放在最前面刷新，
        # 即使离线库状态读不出来（服务还没起）它也照样列得出来
        self._refresh_backups()
        try:
            from app.xdb_service import get_service

            s = get_service().summary()
        except Exception:
            log.exception("读取离线库状态失败")
            return

        files = s.get("files", {})
        lines = []
        for name, d in files.items():
            label = "IPv4 库" if "_v4" in name else "IPv6 库"
            size = f"{d.get('size', 0) / 1048576:.1f} MB" if d.get("exists") else "缺失"
            when = ms_to_str(d.get("synced_at")) if d.get("synced_at") else "随程序内置"
            src = d.get("source", "")
            if src:
                try:
                    src = src.split("/")[2]
                except Exception:
                    src = ""
            lines.append(
                f"{label}：{size} · 本地文件 {ms_to_str(d.get('mtime'))} · "
                f"上次同步 {when}" + (f"（源 {src}）" if src else "")
            )
        last_check = ms_to_str(s.get("last_check_at")) if s.get("last_check_at") else "从未检查"
        lines.append(f"上次检查：{last_check}")
        if s.get("last_result"):
            lines.append(f"最近结果：{s['last_result']}")
        self.lbl_xdb_state.setText("\n".join(lines))

        self.tg_xdb_auto.setChecked(cfg.get_bool("xdb_auto_sync", True))
        self.sp_xdb_interval.setValue(cfg.get_int("xdb_sync_interval_hours", 24))
        self.tg_xdb_start.setChecked(cfg.get_bool("xdb_sync_on_start", True))
        self.tg_xdb_download.setChecked(cfg.get_bool("xdb_auto_download", True))
        if not s.get("busy"):
            self.lbl_xdb_progress.setText("待命中")

    def on_xdb_progress(self, stage: str, message: str, percent: int) -> None:
        """由主窗口事件泵调用（Qt 主线程）"""
        self.xdb_bar.setValue(max(0, min(100, int(percent))))
        self.lbl_xdb_progress.setText(f"[{stage}] {message}")
        color = C.text_muted
        if stage == "failed":
            color = C.danger
        elif stage == "done":
            color = C.success
        elif stage in ("download", "verify", "apply", "reload", "check"):
            color = C.warning
        self.lbl_xdb_progress.setStyleSheet(f"color:{color};font-size:13.5px;")
        if stage in ("done", "uptodate", "failed"):
            self.refresh_xdb_state()

    def _force_sync(self) -> None:
        if (
            QMessageBox.question(
                self,
                "强制重新下载",
                "将忽略版本指纹，重新下载全部离线库并覆盖本地文件。\n"
                "用于修复疑似损坏的库；下载前会自动备份，失败会回滚。\n\n继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        sig = self.xdb_sync_requested
        if sig is not None:
            sig.emit(True)

    def _refresh_backups(self) -> None:
        """列出可回滚的备份：**按库分组**（IPv4 一段、IPv6 一段），组内新在前。"""
        try:
            groups = xdb_updater.group_backups()
        except Exception:
            log.exception("读取离线库备份失败")
            groups = {}

        rows: List[Dict] = []
        for name in XDB_UPSTREAM:
            rows.extend(groups.get(name, []))
        self._bak_rows = rows

        labels = []
        for item in rows:
            name = xdb_updater.backup_group(str(item.get("file", "")))
            labels.append(
                f"{_xdb_label(name)} · {item.get('file', '')} · {ms_to_str(item.get('mtime'))}"
            )
        _fill_backup_picker(self.cb_bak, labels)

        has = bool(rows)
        self.cb_bak.setEnabled(has)
        self.btn_bak_restore.setEnabled(has)
        if has:
            counts = " · ".join(
                f"{_xdb_label(n)} {len(groups.get(n, []))} 份" for n in XDB_UPSTREAM if n in groups
            )
            text = (
                f"{counts}。回滚前会自动备份当前库，回滚错了还能再回滚回来"
                f"（每个库只保留最近 {maintenance.KEEP_BACKUPS_PER_FILE} 份）。"
            )
        else:
            text = "尚无备份。每次在线同步换库前都会自动备份，届时这里会列出可回滚的版本。"
        self._bak_summary = text
        self._show_bak_detail()
        self.lbl_bak.setStyleSheet(f"color:{C.text_muted};font-size:13.5px;")

    def _restore_backup(self) -> None:
        row = _picker_index(self.cb_bak)
        if not 0 <= row < len(self._bak_rows):
            return
        item = self._bak_rows[row]
        name = xdb_updater.backup_group(str(item.get("file", "")))
        path = str(item.get("path", ""))
        file_name = str(item.get("file", ""))
        label = _xdb_label(name)

        if (
            QMessageBox.question(
                self,
                "回滚离线库",
                f"将把{label}回滚到这份备份：\n{file_name}\n\n"
                "· 回滚前会自动备份当前库，回滚错了还能再回滚回来；\n"
                "· 回滚成功后热加载，不需要重启程序；\n"
                "· 若提示热加载失败，文件已经换掉，重启程序才生效。\n\n继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        try:
            ok, err = xdb_updater.restore_backup(name, path)
        except Exception as e:
            log.exception("回滚离线库失败")
            audit.record(
                audit.ACTION_XDB_ROLLBACK,
                target_type="xdb",
                target_id=file_name,
                summary=f"回滚{label}失败：{e}",
                result=audit.RESULT_FAIL,
            )
            QMessageBox.warning(self, "回滚失败", str(e))
            return

        # 回滚会换掉归属地库 —— 之后所有 IP 的判定结果都可能变，必须留痕
        audit.record(
            audit.ACTION_XDB_ROLLBACK,
            target_type="xdb",
            target_id=file_name,
            summary=f"回滚{label}到 {file_name}" + ("" if ok else f"（未完成：{err}）"),
            before={"lib": name},
            after={"lib": name, "file": file_name, "ok": ok},
            result=audit.RESULT_OK if ok else audit.RESULT_FAIL,
            detail=err or "",
        )

        # 回滚本身也产生了一份新备份，列表与「当前库」两处都要跟着变
        self._refresh_backups()
        self._refresh_lib_views()
        if ok:
            QMessageBox.information(self, "回滚完成", f"{label}已回滚到：\n{file_name}")
        else:
            QMessageBox.warning(self, "回滚未完成", err or "未知错误")

    def _refresh_lib_views(self) -> None:
        """回滚后刷新两处「离线库状态」显示（本页 + IP 查询页）。"""
        # DataPage 自身就是权威实现；父页瘦身后经 __getattr__ 转回本页
        self.refresh_xdb_state()
        with contextlib.suppress(Exception):
            page = getattr(self.window(), "page_iplookup", None)
            fn2 = getattr(page, "_update_lib_info", None)
            if callable(fn2):
                fn2()

    # ── 数据库维护（整理 / 重建索引 / 备份 / 恢复）──
    def _scroll_to_db_section(self) -> None:
        """把数据库文件区滚进视野（WAL 提示条上的「去整理」）。"""
        with contextlib.suppress(Exception):
            tabs = getattr(self._parent, "tabs", None)
            if tabs is not None:
                tabs.setCurrentWidget(self.tab_data)
            self._data_scroll.ensureWidgetVisible(self._db_anchor, 0, 12)
            self.btn_db_vacuum.setFocus()

    def refresh_db_state(self) -> None:
        """刷新「数据库大小」与备份列表（构造、切到本 tab、任务结束后各调一次）"""
        try:
            sz = db_size()
            self.lbl_dbsize.setText(
                f"总计 {maintenance.format_size(sz['total'])}"
                f"（主库 {maintenance.format_size(sz['main'])}"
                f" · WAL {maintenance.format_size(sz['wal'])}"
                f" · 共享索引 {maintenance.format_size(sz['shm'])}）"
            )
        except Exception:
            log.exception("读取数据库大小失败")
            self.lbl_dbsize.setText("读取失败")
        self._refresh_db_backups()

    def _refresh_db_backups(self) -> None:
        try:
            rows = maintenance.list_db_backups()
        except Exception:
            log.exception("读取数据库备份失败")
            rows = []
        self._db_rows = rows

        labels = [f"{item.get('file', '')} · {ms_to_str(item.get('mtime'))}" for item in rows]
        _fill_backup_picker(self.cb_db_bak, labels)

        has = bool(rows)
        self.cb_db_bak.setEnabled(has and not self._db_busy)
        self.btn_db_restore.setEnabled(has and not self._db_busy)
        if has:
            text = (
                f"共 {len(rows)} 份，最多保留 {maintenance.KEEP_DB_BACKUPS} 份"
                "（更早的在下次备份时自动删除）。"
            )
        else:
            text = "尚无数据库备份。先点「立即备份」打一份快照，之后才能恢复。"
        self._db_bak_summary = text
        self._show_db_bak_detail()
        self.lbl_db_bak.setStyleSheet(f"color:{C.text_muted};font-size:13.5px;")

    def _db_run(self, kind: str, fn) -> None:
        """把耗时任务丢到后台线程，同一时刻只允许一个。"""
        if self._db_busy:
            return
        self._db_busy = True
        self._set_db_busy(True, DB_TASK_TEXT.get(kind, "处理中…"))

        def work() -> None:
            try:
                ok, msg = fn()
            except Exception as e:  # 兜底：绝不让异常死在后台线程里
                log.exception("数据库维护任务异常：%s", kind)
                ok, msg = False, str(e)
            sig = self.db_task_done
            if sig is not None:
                sig.emit((kind, ok, msg))

        threading.Thread(target=work, daemon=True, name=f"db-{kind}").start()

    def _set_db_busy(self, busy: bool, text: str = "") -> None:
        for b in self._db_buttons:
            b.setEnabled(not busy)
        if busy:
            self.lbl_db_state.setText(text)
            self.lbl_db_state.setStyleSheet(f"color:{C.warning};font-size:13.5px;")
            QApplication.setOverrideCursor(Qt.CursorShape.BusyCursor)
            self._db_cursor = True
        else:
            # 只还原自己压上去的那一个：无条件 restore 会把别处压的光标也弹掉
            if self._db_cursor:
                with contextlib.suppress(Exception):
                    QApplication.restoreOverrideCursor()
                self._db_cursor = False
            self.btn_db_restore.setEnabled(bool(self._db_rows))
        # 任务跑的时候连「换选另一份备份」也一起锁住，避免恢复中途改选择
        self.cb_db_bak.setEnabled(not busy and bool(self._db_rows))

    def _on_db_task_done(self, res: Any) -> None:
        """后台任务结束（Qt 主线程）：恢复按钮、刷新状态、留痕。"""
        try:
            kind, ok, msg = res
        except Exception:
            log.exception("数据库维护结果格式异常：%r", res)
            self._db_busy = False
            self._set_db_busy(False)
            return

        self._db_busy = False
        self._set_db_busy(False)
        self.refresh_db_state()

        if ok:
            text = f"✓ 已备份：{msg}" if kind == "backup" else f"✓ {msg}"
        else:
            text = f"✗ {DB_TASK_NAME.get(kind, kind)}失败：{msg}"
        self.lbl_db_state.setText(text)
        self.lbl_db_state.setStyleSheet(f"color:{C.success if ok else C.danger};font-size:13.5px;")

        self._audit_db_task(kind, ok, msg)

        # 恢复换掉的是整份库，设置也可能跟着换（备份来自另一时刻的库）：
        # 表单按新库重读一遍，且不能因此点亮「未保存」—— 冒泡到父页做全量重载
        if kind == "restore" and ok:
            self._reload_cb()

    def _audit_db_task(self, kind: str, ok: bool, msg: str) -> None:
        """整理 / 备份 / 恢复都要留痕：事后能回答「库是哪天被换掉的」。"""
        result = audit.RESULT_OK if ok else audit.RESULT_FAIL
        if kind == "restore":
            audit.record(
                audit.ACTION_DB_RESTORE,
                target_type="database",
                target_id=db_path(),
                summary=("恢复数据库：" if ok else "恢复数据库失败：") + msg,
                result=result,
                detail=msg,
            )
        elif kind == "backup":
            audit.record(
                audit.ACTION_DB_BACKUP,
                target_type="database",
                target_id=msg if ok else "",
                summary="备份数据库" + ("成功" if ok else f"失败：{msg}"),
                result=result,
            )
        else:
            audit.record(
                audit.ACTION_DB_MAINTENANCE,
                target_type="database",
                summary=("整理数据库（VACUUM）：" if kind == "vacuum" else "重建索引：") + msg,
                result=result,
                detail=msg,
            )

    def _db_backup_now(self) -> None:
        self._db_run("backup", maintenance.backup_db)

    def _db_restore(self) -> None:
        row = _picker_index(self.cb_db_bak)
        if not 0 <= row < len(self._db_rows):
            QMessageBox.information(self, "无法恢复", "请先在下拉框里选中一份备份。")
            return
        item = self._db_rows[row]
        file_name = str(item.get("file", ""))
        size = maintenance.format_size(int(item.get("size", 0) or 0))
        when = ms_to_str(item.get("mtime"))

        # 默认按钮必须是「否」：这是全项目唯一一个「点错就永久丢数据」的按钮
        if (
            QMessageBox.question(
                self,
                "恢复数据库",
                f"将用这份备份整份覆盖当前数据库：\n{file_name}\n"
                f"大小 {size} · 备份于 {when}\n\n"
                "· 备份之后产生的数据会全部消失（访问记录、风险事件、封禁账本、操作审计）；\n"
                "· 恢复前会自动再备份一次当前库，所以反悔了还能再恢复回来；\n"
                "· 恢复期间数据库短暂不可用，完成后写入器自动重启。\n\n确认恢复？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        self._db_run("restore", lambda: maintenance.restore_db(str(item.get("path", ""))))

    def _show_bak_detail(self) -> None:
        """下拉选中项的完整明细（库 / 文件 / 大小 / 时间），替代原来的 4 列表格"""
        rows = list(getattr(self, "_bak_rows", []) or [])
        i = _picker_index(self.cb_bak)
        base = str(getattr(self, "_bak_summary", "") or "")
        if not 0 <= i < len(rows):
            self.lbl_bak.setText(base)
            return
        item = rows[i]
        name = xdb_updater.backup_group(str(item.get("file", "")))
        size_mb = int(item.get("size", 0) or 0) / 1048576
        detail = (
            f"当前选择：{_xdb_label(name)} · {item.get('file', '')} · "
            f"{size_mb:.1f} MB · 备份于 {ms_to_str(item.get('mtime'))}"
        )
        self.lbl_bak.setText(f"{base}\n{detail}" if base else detail)

    def _show_db_bak_detail(self) -> None:
        rows = list(getattr(self, "_db_rows", []) or [])
        i = _picker_index(self.cb_db_bak)
        base = str(getattr(self, "_db_bak_summary", "") or "")
        if not 0 <= i < len(rows):
            self.lbl_db_bak.setText(base)
            return
        item = rows[i]
        detail = (
            f"当前选择：{item.get('file', '')} · "
            f"{maintenance.format_size(int(item.get('size', 0) or 0))} · "
            f"备份于 {ms_to_str(item.get('mtime'))}"
        )
        self.lbl_db_bak.setText(f"{base}\n{detail}" if base else detail)

    # ── 保留期预设 ──
    def _on_retention_preset(self, idx: int) -> None:
        """选了某个档位 → 一次写进四个 SpinBox（保存时才落库）"""
        if self._retention_preset_guard or idx < 0 or idx >= len(RETENTION_PRESETS):
            return  # 「自定义」：保持四项现值，让用户自己调
        days = RETENTION_PRESETS[idx]
        self._retention_preset_guard = True
        try:
            for sp in (
                self.sp_retention,
                self.sp_risk_retention,
                self.sp_ban_retention,
                self.sp_audit_retention,
            ):
                sp.setValue(days)
        finally:
            self._retention_preset_guard = False

    def _sync_retention_combo(self, *_args: int) -> None:
        """四个 SpinBox 的组合值若等于某个档位就回显该档位，否则显示「自定义」。"""
        if getattr(self, "_retention_preset_guard", False):
            return
        values = {
            self.sp_retention.value(),
            self.sp_risk_retention.value(),
            self.sp_ban_retention.value(),
            self.sp_audit_retention.value(),
        }
        custom = len(RETENTION_PRESETS)
        if len(values) == 1:
            only = values.pop()
            if only in RETENTION_PRESETS:
                custom = RETENTION_PRESETS.index(only)
        guard = self._retention_preset_guard
        self._retention_preset_guard = True
        try:
            self.cb_retention.setCurrentIndex(custom)
        finally:
            self._retention_preset_guard = guard

    # ── 清理日志 ──
    def _clean_logs(self) -> None:
        """手动立即清理：四张表 + 磁盘上的过期日志文件。"""
        rows = maintenance.cleanup_logs()
        risk = maintenance.cleanup_risk()
        bans = maintenance.cleanup_bans()
        n_files = maintenance.cleanup_log_files()
        audit.record(
            audit.ACTION_DATA_CLEANUP,
            target_type="data",
            summary=f"手动清理：访问 {rows}、事件 {risk}、封禁 {bans}、日志文件 {n_files}",
            after={
                "access_log": rows,
                "risk_event": risk,
                "ban_list": bans,
                "log_files": n_files,
            },
        )
        QMessageBox.information(
            self,
            "完成",
            f"已清理访问记录 {rows} 条、风险事件 {risk} 条、终态封禁记录 {bans} 条，"
            f"以及 {n_files} 个过期日志文件。\n\n"
            f"保留期：访问 {self.sp_retention.value()} 天 / "
            f"事件 {self.sp_risk_retention.value()} 天 / "
            f"封禁 {self.sp_ban_retention.value()} 天。\n"
            f"「已封禁」和「处理中」的封禁记录不会被清理。\n\n"
            f"日志文件：{log_file()}",
        )

    def _clear_logs(self) -> None:
        if (
            QMessageBox.question(
                self,
                "清空日志",
                "将删除全部访问日志与风险事件（不影响封禁列表）。\n\n确认继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        data_service.clear_all_logs_with_audit()
        QMessageBox.information(self, "完成", "日志已清空。")
