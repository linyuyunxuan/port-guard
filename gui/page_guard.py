"""PortGuard — 设置页「防护与告警」子页

从 `gui.page_settings` 拆出（P2⑤）：负责『告警封禁』tab 的控件构建与展示。
save/load 生命周期仍由父页 `SettingsPage` 统一持有；本页控件改动经构造时注入的
`dirty_cb` 点亮父页「●未保存」。toggle handler / webhook 测试 / 告警测试留在本页。

对外扁平属性面（`page.tg_auto` / `page.sp_duration` …）由父页 `__getattr__`
转发到本页实例，测试与主窗口的既有引用保持不变。
"""

from typing import Callable, Optional

from core.config import (
    BAN_DURATION_TIER_DEFAULTS,
    DEFAULT_ESCALATION_FACTOR,
    DEFAULT_ESCALATION_MAX_SEC,
    DEFAULT_REPEAT_BLACKLIST_HITS,
    LEVEL_CRITICAL,
    LEVEL_HIGH,
    LEVEL_LABEL,
    LEVEL_LOW,
    LEVEL_MEDIUM,
    MAX_BAN_DURATION_DEFAULT_SEC,
)
from core.logger import get_logger
from gui.background import run_in_background
from gui.page_common import (
    _add_section_index,
    _Panel,
    _row_widget,
    _scroll_page,
    _sw_label,
)
from gui.widgets import ToggleSwitch, WarnBanner
from qtcompat import (
    QComboBox,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

log = get_logger(__name__)

LEVEL_ITEMS = [LEVEL_LOW, LEVEL_MEDIUM, LEVEL_HIGH, LEVEL_CRITICAL]
LEVEL_LABELS = [LEVEL_LABEL[x] for x in LEVEL_ITEMS]


class GuardPage(QWidget):
    """『防护与告警』tab：告警封禁相关控件构建 + 展示。

    Args:
        parent: 父页 SettingsPage。控件改动经 `dirty_cb` 点亮父页「未保存」；
            脚本/测试把 `parent` 设为 None 纯构造也行（仅供自检）。
        dirty_cb: 控件改动回调（父页 `_mark_dirty`）。
    """

    def __init__(self, parent: Optional[QWidget] = None, dirty_cb: Optional[Callable] = None):
        super().__init__(parent)
        self._parent = parent
        self._dirty_cb = dirty_cb or (lambda *_a: None)
        self._webhook_testing = False
        self.build()

    # ── 控件构建 ──
    def build(self) -> QScrollArea:
        page, lay = _scroll_page()
        self._section_guard = _add_section_index(
            page, lay, "② 防护与告警", ["封禁策略", "告警通知"]
        )
        self.tab_guard = page

        ban = _Panel("封禁策略")

        self.tg_auto = ToggleSwitch(False)
        self.tg_auto.toggled.connect(self._on_auto_toggle)
        self.lbl_auto = QLabel("")
        self.lbl_auto.setObjectName("form_hint")
        ban.add("自动封禁模式", _row_widget(self.tg_auto, self.lbl_auto, spacing=10))

        # 仅自动模式开启时出现（P1-4）
        self.warn_auto = WarnBanner(
            "自动模式会跳过人工确认直接写入 Windows 防火墙，请先确认规则阈值与默认时长再开启。",
            level="danger",
        )
        self.warn_auto.setVisible(False)
        ban.add_block(self.warn_auto)

        self.sp_threshold = QSpinBox()
        self.sp_threshold.setRange(1, 100)
        self.sp_threshold.setValue(90)
        self.sp_threshold.setFixedWidth(120)

        self.sp_duration = QSpinBox()
        self.sp_duration.setRange(0, 365 * 24 * 60)
        self.sp_duration.setValue(60)
        self.sp_duration.setSuffix(" 分钟（0=永久）")
        self.sp_duration.setSpecialValueText("永久")
        self.sp_duration.setFixedWidth(180)

        # ── 按风险等级分档的封禁时长 ──
        def _tier_spin(level: str) -> QSpinBox:
            sp = QSpinBox()
            sp.setRange(0, 365 * 24 * 60)
            sp.setValue(BAN_DURATION_TIER_DEFAULTS[level] // 60)
            sp.setSuffix(" 分钟（0=不分档）")
            sp.setSpecialValueText("不分档")
            sp.setFixedWidth(200)
            return sp

        self.sp_dur_critical = _tier_spin(LEVEL_CRITICAL)
        self.sp_dur_high = _tier_spin(LEVEL_HIGH)
        self.sp_dur_medium = _tier_spin(LEVEL_MEDIUM)
        self.sp_dur_low = _tier_spin(LEVEL_LOW)

        # ── 重复封禁递增 ──
        self.tg_escalation = ToggleSwitch(False)
        self.tg_escalation.toggled.connect(self._on_escalation_toggle)

        self.sp_esc_factor = QSpinBox()
        self.sp_esc_factor.setRange(1, 10)
        self.sp_esc_factor.setValue(DEFAULT_ESCALATION_FACTOR)
        self.sp_esc_factor.setSuffix(" 倍")
        self.sp_esc_factor.setFixedWidth(120)

        self.sp_esc_max = QSpinBox()
        self.sp_esc_max.setRange(1, 365 * 24)
        self.sp_esc_max.setValue(DEFAULT_ESCALATION_MAX_SEC // 3600)
        self.sp_esc_max.setSuffix(" 小时")
        self.sp_esc_max.setFixedWidth(160)

        # ── 最大封禁时长（硬上限）──
        self.sp_max_ban = QSpinBox()
        self.sp_max_ban.setRange(1, 365)
        self.sp_max_ban.setValue(MAX_BAN_DURATION_DEFAULT_SEC // 86400)
        self.sp_max_ban.setSuffix(" 天")
        self.sp_max_ban.setFixedWidth(120)

        ban.add("自动封禁最低评分", self.sp_threshold)
        ban.add("默认封禁时长", self.sp_duration)
        ban.add("严重档时长", self.sp_dur_critical)
        ban.add("高档时长", self.sp_dur_high)
        ban.add("中档时长", self.sp_dur_medium)
        ban.add("低档时长", self.sp_dur_low)
        ban.add("重复封禁递增", _row_widget(self.tg_escalation, spacing=10))
        ban.add("递增倍数", self.sp_esc_factor)
        ban.add("递增封顶", self.sp_esc_max)
        ban.add("最大封禁时长", self.sp_max_ban)

        # ── 惯犯升级：已封禁 IP 反复访问 → 直接列入黑名单（永久）──
        self.tg_escalate = ToggleSwitch(True)
        self.sp_escalate_hits = QSpinBox()
        self.sp_escalate_hits.setRange(1, 9999)
        self.sp_escalate_hits.setValue(DEFAULT_REPEAT_BLACKLIST_HITS)
        self.sp_escalate_hits.setSuffix(" 次")
        self.sp_escalate_hits.setFixedWidth(120)
        self.sp_escalate_hits.setToolTip(
            "封禁期间累计被拦下多少次后列入黑名单。\n"
            "升级后该 IP 变为永久封禁，并在黑名单里留档（重启仍然生效）。"
        )
        ban.add(
            "惯犯升级黑名单",
            _row_widget(self.tg_escalate, self._sw_label("封了还在撞就永久封"), spacing=10),
        )
        ban.add("升级阈值", self.sp_escalate_hits)

        hint_strategy = QLabel(
            "时长优先级：规则指定 > 重复封禁递增 > 风险等级分档 > 默认封禁时长。"
            "「不分档」表示该等级沿用默认封禁时长；递增以等级档位为基准，"
            "同一 IP 每多一次历史封禁记录就乘一次倍数，直到封顶值。"
            "手动封禁对话框仍以「默认封禁时长」为初始值，可随时改。"
            "「最大封禁时长」是硬上限：任何有限时长都会被截断到它以内"
            "（防火墙规则不会自己到期，程序长期不在时没人会解，所以别设太长）；"
            "「永久封禁」（时长填 0）不受这个上限影响。"
            "「惯犯升级」针对封了还在撞的 IP：达到阈值就直接写进黑名单（永久封禁），"
            "省掉到期重来的循环；次数记在封禁记录上，动作会进审计。"
        )
        hint_strategy.setObjectName("hint")
        hint_strategy.setWordWrap(True)
        ban.add_block(hint_strategy, span=False)

        self.lbl_perm = QLabel("")
        self.lbl_perm.setWordWrap(True)
        ban.add("权限状态", self.lbl_perm)
        lay.addWidget(ban)

        alert = _Panel("告警通知")
        self.tg_sound = ToggleSwitch(True)
        self.lbl_popup_note = QLabel("仅托盘气泡（右下角），不再弹出窗口")
        self.lbl_popup_note.setObjectName("hint")
        self.sp_merge = QSpinBox()
        self.sp_merge.setRange(0, 3600)
        self.sp_merge.setValue(60)
        self.sp_merge.setSuffix(" 秒")
        self.sp_merge.setFixedWidth(120)

        # ── 已拦截（该 IP 已在封禁中）的重复命中 ──
        self.tg_block_silent = ToggleSwitch(True)
        self.tg_block_silent.setToolTip(
            "关闭后，已封禁 IP 的每一次命中都会照常提醒（攻击期会被刷屏）。"
        )

        b_test = QPushButton("测试告警")
        b_test.setObjectName("btn_outline")
        b_test.clicked.connect(self._test_alert)

        alert.add("声音提示", self.tg_sound)
        alert.add("提醒方式", self.lbl_popup_note)
        alert.add("同 IP 合并窗口", self.sp_merge)
        alert.add(
            "已拦截不再提醒",
            _row_widget(self.tg_block_silent, self._sw_label("只累计拦截次数"), spacing=10),
        )

        # ── 外部推送（Webhook）──
        self.tg_webhook = ToggleSwitch(False)
        self.tg_webhook.toggled.connect(self._on_webhook_toggle)
        self.cb_webhook_level = QComboBox()
        self.cb_webhook_level.addItems(LEVEL_LABELS)
        self.cb_webhook_level.setCurrentIndex(len(LEVEL_LABELS) - 1)  # 默认只推「严重」
        self.cb_webhook_level.setFixedWidth(110)

        self.ed_webhook = QLineEdit()
        self.ed_webhook.setPlaceholderText("https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=…")
        self.ed_webhook.setMinimumWidth(320)
        self.ed_webhook.setMaximumWidth(560)
        self.ed_webhook.setToolTip(
            "企业微信 / 钉钉群机器人地址，或任意接受 "
            '{"msgtype":"text","text":{"content":"..."}} 的告警网关。\n'
            "只允许 http/https，且不允许指向本机 / 内网地址（防 SSRF）。\n"
            "地址里通常带密钥：日志与错误提示只会显示 scheme://host。"
        )
        self.btn_webhook_test = QPushButton("发送测试消息")
        self.btn_webhook_test.setObjectName("btn_outline")
        self.btn_webhook_test.clicked.connect(self._test_webhook)

        alert.add(
            "推送级别",
            _row_widget(
                self.tg_webhook,
                self._sw_label("启用外部推送"),
                self.cb_webhook_level,
                spacing=8,
            ),
        )
        alert.add("推送地址", _row_widget(self.ed_webhook, self.btn_webhook_test))
        alert.add("", b_test)
        lay.addWidget(alert)

        note = QLabel(
            "告警一律以托盘气泡（任务栏右下角）提示，不再弹出模态窗口打断操作；"
            "同 IP 在合并窗口内的多次命中只提醒一次。"
            "外部推送用于无人值守场景（企业微信 / 钉钉群机器人），默认关闭。"
        )
        note.setObjectName("hint")
        note.setWordWrap(True)
        lay.addWidget(note)

        lay.addStretch(1)
        # 挂进本页：父页 addTab(guard_page) 使用本 widget
        _root = QVBoxLayout(self)
        _root.setContentsMargins(0, 0, 0, 0)
        _root.addWidget(page)
        self.setLayout(_root)
        return page

    # 为保持与父页旧用法一致，提供 _scroll_to_section 委托（分区导航滚动用）
    def _scroll_to_section(self, page, lay, i):
        from gui.page_common import _scroll_to_section as _impl

        return _impl(page, lay, i)

    def _sw_label(self, text: str) -> QLabel:
        return _sw_label(text)

    # ── toggle handler ──
    def _on_auto_toggle(self, on: bool) -> None:
        self.sp_threshold.setEnabled(on)
        self.lbl_auto.setText(
            "已开启：命中且评分达标将自动封禁"
            if on
            else "已关闭（推荐）：仅生成建议，人工确认后执行"
        )
        self.warn_auto.setVisible(bool(on))

    def _on_escalation_toggle(self, on: bool) -> None:
        """递增关闭时倍数 / 封顶没有意义，置灰避免用户以为改了会生效"""
        self.sp_esc_factor.setEnabled(on)
        self.sp_esc_max.setEnabled(on)
        self.sp_escalate_hits.setEnabled(on)

    def _on_webhook_toggle(self, on: bool) -> None:
        self.ed_webhook.setEnabled(on)
        self.cb_webhook_level.setEnabled(on)
        self.btn_webhook_test.setEnabled(on)

    # ── 告警测试 ──
    def _test_alert(self) -> None:
        from core.alerts import Alerter

        a = Alerter(tray=getattr(self.window(), "tray", None), parent_widget=self)
        a._last_alert.clear()
        a.notify(
            {
                "ip": "203.0.113.10",
                "level": "critical",
                "score": 95,
                "reason": "这是一条测试告警",
                "geo": "测试·测试·测试",
                "local_port": 8080,
            }
        )

    # ── 外部推送（Webhook）测试 ──
    def _test_webhook(self) -> None:
        from core import alert_webhook

        url = self.ed_webhook.text().strip()
        ok, why = alert_webhook.validate_url(url)
        if not ok:
            QMessageBox.warning(self, "推送地址不可用", why)
            return
        if getattr(self, "_webhook_testing", False):
            return
        self._webhook_testing = True
        self.btn_webhook_test.setEnabled(False)
        self.btn_webhook_test.setText("发送中…")

        level = LEVEL_ITEMS[max(0, min(self.cb_webhook_level.currentIndex(), len(LEVEL_ITEMS) - 1))]
        alert = {
            "ip": "203.0.113.10",
            "level": level,
            "score": 95,
            "reason": "这是一条测试消息（由用户在设置页手动触发）",
            "local_port": 3389,
            "disposition": "alert",
        }
        payload = alert_webhook.build_payload(alert)

        def work():
            return alert_webhook.post(url, payload)

        run_in_background(
            self,
            work,
            self._on_webhook_test_done,
            self._on_webhook_test_failed,
            name="webhook-test",
        )

    def _on_webhook_test_done(self, res) -> None:
        self._reset_webhook_test_button()
        ok, err = res if isinstance(res, tuple) else (False, "返回格式异常")
        from core import alert_webhook

        if ok:
            QMessageBox.information(
                self,
                "推送成功",
                f"测试消息已送达：\n{alert_webhook.mask_url(self.ed_webhook.text().strip())}",
            )
            return
        QMessageBox.warning(
            self,
            "推送失败",
            f"地址：{alert_webhook.mask_url(self.ed_webhook.text().strip())}\n原因：{err}\n\n"
            "常见原因：地址填错、机器人已停用、本机访问不了外网。",
        )

    def _on_webhook_test_failed(self, err: str) -> None:
        self._reset_webhook_test_button()
        log.error("Webhook 测试推送异常：%s", err)
        QMessageBox.warning(self, "推送失败", "发送时发生异常，详情见运行日志。")

    def _reset_webhook_test_button(self) -> None:
        self._webhook_testing = False
        self.btn_webhook_test.setText("发送测试消息")
        self.btn_webhook_test.setEnabled(self.tg_webhook.isChecked())
