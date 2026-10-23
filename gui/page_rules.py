"""PortGuard — 规则配置页

两块内容用下划线 tab 分：风险规则 / 访问规则。

2026-10-23 用户要求：「新增规则里也能选放行和拦截，把黑 / 白名单取消掉」。
于是原来的第三个「黑 / 白名单」tab 被撤掉，名单语义并入「访问规则」的
两个动作：`拦截`（命中即直接封禁）与 `放行`（命中即豁免、永不封禁）。
已有的名单条目由 `app.list_migration` 一次性迁移成等价规则（带备份），
本页只负责呈现与保存，不再有第二个维护名单的入口 ——
同一个 IP「该拦还是该放」只在一个地方回答，不会出现两边对不上的情况。

本轮只改呈现（_design/02_ux_spec.md P1-12、P2-3）：
  · 每张规则卡 = `#panel` 无边框 r8，标题区 14/600 + 说明 12 muted；
  · 参数一行栅格：标签在上、控件在下，控件宽度按类型固定，右端留空吸收余量；
  · 任一改动在标题区亮起「● 未保存」，保存后熄灭 —— 之前只有区域 tab 有圆点；
  · 停用的规则整卡降一级明度（标题变 muted + 「已停用」标记），
    而不是只把控件 setEnabled(False) 后看起来像坏了。
"""

import threading
from typing import Dict, List, Tuple

from app import audit, list_migration
from core.config import (
    LEVEL_CRITICAL,
    LEVEL_HIGH,
    LEVEL_LABEL,
    LEVEL_LOW,
    LEVEL_MEDIUM,
    LEVEL_NORMAL,
)
from core.logger import get_logger
from core.rule_engine import get_engine
from core.rules_meta import RULE_DESCS, RULE_LABELS, RULE_PARAMS
from gui.components import PageHeader
from gui.region_rules import RegionRulesTab
from gui.theme import C
from gui.widgets import CONTENT_MAX_W, ToggleSwitch
from qtcompat import (
    QComboBox,
    QDoubleSpinBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSpinBox,
    Qt,
    QTabWidget,
    QTimer,
    QVBoxLayout,
    QWidget,
    Signal,
)

LEVEL_ITEMS = [LEVEL_NORMAL, LEVEL_LOW, LEVEL_MEDIUM, LEVEL_HIGH, LEVEL_CRITICAL]
LEVEL_ITEM_LABELS = [LEVEL_LABEL[x] for x in LEVEL_ITEMS]
ACTION_ITEMS = [("suggest_ban", "生成封禁建议"), ("alert", "仅告警")]

log = get_logger()


class RuleCard(QFrame):
    """单条规则配置卡片"""

    changed = Signal()  # 任一参数变化（用于页面级「未保存」标记）

    def __init__(self, rule_id: str, cfg: Dict, parent=None):
        super().__init__(parent)
        self.rule_id = rule_id
        self.cfg = dict(cfg)
        self._fields: Dict[str, Tuple[QWidget, str]] = {}
        self.setObjectName("panel")
        # 卡片限宽到内容列（见 gui/widgets.CONTENT_MAX_W）：规则卡最宽的一条
        # （geo_sensitive_port）实测只需 810，铺满 1160 会在右侧空出 350px
        self.setMaximumWidth(CONTENT_MAX_W)
        self._build()

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(6)

        top = QHBoxLayout()
        top.setSpacing(10)
        self.toggle = ToggleSwitch(bool(self.cfg.get("enabled", True)))
        self.name = QLabel(RULE_LABELS.get(self.rule_id, self.rule_id))
        self.name.setStyleSheet(f"color:{C.text_on_dark};font-size:16px;font-weight:600;")
        self.tag_off = QLabel("已停用")
        self.tag_off.setStyleSheet(f"color:{C.text_muted};font-size:11.5px;")

        top.addWidget(self.toggle)
        top.addWidget(self.name)
        top.addWidget(self.tag_off)
        top.addStretch(1)
        lay.addLayout(top)

        desc = QLabel(RULE_DESCS.get(self.rule_id, ""))
        desc.setObjectName("hint")
        desc.setWordWrap(True)
        lay.addWidget(desc)

        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(4)
        grid.setContentsMargins(0, 6, 0, 0)

        col = 0
        # 分值
        grid.addWidget(self._lbl("命中加分"), 0, col)
        self.sp_score = QSpinBox()
        self.sp_score.setRange(0, 100)
        self.sp_score.setValue(int(self.cfg.get("score", 0)))
        self.sp_score.setFixedWidth(90)
        grid.addWidget(self.sp_score, 1, col)
        col += 1

        # 等级
        grid.addWidget(self._lbl("风险等级"), 0, col)
        self.cb_level = QComboBox()
        self.cb_level.addItems(LEVEL_ITEM_LABELS)
        try:
            self.cb_level.setCurrentIndex(LEVEL_ITEMS.index(self.cfg.get("level", LEVEL_MEDIUM)))
        except ValueError:
            self.cb_level.setCurrentIndex(2)
        self.cb_level.setFixedWidth(110)
        grid.addWidget(self.cb_level, 1, col)
        col += 1

        # 动作
        grid.addWidget(self._lbl("命中动作"), 0, col)
        self.cb_action = QComboBox()
        self.cb_action.addItems([x[1] for x in ACTION_ITEMS])
        try:
            self.cb_action.setCurrentIndex(
                [x[0] for x in ACTION_ITEMS].index(self.cfg.get("action", "alert"))
            )
        except ValueError:
            self.cb_action.setCurrentIndex(1)
        self.cb_action.setFixedWidth(140)
        grid.addWidget(self.cb_action, 1, col)
        col += 1

        # 参数
        for p in RULE_PARAMS.get(self.rule_id, []):
            key, typ, label = p["key"], p["type"], p["label"]
            val = self.cfg.get(key)
            grid.addWidget(self._lbl(label), 0, col)

            w: QWidget
            if typ == "int":
                sp = QSpinBox()
                sp.setRange(int(p.get("min", 0)), int(p.get("max", 2_000_000_000)))
                sp.setValue(int(val if val is not None else p.get("min", 0)))
                sp.setFixedWidth(110)
                w = sp
            elif typ == "float":
                dsp = QDoubleSpinBox()
                dsp.setDecimals(2)
                dsp.setSingleStep(0.05)
                dsp.setRange(float(p.get("min", 0)), float(p.get("max", 1)))
                dsp.setValue(float(val if val is not None else 0.5))
                dsp.setFixedWidth(110)
                w = dsp
            elif typ == "list_int":
                le = QLineEdit(",".join(str(x) for x in (val or [])))
                le.setFixedWidth(240)
                w = le
            elif typ == "list_str":
                le2 = QLineEdit(",".join(str(x) for x in (val or [])))
                le2.setFixedWidth(280)
                w = le2
            elif typ == "choice":
                cb = QComboBox()
                opts = list(p.get("options") or [])
                for ov, ol in opts:
                    cb.addItem(str(ol), str(ov))
                cur = str(val if val is not None else (p.get("default") or ""))
                # 配置里的值不在选项里（手改过 rules.json）时回落到第一项，
                # 避免下拉框停在空位、用户一保存就把非法值写回去
                idx = next((i for i, (ov, _ol) in enumerate(opts) if str(ov) == cur), 0)
                cb.setCurrentIndex(idx)
                cb.setFixedWidth(140)
                w = cb
            else:
                w = QLineEdit(str(val or ""))
            grid.addWidget(w, 1, col)
            self._fields[key] = (w, typ)
            col += 1

        grid.setColumnStretch(col, 1)
        lay.addLayout(grid)

        for w2 in (self.sp_score, self.cb_level, self.cb_action):
            self._connect(w2)
        for w3, _typ in self._fields.values():
            self._connect(w3)
        self.toggle.toggled.connect(self._on_toggle)
        self._on_toggle(self.toggle.isChecked())

    def _connect(self, w: QWidget) -> None:
        if isinstance(w, (QSpinBox, QDoubleSpinBox)):
            w.valueChanged.connect(self._emit_changed)
        elif isinstance(w, QComboBox):
            w.currentIndexChanged.connect(self._emit_changed)
        elif isinstance(w, QLineEdit):
            w.textChanged.connect(self._emit_changed)

    def _emit_changed(self, *_args) -> None:
        self.changed.emit()

    @staticmethod
    def _lbl(text: str) -> QLabel:
        lb = QLabel(text)
        lb.setStyleSheet(f"color:{C.text_secondary};font-size:13.5px;")
        return lb

    def _on_toggle(self, on: bool) -> None:
        for w, _typ in self._fields.values():
            w.setEnabled(on)
        self.sp_score.setEnabled(on)
        self.cb_level.setEnabled(on)
        self.cb_action.setEnabled(on)
        # 停用态：降明度 + 明说「已停用」，而不是让控件看起来像坏了
        self.name.setStyleSheet(
            f"color:{C.text_on_dark if on else C.text_muted};font-size:16px;font-weight:600;"
        )
        self.tag_off.setVisible(not on)

    def collect(self) -> Dict:
        out = {
            "enabled": self.toggle.isChecked(),
            "score": self.sp_score.value(),
            "level": LEVEL_ITEMS[self.cb_level.currentIndex()],
            "action": ACTION_ITEMS[self.cb_action.currentIndex()][0],
        }
        for key, (w, typ) in self._fields.items():
            if isinstance(w, (QSpinBox, QDoubleSpinBox)):
                out[key] = w.value()
            elif isinstance(w, QComboBox):
                out[key] = w.currentData()
            elif isinstance(w, QLineEdit):
                text = w.text().strip()
                if typ == "list_int":
                    out[key] = [int(x) for x in _split(text) if x.isdigit()]
                elif typ == "list_str":
                    out[key] = _split(text)
                else:
                    out[key] = text
        return out


def _split(text: str) -> List[str]:
    return [x.strip() for x in text.replace("，", ",").split(",") if x.strip()]


class RulesPage(QWidget):
    rules_saved = Signal()
    # 规则 → 防火墙校准的结果（后台线程跑完回主线程）
    enforce_done = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._cards: Dict[str, RuleCard] = {}
        self._dirty = False
        self._loading = True
        self.enforce_done.connect(self._on_enforce_done)
        self._build()
        self.reload()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 16, 24, 12)
        root.setSpacing(12)

        head = PageHeader("规则配置", "修改后保存，规则引擎即时生效，无需重启")
        self.lbl_dirty = QLabel("")
        self.lbl_dirty.setStyleSheet(f"color:{C.warning};font-size:13.5px;")
        self.lbl_dirty.setVisible(False)
        head.add_action(self.lbl_dirty)

        self.btn_reload = QPushButton("重新载入")
        self.btn_reload.setObjectName("btn_outline")
        self.btn_reload.clicked.connect(self.reload)
        head.add_action(self.btn_reload)

        self.btn_save = QPushButton("保存并生效")
        self.btn_save.setObjectName("btn_primary")
        self.btn_save.clicked.connect(self.save)
        head.add_action(self.btn_save)
        root.addWidget(head)

        self.tabs = QTabWidget()

        # Tab1 规则
        self.rules_area = QScrollArea()
        self.rules_area.setWidgetResizable(True)
        self.rules_area.setFrameShape(QFrame.Shape.NoFrame)
        self.rules_area.setStyleSheet("QScrollArea{background:transparent;}")
        self.rules_host = QWidget()
        self.rules_lay = QVBoxLayout(self.rules_host)
        self.rules_lay.setContentsMargins(0, 4, 8, 8)
        self.rules_lay.setSpacing(10)
        # 规则卡限宽后会贴左，加这条对齐让它们落在页面中线（1045 以下宽度时看不出差别）
        self.rules_lay.setAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.rules_lay.addStretch(1)
        self.rules_area.setWidget(self.rules_host)
        self.tabs.addTab(self.rules_area, "风险规则")

        # Tab2 访问规则（原「区域访问白名单」+ 原「黑 / 白名单」合并而来）
        # 名单不再是独立实体：想拦一个 IP 就建一条「拦截」规则，
        # 想放行就建一条「放行」规则，动作与匹配条件在同一个对话框里。
        self.tab_region = RegionRulesTab()
        self.tab_region.changed.connect(self._mark_dirty)
        self.tabs.addTab(self.tab_region, "访问规则")

        root.addWidget(self.tabs, 1)

    # ═══════════════════════════════════════════════
    #  「未保存」标记
    # ═══════════════════════════════════════════════
    def _mark_dirty(self, *_args) -> None:
        """任一改动点亮标题区标记；区域规则另给 tab 加圆点（定位到哪个 tab）"""
        if self._loading:
            return
        if self._dirty:
            return
        self._dirty = True
        self.lbl_dirty.setText("● 未保存")
        self.lbl_dirty.setVisible(True)
        self._dot_region_tab(True)

    def _clear_dirty(self) -> None:
        self._dirty = False
        self.lbl_dirty.setVisible(False)
        self.lbl_dirty.setText("")
        self._dot_region_tab(False)

    def _dot_region_tab(self, on: bool) -> None:
        i = self.tabs.indexOf(self.tab_region)
        if i >= 0:
            self.tabs.setTabText(i, "访问规则 •" if on else "访问规则")

    # ── 数据 ──
    def reload(self) -> None:
        self._loading = True
        eng = get_engine()
        eng.reload()
        cfg = eng.get_config().get("rules", {})

        while self.rules_lay.count() > 1:
            item = self.rules_lay.takeAt(0)
            if item is None:
                continue
            wdg = item.widget()
            if wdg:
                wdg.deleteLater()
        self._cards.clear()

        for rule_id in RULE_LABELS:
            # 「黑名单命中」不再是一张规则卡：名单入口已取消，拦截由
            # 「访问规则」里的拦截动作承担（见 app/list_migration 的说明）。
            # 引擎里仍保留对旧名单文件的兼容判断，但不再暴露开关 ——
            # 让人在这里关掉它却依然被拦（或反过来），是最糟的交互。
            if rule_id == "blacklist":
                continue
            if rule_id not in cfg:
                continue
            card = RuleCard(rule_id, cfg[rule_id], self.rules_host)
            card.changed.connect(self._mark_dirty)
            self.rules_lay.insertWidget(self.rules_lay.count() - 1, card)
            self._cards[rule_id] = card

        # 访问规则（含拦截 / 放行 / 判定风险 / 仅关注 / 降级）
        self.tab_region.load(eng.get_config().get("region_rules") or [])
        self._loading = False
        self._clear_dirty()

    def save(self) -> None:
        eng = get_engine()
        cfg = eng.get_config()
        for rule_id, card in self._cards.items():
            cfg.setdefault("rules", {})[rule_id] = card.collect()
        # 访问规则（顶层数组，与 rules 并列）
        region_rules = self.tab_region.collect()
        cfg["region_rules"] = region_rules
        enabled = sum(1 for r in region_rules if r.get("enabled", True))
        # 拦截 / 放行条数单独统计：它们是会真正改动防火墙的两类规则，
        # 保存结果里必须能一眼看到「这次动了几条」。
        n_block = sum(
            1
            for r in region_rules
            if r.get("enabled", True) and str(r.get("action") or "") == "block"
        )
        n_allow = sum(
            1
            for r in region_rules
            if r.get("enabled", True) and str(r.get("action") or "") in ("allow", "whitelist")
        )
        try:
            eng.save_config(cfg)
            eng.reload()
        except Exception as e:
            QMessageBox.warning(self, "保存失败", str(e))
            audit.record(
                audit.ACTION_RULES_SAVE,
                target_type="rule",
                summary=f"保存规则失败：{e}",
                result=audit.RESULT_FAIL,
            )
            return
        # 审计：规则是「什么样的访问算风险」的唯一权威，改错会直接导致漏判
        # 或误判。只记每条规则的开关与分值，不记区域规则的完整明细（量大且
        # 真正的差异在开关/分值上）。
        audit.record(
            audit.ACTION_RULES_SAVE,
            target_type="rule",
            summary=f"保存规则（{len(self._cards)} 条引擎规则、{len(region_rules)} 条访问规则）",
            after={
                "rules": {
                    rid: {
                        "enabled": (c.collect() or {}).get("enabled"),
                        "score": (c.collect() or {}).get("score"),
                    }
                    for rid, c in self._cards.items()
                },
                "region_rules": len(region_rules),
                "region_enabled": enabled,
                "region_block": n_block,
                "region_allow": n_allow,
            },
        )
        self._clear_dirty()
        self._flash_saved(f"✓ 已保存（拦截 {n_block} / 放行 {n_allow}）")
        self.rules_saved.emit()
        # 保存后必须让防火墙追上规则（拦截补封 / 放行解封），后台跑。
        # 这一步的结果若失败会在 _on_enforce_done 里**弹窗**——那才是需要
        # 打断用户的事：规则看着保存了，实际没拦住。
        self._start_enforce()

    def _flash_saved(self, text: str) -> None:
        """标题区亮一句「已保存」，3 秒后自动消失。

        为什么不弹模态框：保存是低频但结果很确定的动作，多一次
        「点确定」纯属打断（用户明确抱怨过弹窗打断）。真正值得打断的只有
        「拦截规则没生效」，那一条在 _on_enforce_done 里仍然是弹窗。
        """
        self.lbl_dirty.setText(text)
        self.lbl_dirty.setStyleSheet(f"color:{C.success};font-size:13.5px;")
        self.lbl_dirty.setVisible(True)
        QTimer.singleShot(3000, self._clear_flash)

    def _clear_flash(self) -> None:
        """闪一下之后把标题区恢复成「未保存 / 空」的正确状态"""
        if self._dirty:
            self.lbl_dirty.setText("● 未保存")
            self.lbl_dirty.setStyleSheet(f"color:{C.warning};font-size:13.5px;")
            self.lbl_dirty.setVisible(True)
            return
        self.lbl_dirty.setText("")
        self.lbl_dirty.setVisible(False)

    # ── 规则 → 防火墙校准 ──
    def _start_enforce(self) -> None:
        """把「拦截 / 放行」规则落到防火墙（后台线程）。

        为什么保存后必须立刻做一次：拦截规则本身只是「命中时判拦截」，
        如果目标 IP 此刻正连着业务系统、或者干脆不再来了，就没有任何一条
        访问记录能触发它 —— 用户以为「刚加了拦截，现在应该进不来了」，
        而防火墙里实际什么都没有。放行同理：不主动解封，那条放行规则
        永远等不到下一次访问（连接早在防火墙层就被丢了）。
        """
        who = audit.actor_local()

        def work():
            try:
                res = list_migration.calibrate_firewall(actor=who)
            except Exception as e:
                log.exception("规则联动防火墙失败")
                res = {"admin": True, "total": 0, "error": str(e)}
            self.enforce_done.emit(res)

        threading.Thread(target=work, daemon=True, name="rule-enforce").start()

    def _on_enforce_done(self, res) -> None:
        if not res:
            return
        if res.get("error"):
            QMessageBox.warning(self, "规则联动防火墙失败", res["error"])
            return
        if not res.get("total"):
            return
        summary = list_migration.format_calibrate(res)
        detail = list_migration.format_calibrate_detail(res)
        ok = res.get("admin") and not res.get("failed") and not res.get("unban_failed")
        body = summary + ("\n\n" + detail if detail else "")
        if ok:
            # 只有真的动了防火墙才提示。每次保存都弹一个「无变更」很烦，
            # 这是用户明确抱怨过的那类打断。
            if res.get("banned") or res.get("unbanned"):
                QMessageBox.information(self, "拦截 / 放行已生效", body)
            return
        QMessageBox.warning(self, "规则未完全生效", body or "未写入防火墙")
