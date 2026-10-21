"""PortGuard — 规则配置页

三块内容用下划线 tab 分：风险规则 / 黑·白名单 / 区域访问白名单。

本轮只改呈现（_design/02_ux_spec.md P1-12、P2-3）：
  · 每张规则卡 = `#panel` 无边框 r8，标题区 14/600 + 说明 12 muted；
  · 参数一行栅格：标签在上、控件在下，控件宽度按类型固定，右端留空吸收余量；
  · 任一改动在标题区亮起「● 未保存」，保存后熄灭 —— 之前只有区域 tab 有圆点；
  · 停用的规则整卡降一级明度（标题变 muted + 「已停用」标记），
    而不是只把控件 setEnabled(False) 后看起来像坏了。
"""

import threading
from typing import Dict, List, Tuple

from app import audit, blacklist_service
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
from gui.widgets import ToggleSwitch
from qtcompat import (
    QComboBox,
    QDoubleSpinBox,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSpinBox,
    QTabWidget,
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
    # 黑名单变更 → 防火墙联动的结果（后台线程跑完回主线程）
    blacklist_sync_done = Signal(object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._cards: Dict[str, RuleCard] = {}
        self._dirty = False
        self._loading = True
        self.blacklist_sync_done.connect(self._on_blacklist_sync_done)
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
        self.rules_lay.addStretch(1)
        self.rules_area.setWidget(self.rules_host)
        self.tabs.addTab(self.rules_area, "风险规则")

        # Tab2 名单
        self.tabs.addTab(self._build_lists(), "黑 / 白名单")

        # Tab3 区域规则（区域访问白名单）
        self.tab_region = RegionRulesTab()
        self.tab_region.changed.connect(self._mark_dirty)
        self.tabs.addTab(self.tab_region, "区域访问白名单")

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
            self.tabs.setTabText(i, "区域访问白名单 •" if on else "区域访问白名单")

    def _build_lists(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 8, 8, 8)
        lay.setSpacing(10)

        tip = QLabel(
            "每行一条，支持单个 IP 或 CIDR 网段（如 203.0.113.0/24）。"
            "白名单优先于一切规则，命中即豁免且永不封禁。"
        )
        tip.setObjectName("hint")
        tip.setWordWrap(True)
        lay.addWidget(tip)

        row = QHBoxLayout()
        row.setSpacing(12)

        p1, self.txt_black = self._list_panel(
            "黑名单", "命中直接判为严重风险", "203.0.113.10\n198.51.100.0/24"
        )
        p2, self.txt_white = self._list_panel(
            "白名单", "命中即豁免，永不封禁", "127.0.0.1\n192.168.1.0/24"
        )
        for _ed in (self.txt_black, self.txt_white):
            _ed.textChanged.connect(self._mark_dirty)
        row.addWidget(p1)
        row.addWidget(p2)
        lay.addLayout(row, 1)

        b = QHBoxLayout()
        b.addStretch(1)
        self.btn_save_lists = QPushButton("保存名单")
        self.btn_save_lists.setObjectName("btn_primary")
        self.btn_save_lists.clicked.connect(self._save_lists)
        b.addWidget(self.btn_save_lists)
        lay.addLayout(b)
        return w

    @staticmethod
    def _list_panel(title: str, hint: str, placeholder: str) -> Tuple[QFrame, QPlainTextEdit]:
        """一栏地址清单：标题 + 一句说明 + 等宽编辑器（两栏等高 stretch）"""
        p = QFrame()
        p.setObjectName("panel")
        lay = QVBoxLayout(p)
        lay.setContentsMargins(16, 14, 16, 14)
        lay.setSpacing(4)

        t = QLabel(title)
        t.setObjectName("panel_title")
        lay.addWidget(t)
        h = QLabel(hint)
        h.setObjectName("hint")
        lay.addWidget(h)

        ed = QPlainTextEdit()
        ed.setPlaceholderText(placeholder)
        ed.setStyleSheet(
            f"QPlainTextEdit{{background:{C.bg_input};color:{C.text_primary};"
            f"border:1px solid {C.border};border-radius:6px;padding:8px;"
            f'font-family:"Consolas","Microsoft YaHei UI",monospace;font-size:13.5px;}}'
            f"QPlainTextEdit:focus{{border-color:{C.primary};}}"
        )
        lay.addWidget(ed, 1)
        return p, ed

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
            if rule_id not in cfg:
                continue
            card = RuleCard(rule_id, cfg[rule_id], self.rules_host)
            card.changed.connect(self._mark_dirty)
            self.rules_lay.insertWidget(self.rules_lay.count() - 1, card)
            self._cards[rule_id] = card

        self._load_lists()

        # 区域规则
        self.tab_region.load(eng.get_config().get("region_rules") or [])
        self._loading = False
        self._clear_dirty()

    def _load_lists(self) -> None:
        eng = get_engine()
        eng.load_lists()
        self.txt_black.setPlainText("\n".join(eng.blacklist.entries()))
        self.txt_white.setPlainText("\n".join(eng.whitelist.entries()))

    def save(self) -> None:
        eng = get_engine()
        cfg = eng.get_config()
        for rule_id, card in self._cards.items():
            cfg.setdefault("rules", {})[rule_id] = card.collect()
        # 区域访问白名单规则（顶层数组，与 rules 并列）
        region_rules = self.tab_region.collect()
        cfg["region_rules"] = region_rules
        enabled = sum(1 for r in region_rules if r.get("enabled", True))
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
            summary=f"保存规则（{len(self._cards)} 条引擎规则、{len(region_rules)} 条区域规则）",
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
            },
        )
        self._clear_dirty()
        self.rules_saved.emit()
        QMessageBox.information(
            self,
            "已保存",
            f"规则已保存并即时生效。\n\n区域访问白名单：共 {len(region_rules)} 条，启用 {enabled} 条。",
        )

    def _save_lists(self) -> None:
        eng = get_engine()
        from core.rule_engine import _IPSet

        black = _IPSet(_lines(self.txt_black.toPlainText()))
        white = _IPSet(_lines(self.txt_white.toPlainText()))
        # 校验非法项
        bad_b = [
            x
            for x in _lines(self.txt_black.toPlainText())
            if x not in black.entries() and not _valid(x)
        ]
        bad_w = [
            x
            for x in _lines(self.txt_white.toPlainText())
            if x not in white.entries() and not _valid(x)
        ]
        bad = bad_b + bad_w
        if bad:
            QMessageBox.warning(
                self,
                "存在非法条目",
                "以下条目不是合法 IP 或 CIDR，已忽略：\n" + "\n".join(bad[:20]),
            )
        # 审计要记「加了谁、删了谁」，所以必须在覆盖 eng.blacklist **之前**
        # 取旧集合 —— 覆盖之后旧值就没了，只剩「现在有多少条」。
        old_black = set(eng.blacklist.entries())
        old_white = set(eng.whitelist.entries())
        eng.blacklist = black
        eng.whitelist = white
        try:
            eng.save_lists()
        except Exception as e:
            QMessageBox.warning(self, "保存失败", str(e))
            audit.record(
                audit.ACTION_LIST_SAVE,
                target_type="list",
                summary=f"保存黑白名单失败：{e}",
                result=audit.RESULT_FAIL,
            )
            return
        added, removed = blacklist_service.diff(old_black, set(black.entries()))
        if (added or removed) and not self._confirm_blacklist_sync(added, removed):
            # 用户放弃同步：名单已经写盘了，必须说清楚「名单生效了但没拦」
            QMessageBox.warning(
                self,
                "已取消联动封禁",
                "名单已保存，但**没有**对防火墙做任何改动。\n"
                f"新增 {len(added)} 条、移除 {len(removed)} 条仍按原状态拦截，"
                "可在封禁页手工处理。",
            )
        audit.record(
            audit.ACTION_LIST_SAVE,
            target_type="list",
            summary=(
                f"黑名单 {len(black)} 条（+{len(set(black.entries()) - old_black)}"
                f" -{len(old_black - set(black.entries()))}）、"
                f"白名单 {len(white)} 条（+{len(set(white.entries()) - old_white)}"
                f" -{len(old_white - set(white.entries()))}）"
            ),
            before={"black": sorted(old_black), "white": sorted(old_white)},
            after={"black": sorted(black.entries()), "white": sorted(white.entries())},
        )
        self.rules_saved.emit()
        self._sync_blacklist(added, removed)

    # ── 黑名单 → 防火墙联动 ──
    def _confirm_blacklist_sync(self, added: List[str], removed: List[str]) -> bool:
        """批量改名单等于批量写/删防火墙规则，必须先讲清楚再动手。"""
        lines: List[str] = []
        if added:
            lines.append(f"新增 {len(added)} 个 IP：立即在 Windows 防火墙**永久封禁**")
            lines += [f"   · {ip}" for ip in added[:10]]
            if len(added) > 10:
                lines.append(f"   … 其余 {len(added) - 10} 个")
        if removed:
            lines.append(f"移除 {len(removed)} 个 IP：解封**仅限黑名单来源**的封禁")
            lines.append("   （手工封禁 / 自动封禁不会因此被解封）")
            lines += [f"   · {ip}" for ip in removed[:10]]
        return (
            QMessageBox.question(
                self,
                "黑名单联动防火墙",
                "\n".join(lines) + "\n\n继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            == QMessageBox.StandardButton.Yes
        )

    def _sync_blacklist(self, added: List[str], removed: List[str]) -> None:
        if not added and not removed:
            QMessageBox.information(
                self, "已保存", f"黑名单 {len(get_engine().blacklist)} 条，规则已即时生效。"
            )
            return

        def work():
            try:
                res = blacklist_service.apply_changes(added, removed)
            except Exception as e:
                log.exception("黑名单联动封禁失败")
                res = {"admin": False, "failed": [(ip, str(e)) for ip in added]}
            self.blacklist_sync_done.emit(res)

        threading.Thread(target=work, daemon=True, name="blacklist-sync").start()

    def _on_blacklist_sync_done(self, res) -> None:
        summary = blacklist_service.format_summary(res)
        detail = blacklist_service.format_detail(res)
        if res.get("admin") and not res.get("failed") and not res.get("unban_failed"):
            QMessageBox.information(self, "黑名单已生效", summary + "\n\n" + detail)
            return
        QMessageBox.warning(self, "黑名单未完全生效", summary + "\n\n" + detail)


def _lines(text: str) -> List[str]:
    return [x.strip() for x in text.replace("，", "\n").splitlines() if x.strip()]


def _valid(entry: str) -> bool:
    import ipaddress

    try:
        if "/" in entry:
            ipaddress.ip_network(entry, strict=False)
        else:
            ipaddress.ip_address(entry)
    except Exception:
        return False
    return True
