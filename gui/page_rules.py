"""PortGuard — 规则配置页"""

from typing import Dict, List, Tuple

from core.config import (
    LEVEL_CRITICAL,
    LEVEL_HIGH,
    LEVEL_LABEL,
    LEVEL_LOW,
    LEVEL_MEDIUM,
    LEVEL_NORMAL,
)
from core.rule_engine import get_engine
from core.rules_meta import RULE_DESCS, RULE_LABELS, RULE_PARAMS
from gui.region_rules import RegionRulesTab
from gui.theme import C
from gui.widgets import ToggleSwitch
from qtcompat import (
    QComboBox,
    QDoubleSpinBox,
    QFrame,
    QGridLayout,
    QGroupBox,
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


class RuleCard(QFrame):
    """单条规则配置卡片"""

    def __init__(self, rule_id: str, cfg: Dict, parent=None):
        super().__init__(parent)
        self.rule_id = rule_id
        self.cfg = dict(cfg)
        self._fields: Dict[str, Tuple[QWidget, str]] = {}
        self.setObjectName("stat_card")
        self.setStyleSheet(
            f"#stat_card{{background:{C.bg_card};border:1px solid {C.border};border-radius:10px;}}"
        )
        self._build()

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(8)

        top = QHBoxLayout()
        top.setSpacing(8)
        self.toggle = ToggleSwitch(bool(self.cfg.get("enabled", True)))
        name = QLabel(RULE_LABELS.get(self.rule_id, self.rule_id))
        name.setStyleSheet(f"color:{C.text_on_dark};font-size:14px;font-weight:600;")
        desc = QLabel(RULE_DESCS.get(self.rule_id, ""))
        desc.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
        desc.setWordWrap(True)

        top.addWidget(self.toggle)
        top.addWidget(name)
        top.addStretch(1)
        lay.addLayout(top)
        lay.addWidget(desc)

        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(8)

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
            else:
                w = QLineEdit(str(val or ""))
            grid.addWidget(w, 1, col)
            self._fields[key] = (w, typ)
            col += 1

        grid.setColumnStretch(col, 1)
        lay.addLayout(grid)
        self.toggle.toggled.connect(self._on_toggle)
        self._on_toggle(self.toggle.isChecked())

    @staticmethod
    def _lbl(text: str) -> QLabel:
        lb = QLabel(text)
        lb.setStyleSheet(f"color:{C.text_secondary};font-size:12px;")
        return lb

    def _on_toggle(self, on: bool) -> None:
        for w, _typ in self._fields.values():
            w.setEnabled(on)
        self.sp_score.setEnabled(on)
        self.cb_level.setEnabled(on)
        self.cb_action.setEnabled(on)

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

    def __init__(self, parent=None):
        super().__init__(parent)
        self._cards: Dict[str, RuleCard] = {}
        self._build()
        self.reload()

    def _build(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 12)
        root.setSpacing(12)

        head = QHBoxLayout()
        t = QLabel("规则配置")
        t.setObjectName("page_title")
        d = QLabel("修改后点击保存，规则引擎即时生效，无需重启")
        d.setObjectName("page_desc")
        head.addWidget(t)
        head.addWidget(d)
        head.addStretch(1)

        btn_reload = QPushButton("重新载入")
        btn_reload.setObjectName("btn_outline")
        btn_reload.clicked.connect(self.reload)
        btn_save = QPushButton("保存并生效")
        btn_save.setObjectName("btn_primary")
        btn_save.clicked.connect(self.save)
        head.addWidget(btn_reload)
        head.addWidget(btn_save)
        root.addLayout(head)

        self.tabs = QTabWidget()

        # Tab1 规则
        self.rules_area = QScrollArea()
        self.rules_area.setWidgetResizable(True)
        self.rules_host = QWidget()
        self.rules_lay = QVBoxLayout(self.rules_host)
        self.rules_lay.setContentsMargins(2, 8, 8, 8)
        self.rules_lay.setSpacing(10)
        self.rules_lay.addStretch(1)
        self.rules_area.setWidget(self.rules_host)
        self.tabs.addTab(self.rules_area, "风险规则")

        # Tab2 名单
        self.tabs.addTab(self._build_lists(), "黑 / 白名单")

        # Tab3 区域规则（区域访问白名单）
        self.tab_region = RegionRulesTab()
        self.tab_region.changed.connect(self._mark_region_dirty)
        self.tabs.addTab(self.tab_region, "区域访问白名单")

        root.addWidget(self.tabs, 1)

    def _mark_region_dirty(self) -> None:
        """区域规则一改动就给标签加个圆点，提示「有尚未保存的改动」"""
        i = self.tabs.indexOf(self.tab_region)
        if i >= 0:
            self.tabs.setTabText(i, "区域访问白名单 •")

    def _build_lists(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(8, 12, 8, 8)
        lay.setSpacing(10)

        tip = QLabel(
            "每行一条，支持单个 IP 或 CIDR 网段（如 203.0.113.0/24）。"
            "白名单优先于一切规则，命中即豁免且永不封禁。"
        )
        tip.setStyleSheet(f"color:{C.text_muted};font-size:12px;")
        tip.setWordWrap(True)
        lay.addWidget(tip)

        row = QHBoxLayout()
        row.setSpacing(12)

        g1 = QGroupBox("黑名单（命中直接判为严重风险）")
        l1 = QVBoxLayout(g1)
        self.txt_black = QPlainTextEdit()
        self.txt_black.setPlaceholderText("203.0.113.10\n198.51.100.0/24")
        l1.addWidget(self.txt_black)

        g2 = QGroupBox("白名单（永不封禁）")
        l2 = QVBoxLayout(g2)
        self.txt_white = QPlainTextEdit()
        self.txt_white.setPlaceholderText("127.0.0.1\n192.168.1.0/24")
        l2.addWidget(self.txt_white)

        row.addWidget(g1)
        row.addWidget(g2)
        lay.addLayout(row)

        b = QHBoxLayout()
        btn = QPushButton("保存名单")
        btn.setObjectName("btn_primary")
        btn.clicked.connect(self._save_lists)
        b.addStretch(1)
        b.addWidget(btn)
        lay.addLayout(b)
        return w

    # ── 数据 ──
    def reload(self) -> None:
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
            self.rules_lay.insertWidget(self.rules_lay.count() - 1, card)
            self._cards[rule_id] = card

        self._load_lists()

        # 区域规则
        self.tab_region.load(eng.get_config().get("region_rules") or [])
        i = self.tabs.indexOf(self.tab_region)
        if i >= 0:
            self.tabs.setTabText(i, "区域访问白名单")

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
        try:
            eng.save_config(cfg)
            eng.reload()
        except Exception as e:
            QMessageBox.warning(self, "保存失败", str(e))
            return
        i = self.tabs.indexOf(self.tab_region)
        if i >= 0:
            self.tabs.setTabText(i, "区域访问白名单")
        self.rules_saved.emit()
        enabled = sum(1 for r in region_rules if r.get("enabled", True))
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
        eng.blacklist = black
        eng.whitelist = white
        try:
            eng.save_lists()
        except Exception as e:
            QMessageBox.warning(self, "保存失败", str(e))
            return
        self.rules_saved.emit()
        QMessageBox.information(
            self, "已保存", f"黑名单 {len(black)} 条，白名单 {len(white)} 条，已即时生效。"
        )


def _lines(text: str) -> List[str]:
    return [x.strip() for x in text.replace("，", "\n").splitlines() if x.strip()]


def _valid(entry: str) -> bool:
    import ipaddress

    try:
        if "/" in entry:
            ipaddress.ip_network(entry, strict=False)
        else:
            ipaddress.ip_address(entry)
        return True
    except Exception:
        return False
