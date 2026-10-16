"""PortGuard — 规则配置页"""
from typing import Dict, List

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtWidgets import (
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
)

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
from gui.theme import C
from gui.widgets import ToggleSwitch

LEVEL_ITEMS = [LEVEL_NORMAL, LEVEL_LOW, LEVEL_MEDIUM, LEVEL_HIGH, LEVEL_CRITICAL]
LEVEL_ITEM_LABELS = [LEVEL_LABEL[x] for x in LEVEL_ITEMS]
ACTION_ITEMS = [("suggest_ban", "生成封禁建议"), ("alert", "仅告警")]


class RuleCard(QFrame):
    """单条规则配置卡片"""
    def __init__(self, rule_id: str, cfg: Dict, parent=None):
        super().__init__(parent)
        self.rule_id = rule_id
        self.cfg = dict(cfg)
        self._fields: Dict[str, object] = {}
        self.setObjectName("stat_card")
        self.setStyleSheet(
            f"#stat_card{{background:{C.bg_card};border:1px solid {C.border};border-radius:10px;}}")
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
        self._fields["score"] = self.sp_score
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
        self._fields["level"] = self.cb_level
        col += 1

        # 动作
        grid.addWidget(self._lbl("命中动作"), 0, col)
        self.cb_action = QComboBox()
        self.cb_action.addItems([x[1] for x in ACTION_ITEMS])
        try:
            self.cb_action.setCurrentIndex(
                [x[0] for x in ACTION_ITEMS].index(self.cfg.get("action", "alert")))
        except ValueError:
            self.cb_action.setCurrentIndex(1)
        self.cb_action.setFixedWidth(140)
        grid.addWidget(self.cb_action, 1, col)
        self._fields["action"] = self.cb_action
        col += 1

        # 参数
        for p in RULE_PARAMS.get(self.rule_id, []):
            key, typ, label = p["key"], p["type"], p["label"]
            val = self.cfg.get(key)
            grid.addWidget(self._lbl(label), 0, col)

            if typ == "int":
                w = QSpinBox()
                w.setRange(int(p.get("min", 0)), int(p.get("max", 2_000_000_000)))
                w.setValue(int(val if val is not None else p.get("min", 0)))
                w.setFixedWidth(110)
            elif typ == "float":
                w = QDoubleSpinBox()
                w.setDecimals(2)
                w.setSingleStep(0.05)
                w.setRange(float(p.get("min", 0)), float(p.get("max", 1)))
                w.setValue(float(val if val is not None else 0.5))
                w.setFixedWidth(110)
            elif typ == "list_int":
                w = QLineEdit(",".join(str(x) for x in (val or [])))
                w.setFixedWidth(240)
            elif typ == "list_str":
                w = QLineEdit(",".join(str(x) for x in (val or [])))
                w.setFixedWidth(280)
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
        for k, v in self._fields.items():
            if k in ("score", "level", "action"):
                continue
            widget = v[0] if isinstance(v, tuple) else v
            widget.setEnabled(on)
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
        for key, v in self._fields.items():
            if key in ("score", "level", "action"):
                continue
            w, typ = v
            text = w.text().strip()
            if typ in {"int", "float"}:
                out[key] = w.value()
            elif typ == "list_int":
                out[key] = [int(x) for x in _split(text) if x.isdigit()]
            elif typ == "list_str":
                out[key] = _split(text)
            else:
                out[key] = text
        return out


def _split(text: str) -> List[str]:
    return [x.strip() for x in text.replace("，", ",").split(",") if x.strip()]


class RulesPage(QWidget):
    rules_saved = pyqtSignal()

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
        root.addWidget(self.tabs, 1)

    def _build_lists(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(8, 12, 8, 8)
        lay.setSpacing(10)

        tip = QLabel("每行一条，支持单个 IP 或 CIDR 网段（如 203.0.113.0/24）。"
                     "白名单优先于一切规则，命中即豁免且永不封禁。")
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
        try:
            eng.save_config(cfg)
            eng.reload()
        except Exception as e:
            QMessageBox.warning(self, "保存失败", str(e))
            return
        self.rules_saved.emit()
        QMessageBox.information(self, "已保存", "规则已保存并即时生效。")

    def _save_lists(self) -> None:
        eng = get_engine()
        from core.rule_engine import _IPSet
        black = _IPSet(_lines(self.txt_black.toPlainText()))
        white = _IPSet(_lines(self.txt_white.toPlainText()))
        # 校验非法项
        bad_b = [x for x in _lines(self.txt_black.toPlainText()) if x not in black.entries() and not _valid(x)]
        bad_w = [x for x in _lines(self.txt_white.toPlainText()) if x not in white.entries() and not _valid(x)]
        bad = bad_b + bad_w
        if bad:
            QMessageBox.warning(self, "存在非法条目",
                                "以下条目不是合法 IP 或 CIDR，已忽略：\n" + "\n".join(bad[:20]))
        eng.blacklist = black
        eng.whitelist = white
        try:
            eng.save_lists()
        except Exception as e:
            QMessageBox.warning(self, "保存失败", str(e))
            return
        self.rules_saved.emit()
        QMessageBox.information(self, "已保存",
                                f"黑名单 {len(black)} 条，白名单 {len(white)} 条，已即时生效。")


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
