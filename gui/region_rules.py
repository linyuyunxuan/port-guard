"""PortGuard — 区域访问白名单规则编辑器

「规则配置」页里的第三个标签页。用户要求：
  「增加国内区域访问白名单；比如 河南区、山西区的 IP 可访问某端口。
    规则可以人工添加定义的模式」

于是每条规则由两部分组成：
  1. **匹配条件**：省 / 市 / 国家 / 运营商（文本维度）与 IP / CIDR / IP 前缀
     （地址维度）任意组合，再可限定**生效端口**（留空 = 全部端口）
  2. **动作**：这条规则命中后干什么 —— 放行 / 仅关注 / 降级 / 判定风险

规则保存在 rules.json 的顶层 `region_rules` 数组里（与 `rules` 并列），
保存后由 RuleEngine 热重载，无需重启。
"""

import secrets
from typing import Any, Dict, List, Optional

from core.rules_meta import REGION_ACTIONS
from gui.theme import C
from gui.widgets import ToggleSwitch
from qtcompat import (
    QAbstractItemView,
    QColor,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QDoubleSpinBox,
    QFormLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    Qt,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    Signal,
)

ACTION_KEYS = [k for k, _ in REGION_ACTIONS]
ACTION_LABELS = [v for _, v in REGION_ACTIONS]

HEADERS = ["启用", "规则名称", "动作", "生效端口", "匹配条件", "备注"]


def _split_items(text: str) -> List[str]:
    """把用户输入拆成条目：逗号 / 中文逗号 / 顿号 / 分号 / 换行都算分隔符"""
    if not text:
        return []
    norm = str(text)
    for ch in ("，", "、", ";", "；", "\r", "\n", "\t", " "):
        norm = norm.replace(ch, ",")
    out: List[str] = []
    for x in norm.split(","):
        s = x.strip()
        if s and s not in out:
            out.append(s)
    return out


def _join(items) -> str:
    return "，".join(str(x) for x in (items or []))


def new_rule_id() -> str:
    return "r-" + secrets.token_hex(4)


def summarize(rule: Dict[str, Any]) -> str:
    """把匹配条件压成一行表格文本"""
    m = rule.get("match") or {}
    bits: List[str] = []
    if m.get("provinces"):
        bits.append("省份 " + "、".join(str(x) for x in m["provinces"]))
    if m.get("cities"):
        bits.append("城市 " + "、".join(str(x) for x in m["cities"]))
    if m.get("countries"):
        bits.append("国家 " + "、".join(str(x) for x in m["countries"]))
    if m.get("isp"):
        bits.append("运营商 " + "、".join(str(x) for x in m["isp"]))
    if m.get("cidrs"):
        bits.append("网段 " + "、".join(str(x) for x in m["cidrs"]))
    if m.get("ip_keywords"):
        bits.append("IP 前缀 " + "、".join(str(x) for x in m["ip_keywords"]))
    if m.get("only_china"):
        bits.append("仅限中国境内")
    elif m.get("not_china"):
        bits.append("非中国境内")  # 兼容旧配置：该字段已由「仅限境内」取代
    return "；".join(bits) or "（未设置条件，规则不会生效）"


def action_label(action: str) -> str:
    try:
        return ACTION_LABELS[ACTION_KEYS.index(action)]
    except ValueError:
        return action


class RegionRuleDialog(QDialog):
    """新增 / 编辑一条区域规则"""

    def __init__(self, rule: Optional[Dict[str, Any]] = None, parent=None):
        super().__init__(parent)
        rule = rule or {}
        self.setWindowTitle("编辑访问规则" if rule.get("id") else "新增访问规则")
        self.setMinimumWidth(620)
        self._orig_id = str(rule.get("id") or "")
        # 原始条目整份留着：`values()` 要把界面没有控件的字段（例如迁移来的
        # `exempt_only`）原样带回去。丢了它，一条「仅豁免」的放行规则被编辑
        # 一次就会变成「未限定端口的放行规则」并在编译期刷告警。
        self._orig = dict(rule)
        self._build(rule)

    # ── 界面 ──
    def _build(self, rule: Dict[str, Any]) -> None:
        m = rule.get("match") or {}
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 16, 18, 12)
        root.setSpacing(10)

        tip = QLabel(
            "一条规则 = 匹配条件 + 动作。想拦住某个 IP 就选「拦截」并填 IP / 网段；"
            "想放行某个 IP 就选「放行」。匹配条件可只填一项，也可多项组合"
            "（多项之间是「并且」）。省份支持写「河南」或「河南省」。"
        )
        tip.setStyleSheet(f"color:{C.text_muted};font-size:13.5px;")
        tip.setWordWrap(True)
        root.addWidget(tip)

        f = QFormLayout()
        f.setSpacing(9)

        self.ed_name = QLineEdit(str(rule.get("name") or ""))
        self.ed_name.setPlaceholderText("例如：拦截 203.0.113.7 / 河南办公网放行")

        self.tg_enabled = ToggleSwitch(bool(rule.get("enabled", True)))

        self.cb_action = QComboBox()
        self.cb_action.addItems(ACTION_LABELS)
        # 动作文案很长（要讲清「拦截 / 放行」的后果），但下拉框不该被它撑到
        # 比对话框还宽：限制条目宽度，完整文案仍可在下拉列表里看全。
        self.cb_action.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        self.cb_action.setMinimumContentsLength(22)
        self.cb_action.setMaximumWidth(340)
        try:
            self.cb_action.setCurrentIndex(ACTION_KEYS.index(str(rule.get("action") or "block")))
        except ValueError:
            # 未知动作回落到「仅关注」而不是第一项：第一项现在是「拦截」，
            # 老配置里出现一个认不出的动作值时，绝不能因此把它升级成直接封禁。
            self.cb_action.setCurrentIndex(ACTION_KEYS.index("watch"))

        self.ed_ports = QLineEdit(_join(rule.get("target_ports")))
        self.ed_ports.setPlaceholderText("留空 = 全部端口；多个端口用逗号分隔，如 18080,3389")

        self.ed_provinces = QLineEdit(_join(m.get("provinces")))
        self.ed_provinces.setPlaceholderText("河南，山西")
        self.ed_cities = QLineEdit(_join(m.get("cities")))
        self.ed_cities.setPlaceholderText("郑州市，太原市")
        self.ed_countries = QLineEdit(_join(m.get("countries")))
        self.ed_countries.setPlaceholderText("中国")
        self.ed_isp = QLineEdit(_join(m.get("isp")))
        self.ed_isp.setPlaceholderText("联通，电信，移动")

        self.ed_cidrs = QTextEdit(_join(m.get("cidrs")).replace("，", "\n"))
        self.ed_cidrs.setPlaceholderText(
            "每行一条，支持单个 IP 或 CIDR\n203.0.113.0/24\n198.51.100.7"
        )
        self.ed_cidrs.setFixedHeight(74)

        self.ed_keywords = QLineEdit(_join(m.get("ip_keywords")))
        self.ed_keywords.setPlaceholderText("按 IP 文本前缀匹配，如 113.118. ，多个用逗号分隔")

        # 仅限境内：归属地确认为中国（含港澳台按库的实际归属）才命中
        self.tg_only_china = ToggleSwitch(bool(m.get("only_china", False)))

        self.sp_factor = QDoubleSpinBox()
        self.sp_factor.setRange(0.0, 1.0)
        self.sp_factor.setSingleStep(0.1)
        self.sp_factor.setDecimals(2)
        self.sp_factor.setValue(float(rule.get("factor", 0.3) or 0.3))
        self.sp_factor.setFixedWidth(110)

        self.sp_score = QSpinBox()
        self.sp_score.setRange(0, 100)
        self.sp_score.setValue(int(rule.get("score", 90) or 90))
        self.sp_score.setFixedWidth(110)

        self.ed_note = QLineEdit(str(rule.get("note") or ""))
        self.ed_note.setPlaceholderText("可选：写清楚为什么加这条规则")

        f.addRow("规则名称", self.ed_name)
        f.addRow("启用", self._wrap(self.tg_enabled))
        f.addRow("命中动作", self.cb_action)
        f.addRow("生效端口", self.ed_ports)
        f.addRow("省份", self.ed_provinces)
        f.addRow("城市", self.ed_cities)
        f.addRow("国家 / 地区", self.ed_countries)
        f.addRow("运营商", self.ed_isp)
        f.addRow("IP / 网段", self.ed_cidrs)
        f.addRow("IP 前缀", self.ed_keywords)
        f.addRow("仅限境内", self._wrap(self.tg_only_china))
        f.addRow("降级系数", self.sp_factor)
        f.addRow("风险加分", self.sp_score)
        f.addRow("备注", self.ed_note)
        root.addLayout(f)

        self.lbl_hint = QLabel("")
        self.lbl_hint.setStyleSheet(f"color:{C.text_muted};font-size:13.5px;")
        self.lbl_hint.setWordWrap(True)
        root.addWidget(self.lbl_hint)
        self.cb_action.currentIndexChanged.connect(self._update_hint)
        self._update_hint()

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.button(QDialogButtonBox.StandardButton.Ok).setText("确定")
        btns.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        btns.accepted.connect(self._on_ok)
        btns.rejected.connect(self.reject)
        root.addWidget(btns)

    @staticmethod
    def _wrap(w: QWidget) -> QWidget:
        box = QWidget()
        lay = QHBoxLayout(box)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(w)
        lay.addStretch(1)
        return box

    def _update_hint(self) -> None:
        a = self._action()
        if a == "block":
            text = (
                "拦截 = 命中即直接封禁：命中后立刻写入 Windows 防火墙（永久规则），"
                "不看风险评分、不看「自动封禁」开关与阈值；同一条记录若同时命中"
                "「放行」规则，仍以拦截为准（安全侧优先）。内网 / 本机地址永不误封。"
                "生效端口留空 = 拦截该来源访问本机全部端口。"
            )
        elif a == "allow":
            text = (
                "放行 = 仅限所选区域通行：命中区域完全豁免；其他区域"
                "（含归属地未知）访问「生效端口」时直接写入防火墙拦截"
                "（无需开启自动封禁）；内网 / 本机地址永不误封。"
                "此动作必须填写生效端口 —— 不填端口则只豁免、不拦截（避免误配掐掉整机访问）。"
            )
        elif a == "watch":
            text = "仅关注：不影响风险评分，只在事件与日志里打上「区域关注」标签，便于事后审计。"
        elif a == "downgrade":
            text = "降级：把已经累计的风险分乘以「降级系数」（越小降得越狠），仍保留记录。"
        else:
            text = (
                f"判定风险 = 仅针对所选区域拦截：命中后加「风险加分」分（当前 {self.sp_score.value()} 分），"
                "达标即生成封禁建议（开启自动封禁后达到阈值会自动封）；"
                "其他区域不受本规则影响。"
            )
        self.lbl_hint.setText(text)
        # 「风险加分」只有判定风险用得上，「降级系数」只有降级用得上。
        # 原来四个控件一直亮着，用户会以为给「拦截」填 20 分就能只加 20 分 ——
        # 拦截是直接封禁，不看分。灰掉比在说明里写一句更不容易误解。
        self.sp_score.setEnabled(a == "suggest_ban")
        self.sp_factor.setEnabled(a == "downgrade")

    def _action(self) -> str:
        i = max(0, min(self.cb_action.currentIndex(), len(ACTION_KEYS) - 1))
        return ACTION_KEYS[i]

    # ── 校验与产出 ──
    def _on_ok(self) -> None:
        name = self.ed_name.text().strip()
        if not name:
            QMessageBox.warning(self, "无法保存", "请填写规则名称。")
            return
        if not self._has_condition():
            QMessageBox.warning(
                self,
                "无法保存",
                "至少要填一个有效的匹配条件（省份 / 城市 / 国家 / 运营商 / IP 网段 / "
                "IP 前缀 / 仅限境内），否则这条规则会匹配所有地址。",
            )
            return
        # 网段写错必须当场拦住。引擎对非法 CIDR 是「跳过并记日志」——
        # 界面上这条规则看着好好的、规则页也显示已启用，实际永远不命中，
        # 用户会以为「我已经把这个 IP 拦了」。
        bad = self._bad_cidrs()
        if bad:
            QMessageBox.warning(
                self,
                "有无法解析的地址段",
                "下面这些既不是合法 IP 也不是合法网段，保存后本规则不会命中它们：\n"
                + "\n".join(bad[:10])
                + "\n\n请修正（单个 IP 写成 203.0.113.7，网段写成 203.0.113.0/24）。",
            )
            return
        if self._action() == "allow" and not self.values()["target_ports"]:
            QMessageBox.warning(
                self,
                "无法保存",
                "「放行」必须填写生效端口：不限定端口的放行会拦截"
                "所有未命中的来源，等于把整机访问都关掉。请明确写出要保护的端口。",
            )
            return
        if self._action() == "block":
            # 拦截是唯一会「保存即封人」的动作，多问一句。
            # 默认按钮是「否」：误触一个回车不该把一整段地址封掉。
            ok = QMessageBox.question(
                self,
                "确认添加拦截规则",
                f"「{name}」命中后会**立刻把来源 IP 写入 Windows 防火墙**（永久规则），"
                "不看评分、不看自动封禁开关。\n\n确认继续？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                QMessageBox.StandardButton.No,
            )
            if ok != QMessageBox.StandardButton.Yes:
                return
        self.accept()

    def _bad_cidrs(self) -> List[str]:
        """cidrs 里解析不了的条目（空值不算）"""
        import ipaddress

        bad: List[str] = []
        for c in self.values()["match"]["cidrs"]:
            s = str(c).strip()
            if not s:
                continue
            try:
                ipaddress.ip_network(s, strict=False)
            except Exception:
                bad.append(s)
        return bad

    def _has_condition(self) -> bool:
        m = self.values()["match"]
        return bool(
            m["provinces"]
            or m["cities"]
            or m["countries"]
            or m["isp"]
            or m["cidrs"]
            or m["ip_keywords"]
            or m["only_china"]
        )

    def values(self) -> Dict[str, Any]:
        ports = [int(x) for x in _split_items(self.ed_ports.text()) if x.isdigit()]
        # 以原始条目为底再覆盖界面字段：迁移产生的 `exempt_only` 这类
        # 界面没有控件的字段必须原样带回去（见 __init__ 里的说明）。
        out: Dict[str, Any] = dict(self._orig)
        out.update(
            {
                "id": self._orig_id or new_rule_id(),
                "name": self.ed_name.text().strip(),
                "enabled": self.tg_enabled.isChecked(),
                "action": self._action(),
                "target_ports": ports,
                "score": self.sp_score.value(),
                "factor": round(self.sp_factor.value(), 2),
                "match": {
                    "provinces": _split_items(self.ed_provinces.text()),
                    "cities": _split_items(self.ed_cities.text()),
                    "countries": _split_items(self.ed_countries.text()),
                    "isp": _split_items(self.ed_isp.text()),
                    "cidrs": _split_items(self.ed_cidrs.toPlainText()),
                    "ip_keywords": _split_items(self.ed_keywords.text()),
                    "only_china": self.tg_only_china.isChecked(),
                },
                "note": self.ed_note.text().strip(),
            }
        )
        return out


class RegionRulesTab(QWidget):
    """访问规则列表 + 增删改（2026-10-23 起原「黑 / 白名单」也并入这里）"""

    changed = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._rules: List[Dict[str, Any]] = []
        self._build()

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(8, 12, 8, 8)
        lay.setSpacing(10)

        tip = QLabel(
            "访问规则：按 IP / 网段或归属地（省 / 市 / 国家 / 运营商）决定这条流量怎么处理 ——"
            "「拦截」命中即直接封禁、「放行」命中即豁免。原来的黑名单 / 白名单已并入这两种动作，"
            "不再单独维护。规则在这里增删改，保存后立即对上报与本机采集的流量生效。"
        )
        tip.setStyleSheet(f"color:{C.text_muted};font-size:13.5px;")
        tip.setWordWrap(True)
        lay.addWidget(tip)

        self.table = QTableWidget(0, len(HEADERS))
        self.table.setHorizontalHeaderLabels(HEADERS)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, 56)
        self.table.setColumnWidth(1, 180)
        self.table.setColumnWidth(2, 120)
        self.table.setColumnWidth(3, 110)
        hh.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        hh.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table.doubleClicked.connect(lambda _i: self._edit())
        lay.addWidget(self.table, 1)

        row = QHBoxLayout()
        b_add = QPushButton("新增规则")
        b_add.setObjectName("btn_primary")
        b_add.clicked.connect(self._add)
        b_edit = QPushButton("编辑")
        b_edit.setObjectName("btn_outline")
        b_edit.clicked.connect(self._edit)
        b_del = QPushButton("删除")
        b_del.setObjectName("btn_outline")
        b_del.clicked.connect(self._delete)
        b_up = QPushButton("上移")
        b_up.setObjectName("btn_outline")
        b_up.clicked.connect(lambda: self._move(-1))
        b_down = QPushButton("下移")
        b_down.setObjectName("btn_outline")
        b_down.clicked.connect(lambda: self._move(1))
        b_dup = QPushButton("复制")
        b_dup.setObjectName("btn_outline")
        b_dup.clicked.connect(self._duplicate)
        for b in (b_add, b_edit, b_del, b_up, b_down, b_dup):
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)

        self.lbl_state = QLabel("")
        self.lbl_state.setStyleSheet(f"color:{C.text_muted};font-size:13.5px;")
        lay.addWidget(self.lbl_state)

    # ── 数据 ──
    def load(self, rules: List[Dict[str, Any]]) -> None:
        self._rules = [dict(r) for r in (rules or []) if isinstance(r, dict)]
        self._refresh()

    def collect(self) -> List[Dict[str, Any]]:
        return [dict(r) for r in self._rules]

    def _refresh(self) -> None:
        self.table.setRowCount(0)
        for r in self._rules:
            self._append_row(r)
        enabled = sum(1 for r in self._rules if r.get("enabled", True))
        self.lbl_state.setText(f"共 {len(self._rules)} 条规则，其中启用 {enabled} 条。")

    def _append_row(self, r: Dict[str, Any]) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        vals = [
            "是" if r.get("enabled", True) else "否",
            str(r.get("name") or ""),
            action_label(str(r.get("action") or "")),
            "全部端口"
            if not r.get("target_ports")
            else "、".join(str(p) for p in r.get("target_ports") or []),
            summarize(r),
            str(r.get("note") or ""),
        ]
        for col, v in enumerate(vals):
            it = QTableWidgetItem(v)
            if col == 0:
                it.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                it.setForeground(
                    QColor(C.success) if r.get("enabled", True) else QColor(C.text_muted)
                )
            if col == 1:
                it.setToolTip(str(r.get("id") or ""))
            self.table.setItem(row, col, it)

    def _selected(self) -> int:
        rows = {i.row() for i in self.table.selectedItems()}
        if not rows:
            return -1
        return sorted(rows)[0]

    # ── 增删改 ──
    def _add(self) -> None:
        dlg = RegionRuleDialog(None, self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self._rules.append(dlg.values())
        self._refresh()
        self.changed.emit()

    def _edit(self) -> None:
        i = self._selected()
        if i < 0:
            QMessageBox.information(self, "请选择", "请先选中一条规则。")
            return
        dlg = RegionRuleDialog(self._rules[i], self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return
        self._rules[i] = dlg.values()
        self._refresh()
        self.table.selectRow(i)
        self.changed.emit()

    def _delete(self) -> None:
        i = self._selected()
        if i < 0:
            QMessageBox.information(self, "请选择", "请先选中一条规则。")
            return
        name = self._rules[i].get("name") or self._rules[i].get("id")
        if (
            QMessageBox.question(
                self,
                "删除规则",
                f"确定删除区域规则「{name}」吗？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        del self._rules[i]
        self._refresh()
        self.changed.emit()

    def _duplicate(self) -> None:
        i = self._selected()
        if i < 0:
            QMessageBox.information(self, "请选择", "请先选中一条规则。")
            return
        copy = dict(self._rules[i])
        copy["id"] = new_rule_id()
        copy["name"] = f"{copy.get('name') or '规则'}（副本）"
        copy["enabled"] = False  # 副本默认不启用，避免误放行
        self._rules.insert(i + 1, copy)
        self._refresh()
        self.table.selectRow(i + 1)
        self.changed.emit()

    def _move(self, delta: int) -> None:
        i = self._selected()
        if i < 0:
            return
        j = i + delta
        if not (0 <= j < len(self._rules)):
            return
        self._rules[i], self._rules[j] = self._rules[j], self._rules[i]
        self._refresh()
        self.table.selectRow(j)
        self.changed.emit()
