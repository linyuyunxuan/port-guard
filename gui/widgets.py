"""PortGuard — 可复用控件"""
from PySide6.QtCore import (
    Property,
    QEasingCurve,
    QPropertyAnimation,
    QRect,
    QSize,
    Qt,
    Signal,
)
from PySide6.QtGui import QBrush, QColor, QFont, QPainter
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from gui.theme import LEVEL_COLORS, C


class ToggleSwitch(QWidget):
    """简洁的开关控件（替代 QCheckBox 用于"启用/自动模式"）"""
    toggled = Signal(bool)

    def __init__(self, checked: bool = False, parent=None, width: int = 44, height: int = 24):
        super().__init__(parent)
        self._checked = checked
        self._w, self._h = width, height
        self.setFixedSize(width, height)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self._pos = 1.0 if checked else 0.0
        self._anim = QPropertyAnimation(self, b"position", self)
        self._anim.setDuration(140)
        self._anim.setEasingCurve(QEasingCurve.Type.InOutQuad)

    # Qt property for animation
    def _get_pos(self):
        return self._pos

    def _set_pos(self, v):
        self._pos = v
        self.update()

    position = Property(float, fget=_get_pos, fset=_set_pos)

    def isChecked(self) -> bool:
        return self._checked

    def setChecked(self, v: bool) -> None:
        if v == self._checked:
            return
        self._checked = bool(v)
        self._animate()
        self.toggled.emit(self._checked)

    def _animate(self):
        self._anim.stop()
        self._anim.setStartValue(self._pos)
        self._anim.setEndValue(1.0 if self._checked else 0.0)
        self._anim.start()

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton:
            self.setChecked(not self._checked)
        super().mouseReleaseEvent(e)

    def sizeHint(self):
        return QSize(self._w, self._h)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = self._h / 2

        # 轨道
        track = QColor(C.primary) if self._checked else QColor(C.border)
        p.setBrush(QBrush(track))
        p.setPen(Qt.PenStyle.NoPen)
        p.drawRoundedRect(0, 0, self._w, self._h, r, r)

        # 滑块
        pad = 3
        d = self._h - pad * 2
        x = pad + (self._w - pad * 2 - d) * self._pos
        p.setBrush(QBrush(QColor("#FFFFFF")))
        p.drawEllipse(QRect(int(x), pad, d, d))
        p.end()


class StatCard(QFrame):
    """统计卡片：大数字 + 说明文字"""
    def __init__(self, label: str, value: str = "0", color: str | None = None, parent=None):
        super().__init__(parent)
        self.setObjectName("stat_card")
        self.setStyleSheet(
            f"#stat_card{{background:{C.bg_card};border:1px solid {C.border};border-radius:10px;}}")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(14, 12, 14, 12)
        lay.setSpacing(2)

        self.value_lbl = QLabel(value)
        self.value_lbl.setObjectName("stat_value")
        self.value_lbl.setStyleSheet(
            f"font-size:25px;font-weight:700;color:{color or C.text_on_dark};")

        self.label_lbl = QLabel(label)
        self.label_lbl.setStyleSheet(f"font-size:12px;color:{C.text_secondary};")

        lay.addWidget(self.value_lbl)
        lay.addWidget(self.label_lbl)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(78)

    def set_value(self, v) -> None:
        self.value_lbl.setText(str(v))

    def set_color(self, color: str) -> None:
        self.value_lbl.setStyleSheet(f"font-size:25px;font-weight:700;color:{color};")


class RiskBadge(QLabel):
    """风险等级徽章"""
    def __init__(self, level: str = "normal", text: str | None = None, parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_level(level, text)

    def set_level(self, level: str, text: str | None = None) -> None:
        from core.config import LEVEL_LABEL
        color = LEVEL_COLORS.get(level, C.text_secondary)
        label = text if text is not None else LEVEL_LABEL.get(level, level)
        self.setText(label)
        self.setStyleSheet(
            f"color:{color};border:1px solid {color};border-radius:8px;"
            f"padding:1px 8px;font-size:11px;font-weight:600;background:transparent;")


class Badge(QLabel):
    """通用小标签"""
    def __init__(self, text: str = "", color: str | None = None, parent=None):
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_color(color or C.text_secondary)

    def set_color(self, color: str) -> None:
        self.setStyleSheet(
            f"color:{color};border:1px solid {color};border-radius:8px;"
            f"padding:1px 8px;font-size:11px;background:transparent;")


class WarnBanner(QFrame):
    """页面顶部警示条"""
    action_clicked = Signal()

    def __init__(self, text: str = "", action_text: str = "", color: str | None = None, parent=None):
        super().__init__(parent)
        color = color or C.warning
        self.setStyleSheet(
            f"QFrame{{background:{C.warning_light};border:1px solid {color};border-radius:8px;}}")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(12, 8, 12, 8)
        lay.setSpacing(10)

        self.icon = QLabel("⚠")
        self.icon.setStyleSheet(f"color:{color};font-size:14px;font-weight:700;")
        self.text = QLabel(text)
        self.text.setStyleSheet(f"color:{C.text_primary};font-size:12.5px;")
        self.text.setWordWrap(True)

        lay.addWidget(self.icon)
        lay.addWidget(self.text, 1)

        self.btn = None
        if action_text:
            self.btn = QPushButton(action_text)
            self.btn.setObjectName("btn_warning")
            self.btn.setStyleSheet(
                f"QPushButton{{background:{color};color:#1a1408;border:none;border-radius:5px;"
                f"padding:4px 12px;font-size:12px;font-weight:600;}}")
            self.btn.setCursor(Qt.CursorShape.PointingHandCursor)
            self.btn.clicked.connect(self.action_clicked.emit)
            lay.addWidget(self.btn)

    def set_text(self, text: str) -> None:
        self.text.setText(text)


class EmptyHint(QLabel):
    """空态提示"""
    def __init__(self, text: str = "暂无数据", parent=None):
        super().__init__(text, parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet(f"color:{C.text_muted};font-size:13px;padding:28px;")


# ── 表格辅助 ──

def make_item(text: str, color: str | None = None, align=None, bold: bool = False) -> QTableWidgetItem:
    it = QTableWidgetItem(str(text if text is not None else ""))
    if color:
        it.setForeground(QColor(color))
    if align is not None:
        it.setTextAlignment(align)
    if bold:
        f = QFont()
        f.setBold(True)
        it.setFont(f)
    return it


def center() -> Qt.AlignmentFlag:
    return Qt.AlignmentFlag.AlignCenter


def left() -> Qt.AlignmentFlag:
    return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
