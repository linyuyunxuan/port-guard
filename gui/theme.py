"""
PortGuard 全局主题 — 深色科技风
保留 #0E8FD9 医药蓝作为品牌主色；深色底更突出红/琥珀告警色。
API 与 sql-api-manager 的 theme.py 保持一致（Color / C / GLOBAL_STYLE）。
"""
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:                      # 仅用于类型标注，运行时不需要 Qt
    from PyQt6.QtWidgets import QFrame, QLabel


@dataclass(frozen=True)
class Color:
    primary:          str = "#0E8FD9"   # 医药蓝
    primary_hover:    str = "#0C7CBE"
    primary_light:    str = "#123C57"
    primary_soft:     str = "#0F2C42"
    success:          str = "#10B981"
    success_light:    str = "#0C3A2E"
    danger:           str = "#EF4444"
    danger_light:     str = "#3B1517"
    warning:          str = "#F59E0B"
    warning_light:    str = "#3A2A0C"
    critical:         str = "#DC2626"
    critical_light:   str = "#401012"
    info:             str = "#38BDF8"
    info_light:       str = "#0C2E42"

    bg_body:          str = "#0F172A"
    bg_card:          str = "#1E293B"
    bg_card_alt:      str = "#233145"
    bg_sidebar:       str = "#0B1220"
    bg_sidebar_hover: str = "#16233A"
    bg_sidebar_active: str = "#0E8FD9"

    border:           str = "#334155"
    border_light:     str = "#26364D"

    text_primary:     str = "#E2E8F0"
    text_secondary:   str = "#94A3B8"
    text_muted:       str = "#64748B"
    text_on_dark:     str = "#F8FAFC"
    text_link:        str = "#38BDF8"


C = Color()

# 风险等级 -> 文字颜色
LEVEL_COLORS = {
    "normal":   C.text_secondary,
    "low":      C.info,
    "medium":   C.warning,
    "high":     C.danger,
    "critical": C.critical,
}

# 风险等级 -> 行背景（极淡，保持可读）
LEVEL_BG = {
    "normal":   None,
    "low":      None,
    "medium":   C.warning_light,
    "high":     C.danger_light,
    "critical": C.critical_light,
}


GLOBAL_STYLE = f"""
/* ── 全局 ── */
QWidget {{
    font-family: "Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI", sans-serif;
    font-size: 13px;
    color: {C.text_primary};
}}
QMainWindow, QDialog {{
    background-color: {C.bg_body};
}}

/* ── 侧边栏 ── */
#sidebar {{
    background-color: {C.bg_sidebar};
    border-right: 1px solid {C.border_light};
}}
#sidebar_logo {{
    color: {C.text_on_dark};
    font-size: 17px;
    font-weight: 700;
    padding: 18px 16px 4px 16px;
}}
#sidebar_sub {{
    color: {C.text_muted};
    font-size: 11px;
    padding: 0 16px 14px 16px;
}}
#nav_btn {{
    background-color: transparent;
    color: {C.text_secondary};
    border: none;
    border-left: 3px solid transparent;
    text-align: left;
    padding: 11px 14px;
    font-size: 13.5px;
    border-radius: 0;
}}
#nav_btn:hover {{
    background-color: {C.bg_sidebar_hover};
    color: {C.text_on_dark};
}}
#nav_btn:checked {{
    background-color: {C.bg_sidebar_hover};
    color: {C.primary};
    border-left: 3px solid {C.primary};
    font-weight: 600;
}}
#sidebar_footer {{
    color: {C.text_muted};
    font-size: 11px;
    padding: 10px 16px;
}}
#sidebar_sep {{
    background-color: {C.border_light};
    max-height: 1px;
    min-height: 1px;
}}

/* ── 页面标题 ── */
#page_title {{
    color: {C.text_on_dark};
    font-size: 19px;
    font-weight: 700;
}}
#page_desc {{
    color: {C.text_secondary};
    font-size: 12px;
}}

/* ── 卡片 ── */
#stat_card {{
    background-color: {C.bg_card};
    border: 1px solid {C.border};
    border-radius: 10px;
}}
#stat_card:hover {{
    border-color: {C.primary};
}}
#stat_value {{
    font-size: 25px;
    font-weight: 700;
    color: {C.text_on_dark};
}}
#stat_label {{
    font-size: 12px;
    color: {C.text_secondary};
}}
#panel {{
    background-color: {C.bg_card};
    border: 1px solid {C.border};
    border-radius: 10px;
}}
#panel_title {{
    font-size: 13.5px;
    font-weight: 600;
    color: {C.text_on_dark};
}}
#hint {{
    color: {C.text_muted};
    font-size: 12px;
}}

/* ── 按钮（基础样式，避免未命名按钮出现白底白字） ── */
QPushButton {{
    background-color: {C.bg_card_alt};
    color: {C.text_primary};
    border: 1px solid {C.border};
    border-radius: 6px;
    padding: 6px 14px;
    font-size: 13px;
}}
QPushButton:hover {{ background-color: #2B3B52; border-color: {C.text_muted}; }}
QPushButton:pressed {{ background-color: {C.primary_soft}; }}
QPushButton:disabled {{ color: {C.text_muted}; border-color: {C.border_light};
                        background-color: {C.bg_card}; }}

/* ── 按钮（语义化） ── */
#btn_primary {{
    background-color: {C.primary};
    color: #ffffff;
    border: none;
    border-radius: 6px;
    padding: 7px 16px;
    font-size: 13px;
    font-weight: 500;
}}
#btn_primary:hover {{ background-color: {C.primary_hover}; }}
#btn_primary:disabled {{ background-color: {C.primary_light}; color: {C.text_muted}; }}

#btn_success {{
    background-color: {C.success}; color: #ffffff; border: none;
    border-radius: 6px; padding: 7px 16px; font-size: 13px; font-weight: 500;
}}
#btn_success:hover {{ background-color: #0EA271; }}
#btn_success:disabled {{ background-color: {C.success_light}; color: {C.text_muted}; }}

#btn_danger {{
    background-color: {C.danger}; color: #ffffff; border: none;
    border-radius: 6px; padding: 7px 16px; font-size: 13px; font-weight: 500;
}}
#btn_danger:hover {{ background-color: #DC2626; }}
#btn_danger:disabled {{ background-color: {C.danger_light}; color: {C.text_muted}; }}

#btn_warning {{
    background-color: {C.warning}; color: #1a1408; border: none;
    border-radius: 6px; padding: 7px 16px; font-size: 13px; font-weight: 600;
}}
#btn_warning:hover {{ background-color: #D97706; }}

#btn_outline {{
    background-color: transparent;
    color: {C.text_secondary};
    border: 1px solid {C.border};
    border-radius: 6px;
    padding: 6px 14px;
    font-size: 13px;
}}
#btn_outline:hover {{
    background-color: {C.bg_card_alt};
    color: {C.text_on_dark};
    border-color: {C.text_muted};
}}
#btn_outline:disabled {{ color: {C.text_muted}; border-color: {C.border_light}; }}
#btn_sm {{ border-radius: 4px; padding: 3px 10px; font-size: 12px; }}
#btn_link {{
    background: transparent; border: none; color: {C.text_link};
    padding: 2px 4px; font-size: 12px; text-decoration: underline;
}}

/* ── 输入框 ── */
#input, QLineEdit {{
    background-color: {C.bg_body};
    border: 1px solid {C.border};
    border-radius: 6px;
    padding: 7px 10px;
    font-size: 13px;
    color: {C.text_primary};
    selection-background-color: {C.primary};
    selection-color: #ffffff;
}}
#input:focus, QLineEdit:focus {{ border-color: {C.primary}; }}
QLineEdit:disabled {{ color: {C.text_muted}; }}
QLineEdit::placeholder {{ color: {C.text_muted}; }}

/* ── 表格 ── */
QTableView, QTableWidget {{
    background-color: {C.bg_card};
    alternate-background-color: {C.bg_card_alt};
    border: 1px solid {C.border};
    border-radius: 8px;
    gridline-color: {C.border_light};
    font-size: 12.5px;
    outline: none;
    selection-background-color: {C.primary_soft};
    selection-color: {C.text_on_dark};
}}
QTableView::item, QTableWidget::item {{
    padding: 5px 8px;
    border-bottom: 1px solid {C.border_light};
    color: {C.text_primary};
}}
QTableView::item:selected, QTableWidget::item:selected {{
    background-color: {C.primary_soft};
    color: {C.text_on_dark};
}}
QHeaderView {{ background-color: {C.bg_body}; }}
QHeaderView::section {{
    background-color: {C.bg_body};
    color: {C.text_secondary};
    border: none;
    border-bottom: 1px solid {C.border};
    border-right: 1px solid {C.border_light};
    padding: 8px 8px;
    font-weight: 600;
    font-size: 12px;
}}
QHeaderView::section:hover {{ color: {C.primary}; }}
QTableCornerButton::section {{ background-color: {C.bg_body}; border: none; }}

/* ── 组合框 ── */
QComboBox {{
    background-color: {C.bg_body};
    border: 1px solid {C.border};
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 13px;
    color: {C.text_primary};
}}
QComboBox:hover {{ border-color: {C.text_muted}; }}
QComboBox:focus {{ border-color: {C.primary}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background-color: {C.bg_card};
    border: 1px solid {C.border};
    border-radius: 4px;
    selection-background-color: {C.primary_soft};
    color: {C.text_primary};
    padding: 4px;
    outline: none;
}}

/* ── 文本域 ── */
QTextEdit, QPlainTextEdit {{
    background-color: {C.bg_body};
    border: 1px solid {C.border};
    border-radius: 6px;
    padding: 8px;
    font-size: 13px;
    color: {C.text_primary};
    selection-background-color: {C.primary};
    selection-color: #ffffff;
}}
QTextEdit:focus, QPlainTextEdit:focus {{ border-color: {C.primary}; }}

/* ── 复选框 ── */
QCheckBox {{ color: {C.text_primary}; font-size: 13px; spacing: 6px; }}
QCheckBox::indicator {{
    width: 15px; height: 15px;
    border: 1px solid {C.border};
    border-radius: 4px;
    background-color: {C.bg_body};
}}
QCheckBox::indicator:checked {{
    background-color: {C.primary};
    border-color: {C.primary};
    image: none;
}}
QCheckBox::indicator:hover {{ border-color: {C.primary}; }}

/* ── 标签 ── */
QLabel {{ color: {C.text_primary}; font-size: 13px; }}

/* ── 分组框 ── */
QGroupBox {{
    background-color: {C.bg_card};
    border: 1px solid {C.border};
    border-radius: 8px;
    margin-top: 18px;
    padding: 18px 14px 14px 14px;
    font-weight: 600;
    color: {C.text_on_dark};
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 14px;
    padding: 0 6px;
    color: {C.primary};
}}

/* ── 滚动条 ── */
QScrollBar:vertical {{ background: transparent; width: 9px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {C.border}; border-radius: 4px; min-height: 30px; }}
QScrollBar::handle:vertical:hover {{ background: {C.text_muted}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; background: none; }}
QScrollBar:horizontal {{ background: transparent; height: 9px; }}
QScrollBar::handle:horizontal {{ background: {C.border}; border-radius: 4px; min-width: 30px; }}
QScrollBar::handle:horizontal:hover {{ background: {C.text_muted}; }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; background: none; }}
QScrollArea {{ border: none; background: transparent; }}

/* ── 状态栏 ── */
QStatusBar {{
    background-color: {C.bg_sidebar};
    border-top: 1px solid {C.border_light};
    color: {C.text_secondary};
    font-size: 12px;
    padding: 2px 8px;
}}
QStatusBar::item {{ border: none; }}

/* ── 工具提示 ── */
QToolTip {{
    background-color: {C.bg_card_alt};
    color: {C.text_on_dark};
    border: 1px solid {C.border};
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 12px;
}}

/* ── 选项卡 ── */
QTabWidget::pane {{
    border: 1px solid {C.border};
    border-radius: 0 0 8px 8px;
    background-color: {C.bg_card};
    top: -1px;
}}
QTabBar::tab {{
    background-color: {C.bg_body};
    border: 1px solid {C.border};
    border-bottom: none;
    border-radius: 6px 6px 0 0;
    padding: 7px 18px;
    margin-right: 2px;
    color: {C.text_secondary};
    font-size: 13px;
}}
QTabBar::tab:selected {{ background-color: {C.bg_card}; color: {C.primary}; font-weight: 600; }}
QTabBar::tab:hover:!selected {{ background-color: {C.primary_soft}; color: {C.primary}; }}

/* ── 数值框 ── */
QSpinBox, QDoubleSpinBox {{
    background-color: {C.bg_body};
    border: 1px solid {C.border};
    border-radius: 6px;
    padding: 6px 8px;
    font-size: 13px;
    color: {C.text_primary};
}}
QSpinBox:focus, QDoubleSpinBox:focus {{ border-color: {C.primary}; }}
QSpinBox::up-button, QDoubleSpinBox::up-button,
QSpinBox::down-button, QDoubleSpinBox::down-button {{
    background-color: {C.bg_card_alt}; border: none; width: 16px;
}}

/* ── 菜单 ── */
QMenu {{
    background-color: {C.bg_card};
    border: 1px solid {C.border};
    border-radius: 8px;
    padding: 4px;
}}
QMenu::item {{ padding: 7px 28px 7px 14px; border-radius: 4px; color: {C.text_primary}; }}
QMenu::item:selected {{ background-color: {C.primary_soft}; color: {C.primary}; }}
QMenu::separator {{ height: 1px; background: {C.border}; margin: 4px 8px; }}

/* ── 列表 ── */
QListWidget {{
    background-color: {C.bg_card};
    border: 1px solid {C.border};
    border-radius: 8px;
    outline: none;
}}
QListWidget::item {{ padding: 8px 10px; border-bottom: 1px solid {C.border_light}; }}
QListWidget::item:selected {{ background-color: {C.primary_soft}; color: {C.text_on_dark}; }}

/* ── 进度条 ── */
QProgressBar {{
    background-color: {C.bg_body};
    border: 1px solid {C.border};
    border-radius: 6px;
    text-align: center;
    color: {C.text_primary};
    height: 16px;
}}
QProgressBar::chunk {{ background-color: {C.primary}; border-radius: 5px; }}
"""


def card_widget(child=None) -> "QFrame":
    """把内容包装成卡片"""
    from PyQt6.QtWidgets import QFrame, QVBoxLayout
    card = QFrame()
    card.setObjectName("stat_card")
    card.setStyleSheet(
        f"#stat_card{{background:{C.bg_card};border:1px solid {C.border};border-radius:10px;}}"
        f"#stat_card:hover{{border-color:{C.primary};}}")
    layout = QVBoxLayout(card)
    layout.setContentsMargins(14, 14, 14, 14)
    layout.setSpacing(6)
    if child is not None:
        layout.addWidget(child)
    return card


def section_header(text: str) -> "QLabel":
    from PyQt6.QtGui import QFont
    from PyQt6.QtWidgets import QLabel
    lbl = QLabel(text)
    f = QFont()
    f.setPointSize(10)
    f.setBold(True)
    lbl.setFont(f)
    lbl.setStyleSheet(f"color:{C.text_secondary};padding:4px 0;")
    return lbl


# ═══════════════════════════════════════════════════════════
#  表格内小按钮样式常量
#  原实现把同样的样式串内联在 page_bans 的 4 处，改配色要全文件搜；
#  统一到常量后只改这里。
# ═══════════════════════════════════════════════════════════

def small_button_style(kind: str = "outline") -> str:
    """
    kind: danger | success | primary | outline
    返回适配表格单元格内小按钮（高 24px）的样式表。
    """
    base = "border-radius:4px;padding:2px 10px;font-size:12px;"
    if kind == "danger":
        return (f"QPushButton{{background:{C.danger};color:#fff;border:none;{base}}}"
                f"QPushButton:hover{{background:#DC2626;}}"
                f"QPushButton:disabled{{background:{C.border};color:{C.text_muted};}}")
    if kind == "success":
        return (f"QPushButton{{background:{C.success};color:#fff;border:none;{base}}}"
                f"QPushButton:hover{{background:#0EA271;}}"
                f"QPushButton:disabled{{background:{C.border};color:{C.text_muted};}}")
    if kind == "primary":
        return (f"QPushButton{{background:{C.primary};color:#fff;border:none;{base}}}"
                f"QPushButton:hover{{background:{C.primary_hover};}}")
    return (f"QPushButton{{background:transparent;color:{C.text_secondary};"
            f"border:1px solid {C.border};{base}}}"
            f"QPushButton:hover{{border-color:{C.primary};color:{C.primary};}}"
            f"QPushButton:disabled{{color:{C.text_muted};border-color:{C.border_light};}}")
