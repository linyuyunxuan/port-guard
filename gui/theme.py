"""
PortGuard 全局主题 —— 「石墨哨岗 Graphite Watchtower」

设计取向：石墨灰静默底 + 哨兵靛单一强调色，颜色只表达语义、不做装饰。
层级靠明度分层而不是描边：页面 → 卡片 → 行只差 1.05~1.18 的明度，
1px 边框只留给「可交互对象」（输入框 / 次级按钮 / 表头下沿）。

约束：QSS 的 border-radius 只支持单值；无 box-shadow / transition /
letter-spacing。所有取值必须同时在 PySide2(Qt5.15) 与 PySide6(Qt6) 上成立。
设计依据见 _design/01_visual_direction.md。
"""

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # 仅用于类型标注，运行时不需要 Qt
    from qtcompat import QFrame, QLabel


@dataclass(frozen=True)
class Color:
    # ── 强调与语义色 ──
    primary: str = "#6C7CF5"  # 哨兵靛：主动作、选中条、focus、文字强调
    primary_hover: str = "#8A98FF"
    primary_pressed: str = "#5A69E0"
    primary_light: str = "#2A3157"
    primary_soft: str = "#262E57"  # 表格/列表选中行底
    success: str = "#3FBF7F"
    success_light: str = "#16302A"
    danger: str = "#E5484D"  # 高危语义（文字 / 描边）
    danger_solid: str = "#D8383F"  # 满底危险（配白字 4.61:1）
    danger_light: str = "#301E24"
    warning: str = "#E0A03A"
    warning_light: str = "#2A2418"
    critical: str = "#FF6B6B"  # 严重语义的亮调红
    critical_light: str = "#3B1F26"
    info: str = "#8B9BFF"
    info_light: str = "#1E2440"

    # ── 表面层级（由暗到亮）──
    bg_body: str = "#0F1115"
    bg_input: str = "#0B0E12"  # 内凹：输入框 / 下拉 / 日志区
    bg_card: str = "#1A1F27"
    bg_card_alt: str = "#232830"  # 抬升面：对话框 / 菜单 / tooltip
    bg_zebra: str = "#1E232B"
    bg_hover: str = "#2B313C"
    bg_sidebar: str = "#0A0C10"
    bg_sidebar_hover: str = "#171C24"
    bg_sidebar_active: str = "#1B2140"
    bg_disabled: str = "#16191F"

    # ── 描边 ──
    border: str = "#2A303A"
    border_light: str = "#1E242C"
    border_strong: str = "#333A45"
    border_hover: str = "#3E4653"

    # ── 文字 ──
    text_primary: str = "#E4E8ED"
    text_secondary: str = "#98A2AE"
    text_muted: str = "#7B8592"
    text_on_dark: str = "#F4F7FA"
    text_link: str = "#8B9BFF"
    text_disabled: str = "#6A7381"
    accent_on: str = "#0B0E13"  # 亮填充上的文字（近黑，对比度更稳）


C = Color()

# 风险等级 -> 文字颜色
LEVEL_COLORS = {
    "normal": C.text_secondary,
    "low": C.info,
    "medium": C.warning,
    "high": C.critical,
    "critical": C.critical,
}

# 风险等级 -> 行背景（normal/low 不上底色，靠徽章表达）
LEVEL_BG = {
    "normal": None,
    "low": None,
    "medium": C.warning_light,
    "high": C.danger_light,
    "critical": C.critical_light,
}

# 风险等级 -> 徽章底色
LEVEL_BADGE_BG = {
    "normal": "#2B313C",
    "low": C.info_light,
    "medium": C.warning_light,
    "high": C.danger_light,
    "critical": C.danger_solid,
}


GLOBAL_STYLE = f"""
/* ══════════ 全局 ══════════ */
QWidget {{
    font-family: "Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI", sans-serif;
    font-size: 13px;
    color: {C.text_primary};
}}
QMainWindow, QDialog {{ background-color: {C.bg_body}; }}
QStackedWidget {{ background-color: {C.bg_body}; }}

/* ══════════ 侧边栏 ══════════ */
#sidebar {{
    background-color: {C.bg_sidebar};
    border-right: 1px solid {C.border_light};
}}
#sidebar_brand {{
    background-color: transparent;
}}
#sidebar_logo {{
    color: {C.text_on_dark};
    font-size: 15px;
    font-weight: 700;
    padding: 0;
}}
#sidebar_sub {{
    color: {C.text_muted};
    font-size: 11px;
    padding: 0;
}}
#nav_group {{
    color: {C.text_muted};
    font-size: 11px;
    font-weight: 600;
    padding: 0 16px;
}}
#nav_btn {{
    background-color: transparent;
    color: {C.text_secondary};
    border: none;
    border-left: 2px solid transparent;
    border-radius: 0;
    text-align: left;
    padding: 0 14px;
    min-height: 38px;
    font-size: 13px;
    font-weight: 400;
}}
#nav_btn:hover {{
    background-color: {C.bg_sidebar_hover};
    color: {C.text_on_dark};
}}
#nav_btn:checked {{
    background-color: {C.bg_sidebar_active};
    color: {C.text_on_dark};
    border-left: 2px solid {C.primary};
    font-weight: 600;
}}
#sidebar_footer {{
    color: {C.text_muted};
    font-size: 11px;
    padding: 0;
}}
#sidebar_ban {{
    color: {C.text_secondary};
    font-size: 12px;
    font-weight: 600;
    padding: 0;
}}
#sidebar_sep {{ background-color: {C.border_light}; max-height: 1px; min-height: 1px; }}

/* ══════════ 顶部状态条 ══════════ */
#topbar {{
    background-color: {C.bg_body};
    border-bottom: 1px solid {C.border_light};
}}
#topbar_item {{ color: {C.text_secondary}; font-size: 11px; }}
#topbar_sep {{ background-color: {C.border_light}; max-width: 1px; min-width: 1px; }}

/* ══════════ 页面标题 ══════════ */
#page_title {{
    color: {C.text_on_dark};
    font-size: 20px;
    font-weight: 600;
}}
#page_desc {{
    color: {C.text_muted};
    font-size: 12px;
}}
#page_divider {{ background-color: {C.border_light}; max-height: 1px; min-height: 1px; }}

/* ══════════ 统计卡 ══════════ */
#stat_card {{
    background-color: {C.bg_card};
    border: none;
    border-radius: 8px;
}}
#stat_card:hover {{ background-color: {C.bg_card_alt}; }}
#stat_value {{
    font-family: "Consolas", "Microsoft YaHei UI", monospace;
    font-size: 26px;
    font-weight: 700;
    color: {C.text_on_dark};
}}
#stat_label {{
    font-size: 11px;
    color: {C.text_secondary};
}}

/* ══════════ 面板 / 分组 ══════════ */
#panel {{
    background-color: {C.bg_card};
    border: none;
    border-radius: 8px;
}}
#panel_title {{
    font-size: 14px;
    font-weight: 600;
    color: {C.text_on_dark};
}}
#panel_divider {{ background-color: {C.border_light}; max-height: 1px; min-height: 1px; }}
#hint {{
    color: {C.text_muted};
    font-size: 11.5px;
}}

/* ── 表单（设置页 / 对话框）──
   标签列固定 128 右对齐，字段左缘对齐；hint 是字段右侧的一句补充，
   mono_hint 用于路径 / URL / 状态这类等宽对齐更易读的值。 */
#form_label {{
    color: {C.text_secondary};
    font-size: 12.5px;
}}
#form_hint {{
    color: {C.text_muted};
    font-size: 12.5px;
}}
#mono_hint {{
    color: {C.text_secondary};
    font-family: "Consolas", "Microsoft YaHei UI", monospace;
    font-size: 12px;
}}

/* ══════════ 按钮 ══════════ */
QPushButton {{
    background-color: {C.bg_card_alt};
    color: {C.text_primary};
    border: 1px solid {C.border_strong};
    border-radius: 6px;
    padding: 6px 14px;
    font-size: 13px;
    font-weight: 500;
}}
QPushButton:hover {{ background-color: {C.bg_hover}; border-color: {C.border_hover}; }}
QPushButton:pressed {{ background-color: {C.bg_card}; border-color: {C.border}; }}
QPushButton:disabled {{
    color: {C.text_disabled};
    background-color: {C.bg_disabled};
    border-color: {C.border_light};
}}
QPushButton:focus {{ border: 1px solid {C.info}; }}
#btn_primary {{
    background-color: {C.primary};
    color: {C.accent_on};
    border: 1px solid {C.primary};
    border-radius: 6px;
    padding: 6px 16px;
    font-size: 13px;
    font-weight: 600;
}}
#btn_primary:hover {{ background-color: {C.primary_hover}; border-color: {C.primary_hover}; }}
#btn_primary:pressed {{ background-color: {C.primary_pressed}; border-color: {C.primary_pressed}; }}
#btn_primary:disabled {{
    background-color: {C.bg_card_alt};
    color: {C.text_disabled};
    border-color: {C.border_light};
}}

#btn_success {{
    background-color: {C.success};
    color: {C.accent_on};
    border: 1px solid {C.success};
    border-radius: 6px;
    padding: 6px 16px;
    font-size: 13px;
    font-weight: 600;
}}
#btn_success:hover {{ background-color: #4FD190; border-color: #4FD190; }}
#btn_success:disabled {{
    background-color: {C.bg_card_alt};
    color: {C.text_disabled};
    border-color: {C.border_light};
}}

#btn_danger {{
    background-color: {C.danger_solid};
    color: #FFFFFF;
    border: 1px solid {C.danger_solid};
    border-radius: 6px;
    padding: 6px 16px;
    font-size: 13px;
    font-weight: 600;
}}
#btn_danger:hover {{ background-color: {C.danger}; border-color: {C.danger}; }}
#btn_danger:pressed {{ background-color: #B92F36; border-color: #B92F36; }}
#btn_danger:disabled {{
    background-color: {C.bg_card_alt};
    color: {C.text_disabled};
    border-color: {C.border_light};
}}

#btn_warning {{
    background-color: {C.warning};
    color: {C.accent_on};
    border: 1px solid {C.warning};
    border-radius: 6px;
    padding: 5px 14px;
    font-size: 12px;
    font-weight: 600;
}}
#btn_warning:hover {{ background-color: #F0B355; border-color: #F0B355; }}
/* 焦点环：实底按钮上用近黑/白色描边才看得见（info 压 primary 仅 1.35:1） */
#btn_primary:focus {{ border: 1px solid {C.accent_on}; }}
#btn_success:focus {{ border: 1px solid {C.accent_on}; }}
#btn_warning:focus {{ border: 1px solid {C.accent_on}; }}
#btn_danger:focus {{ border: 1px solid #F4F7FA; }}

#btn_outline {{
    background-color: {C.bg_card_alt};
    color: {C.text_primary};
    border: 1px solid {C.border_strong};
    border-radius: 6px;
    padding: 6px 14px;
    font-size: 13px;
    font-weight: 500;
}}
#btn_outline:hover {{
    background-color: {C.bg_hover};
    border-color: {C.border_hover};
    color: {C.text_on_dark};
}}
#btn_outline:disabled {{
    color: {C.text_disabled};
    background-color: {C.bg_disabled};
    border-color: {C.border_light};
}}

#btn_ghost {{
    background-color: transparent;
    color: {C.text_secondary};
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 5px 12px;
    font-size: 12.5px;
}}
#btn_ghost:hover {{ background-color: {C.bg_card_alt}; color: {C.text_primary}; }}

#btn_sm {{ border-radius: 4px; padding: 2px 10px; font-size: 12px; }}
#btn_link {{
    background: transparent; border: none; color: {C.text_link};
    padding: 2px 4px; font-size: 12px;
}}

/* ══════════ 输入控件 ══════════ */
#input, QLineEdit {{
    background-color: {C.bg_input};
    border: 1px solid {C.border};
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 13px;
    color: {C.text_primary};
    selection-background-color: {C.primary};
    selection-color: {C.accent_on};
}}
#input:hover, QLineEdit:hover {{ border-color: {C.border_strong}; }}
#input:focus, QLineEdit:focus {{ border-color: {C.primary}; background-color: #10141A; }}
QLineEdit:disabled {{ color: {C.text_disabled}; background-color: {C.bg_disabled}; }}
QLineEdit::placeholder {{ color: {C.text_muted}; }}

QComboBox {{
    background-color: {C.bg_input};
    border: 1px solid {C.border};
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 13px;
    color: {C.text_primary};
}}
QComboBox:hover {{ border-color: {C.border_strong}; }}
QComboBox:focus {{ border-color: {C.primary}; }}
QComboBox:disabled {{ color: {C.text_disabled}; background-color: {C.bg_disabled}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background-color: {C.bg_card_alt};
    border: 1px solid {C.border_strong};
    border-radius: 6px;
    selection-background-color: {C.primary_soft};
    selection-color: {C.text_on_dark};
    color: {C.text_primary};
    padding: 4px;
    outline: none;
}}

QTextEdit, QPlainTextEdit {{
    background-color: {C.bg_input};
    border: 1px solid {C.border};
    border-radius: 6px;
    padding: 8px;
    font-size: 13px;
    color: {C.text_primary};
    selection-background-color: {C.primary};
    selection-color: {C.accent_on};
}}
QTextEdit:focus, QPlainTextEdit:focus {{ border-color: {C.primary}; }}

QSpinBox, QDoubleSpinBox {{
    background-color: {C.bg_input};
    border: 1px solid {C.border};
    border-radius: 6px;
    padding: 5px 8px;
    font-size: 13px;
    color: {C.text_primary};
    selection-background-color: {C.primary};
    selection-color: {C.accent_on};
}}
QSpinBox:hover, QDoubleSpinBox:hover {{ border-color: {C.border_strong}; }}
QSpinBox:focus, QDoubleSpinBox:focus {{ border-color: {C.primary}; }}
QSpinBox:disabled, QDoubleSpinBox:disabled {{
    color: {C.text_disabled}; background-color: {C.bg_disabled};
}}

/* 日期框必须显式配色：不写这一条会退回 Fusion 默认的白底，
   在深色界面里就是一块刺眼的白板，且日期文字是白字——等于看不见 */
QDateEdit {{
    background-color: {C.bg_input};
    border: 1px solid {C.border};
    border-radius: 6px;
    padding: 5px 8px;
    font-size: 12px;
    color: {C.text_primary};
    selection-background-color: {C.primary};
    selection-color: {C.accent_on};
}}
QDateEdit:hover {{ border-color: {C.border_strong}; }}
QDateEdit:focus {{ border-color: {C.primary}; }}
QDateEdit::drop-down {{ border: none; width: 20px; }}
QDateEdit::down-arrow {{
    image: none;
    border-left: 3px solid transparent;
    border-right: 3px solid transparent;
    border-top: 4px solid {C.text_secondary};
    width: 0; height: 0; margin-right: 6px;
}}
QCalendarWidget QWidget {{ alternate-background-color: {C.bg_card}; }}
QCalendarWidget QAbstractItemView {{
    background-color: {C.bg_card};
    color: {C.text_primary};
    selection-background-color: {C.primary};
    selection-color: {C.accent_on};
}}
QCalendarWidget QToolButton {{
    color: {C.text_primary}; background: transparent; border: none; padding: 4px 8px;
}}
QCalendarWidget QToolButton:hover {{ background: {C.bg_hover}; border-radius: 4px; }}

/* ══════════ 表格 ══════════ */
QTableView, QTableWidget {{
    background-color: {C.bg_card};
    alternate-background-color: {C.bg_zebra};
    border: 1px solid transparent;
    border-radius: 8px;
    gridline-color: transparent;
    font-size: 12px;
    outline: none;
    selection-background-color: {C.primary_soft};
    selection-color: {C.text_on_dark};
}}
QTableView:focus, QTableWidget:focus {{
    border: 1px solid {C.primary};
}}
QTableView::item, QTableWidget::item {{
    padding: 0 8px;
    border: none;
    color: {C.text_primary};
}}
QTableView::item:hover, QTableWidget::item:hover {{ background-color: {C.bg_hover}; }}
QTableView::item:selected, QTableWidget::item:selected {{
    background-color: {C.primary_soft};
    color: {C.text_on_dark};
}}
QHeaderView {{ background-color: {C.bg_body}; border: none; }}
QHeaderView::section {{
    background-color: {C.bg_body};
    color: {C.text_secondary};
    border: none;
    border-bottom: 1px solid {C.border};
    padding: 9px 10px;
    font-weight: 600;
    font-size: 11px;
}}
QHeaderView::section:hover {{ color: {C.text_primary}; }}
QHeaderView::down-arrow, QHeaderView::up-arrow {{ width: 8px; height: 8px; }}
QTableCornerButton::section {{ background-color: {C.bg_body}; border: none; }}

/* ══════════ 复选框 / 单选 ══════════ */
QCheckBox {{ color: {C.text_primary}; font-size: 13px; spacing: 8px; }}
QCheckBox::indicator {{
    width: 14px; height: 14px;
    border: 1px solid {C.border_strong};
    border-radius: 3px;
    background-color: {C.bg_input};
}}
QCheckBox::indicator:hover {{ border-color: {C.primary}; }}
QCheckBox::indicator:checked {{
    background-color: {C.primary};
    border-color: {C.primary};
}}
QCheckBox::indicator:disabled {{
    background-color: {C.bg_disabled}; border-color: {C.border_light};
}}
QCheckBox::indicator:focus {{ border-color: {C.info}; }}

/* ══════════ 图标按钮（行内「⋯」等）══════════ */
QToolButton {{
    background: transparent;
    border: none;
    border-radius: 4px;
    color: {C.text_secondary};
    padding: 0;
    font-size: 14px;
}}
QToolButton:hover {{ background-color: {C.bg_card_alt}; color: {C.text_primary}; }}
QToolButton:pressed {{ background-color: {C.bg_hover}; }}
QToolButton:focus {{ border: 1px solid {C.info}; }}
QToolButton::menu-indicator {{ image: none; width: 0; }}

/* ══════════ 文字 ══════════ */
QLabel {{ color: {C.text_primary}; font-size: 13px; background: transparent; }}

/* ══════════ 分组框（设置页 / 规则页）══════════ */
QGroupBox {{
    background-color: {C.bg_card};
    border: none;
    border-radius: 8px;
    margin-top: 0;
    padding: 44px 16px 16px 16px;
    color: {C.text_on_dark};
}}
QGroupBox::title {{
    subcontrol-origin: padding;
    subcontrol-position: top left;
    left: 16px;
    top: 14px;
    padding: 0;
    background: transparent;
    color: {C.text_on_dark};
    font-size: 14px;
    font-weight: 600;
}}

/* ══════════ 选项卡（下划线式）══════════ */
QTabWidget::pane {{
    border: none;
    background: transparent;
    margin-top: 8px;
}}
QTabBar {{ background: transparent; }}
QTabBar::tab {{
    background: transparent;
    border: none;
    border-bottom: 2px solid transparent;
    padding: 8px 2px;
    margin-right: 24px;
    color: {C.text_secondary};
    font-size: 12.5px;
}}
QTabBar::tab:hover {{ color: {C.text_primary}; }}
QTabBar::tab:selected {{
    color: {C.text_on_dark};
    font-weight: 600;
    border-bottom: 2px solid {C.primary};
}}

/* ══════════ 滚动条 ══════════ */
QScrollBar:vertical {{ background: transparent; width: 10px; margin: 0; }}
QScrollBar::handle:vertical {{
    background: rgba(255, 255, 255, 0.10);
    border-radius: 5px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: rgba(255, 255, 255, 0.18); }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; background: none; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: none; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 0; }}
QScrollBar::handle:horizontal {{
    background: rgba(255, 255, 255, 0.10);
    border-radius: 5px;
    min-width: 30px;
}}
QScrollBar::handle:horizontal:hover {{ background: rgba(255, 255, 255, 0.18); }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; background: none; }}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ background: none; }}
QScrollArea {{ border: none; background: transparent; }}

/* ══════════ 状态栏 ══════════ */
QStatusBar {{
    background-color: {C.bg_sidebar};
    border-top: 1px solid {C.border_light};
    color: {C.text_secondary};
    font-size: 11px;
    padding: 0 8px;
}}
QStatusBar::item {{ border: none; }}

/* ══════════ 菜单 / 提示 ══════════ */
QMenu {{
    background-color: {C.bg_card_alt};
    border: 1px solid {C.border_strong};
    border-radius: 8px;
    padding: 4px;
}}
QMenu::item {{ padding: 7px 24px 7px 12px; border-radius: 4px; color: {C.text_primary}; }}
QMenu::item:selected {{ background-color: {C.primary_soft}; color: {C.text_on_dark}; }}
QMenu::separator {{ height: 1px; background: {C.border_light}; margin: 4px 8px; }}

QToolTip {{
    background-color: {C.bg_card_alt};
    color: {C.text_primary};
    border: 1px solid {C.border_strong};
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 12px;
}}

/* ══════════ 列表 ══════════ */
QListWidget {{
    background-color: {C.bg_card};
    border: none;
    border-radius: 8px;
    outline: none;
}}
QListWidget::item {{ padding: 8px 10px; border: none; }}
QListWidget::item:hover {{ background-color: {C.bg_hover}; }}
QListWidget::item:selected {{ background-color: {C.primary_soft}; color: {C.text_on_dark}; }}

/* ══════════ 进度条 ══════════ */
QProgressBar {{
    background-color: {C.bg_input};
    border: none;
    border-radius: 3px;
    text-align: center;
    color: {C.text_secondary};
    font-size: 10px;
    max-height: 6px;
}}
QProgressBar::chunk {{ background-color: {C.primary}; border-radius: 3px; }}

/* ══════════ 分隔条 ══════════ */
QSplitter::handle {{ background-color: {C.border_light}; }}
QSplitter::handle:horizontal {{ width: 1px; }}
QSplitter::handle:vertical {{ height: 1px; }}

/* ══════════ 消息框 ══════════ */
QMessageBox {{ background-color: {C.bg_card_alt}; }}
QMessageBox QLabel {{ color: {C.text_primary}; font-size: 13px; min-width: 280px; }}
"""


def card_widget(child=None) -> "QFrame":
    """把内容包装成卡片"""
    from qtcompat import QFrame, QVBoxLayout

    card = QFrame()
    card.setObjectName("panel")
    layout = QVBoxLayout(card)
    layout.setContentsMargins(16, 16, 16, 16)
    layout.setSpacing(8)
    if child is not None:
        layout.addWidget(child)
    return card


def section_header(text: str) -> "QLabel":
    from qtcompat import QLabel

    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"color:{C.text_secondary};font-size:11px;font-weight:600;padding:4px 0;background:transparent;"
    )
    return lbl


# ═══════════════════════════════════════════════════════════
#  表格内小按钮样式
#  danger 用「描边」而不是满底红：一屏几十个满底红块会让红色失去稀缺性，
#  用户对危险信号的阈值被拉高 —— 这是防御工具最不能有的失敏。
# ═══════════════════════════════════════════════════════════


def small_button_style(kind: str = "outline") -> str:
    """
    kind: danger | success | primary | outline
    返回适配表格单元格内小按钮（高 22~24px）的样式表。
    """
    base = "border-radius:4px;padding:0 8px;font-size:11px;min-height:20px;max-height:22px;"
    if kind == "danger":
        return (
            f"QPushButton{{background:transparent;color:{C.critical};"
            f"border:1px solid #8E3338;{base}}}"
            f"QPushButton:hover{{background:{C.danger_solid};color:#FFFFFF;"
            f"border-color:{C.danger_solid};}}"
            f"QPushButton:disabled{{background:transparent;color:{C.text_disabled};"
            f"border-color:{C.border_light};}}"
        )
    if kind == "success":
        return (
            f"QPushButton{{background:transparent;color:{C.success};"
            f"border:1px solid #2E6B52;{base}}}"
            f"QPushButton:hover{{background:{C.success};color:{C.accent_on};"
            f"border-color:{C.success};}}"
            f"QPushButton:disabled{{background:transparent;color:{C.text_disabled};"
            f"border-color:{C.border_light};}}"
        )
    if kind == "primary":
        return (
            f"QPushButton{{background:{C.primary};color:{C.accent_on};border:none;{base}}}"
            f"QPushButton:hover{{background:{C.primary_hover};}}"
            f"QPushButton:disabled{{background:{C.bg_card_alt};color:{C.text_disabled};}}"
        )
    return (
        f"QPushButton{{background:transparent;color:{C.text_secondary};"
        f"border:1px solid transparent;{base}}}"
        f"QPushButton:hover{{background:{C.bg_card_alt};color:{C.text_primary};"
        f"border-color:{C.border_strong};}}"
        f"QPushButton:disabled{{color:{C.text_disabled};border-color:transparent;}}"
    )
