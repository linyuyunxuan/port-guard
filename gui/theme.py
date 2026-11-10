"""
PortGuard 全局主题 —— 「素白哨岗 Paper Watchtower」

设计取向：**白底 + 石墨字 + 单一靛蓝强调色**，颜色只表达语义、不做装饰。
实心色块只留给「主动作 + 危险动作」，其余层级靠 1px 细线与极浅的灰阶分层：
页面 #F4F6FA → 卡片 #FFFFFF → 表头 #F8FAFC，差 3~4 个明度点，够分层次又不脏。

字号基准 15px（原先 13px）：表格 13.5px、表头 12.5px、次要说明 12.5~13px。
字号变大后所有固定行高同步放大（表格 34px、页头 62px），否则中文会被裁。

约束：QSS 的 border-radius 只支持单值；无 box-shadow / transition /
letter-spacing。所有取值必须同时在 PySide2(Qt5.15) 与 PySide6(Qt6) 上成立。
"""

import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # 仅用于类型标注，运行时不需要 Qt
    from qtcompat import QFrame, QLabel


@dataclass(frozen=True)
class Color:
    # ── 强调与语义色 ──
    # 浅底上必须自己压深：白字配 #6C7CF5 只有 3.4:1，够不着 4.5:1
    primary: str = "#3349B8"  # 哨兵靛：主动作、选中条、focus、文字强调
    primary_hover: str = "#2A3DA6"
    primary_pressed: str = "#22328E"
    primary_light: str = "#EDF1FC"
    primary_soft: str = "#E5E9FF"  # 表格/列表选中行底
    success: str = "#0B6B4A"
    success_light: str = "#E3F3EC"
    danger: str = "#C0392B"  # 高危语义（文字 / 描边）
    danger_solid: str = "#B02A20"  # 满底危险（配白字 6.6:1）
    danger_light: str = "#FBE9E7"
    warning: str = "#8A5200"
    warning_light: str = "#FFF3DF"
    critical: str = "#8E1B14"  # 严重语义的深红
    critical_light: str = "#FBE8E6"
    info: str = "#1B4FD1"
    info_light: str = "#E6EEFC"

    # ── 表面层级（由浅到深）──
    bg_body: str = "#ECF1F8"  # 页面底
    bg_input: str = "#FFFFFF"  # 输入框 / 下拉 / 日志区
    bg_card: str = "#FFFFFF"  # 卡片 / 表格
    bg_card_alt: str = "#F2F5FA"  # 抬升面：对话框 / 菜单 / 表头 / tooltip
    bg_zebra: str = "#F7F9FC"
    bg_hover: str = "#EDF1F7"
    bg_sidebar: str = "#FAFBFD"
    bg_sidebar_hover: str = "#F0F4FA"
    bg_sidebar_active: str = "#E7EEFC"
    bg_disabled: str = "#F0F2F6"

    # ── 描边 ──
    border: str = "#D7DEEA"
    border_light: str = "#EDF1F7"
    border_strong: str = "#C4CCDA"
    border_hover: str = "#9AA7BC"

    # ── 文字 ──
    text_primary: str = "#18202E"
    text_secondary: str = "#46536A"
    # 弱化文字（表头、提示、页脚）在浅底上不能低于 4.5:1 —— 用户明确说过「看不清」，
    # 这里按 WCAG 卡死：#737D8D 在 bg_card_alt 上只有 3.98:1，已换深一档。
    text_muted: str = "#53627A"
    text_on_dark: str = "#121722"  # 名字沿用：这里指「最强的一档字」（标题 / 悬停）
    text_link: str = "#2F42BE"
    text_disabled: str = "#9AA3B2"
    accent_on: str = "#FFFFFF"  # 实心填充上的文字


C = Color()


def asset_path(rel: str) -> str:
    """`assets/` 下某个文件的绝对路径；不存在返回空串。

    QSS 只认真实文件路径：它既不支持 SVG data URI，也画不了折线，
    所以勾选框的对勾只能是一张小位图（见 `tools/gen_ui_assets.py`）。
    打包后路径要指到 PyInstaller 的 _MEIPASS，不能写死相对路径 —— 从
    快捷方式启动时工作目录不是程序目录，相对路径会静默失效。
    """
    try:
        from core.config import resource_path

        path = os.path.abspath(resource_path(rel))
    except Exception:  # pragma: no cover —— 只读资源缺失时降级，不挡启动
        return ""
    return path if os.path.exists(path) else ""


def asset_url(rel: str) -> str:
    """同 `asset_path`，转成 QSS 的 `url('...')`（Windows 要把反斜杠换掉）"""
    path = asset_path(rel)
    return f"url('{path.replace(chr(92), '/')}')" if path else "none"


#: 勾选框选中态的白色对勾（13×13，绘制于 tools/gen_ui_assets.py）
CHECK_IMAGE = asset_url("assets/check.png")

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
    "normal": C.bg_sidebar_active,
    "low": C.info_light,
    "medium": C.warning_light,
    "high": C.danger_light,
    "critical": C.danger_solid,
}


GLOBAL_STYLE = f"""
/* ══════════ 全局 ══════════ */
QWidget {{
    font-family: "Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI", sans-serif;
    font-size: 15px;
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
    font-size: 17px;
    font-weight: 700;
    padding: 0;
}}
#sidebar_sub {{
    color: {C.text_muted};
    font-size: 12.5px;
    padding: 0;
}}
#nav_group {{
    color: {C.text_muted};
    font-size: 12.5px;
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
    padding: 0 16px;
    min-height: 42px;
    font-size: 14.5px;
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
    font-size: 12.5px;
    padding: 0;
}}
#sidebar_ban {{
    color: {C.text_secondary};
    font-size: 13.5px;
    font-weight: 600;
    padding: 0;
}}
#sidebar_sep {{ background-color: {C.border_light}; max-height: 1px; min-height: 1px; }}

/* ══════════ 顶部状态条 ══════════ */
#topbar {{
    background-color: {C.bg_card};
    border-bottom: 1px solid {C.border_light};
}}
#topbar_item {{ color: {C.text_secondary}; font-size: 12.5px; }}
#topbar_sep {{ background-color: {C.border}; max-width: 1px; min-width: 1px; }}

/* ══════════ 页面标题 ══════════ */
#page_title {{
    color: {C.text_on_dark};
    font-size: 23px;
    font-weight: 600;
}}
#page_desc {{
    color: {C.text_muted};
    font-size: 13.5px;
}}
#page_divider {{ background-color: {C.border_light}; max-height: 1px; min-height: 1px; }}

/* ══════════ 统计卡 ══════════ */
#stat_card {{
    background-color: {C.bg_card};
    border: 1px solid {C.border_light};
    border-radius: 8px;
}}
#stat_card:hover {{ border-color: {C.border}; }}
#stat_value {{
    font-family: "Consolas", "Microsoft YaHei UI", monospace;
    font-size: 32px;
    font-weight: 700;
    color: {C.text_on_dark};
}}
#stat_label {{
    font-size: 12.5px;
    color: {C.text_secondary};
}}
/* 单位跟在数字右下角，用弱化色 —— 它是量纲不是数据 */
#stat_unit {{
    font-size: 13px;
    color: {C.text_muted};
}}

/* ══════════ 面板 / 分组 ══════════ */
#panel {{
    background-color: {C.bg_card};
    border: 1px solid {C.border_light};
    border-radius: 8px;
}}
#panel_title {{
    font-size: 16px;
    font-weight: 600;
    color: {C.text_on_dark};
}}
#panel_divider {{ background-color: {C.border_light}; max-height: 1px; min-height: 1px; }}
#hint {{
    color: {C.text_muted};
    font-size: 13px;
}}

/* ── 表单（设置页 / 对话框）──
   标签列固定 128 右对齐，字段左缘对齐；hint 是字段右侧的一句补充，
   mono_hint 用于路径 / URL / 状态这类等宽对齐更易读的值。 */
#form_label {{
    color: {C.text_secondary};
    font-size: 14px;
}}
#form_hint {{
    color: {C.text_muted};
    font-size: 14px;
}}
#mono_hint {{
    color: {C.text_secondary};
    font-family: "Consolas", "Microsoft YaHei UI", monospace;
    font-size: 13.5px;
}}

/* ══════════ 按钮 ══════════ */
QPushButton {{
    background-color: {C.bg_card};
    color: {C.text_primary};
    border: 1px solid {C.border_strong};
    border-radius: 6px;
    padding: 7px 16px;
    font-size: 14.5px;
    font-weight: 500;
}}
QPushButton:hover {{ background-color: {C.bg_hover}; border-color: {C.border_hover}; }}
QPushButton:pressed {{ background-color: {C.bg_card_alt}; border-color: {C.border}; }}
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
    padding: 7px 18px;
    font-size: 14.5px;
    font-weight: 600;
}}
#btn_primary:hover {{ background-color: {C.primary_hover}; border-color: {C.primary_hover}; }}
#btn_primary:pressed {{ background-color: {C.primary_pressed}; border-color: {C.primary_pressed}; }}
#btn_primary:disabled {{
    background-color: {C.bg_disabled};
    color: {C.text_disabled};
    border-color: {C.border_light};
}}

#btn_success {{
    background-color: {C.success};
    color: {C.accent_on};
    border: 1px solid {C.success};
    border-radius: 6px;
    padding: 7px 18px;
    font-size: 14.5px;
    font-weight: 600;
}}
#btn_success:hover {{ background-color: #0E7450; border-color: #0E7450; }}
#btn_success:disabled {{
    background-color: {C.bg_disabled};
    color: {C.text_disabled};
    border-color: {C.border_light};
}}

#btn_danger {{
    background-color: {C.danger_solid};
    color: #FFFFFF;
    border: 1px solid {C.danger_solid};
    border-radius: 6px;
    padding: 7px 18px;
    font-size: 14.5px;
    font-weight: 600;
}}
#btn_danger:hover {{ background-color: {C.danger}; border-color: {C.danger}; }}
#btn_danger:pressed {{ background-color: #A92724; border-color: #A92724; }}
#btn_danger:disabled {{
    background-color: {C.bg_disabled};
    color: {C.text_disabled};
    border-color: {C.border_light};
}}

#btn_warning {{
    background-color: {C.warning};
    color: {C.accent_on};
    border: 1px solid {C.warning};
    border-radius: 6px;
    padding: 7px 16px;
    font-size: 13.5px;
    font-weight: 600;
}}
#btn_warning:hover {{ background-color: #8A5100; border-color: #8A5100; }}
/* 焦点环：实底按钮上用深色描边才看得见（白描边压在浅色底上等于没有） */
#btn_primary:focus {{ border: 1px solid {C.primary_pressed}; }}
#btn_success:focus {{ border: 1px solid #0B5C40; }}
#btn_warning:focus {{ border: 1px solid #6E4100; }}
#btn_danger:focus {{ border: 1px solid #8E1F1C; }}

#btn_outline {{
    background-color: {C.bg_card};
    color: {C.text_primary};
    border: 1px solid {C.border_strong};
    border-radius: 6px;
    padding: 7px 16px;
    font-size: 14.5px;
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
    padding: 6px 14px;
    font-size: 14px;
}}
#btn_ghost:hover {{ background-color: {C.bg_hover}; color: {C.text_primary}; }}

#btn_sm {{ border-radius: 4px; padding: 3px 12px; font-size: 13.5px; }}
#btn_link {{
    background: transparent; border: none; color: {C.text_link};
    padding: 2px 4px; font-size: 13.5px;
}}

/* ══════════ 输入控件 ══════════ */
#input, QLineEdit {{
    background-color: {C.bg_input};
    border: 1px solid {C.border};
    border-radius: 6px;
    padding: 7px 11px;
    font-size: 14.5px;
    color: {C.text_primary};
    selection-background-color: {C.primary};
    selection-color: {C.accent_on};
}}
#input:hover, QLineEdit:hover {{ border-color: {C.border_strong}; }}
#input:focus, QLineEdit:focus {{ border-color: {C.primary}; background-color: #FFFFFF; }}
QLineEdit:disabled {{ color: {C.text_disabled}; background-color: {C.bg_disabled}; }}
QLineEdit::placeholder {{ color: {C.text_muted}; }}

QComboBox {{
    background-color: {C.bg_input};
    border: 1px solid {C.border};
    border-radius: 6px;
    padding: 7px 11px;
    font-size: 14.5px;
    color: {C.text_primary};
}}
QComboBox:hover {{ border-color: {C.border_strong}; }}
QComboBox:focus {{ border-color: {C.primary}; }}
QComboBox:disabled {{ color: {C.text_disabled}; background-color: {C.bg_disabled}; }}
QComboBox::drop-down {{ border: none; width: 24px; }}
QComboBox QAbstractItemView {{
    background-color: {C.bg_card};
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
    padding: 9px;
    font-size: 14px;
    color: {C.text_primary};
    selection-background-color: {C.primary};
    selection-color: {C.accent_on};
}}
QTextEdit:focus, QPlainTextEdit:focus {{ border-color: {C.primary}; }}

QSpinBox, QDoubleSpinBox {{
    background-color: {C.bg_input};
    border: 1px solid {C.border};
    border-radius: 6px;
    padding: 6px 22px 6px 9px;
    font-size: 14.5px;
    color: {C.text_primary};
    selection-background-color: {C.primary};
    selection-color: {C.accent_on};
}}
QSpinBox:hover, QDoubleSpinBox:hover {{ border-color: {C.border_strong}; }}
QSpinBox:focus, QDoubleSpinBox:focus {{ border-color: {C.primary}; }}
QSpinBox:disabled, QDoubleSpinBox:disabled {{
    color: {C.text_disabled}; background-color: {C.bg_disabled};
}}
/* 上下按钮/箭头交给 Fusion 默认绘制。两条路都试过并都更差：
   只改 ::up-button 宽度 → 箭头不画了（看着像个纯文本框）；
   连 ::up-arrow 一起用「透明边框拼三角」→ QSpinBox 画成黑方块
   （同一个写法 QDateEdit 却是好的）。保留 padding-right 让文字不顶到箭头上。 */
/* 日期框必须显式配色：不写这一条会退回 Fusion 默认样式，
   与全局字号/圆角不一致，深色主题时代更是直接变成一块白板 */
QDateEdit {{
    background-color: {C.bg_input};
    border: 1px solid {C.border};
    border-radius: 6px;
    padding: 6px 9px;
    font-size: 13.5px;
    color: {C.text_primary};
    selection-background-color: {C.primary};
    selection-color: {C.accent_on};
}}
QDateEdit:hover {{ border-color: {C.border_strong}; }}
QDateEdit:focus {{ border-color: {C.primary}; }}
QDateEdit::drop-down {{ border: none; width: 22px; }}
QDateEdit::down-arrow {{
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid {C.text_secondary};
    width: 0; height: 0; margin-right: 6px;
}}
QCalendarWidget QWidget {{ alternate-background-color: {C.bg_card_alt}; }}
QCalendarWidget QAbstractItemView {{
    background-color: {C.bg_card};
    color: {C.text_primary};
    selection-background-color: {C.primary};
    selection-color: {C.accent_on};
}}
QCalendarWidget QToolButton {{
    color: {C.text_primary}; background: transparent; border: none; padding: 5px 9px;
}}
QCalendarWidget QToolButton:hover {{ background: {C.bg_hover}; border-radius: 4px; }}

/* ══════════ 表格 ══════════ */
QTableView, QTableWidget {{
    background-color: {C.bg_card};
    alternate-background-color: {C.bg_zebra};
    border: 1px solid {C.border_light};
    border-radius: 8px;
    gridline-color: {C.border_light};
    font-size: 13.5px;
    outline: none;
    selection-background-color: {C.primary_soft};
    selection-color: {C.text_on_dark};
}}
QTableView:focus, QTableWidget:focus {{
    border: 1px solid {C.primary};
}}
QTableView::item, QTableWidget::item {{
    padding: 0 9px;
    border: none;
    color: {C.text_primary};
}}
QTableView::item:hover, QTableWidget::item:hover {{ background-color: {C.bg_hover}; }}
QTableView::item:selected, QTableWidget::item:selected {{
    background-color: {C.primary_soft};
    color: {C.text_on_dark};
}}
QHeaderView {{ background-color: {C.bg_card_alt}; border: none; }}
QHeaderView::section {{
    background-color: {C.bg_card_alt};
    color: {C.text_secondary};
    border: none;
    border-bottom: 1px solid {C.border};
    padding: 10px 11px;
    font-weight: 600;
    font-size: 12.5px;
}}
QHeaderView::section:hover {{ color: {C.text_primary}; }}
QHeaderView::down-arrow, QHeaderView::up-arrow {{ width: 9px; height: 9px; }}
QTableCornerButton::section {{ background-color: {C.bg_card_alt}; border: none; }}

/* ══════════ 复选框 / 单选 ══════════ */
QCheckBox {{ color: {C.text_primary}; font-size: 14.5px; spacing: 8px; }}
QCheckBox::indicator {{
    width: 16px; height: 16px;
    border: 1px solid {C.border_strong};
    border-radius: 3px;
    background-color: {C.bg_input};
}}
QCheckBox::indicator:hover {{ border-color: {C.primary}; }}
/* 选中态必须带对勾：只改底色的话，浅色主题下它和「禁用色块」分不开，
   用户看不出这张表到底勾了哪些行（对勾是 13×13 位图，见 assets/check.png）。 */
QCheckBox::indicator:checked {{
    background-color: {C.primary};
    border-color: {C.primary};
    image: {CHECK_IMAGE};
}}
QCheckBox::indicator:checked:hover {{
    background-color: {C.primary_hover};
    border-color: {C.primary_hover};
    image: {CHECK_IMAGE};
}}
QCheckBox::indicator:indeterminate {{
    background-color: {C.primary};
    border-color: {C.primary};
}}
QCheckBox::indicator:disabled {{
    background-color: {C.bg_disabled}; border-color: {C.border_light};
}}
/* 勾着却被禁用：保留「已勾」的形状，只把色降下来 —— 变回空框会让人以为勾选丢了 */
QCheckBox::indicator:checked:disabled {{
    background-color: {C.border_strong};
    border-color: {C.border_strong};
    image: {CHECK_IMAGE};
}}
QCheckBox::indicator:focus {{ border-color: {C.info}; }}

/* ══════════ 图标按钮（行内「⋯」等）══════════ */
QToolButton {{
    background: transparent;
    border: none;
    border-radius: 4px;
    color: {C.text_secondary};
    padding: 0;
    font-size: 15px;
}}
QToolButton:hover {{ background-color: {C.bg_hover}; color: {C.text_primary}; }}
QToolButton:pressed {{ background-color: {C.border_light}; }}
QToolButton:focus {{ border: 1px solid {C.info}; }}
QToolButton::menu-indicator {{ image: none; width: 0; }}

/* ══════════ 文字 ══════════ */
QLabel {{ color: {C.text_primary}; font-size: 15px; background: transparent; }}

/* ══════════ 分组框（设置页 / 规则页）══════════ */
QGroupBox {{
    background-color: {C.bg_card};
    border: 1px solid {C.border_light};
    border-radius: 8px;
    margin-top: 0;
    padding: 48px 18px 18px 18px;
    color: {C.text_on_dark};
}}
QGroupBox::title {{
    subcontrol-origin: padding;
    subcontrol-position: top left;
    left: 18px;
    top: 15px;
    padding: 0;
    background: transparent;
    color: {C.text_on_dark};
    font-size: 16px;
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
    padding: 9px 2px;
    margin-right: 26px;
    color: {C.text_secondary};
    font-size: 14px;
}}
QTabBar::tab:hover {{ color: {C.text_primary}; }}
QTabBar::tab:selected {{
    color: {C.text_on_dark};
    font-weight: 600;
    border-bottom: 2px solid {C.primary};
}}

/* ══════════ 滚动条 ══════════ */
QScrollBar:vertical {{ background: transparent; width: 11px; margin: 0; }}
QScrollBar::handle:vertical {{
    background: rgba(30, 36, 48, 0.18);
    border-radius: 5px;
    min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: rgba(30, 36, 48, 0.30); }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; background: none; }}
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: none; }}
QScrollBar:horizontal {{ background: transparent; height: 11px; margin: 0; }}
QScrollBar::handle:horizontal {{
    background: rgba(30, 36, 48, 0.18);
    border-radius: 5px;
    min-width: 30px;
}}
QScrollBar::handle:horizontal:hover {{ background: rgba(30, 36, 48, 0.30); }}
QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{ width: 0; background: none; }}
QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {{ background: none; }}
QScrollArea {{ border: none; background: transparent; }}

/* ══════════ 状态栏 ══════════ */
QStatusBar {{
    background-color: {C.bg_card};
    border-top: 1px solid {C.border_light};
    color: {C.text_secondary};
    font-size: 12.5px;
    padding: 0 10px;
}}
QStatusBar::item {{ border: none; }}

/* ══════════ 菜单 / 提示 ══════════ */
QMenu {{
    background-color: {C.bg_card};
    border: 1px solid {C.border};
    border-radius: 8px;
    padding: 4px;
}}
QMenu::item {{ padding: 8px 26px 8px 13px; border-radius: 4px; color: {C.text_primary}; }}
QMenu::item:selected {{ background-color: {C.primary_soft}; color: {C.text_on_dark}; }}
QMenu::separator {{ height: 1px; background: {C.border_light}; margin: 4px 8px; }}

QToolTip {{
    background-color: {C.bg_card};
    color: {C.text_primary};
    border: 1px solid {C.border_strong};
    border-radius: 6px;
    padding: 7px 11px;
    font-size: 13.5px;
}}

/* ══════════ 列表 ══════════ */
QListWidget {{
    background-color: {C.bg_card};
    border: 1px solid {C.border_light};
    border-radius: 8px;
    outline: none;
}}
QListWidget::item {{ padding: 9px 11px; border: none; }}
QListWidget::item:hover {{ background-color: {C.bg_hover}; }}
QListWidget::item:selected {{ background-color: {C.primary_soft}; color: {C.text_on_dark}; }}

/* ══════════ 进度条 ══════════ */
QProgressBar {{
    background-color: {C.bg_hover};
    border: none;
    border-radius: 3px;
    text-align: center;
    color: {C.text_secondary};
    font-size: 11px;
    max-height: 7px;
}}
QProgressBar::chunk {{ background-color: {C.primary}; border-radius: 3px; }}

/* ══════════ 分隔条 ══════════ */
/* 透明 10px 手感区 + 悬停才显线：1px 实线夹在两张白卡片之间时，
   会被读成「表格的边框」而不是「可以拖的缝」。 */
QSplitter::handle {{ background-color: transparent; }}
QSplitter::handle:hover {{ background-color: {C.border}; }}
QSplitter::handle:horizontal {{ width: 10px; }}
QSplitter::handle:vertical {{ height: 10px; }}

/* ══════════ 消息框 ══════════ */
QMessageBox {{ background-color: {C.bg_card}; }}
QMessageBox QLabel {{ color: {C.text_primary}; font-size: 15px; min-width: 300px; }}

/* ══════════ 总览台（Overview Grid）══════════
   只追加、不前插：test_theme 用 GLOBAL_STYLE.index(selector) 取首次出现，
   前插会改掉被钉住块的命中位置。这里只放颜色 / 间距 / 单值圆角 / 字号。 */
#breadcrumb {{
    background-color: {C.bg_card};
    border-bottom: 1px solid {C.border_light};
    font-size: 13.5px;
}}
#quick_link {{
    background-color: transparent;
    color: {C.text_secondary};
    border: none;
    border-radius: 6px;
    padding: 6px 14px;
    font-size: 14px;
}}
#quick_link:hover {{
    background-color: {C.bg_hover};
    color: {C.text_primary};
}}
#quick_link:checked {{
    background-color: {C.bg_sidebar_active};
    color: {C.text_on_dark};
    font-weight: bold;
}}
#card_number {{
    font-family: "Consolas", "Microsoft YaHei UI", monospace;
    font-size: 38px;
    font-weight: 700;
    color: {C.text_on_dark};
    margin: 0 0 2px 0;
}}
#barstrip_container {{
    background-color: {C.bg_card_alt};
    border: none;
    border-radius: 6px;
    font-size: 12.5px;
}}
QFrame#panel {{
    background-color: {C.bg_card};
    border: 1px solid {C.border_light};
    border-radius: 8px;
    font-size: 15px;
}}

/* ══════════ Phase 2：卡片明细 / 页头强调条（只追加、不前插）══════════ */
#card_detail {{
    background-color: {C.bg_zebra};
    border: 1px solid {C.border_light};
    border-left: 2px solid {C.primary};
    border-radius: 6px;
    padding: 7px 10px;
    color: {C.text_primary};
    font-size: 13px;
}}
#page_accent {{
    background-color: {C.primary};
    border-radius: 2px;
}}

/* ══════════ 二级分区导航 / 子菜单（只追加、不前插）══════════ */
#section_index {{
    background-color: {C.bg_card};
    border: 1px solid {C.border_light};
    border-radius: 8px;
}}
#section_index_group {{
    color: {C.text_muted};
    font-size: 12.5px;
    font-weight: 600;
    padding-right: 6px;
}}
#section_index_btn {{
    background-color: transparent;
    color: {C.text_secondary};
    border: 1px solid transparent;
    border-radius: 14px;
    padding: 5px 13px;
    font-size: 13.5px;
}}
#section_index_btn:hover {{
    background-color: {C.primary_soft};
    color: {C.text_on_dark};
}}
#section_index_btn:checked {{
    background-color: {C.primary};
    color: {C.accent_on};
    font-weight: 600;
}}

/* ══════════ 一级功能分类：胶囊页签（与 #section_index 同一套视觉语言）══════════
   原生 QTabWidget 的 corner widget 落在 tab 条外面，做不出「分组名在框内」，
   所以由 components.CapsuleTabs 自己搭胶囊条；页面仍由隐藏 tabBar 的
   QTabWidget 管，addTab / setTabText / currentChanged 等接口全部照旧。     */
#capsule_tabs_bar {{
    background-color: {C.bg_card};
    border: 1px solid {C.border_light};
    border-radius: 18px;
}}
#capsule_tabs_pages::pane {{
    border: none;
    background: transparent;
}}
#capsule_tabs_group {{
    color: {C.text_muted};
    font-size: 12.5px;
    font-weight: 600;
    padding-right: 6px;
}}
#capsule_tabs_btn {{
    background-color: transparent;
    color: {C.text_secondary};
    border: 1px solid transparent;
    border-radius: 14px;
    padding: 5px 13px;
    font-size: 13.5px;
}}
#capsule_tabs_btn:hover {{
    background-color: {C.primary_soft};
    color: {C.text_on_dark};
}}
#capsule_tabs_btn:checked {{
    background-color: {C.primary};
    color: {C.accent_on};
    font-weight: 600;
}}

/* ══════════ 总览台 6 卡：轻量精修（结构仍是 3 列 × 2 行）══════════
   只加层级锚点、拉开数字与明细的对比，不改卡片数量与下钻目标。         */
#overview_accent {{
    background-color: {C.primary};
    border-radius: 2px;
}}
#overview_dot {{
    background-color: {C.primary};
    border-radius: 4px;
}}
#overview_card_title {{
    color: {C.text_secondary};
    font-size: 13px;
    font-weight: 600;
}}
#overview_card_foot {{
    color: {C.text_muted};
    font-size: 12px;
}}
#overview_link {{
    background-color: transparent;
    color: {C.text_link};
    border: none;
    border-radius: 6px;
    padding: 6px 14px;
    font-size: 13.5px;
    font-weight: 600;
}}
#overview_link:hover {{
    background-color: {C.primary_light};
    color: {C.primary};
}}
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
        f"color:{C.text_secondary};font-size:12.5px;font-weight:600;padding:4px 0;background:transparent;"
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
    返回适配表格单元格内小按钮（高 26px）的样式表。
    """
    base = "border-radius:4px;padding:0 9px;font-size:12.5px;min-height:24px;max-height:26px;"
    if kind == "danger":
        return (
            f"QPushButton{{background:transparent;color:{C.critical};"
            f"border:1px solid #E9B4B2;{base}}}"
            f"QPushButton:hover{{background:{C.danger_solid};color:#FFFFFF;"
            f"border-color:{C.danger_solid};}}"
            f"QPushButton:disabled{{background:transparent;color:{C.text_disabled};"
            f"border-color:{C.border_light};}}"
        )
    if kind == "success":
        return (
            f"QPushButton{{background:transparent;color:{C.success};"
            f"border:1px solid #A9DCC5;{base}}}"
            f"QPushButton:hover{{background:{C.success};color:{C.accent_on};"
            f"border-color:{C.success};}}"
            f"QPushButton:disabled{{background:transparent;color:{C.text_disabled};"
            f"border-color:{C.border_light};}}"
        )
    if kind == "primary":
        return (
            f"QPushButton{{background:{C.primary};color:{C.accent_on};border:none;{base}}}"
            f"QPushButton:hover{{background:{C.primary_hover};}}"
            f"QPushButton:disabled{{background:{C.bg_disabled};color:{C.text_disabled};}}"
        )
    return (
        f"QPushButton{{background:transparent;color:{C.text_secondary};"
        f"border:1px solid transparent;{base}}}"
        f"QPushButton:hover{{background:{C.bg_hover};color:{C.text_primary};"
        f"border-color:{C.border_strong};}}"
        f"QPushButton:disabled{{color:{C.text_disabled};border-color:transparent;}}"
    )
