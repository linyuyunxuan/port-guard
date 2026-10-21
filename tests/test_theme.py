"""主题回归：浅底 + 深字 + 字号下限。

这一组用例是「别再改回深色 / 别再把字缩回去」的护栏。用户明确提出过
「不喜欢黑色、要白色底、字号太小看不清」，而这类要求最容易在下一次
调色时被无意破坏（改一个 bg_card 就整片变灰，改一个 font-size 就缩回 12px）。
"""

import re

import pytest

from gui.theme import (
    GLOBAL_STYLE,
    LEVEL_BADGE_BG,
    LEVEL_COLORS,
    C,
    small_button_style,
)

# ═══════════════════ 对比度工具（WCAG 2.1）═══════════════════


def _srgb(channel: int) -> float:
    v = channel / 255.0
    return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4


def _lum(hex_color: str) -> float:
    h = hex_color.lstrip("#")
    r, g, b = (int(h[i : i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _srgb(r) + 0.7152 * _srgb(g) + 0.0722 * _srgb(b)


def contrast(a: str, b: str) -> float:
    la, lb = _lum(a), _lum(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


# ═══════════════════ 浅色主题 ═══════════════════


def test_surfaces_are_light_and_text_is_dark():
    """底色必须是浅的、正文必须是深的（用户明确不要黑色底）"""
    assert _lum(C.bg_body) > 0.85, f"页面底色不够浅：{C.bg_body}"
    assert _lum(C.bg_card) > 0.95, f"卡片底色不够浅：{C.bg_card}"
    assert _lum(C.bg_sidebar) > 0.95, f"侧边栏底色不够浅：{C.bg_sidebar}"
    assert _lum(C.text_primary) < 0.05, f"正文色不够深：{C.text_primary}"


def test_legacy_dark_palette_is_gone():
    """旧的石墨主题色值不许回流（半途改回去比全改更难看）"""
    from gui import theme

    with open(theme.__file__, encoding="utf-8") as fh:
        src = fh.read().upper()
    for legacy in ("#0F1115", "#1A1F27", "#232830", "#0A0C10", "#E4E8ED"):
        assert legacy not in src, f"旧深色主题色 {legacy} 又回来了"


@pytest.mark.parametrize("fg", ["text_primary", "text_secondary", "text_muted"])
@pytest.mark.parametrize("bg", ["bg_body", "bg_card", "bg_card_alt"])
def test_text_on_surface_has_enough_contrast(fg: str, bg: str):
    """正文/次要/弱化三档文字在三个表面上的对比度都要够 4.5:1"""
    ratio = contrast(getattr(C, fg), getattr(C, bg))
    assert ratio >= 4.5, f"{fg} on {bg} 只有 {ratio:.2f}:1"


@pytest.mark.parametrize(
    "name", ["primary", "success", "danger_solid", "warning", "info", "critical"]
)
def test_solid_fill_supports_white_text(name: str):
    """实底按钮配白字，必须 ≥4.5:1（浅底主题最容易在这里翻车）"""
    ratio = contrast(getattr(C, name), C.accent_on)
    assert ratio >= 4.5, f"{name} 上的白字只有 {ratio:.2f}:1"


@pytest.mark.parametrize("level", ["low", "medium", "high", "critical"])
def test_level_text_on_white_is_readable(level: str):
    ratio = contrast(LEVEL_COLORS[level], C.bg_card)
    assert ratio >= 4.5, f"等级 {level} 的文字只有 {ratio:.2f}:1"


def test_normal_badge_is_not_a_dark_block():
    """「正常」徽章原来固定深灰（#2B313C），浅底上会变成一个个黑块"""
    assert _lum(LEVEL_BADGE_BG["normal"]) > 0.7


def test_selection_row_keeps_dark_text():
    """选中行底是极浅的靛，选中文字必须仍是深色"""
    ratio = contrast(C.text_on_dark, C.primary_soft)
    assert ratio >= 7, f"选中行文字只有 {ratio:.2f}:1"


# ═══════════════════ 字号下限 ═══════════════════


def _font_size(selector_block: str) -> float:
    m = re.search(r"font-size:\s*([\d.]+)px", selector_block)
    assert m, f"没有 font-size：{selector_block[:40]}"
    return float(m.group(1))


def _block(selector: str) -> str:
    """取 QSS 里某个选择器的声明块（只用于断言，不追求通用性）"""
    idx = GLOBAL_STYLE.index(selector)
    return GLOBAL_STYLE[idx : GLOBAL_STYLE.index("}", idx)]


@pytest.mark.parametrize(
    "selector,minimum",
    [
        ("QWidget {", 15),  # 全局基准
        ("QTableView, QTableWidget {", 13.5),  # 表格正文
        ("QHeaderView::section {", 12.5),  # 表头
        ("QPushButton {", 14),  # 普通按钮
        ("#btn_primary {", 14),
        ("QLineEdit {", 14),
        ("#form_label {", 13.5),
        ("#hint {", 12.5),
        ("QToolTip {", 13),
    ],
)
def test_font_sizes_are_not_shrunk_back(selector: str, minimum: float):
    got = _font_size(_block(selector))
    assert got >= minimum, f"{selector} 字号 {got}px < 下限 {minimum}px"


def test_table_small_button_font_matches_denser_table():
    """行内小按钮跟着表格字号走，不能还是 11px"""
    style = small_button_style("danger")
    assert _font_size(style) >= 12
    assert "max-height:26px" in style


def test_checkbox_checked_state_ships_a_real_checkmark():
    """选中态必须带对勾图片，不能退回「只填一个纯色方块」

    QSS 一旦改 `QCheckBox::indicator:checked` 的底色，Qt 就不画原生对勾；
    浅色主题下纯色方块和「禁用色块」几乎分不开，表格勾了哪些行全靠猜。
    这条用例同时兜住 `assets/check.png` 被误删（缺图时 asset_url 返回 none）。
    """
    block = _block("QCheckBox::indicator:checked {")
    assert "image: url(" in block, f"选中态没有对勾图片：{block}"
    assert "none" not in block, "对勾图片没找到（assets/check.png 缺失？）"
