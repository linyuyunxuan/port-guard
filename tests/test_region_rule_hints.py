"""区域规则对话框「动作语义」文案守门用例（2026-10-22 用户反馈）。

用户对动作语义的理解（合并后）：
  · 放行 = 仅限所选区域放行，其他区域访问所选端口直接拦截；
  · 判定风险 = 仅针对所选区域拦截，其他区域不受影响。
要求把这些语义**在新增/编辑规则对话框里标注清楚**，让用户不看文档也会配。

这批用例盯两件事：
1. 下拉框里每个动作的名称必须把语义讲清（含「仅限/仅针对」的方向词）；
2. 选中动作后底部提示必须写明：命中区域怎样、其他区域怎样。
   少了任何一半，用户就会配错方向（比如以为「放行」只豁免不拦）。
"""

import pytest

from core.rules_meta import REGION_ACTIONS
from gui.region_rules import RegionRuleDialog

ACTION_INDEX = {k: i for i, (k, _) in enumerate(REGION_ACTIONS)}


@pytest.fixture()
def qapp():
    """离屏 QApplication（对话框需要实例）"""
    from qtcompat import QApplication

    app = QApplication.instance() or QApplication([])
    yield app


def _dialog(qapp, action: str) -> RegionRuleDialog:
    dlg = RegionRuleDialog({"name": "t"})
    dlg.cb_action.setCurrentIndex(ACTION_INDEX[action])
    return dlg


def test_combo_labels_state_the_direction():
    """下拉框动作名必须自带方向词，光看名字就知道拦的是谁、放的是谁"""
    labels = dict(REGION_ACTIONS)
    assert "仅限所选区域通行" in labels["allow"]
    assert "直接拦截" in labels["allow"]
    assert "仅针对所选区域拦截" in labels["suggest_ban"]
    assert "不受本规则影响" in labels["suggest_ban"]


def test_hint_allow_says_others_blocked(qapp):
    """放行 = 仅限所选区域通行，其他区域访问所选端口直接拦截"""
    dlg = _dialog(qapp, "allow")
    text = dlg.lbl_hint.text()
    assert "仅限所选区域通行" in text
    assert "直接写入防火墙拦截" in text
    assert "归属地未知" in text, "归属地未知的默认拒绝行为必须写明"


def test_hint_suggest_ban_states_both_sides(qapp):
    """判定风险 = 仅针对所选区域拦截，其他区域不受影响"""
    dlg = _dialog(qapp, "suggest_ban")
    text = dlg.lbl_hint.text()
    assert "仅针对所选区域拦截" in text
    assert "其他区域不受本规则影响" in text
