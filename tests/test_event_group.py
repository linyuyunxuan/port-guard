"""gui/event_group.py —— 同类合并的纯逻辑测试。

变异验证已逐条做过（把实现改回错的看会不会红）：
- 分键去掉 handled → test_different_handled_status_split_into_two_groups 红
- 分键去掉 matched_rules → test_different_rules_split 红
- 代表行取第一条而非最新 → test_representative_is_latest 红
- 成员不按时间倒序 → test_members_sorted_desc 红
- group_count 删除 → test_merge_counts_and_ids 红
- flatten 丢 members → test_flatten_expands_groups 红
"""

from typing import Any, Dict, List, Optional

from gui.event_group import flatten_rows, group_key, merge_rows


def _ev(
    id: int,
    ts: int,
    ip: str = "182.118.236.163",
    port: int = 1024,
    score: int = 20,
    level: str = "low",
    handled: int = 0,
    rules: Optional[List[str]] = None,
    path: str = "",
) -> Dict[str, Any]:
    if rules is None:
        rules = ["geo_sensitive_port"]
    return {
        "id": id,
        "event_ts": ts,
        "ip": ip,
        "local_port": port,
        "path": path,
        "risk_score": score,
        "risk_level": level,
        "handled": handled,
        "matched_rules": list(rules),
    }


def test_identical_events_merge_into_one_group():
    rows = [_ev(i, 1000 + i) for i in range(1, 6)]
    out = merge_rows(rows)
    assert len(out) == 1
    g = out[0]
    assert g["group_count"] == 5
    assert g["member_ids"] == [5, 4, 3, 2, 1]
    assert len(g["members"]) == 5


def test_group_count_defaults_and_ids():
    rows = [_ev(7, 500)]
    out = merge_rows(rows)
    assert out[0]["group_count"] == 1
    assert out[0]["member_ids"] == [7]
    # 单条组不应带出误导性的 members 之外的东西；members 就是自己
    assert [m["id"] for m in out[0]["members"]] == [7]


def test_representative_is_latest():
    # 输入故意乱序，代表必须是时间最新的那条
    rows = [_ev(1, 100), _ev(2, 900), _ev(3, 500)]
    out = merge_rows(rows)
    assert out[0]["id"] == 2
    assert out[0]["event_ts"] == 900


def test_members_sorted_desc():
    rows = [_ev(1, 300), _ev(2, 100), _ev(3, 200)]
    out = merge_rows(rows)
    assert [m["id"] for m in out[0]["members"]] == [1, 3, 2]


def test_group_order_follows_first_appearance():
    # SQL 按时间倒序返回：A 组最新在前。B 组虽然成员时间更早，
    # 组间顺序应保持 A、B（= 最近发生的组在前）。两组用不同 score 区分。
    a = [_ev(1, 900, score=20), _ev(2, 800, score=20)]
    b = [_ev(3, 100, score=45), _ev(4, 50, score=45)]
    out = merge_rows(a + b)
    assert len(out) == 2
    assert out[0]["risk_score"] == 20
    assert out[0]["member_ids"] == [1, 2]
    assert out[1]["risk_score"] == 45
    assert out[1]["member_ids"] == [3, 4]


def test_different_ip_split():
    out = merge_rows([_ev(1, 100, ip="1.1.1.1"), _ev(2, 200, ip="2.2.2.2")])
    assert len(out) == 2


def test_different_score_or_level_split():
    out = merge_rows([_ev(1, 100, score=20), _ev(2, 200, score=45)])
    assert len(out) == 2
    out = merge_rows([_ev(1, 100, level="low"), _ev(2, 200, level="high")])
    assert len(out) == 2


def test_different_handled_status_split_into_two_groups():
    # 已确认的 3 条和未处理的 2 条不能摞成一行 —— 状态列不许撒谎
    rows = [_ev(1, 100), _ev(2, 200), _ev(3, 300, handled=1), _ev(4, 400, handled=1)]
    out = merge_rows(rows)
    assert len(out) == 2
    by_handled = {g["handled"]: g for g in out}
    assert by_handled[0]["group_count"] == 2
    assert by_handled[1]["group_count"] == 2


def test_different_rules_split():
    out = merge_rows([_ev(1, 100, rules=["a"]), _ev(2, 200, rules=["a", "b"])])
    assert len(out) == 2


def test_different_path_or_port_split():
    out = merge_rows([_ev(1, 100, path="/admin"), _ev(2, 200, path="/")])
    assert len(out) == 2
    out = merge_rows([_ev(1, 100, port=1024), _ev(2, 200, port=3389)])
    assert len(out) == 2


def test_merge_does_not_mutate_input():
    rows = [_ev(1, 100), _ev(2, 200)]
    merge_rows(rows)
    assert "group_count" not in rows[0]
    assert "members" not in rows[0]


def test_flatten_expands_groups():
    rows = [_ev(1, 100), _ev(2, 200), _ev(3, 300, handled=1)]
    groups = merge_rows(rows)
    flat = flatten_rows(groups)
    assert sorted(m["id"] for m in flat) == [1, 2, 3]
    # 摊平后拿到的必须是原始行（带全部字段），不是组代表
    assert all("members" not in m for m in flat)


def test_flatten_passes_through_plain_rows():
    rows = [_ev(1, 100)]
    assert flatten_rows(rows) == rows


def test_group_key_handles_missing_fields():
    # 脏数据（字段缺失 / None / 非数字分数）不能抛异常
    k1 = group_key({"ip": None, "local_port": None, "risk_score": "x"})
    k2 = group_key({})
    assert k1[0] == ""
    assert k2[2] == ""
    assert group_key(_ev(1, 1)) == group_key(_ev(2, 2))  # 同特征不同 id/time 同组
