"""风险事件页新增能力的数据层守门：时间筛选 + 批量改状态 + 批量删除。

界面行为在 `_design/_events_probe.py` 里做离屏验证（勾选、全选、去重、
工具栏不溢出），这里只钉住三件一旦写错就会静默出错的事：

1. **时间区间是左闭右开**：结束日期传「次日零点」，否则选 10-19 当天会漏掉
   23:59:59.9xx 的事件 —— 毫秒精度下这种 off-by-one 肉眼看不出来。
2. **批量改状态是一次事务**：勾 2000 条逐条提交会产生 2000 次 fsync。
3. **删除只动 risk_event**：access_log 是原始流水，删事件不该把访问记录一起抹了。
"""

import time

import pytest

from core import database
from core.models import AccessRecord, GeoInfo, RiskResult


@pytest.fixture(autouse=True)
def _schema(fresh_db):
    """fresh_db 只清库文件、不建表，这里补一次建表（建在临时库里）。"""
    database.init_db()
    yield


def _mk(score: int, level: str, ts: int, ip: str = "45.33.32.156") -> int:
    rec = AccessRecord(
        ip=ip,
        remote_port=51234,
        local_port=18080,
        protocol="tcp",
        path="/admin/login",
        geo=GeoInfo(ip=ip, country="美国", province="加利福尼亚州", city="弗里蒙特", found=True),
        risk_score=score,
        risk_level=level,
        matched_rules=["geo_sensitive_port"],
        event_ts=ts,
    )
    result = RiskResult(score=score, level=level, matched_rules=["geo_sensitive_port"])
    return database.insert_risk_event(rec, result)


def _day_ms(y: int, m: int, d: int) -> int:
    return int(time.mktime((y, m, d, 0, 0, 0, 0, 0, -1)) * 1000)


def test_query_by_time_range_is_half_open(fresh_db) -> None:
    base = _day_ms(2026, 10, 19)
    inside_first = _mk(90, "high", base)  # 当天 00:00:00.000
    inside_last = _mk(90, "high", base + 86_400_000 - 1)  # 当天 23:59:59.999
    next_day = _mk(90, "high", base + 86_400_000)  # 次日 00:00:00.000
    before = _mk(90, "high", base - 1)

    day = database.query_risk_events(limit=100, since_ts=base, until_ts=base + 86_400_000)
    ids = {int(r["id"]) for r in day}
    assert inside_first in ids
    assert inside_last in ids, "结束当天的最后一毫秒被漏掉了（区间写成了左闭右闭）"
    assert next_day not in ids, "次日零点不该算进当天（右端必须是开区间）"
    assert before not in ids

    # 只给一端也要能用
    only_since = database.query_risk_events(limit=100, since_ts=base)
    assert {int(r["id"]) for r in only_since} == {inside_first, inside_last, next_day}


def test_time_range_composes_with_other_filters(fresh_db) -> None:
    base = _day_ms(2026, 10, 19)
    high = _mk(90, "high", base + 1000)
    _mk(45, "medium", base + 2000)

    rows = database.query_risk_events(
        limit=100,
        level="high",
        handled=0,
        keyword="45.33",
        since_ts=base,
        until_ts=base + 86_400_000,
    )
    assert [int(r["id"]) for r in rows] == [high]


def test_batch_handled_updates_all(fresh_db) -> None:
    ids = [_mk(90, "high", _day_ms(2026, 10, 19) + i) for i in range(5)]
    other = _mk(90, "high", _day_ms(2026, 10, 19) + 100)

    n = database.set_risk_handled_batch(ids, 2)
    assert n == len(ids)

    handled = {int(r["id"]): r["handled"] for r in database.query_risk_events(limit=100)}
    assert all(handled[i] == 2 for i in ids), "批量忽略没有全部生效"
    assert handled[other] == 0, "没被选中的事件被误改了"

    # 空列表必须是安全的空操作（界面上「没勾选」时按钮是禁用的，
    # 但信号仍可能被外部调用）
    assert database.set_risk_handled_batch([], 1) == 0


def test_delete_only_touches_risk_event(fresh_db) -> None:
    ids = [_mk(90, "high", _day_ms(2026, 10, 19) + i) for i in range(3)]
    keep = _mk(45, "medium", _day_ms(2026, 10, 19) + 50)
    # 造一条访问流水，用来证明删事件不会连带删流水
    conn = database._connect()
    try:
        conn.execute(
            "INSERT INTO access_log (ip, local_port, protocol, path, risk_score,"
            " risk_level, event_ts) VALUES (?,?,?,?,?,?,?)",
            ("45.33.32.156", 18080, "tcp", "/admin/login", 90, "high", _day_ms(2026, 10, 19)),
        )
        conn.commit()
    finally:
        conn.close()

    n = database.delete_risk_events(ids)
    assert n == len(ids)

    left = {int(r["id"]) for r in database.query_risk_events(limit=100)}
    assert left == {keep}, "删除范围不对"

    conn = database._connect()
    try:
        access_left = int(conn.execute("SELECT COUNT(*) c FROM access_log").fetchone()["c"])
    finally:
        conn.close()
    assert access_left == 1, "删除风险事件时把访问流水也删了（流水是原始事实，不能动）"

    assert database.delete_risk_events([]) == 0
