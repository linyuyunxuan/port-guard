"""历史访问检索（P2-4）的数据层守门：时间范围 + 分页 + 计数一致性。

界面翻页在离屏探针里验，这里钉住三件写错就会「看起来没坏」的事：

1. **时间区间是左闭右开**：`event_ts == until_ts` 必须排除。写成闭区间时，
   界面上「选 10-19 这一天」会多带出 10-20 00:00:00.000 那一条 —— 一天只有
   一条的话，用户会以为选的是两天。
2. **分页取完 == 总数**：`offset/limit` 与 `count_access_logs` 必须对得上，
   否则「第 3/5 页」这种话就是编的。
3. **count 与 query 同条件**：这是最容易 regressions 的一处 —— 两个函数
   各写一份 WHERE，改了 query 忘改 count 就变成「显示 3 条、分页说 200 页」。
   用例把筛选条件排列组合跑一遍，两边条数必须相等。
"""

import time
from typing import Iterable, List, Set

import pytest

from core import database
from core.models import AccessRecord, GeoInfo

BASE_DAY_MS = int(time.mktime((2026, 10, 19, 0, 0, 0, 0, 0, -1)) * 1000)
DAY_MS = 86_400_000


@pytest.fixture(autouse=True)
def _schema(fresh_db):
    """fresh_db 只清库文件、不建表，这里补一次建表（建在临时库里）。"""
    database.init_db()
    yield


def _ids(rows: Iterable[AccessRecord]) -> Set[int]:
    """取出 id 集合（`AccessRecord.id` 标注为 Optional，落库后必非空）"""
    return {int(r.id or 0) for r in rows}


def _mk(
    ts: int,
    ip: str = "45.33.32.156",
    path: str = "/admin/login",
    ua: str = "Mozilla/5.0",
    level: str = "high",
    port: int = 18080,
    score: int = 90,
) -> int:
    return database.insert_access_log(
        AccessRecord(
            ip=ip,
            remote_port=51234,
            local_port=port,
            protocol="http",
            method="GET",
            path=path,
            status_code=401,
            user_agent=ua,
            size=512,
            geo=GeoInfo(ip=ip, country="中国", province="广东省", city="深圳市", found=True),
            risk_score=score,
            risk_level=level,
            matched_rules=["scanner_ua"],
            event_ts=ts,
        )
    )


# ═══════════════════════════════════════════════════════════
#  时间范围：左闭右开
# ═══════════════════════════════════════════════════════════


def test_time_range_is_half_open(fresh_db) -> None:
    first = _mk(BASE_DAY_MS)  # 当天 00:00:00.000
    last = _mk(BASE_DAY_MS + DAY_MS - 1)  # 当天 23:59:59.999
    next_day = _mk(BASE_DAY_MS + DAY_MS)  # 次日 00:00:00.000
    before = _mk(BASE_DAY_MS - 1)

    ids = _ids(
        database.query_access_logs(limit=100, since_ts=BASE_DAY_MS, until_ts=BASE_DAY_MS + DAY_MS)
    )
    assert first in ids, "区间左端必须是闭的：当天零点那条被漏了"
    assert last in ids, "结束当天最后一毫秒被漏掉了（区间写成了左闭右闭）"
    assert next_day not in ids, "次日零点不该算进当天（右端必须是开区间）"
    assert before not in ids, "区间左端外的记录被带进来了"


def test_time_range_open_end_only(fresh_db) -> None:
    """只给一端时另一端不限（界面的「全部时间」就是两端都 None）"""
    old = _mk(BASE_DAY_MS - 10 * DAY_MS)
    new = _mk(BASE_DAY_MS)

    only_since = _ids(database.query_access_logs(limit=100, since_ts=BASE_DAY_MS))
    assert only_since == {new}

    only_until = _ids(database.query_access_logs(limit=100, until_ts=BASE_DAY_MS))
    assert only_until == {old}, "右端开区间：正好等于 until_ts 的那条要排除"

    both_none = _ids(database.query_access_logs(limit=100))
    assert both_none == {old, new}


# ═══════════════════════════════════════════════════════════
#  关键词 / 等级 / 端口
# ═══════════════════════════════════════════════════════════


def test_keyword_matches_ip_path_and_ua(fresh_db) -> None:
    a = _mk(BASE_DAY_MS + 1, ip="45.33.32.156")
    b = _mk(BASE_DAY_MS + 2, ip="113.118.113.77", path="/admin/login")
    c = _mk(BASE_DAY_MS + 3, ip="203.0.113.9", path="/api/orders", ua="sqlmap/1.7")
    _mk(BASE_DAY_MS + 4, ip="10.0.0.7", path="/health", ua="curl/8.0")

    def ids_of(kw: str) -> Set[int]:
        return _ids(database.query_access_logs(limit=100, keyword=kw))

    assert ids_of("45.33") == {a}, "IP 关键词命中范围不对"
    assert ids_of("/admin") == {a, b}, "路径关键词要同时命中多行"
    assert ids_of("sqlmap") == {c}, "用户代理关键词没生效"
    assert ids_of("no-such-token") == set(), "无匹配时应返回空列表"


def test_level_and_port_filters(fresh_db) -> None:
    high_18080 = _mk(BASE_DAY_MS + 1, level="high", port=18080)
    _mk(BASE_DAY_MS + 2, level="normal", port=18080)
    high_3389 = _mk(BASE_DAY_MS + 3, level="high", port=3389)

    rows = database.query_access_logs(limit=100, level="high")
    assert _ids(rows) == {high_18080, high_3389}

    rows = database.query_access_logs(limit=100, level="high", port=3389)
    assert _ids(rows) == {high_3389}

    rows = database.query_access_logs(limit=100, port=18080)
    assert len(rows) == 2


def test_row_fields_are_restored(fresh_db) -> None:
    """列表页直接吃 AccessRecord：tags / matched_rules / 归属地必须还原"""
    rec = AccessRecord(
        ip="45.33.32.156",
        local_port=18080,
        path="/admin/login",
        user_agent="sqlmap/1.7",
        tags={"channel": "watch", "pid": 4321},
        geo=GeoInfo(ip="45.33.32.156", country="中国", province="广东省", city="深圳市"),
        risk_score=90,
        risk_level="high",
        matched_rules=["scanner_ua", "geo_sensitive_port"],
        event_ts=BASE_DAY_MS,
    )
    database.insert_access_log(rec)

    got = database.query_access_logs(limit=10)[0]
    assert got.tags == {"channel": "watch", "pid": 4321}
    assert got.matched_rules == ["scanner_ua", "geo_sensitive_port"]
    assert got.geo is not None and got.geo.city == "深圳市"
    assert got.level_label and got.matched_str


# ═══════════════════════════════════════════════════════════
#  分页
# ═══════════════════════════════════════════════════════════


def test_paging_covers_every_row_exactly_once(fresh_db) -> None:
    total = 25
    all_ids = {_mk(BASE_DAY_MS + i * 1000, ua=f"ua-{i}") for i in range(total)}
    size = 10

    assert database.count_access_logs() == total

    seen: List[int] = []
    for page in range((total + size - 1) // size):
        rows = database.query_access_logs(limit=size, offset=page * size)
        seen.extend(_ids(rows))
    assert len(seen) == total, "逐页取完的总条数必须等于 count"
    assert set(seen) == all_ids, "分页有重复或漏行"
    # 最新在前：第 0 页首行应是 event_ts 最大的那条
    first_page = database.query_access_logs(limit=size, offset=0)
    assert int(first_page[0].event_ts) == BASE_DAY_MS + (total - 1) * 1000


def test_last_page_and_empty(fresh_db) -> None:
    assert database.query_access_logs(limit=10, offset=0) == []
    assert database.count_access_logs() == 0

    ids = [_mk(BASE_DAY_MS + i * 1000) for i in range(3)]
    # offset 越过末尾：空列表而不是报错
    assert database.query_access_logs(limit=10, offset=99) == []
    assert sorted(_ids(database.query_access_logs(limit=10, offset=2))) == [ids[0]]


# ═══════════════════════════════════════════════════════════
#  count 与 query 的条件必须一致
# ═══════════════════════════════════════════════════════════

# (keyword, level, port, since_ts, until_ts)
FILTER_CASES = [
    ("", "", None, None, None),
    ("45.33", "", None, None, None),
    ("/admin", "", None, None, None),
    ("sqlmap", "", None, None, None),
    ("", "high", None, None, None),
    ("", "normal", None, None, None),
    ("", "", 3389, None, None),
    ("", "", None, BASE_DAY_MS, None),
    ("", "", None, None, BASE_DAY_MS + DAY_MS),
    ("", "", None, BASE_DAY_MS, BASE_DAY_MS + DAY_MS),
    ("45.33", "high", 18080, BASE_DAY_MS, BASE_DAY_MS + DAY_MS),
    ("no-such-token", "", None, None, None),
]


@pytest.mark.parametrize(("keyword", "level", "port", "since_ts", "until_ts"), FILTER_CASES)
def test_count_matches_query(fresh_db, keyword, level, port, since_ts, until_ts) -> None:
    """同一组筛选条件下，`count_access_logs` 必须等于 `query_access_logs` 的条数。

    这条是「条件写了两份、改一处漏一处」的探针：两个函数只要有一个条件
    不一致，这里就会红 —— 而且红的那一格会直接指名是哪种组合。
    """
    # 铺一份覆盖各种组合的样本：三种 IP、两条路径、两种 UA、两个等级、两个端口
    for i in range(12):
        _mk(
            BASE_DAY_MS + i * 3_600_000,
            ip=("45.33.32.156" if i % 2 else "203.0.113.9"),
            path=("/admin/login" if i % 3 else "/api/orders"),
            ua=("sqlmap/1.7" if i % 4 else "Mozilla/5.0"),
            level=("high" if i % 2 else "normal"),
            port=(18080 if i % 2 else 3389),
        )
    # 再放两条落在时间窗之外，用来验证 count 也带时间条件
    _mk(BASE_DAY_MS - DAY_MS, ip="45.33.32.156", level="high", port=18080)
    _mk(BASE_DAY_MS + 2 * DAY_MS, ip="45.33.32.156", level="high", port=18080)

    rows = database.query_access_logs(
        limit=1000,
        keyword=keyword,
        level=level,
        port=port,
        since_ts=since_ts,
        until_ts=until_ts,
    )
    n = database.count_access_logs(
        keyword=keyword, level=level, port=port, since_ts=since_ts, until_ts=until_ts
    )
    assert n == len(rows), (
        f"count={n} 与 query={len(rows)} 不一致 "
        f"（keyword={keyword!r} level={level!r} port={port!r} "
        f"since={since_ts} until={until_ts}）"
    )


def test_count_changes_when_data_changes(fresh_db) -> None:
    """计数不是缓存：新增一条就要多一条（界面翻页依赖它实时）"""
    assert database.count_access_logs(keyword="45.33") == 0
    _mk(BASE_DAY_MS, ip="45.33.32.156")
    assert database.count_access_logs(keyword="45.33") == 1
    _mk(BASE_DAY_MS + 1, ip="45.33.32.157")
    assert database.count_access_logs(keyword="45.33") == 2
    assert database.count_access_logs(keyword="45.33.32.156") == 1
