"""2026-11-10 「待确认封禁建议」口径统一的护栏。

用户反馈：总览写「待确认封禁建议：166 条」，封禁管理 → 待确认建议却是 0 条。
根因是两处口径不同：统计侧数的是全库高危未处理事件行（且把规则已自动拦截的
disposition=block 也算进来），页面侧只取最近 200 条、隐藏已封禁 IP 并按
IP+端口合并。现在三处（总览 / 侧栏角标 / 封禁页）共用同一组判据：

    未处理 + 高危/严重 + 非自动拦截 + IP 未被生效封禁 + 按 (ip, port) 去重

这里钉的是「能自动判定」的部分；真实观感由离屏截图复核。
"""

from core import database
from core.models import DISPOSITION_BLOCK, DISPOSITION_CONFIRM, now_ms
from gui.event_group import merge_rows

_HIGH = ("high", "critical")


def _db() -> None:
    database.init_db()


def _event(
    ip: str,
    disposition: str = "",
    n: int = 1,
    level: str = "high",
    port: int = 3389,
    ts: int = 0,
) -> None:
    conn = database._connect()
    try:
        conn.executemany(
            "INSERT INTO risk_event "
            "(ip, local_port, risk_score, risk_level, handled, disposition, event_ts) "
            "VALUES (?, ?, 90, ?, 0, ?, ?)",
            [(ip, port, level, disposition, (ts or now_ms()) + i) for i in range(n)],
        )
        conn.commit()
    finally:
        conn.close()


def _ban(ip: str, status: str = "active") -> None:
    conn = database._connect()
    try:
        conn.execute("INSERT INTO ban_list (ip, status) VALUES (?, ?)", (ip, status))
        conn.commit()
    finally:
        conn.close()


# ══════════ 统计侧：四条判据 ══════════


def test_stats_excludes_rule_auto_blocked(fresh_db):
    """规则已自动拦截的事件 handled 仍为 0，但不是「等你拿主意」的建议"""
    _db()
    _event("10.0.0.1", DISPOSITION_BLOCK)
    _event("10.0.0.2", DISPOSITION_CONFIRM)
    _event("10.0.0.3", "")
    s = database.stats_snapshot()
    assert s["unhandled"] == 3
    assert s["auto_blocked"] == 1
    assert s["pending"] == 2
    assert s["suggestions"] == 2, "自动拦截过的那条不能再算成待确认建议"


def test_stats_dedups_same_ip_and_port(fresh_db):
    """27 行重复事件 = 1 项建议，统计必须按 merge_rows 的分组键去重"""
    _db()
    _event("10.0.0.1", "", n=27)
    _event("10.0.0.2", "", n=3)
    assert database.stats_snapshot()["suggestions"] == 2


def test_stats_excludes_already_banned_ip(fresh_db):
    _db()
    _event("10.0.0.1")
    _ban("10.0.0.1")
    assert database.stats_snapshot()["suggestions"] == 0


def test_stats_low_level_is_not_a_suggestion(fresh_db):
    _db()
    _event("10.0.0.1", "", level="medium")
    _event("10.0.0.2", "", level="critical")
    assert database.stats_snapshot()["suggestions"] == 1


# ══════════ 页面侧：与统计同口径、且不被 200 条截断 ══════════


def test_suggestion_query_unlimited_and_filters_in_sql(fresh_db):
    """最近 210 条全是自动拦截时，更早的真待办也必须查得到。

    旧实现 limit=200 会先取满 200 条自动拦截事件，真待办被截在后面；
    在 GUI 里再筛也没用 —— 数据根本没取回来。
    """
    _db()
    old = now_ms() - 100_000
    _event("10.0.0.9", DISPOSITION_CONFIRM, ts=old)
    conn = database._connect()
    try:
        conn.executemany(
            "INSERT INTO risk_event "
            "(ip, local_port, risk_score, risk_level, handled, disposition, event_ts) "
            "VALUES (?, 3389, 90, 'high', 0, ?, ?)",
            [(f"10.1.0.{i % 250}", DISPOSITION_BLOCK, now_ms() + i) for i in range(210)],
        )
        conn.commit()
    finally:
        conn.close()

    rows = database.query_risk_events(limit=0, handled=0, pending_only=True)
    assert len(rows) == 1, "自动拦截应在 SQL 里排除，且 limit=0 不能截断"
    assert rows[0]["ip"] == "10.0.0.9"


def test_ban_page_requests_unlimited_pending_only(monkeypatch, fresh_db):
    """页面必须自己要全量、并让 SQL 排除自动拦截；否则口径又会漂回去"""
    from gui import page_bans

    seen = {}

    def _fake(**kw):
        seen.update(kw)
        return []

    monkeypatch.setattr(page_bans, "query_risk_events", _fake)
    monkeypatch.setattr(page_bans, "active_ban_ip_map", dict)

    class _Sort:
        def apply(self, rows):
            return list(rows)

    class _Host:
        def __init__(self) -> None:
            self._banned: dict = {}
            self._sug_rows_src: list = []
            self._sug_rows: list = []
            self._sug_hidden = 0
            self.sug_sort = _Sort()

        def _render_suggestions(self):
            pass

    page_bans.BansPage._load_suggestions(_Host())  # type: ignore[arg-type]
    assert seen.get("limit") == 0, "200 条截断会把真待办藏在后面"
    assert seen.get("pending_only") is True, "自动拦截必须下推到 SQL 排除"


def test_ban_page_count_equals_stats_suggestions(fresh_db):
    """页面合并去重 + 隐藏已封禁 IP 之后，可见项数必须等于角标/总览那个数"""
    _db()
    _event("10.0.0.1", "", n=27)
    _event("10.0.0.2", DISPOSITION_BLOCK, n=5)
    _event("10.0.0.3", "")
    _event("10.0.0.4", "")
    _ban("10.0.0.4")

    rows = [
        r
        for r in database.query_risk_events(limit=0, handled=0, pending_only=True)
        if r.get("risk_level") in _HIGH
    ]
    merged = merge_rows(rows)
    banned = database.active_ban_ip_map()
    visible = [r for r in merged if str(r.get("ip") or "") not in banned]

    assert len(visible) == 2
    assert database.stats_snapshot()["suggestions"] == len(visible)


# ══════════ 总览：0 条时不再挂一行空的「待确认封禁建议」 ══════════


class _Lbl:
    def __init__(self) -> None:
        self.text_value = ""

    def setText(self, text: str) -> None:
        self.text_value = text


def _todo_host():
    from gui.page_overview import OverviewPage

    class _Host:
        def __init__(self) -> None:
            self._refs = {"todo": (_Lbl(), _Lbl(), _Lbl())}
            self._detail_refs = {"todo": _Lbl()}

        _set_detail = OverviewPage._set_detail

        @staticmethod
        def _fail(*_args):
            raise AssertionError("不该走到降级分支")

    return _Host()


def test_todo_detail_hides_zero_suggestions():
    from gui.page_overview import OverviewPage

    host = _todo_host()
    OverviewPage._refresh_todo(host, {"pending": 0, "auto_blocked": 30, "suggestions": 0})
    text = host._detail_refs["todo"].text_value
    assert "规则已自动拦截：30 条" in text
    assert "待确认封禁建议" not in text, "0 条时别再挂一行，点进去是空的更让人困惑"


def test_todo_detail_shows_real_suggestions():
    from gui.page_overview import OverviewPage

    host = _todo_host()
    OverviewPage._refresh_todo(host, {"pending": 2, "auto_blocked": 30, "suggestions": 2})
    text = host._detail_refs["todo"].text_value
    assert "规则已自动拦截：30 条" in text
    assert "待确认封禁建议：2 条" in text
