"""历史访问「清空列表」守门用例。

这一批盯的是四件写错就会静默出事的地方：

1. **删除条件必须与列表查询同源**（都用 `_access_where`）。各写一套的话，
   界面上「共 320 条」、确认框「删 320 条」、实际删掉 5000 条 —— 没人能自查。
2. **无条件清空必须显式声明**。`delete_access_logs()` 空参调用就等于清空整张
   流水表，所以数据层要求 `all_rows=True`，缺了就抛 `ValueError` 而不是照删。
3. **只删流水，不动风险事件**。流水是「发生过什么」，事件是「当时判成了什么」，
   清流水顺手删证据，事后就再也答不出这个 IP 那天被判过什么。
4. **界面上的条数必须是删之前算出来的那个数**，且取消确认后一条都不能少。
"""

import time
from typing import Any, Dict

import pytest

from app import audit
from core import database
from core.models import AccessRecord, GeoInfo, RiskResult

BASE_DAY_MS = int(time.mktime((2026, 10, 19, 0, 0, 0, 0, 0, -1)) * 1000)
DAY_MS = 86_400_000


@pytest.fixture(autouse=True)
def _schema(fresh_db):
    """fresh_db 只清库文件、不建表，这里补一次建表（建在临时库里）。"""
    database.init_db()
    yield


def _mk(
    ip: str = "45.33.32.156",
    level: str = "low",
    port: int = 18080,
    ts: int = BASE_DAY_MS,
    path: str = "/",
    ua: str = "Mozilla/5.0",
) -> int:
    return database.insert_access_log(
        AccessRecord(
            ip=ip,
            remote_port=51234,
            local_port=port,
            protocol="http",
            method="GET",
            path=path,
            status_code=200,
            user_agent=ua,
            size=512,
            geo=GeoInfo(ip=ip, found=False),
            risk_score=0,
            risk_level=level,
            event_ts=ts,
        )
    )


def _count(**kw) -> int:
    return database.count_access_logs(**kw)


# ═══════════════════ 数据层：条件删除 ═══════════════════


def test_delete_by_level_only_touches_matching():
    _mk(ip="10.0.0.1", level="low")
    _mk(ip="10.0.0.2", level="normal")
    _mk(ip="10.0.0.3", level="high")

    assert database.delete_access_logs(level="high") == 1
    assert _count() == 2
    assert _count(level="high") == 0
    assert _count(level="low") == 1


def test_delete_by_port_and_time_range():
    _mk(ip="10.0.0.1", port=80, ts=BASE_DAY_MS)
    _mk(ip="10.0.0.2", port=443, ts=BASE_DAY_MS)
    _mk(ip="10.0.0.3", port=80, ts=BASE_DAY_MS + DAY_MS)

    # 端口 + 时间左闭右开：第二天零点那条不能算进「10-19 这一天」
    assert (
        database.delete_access_logs(port=80, since_ts=BASE_DAY_MS, until_ts=BASE_DAY_MS + DAY_MS)
        == 1
    )
    assert _count() == 2
    assert _count(port=80) == 1


def test_delete_by_keyword_matches_ip_path_and_ua():
    _mk(ip="10.9.9.9", path="/", ua="Mozilla/5.0")
    _mk(ip="10.0.0.1", path="/admin/login", ua="Mozilla/5.0")
    _mk(ip="10.0.0.2", path="/", ua="sqlmap/1.7")

    assert database.delete_access_logs(keyword="10.9.9.9") == 1
    assert database.delete_access_logs(keyword="/admin") == 1
    assert database.delete_access_logs(keyword="sqlmap") == 1
    assert _count() == 0


def test_delete_without_condition_requires_explicit_flag():
    _mk()
    _mk(ip="10.0.0.2")

    with pytest.raises(ValueError):
        database.delete_access_logs()
    # 抛错前不能已经删了 —— 这条用例防的是「先删后校验」
    assert _count() == 2


def test_delete_all_with_explicit_flag():
    for i in range(3):
        _mk(ip=f"10.0.0.{i}")

    assert database.delete_access_logs(all_rows=True) == 3
    assert _count() == 0


def test_delete_returns_zero_when_nothing_matches():
    _mk(ip="10.0.0.1", level="low")
    assert database.delete_access_logs(level="critical") == 0
    assert _count() == 1


def test_delete_keeps_risk_events():
    """流水可以清，风险结论不能跟着消失"""
    rid = _mk(ip="10.0.0.7", level="high")
    rec = AccessRecord(ip="10.0.0.7", local_port=18080, path="/admin")
    database.insert_risk_event(rec, RiskResult(score=90, level="high", reason="爆破"), rid)

    assert _count() == 1
    assert database.delete_access_logs(all_rows=True) == 1
    assert _count() == 0
    # 事件表仍在，且条数没变
    assert len(database.query_risk_events(limit=10)) == 1


# ═══════════════════ 界面：清空列表 ═══════════════════


def _qapp():
    import os

    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from qtcompat import QApplication

    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication([])
    return app


def _page():
    from gui import page_access

    _qapp()  # 必须持有 QApplication，否则控件无法创建
    return page_access.AccessPage()


def test_clear_button_disabled_when_nothing_to_clear():
    page = _page()
    assert page._total == 0
    assert not page.btn_clear.isEnabled()

    _mk(ip="10.0.0.1")
    page.refresh()
    assert page._total == 1
    assert page.btn_clear.isEnabled()


def test_clear_button_text_and_tooltip_says_no_pagination():
    page = _page()
    assert page.btn_clear.text() == "清空列表"
    tip = page.btn_clear.toolTip()
    assert "不受分页限制" in tip
    # 必须写清「不删什么」，否则用户会以为连封禁一起清了
    assert "封禁" in tip


def test_cancelled_clear_keeps_every_row():
    _mk(ip="10.0.0.1", level="low")
    _mk(ip="10.0.0.2", level="high")
    page = _page()
    page.level.setCurrentIndex(2)  # 「高」
    page.refresh()

    # `_notify` 必须一并屏蔽：一旦确认逻辑被写错成「取消也删」，真删除会弹出
    # 模态信息框把用例挂死（离屏下 `exec()` 等不到人点），报出来的是超时而不是
    # 一条能读懂的断言失败。
    page._confirm_clear = lambda head, total: False
    page._notify = lambda title, text, warn=False: None
    page._clear_list()

    assert _count() == 2
    assert len(database.query_audit(limit=10, action=audit.ACTION_DATA_CLEAR)) == 0


def test_confirmed_clear_deletes_only_filtered_rows_and_audits():
    _mk(ip="10.0.0.1", level="low")
    _mk(ip="10.0.0.2", level="high")
    page = _page()
    page.level.setCurrentIndex(2)  # 「高」
    page.refresh()
    assert page._total == 1

    said = []
    page._confirm_clear = lambda head, total: True
    page._notify = lambda title, text, warn=False: said.append((title, text))
    page._clear_list()

    # 只删了「高」这一条，低危那条还在
    assert _count() == 1
    assert _count(level="high") == 0
    assert page._total == 0 and not page.btn_clear.isEnabled()

    # 审计必须留痕，且写明删了多少
    rows = database.query_audit(limit=10, action=audit.ACTION_DATA_CLEAR)
    assert len(rows) == 1
    assert "删除 1 条" in rows[0]["summary"]
    assert said and "1" in said[-1][1]


def test_clear_without_filters_warns_it_is_everything():
    """无筛选时确认框必须说「全部」，不能只说「清空」"""
    for i in range(3):
        _mk(ip=f"10.0.0.{i}")
    page = _page()
    assert page._total == 3

    seen: Dict[str, Any] = {}

    def fake_confirm(head: str, total: int) -> bool:
        seen["head"] = head
        seen["total"] = total
        return False  # 只看文案，不真删

    page._confirm_clear = fake_confirm
    page._notify = lambda title, text, warn=False: None
    page._clear_list()

    assert seen["total"] == 3
    assert "全部" in seen["head"]
    assert _count() == 3


def test_clear_with_filters_names_the_scope():
    _mk(ip="10.0.0.1", level="high")
    _mk(ip="10.0.0.2", level="low")
    page = _page()
    page.level.setCurrentIndex(2)
    page.refresh()

    seen: Dict[str, Any] = {}

    def fake_confirm(head: str, total: int) -> bool:
        seen["head"] = head
        seen["total"] = total
        return False

    page._confirm_clear = fake_confirm
    page._notify = lambda title, text, warn=False: None
    page._clear_list()

    assert seen["total"] == 1
    assert "等级=高" in seen["head"]
    assert _count() == 2
