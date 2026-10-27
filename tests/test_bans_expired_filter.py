"""封禁管理页 2026-10-27 三项需求的数据层/交互守门。

用户原话：「封禁管理中，增加双击选择功能，筛选中增加已到期选项；与防火墙对账、
一键全部封禁直接显示在界面中」。

三条里最容易被写错的是「已到期」—— 直觉写法是 `status = expired`，但那只覆盖
「到期巡检**成功**删掉规则」的记录。普通权限下巡检跑不了，「到期了但规则还在拦」
的记录状态仍是 active，而那正是用户要处理的一批（左下角横幅就写着「另有 N 条已
到期」）。筛选若只认 expired，点进去会是 0 条，横幅和列表自相矛盾。

界面级验证（按钮是否常驻、双击是否真的切换勾选）在 `_design/_bans_probe.py`，
这里钉住可在数据层判定的语义。
"""

import time
from typing import Any, Dict, List

import pytest

from core import database
from core.models import STATUS_ACTIVE, STATUS_EXPIRED, STATUS_UNBANNED, BanRecord


@pytest.fixture(autouse=True)
def _schema(fresh_db):
    """fresh_db 只清库文件、不建表，这里补一次建表（建在临时库里）。"""
    database.init_db()
    yield


def _mk_ban(ip: str, status: str = STATUS_ACTIVE, expire_at: int = 0) -> int:
    rec = BanRecord(
        ip=ip, reason="测试封禁", risk_score=90, source="manual", status=status, expire_at=expire_at
    )
    ban_id = database.insert_ban(rec)
    assert ban_id is not None
    return int(ban_id)


def _ips(rows) -> List[str]:
    return [b.ip for b in rows]


NOW = int(time.time() * 1000)
MIN = 60 * 1000


# ═══════════════════ 「已到期」筛选 ═══════════════════


def test_expired_filter_includes_active_but_overdue(monkeypatch):
    """到期但还没解封（status=active）的记录必须出现在「已到期」里，且排最前"""
    from gui import page_bans

    overdue = _mk_ban("203.0.113.7", STATUS_ACTIVE, NOW - 5 * MIN)
    _mk_ban("203.0.113.8", STATUS_ACTIVE, NOW + 60 * MIN)  # 还没到期
    _mk_ban("203.0.113.9", STATUS_ACTIVE, 0)  # 永久封禁
    done = _mk_ban("203.0.113.10", STATUS_EXPIRED, NOW - 90 * MIN)  # 到期且已解封

    rows = page_bans.BansPage._query_expired("")
    assert [b.id for b in rows] == [overdue, done], (
        "到期未解封的要排在已解封之前 —— 那是唯一需要动手的一条"
    )


def test_expired_filter_skips_manually_unbanned():
    """人工主动解封的记录与「到期」无关：混进来会让列表看起来永远清不干净"""
    from gui import page_bans

    _mk_ban("203.0.113.11", STATUS_UNBANNED, NOW - 10 * MIN)
    assert page_bans.BansPage._query_expired("") == []


def test_expired_filter_respects_keyword():
    """搜索词与筛选是**与**关系：筛了已到期还要能按 IP 收窄"""
    from gui import page_bans

    _mk_ban("203.0.113.12", STATUS_ACTIVE, NOW - 1 * MIN)
    _mk_ban("198.51.100.20", STATUS_ACTIVE, NOW - 2 * MIN)
    assert _ips(page_bans.BansPage._query_expired("198.51")) == ["198.51.100.20"]


# ═══════════════════ 一键全部封禁 ═══════════════════


def _emit_ban_many(rows) -> List[Dict[str, Any]]:
    """用真实实现（BansPage._emit_ban_many）跑一遍，只把信号出口换成记录器。

    不构造整页：BansPage 的 __init__ 会查库、起横幅探测，测试只需要那段
    去重逻辑。`_emit_ban_many` 只依赖 `self.ask_ban_many.emit`，所以给一个
    最小宿主就够了 —— 比起把去重逻辑复制到测试里，这样才是真守门。
    """
    from gui import page_bans

    captured: List[Any] = []

    class _Sig:
        @staticmethod
        def emit(items):
            captured.append(items)

    class _Host:
        ask_ban_many = _Sig()

    page_bans.BansPage._emit_ban_many(_Host(), rows)  # type: ignore[arg-type]
    return captured[0] if captured else []


def test_ban_all_dedupes_by_ip_and_keeps_peak_score():
    """同一 IP 的多条事件只产生一条封禁请求，评分取组内最高"""
    rows = [
        {"ip": "45.33.32.156", "risk_score": 75, "summary": "低分那次"},
        {"ip": "45.33.32.156", "peak_score": 95, "summary": "高分那次"},
        {"ip": "8.8.8.8", "risk_score": 90, "summary": "另一个 IP"},
    ]
    items = _emit_ban_many(rows)
    assert [i["ip"] for i in items] == ["45.33.32.156", "8.8.8.8"]
    assert items[0]["score"] == 95, "一个 IP 只封一次，评分必须取最严重的那次"


def test_ban_all_ignores_rows_without_ip():
    """空 IP 行不能变成一条「封 0.0.0.0」的请求"""
    items = _emit_ban_many([{"ip": "", "risk_score": 90}, {"ip": "8.8.8.8", "risk_score": 90}])
    assert [i["ip"] for i in items] == ["8.8.8.8"]
