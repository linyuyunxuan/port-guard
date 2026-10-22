"""操作 → 状态联动：封禁之后，界面上「该变的东西」必须当场变。

用户主诉：「一键封禁、手动封禁之后，状态应该显示已处理，并且后面的操作应该
显示已封禁」。这类问题肉眼在界面上看得见，根因却全在数据层与刷新时机上，
所以这里钉四件事 —— 每一件写错都会退化成「封了但看不出变化」：

1. `set_risk_handled_by_ip` 只动**未处理**的、且按 IP **等值**匹配
   （用 `LIKE` 会把 1.2.3.4 和 1.2.3.40 一起改掉）；
2. `ban_service.execute` 成功时**在投递封禁事件之前**完成回填 ——
   顺序反了，界面收到的刷新信号早于状态落库，刷新出来的还是「未处理」；
3. 行内主操作按钮随封禁状态改文案并置灰；
4. 「⋯」菜单里当前状态那一项置灰、文案改成状态名（而不是始终可点的
   「确认处理 / 忽略」）。
"""

import os
from typing import Any, Dict, List

import pytest

from core import database
from core.models import AccessRecord, GeoInfo, RiskResult


def _mk(ip: str, score: int = 92, ts: int = 1_700_000_000_000) -> int:
    rec = AccessRecord(
        ip=ip,
        remote_port=51234,
        local_port=18080,
        protocol="tcp",
        path="/admin/login",
        geo=GeoInfo(ip=ip, country="美国", found=True),
        risk_score=score,
        risk_level="critical",
        matched_rules=["geo_sensitive_port"],
        event_ts=ts,
    )
    return database.insert_risk_event(rec, RiskResult(score=score, level="critical"))


def _handled_of(ip: str) -> List[int]:
    rows = database.query_risk_events(limit=100, keyword=ip)
    return [int(r["handled"]) for r in rows]


# ═══════════════════ 1. 按 IP 回填 ═══════════════════


def test_marks_only_unhandled_events(fresh_db) -> None:
    database.init_db()
    _mk("203.0.113.10")
    _mk("203.0.113.10")
    ignored = _mk("203.0.113.10")
    database.set_risk_handled_batch([ignored], 2)

    n = database.set_risk_handled_by_ip("203.0.113.10", 1)

    assert n == 2, "应该只回填两条未处理的"
    assert sorted(_handled_of("203.0.113.10")) == [1, 1, 2], "已忽略的那条被改掉了"


def test_does_not_touch_neighbour_ip(fresh_db) -> None:
    """等值匹配守门：LIKE '%203.0.113.1%' 会顺带改掉 203.0.113.10"""
    database.init_db()
    _mk("203.0.113.1")
    _mk("203.0.113.10")

    n = database.set_risk_handled_by_ip("203.0.113.1", 1)

    assert n == 1
    assert _handled_of("203.0.113.10") == [0], "同前缀的邻居 IP 被连带改了"


def test_empty_ip_is_noop(fresh_db) -> None:
    database.init_db()
    _mk("203.0.113.10")
    assert database.set_risk_handled_by_ip("", 1) == 0
    assert database.set_risk_handled_by_ip("   ", 1) == 0
    assert _handled_of("203.0.113.10") == [0]


# ═══════════════════ 2. 封禁成功 → 回填早于投递 ═══════════════════


def test_execute_marks_events_before_emitting(fresh_db, monkeypatch) -> None:
    """顺序守门：投递那一刻状态必须已经落库。

    反过来（先 emit 再回填）在单测里也能过「最终状态正确」，但真实界面上
    收到 emit 就立刻 refresh 了 —— 用户看到的还是「未处理」，等于没修。
    """
    from app import ban_service
    from core import firewall

    database.init_db()
    ip = "203.0.113.10"
    _mk(ip)
    _mk(ip)

    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    monkeypatch.setattr(firewall, "block_ip", lambda i, duration=None, note="": (True, "r", ""))

    seen: Dict[str, Any] = {}

    def fake_emit(obj: Any) -> None:
        seen["handled"] = _handled_of(ip)

    monkeypatch.setattr(ban_service.bus, "emit_ban", fake_emit)

    ban_id, err = ban_service.execute(ip, 92, "测试", 3600)

    assert ban_id is not None and err == ""
    assert seen.get("handled") == [1, 1], "投递封禁事件时事件状态还没回填，界面会刷到「未处理」"


def test_failed_ban_keeps_events_unhandled(fresh_db, monkeypatch) -> None:
    """封禁失败（防火墙没写进去）不该把事件标成已处理 —— 那是假成功"""
    from app import ban_service
    from core import firewall

    database.init_db()
    ip = "203.0.113.10"
    _mk(ip)

    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    monkeypatch.setattr(
        firewall, "block_ip", lambda i, duration=None, note="": (False, "", "Access denied")
    )

    ban_service.execute(ip, 92, "测试", 3600)

    assert _handled_of(ip) == [0]


# ═══════════════════ 3/4. 界面状态 ═══════════════════


@pytest.fixture(scope="module")
def qapp():
    """离屏 QApplication（与 tests/test_about_dialog.py 同一套做法）"""
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from qtcompat import QApplication

    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication([])
    return app


def test_ban_button_reflects_banned_state(qapp) -> None:
    from gui.components import ban_button

    fired: List[int] = []
    b = ban_button(lambda: fired.append(1))
    assert b.text() == "封禁"
    assert b.isEnabled()
    b.click()
    assert fired == [1]

    b2 = ban_button(lambda: fired.append(2), banned=True, text="确认封禁")
    assert b2.text() == "已封禁"
    assert not b2.isEnabled(), "已封禁的 IP 按钮还能点，用户会以为上次没生效"
    assert b2.toolTip(), "置灰态没有 tooltip，用户看不出为什么点不动"


def test_menu_entry_without_callback_is_disabled(qapp) -> None:
    from gui.components import build_menu

    menu = build_menu([("确认处理", lambda: None), ("已确认", None)])
    acts = menu.actions()
    assert acts[0].isEnabled()
    assert acts[1].text() == "已确认"
    assert not acts[1].isEnabled()


def test_events_page_row_action_and_menu_follow_state(qapp, fresh_db, monkeypatch) -> None:
    from types import SimpleNamespace

    from gui import page_events

    database.init_db()
    page = page_events.EventsPage()
    # 封禁态由 `_load` 从 `database.risk_events_page()` 一次性取回并挂在 `_banned` 上，
    # 行内按钮只认这个映射（不再每次 refresh 单独查一次全表）
    page._banned = {"203.0.113.10": SimpleNamespace(id=7, expire_at=None)}

    banned_row = {"ip": "203.0.113.10", "risk_score": 92, "summary": "x", "handled": 0}
    fresh_row = {"ip": "198.51.100.7", "risk_score": 92, "summary": "x", "handled": 0}
    page._rows = [banned_row, fresh_row]

    # 操作列由自绘 delegate 渲染（gui/row_action.py），状态改从 spec 上取：
    # 「已封禁」必须置灰且 tooltip 说清为什么点不动，未封禁的必须可点。
    banned_spec = page._action_spec(0)
    fresh_spec = page._action_spec(1)
    assert banned_spec is not None
    assert fresh_spec is not None
    assert banned_spec.text == "已封禁" and not banned_spec.enabled
    assert fresh_spec.text == "封禁" and fresh_spec.enabled
    assert "永久" in banned_spec.tip
    # 行号越界（渲染与重排之间）不能抛，也不能画出按钮
    assert page._action_spec(2) is None and page._action_spec(-1) is None

    # 未处理：两个动作都可点（过滤掉分隔线 None，mypy 才能按下标取）
    entries = [e for e in page._menu_entries(fresh_row) if e is not None]
    assert entries[0][0] == "确认处理" and entries[0][1] is not None
    assert entries[1][0] == "忽略" and entries[1][1] is not None

    # 已确认：确认那项置灰、文案即状态；仍保留「改为忽略」以便纠错
    handled = [e for e in page._menu_entries({"ip": "203.0.113.10", "handled": 1}) if e is not None]
    assert handled[0] == ("已确认", None)
    assert handled[1][0] == "改为忽略" and handled[1][1] is not None
