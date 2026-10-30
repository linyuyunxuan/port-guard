"""Alerter（core/alerts.py）的行为锁：静默 / 合并节流 / 升级分支 / GC / 文案。

背景：告警链路在 2026-10-22 / 10-27 连续被用户反馈驱动重构过两轮
（「已拦截还弹窗影响操作」「取消模态弹窗」），这些约定必须锁死，
防止下次重构悄悄退回成"每次都弹、每次都响"。
"""

import time
from typing import Any, Dict, List

import pytest

from core import alert_webhook
from core import settings as cfg
from core.alerts import Alerter
from core.database import init_db
from core.models import DISPOSITION_ALLOW, DISPOSITION_BLOCK, DISPOSITION_CONFIRM


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    init_db()
    # Webhook 一律打桩：单测不许真的调度网络推送
    sent: List[Dict] = []
    monkeypatch.setattr(alert_webhook, "send_async", lambda a: sent.append(a) or True)
    cfg.set("alert_block_silent", "1", persist=False)
    cfg.set("alert_merge_sec", "60", persist=False)
    cfg.set("alert_sound", "0", persist=False)  # 测试环境不响铃
    yield sent


def _alert(**kw) -> Dict[str, Any]:
    base = {
        "ip": "203.0.113.9",
        "level": "high",
        "score": 95,
        "reason": "端口扫描",
        "disposition": DISPOSITION_BLOCK,
    }
    base.update(kw)
    return base


def test_repeated_block_hit_is_silent(_env):
    """「已拦截」的重复命中不弹不响（2026-10-22 用户原话要求）。

    变异：把 notify 里的 block_silent 判断删掉 → 本例变红（返回 True）。
    """
    a = Alerter()
    assert a.notify(_alert(blocked_again=True)) is False
    # 没进节流表：静默不该消耗合并窗口
    assert "203.0.113.9" not in a._last_alert
    assert _env == [], "静默分支不该调度 Webhook"


def test_escalated_bypasses_silence(_env):
    """升级黑名单是「策略变了」：必须突破静默，让用户知道"""
    a = Alerter()
    assert a.notify(_alert(blocked_again=True, escalated=True, block_hits=7)) is True
    assert _env and _env[0]["ip"] == "203.0.113.9"
    assert "已列入黑名单" in Alerter._escalation_title("203.0.113.9", _alert())


def test_merge_throttle_same_ip(_env):
    """同 IP 在合并窗口内的第二条不弹；不同 IP 不受影响"""
    a = Alerter()
    assert a.notify(_alert()) is True
    assert a.notify(_alert()) is False, "同 IP 窗口内重复告警应被节流"
    assert a.notify(_alert(ip="198.51.100.7")) is True


def test_merge_disabled_allows_every_alert(_env):
    """merge_sec=0 表示关闭合并：每条都过（设置页把滑块拉到 0 的语义）"""
    cfg.set("alert_merge_sec", "0", persist=False)
    a = Alerter()
    assert a.notify(_alert()) is True
    assert a.notify(_alert()) is True


def test_block_hits_surfaced_when_silence_off(_env):
    """关掉静默后，重复命中允许弹出，且次数必须写进正文——
    否则这条弹窗和上一条长得一模一样，等于白打扰一次"""
    cfg.set("alert_block_silent", "0", persist=False)
    a = Alerter()
    assert a.notify(_alert(blocked_again=True, block_hits=3)) is True
    body = Alerter._body(_alert(blocked_again=True, block_hits=3))
    assert "3 次" in body


def test_title_speaks_disposition_first():
    """标题先说处理结果再说级别（用户提出的原话）"""
    assert "已拦截" in Alerter._title("high", DISPOSITION_BLOCK)
    assert "待确认" in Alerter._title("critical", DISPOSITION_CONFIRM)
    assert "已放行" in Alerter._title("low", DISPOSITION_ALLOW)
    # 无 disposition（老调用方）退回按级别措辞
    assert "高风险" in Alerter._title("high", "")


def test_gc_caps_throttle_table():
    """节流表超阈值时必须回收旧条目，长期运行不无限增长"""
    a = Alerter()
    now = time.time()
    old = now - 10_000_000  # 远早于任何合并窗口
    a._last_alert = {f"10.0.0.{i}": old for i in range(2100)}
    a._gc(now, 60)
    assert len(a._last_alert) < 2000
    # 新条目不受影响
    assert a.notify(_alert(ip="8.8.8.8")) is True


def test_webhook_failure_never_breaks_local_alert(monkeypatch, _env):
    """推送只是「额外一条路」：它炸了本地气泡/声音照常"""

    def boom(a):
        raise RuntimeError("network down")

    monkeypatch.setattr(alert_webhook, "send_async", boom)
    a = Alerter()
    assert a.notify(_alert()) is True, "Webhook 异常不允许吃掉本地告警"
