"""
上报侧可信度测试

对应 CODE_REVIEW 的「上报字段可伪造」问题，锁定两条服务端兜底规则：

1. **来源 IP**：只有可信来源（回环地址，或本次请求通过 API Key 校验）才允许用
   body 里的 `ip` 覆盖 TCP 对端地址；否则一律按 TCP 对端地址计。
   否则本机任意进程都能给任意 IP 刷风险分、借自动封禁之手封掉别人。

2. **时间戳**：`event_ts` 会被规则引擎当成「现在」推进 / 清理滑动窗口，
   被保留期删除当作边界。与本机时间偏差超过阈值时一律按本机时间计，
   于是「往回拨让窗口永远累积不起来」和「往前拨清空窗口」两种打法都失效。

为什么用 TestClient 而不是直接调 `_process`：要连 `Request` 的来源地址一起测，
那是整个判定的输入之一。TestClient 给的 `client.host` 是占位串 "testclient"，
所以每个用例都先用中间件把它改成想模拟的来源地址。
"""

import time
from typing import Any, Dict, List

import pytest

from core import settings as cfg
from core.database import init_db, query_access_logs
from core.db_writer import get_writer, start_writer

httpx = pytest.importorskip("httpx")
from fastapi.testclient import TestClient

from core import pipeline, report_server

LOOPBACK = "127.0.0.1"
LAN = "192.168.1.50"

GOOD = {
    "local_port": 3000,
    "method": "GET",
    "path": "/api/products",
    "status_code": 200,
    "user_agent": "Mozilla/5.0",
}


# ═══════════════════════════════════════════════
#  装置
# ═══════════════════════════════════════════════


def _make_client(source_ip: str) -> TestClient:
    """起一个上报服务，并把 ASGI scope 里的来源地址改成 `source_ip`"""
    app = report_server._make_app("")

    @app.middleware("http")
    async def _fake_source(request, call_next):
        request.scope["client"] = (source_ip, 50000)
        return await call_next(request)

    return TestClient(app)


@pytest.fixture
def env(isolated_env):
    init_db()
    start_writer()
    cfg.warm()
    cfg.set("api_key", "")
    cfg.set("rate_limit_per_sec", 0)  # 关掉限流，单测专注可信度逻辑
    cfg.set("trust_reported_ip", "1")
    cfg.set("report_max_ts_skew_sec", 300)


@pytest.fixture
def rec_capture(monkeypatch) -> List[Any]:
    """拦下真正交给 pipeline 的 AccessRecord，用于检查 event_ts 等不下发的字段"""
    captured: List[Any] = []
    original = pipeline.process_record

    def spy(rec, **kwargs):
        captured.append(rec)
        return original(rec, **kwargs)

    monkeypatch.setattr(report_server, "process_record", spy)
    return captured


def _flush_db() -> None:
    """等批量写入线程落盘，好在库里断言"""
    w = get_writer()
    if w:
        w.flush(timeout=5)


# ═══════════════════════════════════════════════
#  来源 IP 信任判定
# ═══════════════════════════════════════════════


def test_loopback_source_keeps_body_ip(env, monkeypatch):
    """回环来源属于可信来源：body 里的 ip 照旧生效（兼容既有业务系统）"""
    with _make_client(LOOPBACK) as c:
        d = c.post("/api/v1/access/report", json=dict(GOOD, ip="203.0.113.10")).json()["data"]
    assert d["ip"] == "203.0.113.10"

    _flush_db()
    rows = query_access_logs(keyword="203.0.113.10")
    assert len(rows) == 1


def test_untrusted_source_ignores_body_ip(env, monkeypatch):
    """不可信来源（局域网、未配 API Key）：body 的 ip 被忽略，改用 TCP 对端地址"""
    with _make_client(LAN) as c:
        d = c.post("/api/v1/access/report", json=dict(GOOD, ip="203.0.113.10")).json()["data"]
    assert d["ip"] == LAN

    _flush_db()
    rows = query_access_logs(keyword=LAN)
    assert len(rows) == 1
    assert query_access_logs(keyword="203.0.113.10") == []


def test_api_key_validated_source_keeps_body_ip(env, monkeypatch):
    """配了 Key 且校验通过：来源可信，body 里的 ip 生效（跨主机转发场景）"""
    cfg.set("api_key", "s3cret")
    app = report_server._make_app("s3cret")

    @app.middleware("http")
    async def _fake_source(request, call_next):
        request.scope["client"] = (LAN, 50000)
        return await call_next(request)

    with TestClient(app) as c:
        headers = {"X-API-Key": "s3cret"}
        d = c.post(
            "/api/v1/access/report", json=dict(GOOD, ip="203.0.113.10"), headers=headers
        ).json()["data"]
    assert d["ip"] == "203.0.113.10"


def test_trust_reported_ip_off_forces_peer_ip(env, monkeypatch):
    """
    设置里把信任开关关掉后，即使来源是回环也一律按 TCP 对端地址计。

    先跑一次「开」确认生效，再关掉跑第二次 —— 两次用同一条请求，
    差别只在配置，用来证明行为确实随配置切换。
    """
    with _make_client(LOOPBACK) as c:
        d_on = c.post("/api/v1/access/report", json=dict(GOOD, ip="203.0.113.10")).json()["data"]
    assert d_on["ip"] == "203.0.113.10"

    cfg.set("trust_reported_ip", "0")
    with _make_client(LOOPBACK) as c:
        d_off = c.post("/api/v1/access/report", json=dict(GOOD, ip="203.0.113.10")).json()["data"]
    assert d_off["ip"] == LOOPBACK

    cfg.set("trust_reported_ip", "1")
    with _make_client(LOOPBACK) as c:
        d_back = c.post("/api/v1/access/report", json=dict(GOOD, ip="203.0.113.10")).json()["data"]
    assert d_back["ip"] == "203.0.113.10"


def test_batch_uses_peer_ip_for_untrusted_source(env, monkeypatch):
    """/access/batch 同样走信任判定（批量接口不该成为绕过口）"""
    items = [dict(GOOD, ip="203.0.113.11"), dict(GOOD, ip="203.0.113.12")]
    with _make_client(LAN) as c:
        r = c.post("/api/v1/access/batch", json={"items": items})
    assert r.status_code == 200

    _flush_db()
    assert [x.ip for x in query_access_logs(keyword="203.0.113.1") if x.ip] == []
    assert all(x.ip == LAN for x in query_access_logs(keyword=LAN))


def test_missing_ip_falls_back_to_peer(env, monkeypatch):
    """body 不带 ip 时本来就用对端地址，与信任与否无关"""
    with _make_client(LAN) as c:
        d = c.post("/api/v1/access/report", json=dict(GOOD)).json()["data"]
    assert d["ip"] == LAN


def test_invalid_ip_still_returns_400(env, monkeypatch):
    """回归：伪造 IP 的注入串在可信来源下仍被拒（状态码与文案都不变）"""
    with _make_client(LOOPBACK) as c:
        r = c.post("/api/v1/access/report", json=dict(GOOD, ip='1.2.3.4"; Start-Process calc; #'))
    assert r.status_code == 400
    assert "无效的 IP" in r.json()["detail"]


# ═══════════════════════════════════════════════
#  时间戳纠偏
# ═══════════════════════════════════════════════


def _event_ts_of(payload: Dict[str, Any], source_ip: str, captured: List[Any]) -> int:
    """上报一条并取回服务端实际采用的时间戳"""
    with _make_client(source_ip) as c:
        c.post("/api/v1/access/report", json=payload)
    assert captured, "处理链路没有被调用"
    return captured[-1].event_ts


def test_forged_old_timestamp_replaced_by_server_time(env, monkeypatch, rec_capture):
    """伪造 1970 的时间戳：窗口型规则才不会被「永远累积不起来」废掉"""
    before = int(time.time() * 1000)
    ts = _event_ts_of(dict(GOOD, ip="203.0.113.10", timestamp=0), LOOPBACK, rec_capture)
    after = int(time.time() * 1000)
    assert before <= ts <= after


def test_forged_future_timestamp_replaced_by_server_time(env, monkeypatch, rec_capture):
    """伪造 2099 的时间戳：才不会触发清理逻辑把窗口清空"""
    future = int(time.time() * 1000) + 100 * 365 * 86400 * 1000
    before = int(time.time() * 1000)
    ts = _event_ts_of(dict(GOOD, ip="203.0.113.10", timestamp=future), LOOPBACK, rec_capture)
    after = int(time.time() * 1000)
    assert before <= ts <= after


def test_timestamp_within_skew_is_kept(env, monkeypatch, rec_capture):
    """阈值内的客户端时间戳保留：业务系统带自己采集时间是合理场景"""
    client_ts = int(time.time() * 1000) - 30_000  # 30 秒前的排队日志
    ts = _event_ts_of(dict(GOOD, ip="203.0.113.10", timestamp=client_ts), LOOPBACK, rec_capture)
    assert ts == client_ts


def test_missing_timestamp_uses_server_time(env, monkeypatch, rec_capture):
    """不带 timestamp：直接用服务端时间"""
    before = int(time.time() * 1000)
    ts = _event_ts_of(dict(GOOD, ip="203.0.113.10"), LOOPBACK, rec_capture)
    after = int(time.time() * 1000)
    assert before <= ts <= after


def test_unparsable_timestamp_uses_server_time(env, monkeypatch, rec_capture):
    """timestamp 是乱码：回落服务端时间而不是抛出或写出 0"""
    before = int(time.time() * 1000)
    ts = _event_ts_of(dict(GOOD, ip="203.0.113.10", timestamp="not-a-time"), LOOPBACK, rec_capture)
    after = int(time.time() * 1000)
    assert before <= ts <= after


def test_skew_threshold_is_configurable(env, monkeypatch, rec_capture):
    """阈值调小后，原本被接受的偏差也要被纠偏 —— 证明阈值真的生效"""
    client_ts = int(time.time() * 1000) - 30_000
    ts_wide = _event_ts_of(
        dict(GOOD, ip="203.0.113.10", timestamp=client_ts), LOOPBACK, rec_capture
    )
    assert ts_wide == client_ts

    cfg.set("report_max_ts_skew_sec", 10)
    before = int(time.time() * 1000)
    ts_tight = _event_ts_of(
        dict(GOOD, ip="203.0.113.10", timestamp=client_ts), LOOPBACK, rec_capture
    )
    after = int(time.time() * 1000)
    assert before <= ts_tight <= after
