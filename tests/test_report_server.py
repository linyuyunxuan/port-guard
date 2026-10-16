"""
上报接收服务测试（对应审查报告 S2 / S3）

覆盖：默认收敛、鉴权、限流、请求体上限、错误处理、CORS 收敛。
"""
import json
from typing import Any, Dict

import pytest

from core import settings as cfg
from core.config import APP_VERSION
from core.database import init_db

httpx = pytest.importorskip("httpx")
from fastapi.testclient import TestClient

from core import report_server


@pytest.fixture
def client(isolated_env):
    init_db()
    cfg.warm()
    cfg.set("api_key", "")
    cfg.set("rate_limit_per_sec", 0)       # 默认关掉限流，单测专注其它逻辑
    app = report_server._make_app("")
    with TestClient(app) as c:
        yield c


GOOD = {
    "ip": "203.0.113.10",
    "local_port": 3000,
    "method": "GET",
    "path": "/api/products",
    "status_code": 200,
    "user_agent": "Mozilla/5.0",
}


# ═══════════════════ 默认收敛 ═══════════════════

def test_default_listen_host_is_loopback():
    from core.config import DEFAULT_LISTEN_HOST, DEFAULT_SETTINGS
    assert DEFAULT_LISTEN_HOST == "127.0.0.1"
    assert DEFAULT_SETTINGS["listen_host"] == "127.0.0.1"


def test_interactive_docs_disabled(client):
    """关闭 /docs、/redoc、/openapi.json，减少信息暴露面"""
    assert client.get("/docs").status_code == 404
    assert client.get("/redoc").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_cors_not_enabled_by_default(client):
    """服务端直连不需要 CORS；默认不加中间件"""
    r = client.get("/api/v1/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}


def test_cors_whitelist_when_configured(isolated_env):
    init_db()
    cfg.warm()
    cfg.set("cors_origins", "https://ok.example")
    app = report_server._make_app("")
    with TestClient(app) as c:
        r = c.get("/api/v1/health", headers={"Origin": "https://ok.example"})
        assert r.headers.get("access-control-allow-origin") == "https://ok.example"
        r2 = c.get("/api/v1/health", headers={"Origin": "https://evil.example"})
        assert r2.headers.get("access-control-allow-origin") != "https://evil.example"


# ═══════════════════ 鉴权 ═══════════════════

def test_no_key_means_open(isolated_env):
    init_db()
    cfg.warm()
    cfg.set("api_key", "")
    app = report_server._make_app("")
    with TestClient(app) as c:
        assert c.post("/api/v1/access/report", json=GOOD).status_code == 200


def test_key_required_when_set(isolated_env):
    init_db()
    cfg.warm()
    cfg.set("api_key", "s3cret")
    app = report_server._make_app("s3cret")
    with TestClient(app) as c:
        assert c.post("/api/v1/access/report", json=GOOD).status_code == 401
        assert c.post("/api/v1/access/report", json=GOOD,
                      headers={"X-API-Key": "wrong"}).status_code == 401
        assert c.post("/api/v1/access/report", json=GOOD,
                      headers={"X-API-Key": "s3cret"}).status_code == 200


def test_lan_listen_forces_generated_key(isolated_env, monkeypatch):
    """监听非回环地址时必须强制有 API Key，否则等于把服务敞开给局域网"""
    init_db()
    cfg.warm()
    cfg.set("api_key", "")
    report_server._generated_key = ""
    key = report_server._ensure_api_key("0.0.0.0", "")
    assert key, "非回环监听必须自动生成 Key"
    assert cfg.get("api_key") == key, "生成的 Key 必须落库，以便提示用户复制"
    assert report_server.get_generated_key() == key


def test_loopback_does_not_force_key(isolated_env):
    init_db()
    cfg.warm()
    cfg.set("api_key", "")
    assert report_server._ensure_api_key("127.0.0.1", "") == ""


def test_resolve_host_defaults_to_loopback(isolated_env):
    init_db()
    cfg.invalidate()
    assert report_server._resolve_host() in ("127.0.0.1", "localhost")


# ═══════════════════ 限流 ═══════════════════

def test_rate_limit_returns_429(isolated_env):
    init_db()
    cfg.warm()
    cfg.set("api_key", "")
    cfg.set("rate_limit_per_sec", 5)
    cfg.set("rate_limit_burst", 5)
    report_server._bucket.reset()
    app = report_server._make_app("")
    with TestClient(app) as c:
        codes = [c.post("/api/v1/access/report", json=GOOD).status_code for _ in range(12)]
    assert 429 in codes
    assert codes.count(200) <= 6
    report_server._bucket.reset()
    cfg.set("rate_limit_per_sec", 0)


def test_rate_limit_disabled_when_zero(isolated_env):
    init_db()
    cfg.warm()
    cfg.set("rate_limit_per_sec", 0)
    report_server._bucket.reset()
    app = report_server._make_app("")
    with TestClient(app) as c:
        for _ in range(50):
            assert c.post("/api/v1/access/report", json=GOOD).status_code == 200


# ═══════════════════ 请求体上限 ═══════════════════

def test_body_too_large_returns_413(isolated_env):
    init_db()
    cfg.warm()
    cfg.set("api_key", "")
    cfg.set("rate_limit_per_sec", 0)
    cfg.set("max_body_mb", 1)
    app = report_server._make_app("")
    payload = dict(GOOD)
    payload["user_agent"] = "x" * (2 * 1024 * 1024)
    with TestClient(app) as c:
        r = c.post("/api/v1/access/report", json=payload)
    assert r.status_code == 413


# ═══════════════════ 业务处理 ═══════════════════

def test_report_returns_risk_fields(client):
    r = client.post("/api/v1/access/report", json=GOOD)
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    d = body["data"]
    assert d["ip"] == "203.0.113.10"
    assert "risk_score" in d and "risk_level" in d and "matched_rules" in d


def test_report_rejects_bad_ip(client):
    bad = dict(GOOD, ip='1.2.3.4"; Start-Process calc; #')
    r = client.post("/api/v1/access/report", json=bad)
    assert r.status_code == 400
    assert "无效的 IP" in r.json()["detail"]


def test_single_scanner_probe_is_alerted_not_banned(client):
    """
    单次扫描器探测只应「告警」，不应直接建议封禁。
    sqlmap 的 UA 一条就能命中 scanner_ua（45 分 / medium / action=alert）。
    这是刻意的保守策略：UA 可伪造，单次请求不足以封禁，否则容易误伤。
    """
    evil = dict(GOOD, ip="45.33.32.156", path="/admin/login", status_code=401,
                method="POST", user_agent="sqlmap/1.7")
    d = client.post("/api/v1/access/report", json=evil).json()["data"]
    assert d["risk_score"] >= 45
    assert d["risk_level"] in ("medium", "high", "critical")
    assert "scanner_ua" in d["matched_rules"]
    assert d["suggest_ban"] is False


def test_repeated_login_probing_escalates_to_ban(client):
    """
    持续爆破登录接口才升级为建议封禁：
    sensitive_path_login 是窗口型规则（60s 内 10 次 /admin*/login* 且 401/403），
    命中后 70 分 + scanner_ua 45 分 → critical 且 suggest_ban。
    """
    evil = dict(GOOD, ip="45.33.32.156", path="/admin/login", status_code=401,
                method="POST", user_agent="sqlmap/1.7")
    last: Dict[str, Any] = {}
    for _ in range(12):
        last = client.post("/api/v1/access/report", json=evil).json()["data"]
    assert last["risk_score"] >= 90
    assert last["risk_level"] == "critical"
    assert "sensitive_path_login" in last["matched_rules"]
    assert last["suggest_ban"] is True


def test_foreign_probe_of_report_port_is_banned(client):
    """境外 IP 直接打上报端口（18080）属于典型扫描，应立刻建议封禁"""
    rec = dict(GOOD, ip="45.33.32.156", local_port=18080, path="/")
    d = client.post("/api/v1/access/report", json=rec).json()["data"]
    assert "foreign_sensitive_port" in d["matched_rules"]
    assert d["suggest_ban"] is True


def test_benign_domestic_request_is_not_flagged(client):
    """国内正常业务请求不应产生任何风险分（防误报底线）"""
    good = dict(GOOD, ip="113.118.113.77", path="/api/products", status_code=200,
                user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)")
    d = client.post("/api/v1/access/report", json=good).json()["data"]
    assert d["risk_score"] == 0
    assert d["risk_level"] == "normal"
    assert d["suggest_ban"] is False


def test_batch_endpoint(client):
    items = [dict(GOOD, ip=f"198.51.100.{i}") for i in range(1, 6)]
    r = client.post("/api/v1/access/batch", json={"items": items})
    assert r.status_code == 200
    d = r.json()["data"]
    assert d["accepted"] == 5 and d["failed"] == 0


def test_batch_rejects_non_list(client):
    assert client.post("/api/v1/access/batch", json={"items": "x"}).status_code == 400


def test_batch_rejects_too_many(client):
    items = [dict(GOOD) for _ in range(1001)]
    assert client.post("/api/v1/access/batch", json={"items": items}).status_code == 400


def test_batch_reports_per_item_errors(client):
    items = [dict(GOOD), dict(GOOD, ip="not-an-ip")]
    d = client.post("/api/v1/access/batch", json={"items": items}).json()["data"]
    assert d["accepted"] == 1 and d["failed"] == 1
    assert d["errors"][0]["index"] == 1


def test_health_and_version(client):
    h = client.get("/api/v1/health").json()
    assert h["status"] == "ok"
    assert "writer" in h and "ratelimit" in h
    v = client.get("/api/v1/version").json()
    assert v["app"] == "PortGuard"
    assert v["version"] == APP_VERSION
    assert v["geo_available"] is True


def test_banned_lookup(client):
    r = client.get("/api/v1/banned/203.0.113.10")
    assert r.status_code == 200
    assert r.json()["data"]["banned"] is False
    assert client.get("/api/v1/banned/not-an-ip").status_code == 400


def test_rules_reload_endpoint(client):
    r = client.post("/api/v1/rules/reload")
    assert r.status_code == 200
    assert r.json()["data"]["reloaded"] is True


# ═══════════════════ 无静默异常 ═══════════════════

def test_process_failure_returns_500_without_crashing(client, monkeypatch):
    import core.report_server as rs

    def boom(*a, **k):
        raise RuntimeError("模拟内部错误")

    monkeypatch.setattr(rs, "get_locator", boom)
    r = client.post("/api/v1/access/report", json=GOOD)
    assert r.status_code == 500
    assert r.json()["detail"] == "服务内部错误"


def test_health_after_failure_still_ok(client, monkeypatch):
    import core.report_server as rs
    monkeypatch.setattr(rs, "get_locator", lambda: (_ for _ in ()).throw(RuntimeError("x")))
    client.post("/api/v1/access/report", json=GOOD)
    assert client.get("/api/v1/health").status_code == 200


def test_json_serializable_response(client):
    r = client.post("/api/v1/access/report", json=GOOD)
    json.dumps(r.json(), ensure_ascii=False)
