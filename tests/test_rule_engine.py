"""规则引擎测试"""

import pytest

from core.database import init_db
from core.models import AccessRecord, GeoInfo, now_ms
from core.rule_engine import _MAX_WINDOW_ITEMS, RuleEngine, is_never_ban


@pytest.fixture
def engine(isolated_env):
    init_db()
    e = RuleEngine()
    # 用内置完整规则（真实 rules.json 若不存在会落到 DEFAULT_RULES）
    e._cfg = {
        "version": 1,
        "rules": {
            "blacklist": {"enabled": True, "score": 100, "level": "critical"},
            "port_scan": {"enabled": True, "score": 80, "window_sec": 30, "distinct_ports": 15},
            "sensitive_path_login": {
                "enabled": True,
                "score": 70,
                "window_sec": 60,
                "threshold": 10,
                "paths": ["/admin", "/login"],
                "status": [401, 403],
            },
            "foreign_sensitive_port": {"enabled": True, "score": 65, "ports": [3389, 22, 1433]},
            "rate_limit": {"enabled": True, "score": 60, "window_sec": 10, "threshold": 50},
            "scanner_ua": {
                "enabled": True,
                "score": 45,
                "patterns": ["sqlmap", "nmap", "nikto"],
                "empty_ua": True,
            },
            "error_storm": {
                "enabled": True,
                "score": 40,
                "window_sec": 60,
                "min_samples": 20,
                "error_ratio": 0.7,
            },
            "suspicious_method": {
                "enabled": True,
                "score": 30,
                "methods": ["TRACE", "PROPFIND", "PUT"],
            },
            "large_body": {"enabled": True, "score": 25, "min_bytes": 5 * 1024 * 1024},
        },
    }
    e._compile()
    return e


def _rec(**kw) -> AccessRecord:
    kw.setdefault("ip", "203.0.113.10")
    kw.setdefault("local_port", 3000)
    kw.setdefault("event_ts", now_ms())
    return AccessRecord(**kw)


def test_blacklist_scores_100(engine):
    engine.blacklist.add("203.0.113.10")
    r = engine.evaluate(_rec())
    assert r.score == 100 and r.level == "critical" and r.suggest_ban


def test_whitelist_exempts_everything(engine):
    engine.blacklist.add("203.0.113.10")
    engine.whitelist.add("203.0.113.10")
    r = engine.evaluate(_rec())
    assert r.score == 0 and r.whitelisted and not r.suggest_ban


def test_scanner_ua(engine):
    r = engine.evaluate(_rec(user_agent="sqlmap/1.7"))
    assert "scanner_ua" in r.matched_rules
    assert r.score >= 45


def test_empty_ua_flagged(engine):
    r = engine.evaluate(_rec(user_agent=""))
    assert "scanner_ua" in r.matched_rules


def test_port_scan_detected(engine):
    ip = "198.51.100.9"
    for p in range(1, 17):
        engine.evaluate(_rec(ip=ip, local_port=p))
    r = engine.evaluate(_rec(ip=ip, local_port=999))
    assert "port_scan" in r.matched_rules


def test_foreign_sensitive_port(engine):
    rec = _rec(local_port=3389)
    geo = GeoInfo(ip=rec.ip, country="美国", iso="US", found=True)
    r = engine.evaluate(rec, geo)
    assert "foreign_sensitive_port" in r.matched_rules


def test_unknown_geo_does_not_trigger_foreign_rule(engine):
    """内网 / 保留地址归属地未知时不能误判为境外访问"""
    rec = _rec(ip="192.168.1.5", local_port=3389)
    geo = GeoInfo(ip=rec.ip, found=False)
    r = engine.evaluate(rec, geo)
    assert "foreign_sensitive_port" not in r.matched_rules


def test_sensitive_path_brute_force(engine):
    ip = "198.51.100.20"
    for _ in range(11):
        engine.evaluate(_rec(ip=ip, path="/admin/login", status_code=401))
    r = engine.evaluate(_rec(ip=ip, path="/admin/login", status_code=401))
    assert "sensitive_path_login" in r.matched_rules


def test_rate_limit(engine):
    ip = "198.51.100.30"
    for _ in range(55):
        engine.evaluate(_rec(ip=ip))
    r = engine.evaluate(_rec(ip=ip))
    assert "rate_limit" in r.matched_rules


def test_suspicious_method_and_large_body(engine):
    r = engine.evaluate(_rec(method="TRACE"))
    assert "suspicious_method" in r.matched_rules
    r = engine.evaluate(_rec(ip="198.51.100.40", size=6 * 1024 * 1024))
    assert "large_body" in r.matched_rules


def test_score_capped_at_100(engine):
    engine.blacklist.add("203.0.113.10")
    r = engine.evaluate(
        _rec(
            user_agent="sqlmap",
            method="TRACE",
            size=9 * 1024 * 1024,
            path="/admin",
            status_code=401,
        )
    )
    assert r.score == 100


def test_level_thresholds():
    assert RuleEngine.level_of(0) == "normal"
    assert RuleEngine.level_of(20) == "low"
    assert RuleEngine.level_of(40) == "medium"
    assert RuleEngine.level_of(65) == "high"
    assert RuleEngine.level_of(90) == "critical"


def test_never_ban_networks():
    for ip in (
        "127.0.0.1",
        "10.1.2.3",
        "192.168.0.1",
        "172.16.5.5",
        "169.254.1.1",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "fc00::1",
    ):
        assert is_never_ban(ip) is True, ip
    for ip in ("8.8.8.8", "203.0.113.10", "2408:8000::1"):
        assert is_never_ban(ip) is False, ip


def test_window_bounded_by_maxlen(engine):
    """
    最坏情况防护：某 IP 疯狂请求也不能让窗口无限膨胀，
    否则每次 evaluate 都要遍历全部 → O(n²) 退化（DoD 面）。
    """
    ip = "198.51.100.99"
    for _ in range(_MAX_WINDOW_ITEMS + 2000):
        engine.evaluate(_rec(ip=ip))
    assert len(engine._win[ip]) <= _MAX_WINDOW_ITEMS


def test_engine_handles_10k_ips_without_breaking(engine):
    for i in range(10_000):
        engine.evaluate(_rec(ip=f"198.18.{i // 250}.{i % 250}"))
    assert engine.window_size() <= 10_001
