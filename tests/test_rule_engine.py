"""规则引擎测试"""

import json

import pytest

from core.database import init_db
from core.models import AccessRecord, GeoInfo, now_ms
from core.rule_engine import _MAX_WINDOW_ITEMS, RuleEngine, _migrate_rules, is_never_ban
from core.rules_meta import rule_label


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
            "geo_sensitive_port": {
                "enabled": True,
                "score": 65,
                "ports": [3389, 22, 1433],
                "geo_scope": "china",
            },
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
    """白名单命中即豁免（未同时命中黑名单时）。

    ⚠️ 2026-10-23 需求变更：**黑白同中时以黑名单为准**（原「白名单绝对优先」
    已废止，见 test_lists_as_rules.test_blacklist_beats_whitelist）。
    这里只保留「单白名单」这一半，别再把黑名单加回来 —— 那是被明确推翻的行为。
    """
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


CHINA = GeoInfo(ip="113.118.113.77", country="中国", province="广东省", iso="CN", found=True)
OVERSEAS = GeoInfo(ip="45.33.32.156", country="美国", iso="US", found=True)


def _port_rec(port: int = 3389) -> AccessRecord:
    """管理端口记录：带正常浏览器 UA，避开「空 UA + HTTP 场景 = 扫描器 +45」对分值断言的干扰"""
    return _rec(local_port=port, user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)")


def test_domestic_sensitive_port(engine):
    """默认「仅限境内」：境内 IP 打管理端口加分"""
    rec = _port_rec()
    r = engine.evaluate(rec, CHINA)
    assert "geo_sensitive_port" in r.matched_rules
    assert r.score == 65


def test_overseas_not_scored_under_china_scope(engine):
    """仅限境内时，境外来源打同一端口不加分（范围可改成 overseas / both）"""
    r = engine.evaluate(_port_rec(), OVERSEAS)
    assert "geo_sensitive_port" not in r.matched_rules
    assert r.score == 0


def test_sensitive_port_scope_overseas(engine):
    engine._cfg["rules"]["geo_sensitive_port"]["geo_scope"] = "overseas"
    engine._compile()
    assert "geo_sensitive_port" in engine.evaluate(_port_rec(), OVERSEAS).matched_rules
    assert "geo_sensitive_port" not in engine.evaluate(_port_rec(), CHINA).matched_rules


def test_sensitive_port_scope_both(engine):
    engine._cfg["rules"]["geo_sensitive_port"]["geo_scope"] = "both"
    engine._compile()
    assert "geo_sensitive_port" in engine.evaluate(_port_rec(), OVERSEAS).matched_rules
    assert "geo_sensitive_port" in engine.evaluate(_port_rec(), CHINA).matched_rules


def test_sensitive_port_scope_defaults_to_china(engine):
    """缺省 / 非法值一律按「仅限境内」，避免配错就让规则永不生效"""
    for bad in (None, "", "zzz"):
        engine._cfg["rules"]["geo_sensitive_port"]["geo_scope"] = bad
        engine._compile()
        assert "geo_sensitive_port" in engine.evaluate(_port_rec(), CHINA).matched_rules
        assert "geo_sensitive_port" not in engine.evaluate(_port_rec(), OVERSEAS).matched_rules


def test_unknown_geo_does_not_trigger_sensitive_port_rule(engine):
    """内网 / 保留地址归属地未知时不能误判（否则本机/局域网访问全被加分）"""
    rec = _rec(ip="192.168.1.5", local_port=3389)
    geo = GeoInfo(ip=rec.ip, found=False)
    r = engine.evaluate(rec, geo)
    assert "geo_sensitive_port" not in r.matched_rules


def test_migrate_legacy_foreign_sensitive_port():
    """1.x 的旧规则名自动迁移成新规则名，且默认范围变成「仅限境内」"""
    cfg = {
        "rules": {
            "foreign_sensitive_port": {
                "enabled": True,
                "score": 65,
                "ports": [3389],
                "require_not_china": True,
            }
        }
    }
    assert _migrate_rules(cfg) is True
    assert "foreign_sensitive_port" not in cfg["rules"]
    migrated = cfg["rules"]["geo_sensitive_port"]
    assert migrated["geo_scope"] == "china"
    assert migrated["ports"] == [3389]
    assert migrated["score"] == 65
    assert "require_not_china" not in migrated
    # 幂等：再跑一次不应报错也不应重复迁移
    assert _migrate_rules(cfg) is False


def test_migrate_does_not_override_existing_new_rule():
    """新配置已存在时不覆盖（用户手工改过的参数必须保留），只丢掉废弃的旧 key"""
    cfg = {
        "rules": {
            "geo_sensitive_port": {"enabled": False, "geo_scope": "overseas"},
            "foreign_sensitive_port": {"enabled": True},
        }
    }
    assert _migrate_rules(cfg) is True
    assert cfg["rules"]["geo_sensitive_port"] == {"enabled": False, "geo_scope": "overseas"}
    assert "foreign_sensitive_port" not in cfg["rules"]


def test_reload_migrates_legacy_config_file(tmp_path):
    """从磁盘读到旧配置时，引擎内存里也必须是迁移后的新规则（行为立即改变）"""
    cfg = {
        "version": 1,
        "rules": {
            "foreign_sensitive_port": {
                "enabled": True,
                "score": 65,
                "ports": [3389],
                "require_not_china": True,
            },
        },
    }
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")

    e = RuleEngine(str(p))
    loaded = e.get_config()["rules"]
    assert "foreign_sensitive_port" not in loaded
    assert loaded["geo_sensitive_port"]["geo_scope"] == "china"
    assert "geo_sensitive_port" in e.evaluate(_port_rec(), CHINA).matched_rules


def test_legacy_rule_label_still_translates():
    """历史事件里存的是旧 ID，UI 不能显示成一串英文"""
    assert "旧" in rule_label("foreign_sensitive_port")
    assert rule_label("geo_sensitive_port") == "管理端口归属地检测"


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


def test_save_config_keeps_params_the_ui_cannot_edit(engine, tmp_path):
    """保存配置不得丢掉「界面上没有控件」的命中条件。

    规则页只把 RULE_PARAMS 里的可编辑参数（窗口秒数、阈值、端口列表）提交回来，
    若按传入配置整体覆盖，`sensitive_path_login.paths/status`、`scanner_ua.empty_ua`
    这类命中条件会被静默删除：规则还在、开关还开着，但永远不再命中，且不报错。
    本机实测发生过一次（工作区 rules.json 被整体重写后三个字段消失）。
    """
    path = tmp_path / "rules.json"
    engine._path = str(path)
    engine._cfg["rules"]["sensitive_path_login"]["paths"] = ["/admin", "/.env"]
    engine._cfg["rules"]["sensitive_path_login"]["status"] = [401, 403]
    engine._cfg["rules"]["scanner_ua"]["empty_ua"] = True

    # 模拟规则页：只提交界面上能改的字段
    ui_cfg = json.loads(json.dumps(engine._cfg))
    ui_cfg["rules"]["sensitive_path_login"] = {
        "enabled": True,
        "score": 70,
        "level": "high",
        "action": "suggest_ban",
        "window_sec": 120,  # 用户改了窗口
        "threshold": 5,
    }
    ui_cfg["rules"]["scanner_ua"] = {
        "enabled": True,
        "score": 45,
        "level": "medium",
        "action": "alert",
        "patterns": ["nmap", "sqlmap"],
    }

    engine.save_config(ui_cfg)

    saved = json.loads(path.read_text(encoding="utf-8"))["rules"]
    # 界面改的值必须生效
    assert saved["sensitive_path_login"]["window_sec"] == 120
    assert saved["sensitive_path_login"]["threshold"] == 5
    # 界面改不到的命中条件必须原样保留
    assert saved["sensitive_path_login"]["paths"] == ["/admin", "/.env"]
    assert saved["sensitive_path_login"]["status"] == [401, 403]
    assert saved["scanner_ua"]["empty_ua"] is True


def test_save_config_allows_dropping_a_rule_entirely(engine, tmp_path):
    """合并只补「同一条规则」的缺失键；整条规则被删掉时必须真的删掉。"""
    path = tmp_path / "rules.json"
    engine._path = str(path)
    ui_cfg = json.loads(json.dumps(engine._cfg))
    ui_cfg["rules"].pop("port_scan")

    engine.save_config(ui_cfg)

    saved = json.loads(path.read_text(encoding="utf-8"))["rules"]
    assert "port_scan" not in saved
    assert "blacklist" in saved
