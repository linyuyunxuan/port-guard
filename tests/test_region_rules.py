"""区域访问白名单规则（rules.json 的 region_rules）测试

这是用户明确要求的能力：
  「增加国内区域访问白名单；比如 河南区、山西区的 IP 可访问某端口。
    规则可以人工添加定义的模式」
并且**每条规则自选动作**：allow / watch / downgrade / suggest_ban。

覆盖重点：
· 四种动作各自的语义（放行短路、仅关注不影响分数、降级打折、判风险加分）
· 生效端口限定（只对某端口放行，换个端口不能连带放行）
· 多种匹配维度（省 / 市 / 国家 / 运营商 / CIDR / IP 前缀 / 仅限境内）
· 边界：归属地未知、规则未启用、条件为空的误配规则、非法 CIDR / 非法动作
"""

import json
import os

from core.models import AccessRecord, GeoInfo
from core.rule_engine import RuleEngine
from core.rules_meta import (
    REGION_ACTION_KEYS,
    region_rule_key,
    register_region_rules,
    rule_label,
)

BEIJING = GeoInfo(
    ip="1.1.1.1", country="中国", province="北京市", city="北京市", isp="联通", iso="CN", found=True
)
HENAN = GeoInfo(
    ip="2.2.2.2", country="中国", province="河南省", city="郑州市", isp="联通", iso="CN", found=True
)
SHANXI = GeoInfo(
    ip="3.3.3.3", country="中国", province="山西省", city="太原市", isp="电信", iso="CN", found=True
)
RUSSIA = GeoInfo(
    ip="4.4.4.4", country="俄罗斯", province="", city="莫斯科", isp="", iso="RU", found=True
)
UNKNOWN = GeoInfo(ip="5.5.5.5", found=False)


def _engine(tmp_path, region_rules, rules=None):
    cfg = {
        "version": 2,
        "rules": rules
        if rules is not None
        else {
            "blacklist": {
                "enabled": True,
                "score": 100,
                "level": "critical",
                "action": "suggest_ban",
            },
            "geo_sensitive_port": {
                "enabled": True,
                "ports": [3389, 18080],
                "score": 65,
                "level": "high",
                "action": "suggest_ban",
                # 本文件用境外 IP 造「基础分」（不改境内 IP 的评分前提），
                # 所以把范围钉在 1.x 的老口径「仅限境外」，与生产默认（仅限境内）解耦
                "geo_scope": "overseas",
            },
            "scanner_ua": {
                "enabled": True,
                "patterns": ["nmap"],
                "empty_ua": True,
                "score": 45,
                "level": "medium",
                "action": "alert",
            },
        },
        "region_rules": region_rules,
    }
    p = tmp_path / "rules.json"
    p.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
    return RuleEngine(path=str(p))


def _rec(ip="1.1.1.1", port=18080, protocol="tcp", **kw):
    return AccessRecord(ip=ip, local_port=port, protocol=protocol, **kw)


ALLOW_HENAN = {
    "id": "r-hn",
    "name": "河南办公网放行",
    "enabled": True,
    "action": "allow",
    "target_ports": [18080],
    "match": {"provinces": ["河南省"]},
}


# --------------------------------------------------------------------------- #
# 动作语义
# --------------------------------------------------------------------------- #
def test_allow_short_circuits_with_whitelist(tmp_path):
    """「河南的 IP 可以访问 18080」—— 命中即完全豁免"""
    eng = _engine(tmp_path, [ALLOW_HENAN])
    r = eng.evaluate(_rec("2.2.2.2", 18080), HENAN)
    assert r.score == 0
    assert r.level == "normal"
    assert r.whitelisted is True
    assert r.suggest_ban is False
    assert r.matched_rules == [region_rule_key("allow", "r-hn")]
    assert "河南办公网放行" in r.reason


def test_allow_respects_target_ports(tmp_path):
    """放行只对规则里写的端口生效，换个端口绝不能连带放行"""
    eng = _engine(tmp_path, [ALLOW_HENAN])
    r = eng.evaluate(_rec("2.2.2.2", 3389), HENAN)
    assert r.whitelisted is False


def test_allow_with_empty_ports_applies_to_all(tmp_path):
    eng = _engine(tmp_path, [{**ALLOW_HENAN, "target_ports": []}])
    assert eng.evaluate(_rec("2.2.2.2", 22), HENAN).whitelisted is True


def test_allow_does_not_leak_to_other_provinces(tmp_path):
    eng = _engine(tmp_path, [ALLOW_HENAN])
    assert eng.evaluate(_rec("3.3.3.3", 18080), SHANXI).whitelisted is False


def test_watch_does_not_change_score(tmp_path):
    """仅关注：不加分、不减分，只留痕"""
    eng = _engine(tmp_path, [{**ALLOW_HENAN, "action": "watch", "target_ports": []}])
    r = eng.evaluate(_rec("2.2.2.2", 33333), HENAN)  # 非敏感端口 → 基础分 0
    assert r.score == 0
    assert r.whitelisted is False
    assert r.matched_rules == [region_rule_key("watch", "r-hn")]
    assert "仅关注" in r.reason


def test_watch_keeps_existing_score(tmp_path):
    """仅关注不能把已有风险分抹掉"""
    eng = _engine(
        tmp_path,
        [{**ALLOW_HENAN, "action": "watch", "target_ports": [], "match": {"only_china": True}}],
    )
    r = eng.evaluate(_scanner_rec(), HENAN)  # 中国 + 扫描器 UA → 45
    assert r.score == 45
    assert region_rule_key("watch", "r-hn") in r.matched_rules


def _scanner_rec(ip="2.2.2.2", port=3389):
    """
    构造一条「基础分不为 0 且归属地为中国」的记录。

    这里用扫描器 UA（+45）造基础分，不依赖端口规则的归属地范围 ——
    范围是可配置的，拿它造分会让用例随配置漂移。
    """
    return _rec(ip, port, protocol="http", method="GET", path="/", user_agent="nmap")


def test_downgrade_reduces_score(tmp_path):
    """降级：按系数打折，但结论来源不变（该命中的规则照旧命中）"""
    eng = _engine(
        tmp_path,
        [{**ALLOW_HENAN, "action": "downgrade", "target_ports": [], "factor": 0.2}],
    )
    r = eng.evaluate(_scanner_rec(), HENAN)  # 基础分 45
    assert r.score == round(45 * 0.2)
    assert r.whitelisted is False
    assert region_rule_key("downgrade", "r-hn") in r.matched_rules


def test_downgrade_takes_strongest_factor(tmp_path):
    """多条降级规则同时命中时取最狠的那个系数"""
    eng = _engine(
        tmp_path,
        [
            {**ALLOW_HENAN, "id": "a", "action": "downgrade", "target_ports": [], "factor": 0.8},
            {**ALLOW_HENAN, "id": "b", "action": "downgrade", "target_ports": [], "factor": 0.2},
        ],
    )
    r = eng.evaluate(_scanner_rec(), HENAN)
    assert r.score == round(45 * 0.2)  # 取 0.2（45×0.2=9），而不是 0.8（36）


def test_suggest_ban_adds_score_and_flags(tmp_path):
    eng = _engine(
        tmp_path,
        [
            {
                **ALLOW_HENAN,
                "action": "suggest_ban",
                "score": 95,
                "target_ports": [3389],
                "match": {"only_china": True},
            }
        ],
    )
    r = eng.evaluate(_scanner_rec(), HENAN)  # 45 + 95，封顶 100
    assert r.score == 100
    assert r.level == "critical"
    assert r.suggest_ban is True


def test_allow_beats_all_other_rules(tmp_path):
    """
    区域放行优先级最高。

    这里故意用境外 IP：它本来会命中「管理端口归属地检测」拿 65 分并被建议封禁，
    但管理员既然显式配了放行，就必须以放行为准（命中即短路，连评分都不做）。
    """
    eng = _engine(tmp_path, [{**ALLOW_HENAN, "match": {"countries": ["俄罗斯"]}}])
    r = eng.evaluate(_rec("4.4.4.4", 18080), RUSSIA)
    assert r.whitelisted is True and r.score == 0
    assert r.matched_rules == [region_rule_key("allow", "r-hn")]
    # 反证：同一条记录在「没有放行规则」时必须被判风险，否则这个用例什么都没证明
    plain = _engine(tmp_path, [])
    assert plain.evaluate(_rec("4.4.4.4", 18080), RUSSIA).score == 65


# --------------------------------------------------------------------------- #
# 匹配维度
# --------------------------------------------------------------------------- #
def test_match_by_city(tmp_path):
    eng = _engine(tmp_path, [{**ALLOW_HENAN, "match": {"cities": ["郑州市"]}}])
    assert eng.evaluate(_rec("2.2.2.2"), HENAN).whitelisted is True
    assert eng.evaluate(_rec("3.3.3.3"), SHANXI).whitelisted is False


def test_match_province_prefix_tolerance(tmp_path):
    """用户写「河南」或「河南省」都应当能匹配上"""
    eng = _engine(tmp_path, [{**ALLOW_HENAN, "match": {"provinces": ["河南"]}}])
    assert eng.evaluate(_rec("2.2.2.2"), HENAN).whitelisted is True


def test_match_by_country(tmp_path):
    eng = _engine(tmp_path, [{**ALLOW_HENAN, "match": {"countries": ["中国"]}}])
    assert eng.evaluate(_rec("2.2.2.2"), HENAN).whitelisted is True
    assert eng.evaluate(_rec("4.4.4.4"), RUSSIA).whitelisted is False


def test_match_by_isp(tmp_path):
    eng = _engine(tmp_path, [{**ALLOW_HENAN, "match": {"isp": ["联通"]}}])
    assert eng.evaluate(_rec("2.2.2.2"), HENAN).whitelisted is True
    assert eng.evaluate(_rec("3.3.3.3"), SHANXI).whitelisted is False


def test_match_by_cidr(tmp_path):
    eng = _engine(
        tmp_path,
        [{**ALLOW_HENAN, "match": {"cidrs": ["203.0.113.0/24", "198.51.100.7"]}}],
    )
    assert eng.evaluate(_rec("203.0.113.55"), HENAN).whitelisted is True
    assert eng.evaluate(_rec("198.51.100.7"), HENAN).whitelisted is True
    assert eng.evaluate(_rec("203.0.114.1"), HENAN).whitelisted is False


def test_match_by_ip_keyword(tmp_path):
    eng = _engine(tmp_path, [{**ALLOW_HENAN, "match": {"ip_keywords": ["113.118."]}}])
    assert eng.evaluate(_rec("113.118.113.77"), HENAN).whitelisted is True
    assert eng.evaluate(_rec("113.119.1.1"), HENAN).whitelisted is False


def test_match_only_china(tmp_path):
    """仅限境内：只有归属地确定为中国才命中"""
    eng = _engine(tmp_path, [{**ALLOW_HENAN, "match": {"only_china": True}}])
    assert eng.evaluate(_rec("2.2.2.2"), HENAN).whitelisted is True
    assert eng.evaluate(_rec("4.4.4.4"), RUSSIA).whitelisted is False
    # 归属地未知时不能算「境内」
    assert eng.evaluate(_rec("5.5.5.5"), UNKNOWN).whitelisted is False


def test_match_legacy_not_china_still_works(tmp_path):
    """旧配置的 not_china 字段仍按「仅限境外」生效，升级后不会静默失效"""
    eng = _engine(tmp_path, [{**ALLOW_HENAN, "match": {"not_china": True}}])
    assert eng.evaluate(_rec("4.4.4.4"), RUSSIA).whitelisted is True
    assert eng.evaluate(_rec("2.2.2.2"), HENAN).whitelisted is False


def test_multi_dimension_requires_all(tmp_path):
    eng = _engine(
        tmp_path,
        [{**ALLOW_HENAN, "match": {"provinces": ["河南省"], "isp": ["电信"]}}],
    )
    # 河南省但是联通 → 不命中
    assert eng.evaluate(_rec("2.2.2.2"), HENAN).whitelisted is False
    # 河南省且电信 → 命中
    dl = GeoInfo(province="河南省", city="", isp="电信", country="中国", iso="CN", found=True)
    assert eng.evaluate(_rec("2.2.2.2"), dl).whitelisted is True


def test_unknown_geo_does_not_match_geo_rules(tmp_path):
    """归属地未知时宁可放过，也不能凭「不知道」就放行"""
    eng = _engine(tmp_path, [ALLOW_HENAN])
    assert eng.evaluate(_rec("5.5.5.5"), UNKNOWN).whitelisted is False


def test_unknown_geo_still_allows_cidr_rules(tmp_path):
    """纯 IP 维度的规则不依赖归属地，未知时照样生效"""
    eng = _engine(tmp_path, [{**ALLOW_HENAN, "match": {"cidrs": ["203.0.113.0/24"]}}])
    assert eng.evaluate(_rec("203.0.113.9"), UNKNOWN).whitelisted is True


# --------------------------------------------------------------------------- #
# 边界与容错
# --------------------------------------------------------------------------- #
def test_disabled_rule_ignored(tmp_path):
    eng = _engine(tmp_path, [{**ALLOW_HENAN, "enabled": False}])
    assert eng.evaluate(_rec("2.2.2.2", 18080), HENAN).whitelisted is False


def test_rule_without_conditions_does_not_match_everything(tmp_path):
    """误配成「什么条件都没填」的规则等价于匹配全部地址，必须不生效"""
    eng = _engine(tmp_path, [{**ALLOW_HENAN, "match": {}}])
    assert eng.evaluate(_rec("2.2.2.2", 18080), HENAN).whitelisted is False


def test_invalid_cidr_is_ignored_not_fatal(tmp_path):
    eng = _engine(
        tmp_path,
        [
            {
                "id": "bad",
                "name": "坏网段",
                "enabled": True,
                "action": "allow",
                "target_ports": [18080],
                "match": {"cidrs": ["not-a-cidr", "also/bad", "203.0.113.0/24"]},
            }
        ],
    )
    # 合法的那个仍然生效
    assert eng.evaluate(_rec("203.0.113.9", 18080), HENAN).whitelisted is True
    assert eng.evaluate(_rec("9.9.9.9", 18080), HENAN).whitelisted is False


def test_invalid_action_falls_back_to_watch(tmp_path):
    eng = _engine(tmp_path, [{**ALLOW_HENAN, "action": "nonsense"}])
    r = eng.evaluate(_rec("2.2.2.2", 18080), HENAN)
    assert r.whitelisted is False  # 不再放行
    assert region_rule_key("watch", "r-hn") in r.matched_rules


def test_non_dict_and_missing_id_tolerated(tmp_path):
    eng = _engine(
        tmp_path,
        [
            "garbage",
            42,
            {"action": "allow", "target_ports": [18080], "match": {"provinces": ["河南省"]}},
        ],
    )
    # 没有 id 的条目会被补成 r1/r2...，仍然可用
    assert eng.evaluate(_rec("2.2.2.2", 18080), HENAN).whitelisted is True


def test_region_rules_not_a_list(tmp_path):
    eng = _engine(tmp_path, {"oops": True})
    assert eng.region_rules() == []


def test_region_rules_roundtrip(tmp_path):
    eng = _engine(tmp_path, [ALLOW_HENAN])
    got = eng.region_rules()
    assert len(got) == 1
    assert got[0]["id"] == "r-hn"
    assert got[0]["provinces"] == ["河南省"]
    assert got[0]["ports"] == [18080]


def test_save_config_persists_region_rules(tmp_path):
    eng = _engine(tmp_path, [])
    cfg = eng.get_config()
    cfg["region_rules"] = [ALLOW_HENAN]
    eng.save_config(cfg)
    eng.reload()
    assert eng.evaluate(_rec("2.2.2.2", 18080), HENAN).whitelisted is True


def test_reload_refreshes_rule_names(tmp_path):
    eng = _engine(tmp_path, [ALLOW_HENAN])
    assert "河南办公网放行" in rule_label(region_rule_key("allow", "r-hn"))
    eng.save_config({**eng.get_config(), "region_rules": [{**ALLOW_HENAN, "name": "改名了"}]})
    eng.reload()
    assert "改名了" in rule_label(region_rule_key("allow", "r-hn"))


# --------------------------------------------------------------------------- #
# 标签翻译（rules_meta）
# --------------------------------------------------------------------------- #
def test_rule_label_for_all_region_actions():
    register_region_rules([{"id": "x", "name": "测试规则"}])
    for action in REGION_ACTION_KEYS:
        label = rule_label(region_rule_key(action, "x"))
        assert "测试规则" in label


def test_rule_label_falls_back_to_unknown_id():
    register_region_rules([])
    assert "zzz" in rule_label(region_rule_key("allow", "zzz"))


def test_rule_label_still_handles_builtin_rules():
    assert rule_label("blacklist") == "黑名单命中"
    assert rule_label("unknown_rule") == "unknown_rule"


def test_region_rule_key_format():
    assert region_rule_key("allow", "r-1") == "region_allow:r-1"


# --------------------------------------------------------------------------- #
# 随包默认配置
# --------------------------------------------------------------------------- #
def test_shipped_rules_json_is_valid():
    """随包分发的 rules.json 必须能被解析，且内置示例规则是「默认关闭」的 ——
    示例规则若默认开启会静默改变所有用户的放行行为。"""
    path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "rules.json"
    )
    with open(path, encoding="utf-8") as f:
        cfg = json.load(f)
    assert "rules" in cfg
    assert isinstance(cfg.get("region_rules"), list)
    assert cfg["region_rules"], "应当带示例区域规则"
    for r in cfg["region_rules"]:
        assert r.get("enabled") is False, "示例区域规则必须默认关闭"
        assert r.get("action") in REGION_ACTION_KEYS
        assert r.get("match")


def test_shipped_rules_engine_constructs():
    from core.rule_engine import get_engine

    eng = get_engine()
    eng.reload()
    assert eng.region_rules(), "内置规则应能解析出区域规则"


def test_region_rules_do_not_affect_plain_http_only_when_matched(tmp_path):
    """没有配区域规则时，行为必须与改造前完全一致"""
    eng = _engine(tmp_path, [])
    # 普通浏览器 UA + 境外 + 管理端口 → 只有「管理端口归属地检测」一条
    r = eng.evaluate(
        _rec(
            "4.4.4.4",
            3389,
            protocol="http",
            method="GET",
            path="/",
            user_agent="Mozilla/5.0 (Windows NT 6.1; Trident/7.0)",
        ),
        RUSSIA,
    )
    assert r.whitelisted is False
    assert r.score == 65
    assert r.matched_rules == ["geo_sensitive_port"]

    # HTTP 场景下 UA 为空仍按扫描器加 45 分 —— 这是刻意保留的既有行为，
    # 且正因为有这个行为，「本机采集的 TCP 记录不能套用空 UA 判定」才必须成立
    r2 = eng.evaluate(_rec("4.4.4.4", 3389, protocol="http", method="GET", path="/"), RUSSIA)
    assert r2.score == 100
    assert "scanner_ua" in r2.matched_rules
