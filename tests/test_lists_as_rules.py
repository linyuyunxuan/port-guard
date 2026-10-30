"""名单语义并入规则（2026-10-23 需求）的回归测试

覆盖四件事：
  1. 黑名单**压过**白名单 —— 「加入黑名单的 IP 无视其他规则直接拦截」；
  2. 「拦截」规则的优先级（命中即封、压过同一记录上的「放行」）；
  3. 旧黑 / 白名单 → 规则的迁移（幂等、清空名单、备份）；
  4. 「拦截 / 放行」目标收集（同一 IP 两边都有时以拦截为准）。

这些不是「多测几个分支」，而是每一条都对应一个**会静默放跑攻击者**的失败形态：
名单里有的 IP 判成放行、规则写了却没拦、迁移把名单吞掉不留备份。
"""

import json
import os
from typing import Dict

import pytest

from core import config
from core.models import (
    DISPOSITION_ALLOW,
    DISPOSITION_CONFIRM,
    AccessRecord,
    GeoInfo,
)
from core.rule_engine import RuleEngine, _IPSet

IP = "203.0.113.7"


@pytest.fixture(autouse=True)
def _own_data_dir(monkeypatch, tmp_path):
    """本文件的用例必须独占一个数据目录。

    ⚠️ conftest 的 `isolated_env` 是 **session 级**（所有用例共享一个
    tmp/data），只有数据库靠 `fresh_db` 逐例重建。而迁移用例会真的写
    rules.json 并清空名单文件 —— 写进共享目录就会把「规则配置」改成
    只剩迁移结果，后面任何依赖真实规则集的用例（例如 port_watcher 期望
    `geo_sensitive_port` 加 65 分）都会突然变成 0 分，表现为一个跟本次改动
    毫无关系的红。这里把 project_dir 再指到用例自己的 tmp_path，
    `rules_path()` / `blacklist_path()` / `backup_dir()` 全部落进去。
    """
    monkeypatch.setattr(config, "project_dir", lambda: str(tmp_path))


@pytest.fixture
def engine(isolated_env):
    """一套最小规则集：只留拦截判断本身需要的，别让评分规则干扰结论"""
    e = RuleEngine()
    e._cfg = {"version": 1, "rules": {}, "region_rules": []}
    e._compile()
    return e


def _rec(ip: str = IP, port: int = 80, path: str = "/") -> AccessRecord:
    return AccessRecord(ip=ip, local_port=port, path=path)


def _geo(province: str = "河南省") -> GeoInfo:
    return GeoInfo(found=True, country="中国", province=province, city="焦作市", iso="CN")


def _block_rule(cidr: str = IP, rid: str = "blk-1", ports=None) -> dict:
    return {
        "id": rid,
        "name": f"拦截 {cidr}",
        "enabled": True,
        "action": "block",
        "target_ports": ports or [],
        "match": {"cidrs": [cidr]},
    }


def _allow_rule(province: str = "河南省", rid: str = "alw-1", ports=None) -> dict:
    return {
        "id": rid,
        "name": "河南放行",
        "enabled": True,
        "action": "allow",
        "target_ports": ports or [80],
        "match": {"provinces": [province]},
    }


# ═══════════════════════════════════════════════════════════
#  黑名单：绝对优先
# ═══════════════════════════════════════════════════════════


def test_blacklist_beats_whitelist(engine):
    """同一个 IP 同时躺两个名单里 → 必须拦。

    变异：把 evaluate 里的黑名单判断挪回白名单之后 → 本例变红。
    这是「先封后加白」这种纯配置层面的绕过，用户肉眼几乎发现不了。
    """
    engine.blacklist = _IPSet([IP])
    engine.whitelist = _IPSet([IP])

    r = engine.evaluate(_rec(), _geo())

    assert r.force_block is True, "黑名单必须走直接拦截，而不是仅加 100 分"
    assert r.score == 100
    assert r.disposition != DISPOSITION_ALLOW
    assert "黑名单" in r.reason


def test_whitelist_still_allows_when_not_blacklisted(engine):
    """白名单本身仍然是「命中即豁免」—— 别为了修黑名单把白名单改坏"""
    engine.whitelist = _IPSet([IP])

    r = engine.evaluate(_rec(), _geo())

    assert r.disposition == DISPOSITION_ALLOW
    assert r.score == 0
    assert r.force_block is False


def test_blacklist_blocks_even_if_its_rule_is_switched_off(engine):
    """黑名单不再是「一张能关掉的规则卡」：名单入口已取消，关开关无从谈起。

    变异：把黑名单判断重新包上 `rule_enabled("blacklist")` → 本例变红。
    """
    engine._cfg["rules"]["blacklist"] = {"enabled": False, "score": 100}
    engine.blacklist = _IPSet([IP])

    assert engine.evaluate(_rec(), _geo()).force_block is True


def test_blacklist_blocks_inside_a_region_allow_scope(engine):
    """区域放行规则不能把黑名单里的 IP 捞出来 —— 「无视其他规则」包含它"""
    engine._cfg["region_rules"] = [_allow_rule()]
    engine._compile()
    engine.blacklist = _IPSet([IP])

    r = engine.evaluate(_rec(), _geo())

    assert r.force_block is True
    assert r.disposition != DISPOSITION_ALLOW


# ═══════════════════════════════════════════════════════════
#  拦截规则
# ═══════════════════════════════════════════════════════════


def test_block_rule_is_direct_interception(engine):
    engine._cfg["region_rules"] = [_block_rule()]
    engine._compile()

    r = engine.evaluate(_rec(), _geo())

    assert r.force_block is True
    assert r.suggest_ban is True
    # 结论初值只能是「待确认拦截」：真拦住没有只有写完防火墙才知道
    assert r.disposition == DISPOSITION_CONFIRM
    assert "拦截" in r.reason


def test_block_rule_wins_over_allow_rule(engine):
    """同一记录既命中放行又命中拦截 → 拦。

    变异：把 block 的判断挪到 allow 后面 → 本例变红（放行短路先返回）。
    """
    engine._cfg["region_rules"] = [_allow_rule(), _block_rule()]
    engine._compile()

    r = engine.evaluate(_rec(), _geo())

    assert r.force_block is True
    assert r.disposition != DISPOSITION_ALLOW


def test_block_rule_respects_ports(engine):
    """限定端口的拦截规则只拦那个端口 —— 别把整台机器掐死"""
    engine._cfg["region_rules"] = [_block_rule(ports=[3389])]
    engine._compile()

    assert engine.evaluate(_rec(port=3389), _geo()).force_block is True
    assert engine.evaluate(_rec(port=80), _geo()).force_block is False


def test_block_rule_without_conditions_is_ignored(engine):
    """一条什么条件都没填的拦截规则 = 匹配全部地址，属于误配，必须不生效。

    变异：去掉 `_match_region_rules` 里「无维度即跳过」那一行 → 本例变红，
    结果会是「保存一条空规则，整机所有访问全被封」。
    """
    engine._cfg["region_rules"] = [
        {"id": "blk-x", "name": "空规则", "enabled": True, "action": "block", "match": {}}
    ]
    engine._compile()

    assert engine.evaluate(_rec(), _geo()).force_block is False


# ═══════════════════════════════════════════════════════════
#  名单 → 规则迁移
# ═══════════════════════════════════════════════════════════


def _write_list(path: str, items) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"items": list(items)}, f)


def _read_list(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f).get("items", [])


def test_migrate_lists_creates_block_and_allow_rules(engine, monkeypatch):
    """黑名单 → 拦截规则，白名单 → 放行规则（仅豁免），名单文件清空。"""
    from app import list_migration
    from core import rule_engine

    monkeypatch.setattr(rule_engine, "get_engine", lambda: engine)
    engine.blacklist = _IPSet([IP, "198.51.100.0/24"])
    engine.whitelist = _IPSet(["192.0.2.9"])
    engine.save_lists()

    res = list_migration.migrate_lists_to_rules(actor="tester")

    assert res["error"] == ""
    assert (res["black"], res["white"]) == (2, 1)
    assert res["migrated"] == 3

    rules = engine.get_config().get("region_rules") or []
    by_action: Dict[str, list] = {}
    for r in rules:
        by_action.setdefault(r["action"], []).append(r["match"]["cidrs"])
    assert [IP] in by_action["block"]
    assert ["198.51.100.0/24"] in by_action["block"]
    assert ["192.0.2.9"] in by_action["allow"]
    # 白名单迁移出来的放行规则是「仅豁免」：不能反过来把未命中的来源全拦掉
    allow_rule = next(r for r in rules if r["action"] == "allow")
    assert allow_rule.get("exempt_only") is True
    assert allow_rule["target_ports"] == []

    # 名单文件必须被清空，否则「界面取消了、文件里还在」会变成幽灵策略
    assert _read_list(config.blacklist_path()) == []
    assert _read_list(config.whitelist_path()) == []
    # 备份必须留下
    assert res["backup"] and os.path.isdir(res["backup"])


def test_migrate_is_idempotent(engine, monkeypatch):
    """迁移跑第二次什么都不做（启动时每次都会调它，不能每次加一批规则）。"""
    from app import list_migration
    from core import rule_engine

    monkeypatch.setattr(rule_engine, "get_engine", lambda: engine)
    engine.blacklist = _IPSet([IP])
    engine.save_lists()

    first = list_migration.migrate_lists_to_rules(actor="tester")
    second = list_migration.migrate_lists_to_rules(actor="tester")

    assert first["migrated"] == 1
    assert second["migrated"] == 0
    rules = engine.get_config().get("region_rules") or []
    assert len([r for r in rules if r["action"] == "block"]) == 1


# ═══════════════════════════════════════════════════════════
#  拦截 / 放行目标收集
# ═══════════════════════════════════════════════════════════


def _patch_engine(monkeypatch, rules):
    from app import list_migration
    from core import rule_engine

    class _Eng:
        def get_config(self):
            return {"rules": {}, "region_rules": rules}

    monkeypatch.setattr(rule_engine, "get_engine", _Eng)
    return list_migration


def test_rule_targets_skips_networks_and_blocked_allow(monkeypatch):
    """网段不做预置；同一 IP 既在拦截又在放行 → 只算拦截（否则解封会把它放走）。"""
    rules = [
        _block_rule(cidr=IP, rid="blk-1"),
        _block_rule(cidr="198.51.100.0/24", rid="blk-2"),
        _allow_rule(rid="alw-1", ports=[80]),
        {
            "id": "alw-2",
            "name": "放行同一 IP",
            "enabled": True,
            "action": "allow",
            "match": {"cidrs": [IP]},
        },
        {
            "id": "alw-3",
            "name": "停用的放行",
            "enabled": False,
            "action": "allow",
            "match": {"cidrs": ["192.0.2.44"]},
        },
    ]
    lm = _patch_engine(monkeypatch, rules)

    blocks, allows, nets = lm.rule_targets()

    assert blocks == [IP]
    assert allows == [], "同一 IP 同时被拦截与放行时必须只算拦截"
    assert "block:198.51.100.0/24" in nets


def test_rule_targets_reads_legacy_whitelist_action(monkeypatch):
    """旧名 whitelist 仍要被认成放行，否则老配置升级后就不生效了"""
    rules = [
        {
            "id": "r-old",
            "name": "旧放行",
            "enabled": True,
            "action": "whitelist",
            "match": {"cidrs": ["192.0.2.7"]},
        },
    ]
    lm = _patch_engine(monkeypatch, rules)

    blocks, allows, _nets = lm.rule_targets()
    assert blocks == []
    assert allows == ["192.0.2.7"]


def test_precise_ip_normalizes_host_networks():
    """`1.2.3.4/32` 与 `1.2.3.4` 是同一个目标；网段返回 None。"""
    from app.list_migration import precise_ip

    assert precise_ip("1.2.3.4") == "1.2.3.4"
    assert precise_ip("1.2.3.4/32") == "1.2.3.4"
    assert precise_ip("1.2.3.0/24") is None
    assert precise_ip("垃圾") is None


# ═══════════════════════════════════════════════════════════
#  _IPSet：名单是注入面的最后一道闸
# ═══════════════════════════════════════════════════════════


def test_ipset_rejects_injection_entries(tmp_path):
    """名单文件可能被手工编辑/外部导入污染：解析不了的条目必须被静默拒绝，
    绝不能落盘（save_file 的内容之后会进 netsh 命令行）。

    变异：把 _IPSet.add 的 except 分支改成无条件 return True → 本例变红
    （注入串进了 entries()）。
    """
    from core.rule_engine import _IPSet

    evil = [
        "1.2.3.4; netsh advfirewall delete allprofiles",
        "1.2.3.4 & whoami",
        "1.2.3.4/../../etc/passwd",
        "${jndi:ldap://evil}",
        "1.2.3.4\n1.2.3.5",
    ]
    s = _IPSet(evil)
    assert s.entries() == [], f"注入串不能进集合：{s.entries()}"
    assert "1.2.3.4" not in s  # 前缀也不能被当成有效成员

    # 正常条目不受影响；合法条目落盘后读回来一致
    s.add("192.0.2.9")
    s.add("10.0.0.0/8")
    p = tmp_path / "bl.json"
    s.save_file(str(p))
    back = _IPSet.load_file(str(p))
    assert back.entries() == s.entries()
    assert "192.0.2.9" in back and "10.1.2.3" in back
