"""封禁时长策略测试（P2-8：按风险等级分档 + 重复封禁递增）

钉住四件事：
1. 优先级 **规则级 > 递增级 > 等级级 > 默认**（顺序颠倒必须红）；
2. 递增按倍数放大、受封顶限制，且**首次封禁不放大** —— 历史计数必须不含本次；
3. 策略**永远不返回 0**：0 在 `BanRecord` 里是「永久封禁」，
   递增算错一次就等于把人永久封了，这是本项最贵的 bug；
4. 递增没开时行为与改造前一致（只按分档 / 默认取值）。

每条用例都问过「把实现改回错的，它会红吗」：
· 去掉封顶 → `test_escalation_is_capped` 红；
· 把等级级放到递增级前面 → `test_escalation_multiplies_by_factor` 红；
· 把规则级放到递增级后面 → `test_rule_duration_wins` 红；
· 先 insert 再算历史 → `test_first_auto_ban_is_not_escalated` 红；
· 用 LIKE 统计次数 → `test_count_bans_by_ip_is_exact_match` 红；
· 策略返回 0 → `test_policy_never_returns_zero` 红。
"""

import pytest

from app import ban_service
from core import database, firewall
from core import settings as cfg
from core.config import (
    BAN_DURATION_TIER_DEFAULTS,
    DEFAULT_BAN_DURATION_SEC,
    LEVEL_CRITICAL,
    LEVEL_HIGH,
    LEVEL_LOW,
    LEVEL_MEDIUM,
)
from core.models import AccessRecord, BanRecord, RiskResult, now_ms
from core.pipeline import auto_ban_record
from core.rules_meta import region_rule_key

IP = "203.0.113.10"


@pytest.fixture(autouse=True)
def _schema(fresh_db):
    """fresh_db 只清库文件不建表；这里补一次建表（建在临时库里）"""
    database.init_db()
    yield


def _ban(ip: str = IP, status: str = "expired") -> int:
    """造一条历史封禁记录。默认 expired：不会触发「已在封禁中」的查重"""
    return database.insert_ban(BanRecord(ip=ip, reason="历史", status=status, source="manual"))


class _FakeEngine:
    """替身规则引擎：只提供策略层用到的两个读接口"""

    def __init__(self, rules=None, region_rules=None):
        self._rules = rules or {}
        self._region_rules = region_rules or []

    def rule(self, rule_id: str):
        return dict(self._rules.get(rule_id, {}))

    def get_config(self):
        return {"rules": self._rules, "region_rules": self._region_rules}


# ═══════════════════ 等级分档 ═══════════════════


def test_level_tier_boundaries():
    """score → 等级 → 档位，四个阈值（90/65/40/20）各钉一条"""
    cfg.set("ban_duration_critical_sec", 100)
    cfg.set("ban_duration_high_sec", 200)
    cfg.set("ban_duration_medium_sec", 300)
    cfg.set("ban_duration_low_sec", 400)

    assert ban_service.resolve_duration(score=90) == 100
    assert ban_service.resolve_duration(score=65) == 200
    assert ban_service.resolve_duration(score=40) == 300
    assert ban_service.resolve_duration(score=20) == 400


def test_level_tier_source_is_level():
    cfg.set("ban_duration_high_sec", 7200)
    d = ban_service.resolve_duration_detail(score=70)
    assert (d.seconds, d.source) == (7200, ban_service.SOURCE_LEVEL)


def test_level_tier_defaults_match_config():
    """设置里没改过时，取的就是 config 里登记的分档默认值（单一真源）"""
    assert (
        ban_service.resolve_duration(level=LEVEL_CRITICAL)
        == BAN_DURATION_TIER_DEFAULTS[LEVEL_CRITICAL]
    )
    assert ban_service.resolve_duration(level=LEVEL_HIGH) == BAN_DURATION_TIER_DEFAULTS[LEVEL_HIGH]
    assert (
        ban_service.resolve_duration(level=LEVEL_MEDIUM) == BAN_DURATION_TIER_DEFAULTS[LEVEL_MEDIUM]
    )
    assert ban_service.resolve_duration(level=LEVEL_LOW) == BAN_DURATION_TIER_DEFAULTS[LEVEL_LOW]


def test_normal_level_falls_back_to_default():
    """normal（<20 分）没有档位，必须落到默认时长"""
    cfg.set("default_ban_duration_sec", 1234)
    d = ban_service.resolve_duration_detail(score=0)
    assert (d.seconds, d.source) == (1234, ban_service.SOURCE_DEFAULT)


def test_tier_zero_means_no_tier():
    """档位 0 = 不分档（退回默认），不是「0 秒」"""
    cfg.set("ban_duration_high_sec", 0)
    cfg.set("default_ban_duration_sec", 999)
    d = ban_service.resolve_duration_detail(score=70)
    assert (d.seconds, d.source) == (999, ban_service.SOURCE_DEFAULT)


def test_explicit_default_argument_wins_over_setting():
    cfg.set("default_ban_duration_sec", 111)
    assert ban_service.resolve_duration(score=0, default=222) == 222


# ═══════════════════ 递增 ═══════════════════


def _enable_escalation(factor: int = 2, cap_sec: int = 604800) -> None:
    cfg.set("ban_escalation_enabled", "1")
    cfg.set("ban_escalation_factor", factor)
    cfg.set("ban_escalation_max_sec", cap_sec)


def test_escalation_multiplies_by_factor():
    _enable_escalation(factor=2)
    cfg.set("ban_duration_high_sec", 3600)
    _ban()
    _ban()  # 历史 2 次

    d = ban_service.resolve_duration_detail(score=70, ip=IP)
    assert d.seconds == 3600 * 4, "2 次历史 × 2 倍 = 4 倍基准"
    assert d.source == ban_service.SOURCE_ESCALATION


def test_escalation_is_capped():
    """封顶必须真的生效：4 倍增长被 3 小时压住"""
    _enable_escalation(factor=4, cap_sec=3600 * 3)
    cfg.set("ban_duration_high_sec", 3600)
    _ban()

    assert ban_service.resolve_duration(score=70, ip=IP) == 3600 * 3


def test_escalation_cap_never_shortens_level_tier():
    """封顶小于档位时不反过来压短（封顶只约束「递增」）"""
    _enable_escalation(factor=2, cap_sec=60)
    cfg.set("ban_duration_high_sec", 3600)
    _ban()

    assert ban_service.resolve_duration(score=70, ip=IP) == 3600


def test_escalation_uses_base_when_level_has_no_tier():
    """没有档位时以默认时长为基准递增"""
    _enable_escalation(factor=3)
    cfg.set("ban_duration_high_sec", 0)
    cfg.set("default_ban_duration_sec", 60)
    _ban()

    assert ban_service.resolve_duration(score=70, ip=IP) == 180


def test_escalation_disabled_ignores_history():
    """递增关闭时，历史记录再多也不放大（行为与改造前一致）"""
    cfg.set("ban_escalation_enabled", "0")
    cfg.set("ban_duration_high_sec", 3600)
    for _ in range(5):
        _ban()

    d = ban_service.resolve_duration_detail(score=70, ip=IP)
    assert (d.seconds, d.source) == (3600, ban_service.SOURCE_LEVEL)


def test_escalation_ignores_other_ip_history():
    _enable_escalation(factor=2)
    cfg.set("ban_duration_high_sec", 3600)
    _ban("198.51.100.9")
    _ban("198.51.100.9")

    d = ban_service.resolve_duration_detail(score=70, ip=IP)
    assert (d.seconds, d.source) == (3600, ban_service.SOURCE_LEVEL)


def test_escalation_factor_one_is_noop():
    """倍数配成 1（或 0）等于没开：不能出现「越封越短」，也不能变成 0"""
    _enable_escalation(factor=1)
    cfg.set("ban_duration_high_sec", 3600)
    _ban()
    _ban()

    d = ban_service.resolve_duration_detail(score=70, ip=IP)
    assert d.seconds == 3600
    assert d.source != ban_service.SOURCE_ESCALATION


def test_escalation_without_ip_does_not_query_history():
    """没给 IP 时不递增（自动路径理论上总会给，手动调用可能没有）"""
    _enable_escalation(factor=2)
    cfg.set("ban_duration_high_sec", 3600)
    _ban()

    assert ban_service.resolve_duration(score=70) == 3600


# ═══════════════════ 规则级 ═══════════════════


def test_rule_duration_wins_over_escalation(monkeypatch):
    """规则级优先级最高：即使开了递增、有两倍历史，也按规则配的值来"""
    monkeypatch.setattr(
        ban_service, "get_engine", lambda: _FakeEngine({"blacklist": {"ban_duration_sec": 86400}})
    )
    _enable_escalation(factor=2)
    cfg.set("ban_duration_critical_sec", 60)
    _ban()
    _ban()

    d = ban_service.resolve_duration_detail(score=95, ip=IP, rule_ids=["blacklist"])
    assert (d.seconds, d.source) == (86400, ban_service.SOURCE_RULE)


def test_rule_takes_the_longest(monkeypatch):
    """命中多条规则且都配了时长：取最狠（最长）的那条"""
    monkeypatch.setattr(
        ban_service,
        "get_engine",
        lambda: _FakeEngine({"a": {"ban_duration_sec": 600}, "b": {"ban_duration_sec": 9000}}),
    )

    d = ban_service.resolve_duration_detail(score=95, rule_ids=["a", "b"])
    assert d.seconds == 9000


def test_rule_without_duration_falls_through(monkeypatch):
    monkeypatch.setattr(ban_service, "get_engine", lambda: _FakeEngine({"a": {"score": 80}}))
    cfg.set("ban_duration_high_sec", 3600)

    d = ban_service.resolve_duration_detail(score=70, rule_ids=["a"])
    assert (d.seconds, d.source) == (3600, ban_service.SOURCE_LEVEL)


def test_rule_with_zero_or_negative_duration_is_ignored(monkeypatch):
    """配成 0 / 负数属于「没配」，绝不能当成「0 秒」或「永久」"""
    monkeypatch.setattr(
        ban_service,
        "get_engine",
        lambda: _FakeEngine({"a": {"ban_duration_sec": 0}, "b": {"ban_duration_sec": -5}}),
    )
    cfg.set("ban_duration_high_sec", 3600)

    d = ban_service.resolve_duration_detail(score=70, rule_ids=["a", "b"])
    assert (d.seconds, d.source) == (3600, ban_service.SOURCE_LEVEL)


def test_region_rule_duration(monkeypatch):
    """区域规则（region_<action>:<id>）也能配时长，要从原始配置里反查到"""
    monkeypatch.setattr(
        ban_service,
        "get_engine",
        lambda: _FakeEngine(
            region_rules=[{"id": "r1", "action": "suggest_ban", "ban_duration_sec": 43200}]
        ),
    )

    d = ban_service.resolve_duration_detail(
        score=70, rule_ids=[region_rule_key("suggest_ban", "r1")]
    )
    assert (d.seconds, d.source) == (43200, ban_service.SOURCE_RULE)


# ═══════════════════ 0 不等于永久（坑 1）═══════════════════


def test_policy_never_returns_zero():
    """把能配的值全配成 0：策略仍须给出 ≥1 秒，且 prepare 不会得到永久封禁"""
    for key in (
        "default_ban_duration_sec",
        "ban_duration_critical_sec",
        "ban_duration_high_sec",
        "ban_duration_medium_sec",
        "ban_duration_low_sec",
        "ban_escalation_max_sec",
    ):
        cfg.set(key, 0)
    cfg.set("ban_escalation_enabled", "1")
    cfg.set("ban_escalation_factor", 0)
    _ban()

    assert ban_service.resolve_duration(score=95, ip=IP) >= 1

    rec = ban_service.prepare(IP, 95)
    assert rec.duration_sec is not None, "策略算出 0 会变成永久封禁，这是线上事故"
    assert rec.duration_sec >= 1
    assert rec.expire_at is not None


def test_default_override_zero_still_yields_positive():
    assert ban_service.resolve_duration(score=0, default=0) == DEFAULT_BAN_DURATION_SEC


def test_resolve_clamps_absurd_tier():
    """配了个天文数字的档位：夹到当前生效上限，不抛错也不返回 0。

    「上限」自 S3① 起是可配的（默认 7 天），内置 365 天只是它的天花板。
    """
    cfg.set("ban_duration_critical_sec", 10**12)
    assert ban_service.resolve_duration(score=95) == ban_service.max_ban_seconds()


# ═══════════════════ prepare / execute 语义 ═══════════════════


def test_prepare_none_means_policy():
    cfg.set("ban_duration_high_sec", 7200)
    rec = ban_service.prepare(IP, 70)
    assert rec.duration_sec == 7200
    assert rec.expire_at is not None


def test_prepare_zero_still_means_permanent():
    """`0` 仍然是「永久」——走策略的是 `None`，两者不能混"""
    cfg.set("ban_duration_high_sec", 7200)
    rec = ban_service.prepare(IP, 70, "", 0)
    assert rec.duration_sec is None
    assert rec.expire_at is None


def test_prepare_explicit_duration_overrides_policy():
    cfg.set("ban_duration_high_sec", 7200)
    rec = ban_service.prepare(IP, 70, "", 120)
    assert rec.duration_sec == 120


# ═══════════════════ 历史次数统计（坑 2 的基础）═══════════════════


def test_count_bans_by_ip_is_exact_match():
    """必须 `ip = ?` 等值：LIKE 会把 203.0.113.1 和 .10 混在一起"""
    _ban("203.0.113.1")
    _ban("203.0.113.10")
    _ban("203.0.113.10")

    assert database.count_bans_by_ip("203.0.113.1") == 1
    assert database.count_bans_by_ip("203.0.113.10") == 2
    assert database.count_bans_by_ip("203.0.113.11") == 0


def test_count_bans_by_ip_counts_all_statuses():
    """解封 / 到期 / 失败都算「封过」——否则攻击者等解封重来就又回到第一次"""
    for status in ("active", "expired", "unbanned", "failed"):
        _ban(status=status)

    assert database.count_bans_by_ip(IP) == 4


def test_count_bans_by_ip_since_ts():
    _ban()

    assert database.count_bans_by_ip(IP, since_ts=now_ms() + 60000) == 0
    assert database.count_bans_by_ip(IP, since_ts=now_ms() - 60000) == 1


# ═══════════════════ 自动封禁路径接线 ═══════════════════


@pytest.fixture
def fake_fw(monkeypatch):
    calls = []

    def _block(ip, duration=None, note=""):
        calls.append((ip, duration))
        return (True, f"PortGuard_Block_{ip}", "")

    monkeypatch.setattr(firewall, "block_ip", _block)
    return calls


def _rec(ip: str = IP) -> AccessRecord:
    return AccessRecord(ip=ip, remote_port=51234, local_port=18080, protocol="tcp")


def _result(score: int = 70, level: str = "high") -> RiskResult:
    return RiskResult(score=score, level=level, matched_rules=["rate_limit"], suggest_ban=True)


def test_auto_ban_uses_level_tier(isolated_env, fake_fw):
    """自动封禁不再固定 3600：按等级档位取值，且落库与防火墙拿到的是同一个值"""
    cfg.set("ban_duration_high_sec", 7200)
    cfg.set("default_ban_duration_sec", 60)

    auto_ban_record(_rec(), _result())

    rows = database.query_bans(limit=10)
    assert len(rows) == 1
    assert rows[0].duration_sec == 7200
    assert rows[0].expire_at is not None
    assert fake_fw == [(IP, 7200)]


def test_first_auto_ban_is_not_escalated(isolated_env, fake_fw):
    """坑 2：历史计数必须发生在 insert 之前，否则第一次封禁就被当成第二次而翻倍"""
    _enable_escalation(factor=2)
    cfg.set("ban_duration_high_sec", 3600)

    auto_ban_record(_rec(), _result())

    assert database.query_bans(limit=10)[0].duration_sec == 3600


def test_auto_ban_escalates_on_history(isolated_env, fake_fw):
    _enable_escalation(factor=2)
    cfg.set("ban_duration_high_sec", 3600)
    _ban()
    _ban()  # 两条 expired 历史，不会触发「已在封禁中」的查重

    auto_ban_record(_rec(), _result())

    assert database.query_bans(limit=10)[0].duration_sec == 3600 * 4


def test_auto_ban_falls_back_when_policy_raises(isolated_env, fake_fw, monkeypatch):
    """策略层炸了也不能挡住封禁：退回默认时长继续封"""
    cfg.set("default_ban_duration_sec", 1200)

    def _boom(**kwargs):
        raise RuntimeError("rules.json 读不到")

    monkeypatch.setattr("app.ban_service.resolve_duration_detail", _boom)

    auto_ban_record(_rec(), _result())

    assert database.query_bans(limit=10)[0].duration_sec == 1200


# ═══════════════════════════════════════════════════════════
#  最大封禁时长硬上限（S3①）
#
#  为什么必须钉住：Windows 防火墙规则没有到期时间，到期全靠进程内巡检删规则。
#  程序长期不在时，一条「封 365 天」等于永久封掉一个可能无辜的地址。
#  `_sec()` 与 `prepare()` 是仅有的两个收敛点，改坏任意一处都要红。
# ═══════════════════════════════════════════════════════════

CAP_7D = 7 * 24 * 3600


def test_manual_duration_is_capped(isolated_env):
    """手动封一年 → 被截到最大封禁时长（默认 7 天），且 expire_at 跟着算对"""
    rec = ban_service.prepare("203.0.113.70", duration_sec=365 * 24 * 3600)

    assert rec.duration_sec == CAP_7D
    assert rec.expire_at is not None
    assert rec.expire_at - now_ms() <= CAP_7D * 1000 + 1000


def test_cap_is_configurable(isolated_env):
    cfg.set("max_ban_duration_sec", 2 * 86400)

    rec = ban_service.prepare("203.0.113.71", duration_sec=30 * 86400)

    assert rec.duration_sec == 2 * 86400, "改了设置却不生效，等于上限形同虚设"


def test_cap_cannot_be_configured_below_one_hour(isolated_env):
    """上限配成 1 分钟等于让封禁形同虚设，必须被抬回 1 小时"""
    cfg.set("max_ban_duration_sec", 60)

    assert ban_service.max_ban_seconds() == 3600


def test_permanent_ban_is_not_capped(isolated_env):
    """0 = 永久（黑名单在用）。被截成有限值会让「设为黑名单」第二天自动失效"""
    rec = ban_service.prepare("203.0.113.72", duration_sec=0)

    assert rec.duration_sec is None
    assert rec.expire_at is None


def test_policy_duration_is_capped_and_explained(isolated_env):
    """走策略的时长同样受限，且「为什么这么长」必须说明被截断过 —— 否则
    界面显示的时长与实际生效值不符，运维会拿错数字去判断风险"""
    cfg.set("default_ban_duration_sec", 30 * 86400)
    cfg.set("ban_duration_high_sec", 0)  # 该等级不分档 → 落到默认值

    d = ban_service.resolve_duration_detail(level=LEVEL_HIGH)

    assert d.seconds == CAP_7D
    assert "最大封禁时长" in d.detail
    assert "30 天" in d.detail
