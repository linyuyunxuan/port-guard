"""P1 安全关键路径测试保护：惯犯升级 + 安全启用防火墙（2026-11-04）

审查命中的两条零覆盖高风险路径：
- A1: app/blacklist_service.escalate_repeat_offender（惯犯升级策略链）
- A2: core/firewall.ensure_allow_rules / enable_firewall（安全启用防火墙成功路径）

两条都是「程序自己改安全策略」的敏感动作，出一次错直接影响防护效果：
- A1 升级是把「封了还撞」的 IP 永久拉黑，写错名单 / 漏提示 / 误判阈值都会
  让攻击者在黑名单之外继续撞或让告警失真。
- A2 是先放行当前监听端口再开总开关 —— 顺序反了会把正在用的服务挡到墙外，
  或开完不回读确认就谎报成功。

变异验证（逐条把实现改回错的，确认会红）：
- escalate：`hits < need` 改成 `hits <= ` 放行 → test_escalate_below_threshold_returns_false 红
- escalate：去掉 `engine.blacklist.add`→ 名单没写 → test_escalate_writes_blacklist 红
- escalate：active 分支不调 update_ban → 记录没转永久 → test_escalate_active_ban_to_permanent 红
- escalate：audit failure 分支返回 True → test_escalate_fail_when_blacklist_write_fails 红
- enable_firewall：`allow["failed"]` 判断去掉 → 放行没建全也开总开关 → test_enable_aborts_when_allow_failed 红
- enable_firewall：开完不回读 / after 全关还返回成功 → test_enable_rechecks_state_after_turn_on 红
- ensure_allow_rules：去重逻辑去掉 → 已有同名规则重复添加 → test_ensure_skips_existing_rule 红
"""

from types import SimpleNamespace
from typing import Any, Dict

from app import blacklist_service
from core import firewall
from core import settings as cfg

# ═══════════════════════════════════════════════════════════
#  帮 助 函 数
# ═══════════════════════════════════════════════════════════


class _IPSet:
    """替身名单：`in` 判断 + add + entries，够 escalate 用。"""

    def __init__(self, items=None):
        self._s = set(items or [])

    def add(self, entry: str) -> bool:
        self._s.add(entry)
        return True

    def __contains__(self, ip: str) -> bool:
        return ip in self._s

    def entries(self):
        return sorted(self._s)


def _ban(ip: str, status: str = "active", bid: int = 77) -> SimpleNamespace:
    """替身 BanRecord：只带 escalate 用到的字段。"""
    return SimpleNamespace(
        id=bid,
        ip=ip,
        status=status,
        source="auto",
        duration_sec=1800,
    )


def _patch_settings(monkeypatch, enabled=True, hits=5):
    """打桩核心设置：开关注 + 阈值。conftest 不自动打桩这两个，必须自己来。"""
    monkeypatch.setattr(cfg, "get_bool", lambda key, default=True: enabled)
    monkeypatch.setattr(cfg, "get_int", lambda key, default=5: hits)


class _Env:
    """一次 escalation 的资源袋：打桩清单 + 记录调用。"""

    def __init__(self, monkeypatch, engine_blacklist=None, admin=True):
        self.events: list = []
        self.audit: list = []
        self.updates: list = []
        self.block_rules: list = []
        self.saves: list = [0]
        engine = SimpleNamespace(
            blacklist=_IPSet(engine_blacklist or []),
            save_lists=lambda: self.saves.__setitem__(0, self.saves[0] + 1),
        )
        monkeypatch.setattr("core.rule_engine.get_engine", lambda: engine)
        monkeypatch.setattr(firewall, "is_admin", lambda: admin)
        monkeypatch.setattr("app.list_migration.add_block_rule", self.block_rules.append)
        monkeypatch.setattr(
            "core.database.update_ban", lambda bid, **kw: self.updates.append((bid, kw))
        )
        monkeypatch.setattr("app.audit.record", lambda *a, **k: self.audit.append((a, k)))
        monkeypatch.setattr("core.event_bus.bus.emit_alert", self.events.append)
        self.engine = engine


def _escalated_event(env) -> Dict[str, Any]:
    """从记录的事件里挑出 escalated=True 的那条（这次升级发的提示）。"""
    for ev in env.events:
        if ev.get("escalated"):
            return ev
    return {}


# ═══════════════════════════════════════════════════════════
#  A1：惯犯升级 —— 阈值与开关注守门
# ═══════════════════════════════════════════════════════════


def test_escalate_empty_ip_returns_false(monkeypatch):
    _patch_settings(monkeypatch, enabled=True, hits=5)
    env = _Env(monkeypatch)
    assert blacklist_service.escalate_repeat_offender("  ", None, 9) is False
    assert env.audit == [], "空 IP 不该留审计痕迹"


def test_escalate_feature_disabled_returns_false(monkeypatch):
    _patch_settings(monkeypatch, enabled=False)
    env = _Env(monkeypatch)
    assert (
        blacklist_service.escalate_repeat_offender("203.0.113.100", _ban("203.0.113.100"), 9)
        is False
    )
    assert env.audit == []


def test_escalate_below_threshold_returns_false(monkeypatch):
    _patch_settings(monkeypatch, enabled=True, hits=5)
    env = _Env(monkeypatch)
    ok = blacklist_service.escalate_repeat_offender("203.0.113.101", _ban("203.0.113.101"), hits=4)
    assert ok is False, "4 次没到阈值 5，不该升级"
    assert env.audit == [], "未到阈值不开审计"
    assert list(env.engine.blacklist.entries()) == [], "名单不能被写进尚未达标的 IP"


def test_escalate_already_in_blacklist_returns_false(monkeypatch):
    _patch_settings(monkeypatch, enabled=True, hits=5)
    _Env(monkeypatch, engine_blacklist=["203.0.113.102"])
    ok = blacklist_service.escalate_repeat_offender("203.0.113.102", _ban("203.0.113.102"), hits=10)
    assert ok is False, "已在黑名单就别重复升级/重复提示"


def test_escalate_config_error_returns_false(monkeypatch):
    def _boom(key, default=True):
        raise RuntimeError("cfg down")

    monkeypatch.setattr(cfg, "get_bool", _boom)
    _Env(monkeypatch)
    ok = blacklist_service.escalate_repeat_offender("203.0.113.103", _ban("203.0.113.103"), 9)
    assert ok is False, "设置读取失败时宁可不升级，也不能误升级"


# ═══════════════════════════════════════════════════════════
#  A1：惯犯升级 —— 名单写入
# ═══════════════════════════════════════════════════════════


def test_escalate_writes_blacklist(monkeypatch):
    _patch_settings(monkeypatch, enabled=True, hits=5)
    env = _Env(monkeypatch)
    ok = blacklist_service.escalate_repeat_offender("203.0.113.110", _ban("203.0.113.110"), hits=7)
    assert ok is True
    assert "203.0.113.110" in env.engine.blacklist, "达到阈值必须写进黑名单文件"
    assert env.saves[0] == 1, "写名单后必须 save_lists 落盘（否则重启即失效）"
    assert env.block_rules == ["203.0.113.110"], "升级应同时落一条可见的拦截规则"


def test_escalate_finishes_write_failure_as_failure(monkeypatch):
    _patch_settings(monkeypatch, enabled=True, hits=5)

    class _BoomSet(_IPSet):
        def add(self, entry):
            raise OSError("disk full")

    engine = SimpleNamespace(
        blacklist=_BoomSet(), save_lists=lambda: (_ for _ in ()).throw(RuntimeError)
    )
    monkeypatch.setattr("core.rule_engine.get_engine", lambda: engine)
    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    audit_calls = []

    def _record(*a, **k):
        audit_calls.append((a, k))

    monkeypatch.setattr("app.audit.record", _record)
    ok = blacklist_service.escalate_repeat_offender("203.0.113.111", _ban("203.0.113.111"), hits=6)
    assert ok is False, "名单没写成必须判失败，不能谎称升级成功"
    assert audit_calls, "失败也要留审计"
    assert audit_calls[0][1]["result"] == "fail"


# ═══════════════════════════════════════════════════════════
#  A1：惯犯升级 —— 改为永久 的三种落法
# ═══════════════════════════════════════════════════════════


def test_escalate_active_ban_to_permanent(monkeypatch):
    """active 记录：规则已在墙里 → 只改库不改规则，转永久 + 来源 blacklist。"""
    _patch_settings(monkeypatch, enabled=True, hits=5)
    env = _Env(monkeypatch)
    ok = blacklist_service.escalate_repeat_offender(
        "203.0.113.120", _ban("203.0.113.120", bid=77), hits=6
    )
    assert ok is True
    assert len(env.updates) == 1
    bid, kw = env.updates[0]
    assert bid == 77
    assert kw["duration_sec"] == 0, "永久 = 0"
    assert kw["expire_at"] is None
    assert kw["source"] == blacklist_service.SOURCE_BLACKLIST
    ev = _escalated_event(env)
    assert ev["ip"] == "203.0.113.120" and ev["escalated"] is True and ev["disposition"] == "block"


def test_escalate_pending_ban_builds_rule_when_admin(monkeypatch):
    """pending 记录（规则没建成）：有管理员 → 真去建永久规则。"""
    _patch_settings(monkeypatch, enabled=True, hits=5)
    env = _Env(monkeypatch, admin=True)
    banned = {"flag": False}
    monkeypatch.setattr(
        blacklist_service,
        "apply_changes",
        lambda added, removed, actor=None: (
            banned.update(flag=True),
            {"banned": ["203.0.113.121"], "failed": [], "already": []},
        )[1],
    )
    ok = blacklist_service.escalate_repeat_offender(
        "203.0.113.121", _ban("203.0.113.121", status="pending"), hits=6
    )
    assert ok is True and banned["flag"] is True
    result = env.audit[0][1]["result"]
    assert result == "ok", "真实建了规则应审计为 ok"


def test_escalate_pending_ban_non_admin_does_not_build(monkeypatch):
    """pending 记录 + 非管理员：不建规则、不谎报成功，审计 skipped。"""
    _patch_settings(monkeypatch, enabled=True, hits=5)
    env = _Env(monkeypatch, admin=False)
    monkeypatch.setattr(
        blacklist_service,
        "apply_changes",
        lambda *a, **k: (_ for _ in ()).throw(AssertionError("非管理员不该调 apply_changes")),
    )
    ok = blacklist_service.escalate_repeat_offender(
        "203.0.113.122", _ban("203.0.113.122", status="pending"), hits=6
    )
    assert ok is True, "名单已写、非管理员场景仍返回 True（待下次管理员补齐墙内规则）"
    assert env.updates == [], "非管理员绝不能改库把记录当 active 处理"
    assert env.audit[0][1]["result"] == "skipped"


def test_escalate_pending_ban_rule_build_failure_reports_skip(monkeypatch):
    """pending + 管理员但建规则失败：名单仍生效，审计 skipped，不伪造成功。"""
    _patch_settings(monkeypatch, enabled=True, hits=5)
    env = _Env(monkeypatch, admin=True)
    monkeypatch.setattr(
        blacklist_service,
        "apply_changes",
        lambda added, removed, actor=None: {
            "banned": [],
            "failed": [("203.0.113.123", "timeout")],
            "already": [],
        },
    )
    ok = blacklist_service.escalate_repeat_offender(
        "203.0.113.123", _ban("203.0.113.123", status="pending"), hits=6
    )
    assert ok is True
    assert env.audit[0][1]["result"] == "skipped"
    assert "建规则失败" in env.audit[0][1]["detail"]


def test_escalate_already_banned_via_apply_is_permanent(monkeypatch):
    """pending + 管理员但结果 already（已有生效封禁）→ 不算失败，算永久。"""
    _patch_settings(monkeypatch, enabled=True, hits=5)
    env = _Env(monkeypatch, admin=True)
    monkeypatch.setattr(
        blacklist_service,
        "apply_changes",
        lambda added, removed, actor=None: {
            "banned": [],
            "failed": [],
            "already": ["203.0.113.124"],
        },
    )
    ok = blacklist_service.escalate_repeat_offender(
        "203.0.113.124", _ban("203.0.113.124", status="pending"), hits=6
    )
    assert ok is True
    assert env.audit[0][1]["result"] == "ok", "已有生效封禁，等同已永久"


def test_escalate_tolerates_block_rule_write_failure(monkeypatch):
    """add_block_rule 失败（如防火墙不可用）不能中断升级：名单已生效即可。"""
    _patch_settings(monkeypatch, enabled=True, hits=5)
    env = _Env(monkeypatch)

    def _boom(ip):
        raise RuntimeError("firewall cmd down")

    monkeypatch.setattr("app.list_migration.add_block_rule", _boom)
    ok = blacklist_service.escalate_repeat_offender(
        "203.0.113.130", _ban("203.0.113.130", status="pending"), hits=6
    )
    assert ok is True, "名单已写，拦截规则失败只记日志，不报失败"
    assert "203.0.113.130" in env.engine.blacklist


def test_escalate_tolerates_permanent_convert_failure(monkeypatch):
    """update_ban 抛异常（改永久失败）→ 名单仍生效，审计带 note，不中断升级。"""
    _patch_settings(monkeypatch, enabled=True, hits=5)
    env = _Env(monkeypatch)

    def _boom(bid, **kw):
        raise RuntimeError("db down")

    monkeypatch.setattr("core.database.update_ban", _boom)
    ok = blacklist_service.escalate_repeat_offender(
        "203.0.113.131", _ban("203.0.113.131", bid=77), hits=6
    )
    assert ok is True
    assert "改为永久封禁失败" in env.audit[0][1]["detail"]
    assert "203.0.113.131" in env.engine.blacklist


# ═══════════════════════════════════════════════════════════
#  A2：ensure_allow_rules —— 幂等补齐放行规则
# ═══════════════════════════════════════════════════════════

_FIREWALL_ALLOW_PREFIX = firewall.ALLOW_PREFIX  # "PortGuard_Allow_"


def _patch_allow_env(monkeypatch, tcp, udp, existing=None, add_ok=True):
    """打桩 ensure_allow_rules 的外部边界：监听端口 / 现有规则 / 建规则。"""
    calls: Dict[str, Any] = {"add": []}
    monkeypatch.setattr(firewall, "listening_ports", lambda: (list(tcp), list(udp)))
    monkeypatch.setattr(firewall, "list_rule_names", lambda: list(existing or []))
    add_calls = calls["add"]

    def _add_allow(proto, port):
        add_calls.append((proto, port))
        return (True, "") if add_ok else (False, "权限不足")

    monkeypatch.setattr(firewall, "_add_allow_rule", _add_allow)
    return calls


def test_ensure_creates_rules_for_all_listening_ports(monkeypatch):
    calls = _patch_allow_env(monkeypatch, tcp=[80, 443], udp=[123], existing=[])
    res = firewall.ensure_allow_rules()
    assert sorted(calls["add"]) == [("TCP", 80), ("TCP", 443), ("UDP", 123)]
    assert len(res["created"]) == 3
    assert res["failed"] == []


def test_ensure_skips_existing_rule(monkeypatch):
    """同名放行规则已存在 → 幂等跳过，绝不重复添加报错。"""
    existing = [
        firewall.ALLOW_PREFIX + "TCP_80",
        firewall.ALLOW_PREFIX + "TCP_443",
    ]
    calls = _patch_allow_env(monkeypatch, tcp=[80, 443, 8080], udp=[], existing=existing)
    res = firewall.ensure_allow_rules()
    assert calls["add"] == [("TCP", 8080)], "已存在的不该再建"
    assert res["created"] == [firewall.ALLOW_PREFIX + "TCP_8080"]


def test_ensure_reports_failed_rule(monkeypatch):
    _patch_allow_env(monkeypatch, tcp=[8080], udp=[], existing=[], add_ok=False)
    res = firewall.ensure_allow_rules()
    assert res["failed"] and "权限不足" in res["failed"][0]


def test_ensure_tolerates_rule_list_failure(monkeypatch):
    """列出现有规则失败（如命令出错）→ 按'都不存在'处理，仍尝试补齐，不影响正确性。"""
    monkeypatch.setattr(firewall, "listening_ports", lambda: ([8080], []))
    added = []

    def _boom():
        raise RuntimeError("netsh down")

    monkeypatch.setattr(firewall, "list_rule_names", _boom)

    def _add(proto, port):
        added.append((proto, port))
        return True, ""

    monkeypatch.setattr(firewall, "_add_allow_rule", _add)
    firewall.ensure_allow_rules()
    assert added == [("TCP", 8080)], "列规则失败也不该放弃放行（宁可重复添加报错，也不漏放行）"


# ═══════════════════════════════════════════════════════════
#  A2：enable_firewall —— 安全启用成功路径
# ═══════════════════════════════════════════════════════════


def _patch_enable_env(
    monkeypatch, admin=True, before=None, allow_failed=None, turn_on_code=0, after=None
):
    """打桩 enable_firewall 的整片外设，逐个返回可控值。

    用本地状态让 profiles_state 第一次返回 before（开启前）、
    第二次起返回 after（reset 后回读确认）——模拟真实的开关过程。
    """
    if before is None:
        before = {"domain": False, "private": False, "public": False}
    if after is None:
        after = {"domain": True, "private": True, "public": True}
    runs = []

    monkeypatch.setattr(firewall, "is_admin", lambda: admin)

    state = {"t": 0}

    def _profiles(force=False) -> Dict[str, bool]:
        state["t"] += 1
        return after if state["t"] >= 2 else before

    monkeypatch.setattr(firewall, "profiles_state", _profiles)

    allow: Dict[str, Any] = {"tcp": [], "udp": [], "created": [], "failed": []}
    if allow_failed is not None:
        allow["failed"] = allow_failed
    monkeypatch.setattr(firewall, "ensure_allow_rules", lambda: allow)
    monkeypatch.setattr(firewall, "reset_profile_cache", lambda: None)

    def _run(cmd, timeout=60):
        runs.append(list(cmd))
        return turn_on_code, ""

    monkeypatch.setattr(firewall, "_run", _run)
    return {"runs": runs, "allow": allow}


def test_enable_requires_admin(monkeypatch):
    env = _patch_enable_env(monkeypatch, admin=False)
    ok, err, detail = firewall.enable_firewall()
    assert ok is False and "管理员" in err and detail == {}
    assert env["runs"] == [], "非管理员不该执行任何 netsh"


def test_enable_already_on_is_noop(monkeypatch):
    before = {"domain": True, "private": True, "public": True}
    env = _patch_enable_env(monkeypatch, admin=True, before=before)
    ok, err, detail = firewall.enable_firewall()
    assert ok is True and err == ""
    assert detail.get("already") is True
    assert env["runs"] == [], "已开启时不该再开一次总开关"


def test_enable_aborts_when_allow_failed(monkeypatch):
    """有端口放行失败 → 不碰总开关，宁可先不开，也不挡正在用的服务。"""
    env = _patch_enable_env(
        monkeypatch,
        admin=True,
        before={"domain": False, "private": False, "public": False},
        allow_failed=["PortGuard_Allow_TCP_8080: 权限不足"],
    )
    ok, err, _detail = firewall.enable_firewall()
    assert ok is False
    assert "有监听端口没能放行" in err and "8080" in err
    assert env["runs"] == [], "放行失败时绝不能开总开关"


def test_enable_turns_on_and_returns_created(monkeypatch):
    env = _patch_enable_env(monkeypatch, admin=True)
    ok, err, detail = firewall.enable_firewall()
    assert ok is True and err == ""
    assert env["runs"] and env["runs"][-1].count("on") and "allprofiles" in env["runs"][-1]
    assert "profiles_after" in detail and "created" in detail


def test_enable_rechecks_state_after_turn_on(monkeypatch):
    """开完必须回读确认 —— 不能命令成功就当已开启。"""
    # 开启命令成功但回读仍全关（被组策略/安全软件接管）
    _patch_enable_env(
        monkeypatch,
        admin=True,
        before={"domain": False, "private": False, "public": False},
        after={"domain": False, "private": False, "public": False},
    )
    ok, err, _detail = firewall.enable_firewall()
    assert ok is False
    assert "仍为关闭" in err or "回读" in err


def test_enable_reports_unreadable_state(monkeypatch):
    """开完回读不到 → 返回失败并提示复查，绝不谎报成功。"""
    _patch_enable_env(monkeypatch, admin=True)
    monkeypatch.setattr(firewall, "profiles_state", lambda force=False: None)
    ok, err, _detail = firewall.enable_firewall()
    assert ok is False
    assert "回读不到" in err or "确认" in err


def test_enable_reports_turn_on_command_failure(monkeypatch):
    _patch_enable_env(monkeypatch, admin=True, turn_on_code=1)
    ok, err, _detail = firewall.enable_firewall()
    assert ok is False and "开启防火墙失败" in err
