"""
防火墙规则描述净化 + 到期巡检告警的回归测试。

为什么单独一个文件：这两件事都不是「拼字符串」的小事 ——

1. **描述曾让封禁直接失败**。`netsh advfirewall firewall add rule` 的 `description`
   有自己的字符白名单：`|` 会被判「无效的字符」，成对双引号会打乱它自己的分词。
   而 Server 2008 R2 上没有 `New-NetFirewallRule`（Win8 / 2012 起才有），交付环境
   每次封禁都走 netsh 回退 —— 归属地里的英文长名（`Korea, Republic of`、
   `Côte d'Ivoire`）一旦带上这类符号，封禁就整个失败，攻击者还能借此绕过。
2. **到期巡检依赖管理员权限**，普通权限下原来静默返回空：以管理员封过的 IP 之后
   以普通权限运行就永不解封，界面上一个字都不提示。

本文件的每条用例都做过变异验证（把实现改回错的，确认它会红）。
"""

import pytest

from app import ban_service
from core import firewall
from core.database import init_db, insert_ban
from core.models import STATUS_ACTIVE, BanRecord
from core.validators import cli_note

DIRTY = 'Korea|Republic say "hi" `x` $(calc) a\\b'
DIRTY_IP = "198.51.100.77"
BAD_CHARS = ("|", '"', "`", "$", "\\")


# ═══════════════════ cli_note：描述净化 ═══════════════════


def test_cli_note_keeps_readable_text():
    """汉字、带重音的拉丁字母、常见标点都要原样保留（归属地长这样）"""
    assert cli_note("Côte d'Ivoire") == "Côte d'Ivoire"
    assert cli_note("Korea, Republic of") == "Korea, Republic of"
    assert cli_note("PortGuard 封禁 1.2.3.4") == "PortGuard 封禁 1.2.3.4"


def test_cli_note_replaces_separator_with_space():
    """`·` 不在白名单里 —— 要换成空格，不能直接删（删了会把两个词粘成一个）"""
    assert cli_note("中国·广东省·深圳市") == "中国 广东省 深圳市"


def test_cli_note_drops_netsh_reserved_chars():
    """`|` 与成对引号是实测会让 netsh 拒建规则的字符"""
    out = cli_note(DIRTY)
    for bad in BAD_CHARS:
        assert bad not in out, f"描述里仍残留 {bad!r}：{out!r}"


def test_cli_note_collapses_whitespace_and_truncates():
    assert cli_note("  a   b  ") == "a b"
    assert len(cli_note("A" * 400, 160)) == 160
    assert cli_note("A" * 400, 160) == "A" * 160


def test_cli_note_empty_and_none():
    assert cli_note(None) == ""
    assert cli_note("   ") == ""
    assert cli_note("", default="兜底") == "兜底"


# ═══════════════════ build_description：到期时间写进描述 ═══════════════════


def test_build_description_contains_expiry():
    """Windows 防火墙规则本身没有到期时间，描述是唯一能从控制台看到到期时刻的地方"""
    d = firewall.build_description("203.0.113.10", 3600, "命中规则 x")
    assert d.startswith("PortGuard 封禁 203.0.113.10")
    assert "到期" in d
    assert "命中规则 x" in d


def test_build_description_permanent():
    d = firewall.build_description("203.0.113.10", None, "")
    assert "永久" in d
    assert "到期" not in d


def test_build_description_never_depends_on_strftime(monkeypatch):
    """
    英文版 Windows 上「到期」必须照样写出来 —— 这条挡的是一个不会在本机复现的坑。

    `strftime` 把格式串按**系统 ANSI 代码页**编码：中文 Windows 是 cp936，「到期」
    编得进去，所以本机怎么跑都是绿的；英文 Windows（cp1252）编不进去，抛
    UnicodeEncodeError（ValueError 子类），正好落进 build_description 的
    `except (OverflowError, OSError, ValueError)`，于是描述静默变成「永久」。

    后果不是少一行字：规则其实几小时后就到期删除，控制台里却写着「永久」，
    管理员会以为它永久有效 —— 比不写更糟。GitHub runner 就是 en-US，这个坑当时
    只在 CI 上暴露（2026-10-23）。

    变异：把实现改回 `until.strftime("%Y-%m-%d %H:%M 到期")` → 本例变红。
    """
    import datetime as _dt

    class _NoStrftime(_dt.datetime):
        def strftime(self, fmt):
            raise UnicodeEncodeError("mbcs", str(fmt), 0, 1, "模拟 cp1252 无法编码中文")

    class _Frozen(_dt.datetime):
        @classmethod
        def now(cls, tz=None):
            return _NoStrftime(2026, 10, 23, 12, 34)

    monkeypatch.setattr(_dt, "datetime", _Frozen)
    d = firewall.build_description("203.0.113.10", 3600, "")
    assert "到期" in d, f"非中文代码页下到期时间被吞掉了：{d!r}"
    assert "永久" not in d
    assert "2026-10-23 13:34" in d  # 冻结时刻 12:34 + 3600 秒


def test_build_description_is_netsh_safe_and_bounded():
    """
    最终描述必须**真的触顶截断**：用最长的 IPv6（39 字符）+ 100 字符原因，
    拼出来约 180 字符，超过 `MAX_DESC_LEN`。
    ⚠️ 别把这条改成用短输入 —— 短输入永远碰不到截断，去掉末尾的 cli_note 也照样绿，
    这条用例就变成空转了（变异验证踩过）。
    """
    long_ip = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
    d = firewall.build_description(long_ip, 60, DIRTY * 10)
    for bad in BAD_CHARS:
        assert bad not in d
    # 允许 rstrip 吃掉末尾一两个空格，但不能更多
    assert firewall.MAX_DESC_LEN - 2 <= len(d) <= firewall.MAX_DESC_LEN
    assert "到期" in d, "截断不能把到期时间挤掉 —— 那是这条描述存在的首要原因"


# ═══════════════════ block_ip：描述绝不能挡住封禁 ═══════════════════


def _fail_all(monkeypatch, ps_out: str, netsh_desc_fails: bool = True):
    """PS 全失败；netsh 只在「带 description」时失败（真机上的行为）"""
    calls = []
    exists: set = set()
    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    # block_ip 会先查规则是否存在：存在就复用（续封刷新描述），不存在才新建。
    # 这里用一张假规则表，让「新建 → 回读复核」这条链能被真正走到。
    monkeypatch.setattr(firewall, "rule_exists", lambda name: name in exists)
    monkeypatch.setattr(firewall, "_ps_cmdlet_missing", None)
    monkeypatch.setattr(firewall, "_powershell", lambda script, timeout=30: (1, ps_out))

    def fake_run(cmd, timeout=30):
        calls.append(list(cmd))
        if netsh_desc_fails and any(str(a).startswith("description=") for a in cmd):
            return 1, "描述包含无效的字符，或具有无效的长度。"
        for a in cmd:
            if str(a).startswith("name="):
                exists.add(str(a)[len("name=") :])
        return 0, ""

    monkeypatch.setattr(firewall, "_run", fake_run)
    return calls


def test_block_ip_degrades_to_no_description(monkeypatch):
    """
    描述被防火墙拒绝时，必须降级为「无描述」再建一次并成功。

    不降级的话，攻击者只要让自己的归属地/规则名带上 `|`，就能让自己的封禁静默失败。
    """
    calls = _fail_all(monkeypatch, "描述包含无效的字符，或具有无效的长度。")
    ok, name, err = firewall.block_ip(DIRTY_IP, 3600, DIRTY)
    assert ok is True, err
    assert name.startswith(firewall.RULE_PREFIX)
    assert err == ""
    assert len(calls) == 2, f"应当「带描述失败 → 无描述成功」共两次 netsh，实际 {calls}"
    assert any(str(a).startswith("description=") for a in calls[0]), "第一次应带描述"
    assert not any(str(a).startswith("description=") for a in calls[1]), "降级那次不该带描述"


def test_block_ip_passes_sanitized_description(monkeypatch):
    """真机上 netsh 收到的描述里不能再出现危险字符（净化发生在发命令之前）"""
    calls = []
    exists: set = set()
    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    # 规则一开始不存在 → 走「新建」；建完回读才为真。
    # （固定返回 True 会走「续封复用」分支，那段在 2008 R2 上要先删再建，
    #   真正被断言的那条带描述命令就不是 calls[0] 了）
    monkeypatch.setattr(firewall, "rule_exists", lambda name: name in exists)
    monkeypatch.setattr(firewall, "_ps_cmdlet_missing", True)  # 模拟 2008 R2：只有 netsh

    def fake_run(cmd, timeout=30):
        calls.append(list(cmd))
        for a in cmd:
            if str(a).startswith("name="):
                exists.add(str(a)[len("name=") :])
        return 0, ""

    monkeypatch.setattr(firewall, "_run", fake_run)
    ok, _name, err = firewall.block_ip(DIRTY_IP, 3600, DIRTY)
    assert ok, err
    desc_arg = next(str(a) for a in calls[0] if str(a).startswith("description="))
    for bad in BAD_CHARS:
        assert bad not in desc_arg, f"netsh 收到了危险字符 {bad!r}：{desc_arg!r}"


def test_block_ip_reports_both_attempts_on_total_failure(monkeypatch):
    """两次都失败时，错误里要能看出「无描述重试也失败」，否则排查时以为是描述问题"""
    _fail_all(monkeypatch, "Access is denied", netsh_desc_fails=True)

    def fake_run(cmd, timeout=30):
        return 1, "Access is denied"

    monkeypatch.setattr(firewall, "_run", fake_run)
    ok, name, err = firewall.block_ip(DIRTY_IP, 60, "x")
    assert ok is False and name == ""
    assert "无描述重试" in err


def test_missing_ps_cmdlet_is_cached(monkeypatch):
    """
    2008 R2 没有 New-NetFirewallRule：探到一次之后就别再跑注定失败的 PS 命令，
    否则每次封禁都白等 0.3~0.5 秒。
    """
    ps_calls = []
    exists: set = set()
    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    monkeypatch.setattr(firewall, "rule_exists", lambda name: name in exists)
    monkeypatch.setattr(firewall, "_ps_cmdlet_missing", None)

    def fake_ps(script, timeout=30):
        ps_calls.append(script)
        return 1, "New-NetFirewallRule : 无法将“New-NetFirewallRule”项识别为 cmdlet、函数…"

    def fake_run(cmd, timeout=30):
        for a in cmd:
            if str(a).startswith("name="):
                exists.add(str(a)[len("name=") :])
        return 0, ""

    monkeypatch.setattr(firewall, "_powershell", fake_ps)
    monkeypatch.setattr(firewall, "_run", fake_run)

    ok1, _n1, _e1 = firewall.block_ip("198.51.100.78")
    ok2, _n2, _e2 = firewall.block_ip("198.51.100.79")
    assert ok1 and ok2
    assert len(ps_calls) == 1, "缺 cmdlet 的结论应被缓存，第二次不该再调 PS"
    assert firewall.ps_cmdlet_missing() is True


def test_transient_ps_failure_does_not_poison_cache(monkeypatch):
    """偶发失败（不是「命令不存在」）不能被缓存，否则后续封禁永远跳过 PS"""
    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    # block_ip 写入后会回读复核规则存在性；单测里防火墙是假的，直接放行
    monkeypatch.setattr(firewall, "rule_exists", lambda name: True)
    monkeypatch.setattr(firewall, "_ps_cmdlet_missing", None)
    monkeypatch.setattr(firewall, "_powershell", lambda script, timeout=30: (1, "拒绝访问"))
    monkeypatch.setattr(firewall, "_run", lambda cmd, timeout=30: (0, ""))
    firewall.block_ip("198.51.100.80", 60, "")
    assert firewall.ps_cmdlet_missing() is False


# ═══════════════════ 到期巡检：不许静默 ═══════════════════


class _RecLog:
    def __init__(self):
        self.warnings = []

    def warning(self, msg, *args, **kwargs):
        self.warnings.append(msg % args if args else msg)

    def exception(self, msg, *args, **kwargs):
        self.warnings.append("EXC:" + (msg % args if args else msg))


def _add_expired_ban():
    insert_ban(
        BanRecord(
            ip="203.0.113.10",
            rule_name="PortGuard_Block_x_1_aa",
            status=STATUS_ACTIVE,
            source="manual",
            duration_sec=60,
            expire_at=1,  # 早已过期
        )
    )


def test_expired_backlog_counts_active_expired(isolated_env):
    init_db()
    assert ban_service.expired_backlog() == 0
    _add_expired_ban()
    assert ban_service.expired_backlog() == 1


def test_check_expired_warns_when_no_admin_and_backlog(isolated_env, monkeypatch):
    """这是被打回的那条：非管理员时必须说出来，而不是返回空列表了事"""
    init_db()
    _add_expired_ban()
    monkeypatch.setattr(firewall, "is_admin", lambda: False)
    monkeypatch.setattr(ban_service, "_admin_skip_warned_at", 0.0)
    rec = _RecLog()
    monkeypatch.setattr(ban_service, "log", rec)

    assert ban_service.check_expired() == []
    assert len(rec.warnings) == 1
    assert "1 条封禁已到期" in rec.warnings[0]
    assert "管理员" in rec.warnings[0]


def test_check_expired_warning_is_rate_limited(isolated_env, monkeypatch):
    """巡检每 60 秒一次，不限流会用同一句把日志刷满"""
    init_db()
    _add_expired_ban()
    monkeypatch.setattr(firewall, "is_admin", lambda: False)
    monkeypatch.setattr(ban_service, "_admin_skip_warned_at", 0.0)
    rec = _RecLog()
    monkeypatch.setattr(ban_service, "log", rec)

    for _ in range(5):
        ban_service.check_expired()
    assert len(rec.warnings) == 1


def test_check_expired_silent_when_no_backlog(isolated_env, monkeypatch):
    """普通权限运行本来就是设计内的正常用法，没有积压就不该打扰"""
    init_db()
    monkeypatch.setattr(firewall, "is_admin", lambda: False)
    monkeypatch.setattr(ban_service, "_admin_skip_warned_at", 0.0)
    rec = _RecLog()
    monkeypatch.setattr(ban_service, "log", rec)

    assert ban_service.check_expired() == []
    assert rec.warnings == []


@pytest.mark.parametrize("bad", ["|", '"'])
def test_rejects_input_that_used_to_break_netsh(bad):
    """这条钉住「真机复现过的失败输入」，防止有人把净化当成多余逻辑删掉"""
    assert bad not in cli_note(f"Korea{bad}Republic")


# ═══════════════════ 2008 R2：规则列表的 netsh 回退 ═══════════════════

#: 真机上 netsh 输出的真实形态（表头本地化，不解析它，靠正则抓名字）
NETSH_SHOW_OUTPUT = """
规则名:                            PortGuard_Block_203.0.113.10_1700000000000_ab12
----------------------------------------------------------------------
已启用:                            是
方向:                              入
配置文件:                          任何
分组:
本地 IP:                           任何
远程 IP:                           203.0.113.10
协议:                              任何

规则名:                            PortGuard_Block_203.0.113.11_1700000000001_cd34
----------------------------------------------------------------------
已启用:                            是
"""


def test_list_rules_falls_back_to_netsh(monkeypatch):
    """
    2008 R2 没有 Get-NetFirewallRule：读列表必须回退 netsh。
    否则对账会把所有 active 记录误判为「规则已不存在」。
    """
    monkeypatch.setattr(firewall, "_ps_cmdlet_missing", None)

    def fake_ps(script, timeout=30):
        return 1, "Get-NetFirewallRule : 无法将“Get-NetFirewallRule”项识别为 cmdlet…"

    monkeypatch.setattr(firewall, "_powershell", fake_ps)
    monkeypatch.setattr(firewall, "_run", lambda cmd, timeout=30: (0, NETSH_SHOW_OUTPUT))
    names = firewall.list_rule_names()
    assert names == [
        "PortGuard_Block_203.0.113.10_1700000000000_ab12",
        "PortGuard_Block_203.0.113.11_1700000000001_cd34",
    ]


def test_netsh_rule_list_ignores_description_text(monkeypatch):
    """描述里也写着 PortGuard，但不带 `_Block_` 前缀，不能被当成规则名"""
    text = NETSH_SHOW_OUTPUT + "描述:   PortGuard 封禁 203.0.113.10 - 2026-10-21 15:00 到期\n"
    monkeypatch.setattr(firewall, "_ps_cmdlet_missing", True)
    monkeypatch.setattr(firewall, "_run", lambda cmd, timeout=30: (0, text))
    assert len(firewall.list_rule_names()) == 2


def test_unblock_all_falls_back_to_netsh(monkeypatch):
    """一键解封同样要能在 2008 R2 上工作（PS 没有 cmdlet，netsh 支持通配符）"""
    seen = []

    def fake_run(cmd, timeout=30):
        seen.append(list(cmd))
        return 0, ""

    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    # block_ip 写入后会回读复核规则存在性；单测里防火墙是假的，直接放行
    monkeypatch.setattr(firewall, "rule_exists", lambda name: True)
    monkeypatch.setattr(firewall, "_ps_cmdlet_missing", True)
    monkeypatch.setattr(firewall, "_run", fake_run)
    monkeypatch.setattr(firewall, "_powershell", lambda script, timeout=30: (0, ""))

    ok, _n, err = firewall.unblock_all()
    assert ok and err == ""
    # unblock_all 会先 list_rule_names()（走的是 netsh show），所以只要挑出 delete 那条
    deletes = [c for c in seen if len(c) > 4 and c[3] == "delete"]
    assert deletes, f"没有发出 netsh delete：{seen}"
    assert deletes[0][:5] == ["netsh", "advfirewall", "firewall", "delete", "rule"]
    assert deletes[0][5] == f"name={firewall.RULE_PREFIX}*"


# --------------------------------------------------------------------------- #
# rule_exists 精确优先（P0-3：自动封禁热路径不得做全量枚举）
# --------------------------------------------------------------------------- #
def test_rule_exists_prefers_precise_query(monkeypatch):
    calls = {"list": 0}

    monkeypatch.setattr(
        firewall,
        "_run",
        lambda cmd, timeout=30: (0, "Rule Name:                         PortGuard_Block_1.2.3.4\n"),
    )

    def fake_list():
        calls["list"] += 1
        return []

    monkeypatch.setattr(firewall, "list_rule_names", fake_list)
    assert firewall.rule_exists("PortGuard_Block_1.2.3.4") is True
    # 正常命中路径不应做全量枚举（200~600ms 的 list_rule_names）
    assert calls["list"] == 0


def test_rule_exists_no_match_trusted(monkeypatch):
    calls = {"list": 0}
    monkeypatch.setattr(
        firewall, "_run", lambda cmd, timeout=30: (1, "No rules match the specified criteria.")
    )

    def fake_list():
        calls["list"] += 1
        return []

    monkeypatch.setattr(firewall, "list_rule_names", fake_list)
    assert firewall.rule_exists("PortGuard_Block_9.9.9.9") is False
    # 精确查询明确「无匹配」应被信任，不回退列表
    assert calls["list"] == 0


def test_rule_exists_falls_back_to_list_on_error(monkeypatch):
    calls = {"list": 0}

    def fake_run(cmd, timeout=30):
        raise RuntimeError("netsh 不可用")

    monkeypatch.setattr(firewall, "_run", fake_run)

    def fake_list():
        calls["list"] += 1
        return ["PortGuard_Block_1.2.3.4"]

    monkeypatch.setattr(firewall, "list_rule_names", fake_list)
    assert firewall.rule_exists("PortGuard_Block_1.2.3.4") is True
    # 精确查询异常 → 回退列表枚举一次
    assert calls["list"] == 1
