"""
PortGuard — 规则元数据（规则名称、说明、默认参数）
UI 与核心共用，避免循环依赖。
"""

from typing import Any, Dict, List

# 规则 ID -> 中文名
RULE_LABELS = {
    "blacklist": "黑名单命中",
    "port_scan": "端口扫描",
    "sensitive_path_login": "敏感路径爆破",
    "geo_sensitive_port": "管理端口归属地检测",
    "rate_limit": "高频请求",
    "scanner_ua": "扫描器特征",
    "error_storm": "错误风暴",
    "suspicious_method": "异常 HTTP 方法",
    "large_body": "超大请求体",
}

# 规则 ID -> 说明
RULE_DESCS = {
    "blacklist": "来源 IP 命中人工维护的黑名单，直接判为严重风险",
    "port_scan": "同一 IP 在短时间内访问大量不同端口，疑似端口扫描",
    "sensitive_path_login": "对 /admin、/login 等敏感路径持续返回 401/403，疑似暴力破解",
    "geo_sensitive_port": "按归属地范围判断来源 IP 访问数据库、远程桌面等管理端口（可选境内 / 境外 / 双向）",
    "rate_limit": "同一 IP 在短时间内请求次数超过阈值，疑似压力攻击或爬虫",
    "scanner_ua": "User-Agent 为空或命中 Nmap/sqlmap 等已知扫描器特征",
    "error_storm": "短时间内 4xx/5xx 错误占比过高，疑似探测或探测型攻击",
    "suspicious_method": "使用了 TRACE/PUT/DELETE/CONNECT 等非常规方法",
    "large_body": "单次请求体超过阈值，可能为大流量攻击或异常上传",
}

# 规则 ID -> 该规则可编辑的参数（供 UI 自动生成表单）
#   key: 参数名, type: int/float/str/list, label: 中文标签
RULE_PARAMS: Dict[str, List[Dict[str, Any]]] = {
    "rate_limit": [
        {"key": "window_sec", "type": "int", "label": "统计窗口(秒)", "min": 1, "max": 3600},
        {"key": "threshold", "type": "int", "label": "请求次数阈值", "min": 1, "max": 100000},
    ],
    "port_scan": [
        {"key": "window_sec", "type": "int", "label": "统计窗口(秒)", "min": 1, "max": 3600},
        {"key": "distinct_ports", "type": "int", "label": "不同端口数阈值", "min": 2, "max": 65535},
    ],
    "sensitive_path_login": [
        {"key": "window_sec", "type": "int", "label": "统计窗口(秒)", "min": 1, "max": 3600},
        {"key": "threshold", "type": "int", "label": "失败次数阈值", "min": 1, "max": 10000},
    ],
    "geo_sensitive_port": [
        {"key": "ports", "type": "list_int", "label": "管理端口列表"},
        {
            "key": "geo_scope",
            "type": "choice",
            "label": "归属地范围",
            "options": [
                ("china", "仅限境内"),
                ("overseas", "仅限境外"),
                ("both", "境内+境外"),
            ],
        },
    ],
    "scanner_ua": [
        {"key": "patterns", "type": "list_str", "label": "扫描器特征(逗号分隔)"},
    ],
    "error_storm": [
        {"key": "window_sec", "type": "int", "label": "统计窗口(秒)", "min": 1, "max": 3600},
        {"key": "min_samples", "type": "int", "label": "最小样本数", "min": 1, "max": 100000},
        {"key": "error_ratio", "type": "float", "label": "错误占比(0~1)", "min": 0.0, "max": 1.0},
    ],
    "large_body": [
        {
            "key": "min_bytes",
            "type": "int",
            "label": "请求体阈值(字节)",
            "min": 1,
            "max": 1073741824,
        },
    ],
    "suspicious_method": [
        {"key": "methods", "type": "list_str", "label": "非常规方法(逗号分隔)"},
    ],
}


# 已废弃规则的旧 ID -> 名称。
# 历史记录（events.matched_rules）里存的是当时的 ID，UI 翻译时需要能认出来，
# 否则老事件会显示成一串英文 ID。
LEGACY_RULE_LABELS = {
    "foreign_sensitive_port": "境外访问管理端口（旧）",
}


def rule_label(rule_id: str) -> str:
    # 区域规则的 id 形如 region_allow:r-3f2a，这里解析成「区域放行：河南办公网」
    if rule_id.startswith(REGION_PREFIX) and ":" in rule_id:
        act, _, rid = rule_id[len(REGION_PREFIX) :].partition(":")
        return f"{REGION_ACTION_LABEL.get(act, '区域规则')}：{region_name(rid)}"
    return RULE_LABELS.get(rule_id) or LEGACY_RULE_LABELS.get(rule_id) or rule_id


# ═══════════════════════════════════════════════════════════
#  区域访问白名单规则（用户可手工增删）
# ═══════════════════════════════════════════════════════════

# 每条规则自己挑动作。2026-10-22 用户确认：
#   「放行」= 仅限所选区域通行，其他区域访问所选端口直接封禁（原 whitelist 语义合并进 allow）；
#   「判定风险」= 仅针对所选区域拦截，其他区域不受本规则影响。
#
# 2026-10-23 用户确认：独立维护的「黑名单 / 白名单」取消，统一由规则的
# 「拦截 / 放行」动作表达 —— 一个 IP 想直接拦住，就建一条命中它（IP/CIDR）
# 的「拦截」规则，不必再在两个名单框里各维护一份。于是新增 block：
#   block = 命中即直接拦截（评分 100 + 直接写防火墙），不看自动封禁开关与阈值；
#           与 allow 同时命中时 block 优先（安全侧优先，绝不因为"也配了放行"而漏拦）。
REGION_ACTIONS = [
    ("block", "拦截（命中即直接封禁：无视评分与自动封禁开关，立即写入防火墙）"),
    ("allow", "放行（仅限所选区域通行，其他区域访问所选端口直接拦截）"),
    (
        "suggest_ban",
        "判定风险（仅针对所选区域拦截：命中加分可生成封禁建议，其他区域不受本规则影响）",
    ),
    ("watch", "仅关注（不影响评分，只打标签留痕）"),
    ("downgrade", "降级（把已累计的风险分打到很低，仍留记录）"),
]
# 下拉框展示以上五个动作。whitelist 是「放行」的旧名（已合并进 allow），
# 仍可能在老 rules.json / 老事件里出现，必须保留为合法动作且翻译成放行，避免翻车。
REGION_ACTION_LABEL = {k: v.split("（", 1)[0] for k, v in REGION_ACTIONS}
REGION_ACTION_LABEL["whitelist"] = "放行"
REGION_ACTION_KEYS = ["block", "allow", "suggest_ban", "watch", "downgrade", "whitelist"]

REGION_PREFIX = "region_"

# 规则 id -> 用户起的名字。由 RuleEngine 每次编译配置后调用 register_region_rules 刷新，
# 这样 models.AccessRecord.matched_str 里的 rule_label() 才能翻译出中文名，
# 而不必让 models 反向依赖 rule_engine（会成环）。
_REGION_NAMES: Dict[str, str] = {}


def register_region_rules(rules) -> None:
    _REGION_NAMES.clear()
    for r in rules or []:
        if not isinstance(r, dict):
            continue
        rid = str(r.get("id") or "").strip()
        if rid:
            _REGION_NAMES[rid] = str(r.get("name") or rid).strip() or rid


def region_name(rule_id: str) -> str:
    return _REGION_NAMES.get(rule_id, rule_id)


def region_rule_key(action: str, rule_id: str) -> str:
    """命中标记：region_<action>:<id>"""
    return f"{REGION_PREFIX}{action}:{rule_id}"
