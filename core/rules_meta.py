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
    "foreign_sensitive_port": "境外访问管理端口",
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
    "foreign_sensitive_port": "非中国境内 IP 访问数据库、远程桌面等管理端口",
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
    "foreign_sensitive_port": [
        {"key": "ports", "type": "list_int", "label": "管理端口列表"},
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


def rule_label(rule_id: str) -> str:
    return RULE_LABELS.get(rule_id, rule_id)
