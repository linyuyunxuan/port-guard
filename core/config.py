"""
PortGuard — 路径与全局常量
兼容「源码运行」与「PyInstaller 打包」两种形态：
  · 只读资源（xdb 库、assets、默认 rules.json）从 resource_path() 读取
  · 可写数据（数据库、用户规则、黑/白名单、日志、离线库）写入 user_data_dir()
"""

import os
import shutil
import sys

APP_NAME = "PortGuard"
APP_TITLE = "PortGuard 端口访问防御工具"
APP_VERSION = "1.4.2"

# ── 风险等级 ──
LEVEL_NORMAL = "normal"
LEVEL_LOW = "low"
LEVEL_MEDIUM = "medium"
LEVEL_HIGH = "high"
LEVEL_CRITICAL = "critical"

LEVEL_ORDER = {
    LEVEL_NORMAL: 0,
    LEVEL_LOW: 1,
    LEVEL_MEDIUM: 2,
    LEVEL_HIGH: 3,
    LEVEL_CRITICAL: 4,
}

LEVEL_LABEL = {
    LEVEL_NORMAL: "正常",
    LEVEL_LOW: "低",
    LEVEL_MEDIUM: "中",
    LEVEL_HIGH: "高",
    LEVEL_CRITICAL: "严重",
}

# ── 永远不允许封禁的网段 / 地址 ──
NEVER_BAN_NETWORKS = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
]

# ═══════════════════════════════════════════════════════════
#  离线 IP 库在线同步（ip2region xdb）
# ═══════════════════════════════════════════════════════════

# 上游仓库文件路径（用于元数据 API 与下载模板）
XDB_UPSTREAM = {
    "ip2region_v4.xdb": "data/ip2region_v4.xdb",
    "ip2region_v6.xdb": "data/ip2region_v6.xdb",
}

# 官方元数据接口：只取 sha/size，**不下载整个文件**即可判断是否有新版本
XDB_META_API = "https://api.github.com/repos/lionsoul2014/ip2region/contents/{path}"

# 下载源模板，按顺序尝试，任一成功即停止。
# 顺序考虑国内可达性：CDN → 官方 → 镜像 → Gitee。
XDB_SOURCE_TEMPLATES = [
    "https://cdn.jsdelivr.net/gh/lionsoul2014/ip2region@master/{path}",
    "https://raw.githubusercontent.com/lionsoul2014/ip2region/master/{path}",
    "https://ghproxy.net/https://raw.githubusercontent.com/lionsoul2014/ip2region/master/{path}",
    "https://gh-proxy.com/https://raw.githubusercontent.com/lionsoul2014/ip2region/master/{path}",
    "https://gitee.com/lionsoul/ip2region/raw/master/{path}",
]

# 下载源主机白名单：校验用户自定义源，杜绝被改成内网地址（SSRF）
XDB_ALLOWED_HOSTS = [
    "api.github.com",
    "cdn.jsdelivr.net",
    "raw.githubusercontent.com",
    "github.com",
    "objects.githubusercontent.com",
    "ghproxy.net",
    "gh-proxy.com",
    "mirror.ghproxy.com",
    "ghfast.top",
    "gitcode.com",
    "gitee.com",
    "cdn.statically.io",
]

XDB_DOWNLOAD_TIMEOUT = 60  # 单次下载/探测超时（秒）
XDB_MAX_FILE_MB = 128  # 单文件体积上限，防止被喂超大文件打爆磁盘


def _is_frozen() -> bool:
    return getattr(sys, "frozen", False)


def project_dir() -> str:
    """项目根目录（源码运行时为 port-guard/，打包后为 exe 所在目录）"""
    if _is_frozen():
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def resource_path(rel: str) -> str:
    """只读资源绝对路径。打包后指向 _MEIPASS 解压目录。"""
    base = getattr(sys, "_MEIPASS", project_dir()) if _is_frozen() else project_dir()
    return os.path.join(base, rel)


def user_data_dir() -> str:
    """可写数据目录。打包后使用 %APPDATA%/PortGuard，源码运行直接用 port-guard/data。"""
    if _is_frozen():
        base = os.path.join(os.environ.get("APPDATA", project_dir()), APP_NAME)
    else:
        base = os.path.join(project_dir(), "data")
    os.makedirs(base, exist_ok=True)
    return base


def ensure_data_file(rel_name: str) -> str:
    """
    保证可写目录下存在该文件：不存在时从只读资源目录首次拷贝一份。
    用于 xdb 库与默认 rules.json。
    """
    dst = os.path.join(user_data_dir(), rel_name)
    if not os.path.exists(dst):
        src = resource_path(os.path.join("data", rel_name))
        if os.path.exists(src):
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
    return dst


# ── 常用路径 ──
def db_path() -> str:
    return os.path.join(user_data_dir(), "port_guard.db")


def rules_path() -> str:
    return ensure_data_file("rules.json")


def blacklist_path() -> str:
    return os.path.join(user_data_dir(), "blacklist.json")


def whitelist_path() -> str:
    return os.path.join(user_data_dir(), "whitelist.json")


def v4_xdb_path() -> str:
    return ensure_data_file("ip2region_v4.xdb")


def v6_xdb_path() -> str:
    return ensure_data_file("ip2region_v6.xdb")


def xdb_path(name: str) -> str:
    return ensure_data_file(name)


def xdb_manifest_path() -> str:
    """离线库版本清单（记录 sha/sha256/大小/来源/时间）"""
    return os.path.join(user_data_dir(), "xdb_manifest.json")


def download_dir() -> str:
    """下载临时目录（与正式库同盘，保证 os.replace 是原子操作）"""
    d = os.path.join(user_data_dir(), "download")
    os.makedirs(d, exist_ok=True)
    return d


def backup_dir() -> str:
    """换库前的备份目录"""
    d = os.path.join(user_data_dir(), "backup")
    os.makedirs(d, exist_ok=True)
    return d


def logs_dir() -> str:
    d = os.path.join(user_data_dir(), "logs")
    os.makedirs(d, exist_ok=True)
    return d


def assets_path(rel: str) -> str:
    return resource_path(os.path.join("assets", rel))


# ═══════════════════════════════════════════════════════════
#  封禁时长策略（按风险等级分档 + 重复封禁递增）
#  解析优先级见 app.ban_service.resolve_duration：
#      规则级 > 递增级 > 等级级 > 默认
# ═══════════════════════════════════════════════════════════

#: 默认封禁时长（秒）。既是所有策略的兜底值，也是手动封禁的默认值
DEFAULT_BAN_DURATION_SEC = 3600

#: 按风险等级分档的默认时长（秒）。未列出的等级（normal）= 不分档，退回默认时长
BAN_DURATION_TIER_DEFAULTS = {
    LEVEL_CRITICAL: 86400,  # 24 小时
    LEVEL_HIGH: 21600,  # 6 小时
    LEVEL_MEDIUM: 7200,  # 2 小时
    LEVEL_LOW: 1800,  # 30 分钟
}

#: 递增倍数：同一 IP 每多一次历史封禁，时长乘以该值
DEFAULT_ESCALATION_FACTOR = 2
#: 递增封顶（秒）。必须 ≤ app.ban_service.MAX_BAN_SECONDS（365 天），
#: 否则 prepare() 里的 clamp_int 会静默截断 → 界面显示值与实际生效值不符
DEFAULT_ESCALATION_MAX_SEC = 7 * 24 * 3600

#: 最大封禁时长（秒）的出厂值：7 天。
#: 见 DEFAULT_SETTINGS["max_ban_duration_sec"] 的说明；界面按天展示。
MAX_BAN_DURATION_DEFAULT_SEC = 7 * 24 * 3600


# ═══════════════════════════════════════════════════════════
#  保留期（定期清理）
#
#  ⚠️ 三张派生/记账表各有各的保留期，**不要合并成一个**：
#  · access_log 是原始事实流水，最短（30 天）；
#  · risk_event 是规则算出的结论 —— 流水没了但结论还在，才会出现「这条访问
#    曾经被判严重风险、但流水查不到」的断档，所以它比流水留得更久（90 天）；
#  · ban_list  是封禁账本，只清终态记录，且它要回答「这个 IP 是不是惯犯」
#    （递增封禁靠它数历史次数），清太狠会让递增失效，故最长（180 天）；
#  · audit_log 是审计留痕，要能回溯一个季度（180 天）。
# ═══════════════════════════════════════════════════════════

DEFAULT_LOG_RETENTION_DAYS = 30
DEFAULT_RISK_RETENTION_DAYS = 90
DEFAULT_BAN_RETENTION_DAYS = 180
DEFAULT_AUDIT_RETENTION_DAYS = 180


# ── 默认设置（写入 settings 表）──
DEFAULT_SETTINGS = {
    # 封禁
    "auto_mode": "0",  # 1=自动封禁（默认关闭）
    "auto_ban_threshold": "90",  # 自动封禁的最低风险分
    "default_ban_duration_sec": "3600",
    # ── 封禁时长策略：按等级分档 ──
    # 分档只在「自动封禁 / 走策略」时生效，手动封禁仍以 default_ban_duration_sec 为默认值。
    # 0 = 该等级不分档，退回 default_ban_duration_sec。
    "ban_duration_critical_sec": str(BAN_DURATION_TIER_DEFAULTS[LEVEL_CRITICAL]),
    "ban_duration_high_sec": str(BAN_DURATION_TIER_DEFAULTS[LEVEL_HIGH]),
    "ban_duration_medium_sec": str(BAN_DURATION_TIER_DEFAULTS[LEVEL_MEDIUM]),
    "ban_duration_low_sec": str(BAN_DURATION_TIER_DEFAULTS[LEVEL_LOW]),
    # ── 封禁时长策略：重复封禁递增 ──
    "ban_escalation_enabled": "0",  # 1=同一 IP 再次被封时按倍数加长
    "ban_escalation_factor": str(DEFAULT_ESCALATION_FACTOR),  # 每次递增的倍数
    "ban_escalation_max_sec": str(DEFAULT_ESCALATION_MAX_SEC),  # 递增封顶（秒）
    # ── 最大封禁时长（硬上限，秒）──
    # 防火墙规则本身没有到期时间，到期完全靠程序内巡检删规则。程序长期不在时，
    # 「封一年」就等于永久封掉一个可能无辜的地址。所以所有**有限时长**都会被截断到
    # 这个值以内（app.ban_service.max_ban_seconds 是唯一读取点）。
    # ⚠️ 永久封禁（default_ban_duration_sec=0 / 黑名单）**不受此限**。
    "max_ban_duration_sec": str(MAX_BAN_DURATION_DEFAULT_SEC),
    # 告警
    "alert_sound": "1",
    "alert_popup_level": LEVEL_CRITICAL,
    "alert_merge_sec": "60",  # 同 IP 告警合并窗口
    # ── 外部告警推送（Webhook，默认关闭）──
    # 地址里通常带机器人 key，日志只记录 scheme://host（见 core/alert_webhook.py）
    "alert_webhook_enabled": "0",
    "alert_webhook_url": "",
    "alert_webhook_level": "critical",
    # 运行与守护
    # 开机自启：封禁时长只靠本程序的到点巡检兑现（防火墙规则没有到期时间），
    # 所以进程没了 = 到期的封禁永远不解除。默认关闭是因为本程序要管理员权限，
    # 开启后每次登录都会弹一次 UAC，得由用户自己权衡（7×24 服务器通常要开）。
    "autostart_enabled": "0",
    # 数据
    "log_retention_days": str(DEFAULT_LOG_RETENTION_DAYS),  # 访问记录 + 日志文件的保留天数
    # ── 其余三张表各自的保留期（见 DEFAULT_*_RETENTION_DAYS 说明）──
    "risk_retention_days": str(DEFAULT_RISK_RETENTION_DAYS),  # risk_event
    "ban_retention_days": str(DEFAULT_BAN_RETENTION_DAYS),  # ban_list（仅终态记录）
    "audit_retention_days": str(DEFAULT_AUDIT_RETENTION_DAYS),  # audit_log
    "maintenance_hour": "3",  # 每天几点执行定期清理（0-23）
    "maintenance_last_date": "",  # 最近一次清理日期 YYYY-MM-DD（内部状态）
    "log_level": "INFO",
    "geo_cache_size": "20000",
    "monitor_buffer_size": "5000",  # 实时监控环形缓冲行数
    "db_batch_size": "200",  # 批量写入攒批条数
    "db_flush_ms": "200",  # 批量写入最大延迟（毫秒）
    # ── 本机端口访问观察（双通道采集）──
    "watch_enabled": "0",  # 1=启动程序时自动开启本机端口观察
    "watch_ports": "3389,1433,3306,6379,18080",  # 要观察的本机端口列表
    "watch_methods": "table,fwlog",  # 采集通道：table=TCP连接表 fwlog=防火墙日志
    "watch_interval_sec": "5",  # 采样间隔（秒）
    "watch_dedupe_sec": "120",  # 同一来源在多少秒内只上报一次
    "watch_fwlog_path": "",  # 防火墙日志路径，留空用系统默认位置
    "watch_resolve_pid": "1",  # 1=尝试解析监听进程名（需要权限）
    "watch_skip_history": "1",  # 1=启动时跳过日志里的历史内容，避免洪水
    "watch_auto_ban": "0",  # 1=允许本机采集的数据触发自动封禁（默认关闭）
    # ── 程序内日志显示页 ──
    "log_view_max_lines": "2000",  # 日志页保留的最大行数
    "log_view_tail_ms": "1000",  # 日志页刷新间隔（毫秒）
    # 离线库在线同步
    "xdb_auto_sync": "1",  # 1=按间隔自动检查更新
    "xdb_sync_interval_hours": "24",  # 自动检查间隔（小时）
    "xdb_sync_on_start": "1",  # 1=启动后后台检查一次
    "xdb_auto_download": "1",  # 1=发现新版本自动下载并热换（全程校验+可回滚）
    # 自定义镜像源：JSON 数组，每项一个模板前缀（含 {path} 占位），按顺序优先尝试。
    # 空数组 = 只用内置源；旧的单条 xdb_source 仍会被读取并自动迁移过来。
    "xdb_sources": "[]",
    "xdb_proxy": "",  # 下载代理，留空=直连
    "xdb_last_check_at": "0",  # epoch 毫秒
    "xdb_last_update_at": "0",  # epoch 毫秒
    "xdb_last_result": "",  # 最近一次同步结果摘要
}

# 外部可关闭的联网行为（企业内网无出口时用环境变量一键关掉）
XDB_SYNC_DISABLED_ENV = "PORTGUARD_NO_UPDATE"
