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
APP_VERSION = "1.1.0"

# 默认监听端口（避开 sql-api-manager 的 8090）
DEFAULT_LISTEN_PORT = 18080

# 默认监听地址：**只监听本机**。
# 需要局域网内其他主机上报时，由用户在设置页显式打开「允许局域网访问」，
# 届时程序会强制要求设置 API Key。把"暴露到网络"变成显式选择而非默认。
DEFAULT_LISTEN_HOST = "127.0.0.1"
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")

# 上报时间戳与本机时间的允许偏差（秒）：超出即以本机时间为准。
# 放在这里是为了让「配置默认值」与「代码兜底值」同源 —— settings 表读不到时
# （例如上报在 warm() 之前进来）用同一个数，不会出现两套口径。
DEFAULT_TS_SKEW_SEC = 300

# 「绑定所有网卡」的地址。集中在这里定义有两个目的：
#   1) 全项目只有这一处硬编码字面量，S104（bind-all-interfaces）单点豁免；
#   2) 默认值、设置页、安全检查共用同一常量，避免三处写法各自漂移。
WILDCARD_HOST = "0.0.0.0"  # noqa: S104 —— 唯一允许出现该字面量的地方
# 被视为「对所有网卡监听」的等价写法（含 IPv6 与通配符），供安全检测使用
BIND_ALL_HOSTS = (WILDCARD_HOST, "::", "*")

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


# ── 默认设置（写入 settings 表）──
DEFAULT_SETTINGS = {
    # 服务
    "listen_port": str(DEFAULT_LISTEN_PORT),
    "listen_host": DEFAULT_LISTEN_HOST,
    "api_key": "",
    "cors_origins": "",  # 逗号分隔白名单，留空=不加 CORS 中间件
    "rate_limit_per_sec": "300",  # 每个来源 IP 每秒允许的上报数
    "rate_limit_burst": "600",  # 桶容量（允许的瞬时突发）
    "max_body_mb": "2",  # 单次请求体上限（MB）
    "autostart_server": "0",  # 1=启动程序时自动开启接收服务
    # 上报来源可信度（详见 core.report_server._is_loopback_source）：
    # 1=仅可信来源（回环地址，或本次请求通过 API Key 校验）才采信 body 里的 ip；
    # 0=一律使用 TCP 对端地址，忽略 body 里的 ip
    "trust_reported_ip": "1",
    "report_max_ts_skew_sec": str(
        DEFAULT_TS_SKEW_SEC
    ),  # 上报 timestamp 与本机时间的最大偏差（秒），超出按本机时间计
    # 封禁
    "auto_mode": "0",  # 1=自动封禁（默认关闭）
    "auto_ban_threshold": "90",  # 自动封禁的最低风险分
    "default_ban_duration_sec": "3600",
    # 告警
    "alert_sound": "1",
    "alert_popup_level": LEVEL_CRITICAL,
    "alert_merge_sec": "60",  # 同 IP 告警合并窗口
    # 数据
    "log_retention_days": "30",  # 访问记录 + 日志文件的保留天数
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
    "xdb_source": "",  # 自定义镜像前缀，留空用内置源列表
    "xdb_proxy": "",  # 下载代理，留空=直连
    "xdb_last_check_at": "0",  # epoch 毫秒
    "xdb_last_update_at": "0",  # epoch 毫秒
    "xdb_last_result": "",  # 最近一次同步结果摘要
}

# 外部可关闭的联网行为（企业内网无出口时用环境变量一键关掉）
XDB_SYNC_DISABLED_ENV = "PORTGUARD_NO_UPDATE"
