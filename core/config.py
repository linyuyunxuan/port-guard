"""
PortGuard — 路径与全局常量
兼容「源码运行」与「PyInstaller 打包」两种形态：
  · 只读资源（xdb 库、assets、默认 rules.json）从 resource_path() 读取
  · 可写数据（数据库、用户规则、黑/白名单、日志、离线库）写入 user_data_dir()
"""

import os
import shutil
import sys
from typing import Dict, NamedTuple, Optional

APP_NAME = "PortGuard"
APP_TITLE = "PortGuard 端口访问防御工具"
APP_VERSION = "1.9.5"
#: 作者与联系方式。出现在三处，必须是同一个来源（core.config）：
#: 关于对话框、exe 文件属性（version_info.txt 由本文件同步）、README。
APP_AUTHOR = "林玉云轩"
APP_CONTACT = "1416161819"

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

#: 自动清理的保留期预设（天）。用户要的是「1 天 / 3 天 / 7 天」这种一句话
#: 就能选完的档位，而不是在四个 SpinBox 里逐个填 —— 预设一次写入四张表。
#: 「自定义」= 保留下方四项各自的取值，由用户自己调。
RETENTION_PRESETS: list = [1, 3, 7, 30, 90, 180]

#: 已封禁 IP 反复访问多少次后直接列入黑名单（永久）
DEFAULT_REPEAT_BLACKLIST_HITS = 5


# ═══════════════════════════════════════════════════════════
#  配置声明式 schema
#
#  目标：把「默认值（config.py）」与「取值范围（settings.py 的 _NUMERIC_RANGES）」
#  这两份各自维护的源合并到唯一一份 schema —— 每个键的类型 / 默认值 / 范围 /
#  可选枚举 / 中文说明集中登记在这里。settings.py 的数值读取（get_int / get_float）
#  直接读 schema 做解析 + clamp，不再重复手写范围。
# ═══════════════════════════════════════════════════════════


class SettingSpec(NamedTuple):
    """单个设置键的元数据声明。

    字段：
    - `type`: 存储值的目标类型，用于读取层解析。str 型也要登记（值为字符串）
      以便统一说明；int/float 型除默认值外还需 min/max 供 clamp。
    - `default`: 出厂默认值。**始终以字符串表示**（settings 表 value 是 TEXT，
      INSERT OR IGNORE 与 cfg.get(key, "str") 调用点都假定字符串）。
      尽量引用已有常量作为「来源真值」，避免复制数值。
    - `min` / `max`: 数值型键的合法闭区间（可省略，省略则读取层不 clamp）。
    - `choices`: 枚举型键的合法取值集合（可省略）。
    - `desc`: 中文说明，代替原来散落在 flat dict 各处的行尾注释。
    """

    type: str  # int / float / bool / str / json / map
    default: str
    min: Optional[float] = None
    max: Optional[float] = None
    choices: Optional[tuple] = None
    desc: str = ""


#: 封禁时长类的统一上限（秒），与 ban_service.MAX_BAN_SECONDS（365 天）对齐
_BAN_SEC_MIN = 0
_BAN_SEC_MAX = 365 * 86400


def build_settings_schema() -> Dict[str, SettingSpec]:
    """构建全量设置 schema。

    默认值 `default` 引用 `build_default_settings` 里用到的常量（来源真值），
    schema 化后这些常量仍是唯一数值来源。`rate_limit_per_sec` 不在
    DEFAULT_SETTINGS 里但历史上一直有 clamp，一并登记以保留行为。
    """
    ban_tier = BAN_DURATION_TIER_DEFAULTS
    return {
        # ── 封禁 ──
        "auto_mode": SettingSpec("int", "0", min=0, max=1, desc="1=自动封禁（默认关闭）"),
        "auto_ban_threshold": SettingSpec("int", "90", min=0, max=100, desc="自动封禁的最低风险分"),
        "default_ban_duration_sec": SettingSpec(
            "int",
            str(DEFAULT_BAN_DURATION_SEC),
            min=_BAN_SEC_MIN,
            max=_BAN_SEC_MAX,
            desc="手动封禁 / 策略兜底的默认封禁时长（秒），0=永久",
        ),
        # ── 封禁时长策略：按等级分档 ──
        # 分档只在「自动封禁 / 走策略」时生效，手动封禁仍以 default_ban_duration_sec 为默认值。
        # 0 = 该等级不分档，退回 default_ban_duration_sec。
        "ban_duration_critical_sec": SettingSpec(
            "int",
            str(ban_tier[LEVEL_CRITICAL]),
            min=_BAN_SEC_MIN,
            max=_BAN_SEC_MAX,
            desc="严重等级封禁时长（秒），0=不分档退回默认",
        ),
        "ban_duration_high_sec": SettingSpec(
            "int",
            str(ban_tier[LEVEL_HIGH]),
            min=_BAN_SEC_MIN,
            max=_BAN_SEC_MAX,
            desc="高危等级封禁时长（秒），0=不分档退回默认",
        ),
        "ban_duration_medium_sec": SettingSpec(
            "int",
            str(ban_tier[LEVEL_MEDIUM]),
            min=_BAN_SEC_MIN,
            max=_BAN_SEC_MAX,
            desc="中危等级封禁时长（秒），0=不分档退回默认",
        ),
        "ban_duration_low_sec": SettingSpec(
            "int",
            str(ban_tier[LEVEL_LOW]),
            min=_BAN_SEC_MIN,
            max=_BAN_SEC_MAX,
            desc="低危等级封禁时长（秒），0=不分档退回默认",
        ),
        # ── 封禁时长策略：重复封禁递增 ──
        "ban_escalation_enabled": SettingSpec(
            "int", "0", min=0, max=1, desc="1=同一 IP 再次被封时按倍数加长"
        ),
        "ban_escalation_factor": SettingSpec(
            "int",
            str(DEFAULT_ESCALATION_FACTOR),
            min=1,
            max=1000,
            desc="每次递增的倍数",
        ),
        "ban_escalation_max_sec": SettingSpec(
            "int",
            str(DEFAULT_ESCALATION_MAX_SEC),
            min=60,
            max=_BAN_SEC_MAX,
            desc="递增封顶（秒）",
        ),
        # ── 惯犯自动加固：已封禁 IP 反复访问 → 直接列入黑名单（永久）──
        "repeat_blacklist_enabled": SettingSpec(
            "int", "1", min=0, max=1, desc="1=惯犯自动加固开启"
        ),
        "repeat_blacklist_hits": SettingSpec(
            "int",
            str(DEFAULT_REPEAT_BLACKLIST_HITS),
            min=1,
            max=10000,
            desc="达到该次数直接列入黑名单",
        ),
        # ── 最大封禁时长（硬上限，秒）──
        "max_ban_duration_sec": SettingSpec(
            "int",
            str(MAX_BAN_DURATION_DEFAULT_SEC),
            min=60,
            max=_BAN_SEC_MAX,
            desc="所有有限时长的硬上限（秒），0=永久封禁不受此限",
        ),
        # ── 告警 ──
        "alert_sound": SettingSpec("int", "1", min=0, max=1, desc="1=告警时播放提示音"),
        # ⚠️ 已废弃（2026-10-27）：模态弹窗已取消，告警只走托盘气泡 + 声音 + 外部推送。
        "alert_popup_level": SettingSpec("str", LEVEL_CRITICAL, desc="已废弃，仅兼容旧库"),
        "alert_merge_sec": SettingSpec(
            "int",
            "60",
            min=0,
            max=86400,
            desc="同 IP 告警合并窗口（秒）",
        ),
        # ── 已拦截（该 IP 已在封禁名单中）的重复命中 ──
        "alert_block_silent": SettingSpec(
            "int",
            "1",
            min=0,
            max=1,
            desc="1=已拦截的重复命中静默（不弹窗、不气泡、不响铃）",
        ),
        # ── 外部告警推送（Webhook，默认关闭）──
        "alert_webhook_enabled": SettingSpec(
            "int", "0", min=0, max=1, desc="1=开启外部 Webhook 推送"
        ),
        "alert_webhook_url": SettingSpec("str", "", desc="Webhook 地址（含机器人 key）"),
        "alert_webhook_level": SettingSpec(
            "str",
            LEVEL_CRITICAL,
            desc="告警推送的最低等级",
        ),
        # ── 运行与守护 ──
        "autostart_enabled": SettingSpec(
            "int", "0", min=0, max=1, desc="1=开机自启（普通权限观察模式）"
        ),
        # ── 数据 ──
        "maintenance_enabled": SettingSpec("int", "1", min=0, max=1, desc="1=每天到点自动清理"),
        "log_retention_days": SettingSpec(
            "int",
            str(DEFAULT_LOG_RETENTION_DAYS),
            min=1,
            max=3650,
            desc="访问记录 + 日志文件的保留天数",
        ),
        "risk_retention_days": SettingSpec(
            "int",
            str(DEFAULT_RISK_RETENTION_DAYS),
            min=1,
            max=3650,
            desc="risk_event 保留天数",
        ),
        "ban_retention_days": SettingSpec(
            "int",
            str(DEFAULT_BAN_RETENTION_DAYS),
            min=1,
            max=3650,
            desc="ban_list 保留天数",
        ),
        "audit_retention_days": SettingSpec(
            "int",
            str(DEFAULT_AUDIT_RETENTION_DAYS),
            min=1,
            max=3650,
            desc="audit_log 保留天数",
        ),
        "maintenance_hour": SettingSpec(
            "int",
            "3",
            min=0,
            max=23,
            desc="每天几点执行定期清理（0-23）",
        ),
        "maintenance_last_date": SettingSpec(
            "str", "", desc="最近一次清理日期 YYYY-MM-DD（内部状态）"
        ),
        "log_level": SettingSpec("str", "INFO", desc="日志级别"),
        "geo_cache_size": SettingSpec(
            "int",
            "20000",
            min=1000,
            max=10_000_000,
            desc="IP 归属地缓存条数",
        ),
        "monitor_buffer_size": SettingSpec(
            "int",
            "5000",
            min=100,
            max=10_000_000,
            desc="实时监控环形缓冲行数",
        ),
        "db_batch_size": SettingSpec("int", "200", desc="批量写入攒批条数"),
        "db_flush_ms": SettingSpec("int", "200", desc="批量写入最大延迟（毫秒）"),
        # ── 本机端口访问观察（双通道采集）──
        "watch_enabled": SettingSpec("int", "0", min=0, max=1, desc="1=启动时自动开启本机端口观察"),
        "watch_ports": SettingSpec("str", "3389,1433,3306,6379,18080", desc="要观察的本机端口列表"),
        "watch_methods": SettingSpec(
            "str",
            "table,fwlog",
            desc="采集通道：table=TCP连接表 fwlog=防火墙日志",
        ),
        "watch_interval_sec": SettingSpec(
            "float",
            "5",
            min=1.0,
            max=86400.0,
            desc="采样间隔（秒）",
        ),
        "watch_dedupe_sec": SettingSpec(
            "int",
            "120",
            min=0,
            max=86400,
            desc="同一来源在多少秒内只上报一次",
        ),
        "watch_fwlog_path": SettingSpec("str", "", desc="防火墙日志路径，留空用系统默认位置"),
        "watch_resolve_pid": SettingSpec("int", "1", min=0, max=1, desc="1=尝试解析监听进程名"),
        "watch_skip_history": SettingSpec("int", "1", min=0, max=1, desc="1=启动时跳过历史日志"),
        "watch_auto_ban": SettingSpec("int", "0", min=0, max=1, desc="1=允许本机采集触发自动封禁"),
        # ── 程序内日志显示页 ──
        "log_view_max_lines": SettingSpec(
            "int",
            "2000",
            min=200,
            max=1_000_000,
            desc="日志页保留的最大行数",
        ),
        "log_view_tail_ms": SettingSpec(
            "int",
            "1000",
            min=200,
            max=3_600_000,
            desc="日志页刷新间隔（毫秒）",
        ),
        # ── 离线库在线同步 ──
        "xdb_auto_sync": SettingSpec("int", "1", min=0, max=1, desc="1=按间隔自动检查更新"),
        "xdb_sync_interval_hours": SettingSpec(
            "int",
            "24",
            min=1,
            max=8760,
            desc="自动检查间隔（小时）",
        ),
        "xdb_sync_on_start": SettingSpec("int", "1", min=0, max=1, desc="1=启动后后台检查一次"),
        "xdb_auto_download": SettingSpec(
            "int", "1", min=0, max=1, desc="1=发现新版本自动下载并热换"
        ),
        "xdb_sources": SettingSpec("json", "[]", desc="自定义镜像源（JSON 数组，空=只用内置源）"),
        "xdb_proxy": SettingSpec("str", "", desc="下载代理，留空=直连"),
        "xdb_last_check_at": SettingSpec("int", "0", desc="epoch 毫秒"),
        "xdb_last_update_at": SettingSpec("int", "0", desc="epoch 毫秒"),
        "xdb_last_result": SettingSpec("str", "", desc="最近一次同步结果摘要"),
        # ── 令牌桶限速（历史 clamp 键，不在 DEFAULT_SETTINGS 里）──
        "rate_limit_per_sec": SettingSpec(
            "int",
            "300",
            min=1,
            max=1_000_000,
            desc="令牌桶每秒补充令牌数",
        ),
    }


#: 进程内全局 schema（构建一次）。settings.py 读它做类型解析与 clamp；
#: 新增 / 调整键只改 build_settings_schema() 即可，默认值与范围天然一致。
SETTINGS_SCHEMA: Dict[str, SettingSpec] = build_settings_schema()


#: 只在 schema 里登记（供 clamp/解析）、但不写入 settings 表的键。
#: 目前仅 `rate_limit_per_sec`（令牌桶限速）：它没有出厂默认值，默认由调用方
#: 传（如 selftest.py cfg.get_int("rate_limit_per_sec", 300)），历史上只作为
#: 读取层的范围 clamp 存在，不属于 DEFAULT_SETTINGS 的 53 个落表键。
_SETTINGS_NO_SEED = {"rate_limit_per_sec"}


# ── 默认设置（写入 settings 表）──
def build_default_settings() -> Dict[str, str]:
    """由 schema 派生 flat-string 默认设置 dict。

    每个键的默认值取 `SettingSpec.default`（本就是字符串，直接落表 /
    供 `cfg.get(key, "str")` 使用），顺序即 schema 的登记顺序。
    跳过 `_SETTINGS_NO_SEED` 中登记的键（它们只参与 clamp，不落表）。
    这是 seeding（core/database.py:189 `for k, v in DEFAULT_SETTINGS.items()`）
    的唯一事实来源。
    """
    return {k: spec.default for k, spec in SETTINGS_SCHEMA.items() if k not in _SETTINGS_NO_SEED}


DEFAULT_SETTINGS: Dict[str, str] = build_default_settings()

# 预留常量：当前版本没有读取该环境变量，不要对外宣称「一键关联网」。
# 纯内网关闭出站同步的正式途径是设置页的三个开关：
# xdb_auto_sync / xdb_sync_on_start / xdb_auto_download（见 delivery/01_DEPLOY.txt）。
XDB_SYNC_DISABLED_ENV = "PORTGUARD_NO_UPDATE"
