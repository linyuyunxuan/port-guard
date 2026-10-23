"""
PortGuard — 领域模型
所有对象均为轻量 dataclass，可安全地在后台线程中创建后投递给 UI 线程。
"""

import datetime
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar, Dict, List, Optional

from core.config import (
    LEVEL_CRITICAL,
    LEVEL_HIGH,
    LEVEL_LABEL,
    LEVEL_NORMAL,
    LEVEL_ORDER,
)


def now_ms() -> int:
    """当前 epoch 毫秒"""
    return int(time.time() * 1000)


def ms_to_str(ms: Optional[int]) -> str:
    """毫秒时间戳 -> 本地时间字符串"""
    if not ms:
        return "-"
    try:
        return datetime.datetime.fromtimestamp(ms / 1000).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "-"


def ms_to_short(ms: Optional[int]) -> str:
    """毫秒时间戳 -> 表格用短时间 `MM-DD HH:MM`

    19 字符的完整时间在 30px 行高里要占 153px（Consolas 12 + 内边距），
    1200 宽窗口下光时间列就要吃掉六分之一。列表只用来判断「什么时候」，
    年份与秒数在 tooltip 和详情对话框里仍然是完整的。
    """
    if not ms:
        return "-"
    try:
        return datetime.datetime.fromtimestamp(ms / 1000).strftime("%m-%d %H:%M")
    except Exception:
        return "-"


def ms_to_min(ms: Optional[int]) -> str:
    """毫秒时间戳 -> `YYYY-MM-DD HH:MM`（去掉秒，保留年份）

    封禁到期时间可以跨年（最长 365 天 / 也可以是永久），
    所以这里不能像事件列表那样省掉年份。
    """
    if not ms:
        return "-"
    try:
        return datetime.datetime.fromtimestamp(ms / 1000).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return "-"


# ═══════════════════════════════════════════════════════════
#  IP 归属地
# ═══════════════════════════════════════════════════════════


@dataclass
class GeoInfo:
    ip: str = ""
    country: str = ""
    province: str = ""
    city: str = ""
    isp: str = ""
    iso: str = ""
    found: bool = False

    @property
    def is_china(self) -> bool:
        return self.iso.upper() == "CN" or self.country == "中国"

    @property
    def display(self) -> str:
        """人类可读的一行归属地：中国·广东省·深圳市·电信"""
        if not self.found:
            return "未知"
        parts = [p for p in (self.country, self.province, self.city, self.isp) if p and p != "0"]
        return "·".join(parts) if parts else "未知"

    # 离线库里对保留 / 内网段的 country 字段是英文标记，列表里统一成中文短词，
    # 免得一列里中英混排（完整原文仍在 tooltip 的 display 里）
    _SPECIAL: ClassVar[Dict[str, str]] = {
        "reserved": "保留地址",
        "lan": "内网",
        "localhost": "本机",
        "loopback": "回环",
        "private": "内网",
    }

    @property
    def region_short(self) -> str:
        """表格用的紧凑归属地：广东省 深圳市（境外则为 国家 城市）"""
        if not self.found:
            return "未知"
        if self.is_china:
            # 去重：直辖市 / 特别行政区常出现「香港 香港」，省与市同名时只留一个
            parts = [p for p in (self.province, self.city) if p and p != "0"]
            if len(parts) == 2 and parts[0] == parts[1]:
                parts = parts[:1]
            return " ".join(parts) or "中国"
        country = self._SPECIAL.get(self.country.strip().lower(), self.country)
        city = self.city
        # 保留段常见「Reserved Reserved」：国家与城市同名时只留一个
        if city and city.lower() == self.country.strip().lower():
            city = ""
        label = " ".join(p for p in (country, city) if p and p != "0")
        # 境外长名（United States Fremont / Australia Brisbane）在表格里会吃掉 160px：
        # 列表只保证「哪个国家」可读，城市留给 tooltip 的完整 display
        if len(label) > 16 and country:
            label = country
        return label or country or "未知"

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)

    @staticmethod
    def from_json(s: Optional[str]) -> "GeoInfo":
        if not s:
            return GeoInfo()
        try:
            return GeoInfo(**json.loads(s))
        except Exception:
            return GeoInfo()


# ═══════════════════════════════════════════════════════════
#  访问记录
# ═══════════════════════════════════════════════════════════


@dataclass
class AccessRecord:
    ip: str = ""
    remote_port: Optional[int] = None
    local_port: int = 0
    protocol: str = "http"
    method: str = ""
    path: str = ""
    status_code: Optional[int] = None
    user_agent: str = ""
    size: int = 0  # 对外 JSON 字段名为 bytes
    host: str = ""
    server_name: str = ""
    tags: Dict[str, Any] = field(default_factory=dict)
    event_ts: int = field(default_factory=now_ms)

    # 运行期填充（不参与上报）
    id: Optional[int] = None
    geo: GeoInfo = field(default_factory=GeoInfo)
    risk_score: int = 0
    risk_level: str = LEVEL_NORMAL
    matched_rules: List[str] = field(default_factory=list)
    suggest_ban: bool = False
    #: 处置结论（见 DISPOSITION_*）。由 pipeline 在知道封禁状态后填，
    #: 实时监控据此显示「已放行 / 仅提醒 / 待确认 / 已拦截」。
    #: 只在内存里用，不写 access_log —— 访问日志记的是原始事实，
    #: 处置随封禁状态会变，落库会变成一份永远对不上的快照。
    disposition: str = ""

    @property
    def level_rank(self) -> int:
        return LEVEL_ORDER.get(self.risk_level, 0)

    @property
    def time_str(self) -> str:
        return ms_to_str(self.event_ts)

    @property
    def level_label(self) -> str:
        return LEVEL_LABEL.get(self.risk_level, self.risk_level)

    @property
    def matched_str(self) -> str:
        from core.rules_meta import rule_label

        return "、".join(rule_label(r) for r in self.matched_rules)


# ═══════════════════════════════════════════════════════════
#  处置结论（disposition）
# ═══════════════════════════════════════════════════════════

# 与 risk_event.handled 是**两个维度**，别混：
#   handled     = 人看过没有（未处理 / 已确认 / 已忽略）
#   disposition = 这条访问最终被怎么处理（放行 / 仅提醒 / 待确认 / 已拦截）
# 「已确认」与「仅提醒」可以同时成立 —— 用户知道了，但系统只提醒、没拦。
#
# 早先只有 handled，弹窗里只写「风险评分 20」，用户看不出「到底拦没拦」，
# 只能自己猜；有了这层，通知、事件表、上报响应体说的是同一句话。
DISPOSITION_ALLOW = "allow"
DISPOSITION_ALERT = "alert"
DISPOSITION_CONFIRM = "confirm"
DISPOSITION_BLOCK = "block"
DISPOSITION_IGNORED = "ignored"

DISPOSITION_LABEL = {
    DISPOSITION_ALLOW: "已放行",
    DISPOSITION_ALERT: "仅提醒",
    DISPOSITION_CONFIRM: "待确认",
    DISPOSITION_BLOCK: "已拦截",
    DISPOSITION_IGNORED: "已忽略",
}

#: 表格排序用（按处置力度，不按中文笔画）
DISPOSITION_ORDER = {
    DISPOSITION_ALLOW: 0,
    DISPOSITION_IGNORED: 1,
    DISPOSITION_ALERT: 2,
    DISPOSITION_CONFIRM: 3,
    DISPOSITION_BLOCK: 4,
}

#: 一句话解释，给弹窗与 tooltip 用。措辞里不带「可能」「建议」以外的模糊词 ——
#: 用户问的就是「到底拦没拦」，答「已拦截」就必须真有一条防火墙规则在生效。
DISPOSITION_HINT = {
    DISPOSITION_ALLOW: "命中白名单或区域放行规则，判定为正常访问",
    DISPOSITION_ALERT: "已记录并提醒，未做任何拦截",
    DISPOSITION_CONFIRM: "建议封禁，等待人工确认（尚未拦截）",
    DISPOSITION_BLOCK: "已写入防火墙规则，该 IP 的新连接会被阻断",
    DISPOSITION_IGNORED: "已人工忽略，不再提示",
}


def disposition_base(level: str, whitelisted: bool = False) -> str:
    """规则引擎用的基础结论：**只看判定结果**，不考虑该 IP 当前是否在封禁中"""
    # normal 表示「一条规则都没命中（或分数不到低危线）」—— 那就是正常放行，
    # 写「仅提醒」会让监控页刷满一屏「仅提醒」，等于噪声。
    if whitelisted or level == LEVEL_NORMAL:
        return DISPOSITION_ALLOW
    if level in (LEVEL_HIGH, LEVEL_CRITICAL):
        return DISPOSITION_CONFIRM
    return DISPOSITION_ALERT


def disposition_label(value: str) -> str:
    return DISPOSITION_LABEL.get(value, value or "-")


def disposition_of(row: Dict[str, Any]) -> str:
    """从一行记录（risk_event / access_log）取处置结论。

    新库直接读 `disposition` 列；升级前写入的老记录该列为空，按等级兜底：
    高/严重 = 待确认（当时确实没拦），其余 = 仅提醒。

    **不能**改用「该 IP 现在是否被封禁」来推：那会把上周只提醒过的记录
    显示成「已拦截」，与当时的事实不符，事后复盘时会误判处置是否及时。
    """
    d = str(row.get("disposition") or "")
    if d:
        return d
    if int(row.get("handled") or 0) == 2:
        return DISPOSITION_IGNORED
    return disposition_base(str(row.get("risk_level") or ""))


# ═══════════════════════════════════════════════════════════
#  风险判定结果
# ═══════════════════════════════════════════════════════════


@dataclass
class RiskResult:
    score: int = 0
    level: str = LEVEL_NORMAL
    matched_rules: List[str] = field(default_factory=list)
    suggest_ban: bool = False
    whitelisted: bool = False
    #: 端口白名单规则的「未命中即拦截」：pipeline 见到该标记就**不等
    #: auto_mode 开关**直接走自动封禁（管理员在规则里显式写了「其余拦截」，
    #: 就该按规则办事）。内网 / 本机保护（is_never_ban）依然生效。
    force_block: bool = False
    reason: str = ""
    #: 处置结论。引擎先填基础值，pipeline 在**知道封禁状态之后**可能改写为「已拦截」。
    disposition: str = ""

    @property
    def is_risk(self) -> bool:
        return self.score > 0 and not self.whitelisted

    @property
    def level_label(self) -> str:
        return LEVEL_LABEL.get(self.level, self.level)

    @property
    def disposition_label(self) -> str:
        """处置结论的中文文案（空值按等级兜底，避免漏填时界面出现空白）"""
        return (
            DISPOSITION_LABEL.get(self.disposition)
            or DISPOSITION_LABEL[disposition_base(self.level, self.whitelisted)]
        )


# ═══════════════════════════════════════════════════════════
#  封禁记录
# ═══════════════════════════════════════════════════════════

STATUS_PENDING = "pending"
STATUS_ACTIVE = "active"
STATUS_UNBANNED = "unbanned"
STATUS_FAILED = "failed"
STATUS_EXPIRED = "expired"

STATUS_LABEL = {
    STATUS_PENDING: "处理中",
    STATUS_ACTIVE: "已封禁",
    STATUS_UNBANNED: "已解封",
    STATUS_FAILED: "失败",
    STATUS_EXPIRED: "已到期",
}

SOURCE_LABEL = {
    "manual": "手动",
    "auto": "自动",
    "suggest": "建议",
}

#: risk_event.handled 的中文标签。放在模型层是因为 GUI 与 CSV 导出都要用同一套
#: 措辞 —— 各写一份的话改文案时必然只改一处，界面和导出文件就会对不上。
HANDLED_LABEL = {0: "未处理", 1: "已确认", 2: "已忽略"}


@dataclass
class BanRecord:
    id: Optional[int] = None
    ip: str = ""
    rule_name: str = ""
    reason: str = ""
    risk_score: int = 0
    source: str = "manual"
    status: str = STATUS_ACTIVE
    duration_sec: Optional[int] = None  # None = 永久
    expire_at: Optional[int] = None  # epoch 毫秒
    created_at: str = ""
    updated_at: str = ""
    error_msg: str = ""
    #: 谁解封的（v2 迁移加的列，长期为空是因为一直没有写入点；现在由审计
    #: 埋点统一填，口径见 app.audit.ACTOR_*）
    unblocked_by: str = ""
    #: 本次封禁期间又拦下该 IP 的次数（v5 迁移加的列）。
    #: 它回答的是「封了还在撞吗、撞了几次」—— 达到阈值就要升级成黑名单，
    #: 所以必须落库：进程一重启内存计数就归零，升级判断会永远差一口气。
    hit_count: int = 0
    #: 最近一次被拦下的时刻（epoch 毫秒）
    last_hit_at: Optional[int] = None

    @property
    def status_label(self) -> str:
        return STATUS_LABEL.get(self.status, self.status)

    @property
    def source_label(self) -> str:
        return SOURCE_LABEL.get(self.source, self.source)

    @property
    def duration_label(self) -> str:
        if not self.duration_sec:
            return "永久"
        s = int(self.duration_sec)
        if s % 86400 == 0:
            return f"{s // 86400} 天"
        if s % 3600 == 0:
            return f"{s // 3600} 小时"
        if s % 60 == 0:
            return f"{s // 60} 分钟"
        return f"{s} 秒"

    @property
    def expire_label(self) -> str:
        if self.status == STATUS_UNBANNED:
            return "-"
        if not self.expire_at:
            return "永久"
        return ms_to_str(self.expire_at)

    @property
    def expire_min(self) -> str:
        """表格用到期时间（`YYYY-MM-DD HH:MM`）；文字态（永久 / 已解封）原样保留"""
        if self.status == STATUS_UNBANNED:
            return "-"
        if not self.expire_at:
            return "永久"
        return ms_to_min(self.expire_at)

    @property
    def hit_label(self) -> str:
        """表格里跟在状态后面的拦截次数（`×3`），0 次返回空串。

        用 `×N` 而不是「拦截 3 次」：封禁记录表只有 1097px 的视口，
        每加一个字都要从「原因」列身上扣（见 gui/page_bans.py 的列宽注释）。
        `×N` 在本项目里已经是「同一件事重复 N 次」的既定写法
        （封禁建议的合并行就标 ×N），不另造一套。
        """
        n = int(self.hit_count or 0)
        return f"×{n}" if n > 0 else ""

    @property
    def hit_hint(self) -> str:
        """拦截次数的 tooltip：把 `×3` 说明白，并带上最近一次的时间"""
        n = int(self.hit_count or 0)
        if n <= 0:
            return "封禁期间没有再拦到该 IP 的访问"
        tail = f"，最近一次 {ms_to_str(self.last_hit_at)}" if self.last_hit_at else ""
        return f"封禁期间又拦下该 IP {n} 次访问{tail}"

    @property
    def created_min(self) -> str:
        """`created_at` 是库里的 `YYYY-MM-DD HH:MM:SS` 字符串，表格里去掉秒"""
        text = (self.created_at or "").strip()
        if len(text) >= 16 and text[4] == "-" and text[7] == "-":
            return text[:16]
        return text or "-"
