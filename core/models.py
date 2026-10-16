"""
PortGuard — 领域模型
所有对象均为轻量 dataclass，可安全地在后台线程中创建后投递给 UI 线程。
"""
import datetime
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

from core.config import LEVEL_LABEL, LEVEL_NORMAL, LEVEL_ORDER


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


def parse_timestamp(value: Any) -> int:
    """
    解析上报的 timestamp：兼容 epoch 毫秒(int)、epoch 秒(float)、ISO8601 字符串。
    解析失败则回退当前时间。
    """
    if value is None or value == "":
        return now_ms()
    if isinstance(value, (int, float)):
        v = float(value)
        # 小于 1e11 视为「秒」，否则视为「毫秒」
        return int(v * 1000) if v < 1e11 else int(v)
    s = str(value).strip()
    if s.isdigit():
        v = int(s)
        return v if v >= 1e11 else v * 1000
    try:
        s2 = s.replace("Z", "+00:00")
        dt = datetime.datetime.fromisoformat(s2)
        if dt.tzinfo is not None:
            return int(dt.timestamp() * 1000)
        # 无时区信息：按本地时间处理
        return int(dt.timestamp() * 1000)
    except Exception:
        return now_ms()


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

    @property
    def region_short(self) -> str:
        """表格用的紧凑归属地：广东省 深圳市（境外则为 国家 城市）"""
        if not self.found:
            return "未知"
        if self.is_china:
            parts = [p for p in (self.province, self.city) if p and p != "0"]
            return " ".join(parts) or "中国"
        parts = [p for p in (self.country, self.city) if p and p != "0"]
        return " ".join(parts) or self.country or "未知"

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
    size: int = 0                       # 对外 JSON 字段名为 bytes
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

    @staticmethod
    def from_payload(body: Dict[str, Any], ip: str) -> "AccessRecord":
        def _int(v):
            try:
                return int(v) if v is not None and v != "" else None
            except Exception:
                return None

        tags = body.get("tags") or {}
        if not isinstance(tags, dict):
            tags = {"raw": str(tags)}

        return AccessRecord(
            ip=ip,
            remote_port=_int(body.get("remote_port")),
            local_port=_int(body.get("local_port")) or 0,
            protocol=str(body.get("protocol") or "http").lower(),
            method=str(body.get("method") or "").upper(),
            path=str(body.get("path") or ""),
            status_code=_int(body.get("status_code")),
            user_agent=str(body.get("user_agent") or ""),
            size=_int(body.get("bytes")) or 0,
            host=str(body.get("host") or ""),
            server_name=str(body.get("server_name") or ""),
            tags=tags,
            event_ts=parse_timestamp(body.get("timestamp")),
        )

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
#  风险判定结果
# ═══════════════════════════════════════════════════════════

@dataclass
class RiskResult:
    score: int = 0
    level: str = LEVEL_NORMAL
    matched_rules: List[str] = field(default_factory=list)
    suggest_ban: bool = False
    whitelisted: bool = False
    reason: str = ""

    @property
    def is_risk(self) -> bool:
        return self.score > 0 and not self.whitelisted

    @property
    def level_label(self) -> str:
        return LEVEL_LABEL.get(self.level, self.level)


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


@dataclass
class BanRecord:
    id: Optional[int] = None
    ip: str = ""
    rule_name: str = ""
    reason: str = ""
    risk_score: int = 0
    source: str = "manual"
    status: str = STATUS_ACTIVE
    duration_sec: Optional[int] = None      # None = 永久
    expire_at: Optional[int] = None         # epoch 毫秒
    created_at: str = ""
    updated_at: str = ""
    error_msg: str = ""

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
