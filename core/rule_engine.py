"""
PortGuard — 规则引擎

- 规则读自 data/rules.json（UI 可编辑并热重载）
- 滑动窗口按「来源 IP」累积 (ts, local_port, path, status_code)
- 多规则命中分值累加，单条封顶 100，映射到风险等级
- 黑/白名单支持 IP 与 CIDR，白名单优先（命中即清零且不封禁）
"""
import ipaddress
import json
import os
import re
import threading
from collections import defaultdict, deque
from typing import Any, Dict, List, Optional

from core.config import (
    LEVEL_CRITICAL,
    LEVEL_HIGH,
    LEVEL_LOW,
    LEVEL_MEDIUM,
    LEVEL_NORMAL,
    NEVER_BAN_NETWORKS,
    blacklist_path,
    rules_path,
    whitelist_path,
)
from core.logger import get_logger
from core.models import AccessRecord, GeoInfo, RiskResult
from core.rules_meta import rule_label

log = get_logger(__name__)

# 滑动窗口最大保留时长（秒），超过此时间的记录可清理
_MAX_WINDOW = 300

# 单个 IP 窗口的硬上限（条）。
# 原实现只按时间裁剪，理论上某 IP 在 300 秒内打 10 万次请求就会让 deque
# 堆积 10 万条，此后每次 evaluate 都要遍历全部 → O(n²) 退化（DoS 面）。
# 加上上限后最坏情况被钉死。
_MAX_WINDOW_ITEMS = 5000


class _IPSet:
    """IP / CIDR 集合，支持快速成员判断"""

    def __init__(self, entries: Optional[List[str]] = None):
        self._exact: set = set()
        self._nets: List[Any] = []
        for e in (entries or []):
            self.add(e)

    def add(self, entry: str) -> bool:
        entry = (entry or "").strip()
        if not entry:
            return False
        try:
            if "/" in entry:
                self._nets.append(ipaddress.ip_network(entry, strict=False))
            else:
                self._exact.add(str(ipaddress.ip_address(entry)))
            return True
        except Exception:
            return False

    def __contains__(self, ip: str) -> bool:
        if not ip:
            return False
        if ip in self._exact:
            return True
        if not self._nets:
            return False
        try:
            addr = ipaddress.ip_address(ip)
        except Exception:
            return False
        return any(addr in net for net in self._nets)

    def __len__(self) -> int:
        return len(self._exact) + len(self._nets)

    def entries(self) -> List[str]:
        return sorted(self._exact) + [str(n) for n in self._nets]

    @classmethod
    def load_file(cls, path: str) -> "_IPSet":
        if not os.path.exists(path):
            return cls()
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            items = data.get("items", []) if isinstance(data, dict) else data
            return cls([str(x) for x in items])
        except Exception:
            log.exception("读取 IP 名单失败（按空名单处理）：%s", path)
            return cls()

    def save_file(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"items": self.entries()}, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)


# 与系统本地/内网/回环地址重合的网段：永不封禁
_NEVER_BAN = _IPSet(NEVER_BAN_NETWORKS)


def is_never_ban(ip: str) -> bool:
    return ip in _NEVER_BAN


DEFAULT_RULES = {
    "version": 1,
    "rules": {
        "blacklist": {"enabled": True, "score": 100, "level": "critical", "action": "suggest_ban"},
    },
}


class RuleEngine:
    def __init__(self, path: Optional[str] = None):
        self._lock = threading.Lock()
        self._path = path or rules_path()
        self._cfg: Dict = {}
        self._win: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=_MAX_WINDOW_ITEMS))
        self._last_prune = 0.0
        self._ua_re: List[re.Pattern] = []
        self._path_cfg: Dict[str, Any] = {"paths": [], "status": []}
        self.blacklist = _IPSet.load_file(blacklist_path())
        self.whitelist = _IPSet.load_file(whitelist_path())
        self.reload()

    # ── 配置加载 ──
    def reload(self) -> bool:
        cfg = None
        try:
            if os.path.exists(self._path):
                with open(self._path, encoding="utf-8") as f:
                    cfg = json.load(f)
        except Exception:
            log.exception("读取规则配置失败，回退内置默认规则：%s", self._path)
            cfg = None
        if not isinstance(cfg, dict) or "rules" not in cfg:
            log.warning("规则配置缺失或格式错误，使用内置默认规则")
            cfg = json.loads(json.dumps(DEFAULT_RULES))
        with self._lock:
            self._cfg = cfg
            self._compile()
        self.load_lists()
        return True

    def _compile(self) -> None:
        rules = self._cfg.get("rules", {})
        ua = rules.get("scanner_ua", {})
        self._ua_re = []
        for p in (ua.get("patterns") or []):
            try:
                self._ua_re.append(re.compile(re.escape(str(p)), re.I))
            except Exception:
                continue
        sp = rules.get("sensitive_path_login", {})
        self._path_cfg = {
            "paths": [str(x).lower() for x in (sp.get("paths") or [])],
            "status": [int(x) for x in (sp.get("status") or []) if str(x).isdigit()],
        }

    def load_lists(self) -> None:
        self.blacklist = _IPSet.load_file(blacklist_path())
        self.whitelist = _IPSet.load_file(whitelist_path())

    def save_lists(self) -> None:
        self.blacklist.save_file(blacklist_path())
        self.whitelist.save_file(whitelist_path())

    def get_config(self) -> Dict:
        with self._lock:
            return json.loads(json.dumps(self._cfg))

    def save_config(self, cfg: Dict) -> None:
        os.makedirs(os.path.dirname(self._path), exist_ok=True)
        tmp = self._path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self._path)
        with self._lock:
            self._cfg = cfg
            self._compile()

    def rule(self, rule_id: str) -> Dict:
        with self._lock:
            return dict(self._cfg.get("rules", {}).get(rule_id, {}))

    def rule_enabled(self, rule_id: str) -> bool:
        return bool(self.rule(rule_id).get("enabled", False))

    # ── 评估 ──
    def evaluate(self, rec: AccessRecord, geo: Optional[GeoInfo] = None) -> RiskResult:
        geo = geo or rec.geo or GeoInfo()
        ip = rec.ip
        now = rec.event_ts

        # 白名单优先
        if ip in self.whitelist:
            return RiskResult(score=0, level=LEVEL_NORMAL, matched_rules=[],
                              suggest_ban=False, whitelisted=True,
                              reason="命中白名单，已豁免")

        score = 0
        matched: List[str] = []

        with self._lock:
            rules = self._cfg.get("rules", {})
            dq = self._win[ip]
            dq.append((now, rec.local_port, (rec.path or "").lower(),
                       rec.status_code, rec.size))
            self._prune(dq, now)
            self._maybe_gc(now)

            # 1. 黑名单
            r = rules.get("blacklist", {})
            if r.get("enabled") and ip in self.blacklist:
                score += int(r.get("score", 100))
                matched.append("blacklist")

            # 2. 端口扫描
            r = rules.get("port_scan", {})
            if r.get("enabled"):
                win = int(r.get("window_sec", 30))
                ports = {t[1] for t in dq if now - t[0] <= win * 1000 and t[1]}
                if len(ports) >= int(r.get("distinct_ports", 15)):
                    score += int(r.get("score", 80))
                    matched.append("port_scan")

            # 3. 敏感路径爆破
            r = rules.get("sensitive_path_login", {})
            if r.get("enabled"):
                win = int(r.get("window_sec", 60))
                n = 0
                for t in dq:
                    if now - t[0] > win * 1000:
                        continue
                    path, st = t[2], t[3]
                    if not path or st not in self._path_cfg["status"]:
                        continue
                    if any(path.startswith(p) for p in self._path_cfg["paths"]):
                        n += 1
                if n >= int(r.get("threshold", 10)):
                    score += int(r.get("score", 70))
                    matched.append("sensitive_path_login")

            # 4. 境外访问管理端口（必须归属地命中且非中国，避免内网/保留地址误判）
            r = rules.get("foreign_sensitive_port", {})
            if r.get("enabled"):
                ports = {int(p) for p in (r.get("ports") or []) if str(p).isdigit()}
                if rec.local_port in ports and geo.found and not geo.is_china:
                    score += int(r.get("score", 65))
                    matched.append("foreign_sensitive_port")

            # 5. 高频请求
            r = rules.get("rate_limit", {})
            if r.get("enabled"):
                win = int(r.get("window_sec", 10))
                n = sum(1 for t in dq if now - t[0] <= win * 1000)
                if n >= int(r.get("threshold", 50)):
                    score += int(r.get("score", 60))
                    matched.append("rate_limit")

            # 6. 扫描器 UA
            r = rules.get("scanner_ua", {})
            if r.get("enabled"):
                ua = rec.user_agent or ""
                hit = bool(ua) and any(rx.search(ua) for rx in self._ua_re)
                if not hit and not ua and r.get("empty_ua", True):
                    hit = True
                if hit:
                    score += int(r.get("score", 45))
                    matched.append("scanner_ua")

            # 7. 错误风暴
            r = rules.get("error_storm", {})
            if r.get("enabled"):
                win = int(r.get("window_sec", 60))
                samples = [t for t in dq if now - t[0] <= win * 1000 and t[3]]
                if len(samples) >= int(r.get("min_samples", 20)):
                    errs = sum(1 for t in samples if t[3] >= 400)
                    if errs / len(samples) >= float(r.get("error_ratio", 0.7)):
                        score += int(r.get("score", 40))
                        matched.append("error_storm")

            # 8. 异常方法
            r = rules.get("suspicious_method", {})
            if r.get("enabled"):
                methods = {str(m).upper() for m in (r.get("methods") or [])}
                if rec.method and rec.method.upper() in methods:
                    score += int(r.get("score", 30))
                    matched.append("suspicious_method")

            # 9. 超大请求体
            r = rules.get("large_body", {})
            if r.get("enabled") and rec.size >= int(r.get("min_bytes", 5242880)):
                score += int(r.get("score", 25))
                matched.append("large_body")

        score = min(score, 100)
        level = self.level_of(score)
        suggest = level in (LEVEL_HIGH, LEVEL_CRITICAL) and ip not in self.whitelist
        reason = "命中规则：" + "、".join(rule_label(m) for m in matched) if matched else ""
        return RiskResult(score=score, level=level, matched_rules=matched,
                          suggest_ban=suggest, reason=reason)

    @staticmethod
    def level_of(score: int) -> str:
        if score >= 90:
            return LEVEL_CRITICAL
        if score >= 65:
            return LEVEL_HIGH
        if score >= 40:
            return LEVEL_MEDIUM
        if score >= 20:
            return LEVEL_LOW
        return LEVEL_NORMAL

    # ── 窗口维护 ──
    @staticmethod
    def _prune(dq: deque, now: int) -> None:
        limit = now - _MAX_WINDOW * 1000
        while dq and dq[0][0] < limit:
            dq.popleft()

    def _maybe_gc(self, now: int) -> None:
        """每 60 秒清理一次空闲 IP 的窗口，防止内存膨胀（调用方已持锁）"""
        if now - self._last_prune < 60000:
            return
        self._last_prune = now
        limit = now - _MAX_WINDOW * 1000
        dead = [ip for ip, dq in self._win.items() if not dq or dq[-1][0] < limit]
        for ip in dead:
            self._win.pop(ip, None)

    def window_size(self) -> int:
        with self._lock:
            return len(self._win)


# ── 全局单例 ──
_engine: Optional[RuleEngine] = None
_engine_lock = threading.Lock()


def get_engine() -> RuleEngine:
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = RuleEngine()
    return _engine


def set_engine(e: RuleEngine) -> None:
    global _engine
    _engine = e
