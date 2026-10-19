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
from core.rules_meta import (
    REGION_ACTION_KEYS,
    region_rule_key,
    register_region_rules,
    rule_label,
)

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
        for e in entries or []:
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


def has_http_context(rec: AccessRecord) -> bool:
    """
    这条记录是否来自 HTTP 层。

    判据：协议是 http/https，或带了 HTTP 特有的 method / path。
    本机端口采集（core/port_watcher 的 TCP 表轮询与防火墙日志）产生的记录
    三者皆无 —— 它们描述的是"一次 TCP 连接/一个被丢弃的包"，不是一次 HTTP 请求。

    为什么必须区分：`scanner_ua` 规则里有「UA 为空即视为扫描器」这条启发式，
    对 HTTP 上报完全合理（正常人浏览器一定带 UA），但对 TCP 层采集是**必然误报**
    —— 每条自采记录都会白拿那 45 分，直接把分数抬到"中危"。
    """
    if (rec.protocol or "").lower() in ("http", "https"):
        return True
    return bool((rec.method or "").strip() or (rec.path or "").strip())


DEFAULT_RULES = {
    "version": 1,
    "rules": {
        "blacklist": {"enabled": True, "score": 100, "level": "critical", "action": "suggest_ban"},
    },
}

# 管理端口规则的归属地范围取值（与 rules_meta.RULE_PARAMS 里的 options 对应）
GEO_SCOPE_CHINA = "china"
GEO_SCOPE_OVERSEAS = "overseas"
GEO_SCOPE_BOTH = "both"
GEO_SCOPES = (GEO_SCOPE_CHINA, GEO_SCOPE_OVERSEAS, GEO_SCOPE_BOTH)


def geo_scope_hit(scope: Any, is_china: bool) -> bool:
    """
    归属地范围是否命中。

    1.x 版本这条规则叫「境外访问管理端口」，范围写死在代码里（非中国）；
    2.x 起范围变成可配置项，默认「仅限境内」——只监听本机的部署场景下，
    能打到管理端口的绝大多数是境内来源（境外 IP 基本到不了内网）。
    非法/缺省值一律按 china 处理，避免配错就把规则变成「对谁都不生效」。
    """
    s = str(scope or GEO_SCOPE_CHINA).strip().lower()
    if s == GEO_SCOPE_BOTH:
        return True
    if s == GEO_SCOPE_OVERSEAS:
        return not is_china
    return is_china


def _migrate_rules(cfg: Dict[str, Any]) -> bool:
    """
    把 1.x 的 `foreign_sensitive_port` 就地迁移成 `geo_sensitive_port`。

    返回值表示是否发生了迁移（供日志留痕）。已存在新 key 时不覆盖，
    只丢弃废弃的旧 key，避免两份配置同时生效产生双倍加分。
    """
    rules = cfg.get("rules")
    if not isinstance(rules, dict):
        return False
    old = rules.pop("foreign_sensitive_port", None)
    if not isinstance(old, dict):
        return False
    if "geo_sensitive_port" in rules:
        return True
    new = dict(old)
    new.pop("require_not_china", None)  # 1.x 的字段实际没被引擎读过，直接丢掉
    new.setdefault("geo_scope", GEO_SCOPE_CHINA)
    rules["geo_sensitive_port"] = new
    return True


class RuleEngine:
    def __init__(self, path: Optional[str] = None):
        self._lock = threading.Lock()
        self._path = path or rules_path()
        self._cfg: Dict = {}
        self._win: Dict[str, deque] = defaultdict(lambda: deque(maxlen=_MAX_WINDOW_ITEMS))
        self._last_prune = 0.0
        self._ua_re: List[re.Pattern] = []
        self._path_cfg: Dict[str, Any] = {"paths": [], "status": []}
        self._region_rules: List[Dict[str, Any]] = []
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
        if _migrate_rules(cfg):
            log.warning(
                "规则配置已从旧版 foreign_sensitive_port 迁移为 geo_sensitive_port"
                "（归属地范围默认=仅限境内），在规则页点「保存并生效」即落盘"
            )
        with self._lock:
            self._cfg = cfg
            self._compile()
        self.load_lists()
        return True

    def _compile(self) -> None:
        rules = self._cfg.get("rules", {})
        ua = rules.get("scanner_ua", {})
        self._ua_re = []
        for p in ua.get("patterns") or []:
            try:
                self._ua_re.append(re.compile(re.escape(str(p)), re.I))
            except Exception:
                continue
        sp = rules.get("sensitive_path_login", {})
        self._path_cfg = {
            "paths": [str(x).lower() for x in (sp.get("paths") or [])],
            "status": [int(x) for x in (sp.get("status") or []) if str(x).isdigit()],
        }
        self._region_rules = self._compile_region_rules(self._cfg.get("region_rules") or [])
        # 让 rules_meta 记住 id->名称，models.matched_str 才能把命中翻译成中文
        register_region_rules(self._region_rules)

    # ── 区域规则编译 ──
    @staticmethod
    def _as_str_list(match: Dict[str, Any], key: str) -> List[str]:
        """把 match 里的某个维度归一化成「去空、去重的字符串列表」"""
        v = match.get(key) or []
        if isinstance(v, str):
            v = [v]
        out: List[str] = []
        for x in v:
            s = str(x).strip()
            if s and s not in out:
                out.append(s)
        return out

    @classmethod
    def _compile_region_rules(cls, raw: Any) -> List[Dict[str, Any]]:
        """
        把 rules.json 里的 region_rules 预编译成便于逐条比对的结构。

        编译期就把 CIDR 解析成 ip_network 对象、把端口转成 int，
        避免每条上报都重复做字符串解析（热路径）。
        非法条目**跳过而不是抛错** —— 用户手改 JSON 写错一行，
        不该让整个规则引擎罢工。
        """
        out: List[Dict[str, Any]] = []
        if not isinstance(raw, list):
            return out
        for i, r in enumerate(raw):
            if not isinstance(r, dict):
                continue
            match = r.get("match")
            if not isinstance(match, dict):
                match = {}
            rid = str(r.get("id") or f"r{i + 1}").strip() or f"r{i + 1}"
            action = str(r.get("action") or "watch").strip().lower()
            if action not in REGION_ACTION_KEYS:
                log.warning("区域规则 %s 的动作 %r 不合法，按 watch 处理", rid, action)
                action = "watch"

            ports: List[int] = []
            for p in r.get("target_ports") or []:
                if str(p).strip().isdigit():
                    ports.append(int(str(p).strip()))

            nets: List[Any] = []
            for c in match.get("cidrs") or []:
                try:
                    nets.append(ipaddress.ip_network(str(c).strip(), strict=False))
                except ValueError:
                    log.warning("区域规则 %s 忽略非法网段 %r", rid, c)

            out.append(
                {
                    "id": rid,
                    "name": str(r.get("name") or rid).strip() or rid,
                    "enabled": bool(r.get("enabled", True)),
                    "action": action,
                    "ports": ports,
                    "factor": float(r.get("factor", 0.3) or 0.3),
                    "score": int(r.get("score", 90) or 90),
                    "provinces": cls._as_str_list(match, "provinces"),
                    "cities": cls._as_str_list(match, "cities"),
                    "countries": cls._as_str_list(match, "countries"),
                    "isps": cls._as_str_list(match, "isp"),
                    "nets": nets,
                    "ip_keywords": cls._as_str_list(match, "ip_keywords"),
                    # 归属地范围（单一维度，二选一）：
                    #   china    = 仅限境内（只有归属地确定为中国才命中）
                    #   overseas = 仅限境外（兼容旧的 not_china 字段，配置可平滑迁移）
                    #   ""       = 不限定
                    "geo_scope": (
                        "china"
                        if match.get("only_china", False)
                        else ("overseas" if match.get("not_china", False) else "")
                    ),
                }
            )
        return out

    @staticmethod
    def _text_hit(configured: List[str], actual: str) -> bool:
        """文本维度匹配：双向包含，兼容 '河南' / '河南省' 两种写法"""
        if not configured:
            return True
        a = (actual or "").strip()
        if not a:
            return False
        return any(c in a or a in c for c in configured)

    def _match_region_rules(self, rec: AccessRecord, geo: GeoInfo) -> List[Dict[str, Any]]:
        """返回所有命中的区域规则（保持配置顺序）"""
        hits: List[Dict[str, Any]] = []
        ip = (rec.ip or "").split("%", 1)[0]
        for r in self._region_rules:
            if not r["enabled"]:
                continue
            # 端口限定：留空表示对所有端口生效
            if r["ports"] and rec.local_port not in r["ports"]:
                continue
            # IP 维度（与归属地无关，可独立使用）
            if r["nets"]:
                try:
                    addr = ipaddress.ip_address(ip)
                except ValueError:
                    continue
                if not any(addr in n for n in r["nets"]):
                    continue
            if r["ip_keywords"] and not any(ip.startswith(k) for k in r["ip_keywords"]):
                continue
            # 归属地范围：境内 / 境外都必须「归属地已确定」才判定，
            # 未知（内网、保留地址、库未收录）既不当作境内，也不当作境外
            scope = r["geo_scope"]
            if scope == "china" and not (geo.found and geo.is_china):
                continue
            if scope == "overseas" and not (geo.found and not geo.is_china):
                continue

            geo_dims = r["provinces"] or r["cities"] or r["countries"] or r["isps"]
            ip_dims = r["nets"] or r["ip_keywords"] or bool(scope)
            # 一条什么维度都没配的规则等价于"匹配全部地址"，属于误配，直接不生效
            if not geo_dims and not ip_dims:
                continue
            if geo_dims:
                # 归属地未知时不猜测：宁可放过，也不能凭"不知道"就放行
                if not geo.found:
                    continue
                if not self._text_hit(r["provinces"], geo.province):
                    continue
                if not self._text_hit(r["cities"], geo.city):
                    continue
                if not self._text_hit(r["countries"], geo.country):
                    continue
                if not self._text_hit(r["isps"], geo.isp):
                    continue
            hits.append(r)
        return hits

    def region_rules(self) -> List[Dict[str, Any]]:
        with self._lock:
            return json.loads(json.dumps(self._region_rules, default=str))

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
            return RiskResult(
                score=0,
                level=LEVEL_NORMAL,
                matched_rules=[],
                suggest_ban=False,
                whitelisted=True,
                reason="命中白名单，已豁免",
            )

        # ── 区域规则：action=allow 优先级最高，命中即豁免 ──
        # 「河南/山西的 IP 可以访问某端口」就是靠这条短路实现的。
        region_hits = self._match_region_rules(rec, geo)
        for r in region_hits:
            if r["action"] == "allow":
                return RiskResult(
                    score=0,
                    level=LEVEL_NORMAL,
                    matched_rules=[region_rule_key("allow", r["id"])],
                    suggest_ban=False,
                    whitelisted=True,
                    reason=f"命中区域放行规则「{r['name']}」，已豁免",
                )

        score = 0
        matched: List[str] = []

        with self._lock:
            rules = self._cfg.get("rules", {})
            dq = self._win[ip]
            dq.append((now, rec.local_port, (rec.path or "").lower(), rec.status_code, rec.size))
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

            # 4. 管理端口归属地检测（必须归属地命中，避免内网/保留地址误判）
            r = rules.get("geo_sensitive_port", {})
            if r.get("enabled"):
                ports = {int(p) for p in (r.get("ports") or []) if str(p).isdigit()}
                if (
                    rec.local_port in ports
                    and geo.found
                    and geo_scope_hit(r.get("geo_scope"), geo.is_china)
                ):
                    score += int(r.get("score", 65))
                    matched.append("geo_sensitive_port")

            # 5. 高频请求
            r = rules.get("rate_limit", {})
            if r.get("enabled"):
                win = int(r.get("window_sec", 10))
                n = sum(1 for t in dq if now - t[0] <= win * 1000)
                if n >= int(r.get("threshold", 50)):
                    score += int(r.get("score", 60))
                    matched.append("rate_limit")

            # 6. 扫描器 UA
            #    「UA 为空」只在 HTTP 场景下才是有效信号，详见 has_http_context
            r = rules.get("scanner_ua", {})
            if r.get("enabled"):
                ua = rec.user_agent or ""
                hit = bool(ua) and any(rx.search(ua) for rx in self._ua_re)
                if not hit and not ua and r.get("empty_ua", True) and has_http_context(rec):
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

        # ── 区域规则（非放行类）：在常规评分之后叠加 / 调整 ──
        for r in region_hits:
            act = r["action"]
            matched.append(region_rule_key(act, r["id"]))
            if act == "suggest_ban":
                score += int(r["score"])

        # downgrade：多条同时命中时取最狠的那个系数（最低 factor）
        factors = [r["factor"] for r in region_hits if r["action"] == "downgrade"]
        if factors:
            factor = max(0.0, min([*factors, 1.0]))
            score = round(score * factor)

        score = min(score, 100)
        level = self.level_of(score)
        suggest = level in (LEVEL_HIGH, LEVEL_CRITICAL) and ip not in self.whitelist
        reason = "命中规则：" + "、".join(rule_label(m) for m in matched) if matched else ""
        return RiskResult(
            score=score, level=level, matched_rules=matched, suggest_ban=suggest, reason=reason
        )

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
