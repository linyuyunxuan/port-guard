"""PortGuard — 可选的外部告警推送（Webhook）

## 为什么需要

v1.2.0 删掉业务系统的 HTTP 上报时，把 Webhook 一起删了，于是告警只剩
「托盘气泡 + 声音」—— 这三种提醒都要求**有人正看着这台机器**。而封禁工具最需要
告警的场景恰恰是无人值守：半夜两点有人在爆破 3389，气泡八秒后就消失了，
第二天早上只剩一条风险事件记录。

所以这里补一条**可选**出口：把「严重」级别的告警推到一个 HTTP 地址上
（企业微信 / 钉钉群机器人、自建告警网关都吃这个格式）。

## 安全边界（这一段比功能本身重要）

v1.2.0 删网络上报的收益是「攻击面从全网收敛到本机输入」，这不能轻易还回去：

- **默认关闭**，地址留空即彻底不联网；
- 只允许 http/https，**拒绝指向本机 / 内网 / 保留地址**（防被改成 SSRF 探针
  去打内网服务）；单标签主机名也拒绝（靠 DNS 后缀补全的一定是内网）；
- 超时 5 秒、只发不收（不解析响应体），失败只写日志不重试；
- 地址里通常带 key，**日志与界面一律只显示 scheme+host**，不打印完整 URL；
- 推送在后台线程跑，不阻塞界面线程（告警是高频事件）。

## 与托盘告警的分工

`core/alerts.Alerter` 负责本地提醒（气泡 / 声音 / 弹窗），本模块只负责「送到
外面」。两者独立开关：可以只要气泡，也可以只要推送。
"""

import json
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlparse

from core import settings as cfg
from core.logger import get_logger
from core.models import DISPOSITION_BLOCK, DISPOSITION_LABEL
from core.xdb_updater import _is_private_host  # 复用同一套 SSRF 判定（内网/环回/保留）

log = get_logger(__name__)

#: 单次推送超时。告警要的是「尽快送到」，慢接口不该拖住后面的告警
TIMEOUT_SEC = 5.0
#: 同一 IP 的推送合并窗口（秒）。爆破时同一 IP 一分钟能命中几十次
THROTTLE_SEC = 60

#: 发送线程池（P2-3）。原来每条告警各起一个 daemon 线程：攻击洪峰下「每 IP
#: 每合并窗口一条」仍可能同时挂几十个线程各自等 5s 超时。两个线程 + 队列
#: 上限足够：合并窗口本身已把速率压到每 IP 60s 一条，池满时新任务排队，
#: 不会丢（futures 队列无界但被 THROTTLE_SEC 天然限速，不可能积压成灾）。
_POOL = ThreadPoolExecutor(max_workers=2, thread_name_prefix="alert-webhook")

# ── 成功/失败计数（P2-10 可观测性）──
# 「到底推出去没有」不能只靠翻日志：连续失败意味着接收端挂了，
# 而告警链路自己没有告警。诊断与测试读 stats() 即可。
_stats_lock = threading.Lock()
_stats: Dict[str, int] = {"sent_ok": 0, "sent_fail": 0, "scheduled": 0}


def stats() -> Dict[str, int]:
    """推送计数快照：scheduled=已安排发送，sent_ok/sent_fail=发送结果"""
    with _stats_lock:
        return dict(_stats)


#: 等级排序（与 core.models.LEVEL_ORDER 同口径，但这里只关心「够不够格推送」）
_LEVEL_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

#: 每个 IP 上次推送时间（模块级，进程内）
_last_sent: Dict[str, float] = {}
_lock = threading.Lock()


# ── 地址校验 ──


def mask_url(url: str) -> str:
    """只留 `scheme://host[:port]`，用于日志与界面提示（key 不能进日志）"""
    try:
        p = urlparse(url.strip())
    except Exception:
        return "(无法解析的地址)"
    if not p.scheme:
        return "(未配置)"
    host = p.hostname or ""
    port = f":{p.port}" if p.port else ""
    return f"{p.scheme}://{host}{port}/…"


def validate_url(url: str) -> Tuple[bool, str]:
    """校验推送地址；返回 (是否可用, 不可用原因)"""
    url = (url or "").strip()
    if not url:
        return False, "未填写推送地址"
    try:
        p = urlparse(url)
    except Exception:
        return False, "地址格式不正确"
    if p.scheme not in ("http", "https"):
        return False, "只支持 http / https 地址"
    if not p.hostname:
        return False, "地址里缺少主机名"
    if p.username or p.password:
        # 带账号密码的 URL 会被写进日志/审计，而且多数机器人不支持
        return False, "地址里不要带用户名密码（请把密钥放在路径里）"
    if _is_private_host(p.hostname):
        return False, "不允许指向本机 / 内网 / 保留地址（防止被用作内网探测）"
    return True, ""


# ── 消息构造 ──


def build_content(alert: Dict[str, Any]) -> str:
    """企业微信 / 钉钉群机器人都吃的纯文本消息体

    格式刻意用纯文本而不是 markdown：两家机器人的 markdown 方言不一样，
    而告警要的是「一眼看清谁、多严重、做了什么」，不需要排版。
    """
    level = str(alert.get("level") or "")
    level_cn = {"critical": "严重", "high": "高风险", "medium": "中风险", "low": "低风险"}.get(
        level, level or "未知"
    )
    disp = str(alert.get("disposition") or "")
    disp_cn = DISPOSITION_LABEL.get(disp, "") if disp else ""
    geo = alert.get("geo")
    lines = [
        f"【PortGuard】{level_cn}风险事件",
        f"来源 IP：{alert.get('ip') or '-'}",
    ]
    if geo is not None and getattr(geo, "found", False):
        lines.append(f"归属地：{getattr(geo, 'display', '') or '-'}")
    if alert.get("local_port"):
        lines.append(f"目标端口：{alert.get('local_port')}")
    lines.append(f"风险评分：{alert.get('score', '-')}")
    if alert.get("reason"):
        lines.append(f"命中规则：{alert.get('reason')}")
    if disp_cn:
        lines.append(f"处置：{disp_cn}" + ("（已自动拦截）" if disp == DISPOSITION_BLOCK else ""))
    lines.append(f"时间：{time.strftime('%Y-%m-%d %H:%M:%S')}")
    return "\n".join(lines)


def build_payload(alert: Dict[str, Any]) -> bytes:
    body = {"msgtype": "text", "text": {"content": build_content(alert)}}
    return json.dumps(body, ensure_ascii=False).encode("utf-8")


# ── 发送 ──


def post(url: str, payload: bytes, timeout: float = TIMEOUT_SEC) -> Tuple[bool, str]:
    """同步 POST（调用方负责放到后台线程）。不解析响应体，只看状态码"""

    req = urllib.request.Request(  # noqa: S310
        url,
        data=payload,
        headers={"Content-Type": "application/json; charset=utf-8"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            code = int(getattr(resp, "status", 0) or 0)
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except Exception as e:  # 网络不可达 / 超时 / TLS 失败
        return False, f"{type(e).__name__}: {e}"
    if not 200 <= code < 300:
        return False, f"HTTP {code}"
    return True, ""


def _settings() -> Dict[str, Any]:
    try:
        return {
            "enabled": cfg.get_bool("alert_webhook_enabled", False),
            "url": (cfg.get("alert_webhook_url", "") or "").strip(),
            "level": (cfg.get("alert_webhook_level", "critical") or "critical").strip(),
        }
    except Exception:
        log.exception("读取 Webhook 设置失败，按关闭处理")
        return {"enabled": False, "url": "", "level": "critical"}


def should_send(alert: Dict[str, Any], s: Optional[Dict[str, Any]] = None) -> bool:
    """该不该推：开关 / 地址 / 等级 / 合并窗口，四关都过才推"""
    s = s or _settings()
    if not s["enabled"] or not s["url"]:
        return False
    level = str(alert.get("level") or "")
    if _LEVEL_RANK.get(level, 0) < _LEVEL_RANK.get(str(s["level"]), 4):
        return False
    ip = str(alert.get("ip") or "")
    now = time.time()
    with _lock:
        last = _last_sent.get(ip, 0.0)
        if now - last < THROTTLE_SEC:
            return False
        # 先占坑再发：发送失败也不在窗口内重试，避免网络坏掉时刷屏
        _last_sent[ip] = now
        if len(_last_sent) > 512:  # 长期运行别让字典无限长
            for k in [k for k, t in _last_sent.items() if now - t > 3600]:
                _last_sent.pop(k, None)
    return True


def send_async(alert: Dict[str, Any]) -> bool:
    """按设置决定是否推送；实际发送在后台线程。返回「是否已安排发送」。

    必须在主线程调用（只读设置与内存节流表，很快），但**不会**等网络。
    """
    s = _settings()
    if not should_send(alert, s):
        return False
    ok, why = validate_url(s["url"])
    if not ok:
        log.warning("Webhook 地址不可用（%s）：%s", why, mask_url(s["url"]))
        return False

    url = s["url"]
    payload = build_payload(alert)
    masked = mask_url(url)

    def work() -> None:
        good, err = post(url, payload)
        with _stats_lock:
            _stats["sent_ok" if good else "sent_fail"] += 1
        if good:
            log.info("Webhook 已推送：%s ip=%s", masked, alert.get("ip"))
        else:
            log.warning("Webhook 推送失败：%s ip=%s %s", masked, alert.get("ip"), err)

    # 有界线程池代替「每条告警一个线程」（P2-3）：池满自动排队，
    # 异常在 work() 内部消化不会外溢
    with _stats_lock:
        _stats["scheduled"] += 1
    _POOL.submit(work)
    return True


def reset_throttle() -> None:
    """清空合并窗口（测试与「立即测试推送」用）"""
    with _lock:
        _last_sent.clear()
