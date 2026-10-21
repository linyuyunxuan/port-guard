"""
PortGuard — Webhook 告警发送（纯函数层，无线程 / 无 Qt）

定位：一次 `send()` = 一次同步 HTTPS POST。**本模块不负责异步**，
调用方必须把它放到后台线程（见 `app/notify_service.py`）。

为什么拆出来单独一层：
- `core/alerts.py` 的 docstring 明确要求「必须由 Qt 主线程调用」，
  在告警链路上同步发 HTTP 会直接冻住界面；
- 发送逻辑与线程编排解耦后，签名 / 超时 / 错误归类都可以脱离线程单测。

交付栈约束（py3.8.10 + PySide2，目标 Server 2008 R2）：
- 没有 requests / httpx，只能用标准库 `urllib.request`；
- py3.8 的 `Request(data=...)` 只接受 `bytes`，body 必须显式 encode；
- 不能直接 `urlopen(url)`（ruff bandit S310），必须先构造 Request 再交给 opener；
- 代理策略与离线库同步同源（设置项 `xdb_proxy`），避免出现
  「离线库能下载、告警发不出去」的割裂。
"""

import contextlib
import hmac
import ipaddress
import json
import socket
import ssl
import time
import urllib.error
import urllib.request
from hashlib import sha256
from typing import Any, Dict, NamedTuple
from urllib.parse import urlparse

from core import xdb_updater
from core.config import APP_VERSION, LEVEL_ORDER
from core.logger import get_logger
from core.validators import InvalidURL, safe_https_url

log = get_logger(__name__)

#: 签名请求头：值形如 `sha256=<hex>`，对端用同一 secret 复算即可验真伪
SIG_HEADER = "X-PortGuard-Signature"
#: 发送时刻（epoch 毫秒），便于对端做重放窗口判断
TS_HEADER = "X-PortGuard-Timestamp"
CONTENT_TYPE = "application/json; charset=utf-8"
EVENT_TYPE = "alert"

DEFAULT_TIMEOUT_SEC = 10.0
MIN_TIMEOUT_SEC = 1.0
MAX_TIMEOUT_SEC = 30.0
DEFAULT_MAX_PER_MIN = 20
DEFAULT_MIN_LEVEL = "high"

_USER_AGENT = f"PortGuard/{APP_VERSION} (+webhook)"


class SendResult(NamedTuple):
    """发送结果。kind 用于 UI 给出针对性提示（尤其 ssl）"""

    ok: bool
    kind: str  # ok / invalid / timeout / ssl / http / network
    status: int
    message: str


def level_rank(level: Any) -> int:
    """风险级别 → 序号（与 core.alerts.Alerter._rank 同一口径）"""
    return LEVEL_ORDER.get(str(level or "").strip().lower(), 0)


def clamp_timeout(raw: Any) -> float:
    """超时夹到 [1, 30] 秒：太短会误判超时，太长会占住后台线程"""
    try:
        v = float(raw)
    except (TypeError, ValueError):
        return DEFAULT_TIMEOUT_SEC
    return max(MIN_TIMEOUT_SEC, min(MAX_TIMEOUT_SEC, v))


def _is_intranet_literal(host: str) -> bool:
    """主机是否是「内网 / 回环 / 链路本地」的 IP 字面量"""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False  # 域名无法证明它在内网，一律不放行
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local)


def validate_target(raw: Any, allow_http: bool = False) -> str:
    """
    校验 Webhook 地址。

    - 默认**强制 https**：告警内容含内网 IP、端口、归属地与命中规则，
      明文 http 在链路上可被直接读取，因此与离线库下载源共用同一道防线。
    - `allow_http=True`（设置项 webhook_allow_http）只放行**内网 IP 字面量**，
      域名不放行：域名既可能是公网主机，也可能被 DNS 指到内网任一地址。
    """
    s = "" if raw is None else str(raw).strip()
    if not s:
        raise InvalidURL("Webhook 地址不能为空")
    if len(s) > 500:
        raise InvalidURL("Webhook 地址过长")
    scheme = (urlparse(s).scheme or "").lower()
    if scheme != "http":
        # 非 http 一律走离线库下载源那套校验（强制 https / 无内嵌凭据 / 有主机名）
        return safe_https_url(s)

    if not allow_http:
        raise InvalidURL("Webhook 地址必须用 https；内网明文 http 请在设置里显式开启豁免")
    p = urlparse(s)
    host = p.hostname or ""
    if p.username or p.password:
        raise InvalidURL("Webhook 地址不允许内嵌凭据")
    if not _is_intranet_literal(host):
        raise InvalidURL(
            "明文 http 仅允许内网 IP 地址（如 http://10.0.0.5:8080/hook），域名一律拒绝"
        )
    return s


def build_payload(alert: Dict, host: str = "") -> Dict[str, Any]:
    """告警 → 对端收到的 JSON 结构（字段与 core.pipeline 投递的 alert 对齐）"""
    try:
        who = host or socket.gethostname()
    except Exception:
        who = ""
    return {
        "type": EVENT_TYPE,
        "ts": int(time.time() * 1000),  # epoch 毫秒，与项目其它时间字段一致
        "host": who,
        "ip": alert.get("ip", ""),
        "level": alert.get("level", ""),
        "score": alert.get("score", 0),
        "reason": alert.get("reason", ""),
        "geo": alert.get("geo", ""),
        "local_port": alert.get("local_port", 0),
        # 处置结论（allow/alert/confirm/block）：对端据此决定是否还要转发给
        # 值班人 —— 「已拦截」只是知会，「待确认」才需要人来看。
        # 只增字段不改老字段，老对接方按原样解析不受影响。
        "disposition": alert.get("disposition", ""),
    }


def encode_body(payload: Dict) -> bytes:
    """py3.8 的 Request(data=) 只吃 bytes，这里统一 encode"""
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def signature(body: bytes, secret: str) -> str:
    """HMAC-SHA256 签名（GitHub Webhook 风格：`sha256=<hex>`）"""
    digest = hmac.new(secret.encode("utf-8"), body, sha256).hexdigest()
    return "sha256=" + digest


def _ssl_context(verify: bool) -> ssl.SSLContext:
    """
    证书校验开关。关闭校验（webhook_verify_ssl=0）只应在排查
    「Server 2008 R2 自带 OpenSSL 不认对端 TLS1.3 / 新根证书」时临时使用，
    UI 上必须明示风险。
    """
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """不跟随 302：避免被重定向到内网其它地址（SSRF 兜底）"""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(
            req.full_url, code, f"Webhook 不允许跟随重定向（{code} → {newurl}）", headers, fp
        )


def _opener(verify_ssl: bool) -> urllib.request.OpenerDirector:
    handlers = []
    proxy = xdb_updater.proxy_handler()
    if proxy is not None:
        handlers.append(proxy)
    handlers.append(urllib.request.HTTPSHandler(context=_ssl_context(verify_ssl)))
    handlers.append(_NoRedirect())
    return urllib.request.build_opener(*handlers)


def _ssl_message(e: BaseException) -> str:
    return (
        f"TLS 握手失败：{e}。"
        "对端若使用 TLS1.3 或较新的根证书，Server 2008 R2 自带的 OpenSSL 可能不支持；"
        "可临时关闭证书校验确认，或改用内网 http 通道。"
    )


def _result_from(exc: BaseException) -> SendResult:
    """把异常归类成 SendResult.kind（SSL 单独成类，便于 UI 提示）"""
    if isinstance(exc, ssl.SSLError):
        return SendResult(False, "ssl", 0, _ssl_message(exc))
    if isinstance(exc, urllib.error.HTTPError):
        code = int(getattr(exc, "code", 0) or 0)
        return SendResult(False, "http", code, f"对端返回 HTTP {code}")
    if isinstance(exc, urllib.error.URLError):
        reason = getattr(exc, "reason", None)
        if isinstance(reason, BaseException):
            return _result_from(reason)
        return SendResult(False, "network", 0, f"网络不可达：{exc}")
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return SendResult(False, "timeout", 0, f"请求超时：{exc}")
    if isinstance(exc, OSError):
        return SendResult(False, "network", 0, f"网络错误：{exc}")
    return SendResult(False, "network", 0, f"发送失败：{exc}")


def send(
    url: Any,
    payload: Dict,
    secret: str = "",
    timeout: Any = DEFAULT_TIMEOUT_SEC,
    verify_ssl: bool = True,
    allow_http: bool = False,
) -> SendResult:
    """
    同步 POST 一条告警 JSON。**调用方负责放到后台线程。**

    成功判定：HTTP 2xx。其余情况都返回 ok=False，并用 kind 说明原因，
    便于上层决定「重试 / 放弃 / 提示用户」。
    """
    try:
        target = validate_target(url, allow_http=allow_http)
    except InvalidURL as e:
        return SendResult(False, "invalid", 0, str(e))

    body = encode_body(payload)
    headers = {
        "Content-Type": CONTENT_TYPE,
        "User-Agent": _USER_AGENT,
        "Accept": "*/*",
        TS_HEADER: str(int(time.time() * 1000)),
    }
    if secret:
        headers[SIG_HEADER] = signature(body, secret)

    # target 已在 validate_target() 里收敛成 https 或内网 http（无内嵌凭据、无 file: 等协议），
    # 这里仍按 S310 的要求显式构造 Request 再交给 opener
    req = urllib.request.Request(target, data=body, headers=headers, method="POST")  # noqa: S310
    try:
        resp = _opener(verify_ssl).open(req, timeout=clamp_timeout(timeout))
    except Exception as e:  # 统一归类：UI 要的是 kind，不是异常类型
        res = _result_from(e)
        log.debug("Webhook 发送失败 kind=%s：%s", res.kind, res.message)
        return res

    try:
        status = int(getattr(resp, "status", None) or resp.getcode() or 0)
        resp.read(4096)  # 读掉响应体，连接才能干净关闭
    except Exception:
        status = 0
    finally:
        with contextlib.suppress(Exception):
            resp.close()

    if 200 <= status < 300:
        return SendResult(True, "ok", status, "")
    return SendResult(False, "http", status, f"对端返回 HTTP {status}")
