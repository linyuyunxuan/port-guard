"""
PortGuard — 业务系统上报接收服务（FastAPI + 后台线程 uvicorn）

线程模型：uvicorn 在独立 daemon 线程里跑自己的 asyncio loop，
与 Qt 事件循环完全隔离。路由函数写成同步 def，FastAPI 会自动放到
线程池执行，因此不会阻塞事件循环。

处理链路：限流 → 鉴权 → 校验 IP → 归属地查询 → 规则评估 → 投递写入队列 → 投递给 UI。

安全基线（相对 v1.0.0 的收敛）：
- 默认只监听 127.0.0.1；监听非回环地址时**强制**要求 API Key
- 关闭 /docs、/redoc、/openapi.json（减少信息暴露面）
- CORS 默认不加；需要时按设置页白名单显式开启
- 每来源 IP 令牌桶限流 + 请求体大小上限
- 服务端直连场景不需要 CORS，`allow_origins=["*"]` 纯属多余风险

上报侧可信度（相对 v1.1.0 的收敛）：
- `timestamp`：与本机时间偏差超过 `report_max_ts_skew_sec` 时按本机时间计
  （它会驱动规则引擎的滑动窗口，可被伪造就等于规则失效）
- `ip`：仅可信来源（回环地址，或本次请求通过 API Key 校验）可覆盖 TCP 对端地址
"""

import contextlib
import errno
import ipaddress
import socket
import threading
import time
import traceback
from typing import Any, Dict, Optional

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core import settings as cfg
from core.config import (
    APP_VERSION,
    DEFAULT_LISTEN_HOST,
    DEFAULT_LISTEN_PORT,
    LOOPBACK_HOSTS,
)
from core.database import (
    find_active_ban_by_ip,
    init_db,
)
from core.db_writer import get_writer
from core.geo_locator import get_locator
from core.logger import get_logger, log_file, route_uvicorn_logs
from core.models import AccessRecord, GeoInfo, RiskResult, ThrottledWarning
from core.pipeline import process_record, result_payload
from core.ratelimit import TokenBucket
from core.rule_engine import get_engine
from core.validators import InvalidIP, normalize_ip

log = get_logger(__name__)

_server: Optional[uvicorn.Server] = None
_thread: Optional[threading.Thread] = None
_running = False
_host = DEFAULT_LISTEN_HOST
_port = DEFAULT_LISTEN_PORT
_start_error = ""
_start_error_cause = ""
_start_error_detail = ""
# 真实异常是否"什么都没说明"（uvicorn 绑定失败只抛 SystemExit(1)，不携带原因）
_start_error_bare = False
_generated_key = ""  # 对外监听时自动生成的 Key（用于提示用户）

# 限流桶：上报接口按来源 IP 计
_bucket = TokenBucket(rate=300.0, burst=600)

# 启动后等待「真正开始监听」的上限。正常情况下 uvicorn 在几十毫秒内就绪，
# 这个等待只在失败时才会跑满，用来把失败原因如实返回给界面。
_READY_TIMEOUT_MS = 5000


# ═══════════════════════════════════════════════════════════
#  启动失败诊断
# ═══════════════════════════════════════════════════════════

# 故障归因分类。之所以要分：以前界面不管什么原因都硬编码一句
# 「可能被占用或权限不足」，而真实原因可能和端口毫无关系
# （例如 uvicorn 的 formatter 配置异常），误导排障方向。
CAUSE_OCCUPIED = "occupied"
CAUSE_PERMISSION = "permission"
CAUSE_INTERNAL = "internal"
CAUSE_UNKNOWN = "unknown"

# Windows 的 WSAEADDRINUSE / WSAEACCES，以及类 Unix 的 errno
_OCCUPIED_CODES = {errno.EADDRINUSE, 10048, 98}
_PERMISSION_CODES = {errno.EACCES, errno.EPERM, errno.EADDRNOTAVAIL, 10013, 13, 1, 10049}


def _code_of(exc: BaseException) -> int:
    """取异常里的错误码（Windows 优先用 winerror）"""
    return int(getattr(exc, "winerror", 0) or getattr(exc, "errno", 0) or 0)


def _cause_of(exc: BaseException) -> str:
    """把异常归到一个可解释的原因上"""
    if isinstance(exc, OSError):
        code = _code_of(exc)
        if code in _OCCUPIED_CODES:
            return CAUSE_OCCUPIED
        if code in _PERMISSION_CODES:
            return CAUSE_PERMISSION
        return CAUSE_UNKNOWN
    return CAUSE_INTERNAL


def _hint_for(cause: str) -> str:
    """给用户一句话的下一步动作，而不是笼统地猜"""
    if cause == CAUSE_OCCUPIED:
        return (
            "该端口已被其它程序占用。可在设置页换一个端口；"
            f"或用 netstat -ano | findstr :{_port} 查出占用进程。"
        )
    if cause == CAUSE_PERMISSION:
        return (
            "系统拒绝绑定该端口。低于 1024 的端口需要管理员权限；"
            "也可能被系统保留段拦下（netsh http show urlacl 可查）。"
        )
    if cause == CAUSE_INTERNAL:
        return "这是程序内部错误，与端口占用、权限无关。完整堆栈已写入日志文件。"
    return "原因未知，完整堆栈已写入日志文件。"


def _record_start_error(exc: BaseException) -> None:
    """记录启动失败：给界面看的短信息 + 归因 + 完整堆栈"""
    global _start_error, _start_error_cause, _start_error_detail, _start_error_bare
    # uvicorn 绑定端口失败时走的是 sys.exit(STARTUP_FAILURE)，属于 BaseException
    # 而非 Exception —— 以前只 except Exception 会把它整个漏掉，结果是
    # 「界面显示已启动、实际没有任何监听」，比直接报错更难查。这种异常本身
    # 不携带原因，所以要靠预检结论补上。
    bare = isinstance(exc, SystemExit)
    _start_error_bare = bare
    if bare:
        _start_error = f"服务启动失败（uvicorn 退出码 {getattr(exc, 'code', None)}）"
    else:
        _start_error = f"{type(exc).__name__}: {exc}"
    _start_error_cause = CAUSE_INTERNAL if bare else _cause_of(exc)
    _start_error_detail = traceback.format_exc()


def _probe_bind(host: str, port: int) -> Optional[BaseException]:
    """
    预检：这个地址能不能绑定成功。

    与 uvicorn 的实际行为保持一致（Windows 下 asyncio 不会设 SO_REUSEADDR，
    两边都是朴素 bind），所以结论可靠。返回 None 表示可以绑定。
    """
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    try:
        s.bind((host, port))
        return None
    except OSError as e:
        return e
    finally:
        with contextlib.suppress(Exception):
            s.close()


def _wait_ready(timeout_ms: int = _READY_TIMEOUT_MS) -> bool:
    """
    等 uvicorn 真正开始监听。

    `Server.started` 是 uvicorn 在绑定+启动完成后置位的标志。超时但没出现
    任何错误时按「可能只是慢」处理（返回 True），避免在慢机器上误判失败。
    """
    if _server is None:
        return False
    deadline = time.monotonic() + timeout_ms / 1000
    while time.monotonic() < deadline:
        if _server.started:
            return True
        if _start_error:
            return False
        if _thread is not None and not _thread.is_alive():
            return False
        time.sleep(0.02)
    if not _server.started and not _start_error:
        log.warning("接收服务在 %d ms 内未报告就绪，按已启动继续（可能只是启动较慢）", timeout_ms)
    return True


def _peer_ip(request: Request) -> str:
    """TCP 对端地址（取不到时返回空串，由调用方决定是否拒绝）"""
    try:
        return (request.client.host if request.client else "") or ""
    except Exception:
        return ""


def _client_key(request: Request) -> str:
    """限流用的来源键。拿不到地址时归到 unknown，避免空串被当成合法 IP"""
    return _peer_ip(request) or "unknown"


def _is_loopback_source(host: str) -> bool:
    """
    来源是否为「可信来源」的回环判定：127.0.0.0/8 与 ::1。

    取不到来源、或来源不是 IP 字面量时按可信处理：那只可能发生在进程内直调
    ASGI（Starlette TestClient 给的就是 "testclient"）或 unix socket 场景，
    根本没有「远端主机」这一层，也就无所谓伪造来源。真实部署里 uvicorn 交给
    应用的 `client.host` 一定是 IP 字面量，不会走到这个兜底分支。
    """
    s = (host or "").strip()
    if not s:
        return True
    try:
        return bool(ipaddress.ip_address(s).is_loopback)
    except ValueError:
        return True


# 与时间戳纠偏共用同一套按秒去重，理由见 core.models 里的说明
_warn_ip_spoof = ThrottledWarning(
    log,
    "来源不可信，忽略上报 body 里的 ip %s，按 TCP 对端地址 %s 计",
)


# ═══════════════════════════════════════════════════════════
#  单条处理
# ═══════════════════════════════════════════════════════════


def _process(
    body: Dict[str, Any],
    fallback_ip: str,
    trusted_source: bool = False,
) -> Dict[str, Any]:
    """
    处理一条上报，返回判定结果。

    `trusted_source` —— 来源是否可信（回环地址，或本次请求的 API Key 校验通过）。
    只有可信来源才允许用 body 里的 `ip` 覆盖 TCP 对端地址，否则任何能访问到本服务
    的进程都能指定任意 IP：把风险分打给别人、或借自动封禁之手封掉别人。
    """
    raw_ip = body.get("ip") or ""
    override_allowed = trusted_source and cfg.get_bool("trust_reported_ip", True)
    if raw_ip and not override_allowed:
        _warn_ip_spoof.emit(raw_ip, fallback_ip or "(未知)")
        raw_ip = ""
    ip_raw = raw_ip or fallback_ip or ""
    try:
        ip = normalize_ip(ip_raw)
    except InvalidIP:
        raise HTTPException(status_code=400, detail=f"无效的 IP 地址: {ip_raw!r}") from None

    rec = AccessRecord.from_payload(body, ip)

    # 归属地 / 规则评估 / 落库 / UI 投递 / 告警 / 自动封禁 全部收在 core.pipeline，
    # 与「本机端口访问采集」共用同一条链路 —— 两条来源的结论必须一致。
    result = process_record(rec)
    return result_payload(rec, result)


def _auto_ban(rec: AccessRecord, result: RiskResult, geo: Optional[GeoInfo] = None) -> None:
    """
    自动封禁。

    实现已下沉到 core.pipeline.auto_ban_record（与「本机端口采集」共用），
    这里保留同名薄封装是因为 selftest / 历史调用点仍在用它。
    """
    from core.pipeline import auto_ban_record

    auto_ban_record(rec, result)


# ═══════════════════════════════════════════════════════════
#  FastAPI 应用
# ═══════════════════════════════════════════════════════════


def _make_app(api_key: str) -> FastAPI:
    # 关闭交互式文档与 OpenAPI：这是一个内部接收端点，不需要对外暴露接口清单
    app = FastAPI(
        title="PortGuard 上报接收服务",
        version=APP_VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # CORS：默认不加。业务系统是服务端直连，不需要 CORS；
    # 确需浏览器直连时，由用户在设置页填白名单域名。
    allow = [o.strip() for o in (cfg.get("cors_origins", "") or "").split(",") if o.strip()]
    if allow:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allow,
            allow_methods=["POST", "GET"],
            allow_headers=["Content-Type", "X-API-Key"],
        )
        log.info("已启用 CORS 白名单：%s", allow)

    def _check_key(key: Optional[str]) -> bool:
        """
        校验 API Key，返回「本次请求是否通过了真实的 Key 校验」。

        注意区分**放行**与**可信**：未配置 Key 时本服务照旧放行（内部网络部署下
        这是既定策略），但返回值是 False —— 没有凭据就不算可信来源，body 里的
        `ip` 不予采信。两者混为一谈的话，本机任意进程都能伪造来源 IP。
        """
        current = (api_key or cfg.get("api_key", "") or "").strip()
        if not current:
            return False
        if key != current:
            raise HTTPException(status_code=401, detail="API Key 无效")
        return True

    def _check_rate(request: Request) -> None:
        bucket_rate = cfg.get_int("rate_limit_per_sec", 300)
        if bucket_rate <= 0:
            return
        bucket_burst = cfg.get_int("rate_limit_burst", 600)
        if (_bucket.rate != float(bucket_rate)) or (_bucket.burst != int(bucket_burst)):
            _bucket.configure(bucket_rate, bucket_burst)
        if not _bucket.allow(_client_key(request)):
            raise HTTPException(status_code=429, detail="上报过于频繁，已被限流")

    @app.middleware("http")
    async def _body_limit(request: Request, call_next):
        """请求体上限：防止单请求把内存打爆"""
        max_mb = cfg.get_int("max_body_mb", 2)
        cl = request.headers.get("content-length")
        if cl and cl.isdigit() and max_mb > 0 and int(cl) > max_mb * 1024 * 1024:
            return JSONResponse(status_code=413, content={"detail": f"请求体超过 {max_mb} MB 上限"})
        return await call_next(request)

    @app.get("/api/v1/health")
    def health():
        w = get_writer()
        return {
            "status": "ok",
            "ts": int(time.time() * 1000),
            "version": APP_VERSION,
            "writer": w.stats() if w else None,
            "ratelimit": _bucket.stats(),
        }

    @app.get("/api/v1/version")
    def version():
        eng = get_engine()
        conf = eng.get_config().get("rules", {})
        enabled = sum(1 for v in conf.values() if v.get("enabled"))
        loc = get_locator()
        return {
            "app": "PortGuard",
            "version": APP_VERSION,
            "listen_host": _host,
            "listen_port": _port,
            "rules_enabled": enabled,
            "rules_total": len(conf),
            "geo_available": loc.available,
            "geo_library": loc.library_info(),
        }

    @app.post("/api/v1/access/report")
    def report(
        body: Dict[str, Any], request: Request, x_api_key: Optional[str] = Header(default=None)
    ):
        _check_rate(request)
        key_ok = _check_key(x_api_key)
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="请求体必须是 JSON 对象")
        fallback = _peer_ip(request)
        try:
            data = _process(body, fallback, trusted_source=key_ok or _is_loopback_source(fallback))
        except HTTPException:
            raise
        except Exception:
            log.exception("处理上报失败")
            raise HTTPException(status_code=500, detail="服务内部错误") from None
        return JSONResponse({"success": True, "data": data})

    @app.post("/api/v1/access/batch")
    def report_batch(
        body: Dict[str, Any], request: Request, x_api_key: Optional[str] = Header(default=None)
    ):
        _check_rate(request)
        key_ok = _check_key(x_api_key)
        items = body.get("items") if isinstance(body, dict) else None
        if not isinstance(items, list):
            raise HTTPException(status_code=400, detail="items 必须是数组")
        if len(items) > 1000:
            raise HTTPException(status_code=400, detail="单次最多上报 1000 条")
        fallback = _peer_ip(request)
        trusted = key_ok or _is_loopback_source(fallback)
        results, errors = [], []
        for i, item in enumerate(items):
            try:
                if isinstance(item, dict):
                    results.append(_process(item, fallback, trusted_source=trusted))
            except HTTPException as e:
                errors.append({"index": i, "error": e.detail})
            except Exception as e:
                log.exception("批处理第 %d 条失败", i)
                errors.append({"index": i, "error": str(e)})
        return JSONResponse(
            {
                "success": True,
                "data": {"accepted": len(results), "failed": len(errors), "errors": errors[:20]},
            }
        )

    @app.post("/api/v1/rules/reload")
    def rules_reload(x_api_key: Optional[str] = Header(default=None)):
        _check_key(x_api_key)
        get_engine().reload()
        log.info("规则配置已通过 API 热重载")
        return {"success": True, "data": {"reloaded": True}}

    @app.get("/api/v1/banned/{ip}")
    def is_banned(ip: str, x_api_key: Optional[str] = Header(default=None)):
        """供业务系统查询某 IP 当前是否处于封禁状态"""
        _check_key(x_api_key)
        try:
            safe_ip = normalize_ip(ip)
        except InvalidIP as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
        rec = find_active_ban_by_ip(safe_ip)
        return {
            "success": True,
            "data": {
                "ip": safe_ip,
                "banned": rec is not None,
                "reason": rec.reason if rec else "",
                "expire_at": rec.expire_at if rec else None,
            },
        }

    return app


# ═══════════════════════════════════════════════════════════
#  启停
# ═══════════════════════════════════════════════════════════


def _resolve_host() -> str:
    host = (cfg.get("listen_host", DEFAULT_LISTEN_HOST) or DEFAULT_LISTEN_HOST).strip()
    return host or DEFAULT_LISTEN_HOST


def _ensure_api_key(host: str, provided: str) -> str:
    """
    非回环监听时**强制**要求 API Key：没有就自动生成一个随机 Key。
    否则局域网任意主机都能伪造上报 → 打满分 → 借自动封禁之手封掉任意 IP。
    """
    global _generated_key
    key = (provided or cfg.get("api_key", "") or "").strip()
    if host not in LOOPBACK_HOSTS and not key:
        import secrets

        key = secrets.token_urlsafe(24)
        cfg.set("api_key", key)
        _generated_key = key
        log.warning(
            "服务监听非本机地址 %s 但未设置 API Key：已自动生成 %s "
            "（请把该 Key 配到业务系统上报请求头 X-API-Key）",
            host,
            key,
        )
    else:
        _generated_key = ""
    return key


def _finalize_failure(probe_err: Optional[BaseException]) -> None:
    """
    失败收尾：优先采信真实异常，其次是预检结论，都没有才给兜底文案。

    为什么不是简单地用预检结论：预检只是朴素 bind，理论上存在极小概率的
    误报；真实异常才是权威。但如果真实异常是 uvicorn 的 `SystemExit(1)`
    （它不携带任何原因），此时预检结论反而是唯一有信息量的线索。
    """
    global _start_error, _start_error_cause, _start_error_detail
    if not _start_error_bare and _start_error_cause in (CAUSE_OCCUPIED, CAUSE_PERMISSION):
        pass  # 已经有明确定论，不必再动
    elif _start_error_bare or not _start_error:
        if probe_err is not None:
            _start_error = f"{type(probe_err).__name__}: {probe_err}"
            _start_error_cause = _cause_of(probe_err)
            _start_error_detail = "".join(
                traceback.format_exception(type(probe_err), probe_err, probe_err.__traceback__)
            )
        else:
            if not _start_error:
                _start_error = "服务未能在超时时间内就绪"
            _start_error_cause = CAUSE_UNKNOWN

    log.error(
        "接收服务启动失败：%s | %s（日志：%s）",
        _start_error,
        _hint_for(_start_error_cause),
        log_file(),
    )


def start_server(port: Optional[int] = None, api_key: str = "") -> bool:
    global _server, _thread, _running, _port, _start_error, _host
    global _start_error_cause, _start_error_detail, _start_error_bare
    if _running:
        return True

    _start_error = ""
    _start_error_cause = ""
    _start_error_detail = ""
    _start_error_bare = False

    try:
        init_db()
        _port = int(port or cfg.get_int("listen_port", DEFAULT_LISTEN_PORT))
        _host = _resolve_host()
        key = _ensure_api_key(_host, api_key)

        _bucket.configure(
            cfg.get_int("rate_limit_per_sec", 300), cfg.get_int("rate_limit_burst", 600)
        )

        # 预检端口：把「被占用 / 权限不足」这类确定性失败提前到同步路径上，
        # 不用等 uvicorn 在后台线程里 sys.exit(1)（那个信号以前会被漏掉）
        probe_err = _probe_bind(_host, _port)

        app = _make_app(key)
        max_body = cfg.get_int("max_body_mb", 2)
        config = uvicorn.Config(
            app=app,
            host=_host,
            port=_port,
            log_level="warning",
            access_log=False,
            # 单次未完成事件的字节上限，兜住不带 Content-Length 的慢速大 body
            h11_max_incomplete_event_size=max(16 * 1024, max_body * 1024 * 1024),
            # ⚠️ 不能让 uvicorn 配置自己的日志：它的 DefaultFormatter 在构造时会执行
            # `sys.stdout.isatty()`，窗口化运行（pythonw / 打包后 console=False）下
            # std 流为 None，于是抛 AttributeError，被 dictConfig 包成
            # 「Unable to configure formatter 'default'」，服务根本起不来，
            # 而且报错和端口毫无关系、极易误导排障。日志统一交给 core.logger。
            log_config=None,
        )
        _server = uvicorn.Server(config)
        # 把 uvicorn 自己的日志接到 portguard 的 handler 上，避免排障时两头找
        route_uvicorn_logs()

        def run():
            import asyncio

            global _running
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(_server.serve())
            except BaseException as e:
                # 必须连 SystemExit 一起抓：uvicorn 绑定端口失败时走的就是
                # sys.exit(STARTUP_FAILURE)，它属于 BaseException 而非 Exception，
                # 以前只 except Exception 会把它整个吞掉 —— 结果是「界面显示已启动、
                # 实际没有任何监听」，比直接报错更糟。
                _record_start_error(e)
                log.exception("接收服务异常退出")
            finally:
                with contextlib.suppress(Exception):
                    loop.close()
                _running = False

        _thread = threading.Thread(target=run, daemon=True, name="portguard-api")
        _thread.start()

        if not _wait_ready():
            _running = False
            _finalize_failure(probe_err)
            return False

        _running = True
        log.info(
            "接收服务已启动：http://%s:%d（API Key %s，日志 %s）",
            _host,
            _port,
            "已启用" if key else "未启用",
            log_file(),
        )
        return True
    except Exception as e:
        _record_start_error(e)
        _running = False
        log.exception("接收服务启动失败：%s", _start_error)
        return False


def stop_server() -> None:
    global _running
    was_running = _running
    if _server:  # 只读引用，不需要 global 声明
        with contextlib.suppress(Exception):
            _server.should_exit = True
    _running = False
    if was_running:
        log.info("接收服务已收到停止指令（端口 %d）", _port)


def is_running() -> bool:
    return _running


def get_port() -> int:
    return _port


def get_host() -> str:
    return _host


def get_start_error() -> str:
    return _start_error


def get_start_error_cause() -> str:
    """启动失败的归因（occupied / permission / internal / unknown）"""
    return _start_error_cause


def get_start_error_hint() -> str:
    """给用户看的下一步动作建议（不是笼统猜测）"""
    if not _start_error_cause:
        return ""
    return _hint_for(_start_error_cause)


def get_start_error_detail() -> str:
    """完整堆栈（已同时写入日志文件）"""
    return _start_error_detail


def get_generated_key() -> str:
    """自动生成的 API Key（供 UI 提示用户复制）"""
    return _generated_key


def is_lan_exposed() -> bool:
    return _host not in LOOPBACK_HOSTS


def rate_limit_stats() -> dict:
    return _bucket.stats()
