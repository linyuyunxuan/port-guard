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
"""

import contextlib
import threading
import time
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
    insert_ban,
    update_ban,
)
from core.db_writer import get_writer
from core.event_bus import bus
from core.geo_locator import get_locator
from core.logger import get_logger
from core.models import STATUS_ACTIVE, AccessRecord, BanRecord, GeoInfo, RiskResult
from core.ratelimit import TokenBucket
from core.rule_engine import get_engine, is_never_ban
from core.validators import InvalidIP, normalize_ip

log = get_logger(__name__)

_server: Optional[uvicorn.Server] = None
_thread: Optional[threading.Thread] = None
_running = False
_host = DEFAULT_LISTEN_HOST
_port = DEFAULT_LISTEN_PORT
_start_error = ""
_generated_key = ""  # 对外监听时自动生成的 Key（用于提示用户）

# 限流桶：上报接口按来源 IP 计
_bucket = TokenBucket(rate=300.0, burst=600)


def _client_key(request: Request) -> str:
    try:
        return (request.client.host if request.client else "") or "unknown"
    except Exception:
        return "unknown"


# ═══════════════════════════════════════════════════════════
#  单条处理
# ═══════════════════════════════════════════════════════════


def _process(body: Dict[str, Any], fallback_ip: str) -> Dict[str, Any]:
    """处理一条上报，返回判定结果"""
    raw_ip = body.get("ip") or fallback_ip or ""
    try:
        ip = normalize_ip(raw_ip)
    except InvalidIP:
        raise HTTPException(status_code=400, detail=f"无效的 IP 地址: {raw_ip!r}") from None

    rec = AccessRecord.from_payload(body, ip)

    # 1. 归属地（整库入内存，微秒级）
    geo = get_locator().lookup(ip)
    rec.geo = geo

    # 2. 规则评估
    engine = get_engine()
    result = engine.evaluate(rec, geo)
    rec.risk_score = result.score
    rec.risk_level = result.level
    rec.matched_rules = result.matched_rules
    rec.suggest_ban = result.suggest_ban

    # 3. 投递落库（非阻塞：入队即返回，由单写线程批量提交）
    writer = get_writer()
    if result.is_risk:
        # 风险条目：访问日志 + 风险事件在同一事务内写入并关联 access_id
        writer.submit_risk(rec, result)
    else:
        writer.submit_access(rec)

    # 4. 投递给 UI（实时监控）
    bus.emit_access(rec)

    # 5. 风险事件后续处理
    if result.is_risk:
        bus.emit_risk({"record": rec, "result": result})

        bus.emit_alert(
            {
                "ip": ip,
                "level": result.level,
                "score": result.score,
                "reason": result.reason or "命中风险规则",
                "geo": geo.display,
                "local_port": rec.local_port,
            }
        )

        # 自动封禁模式（默认关闭）
        if (
            result.suggest_ban
            and cfg.get_bool("auto_mode", False)
            and result.score >= cfg.get_int("auto_ban_threshold", 90)
        ):
            _auto_ban(rec, result, geo)

    return {
        "id": None,
        "ip": ip,
        "geo": geo.display,
        "risk_score": result.score,
        "risk_level": result.level,
        "matched_rules": result.matched_rules,
        "suggest_ban": result.suggest_ban,
    }


def _auto_ban(rec: AccessRecord, result: RiskResult, geo: GeoInfo) -> None:
    """自动模式：无需人工确认直接封禁（默认关闭）"""
    from core.firewall import block_ip

    if is_never_ban(rec.ip):
        return
    duration = cfg.get_int("default_ban_duration_sec", 3600)
    expire = int(time.time() * 1000) + duration * 1000
    rec_ban = BanRecord(
        ip=rec.ip,
        reason=f"[自动] {result.reason}",
        risk_score=result.score,
        source="auto",
        status="pending",
        duration_sec=duration,
        expire_at=expire,
    )
    try:
        ban_id = insert_ban(rec_ban)
    except Exception:
        log.exception("自动封禁：写入 pending 记录失败 ip=%s", rec.ip)
        ban_id = None
    ok, name, err = block_ip(rec.ip, duration, note=result.reason)
    if ban_id:
        try:
            update_ban(
                ban_id, status=(STATUS_ACTIVE if ok else "failed"), rule_name=name, error_msg=err
            )
        except Exception:
            log.exception("自动封禁：回填记录失败 ban_id=%s", ban_id)
    if ok:
        log.warning("自动封禁生效 ip=%s rule=%s score=%d", rec.ip, name, result.score)
    else:
        log.error("自动封禁失败 ip=%s err=%s", rec.ip, err)
    bus.emit_ban(
        {
            "ip": rec.ip,
            "ok": ok,
            "rule_name": name,
            "error": err,
            "source": "auto",
            "ban_id": ban_id,
            "auto": True,
        }
    )


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

    def _check_key(key: Optional[str]) -> None:
        current = (api_key or cfg.get("api_key", "") or "").strip()
        if current and key != current:
            raise HTTPException(status_code=401, detail="API Key 无效")

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
        _check_key(x_api_key)
        if not isinstance(body, dict):
            raise HTTPException(status_code=400, detail="请求体必须是 JSON 对象")
        fallback = request.client.host if request.client else ""
        try:
            data = _process(body, fallback)
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
        _check_key(x_api_key)
        items = body.get("items") if isinstance(body, dict) else None
        if not isinstance(items, list):
            raise HTTPException(status_code=400, detail="items 必须是数组")
        if len(items) > 1000:
            raise HTTPException(status_code=400, detail="单次最多上报 1000 条")
        fallback = request.client.host if request.client else ""
        results, errors = [], []
        for i, item in enumerate(items):
            try:
                if isinstance(item, dict):
                    results.append(_process(item, fallback))
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


def start_server(port: Optional[int] = None, api_key: str = "") -> bool:
    global _server, _thread, _running, _port, _start_error, _host
    if _running:
        return True
    try:
        init_db()
        _port = int(port or cfg.get_int("listen_port", DEFAULT_LISTEN_PORT))
        _host = _resolve_host()
        key = _ensure_api_key(_host, api_key)

        _bucket.configure(
            cfg.get_int("rate_limit_per_sec", 300), cfg.get_int("rate_limit_burst", 600)
        )

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
        )
        _server = uvicorn.Server(config)

        def run():
            import asyncio

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(_server.serve())
            except Exception as e:
                global _start_error
                _start_error = str(e)
                log.exception("接收服务异常退出")

        _thread = threading.Thread(target=run, daemon=True, name="portguard-api")
        _thread.start()
        _running = True
        _start_error = ""
        log.info(
            "接收服务已启动：http://%s:%d（API Key %s）",
            _host,
            _port,
            "已启用" if key else "未启用",
        )
        return True
    except Exception as e:
        _start_error = str(e)
        _running = False
        log.exception("接收服务启动失败")
        return False


def stop_server() -> None:
    global _running
    if _server:  # 只读引用，不需要 global 声明
        with contextlib.suppress(Exception):
            _server.should_exit = True
    _running = False


def is_running() -> bool:
    return _running


def get_port() -> int:
    return _port


def get_host() -> str:
    return _host


def get_start_error() -> str:
    return _start_error


def get_generated_key() -> str:
    """自动生成的 API Key（供 UI 提示用户复制）"""
    return _generated_key


def is_lan_exposed() -> bool:
    return _host not in LOOPBACK_HOSTS


def rate_limit_stats() -> dict:
    return _bucket.stats()
