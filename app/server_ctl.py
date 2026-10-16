"""
PortGuard — 上报服务启停编排（不依赖 Qt）

把「读设置 → 解析监听地址 → 处理 Key → 启停 → 组装提示文案」集中在这里，
界面层只负责把 message 丢到状态栏。
"""

from typing import Dict, Optional, Tuple

from core import report_server
from core import settings as cfg
from core.config import DEFAULT_LISTEN_PORT, LOOPBACK_HOSTS
from core.logger import get_logger, log_file

log = get_logger(__name__)


def state() -> Dict:
    """当前服务状态快照（供 UI 渲染）"""
    host = (
        report_server.get_host()
        if report_server.is_running()
        else (cfg.get("listen_host", "127.0.0.1") or "127.0.0.1")
    )
    return {
        "running": report_server.is_running(),
        "host": host,
        "port": report_server.get_port(),
        "loopback": host in LOOPBACK_HOSTS,
        "api_key_set": bool((cfg.get("api_key", "") or "").strip()),
        "generated_key": report_server.get_generated_key(),
        "error": report_server.get_start_error(),
        "error_cause": report_server.get_start_error_cause(),
        "error_hint": report_server.get_start_error_hint(),
        "rate_limit": report_server.rate_limit_stats(),
    }


def start(port: Optional[int] = None) -> Tuple[bool, str]:
    """启动接收服务。返回 (成功, 给用户看的提示)"""
    if report_server.is_running():
        return True, "接收服务已在运行"

    p = int(port or cfg.get_int("listen_port", DEFAULT_LISTEN_PORT))
    ok = report_server.start_server(p)
    if not ok:
        err = report_server.get_start_error() or "未知错误"
        hint = report_server.get_start_error_hint()
        host = report_server.get_host()
        log.error("接收服务启动失败（%s:%d）：%s", host, p, err)
        msg = f"启动失败（{host}:{p}）：{err}"
        if hint:
            msg += f"\n{hint}"
        msg += f"\n详细堆栈见日志：{log_file()}"
        return False, msg

    host = report_server.get_host()
    if host in LOOPBACK_HOSTS:
        msg = f"接收服务已启动，仅本机可访问 http://{host}:{p}"
    else:
        msg = f"接收服务已启动，监听 {host}:{p}（已启用 API Key 校验）"
    key = report_server.get_generated_key()
    if key:
        msg += f"\n已自动生成 API Key：{key}\n请复制到业务系统的 X-API-Key 请求头。"
    return True, msg


def stop() -> Tuple[bool, str]:
    if not report_server.is_running():
        return True, "接收服务未在运行"
    report_server.stop_server()
    return True, "接收服务已停止"


def toggle(start_it: Optional[bool] = None) -> Tuple[bool, str]:
    running = report_server.is_running()
    if start_it is None:
        start_it = not running
    return start() if start_it else stop()


def endpoint_text() -> str:
    """给设置页展示的上报地址（未运行时按配置预览）"""
    host = cfg.get("listen_host", "127.0.0.1") or "127.0.0.1"
    port = (
        report_server.get_port()
        if report_server.is_running()
        else cfg.get_int("listen_port", DEFAULT_LISTEN_PORT)
    )
    shown = "127.0.0.1" if host in LOOPBACK_HOSTS else host
    return (
        f"POST http://{shown}:{port}/api/v1/access/report\nGET  http://{shown}:{port}/api/v1/health"
    )


def should_autostart() -> bool:
    return cfg.get_bool("autostart_server", False)
