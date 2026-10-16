"""
日志与启动体检测试（回归 2026-10-16 的「接收服务启动失败」）

背景：窗口化运行（pythonw / 打包 exe 的 `console=False`）下 `sys.stdout` 与
`sys.stderr` 都是 None。uvicorn 的 `DefaultFormatter.__init__` 会执行
`sys.stdout.isatty()`，于是抛 AttributeError，被 `logging.config.dictConfig`
包成 `ValueError: Unable to configure formatter 'default'` —— 服务压根没走到
绑定端口那一步，而界面提示的是「可能被占用或权限不足」，把排障方向带偏。

这里锁死三道防线：
① `ensure_std_streams()` —— std 流永不为 None
② `report_server` 给 uvicorn 传 `log_config=None` —— 不走它那套 formatter
③ uvicorn 绑定失败抛的是 SystemExit（BaseException），必须被捕获并如实归因

外加「日志按日期清理」与「保留天数/执行时刻可改」的行为。

⚠️ 打补丁的时机很讲究：pytest 的全局捕获会在「夹具装配完成、用例体开始」之间
把 `sys.stdout` 换回它自己的捕获对象。所以**不能用夹具自动注入** ——
必须由用例体第一行显式调用 `_no_console(monkeypatch)`，否则断言会在有 stdout
的环境里"假通过"（这个坑本轮真的踩到了）。
"""

import logging
import os
import socket
import sys
import time

import pytest

from core import settings as cfg
from core.database import init_db


def _no_console(monkeypatch) -> None:
    """把 std 流置为 None，模拟 pythonw / 打包窗口程序"""
    monkeypatch.setattr(sys, "stdout", None)
    monkeypatch.setattr(sys, "stderr", None)
    assert sys.stdout is None and sys.stderr is None, "pytest 捕获把标准流换回去了"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = int(s.getsockname()[1])
    s.close()
    return port


# ═══════════════════ 防线 ①：替身流 ═══════════════════


def test_ensure_std_streams_fills_none(monkeypatch):
    _no_console(monkeypatch)
    from core.logger import ensure_std_streams

    assert set(ensure_std_streams()) == {"stdout", "stderr"}
    assert sys.stdout.isatty() is False
    assert sys.stderr.isatty() is False
    # 写入 / 刷新不能抛异常（第三方库会随手往 stderr 写）
    sys.stdout.write("要能吞下中文")
    sys.stderr.flush()
    # 但 fileno() 必须如实报告「没有控制台」，否则会误判成有终端
    with pytest.raises(OSError):
        sys.stderr.fileno()


def test_ensure_std_streams_keeps_real_streams():
    from core.logger import ensure_std_streams

    assert ensure_std_streams() == []  # 正常情况下什么都不改


def test_null_stream_satisfies_uvicorn_formatter(monkeypatch):
    """防线 ① 独立成立：即使真的走到 uvicorn 的 formatter 也不会崩"""
    _no_console(monkeypatch)
    from uvicorn.logging import DefaultFormatter

    from core.logger import ensure_std_streams

    ensure_std_streams()
    assert DefaultFormatter().use_colors is False  # 修复前这里抛 AttributeError


# ═══════════════════ 防线 ②：不复用 uvicorn 的日志配置 ═══════════════════


def test_default_uvicorn_config_reproduces_the_bug(monkeypatch):
    """复现原始缺陷（uvicorn 若已修掉则跳过，避免测试变成版本绑定的断言）"""
    _no_console(monkeypatch)
    import uvicorn
    from fastapi import FastAPI

    try:
        uvicorn.Config(app=FastAPI(), host="127.0.0.1", port=0, log_level="warning")
    except ValueError as e:
        assert "formatter 'default'" in str(e)
    else:
        pytest.skip("当前 uvicorn 版本已不再默认使用该 formatter")


def test_uvicorn_config_disables_its_own_logging(isolated_env, monkeypatch):
    """启动时必须显式传 `log_config=None` —— 这是不再触发该崩溃的关键"""
    init_db()
    cfg.warm()

    import uvicorn

    from core import report_server

    captured: dict = {}
    real_init = uvicorn.Config.__init__

    def spy(self, *args, **kwargs):
        captured.update(kwargs)
        return real_init(self, *args, **kwargs)

    monkeypatch.setattr(uvicorn.Config, "__init__", spy)
    _no_console(monkeypatch)

    port = _free_port()
    ok = report_server.start_server(port)
    report_server.stop_server()

    assert ok, report_server.get_start_error()
    assert captured.get("log_config", "未传") is None, f"实际传入：{captured.get('log_config')}"


def test_report_server_starts_without_console(isolated_env, monkeypatch):
    """防线 ②：std 流为 None 时，接收服务必须真的能起来"""
    init_db()
    cfg.warm()

    from core import report_server

    _no_console(monkeypatch)
    port = _free_port()
    ok = report_server.start_server(port)
    err = report_server.get_start_error()
    detail = report_server.get_start_error_detail()
    report_server.stop_server()

    assert ok, f"无控制台环境下启动失败：{err}\n{detail}"


# ═══════════════════ 防线 ③：失败原因如实归因 ═══════════════════


def test_occupied_port_is_reported_accurately(isolated_env):
    """端口被占用 → 归因 occupied，且提示里给出可执行的下一步"""
    init_db()
    cfg.warm()

    from core import report_server

    hold = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hold.bind(("127.0.0.1", 0))
    hold.listen(1)
    port = int(hold.getsockname()[1])
    try:
        ok = report_server.start_server(port)
        err = report_server.get_start_error()
        cause = report_server.get_start_error_cause()
        hint = report_server.get_start_error_hint()
        report_server.stop_server()
    finally:
        hold.close()

    assert not ok
    assert cause == report_server.CAUSE_OCCUPIED, f"归因={cause} 信息={err}"
    assert "占用" in hint
    assert "权限不足" not in hint  # 不能再把原因含糊地推给权限


def test_cause_classification():
    import errno

    from core import report_server as rs

    assert rs._cause_of(OSError(errno.EADDRINUSE, "in use")) == rs.CAUSE_OCCUPIED
    assert rs._cause_of(OSError(errno.EACCES, "denied")) == rs.CAUSE_PERMISSION
    assert rs._cause_of(ValueError("boom")) == rs.CAUSE_INTERNAL
    # Windows 下 winerror 优先于 errno
    exc = OSError(2, "no such file")
    exc.winerror = 10048
    assert rs._cause_of(exc) == rs.CAUSE_OCCUPIED


# ═══════════════════ 日志文件：按日期清理 ═══════════════════


def test_cleanup_log_files_by_date(isolated_env):
    from app import maintenance
    from core.logger import log_file, logs_dir

    d = logs_dir()
    old = os.path.join(d, "portguard.log.2026-01-01")
    fresh = os.path.join(d, "portguard.log.2099-01-01")
    other = os.path.join(d, "notes.txt")
    for p in (old, fresh, other):
        with open(p, "w", encoding="utf-8") as f:
            f.write("x\n")
    stale = time.time() - 400 * 86400
    os.utime(old, (stale, stale))

    removed = maintenance.cleanup_log_files(30)

    assert removed == 1
    assert not os.path.exists(old), "超过保留天数的日志归档应被删除"
    assert os.path.exists(fresh), "未过期的归档不能被删"
    assert os.path.exists(other), "非 .log 文件不归日志清理管"

    # 正在写入的活跃日志：即便 mtime 很旧也绝不能删
    active = log_file()
    if not os.path.exists(active):
        with open(active, "a", encoding="utf-8"):
            pass
    os.utime(active, (stale, stale))
    maintenance.cleanup_log_files(30)
    assert os.path.exists(active), "活跃日志文件绝不能被删"


def test_handler_keeps_same_day_archives(tmp_path):
    """
    同一天内滚动两次，两份归档必须都在。

    标准库 `TimedRotatingFileHandler.doRollover()` 会算出同名目标文件并
    `os.remove` 掉前一份 —— 静默丢日志。这里验证序号兜底确实生效。
    """
    from core.logger import DailySizeRotatingFileHandler

    p = tmp_path / "portguard.log"
    h = DailySizeRotatingFileHandler(str(p), keep_days=30, max_bytes=5 * 1024 * 1024)
    h.setFormatter(logging.Formatter("%(message)s"))

    p.write_text("first\n", encoding="utf-8")
    h.doRollover()
    p.write_text("second\n", encoding="utf-8")
    h.doRollover()

    names = sorted(x.name for x in tmp_path.glob("portguard.log.*"))
    assert len(names) == 2, f"同一天两次滚动互相覆盖了：{names}"


def test_size_guard_is_actually_effective(tmp_path):
    """
    `maxBytes` 必须真的生效。

    标准库的 `TimedRotatingFileHandler.shouldRollover()` 只看时间、**不读
    `maxBytes`**，直接传参是静默失效的；日志风暴时单文件能涨到几个 GB。
    """
    from core.logger import DailySizeRotatingFileHandler

    p = tmp_path / "portguard.log"
    h = DailySizeRotatingFileHandler(str(p), keep_days=30, max_bytes=200)
    h.setFormatter(logging.Formatter("%(message)s"))
    rec = logging.LogRecord("t", logging.INFO, __file__, 1, "x" * 100, None, None)

    for _ in range(20):
        h.emit(rec)
    h.flush()
    if h.stream is not None:
        h.stream.close()

    archives = list(tmp_path.glob("portguard.log.*"))
    assert archives, "超过 maxBytes 后必须产生归档（说明大小兜底生效）"
    assert p.stat().st_size < 400, f"活跃日志没有被大小上限截断：{p.stat().st_size} 字节"


def test_setup_guards_against_reentrancy(monkeypatch):
    """
    `setup()` 必须"先置位再配置"。

    它在配置过程中会读设置（保留天数）→ 触达 core.database，而该模块末尾的
    `log = get_logger(__name__)` 会回调 setup()。守卫没置位的话就会被装上两套
    handler，日志每行重复输出两遍 —— 这是真实踩到的坑。
    """
    from core import logger as lg

    logger_obj = logging.getLogger("portguard")
    monkeypatch.setattr(logger_obj, "handlers", [])
    monkeypatch.setattr(lg, "_configured", False)
    monkeypatch.setattr(lg, "_file_handler", None)

    seen: list = []
    real_retention = lg.retention_days

    def probe() -> int:
        seen.append(lg._configured)  # 创建 handler 之前，守卫应该已经置位
        return real_retention()

    monkeypatch.setattr(lg, "retention_days", probe)
    lg.setup()

    assert seen == [True], f"创建 handler 时 _configured={seen}，重入保护缺失"
    files = [h for h in logger_obj.handlers if isinstance(h, logging.FileHandler)]
    assert len(files) == 1, f"文件 handler 重复安装：{logger_obj.handlers}"


def test_set_retention_updates_running_handler(isolated_env):
    """保留天数改动要即时生效，不必重启"""
    from core import logger as lg

    lg.setup()
    if lg._file_handler is None:
        pytest.skip("当前环境无法创建文件日志 handler")
    before = lg._file_handler.backupCount  # type: ignore[attr-defined]
    try:
        lg.set_retention(7)
        assert lg._file_handler.backupCount == 7  # type: ignore[attr-defined]
    finally:
        lg.set_retention(before)


# ═══════════════════ 定期清理的时刻可配 ═══════════════════


def test_due_today_respects_configured_hour(isolated_env):
    init_db()
    cfg.warm()

    from app import maintenance

    # 从没清理过 → 不受时刻限制，立即跑一次
    cfg.set("maintenance_last_date", "")
    cfg.set("maintenance_hour", 0)
    assert maintenance.due_today() is True
    # 同一天不重复
    assert maintenance.due_today() is False

    # 「昨天跑过」+ 时刻未到 → 不跑
    cfg.set("maintenance_last_date", "1970-01-01")
    cfg.set("maintenance_hour", 23)
    expected = time.localtime().tm_hour >= 23
    assert maintenance.due_today() is expected
