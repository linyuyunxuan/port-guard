"""
日志与启动体检测试

背景：窗口化运行（pythonw / 打包 exe 的 `console=False`）下 `sys.stdout` 与
`sys.stderr` 都是 None。任何第三方库只要调一次 `sys.stdout.isatty()` 就会抛
AttributeError —— 曾被 uvicorn 的日志 formatter 触发，表现成「服务启动失败」，
而界面提示「可能被占用或权限不足」，把排障方向完全带偏（上报服务已在 1.2 移除，
但这条兜底对任何库都有效，因此继续锁死）。

这里锁死防线：`ensure_std_streams()` —— std 流永不为 None。
外加「日志按日期清理」与「保留天数/执行时刻可改」的行为。

⚠️ 打补丁的时机很讲究：pytest 的全局捕获会在「夹具装配完成、用例体开始」之间
把 `sys.stdout` 换回它自己的捕获对象。所以**不能用夹具自动注入** ——
必须由用例体第一行显式调用 `_no_console(monkeypatch)`，否则断言会在有 stdout
的环境里"假通过"（这个坑本轮真的踩到了）。
"""

import logging
import os
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
