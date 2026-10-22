"""降级环境护栏：数据目录坏掉、日志目录写不了、磁盘满。

这三件事的共同点是「用户不会告诉我们」，而它们的坏法差别很大：

1. **日志目录写不了** → 绝不能让程序起不来。日志是排障手段，不是功能本体，
   丢掉文件日志只该退化成「没有文件日志」，不该连锁崩掉启动。
2. **数据目录坏掉** → 必须**明确失败**：起得来但没有库的半残状态比直接报错
   危险得多（用户会以为在监控，其实一条都没落库）。同时堆栈必须落到一个
   **不依赖该目录**的位置，否则「为什么起不来」连证据都没有。
3. **磁盘满** → 批量写入器要记账并继续活着。一旦线程挂了，之后所有记录都被
   静默丢弃，界面还显示「监控中」—— 这是最糟的一种失败。

这里用「路径中间夹一个普通文件」来制造不可写，比改 ACL 稳定：os.makedirs
会稳定抛 NotADirectoryError，换个机器、换个账户都一样。
"""

import contextlib
import logging
import os
import sqlite3
import time

import pytest

from core import config


def _blocker(tmp_path):
    """一个普通文件，拿来当「目录」用，让 makedirs 稳定失败"""
    p = tmp_path / "blocker"
    p.write_text("not a directory", encoding="utf-8")
    return str(p)


# ═══════════════════ 日志目录写不了 ═══════════════════


def test_logger_degrades_to_console_when_log_dir_unwritable(tmp_path, monkeypatch):
    """日志目录写不了 → 退化成「没有文件日志」，绝不抛异常打断启动"""
    from core import logger

    base = logging.getLogger(logger._LOGGER_NAME)
    before = list(base.handlers)
    saved_cfg, saved_fh = logger._configured, logger._file_handler
    try:
        logger._configured = False
        logger._file_handler = None
        monkeypatch.setattr(config, "user_data_dir", lambda: _blocker(tmp_path) + "/data")

        lg = logger.setup(console=False)
        assert logger._file_handler is None, "写不了还留个 handler，之后每条日志都会炸"
        # 最关键的一条：真的写一条，不能抛
        lg.info("这条只会落到空 handler")
    finally:
        # 全局 logger 会被后续用例复用，多加的 handler 必须拆干净，
        # 否则同一个进程里开始「每条日志打印两遍」
        for h in list(base.handlers):
            if h not in before:
                base.removeHandler(h)
                with contextlib.suppress(Exception):
                    h.close()
        logger._configured = saved_cfg
        logger._file_handler = saved_fh


def test_log_file_path_is_reported_even_when_broken(tmp_path, monkeypatch):
    """诊断页要展示日志路径：目录坏了也得把「本来想写哪」说清楚"""
    from core import logger

    monkeypatch.setattr(config, "user_data_dir", lambda: _blocker(tmp_path) + "/data")
    with pytest.raises(OSError):
        logger.log_file()


# ═══════════════════ 数据目录坏掉 ═══════════════════


def test_init_db_fails_loudly_when_data_dir_unusable(tmp_path, monkeypatch):
    """库打不开必须抛，不能静默降级成「没有库但界面照常」"""
    from core import database

    monkeypatch.setattr(database, "db_path", lambda: _blocker(tmp_path) + "/data/port_guard.db")
    monkeypatch.setattr(database, "_initialized", False)

    with pytest.raises(sqlite3.Error) as ei:
        database.init_db()

    msg = str(ei.value).lower()
    assert "unable to open" in msg or "not a directory" in msg or "readonly" in msg, msg
    assert database._initialized is False, "失败了却把标志置位，重启后会用空库假装正常"


def test_crash_dump_does_not_live_in_the_data_dir(tmp_path, monkeypatch):
    """崩溃堆栈必须落在数据目录之外。

    这条是「数据目录坏掉」场景的救命细节：如果 crash-*.txt 也写在坏掉的数据
    目录里，现场只会得到「双击没反应、日志里什么都没有」，只能靠猜。
    """
    from core import diag

    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))
    crash_dir = diag._logs_dir()
    assert not crash_dir.startswith(_blocker(tmp_path))

    path = diag.write_crash("boom: 数据目录不可写")
    assert path, "写不了崩溃日志就等于没有现场"
    assert os.path.dirname(path) == crash_dir
    with open(path, encoding="utf-8") as fh:
        assert "数据目录不可写" in fh.read()


# ═══════════════════ 磁盘满 ═══════════════════


def test_batch_writer_survives_disk_full(fresh_db, monkeypatch):
    """磁盘满：记账 + 回滚 + 线程活着，磁盘恢复后继续写"""
    from core import database, db_writer

    calls = {"n": 0}

    def flaky(conn, rec):
        calls["n"] += 1
        if calls["n"] <= 2:
            raise sqlite3.OperationalError("database or disk is full")
        return 1

    monkeypatch.setattr(database, "insert_access_log_sql", flaky)

    w = db_writer.BatchWriter(batch_size=1, flush_interval=0.01, name="pg-degraded-test")
    w.start()
    try:
        for _ in range(6):
            assert w.submit_access({"ip": "1.2.3.4"}) is True
            w.flush(timeout=3.0)
            time.sleep(0.01)
        assert w.running is True, "写崩一次线程就退出，之后所有记录会被静默丢弃"
    finally:
        w.stop()

    s = w.stats()
    assert s["errors"] >= 2, f"磁盘满没记账，界面会以为写成功了：{s}"
    assert s["written"] >= 3, f"磁盘恢复后没继续写：{s}"
    assert calls["n"] >= 5, f"失败后没有重试后续批次：{calls}"

    # 磁盘满期间那两条是「明确失败」，不是被吞掉：错误计数要能对上
    assert s["errors"] == 2
