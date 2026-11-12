"""
批量写入器「连接衰竭自愈」测试（对应 P0：原 _loop 见 connect() 返回 None 直接退线程，
写线程永久死亡且无看护）。

断言核心：**建连失败后写线程绝不静默退场** —— 连接长时间不可用期间线程保持 running，
数据安全滞留在队列（不从队列取走 → 不丢），连接一恢复即续写落库。

关键手法：monkeypatch `database.connect_for_writer` 按预设计数控制「前 N 次失败、
之后成功」，确定性复现「第 30 次才成功」这类边界，而非依赖真实锁等待。
"""

import time
from typing import Any, Dict
from unittest import mock

from core import database
from core.database import init_db, query_access_logs
from core.db_writer import BatchWriter
from core.models import AccessRecord, GeoInfo, now_ms


def _rec(i: int, ip: str = "203.0.113.10") -> AccessRecord:
    """本地构造一条访问记录，与 test_batch_writer 里的 _rec 等价、无需跨文件 import。

    刻意不 import tests.test_db_writer._rec：tests/ 无 __init__.py 时，跨文件
    import 会让 mypy 把 tests 视为包、产生「Source file found twice under
    different module names」二义（test_db_writer vs tests.test_db_writer）。
    自包含实现既消二义、也让本测试不依赖既有文件。
    """
    r = AccessRecord(
        ip=ip,
        local_port=3000,
        path=f"/p/{i}",
        user_agent="pytest",
        status_code=200,
        event_ts=now_ms(),
    )
    r.geo = GeoInfo(
        ip=ip, country="中国", province="广东省", city="深圳市", isp="电信", iso="CN", found=True
    )
    return r


def _make_writer(**kw) -> BatchWriter:
    """退避/重试次数调小，让测试在真实时间内跑得快。"""
    kw.setdefault("max_backoff", 0.15)
    kw.setdefault("connect_attempts", 3)
    return BatchWriter(**kw)


def test_thread_stays_alive_when_connect_fails_permanently_then_recovers():
    """
    第 30 次才成功（connect_attempts=30）边界：前 29 次全抛错期间线程必须保持 live，
    一旦恢复即续写 —— 证明不再「见 None 就退线程」静默死亡。
    """
    init_db()
    calls: Dict[str, Any] = {"n": 0, "real": database.connect_for_writer}

    def fake30():
        calls["n"] += 1
        if calls["n"] <= 29:
            raise OSError("模拟前 29 次建连失败")
        return calls["real"]()

    w = _make_writer(connect_attempts=30, max_backoff=0.08)
    try:
        with mock.patch.object(database, "connect_for_writer", fake30):
            w.start()
            # 首启即失败→进入 30 连发重试（会 backoff）+ 看护探测；
            # 观测点：连接连续失败时线程仍活着（自愈看护已接管）
            time.sleep(0.5)
            assert w.running is True, "连接持续失败时写线程必须保持存活（看护）"
            # 恢复可连后：写入
            w.submit_access(_rec(1, ip="198.51.100.30"))
            assert w.flush(timeout=10) is True
            assert len(query_access_logs(limit=10)) == 1
            assert w.stats()["running"] is True
    finally:
        w.stop(timeout=3)


def test_data_buffered_during_outage_is_not_lost():
    """
    连接持续不可用期间提交的记录 = 必须安全滞留队列（不取走不丢弃），恢复后照写。
    """
    init_db()
    calls: Dict[str, Any] = {"n": 0, "real": database.connect_for_writer}

    def fake():
        calls["n"] += 1
        if calls["n"] <= 10:
            raise OSError("模拟持续失败")
        return calls["real"]()

    w = _make_writer(connect_attempts=2, max_backoff=0.1)
    try:
        with mock.patch.object(database, "connect_for_writer", fake):
            w.start()
            # 等进入看护期
            time.sleep(0.3)
            # 连接仍不可用时提交一批——不得丢弃、不得被取走
            for i in range(20):
                w.submit_access(_rec(i, ip="198.51.100.40"))
            assert w.pending() == 20, "连接不可用期间已入队数据必须滞留"
            # 恢复后 flush 把全部写入
            assert w.flush(timeout=10) is True
            assert len(query_access_logs(limit=100)) == 20
    finally:
        w.stop(timeout=3)


def test_stop_during_watchdog_exits_cleanly():
    """
    连接一直不可用期间 stop()：写线程必须退出，且退避 wait 能被 stop 打断，
    不会 join 超时。
    """
    init_db()

    def always_fail():
        raise OSError("永远失败")

    w = _make_writer(connect_attempts=2, max_backoff=0.05)
    try:
        with mock.patch.object(database, "connect_for_writer", always_fail):
            w.start()
            time.sleep(0.1)  # 让线程进入看护退避
            started = time.monotonic()
            w.stop(timeout=2)
            elapsed = time.monotonic() - started
            assert w.running is False, "stop() 后写线程必须退出"
            assert elapsed < 1.5, f"看护退避应被 stop 打断，实际 {elapsed:.2f}s"
    finally:
        w._stop.set()
        if w._thread and w._thread.is_alive():
            w._thread.join(timeout=1)


def test_connect_fails_once_then_recovers_and_resumes():
    """仅首次建连失败、随后即恢复：线程正常启动并写入（不误杀）。"""
    init_db()
    calls: Dict[str, Any] = {"n": 0, "real": database.connect_for_writer}

    def fake():
        calls["n"] += 1
        if calls["n"] == 1:
            raise OSError("仅首次失败")
        return calls["real"]()

    w = _make_writer(connect_attempts=1, max_backoff=0.1)
    try:
        with mock.patch.object(database, "connect_for_writer", fake):
            w.start()
            time.sleep(0.2)
            assert w.running is True
            w.submit_access(_rec(1, ip="198.51.100.50"))
            assert w.flush(timeout=8) is True
            assert len(query_access_logs(limit=10)) == 1
    finally:
        w.stop(timeout=3)
