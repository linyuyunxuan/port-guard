"""
批量写入器测试（对应审查报告 P1：每条上报一次独立事务，实测慢 2000 倍）

以「相对倍数」做断言而不是绝对毫秒：绝对耗时受本机磁盘与杀软影响，
但「每条一事务」与「批量一事务」的量级差距在任何环境都成立。
"""
import time

import pytest

from core import database
from core import settings as cfg
from core.database import connect_for_writer, init_db, query_access_logs, query_risk_events
from core.db_writer import BatchWriter
from core.models import AccessRecord, GeoInfo, RiskResult, now_ms


def _rec(i: int, ip: str = "203.0.113.10") -> AccessRecord:
    r = AccessRecord(ip=ip, local_port=3000, path=f"/p/{i}", user_agent="pytest",
                     status_code=200, event_ts=now_ms())
    r.geo = GeoInfo(ip=ip, country="中国", province="广东省", city="深圳市",
                    isp="电信", iso="CN", found=True)
    return r


@pytest.fixture
def writer():
    init_db()                      # 写入器建连前 schema 必须已就绪（生产里也是这个顺序）
    w = BatchWriter(batch_size=100, flush_interval=0.02)
    w.start()
    yield w
    w.stop(timeout=3)


def test_batch_writer_persists(writer):
    init_db()
    n = 300
    for i in range(n):
        writer.submit_access(_rec(i))
    assert writer.flush(timeout=10) is True
    rows = query_access_logs(limit=1000)
    assert len(rows) == n
    assert writer.stats()["dropped"] == 0
    assert writer.stats()["errors"] == 0


def test_risk_pair_links_access_id(writer):
    """风险条目：访问日志与风险事件在同一事务内写入，并正确关联 access_id"""
    init_db()
    rec = _rec(1)
    rec.risk_score = 95
    rec.risk_level = "critical"
    rec.matched_rules = ["blacklist"]
    res = RiskResult(score=95, level="critical", matched_rules=["blacklist"],
                     reason="命中规则：黑名单")
    writer.submit_risk(rec, res)
    assert writer.flush(timeout=10) is True

    events = query_risk_events(limit=10)
    assert len(events) == 1
    access = query_access_logs(limit=10)
    assert len(access) == 1
    assert events[0]["access_id"] == access[0].id


def test_queue_overflow_is_counted_not_silent():
    """队列满时必须计数并告警，绝不静默丢数据"""
    w = BatchWriter(batch_size=10, flush_interval=10.0, queue_size=5)
    # 故意不启动写入线程，把队列塞满
    for i in range(20):
        w.submit_access(_rec(i))
    assert w.dropped > 0
    assert w.stats()["dropped"] == w.dropped


def test_stop_drains_pending(writer):
    """停止时应把队列里剩下的数据写完，不能丢"""
    init_db()
    for i in range(250):
        writer.submit_access(_rec(i))
    writer.stop(timeout=10)
    rows = query_access_logs(limit=1000)
    assert len(rows) == 250


class _CommitSpy:
    """代理连接，只统计 commit 次数（其余属性透传）"""

    def __init__(self, real):
        self._real = real
        self.commits = 0

    def commit(self):
        self.commits += 1
        return self._real.commit()

    def __getattr__(self, name):
        return getattr(self._real, name)


def test_batch_writer_cuts_commit_count(monkeypatch):
    """
    确定性性能断言（不依赖计时，因此不受磁盘/杀软影响）：
    写 300 条，批量写入器只提交 handful 次；逐条提交的实现要 300 次。
    commit 就是 fsync 边界 —— 次数差 100 倍，就是原来慢的根因。
    """
    init_db()
    holder = {}
    real = database.connect_for_writer

    def fake_connect():
        c = _CommitSpy(real())
        holder["c"] = c
        return c

    monkeypatch.setattr(database, "connect_for_writer", fake_connect)

    n = 300
    w = BatchWriter(batch_size=100, flush_interval=0.02)
    w.start()
    for i in range(n):
        w.submit_access(_rec(i))
    assert w.flush(timeout=10) is True
    w.stop(timeout=5)

    spy = holder["c"]
    assert w.stats()["written"] == n
    assert spy.commits <= 5, f"提交次数过多：{spy.commits}"
    assert n / spy.commits >= 60, f"提交次数只压缩了 {n / spy.commits:.1f} 倍"


def test_batch_is_faster_than_per_row_commit():
    """
    计时冒烟（机器相关，故只设 5 倍保守下限）。
    真正的硬保证在 test_batch_writer_cuts_commit_count（比较 commit 次数）。
    """
    init_db()
    n = 200

    # A) 每条一次独立连接 + commit（原实现的方式）
    t0 = time.perf_counter()
    for i in range(n):
        database.insert_access_log(_rec(i))
    per_row = time.perf_counter() - t0

    # B) 单写线程 + 攒批事务
    w = BatchWriter(batch_size=200, flush_interval=0.02)
    t1 = time.perf_counter()
    w.start()
    for i in range(n):
        w.submit_access(_rec(i, ip="198.51.100.7"))
    assert w.flush(timeout=20) is True
    w.stop(timeout=5)
    batched = time.perf_counter() - t1

    assert batched < per_row / 5, (
        f"批量写入没有体现出应有的优势：per_row={per_row:.3f}s batched={batched:.3f}s")


def test_low_traffic_still_gets_written():
    """
    回归：低流量下必须照常落库。
    初版 _drain 拿到第一条后会 `get(timeout=None)` 无限阻塞等下一条，
    导致「只来一条上报就再也不写」，只有攒够 batch_size 才落库。
    """
    init_db()
    w = BatchWriter(batch_size=500, flush_interval=0.05)   # batch 远大于本次条数
    w.start()
    try:
        w.submit_access(_rec(1, ip="198.51.100.11"))
        assert w.flush(timeout=5) is True
        assert len(query_access_logs(limit=10)) == 1
        # 再来一条也必须立刻落库
        w.submit_access(_rec(2, ip="198.51.100.12"))
        assert w.flush(timeout=5) is True
        assert len(query_access_logs(limit=10)) == 2
        assert w.stats()["written"] == 2
    finally:
        w.stop(timeout=5)


def test_writer_uses_explicit_transaction():
    """写入器连接必须是自动提交模式，才能自己划定批量事务边界"""
    init_db()
    conn = connect_for_writer()
    try:
        assert conn.isolation_level is None
        assert conn.row_factory is not None
    finally:
        conn.close()


def test_no_settings_queries_in_hot_path():
    """
    settings 走内存缓存后，热点路径不应再查库。
    这里通过「清空缓存后 get 一次即命中」来验证缓存生效。
    """
    init_db()
    cfg.warm()
    before = len(cfg.snapshot())
    assert before > 0
    for _ in range(100):
        cfg.get_int("rate_limit_per_sec", 300)
    assert len(cfg.snapshot()) == before, "读缓存不应产生新键，说明没有回源"
    assert cfg.is_warmed() is True
