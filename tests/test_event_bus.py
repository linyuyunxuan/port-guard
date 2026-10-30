"""EventBus（core/event_bus.py）背压语义的回归锁。

总线是后台线程与 UI 之间唯一的桥：攻击洪峰下队列必然满，这里的
「丢最旧 + 计数」行为决定了 UI 是卡死还是只是少显示几行。
"""

import logging
import threading

from core.event_bus import EventBus


def test_full_queue_drops_oldest_and_counts():
    """队列满：新事件挤掉最旧的一条，_dropped 计数累加。

    变异：把 _put 的 queue.Full 分支改成直接 return → 本例变红
    （最旧一条还在、新事件丢了、计数为 0）。
    """
    b = EventBus(risk_size=3)
    for i in range(3):
        b.emit_risk(i)
    assert b.pending() == 3

    b.emit_risk(99)  # 满了 → 丢 0，进 99
    rows = b.drain_risk()
    assert rows == [1, 2, 99], f"必须丢最旧、保最新：{rows}"
    assert b.dropped == 1


def test_drop_count_accumulates_across_queues():
    """计数跨队列、跨多次丢弃累加，且 dropped 是只读快照"""
    b = EventBus(access_size=1, xdb_size=1)
    b.emit_access("a1")
    b.emit_access("a2")  # 丢 a1
    b.emit_xdb("x1")
    b.emit_xdb("x2")  # 丢 x1
    assert b.dropped == 2
    assert b.drain_access() == ["a2"]
    assert b.drain_xdb() == ["x2"]
    # drain 后 dropped 不清零：丢过就是丢过，可观测性不能被消费重置
    assert b.dropped == 2


def test_concurrent_emits_never_crash_or_lose_count():
    """多线程同时挤满队列：不崩、成功投递总数正确、丢弃都有计数"""
    b = EventBus(risk_size=100)
    N_THREADS, N_EACH = 8, 500

    def worker(seed: int) -> None:
        for i in range(N_EACH):
            b.emit_risk((seed, i))

    ts = [threading.Thread(target=worker, args=(s,)) for s in range(N_THREADS)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()

    # 队列恒满（丢弃的比进来的多），其余都在队列里：进队数 = 队列数 + 丢弃数
    in_queue = b.drain_risk()
    assert len(in_queue) == 100
    assert b.dropped == N_THREADS * N_EACH - len(in_queue)


def test_drop_logs_warning_periodically(caplog):
    """P2-10 可观测性：丢弃每满 1000 条必须记一条 WARNING——
    「丢过事件」不能只有内存计数器知道（变异：删掉 _put 里的日志分支）"""
    b = EventBus(risk_size=2)
    for i in range(2):
        b.emit_risk(i)
    with caplog.at_level(logging.WARNING, logger="core.event_bus"):
        for i in range(1000):
            b.emit_risk(i)
    assert b.dropped == 1000
    warnings = [r for r in caplog.records if "1000" in r.getMessage()]
    assert warnings, "丢弃满 1000 条时必须写 WARNING 日志"
