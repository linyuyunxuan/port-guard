"""
PortGuard — 单写线程 + 攒批事务写入器

为什么需要（实测数据）：原实现「每条上报一次独立连接 + 一次 commit」，
在本机临时库上 1000 条耗时 119 087 ms；改成「复用连接 + 单事务批量」只需
56.6 ms —— 差距 2000 倍。根因定位：去掉 WAL PRAGMA 几乎无变化，每次 commit
的磁盘同步占 85%，批量事务再把剩余部分压掉 47 倍。

注：现在 `database._connect()` 统一使用 `synchronous=NORMAL`（WAL 下的常规
取舍：断电可能丢最后几批日志，但不会损坏库），单条 commit 变便宜了，
逐条 vs 批量的实测差距收敛到 10~15 倍；但 commit 次数（= fsync 边界）
依然是 300 : 3 的量级差别，故测试以「commit 次数」而非计时做硬断言。

SQLite 只允许一个写者，单写线程天然消除 `database is locked`；
读侧走 WAL 独立连接，不受影响。

语义取舍：上报到落库最多 `flush_interval` 的延迟（默认 200ms）。
本工具是安全监控而非交易系统，完全可接受；需要强一致时把
flush_interval 调小即可。

队列满时**显式计数并告警**（dropped），绝不静默丢数据。
"""

import contextlib
import queue
import threading
import time
from typing import Any, List, Optional, Tuple

from core import database
from core.logger import get_logger

log = get_logger(__name__)


class BatchWriter:
    def __init__(
        self,
        batch_size: int = 200,
        flush_interval: float = 0.2,
        queue_size: int = 200_000,
        name: str = "pg-writer",
        max_backoff: float = 5.0,
        connect_attempts: int = 30,
    ):
        self._q: queue.Queue[Tuple[str, Any]] = queue.Queue(maxsize=queue_size)
        self._batch_size = max(1, int(batch_size))
        self._flush_interval = max(0.005, float(flush_interval))
        self._name = name
        self._max_backoff = max(0.05, float(max_backoff))
        self._connect_attempts = max(1, int(connect_attempts))
        self._stop = threading.Event()
        self._idle = threading.Event()  # 「没有半途取走但未提交的数据」
        self._idle.set()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self.written = 0
        self.hits = 0
        self.dropped = 0
        self.errors = 0
        self.batches = 0
        self._conn_fails = 0  # 累计建连失败次数（看护日志用）
        self._reconnects = 0  # 累计成功重连次数

    # ── 生命周期 ──
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name=self._name)
        self._thread.start()
        log.info(
            "批量写入器已启动（batch=%d, flush=%.0fms）",
            self._batch_size,
            self._flush_interval * 1000,
        )

    def stop(self, timeout: float = 5.0) -> None:
        """停止写入器：先榨干队列再退出（保证不丢已入队数据）"""
        self._stop.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout=timeout)

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    # ── 提交 ──
    def submit_access(self, rec) -> bool:
        return self.submit("access", rec)

    def submit_risk(self, rec, result) -> bool:
        """一条记录 + 它的风险事件（同一事务内插入并关联 access_id）"""
        return self.submit("risk", (rec, result))

    def submit_hit(self, ip: str, ts: Optional[int] = None) -> bool:
        """
        已封禁 IP 又命中一次 → 累加封禁记录的拦截次数。

        为什么要进队列而不是就地写库：这条路径在攻击期每秒几十次，而
        「新连接 + commit + close」在 SQLite 上单次 170ms（关闭时触发 WAL
        checkpoint），长连接只要 2ms。见 `database.bump_ban_hits_sql` 的说明。

        计数是**幂等增量**，所以这里允许丢（队列满时 submit 会返回 False）：
        少记几次不影响「这个 IP 是惯犯」的判断，但绝不能因此堵住采集线程。
        """
        return self.submit("hit", (ip, ts))

    def submit(self, kind: str, payload: Any) -> bool:
        try:
            self._q.put_nowait((kind, payload))
            return True
        except queue.Full:
            with self._lock:
                self.dropped += 1
                n = self.dropped
            if n == 1 or n % 1000 == 0:
                log.error("写入队列已满，已丢弃 %d 条记录（下游写入跟不上）", n)
            return False

    def pending(self) -> int:
        return self._q.qsize()

    def stats(self) -> dict:
        with self._lock:
            return {
                "written": self.written,
                "hits": self.hits,
                "dropped": self.dropped,
                "errors": self.errors,
                "batches": self.batches,
                "pending": self._q.qsize(),
                "running": self.running,
            }

    def flush(self, timeout: float = 5.0) -> bool:
        """
        等待「队列排空」**且**「当前批次已提交」。

        为什么不能只看队列空：写入线程可能已经把记录从队列取走、正在组批，
        此时队列为空但数据尚未落库 —— 只看队列空会提前返回 True 骗过调用方。
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._q.empty() and self._idle.is_set():
                time.sleep(0.005)  # 再确认一次，避开「取走 → 开写」的瞬间
                if self._q.empty() and self._idle.is_set():
                    return True
            time.sleep(0.01)
        return self._q.empty() and self._idle.is_set()

    # ── 写入线程 ──
    def _connect_once(self):
        """单次建连尝试（无重试，仅成功/抛异常）。供启动期与看护期复用。"""
        return database.connect_for_writer()

    def _count_conn_fail(self) -> None:
        with self._lock:
            self._conn_fails += 1

    def _connect(self):
        """
        建立写入连接。SQLite 的 `PRAGMA journal_mode=WAL` 需要一个短暂的
        排他锁，遇到杀软扫描 / 备份 / 刚建库时会瞬间拿到 "database is locked"。
        这种锁几乎都是瞬时的，所以做有限重试，而不是一失败就放弃写入。

        返回 `None` 表示「本回合建连不可用」（超限失败或收到停止信号）；调用方
        （`_loop` 的看护逻辑）须进入有限退避重试，绝不允许因此退线程。
        """
        attempt = 0
        while not self._stop.is_set():
            try:
                return self._connect_once()
            except Exception as e:
                attempt += 1
                self._count_conn_fail()
                if attempt >= self._connect_attempts:
                    log.exception(
                        "批量写入器连续 %d 次建连失败（启动期），转入看护重连；累计失败 %d 次",
                        attempt,
                        self._conn_fails,
                    )
                    return None
                if attempt == 1:
                    log.warning("批量写入器建立连接失败（%s），正在重试…", e)
                self._wait_backoff(attempt)
        return None

    def _wait_backoff(self, attempt: int) -> bool:
        """
        指数退避等待，且可被 ``stop()`` 立即打断。

        返回 ``True`` 表示期间未收到停止信号可继续；``False`` 表示已请求停止，
        应退出循环。用 ``_stop.wait()`` 代替 ``time.sleep()`` 是让看护重试的
        长时间等待在 stop 时立即唤醒，而不是干等满一个退避周期。
        """
        delay = min(self._max_backoff, 0.05 * (2 ** min(attempt, 10)))
        return not self._stop.wait(delay)

    def _loop(self) -> None:
        """
        写线程主循环：建连 → 攒批写入 → 建连失败进入看护重连 → 恢复续写。

        关键设计：**建连失败绝不退线程**。`_connect()` 返回 None 后进入指数
        退避重连循环（可被 stop 打断）；期间队列里的待写数据**不从队列取走**，
        天然安全暂存、不丢。连接一恢复，正常 drain/写继续。
        """
        while not self._stop.is_set():
            conn = self._connect()
            if conn is None:
                # 看护重连：有限指数退避 + 可被打断；不吞异常、不假活。
                if self._watchdog_backoff():
                    continue
                break
            try:
                self._run_with_conn(conn)
                break  # 正常退出路径（收到 stop 且队列榨干）
            except Exception:
                # 运行期连接突然失效（非本批可回滚的错，连接本身坏了）→ 重连。
                log.exception("批量写入器运行期连接异常，丢弃后重连")
                with contextlib.suppress(Exception):
                    conn.close()
                with self._lock:
                    self._reconnects += 1
                continue
        log.info("批量写入器已退出：%s", self.stats())

    def _watchdog_backoff(self) -> bool:
        """
        连接不可用时的看护等待。指数退避递增至 ``_max_backoff`` 封顶，
        可被 ``stop()`` 打断。返回 True 表示应继续重试，False 表示应退出。

        探测用轻量 `_connect_once`（单次）而不是 `_connect`（30 连发），
        否则每一轮探测自身就要阻塞近 150s，看护退避形同虚设。
        """
        attempt = 0
        while not self._stop.is_set():
            delay = min(self._max_backoff, 0.2 * (2 ** min(attempt, 10)))
            log.warning(
                "批量写入器连接不可用，%.1fs 后重试（第 %d 轮，累计失败 %d 次）",
                delay,
                attempt + 1,
                self._conn_fails,
            )
            if self._stop.wait(delay):
                return False
            try:
                probe = self._connect_once()
            except Exception:
                # 本轮探测失败，计数并退避递增继续看护
                self._count_conn_fail()
                attempt += 1
                continue
            with contextlib.suppress(Exception):
                probe.close()  # 只验证可连，真正建连交给外层 _loop 下次
            with self._lock:
                self._reconnects += 1
            log.info("批量写入器连接已恢复，重新进入写入循环")
            return True
        return False

    def _run_with_conn(self, conn) -> None:
        """持有一条健康连接时的正常写入循环；连接失效抛异常交给外层看护。"""
        while True:
            items = self._drain()
            if items:
                try:
                    self._write_batch(conn, items)
                finally:
                    self._idle.set()
                continue
            self._idle.set()
            if self._stop.is_set():
                # 收到停止：榨干队列（此时队列为空）后正常退出，关闭连接
                with contextlib.suppress(Exception):
                    conn.close()
                return
            # 队列空且未停止：回到 _drain 阻塞等待积累下一条（最长 flush_interval），
            # 既不会忙等空转 CPU，又保证低流量也照常落库。
        return

    def _write_batch(self, conn, items: List[Tuple[str, Any]]) -> None:
        try:
            conn.execute("BEGIN")
            n_access = 0
            n_hit = 0
            for kind, payload in items:
                if kind == "access":
                    database.insert_access_log_sql(conn, payload)
                    n_access += 1
                elif kind == "risk":
                    rec, result = payload
                    access_id = database.insert_access_log_sql(conn, rec)
                    database.insert_risk_event_sql(conn, rec, result, access_id)
                    n_access += 1
                elif kind == "hit":
                    # 拦截次数的累加：同一条语句、同一个事务，不额外 fsync
                    ip, ts = payload
                    database.bump_ban_hits_sql(conn, ip, ts)
                    n_hit += 1
            conn.commit()  # ← 每批一次 fsync，这就是 2000 倍差距的来源
            with self._lock:
                self.written += n_access
                self.hits += n_hit
                self.batches += 1
        except Exception:
            with contextlib.suppress(Exception):
                conn.rollback()
            with self._lock:
                self.errors += len(items)
            log.exception("批量写入失败，本批 %d 条已回滚", len(items))

            # 连接已证失效（库被关/写锁被锁死到不可用）：回滚后不能继续复用，
            # 把「连接坏」这一事实抛给外层看护去重连 —— 否则带着坏连接会在
            # 下一次 drain 反复失败。已入队批次在此计入 errors，非静默丢。
            try:
                conn.execute("SELECT 1")
            except Exception:
                raise

    def _drain(self) -> List[Tuple[str, Any]]:
        """
        收满一批、或「队列暂时空了」就返回。

        **必须注意**：拿到第一条之后只能用非阻塞取，绝不能阻塞等下一条。
        否则低流量场景（几分钟才来一条上报）下，记录会被一直攥在手里，
        只有攒够 batch_size 才落库 —— 流量一停就永远不写。
        （这正是初版把 `timeout=0` 当成非阻塞、结果传成 `get(timeout=None)`
        无限阻塞所导致的缺陷，测试 `test_stop_drains_pending` 抓住了它。）
        """
        out: List[Tuple[str, Any]] = []
        deadline = time.monotonic() + self._flush_interval
        while len(out) < self._batch_size:
            if out:
                try:
                    out.append(self._q.get_nowait())
                except queue.Empty:
                    break
            else:
                timeout = deadline - time.monotonic()
                if timeout <= 0:
                    break
                try:
                    out.append(self._q.get(timeout=timeout))
                except queue.Empty:
                    break
            if len(out) == 1:
                # 已经从队列取走数据，flush() 必须等到这批 commit 完成
                self._idle.clear()
        return out


# ── 全局单例 ──
_writer: Optional[BatchWriter] = None
_writer_lock = threading.Lock()


def get_writer() -> BatchWriter:
    global _writer
    if _writer is None:
        with _writer_lock:
            if _writer is None:
                _writer = BatchWriter()
    return _writer


def peek_writer() -> Optional[BatchWriter]:
    """
    返回当前写入器；**没有时返回 None，绝不创建**。

    与 `get_writer()` 的区别是这里不做 lazy 初始化 —— 测试夹具要在收尾时
    判断「有没有写入线程泄漏」，若用 `get_writer()` 会在本无写入器的情况下
    凭空造出一个，护栏就永远看不到泄漏。
    """
    return _writer


def start_writer() -> BatchWriter:
    w = get_writer()
    w.start()
    return w


def stop_writer(timeout: float = 5.0) -> None:
    global _writer
    if _writer is not None:
        _writer.stop(timeout=timeout)
        _writer = None


def set_writer(w: Optional[BatchWriter]) -> None:
    """供测试注入"""
    global _writer
    _writer = w
