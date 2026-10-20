"""
PortGuard — 本机多端口访问观察器（双通道采集）

把两条互补的采集通道合成**一条统一的事件流**：

  通道 A：TCP 连接表轮询（core/win_net）
          · 零系统改动、**免管理员**、Win7 SP1 / Server 2008 R2 即支持
          · 只能看见仍然存活的连接（ESTABLISHED）
  通道 B：Windows 防火墙安全日志（core/win_fwlog）
          · 连**被 DROP 掉的扫描**都看得见（这是最想抓到的部分）
          · 需要管理员开启一次日志；按大小滚动，历史窗口有限

两条通道都可能报告同一次访问（表里 ESTABLISHED、日志里 ALLOW），
**必须去重**，否则一次访问会变成两条记录、告警翻倍、风险分也被重复累积。
去重键刻意做成「通道无关」的 (local_port, remote_ip, remote_port)，在
`dedupe_sec` 窗口内同一组合只上报一次。

采集到的记录最终交给 core.pipeline.process_record —— 与业务系统 HTTP 上报
走的是同一条链路，所以实时监控页 / 风险事件页 / 数据库里三者完全同构。

本模块不依赖 Qt，可单测。
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core import settings as cfg
from core import win_fwlog, win_net
from core.logger import get_logger
from core.models import AccessRecord, now_ms
from core.pipeline import process_record

log = get_logger(__name__)

METHOD_TABLE = "table"
METHOD_FWLOG = "fwlog"
ALL_METHODS = (METHOD_TABLE, METHOD_FWLOG)

METHOD_LABEL = {
    METHOD_TABLE: "TCP 连接表轮询",
    METHOD_FWLOG: "防火墙日志",
}

# 采集方式在设置里存成 "table,fwlog" 这种逗号串
DEFAULT_PORTS = [3389, 1433, 3306, 6379, 18080]


def parse_methods(text: Optional[str]) -> List[str]:
    """把设置里的字符串解析成合法的通道列表（至少一个，非法值一律丢弃）

    入参允许为 None：设置项被清空或旧版本配置里缺这个键时会传进来 None，
    此时退回默认通道，而不是抛异常让观察线程起不来。
    """
    if text is None:
        return [METHOD_TABLE]
    got = [x.strip().lower() for x in str(text).replace("，", ",").split(",") if x.strip()]
    out = [m for m in got if m in ALL_METHODS]
    return out or [METHOD_TABLE]


def parse_ports(text: Any) -> List[int]:
    """
    解析监控端口列表。支持 "18080,3389" 与 [18080, 3389] 两种入参。

    非法端口（非数字 / 越界）直接丢弃而不是抛错 —— 用户手输的配置里
    混进笔误是常态，不能让观察器整个起不来。
    """
    if text is None:
        return []
    items: List[Any]
    if isinstance(text, (list, tuple, set)):
        items = list(text)
    else:
        items = list(str(text).replace("，", ",").replace(" ", ",").split(","))
    out: List[int] = []
    for x in items:
        s = str(x).strip()
        if not s.isdigit():
            continue
        p = int(s)
        if 1 <= p <= 65535 and p not in out:
            out.append(p)
    return out


def ports_to_text(ports: List[int]) -> str:
    return ",".join(str(p) for p in ports)


def _conn_key(local_port: int, remote_ip: str, remote_port: int) -> Tuple[Any, ...]:
    """
    跨通道统一的去重键：**只描述连接本身，不含采集通道**。

    两条通道对「同一次外部访问」的描述字段不同（连接表给 remote_ip/remote_port，
    防火墙日志给 src-ip/src-port），但语义一一对应，所以可以归一到同一个键。
    """
    return (int(local_port or 0), str(remote_ip or ""), int(remote_port or 0))


@dataclass
class WatchConfig:
    """观察器运行参数"""

    enabled: bool = False
    ports: List[int] = field(default_factory=lambda: list(DEFAULT_PORTS))
    methods: List[str] = field(default_factory=lambda: [METHOD_TABLE])
    interval_sec: float = 5.0
    dedupe_sec: int = 120
    fwlog_path: str = ""
    resolve_pid: bool = True
    # 自采数据是否允许触发自动封禁。默认 False：用户可能只是想知道
    # 「谁在访问」，不想因为本机自采的数据就真的把人家封了。
    allow_auto_ban: bool = False
    # 预热：启动时丢掉防火墙日志里的历史内容，避免旧日志被当成海量新事件
    skip_existing_log: bool = True

    @staticmethod
    def from_settings() -> "WatchConfig":
        """从设置表读一份配置（都带兜底默认值）"""
        return WatchConfig(
            enabled=cfg.get_bool("watch_enabled", False),
            ports=parse_ports(cfg.get("watch_ports", ports_to_text(DEFAULT_PORTS))),
            methods=parse_methods(cfg.get("watch_methods", METHOD_TABLE)),
            interval_sec=max(1.0, cfg.get_float("watch_interval_sec", 5.0)),
            dedupe_sec=max(0, cfg.get_int("watch_dedupe_sec", 120)),
            fwlog_path=cfg.get("watch_fwlog_path", "") or win_fwlog.DEFAULT_LOG_PATH,
            resolve_pid=cfg.get_bool("watch_resolve_pid", True),
            allow_auto_ban=cfg.get_bool("watch_auto_ban", False),
            skip_existing_log=cfg.get_bool("watch_skip_history", True),
        )


class PortWatcher:
    """多端口访问观察器（后台单线程）"""

    def __init__(self, config: Optional[WatchConfig] = None):
        self._lock = threading.RLock()
        self._cfg = config or WatchConfig()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._tailer = win_fwlog.FwLogTailer(self._cfg.fwlog_path or win_fwlog.DEFAULT_LOG_PATH)
        self._seen: Dict[Tuple[Any, ...], float] = {}
        self._stats: Dict[str, Any] = self._blank_stats()

    @staticmethod
    def _blank_stats() -> Dict[str, Any]:
        return {
            "running": False,
            "polls": 0,
            "table_hits": 0,
            "fwlog_hits": 0,
            "emitted": 0,
            "deduped": 0,
            "errors": 0,
            "started_at": 0,
            "last_poll_at": 0,
            "last_error": "",
            "log_offset": 0,
        }

    # ── 配置 ──
    @property
    def config(self) -> WatchConfig:
        with self._lock:
            return self._cfg

    def update_config(self, config: WatchConfig, restart: bool = True) -> None:
        """热更新配置；正在运行时默认重启采集线程让新配置立即生效"""
        was_running = self.running
        if was_running and restart:
            self.stop()
        with self._lock:
            self._cfg = config
            if self._tailer.path != (config.fwlog_path or win_fwlog.DEFAULT_LOG_PATH):
                self._tailer.set_path(config.fwlog_path or win_fwlog.DEFAULT_LOG_PATH)
        if was_running and restart and config.enabled:
            self.start()

    # ── 生命周期 ──
    @property
    def running(self) -> bool:
        t = self._thread
        return bool(t and t.is_alive())

    def start(self) -> bool:
        with self._lock:
            if self.running:
                return True
            stop_event = self._stop
            stop_event.clear()
            self._stats = self._blank_stats()
            self._stats["started_at"] = now_ms()
            self._stats["running"] = True
            self._thread = threading.Thread(target=self._loop, daemon=True, name="pg-watch")
            self._thread.start()
            return True

    def stop(self, timeout: float = 4.0) -> None:
        self._stop.set()
        t = self._thread
        if t and t.is_alive():
            t.join(timeout=timeout)
        with self._lock:
            self._thread = None
            self._stats["running"] = False

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            out = dict(self._stats)
            out["running"] = self.running
            out["ports"] = list(self._cfg.ports)
            out["methods"] = list(self._cfg.methods)
            out["interval_sec"] = self._cfg.interval_sec
            out["dedupe_sec"] = self._cfg.dedupe_sec
            out["allow_auto_ban"] = self._cfg.allow_auto_ban
            out["log_offset"] = self._tailer.stats().get("offset", 0)
            out["log_exists"] = self._tailer.exists()
            return out

    # ── 主循环 ──
    def _loop(self) -> None:
        c = self.config
        log.info(
            "本机端口观察器已启动：端口=%s 通道=%s 间隔=%.1fs 去重=%ds",
            c.ports or "（未配置，不会采集）",
            "、".join(METHOD_LABEL.get(m, m) for m in c.methods),
            c.interval_sec,
            c.dedupe_sec,
        )
        if METHOD_FWLOG in c.methods and c.skip_existing_log:
            skipped = self._tailer.skip_to_end()
            if skipped:
                log.info("已跳过防火墙日志中的 %d 字节历史内容", skipped)

        while not self._stop.is_set():
            c = self.config
            t0 = time.monotonic()
            try:
                if c.ports:
                    if METHOD_TABLE in c.methods:
                        self._poll_table(c)
                    if METHOD_FWLOG in c.methods:
                        self._poll_fwlog(c)
            except Exception as e:
                with self._lock:
                    self._stats["errors"] += 1
                    self._stats["last_error"] = str(e)
                log.exception("端口观察轮询出错")
            with self._lock:
                self._stats["polls"] += 1
                self._stats["last_poll_at"] = now_ms()
            elapsed = time.monotonic() - t0
            self._stop.wait(max(0.5, c.interval_sec - elapsed))
        log.info(
            "本机端口观察器已停止：%s", {k: v for k, v in self.stats().items() if k != "ports"}
        )

    # ── 通道 A：TCP 连接表 ──
    def _poll_table(self, c: WatchConfig) -> int:
        if not win_net.available():
            return 0
        conns = win_net.inbound_connections(c.ports, established_only=True, external_only=True)
        n = 0
        for conn in conns:
            if not self._dedupe(_conn_key(conn.local_port, conn.remote_ip, conn.remote_port), c):
                continue
            proc = win_net.process_name(conn.pid) if (c.resolve_pid and conn.pid) else ""
            self._emit(
                ip=conn.remote_ip,
                local_port=conn.local_port,
                remote_port=conn.remote_port,
                protocol=conn.proto,
                size=0,
                channel=METHOD_TABLE,
                action="ESTABLISHED",
                pid=conn.pid,
                process=proc,
            )
            n += 1
        if n:
            with self._lock:
                self._stats["table_hits"] += n
        return n

    # ── 通道 B：防火墙日志 ──
    def _poll_fwlog(self, c: WatchConfig) -> int:
        entries = self._tailer.read_new()
        if not entries:
            return 0
        hits = win_fwlog.filter_inbound(entries, c.ports)
        n = 0
        for e in hits:
            # 去重键刻意与通道 A **完全一致**（不含通道名）：
            # 同一次连接可能既在连接表里 ESTABLISHED、又在日志里 ALLOW，
            # 键里带上通道名就等于没去重 —— 一次访问会变成两条记录、告警翻倍、
            # 风险分也被重复累积。（DROP 掉的连接不会 ESTABLISHED，故不会互相遮蔽。）
            if not self._dedupe(_conn_key(e.dst_port, e.src_ip, e.src_port), c):
                continue
            self._emit(
                ip=e.src_ip,
                local_port=e.dst_port,
                remote_port=e.src_port,
                protocol=(e.protocol or "tcp").lower(),
                size=e.size,
                channel=METHOD_FWLOG,
                action=e.action,
                extra={"tcpflags": e.tcpflags} if e.tcpflags else None,
                ts=e.event_ts or now_ms(),
            )
            n += 1
        if n:
            with self._lock:
                self._stats["fwlog_hits"] += n
        return n

    # ── 去重 ──
    def _dedupe(self, key: Tuple[Any, ...], c: WatchConfig) -> bool:
        """返回 True 表示这是新事件（应当上报）"""
        window_sec = max(0, int(c.dedupe_sec))
        now = time.monotonic()
        with self._lock:
            last = self._seen.get(key)
            if last is not None and now - last < window_sec:
                self._stats["deduped"] += 1
                return False
            self._seen[key] = now
            if len(self._seen) > 50000:
                limit = now - max(1, window_sec)
                self._seen = {k: v for k, v in self._seen.items() if v >= limit}
        return True

    # ── 产出 ──
    def _emit(
        self,
        *,
        ip: str,
        local_port: int,
        remote_port: int,
        protocol: str,
        size: int = 0,
        channel: str = METHOD_TABLE,
        action: str = "",
        pid: int = 0,
        process: str = "",
        extra: Optional[Dict[str, Any]] = None,
        ts: int = 0,
    ) -> None:
        tags: Dict[str, Any] = {"source": "local-watch", "channel": channel}
        if action:
            tags["action"] = action
        if pid:
            tags["pid"] = pid
        if process:
            tags["process"] = process
        if extra:
            tags.update(extra)

        rec = AccessRecord(
            ip=ip,
            remote_port=int(remote_port) if remote_port else None,
            local_port=int(local_port or 0),
            protocol=(protocol or "tcp").lower(),
            method="",
            path="",
            status_code=None,
            user_agent="",
            size=int(size or 0),
            host="",
            server_name="",
            tags=tags,
            event_ts=ts or now_ms(),
        )
        # 与业务系统上报共用同一条链路（归属地/评分/落库/告警/自动封禁）。
        # actor=system：本机采集不是任何「人」发起的，也不是外部上报，
        # 是程序自己在看自己 —— 审计里必须能和人工操作区分开。
        process_record(rec, allow_auto_ban=self.config.allow_auto_ban, actor="system")
        with self._lock:
            self._stats["emitted"] += 1


# ── 全局单例 ──
_watcher: Optional[PortWatcher] = None
_watcher_lock = threading.Lock()


def get_watcher() -> PortWatcher:
    global _watcher
    if _watcher is None:
        with _watcher_lock:
            if _watcher is None:
                _watcher = PortWatcher(WatchConfig.from_settings())
    return _watcher


def set_watcher(w: Optional[PortWatcher]) -> None:
    """供测试注入"""
    global _watcher
    _watcher = w


def start_watcher() -> PortWatcher:
    w = get_watcher()
    w.start()
    return w


def stop_watcher(timeout: float = 4.0) -> None:
    global _watcher
    if _watcher is not None:
        _watcher.stop(timeout=timeout)
        _watcher = None


def reload_from_settings(restart: bool = True) -> WatchConfig:
    """设置页保存后调用：把新配置应用到运行中的观察器"""
    c = WatchConfig.from_settings()
    get_watcher().update_config(c, restart=restart)
    return c
