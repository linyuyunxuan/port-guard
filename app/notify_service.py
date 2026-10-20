"""
PortGuard — 外部告警通道编排（Webhook）

分工：
- `core/webhook.py` 只管「一次同步 POST」（纯函数，可单测）
- 本模块只管编排：入队 → 后台线程 → 令牌桶限流 → 失败重试退避

为什么必须异步：`Alerter.notify()` 由 Qt 主线程的事件泵驱动
（`gui/mixins._drain_events`），在这里同步发 HTTP 会直接冻住界面；
而自采通道一次扫描就能产生几十条事件，不限流会把对端打挂。

未启用 / 未配地址时**静默不发**：这是默认关闭的可选功能，
没配就不该在日志里刷屏。
"""

import queue
import threading
import time
from typing import Any, Callable, Dict, Optional

from core import settings as cfg
from core import webhook
from core.logger import get_logger
from core.ratelimit import TokenBucket

log = get_logger(__name__)

#: 第 1 / 2 次失败后的等待秒数（共 3 次尝试）。退避而非立刻重试：
#: 对端抖动通常是秒级的，连续猛打只会把对方彻底打死。
RETRY_DELAYS = (1.0, 3.0)

#: 队列上限。告警是「尽力送达」，满了就丢最旧的，绝不无限堆积内存
MAX_QUEUE = 500

TEST_ALERT: Dict[str, Any] = {
    "ip": "203.0.113.10",
    "level": "critical",
    "score": 95,
    "reason": "这是一条 PortGuard Webhook 测试告警",
    "geo": "测试·测试·测试",
    "local_port": 8080,
}

DoneFn = Optional[Callable[[webhook.SendResult], None]]


class NotifyService:
    """Webhook 告警发送编排（无 Qt，可单测）"""

    def __init__(self) -> None:
        # 队列元素是告警 dict；不标注泛型是因为 queue.Queue[...] 在 py3.8 上不可下标
        self._q: Any = queue.Queue(maxsize=MAX_QUEUE)
        self._bucket = TokenBucket(rate=webhook.DEFAULT_MAX_PER_MIN / 60.0, burst=1)
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        # 「已入队且还没处理完」的条数。不能用「队列空 + 正在干活」来判定空闲：
        # 工作线程是先把元素取走（队列变空）再置标志的，中间存在一个窗口，
        # 主线程正好在这时查就会误判为空闲 —— 曾让 wait_idle 提前返回、测试间歇红。
        # 计数从入队开始，到 _deliver 结束才减，窗口不存在。
        self._inflight = 0
        self._lock = threading.Lock()
        self._last_error = ""
        self.sent = 0
        self.failed = 0
        self.throttled = 0
        self.skipped = 0
        self.dropped = 0

    # ── 状态 ──
    @property
    def last_error(self) -> str:
        return self._last_error

    @property
    def pending(self) -> int:
        return self._q.qsize()

    def stats(self) -> Dict[str, int]:
        return {
            "sent": self.sent,
            "failed": self.failed,
            "throttled": self.throttled,
            "skipped": self.skipped,
            "dropped": self.dropped,
            "pending": self.pending,
        }

    # ── 设置（走内存缓存，UI 改动即时生效且零查库开销）──
    @staticmethod
    def _settings() -> Dict[str, Any]:
        try:
            return {
                "enabled": cfg.get_bool("webhook_enabled", False),
                "url": (cfg.get("webhook_url", "") or "").strip(),
                "secret": cfg.get("webhook_secret", "") or "",
                "timeout": cfg.get_float("webhook_timeout_sec", webhook.DEFAULT_TIMEOUT_SEC),
                "min_level": (
                    cfg.get("webhook_min_level", webhook.DEFAULT_MIN_LEVEL) or ""
                ).strip(),
                "max_per_min": cfg.get_int("webhook_max_per_min", webhook.DEFAULT_MAX_PER_MIN),
                "verify_ssl": cfg.get_bool("webhook_verify_ssl", True),
                "allow_http": cfg.get_bool("webhook_allow_http", False),
            }
        except Exception:
            log.exception("读取 Webhook 设置失败，本次不发送")
            return {
                "enabled": False,
                "url": "",
                "secret": "",
                "timeout": webhook.DEFAULT_TIMEOUT_SEC,
                "min_level": webhook.DEFAULT_MIN_LEVEL,
                "max_per_min": webhook.DEFAULT_MAX_PER_MIN,
                "verify_ssl": True,
                "allow_http": False,
            }

    # ── 入口：入队即返回 ──
    def send(self, alert: Dict) -> bool:
        """
        把一条告警交给后台线程。返回 True 只表示「已接受」，不保证送达。

        未启用 / 未配地址 / 低于级别门槛 → 直接返回 False（静默）。
        """
        s = self._settings()
        if not s["enabled"] or not s["url"]:
            return False
        if webhook.level_rank(alert.get("level")) < webhook.level_rank(s["min_level"]):
            self.skipped += 1
            return False
        try:
            self._q.put_nowait(dict(alert))
        except queue.Full:
            self.dropped += 1
            log.warning("Webhook 队列已满（%d），丢弃一条告警", MAX_QUEUE)
            return False
        with self._lock:
            self._inflight += 1
        self._ensure_worker()
        return True

    def test(self, overrides: Optional[Dict[str, Any]] = None, on_done: DoneFn = None) -> bool:
        """
        发一条测试告警。用 overrides 传入表单当前值，
        这样「没点保存」也能验证配置是否正确。

        结果通过回调返回（回调在后台线程触发，UI 侧请用 Qt 信号转回主线程）。
        """
        s = self._settings()
        if overrides:
            s.update({k: v for k, v in overrides.items() if v is not None})
        if not s["url"]:
            self._report(on_done, webhook.SendResult(False, "invalid", 0, "请先填写 Webhook 地址"))
            return False

        def work() -> None:
            payload = webhook.build_payload(TEST_ALERT)
            try:
                res = self._post(payload, s)
            except Exception as e:  # 兜底：测试按钮不能把线程炸了还让用户等
                res = webhook.SendResult(False, "network", 0, str(e))
            self._report(on_done, res)

        threading.Thread(target=work, daemon=True, name="notify-test").start()
        return True

    # ── 后台线程 ──
    def _ensure_worker(self) -> None:
        with self._lock:
            t = self._thread
            if t is not None and t.is_alive():
                return
            self._stop.clear()
            t = threading.Thread(target=self._loop, daemon=True, name="notify-webhook")
            self._thread = t
        t.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                alert = self._q.get(timeout=0.5)
            except queue.Empty:
                continue
            try:
                self._deliver(alert)
            except Exception:
                log.exception("处理 Webhook 告警异常")
            finally:
                self._q.task_done()
                with self._lock:
                    self._inflight -= 1

    def _deliver(self, alert: Dict) -> None:
        s = self._settings()
        if not s["enabled"] or not s["url"]:
            return
        # 限流：自采通道一次扫描能瞬间产生几十条事件，必须挡住
        self._bucket.configure(rate=max(0.1, float(s["max_per_min"]) / 60.0), burst=1)
        if not self._bucket.allow("webhook"):
            self.throttled += 1
            log.debug(
                "Webhook 触发限流（%s 条/分钟），本次丢弃：%s", s["max_per_min"], alert.get("ip")
            )
            return

        res = self._post(webhook.build_payload(alert), s)
        if res.ok:
            self.sent += 1
            self._last_error = ""
            return
        self.failed += 1
        self._last_error = res.message
        log.warning("Webhook 发送失败[%s]：%s", res.kind, res.message)

    def _post(self, payload: Dict, s: Dict[str, Any]) -> webhook.SendResult:
        """带重试退避的一次投递。地址不合法 / 4xx 不重试（重试也没用）"""
        res = webhook.SendResult(False, "invalid", 0, "未发送")
        for attempt in range(len(RETRY_DELAYS) + 1):
            res = webhook.send(
                url=s["url"],
                payload=payload,
                secret=s["secret"],
                timeout=s["timeout"],
                verify_ssl=bool(s["verify_ssl"]),
                allow_http=bool(s["allow_http"]),
            )
            if res.ok:
                return res
            if res.kind == "invalid":
                break
            if res.kind == "http" and 400 <= res.status < 500:
                break
            if attempt < len(RETRY_DELAYS):
                time.sleep(RETRY_DELAYS[attempt])
        return res

    # ── 生命周期 ──
    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        t = self._thread
        if t is not None and t.is_alive():
            t.join(timeout)
        with self._lock:
            self._thread = None

    def wait_idle(self, timeout: float = 5.0) -> bool:
        """
        等到「队列里没有、也没有正在处理的」为止（测试与退出前用）。超时返回 False。

        只看 _inflight 就够：每入队一条就 +1，处理完才 -1，
        所以「已取走但还没处理」这段时间计数恒 ≥ 1，不会出现提前返回。
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                inflight = self._inflight
            if inflight == 0 and self._q.empty():
                return True
            time.sleep(0.005)
        return False

    @staticmethod
    def _report(on_done: DoneFn, res: webhook.SendResult) -> None:
        if on_done is None:
            return
        try:
            on_done(res)
        except Exception:
            log.exception("Webhook 结果回调失败")


# 全局单例
_service: Optional[NotifyService] = None
_service_lock = threading.Lock()


def get_service() -> NotifyService:
    global _service
    if _service is None:
        with _service_lock:
            if _service is None:
                _service = NotifyService()
    return _service
