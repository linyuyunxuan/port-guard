"""
PortGuard — 轻量令牌桶限流

单进程内存实现，零依赖。用于上报接口防刷：
- 默认按「来源 IP」限流；也可按固定 key 做全局限流
- 桶数量超过阈值时按「最后访问时间」淘汰，防止被大量伪造 IP 打爆内存
"""

import threading
import time
from typing import Dict, Optional, Tuple

from core.logger import get_logger

log = get_logger(__name__)


class TokenBucket:
    """按 key 限流的令牌桶"""

    def __init__(
        self, rate: float = 200.0, burst: int = 500, max_keys: int = 10000, ttl: float = 120.0
    ):
        self._rate = max(0.1, float(rate))  # 每秒补充令牌数
        self._burst = max(1, int(burst))  # 桶容量
        self._max_keys = max(100, int(max_keys))
        self._ttl = max(10.0, float(ttl))
        self._buckets: Dict[str, Tuple[float, float]] = {}
        self._lock = threading.Lock()
        self.rejected = 0

    def configure(self, rate: Optional[float] = None, burst: Optional[int] = None) -> None:
        with self._lock:
            if rate is not None:
                self._rate = max(0.1, float(rate))
            if burst is not None:
                self._burst = max(1, int(burst))

    @property
    def rate(self) -> float:
        return self._rate

    @property
    def burst(self) -> int:
        return self._burst

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (float(self._burst), now))
            tokens = min(float(self._burst), tokens + (now - last) * self._rate)
            if tokens < 1.0:
                self._buckets[key] = (tokens, now)
                self.rejected += 1
                return False
            self._buckets[key] = (tokens - 1.0, now)
            if len(self._buckets) > self._max_keys:
                self._evict_locked(now)
            return True

    def _evict_locked(self, now: float) -> None:
        """按最后访问时间淘汰过期桶（调用方已持锁）"""
        cutoff = now - self._ttl
        stale = [k for k, v in self._buckets.items() if v[1] < cutoff]
        for k in stale:
            self._buckets.pop(k, None)
        if len(self._buckets) > self._max_keys:
            # 仍然过多：直接按最后访问时间丢掉最旧的一半
            items = sorted(self._buckets.items(), key=lambda kv: kv[1][1])
            for k, _ in items[: len(items) // 2]:
                self._buckets.pop(k, None)
            log.warning("限流桶数量超限，已强制淘汰至 %d", len(self._buckets))

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()

    def stats(self) -> Dict:
        with self._lock:
            return {
                "keys": len(self._buckets),
                "rejected": self.rejected,
                "rate": self._rate,
                "burst": self._burst,
            }
