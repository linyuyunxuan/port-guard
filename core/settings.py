"""
PortGuard — 设置读取缓存

为什么需要：原实现每次上报会读 3 次 settings 表（_check_key / auto_mode /
auto_ban_threshold），实测 17.8 ms/条 的无谓开销；而设置几乎从不在运行中变化。

策略：进程内字典缓存 + 写时失效。
- `warm()`   启动时全量预热一次
- `get/set`  走缓存；set 同时落库并更新缓存
- `invalidate()` 外部直接改了库（如迁移脚本）时强制重载
- 线程安全（RLock）

注意：`core.database` 只保留原始读写，业务层统一走本模块。
"""

import threading
from typing import Dict, Mapping, Optional, Tuple

from core import database

_lock = threading.RLock()
_cache: Dict[str, str] = {}
_warmed = False

# ── 数值型设置的合法区间（闭区间，P2-2）──
#
# 为什么在读取层夹：设置表的 value 是 TEXT，手工改库 / 老版本 bug / 恢复了别人
# 导出的库，都可能写入「保留期 0 天」（启动即删光日志）或「阈值 -5」（每个
# 连接都算风险）这类脏值。读取层夹回合法范围是最靠近消费者的最后一道闸，
# 比在每个调用点各写一遍 max/min 可靠得多。
#
# 注意边界语义（改范围前先核对 tests/）：
# - 封禁时长 0 = 「永久」（ban_service.prepare 的既有约定），min 必须是 0；
# - 时长上限与 MAX_BAN_SECONDS（365 天）对齐，超长值由 ban_service 再夹一次；
# - 时间戳类键（xdb_last_check_at 等）**不登记**——它们是动态值，不该被夹。
_NUMERIC_RANGES: Dict[str, Tuple[float, float]] = {
    "auto_ban_threshold": (0, 100),
    "default_ban_duration_sec": (0, 365 * 86400),
    "ban_duration_critical_sec": (0, 365 * 86400),
    "ban_duration_high_sec": (0, 365 * 86400),
    "ban_duration_medium_sec": (0, 365 * 86400),
    "ban_duration_low_sec": (0, 365 * 86400),
    "max_ban_duration_sec": (60, 365 * 86400),
    "ban_escalation_factor": (1, 1000),
    "ban_escalation_max_sec": (60, 365 * 86400),
    "repeat_blacklist_hits": (1, 10000),
    "alert_merge_sec": (0, 86400),
    "log_retention_days": (1, 3650),
    "risk_retention_days": (1, 3650),
    "ban_retention_days": (1, 3650),
    "audit_retention_days": (1, 3650),
    "maintenance_hour": (0, 23),
    "monitor_buffer_size": (100, 10_000_000),
    "geo_cache_size": (1000, 10_000_000),
    "watch_interval_sec": (1.0, 86400.0),
    "watch_dedupe_sec": (0, 86400),
    "xdb_sync_interval_hours": (1, 8760),
    "log_view_max_lines": (200, 1_000_000),
    "log_view_tail_ms": (200, 3_600_000),
    "rate_limit_per_sec": (1, 1_000_000),
}


def _clamp_range(key: str, value: float) -> float:
    rng: Optional[Tuple[float, float]] = _NUMERIC_RANGES.get(key)
    if rng is None:
        return value
    lo, hi = rng
    if value < lo:
        return lo
    if value > hi:
        return hi
    return value


def warm() -> int:
    """启动时全量预热，返回载入条目数"""
    global _warmed
    with _lock:
        try:
            _cache.clear()
            _cache.update(database.get_all_settings())
        except Exception:
            pass
        _warmed = True
        return len(_cache)


def invalidate() -> None:
    """清空缓存，下次 get 触发单条回源"""
    global _warmed
    with _lock:
        _cache.clear()
        _warmed = False


def get(key: str, default: str = "") -> str:
    with _lock:
        if key in _cache:
            return _cache[key]
    # 缓存未命中：回源一次。
    # 只有「库里确实存在这个键」才回填缓存 —— 若把调用方传进来的 default
    # 当作值缓存，之后换一个 default 再取就会拿到上一次的 default
    # （曾导致 get_bool(k, True) 之后 get_float(k, 1.5) 读到 1 而不是 1.5）。
    try:
        v = database.get_setting_optional(key)
    except Exception:
        v = None
    if v is None:
        return default
    with _lock:
        _cache[key] = v
    return v


def get_int(key: str, default: int = 0) -> int:
    try:
        v = int(str(get(key, str(default))).strip())
    except (TypeError, ValueError):
        return default
    # 登记过区间的键夹回合法范围（P2-2）；未登记的键原样返回
    return int(_clamp_range(key, v))


def get_float(key: str, default: float = 0.0) -> float:
    try:
        v = float(str(get(key, str(default))).strip())
    except (TypeError, ValueError):
        return default
    return _clamp_range(key, v)


def get_bool(key: str, default: bool = False) -> bool:
    v = str(get(key, "1" if default else "0")).strip().lower()
    return v in ("1", "true", "yes", "on")


def set(key: str, value, persist: bool = True) -> None:
    """写设置：先更缓存（UI 立即读到新值），再落库"""
    sv = str(value)
    with _lock:
        _cache[key] = sv
    if persist:
        try:
            database.set_setting(key, sv)
        except Exception:
            from core.logger import get_logger

            get_logger(__name__).exception("写入设置失败 key=%s", key)


def set_many(items: Mapping[str, object]) -> None:
    """批量写入。签名用 Mapping 而不是 Dict：Dict 的值类型是不变的（invariant），
    传 `Dict[str, int]` 给 `Dict[str, object]` 会被类型检查器拒绝 —— 而调用方
    手里拿的往往就是具体类型的字典。"""
    for k, v in items.items():
        set(k, v)


def snapshot() -> Dict[str, str]:
    with _lock:
        return dict(_cache)


def is_warmed() -> bool:
    return _warmed
