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
from typing import Dict

from core import database

_lock = threading.RLock()
_cache: Dict[str, str] = {}
_warmed = False


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
        return int(str(get(key, str(default))).strip())
    except (TypeError, ValueError):
        return default


def get_float(key: str, default: float = 0.0) -> float:
    try:
        return float(str(get(key, str(default))).strip())
    except (TypeError, ValueError):
        return default


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


def set_many(items: Dict[str, object]) -> None:
    for k, v in items.items():
        set(k, v)


def snapshot() -> Dict[str, str]:
    with _lock:
        return dict(_cache)


def is_warmed() -> bool:
    return _warmed
