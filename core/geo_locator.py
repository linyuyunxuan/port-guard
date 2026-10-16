"""
PortGuard — IP 归属地查询（基于 vendored 的 ip2region Python 客户端）

关键点：
- 启动时一次性 verify xdb，整库读入内存后用 new_with_buffer 构造 Searcher
- buffer 模式的 Searcher 是无状态的（read 只做内存切片），可跨线程安全共享
- v4 / v6 自动分流
- 线程安全 LRU 缓存原始 region 字符串
- **支持热换库**：在线同步下载完成后调用 reload()，把新库整库载入内存后
  原子替换旧 searcher，无需重启进程
- 任何异常都兜底为「未知」，绝不把异常抛给 HTTP 层
"""

import ipaddress
import os
import threading
import time
from collections import OrderedDict
from typing import Optional, Tuple

from core.config import v4_xdb_path, v6_xdb_path
from core.logger import get_logger
from core.models import GeoInfo
from ip2region import searcher as xdb
from ip2region import util as ip2util

log = get_logger(__name__)


def get_int_setting_safe(key: str, default: int) -> int:
    try:
        from core import settings as cfg

        return cfg.get_int(key, default)
    except Exception:
        return default


class GeoLocator:
    def __init__(
        self, v4_path: str | None = None, v6_path: str | None = None, cache_size: int = 20000
    ):
        self._lock = threading.Lock()
        self._reload_lock = threading.Lock()
        self._cache: OrderedDict[str, str] = OrderedDict()
        self._cache_size = max(1000, int(cache_size))
        self._v4 = None
        self._v6 = None
        self._v4_path = v4_path or v4_xdb_path()
        self._v6_path = v6_path or v6_xdb_path()
        self._load_error = ""
        self._loaded_at = 0.0
        self.generation = 0  # 换库代数，用于 UI 提示
        self.stats = {"hit": 0, "miss": 0, "error": 0}
        self.load()

    # ── 加载 ──
    def load(self) -> bool:
        ok = True
        errs = []
        v4 = v6 = None
        try:
            v4 = self._build(self._v4_path, ip2util.IPv4)
        except Exception as e:
            ok = False
            errs.append(f"IPv4 库加载失败: {e}")
            log.exception("IPv4 库加载失败：%s", self._v4_path)
        try:
            v6 = self._build(self._v6_path, ip2util.IPv6)
        except Exception as e:
            ok = False
            errs.append(f"IPv6 库加载失败: {e}")
            log.exception("IPv6 库加载失败：%s", self._v6_path)

        self._v4, self._v6 = v4, v6
        self._load_error = " | ".join(errs)
        if ok:
            self._loaded_at = time.time()
            log.info(
                "定位库加载完成：v4=%s（%.1f MB） v6=%s（%.1f MB）",
                os.path.basename(self._v4_path),
                _mb(self._v4_path),
                os.path.basename(self._v6_path),
                _mb(self._v6_path),
            )
        return ok

    def reload(self, v4_path: str | None = None, v6_path: str | None = None) -> Tuple[bool, str]:
        """
        热换库：重新载入 xdb 并原子替换 searcher，同时清空归属地缓存。
        不重启进程、不打断正在处理的上报（新老 searcher 都是纯内存只读对象）。

        返回 (成功, 错误信息)
        """
        with self._reload_lock:
            if v4_path:
                self._v4_path = v4_path
            if v6_path:
                self._v6_path = v6_path

            # 先在局部变量里构建，全部成功后才赋值 —— 失败时旧库继续可用
            new_v4 = self._v4
            new_v6 = self._v6
            errs = []
            try:
                new_v4 = self._build(self._v4_path, ip2util.IPv4)
            except Exception as e:
                errs.append(f"IPv4 库加载失败: {e}")
                log.exception("热换库：IPv4 加载失败")
            try:
                new_v6 = self._build(self._v6_path, ip2util.IPv6)
            except Exception as e:
                errs.append(f"IPv6 库加载失败: {e}")
                log.exception("热换库：IPv6 加载失败")

            if errs:
                self._load_error = " | ".join(errs)
                return False, self._load_error

            self._v4, self._v6 = new_v4, new_v6
            self._load_error = ""
            self._loaded_at = time.time()
            self.generation += 1
            self.cache_clear()
            log.info(
                "定位库热换完成（第 %d 代）：v4=%.1fMB v6=%.1fMB",
                self.generation,
                _mb(self._v4_path),
                _mb(self._v6_path),
            )
            return True, ""

    @staticmethod
    def _build(path: str, version):
        if not path:
            raise FileNotFoundError("xdb 路径为空")
        if not os.path.exists(path):
            raise FileNotFoundError(f"xdb 文件不存在: {path}")
        # 只校验一次，之后不再调用（避免拖慢查询）
        ip2util.verify_from_file(path)
        buf = ip2util.load_content_from_file(path)
        return xdb.new_with_buffer(version, buf)

    @property
    def available(self) -> bool:
        return self._v4 is not None or self._v6 is not None

    @property
    def load_error(self) -> str:
        return self._load_error

    @property
    def v4_available(self) -> bool:
        return self._v4 is not None

    @property
    def v6_available(self) -> bool:
        return self._v6 is not None

    # ── 查询 ──
    def lookup(self, ip: str) -> GeoInfo:
        geo = GeoInfo(ip=ip)
        if not ip:
            return geo

        raw = self._cache_get(ip)
        if raw is None:
            self.stats["miss"] += 1
            try:
                addr = ipaddress.ip_address(ip)
                if addr.version == 4:
                    raw = (self._v4.search(ip) or "") if self._v4 else ""
                else:
                    raw = (self._v6.search(ip) or "") if self._v6 else ""
            except Exception:
                self.stats["error"] += 1
                raw = ""
            self._cache_put(ip, raw)
        else:
            self.stats["hit"] += 1

        return self._parse(ip, raw)

    @staticmethod
    def _parse(ip: str, region: str) -> GeoInfo:
        if not region:
            return GeoInfo(ip=ip, found=False)
        parts = region.split("|")
        parts += [""] * (5 - len(parts))
        country, province, city, isp, iso = parts[:5]
        return GeoInfo(
            ip=ip,
            country=country.strip(),
            province=province.strip(),
            city=city.strip(),
            isp=isp.strip(),
            iso=iso.strip().upper(),
            found=True,
        )

    @staticmethod
    def is_china(geo: Optional[GeoInfo]) -> bool:
        return bool(geo and geo.is_china)

    # ── 线程安全 LRU ──
    def _cache_get(self, ip: str):
        with self._lock:
            v = self._cache.get(ip)
            if v is not None:
                self._cache.move_to_end(ip)
            return v

    def _cache_put(self, ip: str, raw: str) -> None:
        with self._lock:
            self._cache[ip] = raw
            while len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)

    def cache_clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def set_cache_size(self, n: int) -> None:
        with self._lock:
            self._cache_size = max(1000, int(n))
            while len(self._cache) > self._cache_size:
                self._cache.popitem(last=False)

    def cache_info(self) -> dict:
        with self._lock:
            return {"size": len(self._cache), "capacity": self._cache_size, **self.stats}

    def library_info(self) -> dict:
        """当前生效的库信息（含文件指纹与同步清单），供 UI 展示"""
        info = {
            "generation": self.generation,
            "loaded_at": int(self._loaded_at * 1000) if self._loaded_at else 0,
            "v4": _file_info(self._v4_path),
            "v6": _file_info(self._v6_path),
        }
        try:
            from core.xdb_updater import get_manifest

            info["manifest"] = get_manifest()
        except Exception:
            info["manifest"] = {}
        return info


def _mb(path: str) -> float:
    try:
        return os.path.getsize(path) / 1024 / 1024
    except Exception:
        return 0.0


def _file_info(path: str) -> dict:
    d = {"path": path, "name": os.path.basename(path or ""), "size": 0, "mtime": 0, "exists": False}
    try:
        st = os.stat(path)
        d.update(size=st.st_size, mtime=int(st.st_mtime * 1000), exists=True)
    except Exception:
        pass
    return d


# ── 全局单例 ──
_locator: Optional[GeoLocator] = None
_locator_lock = threading.Lock()


def get_locator() -> GeoLocator:
    global _locator
    if _locator is None:
        with _locator_lock:
            if _locator is None:
                _locator = GeoLocator(cache_size=get_int_setting_safe("geo_cache_size", 20000))
    return _locator


def set_locator(loc) -> None:
    """供测试或重载时替换单例"""
    global _locator
    _locator = loc


def reload_locator() -> Tuple[bool, str]:
    """热换库入口（供在线同步完成后调用）"""
    loc = get_locator()
    ok, err = loc.reload()
    return ok, err
