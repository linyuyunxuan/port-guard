"""
PortGuard — 离线库在线同步调度（不依赖 Qt）

职责：
- 把「探测/下载」放在后台线程执行，绝不阻塞界面
- 按设置决定是否该自动同步（间隔 + 启动检查 + 是否自动下载）
- 通过事件总线把进度推给 UI（worker 线程只投队列，不碰控件）

界面侧只需要：QTimer 定期调 `maybe_auto()`，并把 `bus.drain_xdb()` 的内容渲染出来。
"""
import threading
import time
from typing import Callable, Optional

from core import settings as cfg
from core import xdb_updater
from core.logger import get_logger

log = get_logger(__name__)

DoneFn = Optional[Callable[[object], None]]


class XdbSyncService:
    def __init__(self):
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._last_error = ""

    # ── 状态 ──
    @property
    def busy(self) -> bool:
        return xdb_updater.is_updating() or bool(self._thread and self._thread.is_alive())

    @property
    def last_error(self) -> str:
        return self._last_error

    # ── 后台任务 ──
    def _spawn(self, target, on_done: DoneFn) -> bool:
        with self._lock:
            if self.busy:
                log.info("已有离线库同步任务在执行，忽略本次请求")
                return False
            t = threading.Thread(target=target, daemon=True, name="xdb-sync")
            self._thread = t
        t.start()
        return True

    def check_async(self, on_done: DoneFn = None, auto: bool = False) -> bool:
        """后台探测线上版本（只发几百字节请求，不下载）"""

        def work():
            try:
                res = xdb_updater.check()
                self._last_error = "" if res.ok else res.message
            except Exception as e:
                log.exception("离线库探测异常")
                self._last_error = str(e)
                res = None
            if on_done:
                try:
                    on_done(res)
                except Exception:
                    log.exception("离线库探测回调失败")

        return self._spawn(work, on_done)

    def update_async(self, force: bool = False, on_done: DoneFn = None) -> bool:
        """后台执行完整同步（下载 + 校验 + 热换库 + 回滚）"""

        def work():
            try:
                res = xdb_updater.update(force=force)
                self._last_error = "" if res.ok else res.message
            except Exception as e:
                log.exception("离线库同步异常")
                self._last_error = str(e)
                res = None
            if on_done:
                try:
                    on_done(res)
                except Exception:
                    log.exception("离线库同步回调失败")

        return self._spawn(work, on_done)

    # ── 自动策略 ──
    def should_check(self) -> bool:
        """是否到了该自动探测的时间点"""
        if not cfg.get_bool("xdb_auto_sync", True):
            return False
        interval_h = max(1, cfg.get_int("xdb_sync_interval_hours", 24))
        last = cfg.get_int("xdb_last_check_at", 0)
        if last <= 0:
            return True
        return (time.time() * 1000 - last) >= interval_h * 3600 * 1000

    def maybe_auto(self, on_done: DoneFn = None, first_run: bool = False) -> bool:
        """
        被定时器反复调用：
        - 首次启动时看 xdb_sync_on_start
        - 之后按 xdb_sync_interval_hours 判断
        发现更新且允许自动下载时直接下载，否则只探测并提示。
        """
        if self.busy:
            return False
        if first_run:
            if not cfg.get_bool("xdb_sync_on_start", True):
                return False
        elif not self.should_check():
            return False
        if not cfg.get_bool("xdb_auto_sync", True) and not first_run:
            return False

        auto_download = cfg.get_bool("xdb_auto_download", True)

        def work():
            try:
                # 注意：两个分支返回的是不同结构（UpdateResult / CheckResult），
                # 早先共用一个变量在类型上会混淆，这里显式归一化后再用。
                if auto_download:
                    upd = xdb_updater.update()
                    ok, message = upd.ok, upd.message
                else:
                    chk = xdb_updater.check()
                    ok, message = chk.ok, chk.message
                    try:
                        from core.event_bus import bus
                        bus.emit_xdb({"stage": "checked", "message": chk.message,
                                      "percent": 100, "has_update": chk.has_update})
                    except Exception:
                        log.exception("投递离线库探测事件失败")
                self._last_error = "" if ok else (message or "未知错误")
            except Exception as e:
                log.exception("自动同步离线库失败")
                self._last_error = str(e)
                ok, message = False, str(e)
            if on_done:
                try:
                    on_done({"ok": ok, "message": message})
                except Exception:
                    log.exception("自动同步回调失败")

        return self._spawn(work, on_done)

    def summary(self) -> dict:
        try:
            d = xdb_updater.status_summary()
            d["busy"] = self.busy
            return d
        except Exception:
            log.exception("读取离线库状态摘要失败")
            return {"files": {}, "busy": self.busy}


# 全局单例
_service: Optional[XdbSyncService] = None
_service_lock = threading.Lock()


def get_service() -> XdbSyncService:
    global _service
    if _service is None:
        with _service_lock:
            if _service is None:
                _service = XdbSyncService()
    return _service
