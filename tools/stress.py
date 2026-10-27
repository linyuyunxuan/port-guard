"""PortGuard 稳定性压测（离屏，可重复跑）

回答验收清单里的三条硬指标：

    · 事件页刷新：200 行 < 100ms、2000 行 < 800ms（S1 改完的复测）
    · 攻击期：1 秒灌 200 条风险事件，界面仍能响应（心跳最大间隔）、CPU < 30%
    · 浸泡：持续灌事件时内存 / 数据库 / WAL 不失控

用法（开发栈）：

    python tools/stress.py refresh
    python tools/stress.py flood --seconds 60 --rate 200
    python tools/stress.py soak --seconds 300 --rate 10
    python tools/stress.py all --report ../docs/压测报告.md

三条设计约定：

1. **数据落在临时目录**，绝不碰 `port-guard/data` 里的真库与离线库
   （`core.config.project_dir` 在导入业务模块之前换成临时目录）。
2. **不启动真实采集**：建完窗口立刻 `port_watcher.stop_watcher()`，事件全部由
   本脚本按指定速率注入，否则量到的是「本机有没有人扫」而不是「代码扛不扛」。
3. **心跳用定时器而不是计时器**：16ms 的 `QTimer` 记录实际触发间隔，最大间隔就是
   用户感受到的「最长卡顿」。界面线程被占住时它必然延后，这是最贴近体感的指标。
"""

import argparse
import ctypes
import json
import os
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List

# ── 顺序很重要：先把数据目录换到临时目录，再导入会算路径的模块 ──
_TMP_ROOT = tempfile.mkdtemp(prefix="pg-stress-")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.config as _cfgmod

_cfgmod.project_dir = lambda: _TMP_ROOT

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import contextlib

from core import database
from core.event_bus import bus
from core.models import AccessRecord, GeoInfo, RiskResult, now_ms

_LEVELS = ["low", "medium", "high", "critical"]


# ═══════════════════════════════════════════════════════════
#  进程指标（不依赖 psutil）
# ═══════════════════════════════════════════════════════════
class _PMC(ctypes.Structure):
    _fields_ = [
        ("cb", ctypes.c_ulong),
        ("PageFaultCount", ctypes.c_ulong),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
_KERNEL32.GetCurrentProcess.restype = ctypes.c_void_p
try:
    _PSAPI: Any = ctypes.WinDLL("psapi")
    _PSAPI.GetProcessMemoryInfo.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(_PMC),
        ctypes.c_ulong,
    ]
    _PSAPI.GetProcessMemoryInfo.restype = ctypes.c_int
except Exception:  # 非 Windows 或 psapi 不可用：内存指标退化为 0
    _PSAPI = None


def rss_mb() -> float:
    """当前工作集（MB）。读不到就返回 0，压测不该因为指标缺失而中断。

    ⚠️ 必须显式声明 argtypes/restype：`GetCurrentProcess()` 返回的是 HANDLE，
    不声明时 ctypes 按 C int 处理，64 位下句柄被截断成 32 位 → `GetProcessMemoryInfo`
    直接返回 0，于是所有内存指标都变成 0 MB（「内存零增长」看起来像好消息，
    其实是压根没量到）。第一版压测报告就是这么被骗过去的。
    """
    try:
        if _PSAPI is None:
            return 0.0
        info = _PMC()
        info.cb = ctypes.sizeof(_PMC)
        if _PSAPI.GetProcessMemoryInfo(_KERNEL32.GetCurrentProcess(), ctypes.byref(info), info.cb):
            return info.WorkingSetSize / (1024.0 * 1024.0)
    except Exception:
        pass
    return 0.0


def dir_size_mb(path: str) -> float:
    total = 0
    for root, _dirs, files in os.walk(path):
        for name in files:
            with contextlib.suppress(OSError):
                total += os.path.getsize(os.path.join(root, name))
    return total / (1024.0 * 1024.0)


# ═══════════════════════════════════════════════════════════
#  数据准备
# ═══════════════════════════════════════════════════════════
def _rec(i: int) -> AccessRecord:
    return AccessRecord(
        ip=f"10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}",
        local_port=3389,
        path="/admin/login.php" if i % 3 else "/.env",
        event_ts=now_ms(),
        geo=GeoInfo(found=True, country="中国", province="广东", city="深圳"),
    )


def _result(i: int) -> RiskResult:
    return RiskResult(
        score=20 + (i % 80),
        level=_LEVELS[i % 4],
        matched_rules=["scan_ua_empty"],
        reason="合成事件：压测注入",
        disposition="alert",
    )


def seed_events(n: int) -> None:
    """一次性灌 n 条风险事件（直接写库，模拟「历史已堆满」的起始状态）"""
    if n <= 0:
        return
    conn = database._connect()
    try:
        for i in range(n):
            database.insert_risk_event_sql(conn, _rec(i), _result(i), None)
        conn.commit()
    finally:
        conn.close()
    print(f"  已预置 {n} 条风险事件")


# ═══════════════════════════════════════════════════════════
#  压测主体
# ═══════════════════════════════════════════════════════════
class Probe:
    """心跳探针：16ms 定时器，记录实际间隔（= 用户感知的卡顿）"""

    def __init__(self, interval_ms: int = 16) -> None:
        from qtcompat import QTimer

        self.gaps: List[float] = []
        self._last = time.monotonic()
        self._timer: Any = QTimer()
        self._timer.setInterval(interval_ms)
        self._timer.timeout.connect(self._tick)

    def _tick(self) -> None:
        now = time.monotonic()
        self.gaps.append(now - self._last)
        self._last = now

    def start(self) -> None:
        self._last = time.monotonic()
        self._timer.start()

    def stop(self) -> None:
        self._timer.stop()

    def stats(self) -> Dict[str, float]:
        if not self.gaps:
            return {"max": 0.0, "p95": 0.0, "n": 0}
        ordered = sorted(self.gaps)
        idx = max(0, int(len(ordered) * 0.95) - 1)
        return {"max": ordered[-1] * 1000, "p95": ordered[idx] * 1000, "n": len(ordered)}


def _silence_dialogs() -> None:
    """把所有 `QMessageBox` 换成记录器。

    压测是无人值守的：任何一个模态框（「归属地库加载失败」「未拦截」…）都会
    把脚本挂在 `exec()` 上直到超时 —— 表现就是「脚本跑了 5 分钟什么都没有」。
    这和 `--diag` 不带 `--quiet` 会挂死是同一类坑，处理办法也一样：先打桩。
    """
    import qtcompat

    class _Stub:
        @staticmethod
        def information(*_a: Any, **_k: Any) -> int:
            return 0

        @staticmethod
        def warning(*_a: Any, **_k: Any) -> int:
            return 0

        @staticmethod
        def critical(*_a: Any, **_k: Any) -> int:
            return 0

        @staticmethod
        def question(*_a: Any, **_k: Any) -> int:
            return 0

    qtcompat.QMessageBox = _Stub  # type: ignore[assignment]
    for name, mod in list(sys.modules.items()):
        if (name == "gui" or name.startswith("gui.")) and getattr(mod, "QMessageBox", None):
            mod.QMessageBox = _Stub  # type: ignore[attr-defined]


def _make_window():
    """离屏建主窗口：注册中文字体、装样式、停掉真实采集"""
    from gui.theme import GLOBAL_STYLE
    from qtcompat import QApplication, QFont, QtGui

    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication([])
    for font_file in ("C:/Windows/Fonts/msyh.ttc", "C:/Windows/Fonts/simhei.ttf"):
        if os.path.exists(font_file):
            QtGui.QFontDatabase.addApplicationFont(font_file)
            break
    app.setFont(QFont("Microsoft YaHei UI", 10))
    app.setStyleSheet(GLOBAL_STYLE)

    from core import port_watcher
    from gui.main_window import MainWindow

    # 主窗口一建就会 import 全部页面，此后打桩才能覆盖到它们各自的模块名
    _silence_dialogs()

    win = MainWindow()
    win.resize(1360, 860)
    win.show()
    app.processEvents()
    with contextlib.suppress(Exception):
        port_watcher.stop_watcher()
    return app, win


def _select_events_page(win) -> None:
    for btn in win.nav_buttons:
        if "事件" in btn.text():
            btn.click()
            return


_LIMIT_INDEX = {200: 0, 500: 1, 2000: 2}


def measure_refresh(app, win, rows: int, repeat: int = 3) -> Dict[str, Any]:
    """在指定条数档位下量一次 `_load` 的耗时（取中位数，避开首次冷启动）"""
    page = win.page_events
    page.limit.setCurrentIndex(_LIMIT_INDEX[rows])
    app.processEvents()

    costs: List[float] = []
    for _ in range(repeat):
        started = time.monotonic()
        page._load()
        costs.append((time.monotonic() - started) * 1000)
        app.processEvents()
    costs.sort()
    return {
        "rows": rows,
        "median_ms": round(costs[len(costs) // 2], 1),
        "all_ms": [round(c, 1) for c in costs],
    }


def run_flood(app, win, seconds: float, rate: int, rows: int) -> Dict[str, Any]:
    """按 `rate` 条/秒灌风险事件，同时量心跳 / CPU / 刷新次数 / 节流状态"""
    page = win.page_events
    page.limit.setCurrentIndex(_LIMIT_INDEX[rows])
    app.processEvents()

    refreshes: List[float] = []
    original_load = page._load

    def counted_load() -> None:
        started = time.monotonic()
        original_load()
        refreshes.append((time.monotonic() - started) * 1000)

    page._load = counted_load

    stop_flag = threading.Event()
    produced = {"n": 0}

    def producer() -> None:
        interval = 1.0 / max(1, rate)
        nxt = time.monotonic()
        i = 0
        while not stop_flag.is_set():
            bus.emit_risk({"record": _rec(i), "result": _result(i)})
            produced["n"] += 1
            i += 1
            nxt += interval
            delay = nxt - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            else:  # 生产比消费快时不要死追
                nxt = time.monotonic()

    probe = Probe()
    cpu0 = time.process_time()
    wall0 = time.monotonic()
    rss0 = rss_mb()

    thread = threading.Thread(target=producer, daemon=True, name="stress-producer")
    probe.start()
    thread.start()
    while time.monotonic() - wall0 < seconds:
        app.processEvents()
        time.sleep(0.002)
    stop_flag.set()
    thread.join(timeout=3)
    probe.stop()
    app.processEvents()

    wall = time.monotonic() - wall0
    cpu = time.process_time() - cpu0
    page._load = original_load

    beat = probe.stats()
    return {
        "seconds": round(wall, 1),
        "rate": rate,
        "rows": rows,
        "produced": produced["n"],
        "refreshes": len(refreshes),
        "refresh_ms_avg": round(sum(refreshes) / len(refreshes), 1) if refreshes else 0,
        "refresh_ms_max": round(max(refreshes), 1) if refreshes else 0,
        "heartbeat_max_ms": round(beat["max"], 1),
        "heartbeat_p95_ms": round(beat["p95"], 1),
        "cpu_pct": round(cpu / wall * 100, 1),
        "rss_start_mb": round(rss0, 1),
        "rss_end_mb": round(rss_mb(), 1),
        "auto_paused": page.auto_paused,
        "db_total_mb": round(dir_size_mb(os.path.join(_TMP_ROOT, "data")), 1),
    }


def run_soak(app, win, seconds: float, rate: int) -> Dict[str, Any]:
    """低压长时间浸泡：看内存与库体积是否单调失控"""
    samples: List[Dict[str, float]] = []
    cpu0 = time.process_time()
    wall0 = time.monotonic()
    stop_flag = threading.Event()

    def producer() -> None:
        interval = 1.0 / max(1, rate)
        i = 0
        while not stop_flag.is_set():
            rec, res = _rec(i), _result(i)
            bus.emit_access(rec)
            bus.emit_risk({"record": rec, "result": res})
            with contextlib.suppress(Exception):
                database.insert_risk_event(rec, res)
            i += 1
            time.sleep(interval)

    thread = threading.Thread(target=producer, daemon=True, name="soak-producer")
    thread.start()
    nxt = time.monotonic() + 30
    while time.monotonic() - wall0 < seconds:
        app.processEvents()
        time.sleep(0.005)
        if time.monotonic() >= nxt:
            nxt += 30
            samples.append(
                {
                    "t": round(time.monotonic() - wall0, 0),
                    "rss_mb": round(rss_mb(), 1),
                    "db_mb": round(dir_size_mb(os.path.join(_TMP_ROOT, "data")), 1),
                }
            )
    stop_flag.set()
    thread.join(timeout=3)
    app.processEvents()

    wall = time.monotonic() - wall0
    rss_values = [s["rss_mb"] for s in samples] or [rss_mb()]
    return {
        "seconds": round(wall, 1),
        "rate": rate,
        "samples": samples,
        "rss_growth_mb": round(rss_values[-1] - rss_values[0], 1),
        "cpu_pct": round((time.process_time() - cpu0) / wall * 100, 1),
        "dropped": _dropped_count(),
    }


def _dropped_count() -> int:
    """写入器丢弃计数：队列满时它会计数而不是静默丢（数据层唯一允许的失败形态）"""
    try:
        from core import db_writer

        return int(db_writer.get_writer().stats().get("dropped", 0) or 0)
    except Exception:
        return 0


# ═══════════════════════════════════════════════════════════
#  报告
# ═══════════════════════════════════════════════════════════
def _to_markdown(r: Dict[str, Any]) -> str:
    lines = ["# PortGuard 稳定性压测报告", "", "- 时间：{}".format(r.get("ts", "")), ""]
    if r.get("refresh"):
        lines += [
            "## 事件页单次刷新",
            "",
            "| 条数 | 中位数 | 各次 | 预算 | 结论 |",
            "|---|---|---|---|---|",
        ]
        for item in r["refresh"]:
            budget = 100 if item["rows"] == 200 else 800
            verdict = "通过" if item["median_ms"] <= budget else "超预算"
            each = ", ".join(str(int(c)) for c in item["all_ms"])
            lines.append(
                "| {} | {:.0f} ms | {} | <{} ms | {} |".format(
                    item["rows"], item["median_ms"], each, budget, verdict
                )
            )
        lines.append("")
    if r.get("flood"):
        f = r["flood"]
        growth = f["rss_end_mb"] - f["rss_start_mb"]
        paused = "是" if f["auto_paused"] else "否"
        lines += [
            "## 攻击期（{} 条/秒 × {:.0f}s，{} 行档位）".format(f["rate"], f["seconds"], f["rows"]),
            "",
            "| 指标 | 值 |",
            "|---|---|",
            "| 注入事件 | {} 条 |".format(f["produced"]),
            "| 实际刷新次数 | {} 次 |".format(f["refreshes"]),
            "| 单次刷新均值 / 峰值 | {:.0f} / {:.0f} ms |".format(
                f["refresh_ms_avg"], f["refresh_ms_max"]
            ),
            "| 心跳最大间隔（最长卡顿） | {:.0f} ms |".format(f["heartbeat_max_ms"]),
            "| 心跳 P95 | {:.0f} ms |".format(f["heartbeat_p95_ms"]),
            "| CPU 占用 | {:.0f}% |".format(f["cpu_pct"]),
            "| 内存 | {:.0f} → {:.0f} MB（+{:.0f} MB） |".format(
                f["rss_start_mb"], f["rss_end_mb"], growth
            ),
            f"| 自动暂停 | {paused} |",
            "",
        ]
    if r.get("soak"):
        s = r["soak"]
        lines += [
            "## 浸泡（{} 条/秒 × {:.0f}s）".format(s["rate"], s["seconds"]),
            "",
            "| 时刻 | RSS | 库体积 |",
            "|---|---|---|",
        ]
        for sample in s["samples"]:
            lines.append(
                "| {:.0f}s | {:.0f} MB | {:.0f} MB |".format(
                    sample["t"], sample["rss_mb"], sample["db_mb"]
                )
            )
        lines += [
            "",
            "- 内存增长：{:.0f} MB；CPU：{:.0f}%；写入丢弃：{} 条".format(
                s["rss_growth_mb"], s["cpu_pct"], s["dropped"]
            ),
            "",
        ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="PortGuard 稳定性压测")
    parser.add_argument("mode", choices=["refresh", "flood", "soak", "all"])
    parser.add_argument("--seconds", type=float, default=60)
    parser.add_argument("--rate", type=int, default=200)
    parser.add_argument("--rows", type=int, default=2000, choices=[200, 500, 2000])
    parser.add_argument("--seed", type=int, default=2000, help="预置事件条数")
    parser.add_argument("--report", default="")
    args = parser.parse_args()

    print(f"临时数据目录：{_TMP_ROOT}")
    database.init_db()
    from core import settings as cfg

    cfg.warm()
    # 关掉所有「会自动跑起来」的东西：离线库同步会真的去下载 10MB（还带重试），
    # 声音会占住音频设备 —— 这两样都会把压测结果污染成「网络慢」和「什么都没量到」。
    # 告警弹窗已取消（2026-10-27），没有需要关的模态窗口了。
    cfg.set("alert_sound", "0", persist=False)  # 压测机上别真的响
    cfg.set("xdb_auto_sync", "0", persist=False)
    cfg.set("xdb_sync_on_start", "0", persist=False)
    cfg.set("auto_mode", "0", persist=False)  # 别让合成事件触发自动封禁

    result: Dict[str, Any] = {"mode": args.mode, "ts": time.strftime("%Y-%m-%d %H:%M:%S")}
    app, win = _make_window()
    _select_events_page(win)
    seed_events(args.seed)
    app.processEvents()

    try:
        if args.mode in ("refresh", "all"):
            result["refresh"] = [measure_refresh(app, win, rows) for rows in (200, 500, 2000)]
        if args.mode in ("flood", "all"):
            result["flood"] = run_flood(app, win, args.seconds, args.rate, args.rows)
        if args.mode in ("soak", "all"):
            result["soak"] = run_soak(app, win, args.seconds, 10)
    finally:
        try:
            from core import db_writer

            db_writer.stop_writer(timeout=5)
        except Exception:
            pass
        win.close()
        app.processEvents()

    print(json.dumps(result, ensure_ascii=False, indent=2))
    if args.report:
        with open(args.report, "w", encoding="utf-8", newline="") as fh:
            fh.write(_to_markdown(result))
        print(f"报告已写入：{args.report}")

    # 进度门槛：只提示，不让脚本因为「慢」而失败（慢本身就是结论）
    ok = True
    for item in result.get("refresh", []):
        limit = 100 if item["rows"] == 200 else 800
        if item["median_ms"] > limit:
            ok = False
            print(
                "✗ 刷新超预算：{} 行 {:.0f}ms > {}ms".format(item["rows"], item["median_ms"], limit)
            )
    flood = result.get("flood") or {}
    if flood:
        if flood["heartbeat_max_ms"] > 1200:
            ok = False
            print(
                "✗ 攻击期最长卡顿 {:.0f}ms（>1.2s 用户会认为界面死了）".format(
                    flood["heartbeat_max_ms"]
                )
            )
        if flood["cpu_pct"] > 30:
            ok = False
            print("✗ 攻击期 CPU {:.0f}%（>30%）".format(flood["cpu_pct"]))
    print("RESULT: {}".format("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
