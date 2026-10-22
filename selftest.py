"""
PortGuard 端到端自检（离屏运行，不需要显示器）

用途：在真实数据目录上跑一遍「启动 → 上报 → 落库 → 界面 → HTTP → 停止」，
用来在打包/交付前确认整条链路没有断。与 pytest 的分工：
- pytest：隔离环境 + 大量边界与安全回归用例（CI 门禁）
- selftest：真实环境 + 精简主链路（交付前人工/流水线冒烟）

注意：本脚本会写入真实 data/ 目录（数据库、日志），但**不会**创建任何防火墙
规则 —— 封禁只跑到 prepare() 的校验阶段就停。
"""

import os
import sys
import time
from typing import Any, List

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_failures: List[str] = []


def check(label: str, ok: bool, detail: str = "") -> None:
    print(f"{'  OK ' if ok else ' FAIL'} {label}{(' — ' + detail) if detail else ''}", flush=True)
    if not ok:
        _failures.append(label)


from qtcompat import QApplication, QTimer

app = QApplication(sys.argv)

# ── 1. 后端初始化（与 main.py 完全同一条路径）──
import main as app_main
from core import db_writer, xdb_updater
from core import settings as cfg
from core.config import APP_VERSION
from core.database import count_today, query_access_logs, query_risk_events
from core.geo_locator import get_locator
from core.models import STATUS_PENDING, AccessRecord
from core.rule_engine import get_engine

app_main._init_backend()
check("后端初始化（日志/数据库/设置缓存/批量写入器）", cfg.is_warmed())
check("APP_VERSION", APP_VERSION == "1.4.1", APP_VERSION)

# 自检期间必须关掉自动封禁与弹窗告警：本脚本会喂入「恶意样本」，
# 若开着自动封禁、又恰好以管理员身份运行，就会真的往系统防火墙上写规则。
_backup = {k: cfg.get(k) for k in ("auto_mode", "alert_popup_level", "alert_sound")}
cfg.set("auto_mode", "0")
cfg.set("alert_popup_level", "none")
cfg.set("alert_sound", "0")
check(
    "自检已切到无副作用模式（不自动封禁）",
    cfg.get("auto_mode") == "0",
    f"原值 auto_mode={_backup['auto_mode']!r}，结束后会还原",
)

# ── 2. 设置缓存 ──
n_before = len(cfg.snapshot())
for _ in range(200):
    cfg.get_int("rate_limit_per_sec", 300)
check("设置缓存预热且热点读取不回源", len(cfg.snapshot()) == n_before, f"{n_before} 项")

# ── 3. 离线定位库 ──
loc = get_locator()
check("定位库加载", loc.available, loc.load_error or "")
geo_cn = loc.lookup("113.118.113.77")
check("国内 IP 定位", geo_cn.found and geo_cn.is_china, geo_cn.display)
lib = loc.library_info()
check(
    "离线库文件信息（v4/v6 均存在）",
    lib["v4"]["exists"] and lib["v6"]["exists"],
    f"v4={lib['v4']['size'] / 1048576:.1f}MB v6={lib['v6']['size'] / 1048576:.1f}MB "
    f"gen={lib['generation']}",
)

# 在线同步状态（只读，不触发下载）
st = xdb_updater.status_summary()
check(
    "离线库在线同步模块可用",
    set(st["files"].keys()) == {"ip2region_v4.xdb", "ip2region_v6.xdb"},
    f"auto_sync={st['auto_sync']} interval={st['interval_hours']}h",
)

# ── 4. 采集记录处理 + 批量落库（与本机观察器同一条链路）──
from core.pipeline import process_record

n_acc_before = len(query_access_logs(1000))

t0 = time.perf_counter()
r1 = process_record(
    AccessRecord(
        ip="113.118.113.77",
        local_port=3000,
        protocol="tcp",
        method="GET",
        path="/api/products",
        status_code=200,
        user_agent="Mozilla/5.0 (Windows NT 10.0)",
        size=1024,
        tags={"channel": "table"},
    ),
    allow_auto_ban=False,
    actor="system",
)
check(
    "正常访问判定",
    r1.level == "normal" and r1.suggest_ban is False,
    f"score={r1.score} disposition={r1.disposition}",
)

r2 = process_record(
    AccessRecord(
        ip="45.33.32.156",
        local_port=8080,
        protocol="http",
        method="POST",
        path="/admin/login",
        status_code=401,
        user_agent="sqlmap/1.7",
        size=512,
        tags={"channel": "table"},
    ),
    allow_auto_ban=False,
    actor="system",
)
check(
    "恶意访问判定（单次只告警，不封禁）",
    r2.score >= 45 and "scanner_ua" in r2.matched_rules,
    f"score={r2.score} level={r2.level} rules={r2.matched_rules}",
)

check("批量写入排空", db_writer.get_writer().flush(timeout=5))
n_acc_after = len(query_access_logs(1000))
check(
    "上报已落库（批量写入器）",
    n_acc_after >= n_acc_before + 2,
    f"{n_acc_before} → {n_acc_after}，写入器 {db_writer.get_writer().stats()}",
)

# ── 5. 主窗口与各页面 ──
from gui.main_window import PAGE_LOGS, PAGE_SETTINGS, MainWindow
from gui.region_rules import new_rule_id

win = MainWindow()
check("MainWindow 构建", win is not None)
# 离屏模式下必须真正 show()，否则页面 isVisible() 恒为 False，
# page_logs.append_access 会走「只进缓冲、不渲染」分支，访问行进不了界面文档
win.show()
app.processEvents()

# 导航按钮真实点击（PySide2 回归锁）：shiboken2 会把「带默认参数的 lambda」槽
# 按 0 参调用，点击全部失灵且错误只进看不见的 stderr —— 必须逐颗点一遍
_nav_bad = []
for _i, _btn in enumerate(win.nav_buttons):
    _btn.click()
    app.processEvents()
    if win.stack.currentIndex() != _i:
        _nav_bad.append(f"按钮{_i}→页{win.stack.currentIndex()}")
check(
    "导航按钮点击可切页",
    not _nav_bad,
    ";".join(_nav_bad) if _nav_bad else f"{len(win.nav_buttons)} 颗全部命中",
)

win._drain_events()
app.processEvents()
rows = win.page_monitor.model.rowCount()
check("实时监控表收到记录", rows >= 2, f"行数={rows}")

win.page_events.refresh()
win.page_bans.refresh()
check(
    "风险事件页", win.page_events.table.rowCount() >= 1, f"行数={win.page_events.table.rowCount()}"
)
check(
    "封禁建议页",
    win.page_bans.sug_table.rowCount() >= 1,
    f"行数={win.page_bans.sug_table.rowCount()}",
)

# 历史访问页的「清空列表」：按钮存在，且可用性跟着「有没有记录」走
# （一条都没有时置灰，否则用户点下去只会弹一个「没有可清空」的空框）
win.page_access.refresh()
_acc_total = win.page_access._total
check(
    "历史访问页清空入口",
    win.page_access.btn_clear.text() == "清空列表"
    and win.page_access.btn_clear.isEnabled() == (_acc_total > 0),
    f"total={_acc_total} enabled={win.page_access.btn_clear.isEnabled()}",
)

win.page_iplookup.lookup_and_show("8.8.8.8")
check(
    "IP 查询页",
    bool(win.page_iplookup.single_result.text()),
    win.page_iplookup.single_result.text(),
)

check("规则页卡片数", len(win.page_rules._cards) == 9, str(len(win.page_rules._cards)))
win.page_rules.reload()

# 区域访问白名单页签（本轮新增）：装填 / 回收 / ID 生成 / 引擎一致性
tab_region = win.page_rules.tab_region
check("区域规则页签已就绪", tab_region is not None)
n_region = tab_region.table.rowCount()
check("区域规则表已装填", n_region >= 1, f"行数={n_region}")
collected = tab_region.collect()
check(
    "区域规则可回收",
    len(collected) == n_region and all(r.get("id") for r in collected),
    f"回收 {len(collected)} 条",
)
ids = {new_rule_id() for _ in range(5)}
check("区域规则 ID 不重复", len(ids) == 5, ",".join(sorted(ids)))
n_engine_region = len(get_engine().region_rules())
check(
    "引擎已装填区域规则",
    n_engine_region == n_region,
    f"引擎 {n_engine_region} 条 / 界面 {n_region} 条",
)

win._refresh_stats(force=True)
check(
    "统计卡片刷新",
    win.page_monitor.card_total.value_lbl.text() != "",
    f"今日访问={win.page_monitor.card_total.value_lbl.text()} "
    f"今日风险={win.page_monitor.card_risk.value_lbl.text()}",
)

# 设置页（封禁策略 / 离线库在线同步组）
check(
    "设置页-封禁策略组",
    win.page_settings.sp_threshold.value() > 0,
    f"阈值={win.page_settings.sp_threshold.value()}",
)
check(
    "设置页-离线库同步组已就绪",
    hasattr(win.page_settings, "btn_xdb_check") and hasattr(win.page_settings, "tg_xdb_auto"),
    f"自动同步={win.page_settings.tg_xdb_auto.isChecked()}",
)
# 设置页-本机端口观察组（本轮新增：自定义端口 + 双通道采集 + 区域规则配套）
_watch_attrs = (
    "tg_watch",
    "ed_watch_ports",
    "sp_watch_interval",
    "sp_watch_dedupe",
    "tg_watch_pid",
    "tg_watch_skip",
    "tg_watch_autoban",
    "lbl_watch_state",
)
_watch_missing = [a for a in _watch_attrs if not hasattr(win.page_settings, a)]
check(
    "设置页-端口观察组已就绪",
    not _watch_missing,
    f"缺失={_watch_missing}"
    if _watch_missing
    else f"端口={win.page_settings.ed_watch_ports.text()!r} "
    f"间隔={win.page_settings.sp_watch_interval.value()}s "
    f"状态={win.page_settings.lbl_watch_state.text()!r}",
)

# 运行日志页（本轮新增）：切页 + 访问行在程序内渲染，不再只是「打开日志目录」
from gui.page_logs import SOURCE_ACCESS, format_access_line

win._switch_page(PAGE_LOGS)
app.processEvents()
check(
    "运行日志页可切换",
    win.page_logs is not None and win.page_logs.view is not None,
    f"当前页={win.stack.currentIndex()}",
)
# 默认视图是「程序运行日志」，访问行走另一路；切过去才能看到访问行
win.page_logs.source.setCurrentIndex(SOURCE_ACCESS)
app.processEvents()
rec_sample = AccessRecord(
    ip="113.118.113.77",
    remote_port=51000,
    local_port=3000,
    protocol="http",
    method="GET",
    path="/api/products",
    status_code=200,
)
rec_sample.geo = geo_cn
win.page_logs.append_access([rec_sample])
app.processEvents()
check(
    "访问记录进日志页",
    "113.118.113.77" in win.page_logs.view.document().toPlainText(),
    format_access_line(rec_sample),
)
win._switch_page(PAGE_SETTINGS)
app.processEvents()
# 过滤与搜索（验证重建视图不丢原始数据）
win.page_monitor.scope.setCurrentText("有风险")
app.processEvents()
n_risk = win.page_monitor.model.rowCount()
win.page_monitor.scope.setCurrentText("全部")
win.page_monitor.search.setText("113.118")
app.processEvents()
n_search = win.page_monitor.model.rowCount()
check("搜索过滤", n_search == 1, f"搜索 '113.118' 命中 {n_search} 行（有风险视图 {n_risk} 行）")
win.page_monitor.search.setText("")
app.processEvents()
check(
    "清空搜索不丢数据",
    win.page_monitor.model.rowCount() == rows,
    f"行数={win.page_monitor.model.rowCount()}",
)

# ── 6. 封禁校验（只校验，不真的动防火墙）──
from app import ban_service

try:
    ban_service.prepare('1.2.3.4"; Start-Process calc; #')
    check("封禁入口拒绝命令注入", False, "竟然通过了校验")
except ban_service.BanError as e:
    check("封禁入口拒绝命令注入", True, str(e)[:60])

try:
    ban_service.prepare("192.168.1.10")
    check("内网地址硬保护", False, "内网地址竟然通过了校验")
except ban_service.BanError as e:
    check("内网地址硬保护", True, str(e)[:60])

rec = ban_service.prepare("203.0.113.10", score=95, reason="自检", duration_sec=600)
# prepare() 只做校验并构造记录：状态是 pending，rule_name 要等 execute() 真正建规则时生成
check(
    "合法 IP 通过校验",
    rec.ip == "203.0.113.10" and rec.status == STATUS_PENDING and rec.duration_sec == 600,
    f"score={rec.risk_score} duration={rec.duration_sec}s status={rec.status}",
)

# ── 7. 无控制台运行（窗口化产物的真实场景）──
# pythonw / 打包后 console=False 时 sys.stdout 与 sys.stderr 是 None，第三方库
# 一旦调用 sys.stdout.isatty() 就会抛 AttributeError。logger 的兜底必须仍然生效。
_saved_out, _saved_err = sys.stdout, sys.stderr
sys.stdout = None  # 模拟窗口化运行：无控制台
sys.stderr = None
_nc_null_ok = False
_nc_patched: List[str] = []
try:
    from core.logger import ensure_std_streams

    _nc_patched = ensure_std_streams()
    # 上面把 sys.* 置成 None 后，类型检查器已把它们收窄为 None；
    # 先落到 Any 变量上，后面才能安全地调用 write/flush/isatty
    _out: Any = sys.stdout
    _err_out: Any = sys.stderr
    try:
        _out.write("x")
        _err_out.flush()
        _nc_null_ok = _out.isatty() is False and _err_out.isatty() is False
    except Exception:
        _nc_null_ok = False
finally:
    sys.stdout = _saved_out
    sys.stderr = _saved_err

check(
    "无控制台时自动兜底 std 流", set(_nc_patched) == {"stdout", "stderr"}, f"patched={_nc_patched}"
)
check("替身流可写且 isatty 为假", _nc_null_ok)

# ── 9. 日志保留（定期清理）──
from app import maintenance
from core.logger import log_file, logs_dir

_d = logs_dir()
_stale_file = os.path.join(_d, "portguard.log.2000-01-01")
with open(_stale_file, "w", encoding="utf-8") as f:
    f.write("stale\n")
_old_ts = time.time() - 400 * 86400
os.utime(_stale_file, (_old_ts, _old_ts))
_removed = maintenance.cleanup_log_files(30)
check(
    "超期日志归档被清理、活跃日志保留",
    _removed >= 1 and not os.path.exists(_stale_file) and os.path.exists(log_file()),
    f"删除={_removed} 保留天数={cfg.get_int('log_retention_days', 30)}",
)
check(
    "定期清理时刻可配置",
    isinstance(cfg.get_int("maintenance_hour", -1), int)
    and cfg.get_int("maintenance_hour", -1) >= 0,
    f"maintenance_hour={cfg.get('maintenance_hour')} last={cfg.get('maintenance_last_date') or '(未跑过)'}",
)

# ── 10. 数据库总览 ──
today = count_today()
check(
    "数据库统计可读",
    isinstance(today, tuple),
    f"today={today} access={len(query_access_logs(50))} events={len(query_risk_events(50))}",
)

# ── 收尾 ──
for k, v in _backup.items():  # 还原为运行前的设置
    cfg.set(k, v)
check(
    "已还原运行前设置",
    all(cfg.get(k) == v for k, v in _backup.items()),
    f"auto_mode={cfg.get('auto_mode')!r}",
)

QTimer.singleShot(200, app.quit)
app.exec()

if _failures:
    print(f"\n=== 自检失败 {len(_failures)} 项：{_failures} ===", flush=True)
    sys.exit(1)

print("\n=== 全部自检项通过 ===", flush=True)
sys.exit(0)
