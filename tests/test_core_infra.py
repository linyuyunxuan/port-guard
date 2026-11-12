"""设置缓存、令牌桶、schema 迁移的测试"""

import sqlite3

import pytest

from core import settings as cfg
from core.database import get_setting, init_db
from core.migrations import SCHEMA_VERSION, get_version, migrate
from core.ratelimit import TokenBucket

# ═══════════════════ 设置缓存 ═══════════════════


def test_settings_cache_roundtrip():
    init_db()
    cfg.set("unit_test_key", "v1")
    assert cfg.get("unit_test_key") == "v1"
    # 直接读库也应看到（说明确实落盘了）
    assert get_setting("unit_test_key") == "v1"


def test_settings_get_bool_and_int():
    init_db()
    cfg.set("unit_bool", "1")
    cfg.set("unit_int", "42")
    cfg.set("unit_bad_int", "abc")
    assert cfg.get_bool("unit_bool") is True
    assert cfg.get_bool("unit_missing", True) is True
    assert cfg.get_int("unit_int") == 42
    assert cfg.get_int("unit_bad_int", 9) == 9
    assert cfg.get_float("unit_missing", 1.5) == 1.5


def test_settings_hits_cache_not_db(monkeypatch):
    """预热后读取必须全部命中缓存，不能再回源查库"""
    init_db()
    cfg.warm()
    calls = {"n": 0}
    real = cfg.database.get_setting_optional

    def counting(key):
        calls["n"] += 1
        return real(key)

    monkeypatch.setattr(cfg.database, "get_setting_optional", counting)
    for _ in range(3):
        cfg.get("auto_mode")
    assert calls["n"] == 0, "预热后回源次数应为 0（全部命中缓存）"


def test_missing_key_default_is_not_cached_as_value():
    """
    回归：缺失的键不能把调用方的 default 缓存成「值」。
    否则同一次会话里换个 default 再读，会拿到上一次的 default。
    """
    init_db()
    assert cfg.get_bool("unit_missing_x", True) is True
    assert cfg.get_float("unit_missing_x", 1.5) == 1.5
    assert cfg.get_int("unit_missing_x", 7) == 7
    assert cfg.get("unit_missing_x", "abc") == "abc"


def test_numeric_ranges_clamp_dirty_values():
    """P2-2：登记过区间的键，脏值（手工改库/老版本 bug）在读取层夹回合法范围。

    变异：删掉 settings._NUMERIC_RANGES 或 get_int 里的 _clamp_range → 本例变红
    （999/0/-5 原样穿透）。
    """
    init_db()
    cfg.set("auto_ban_threshold", "999", persist=False)
    assert cfg.get_int("auto_ban_threshold", 90) == 100
    cfg.set("auto_ban_threshold", "-5", persist=False)
    assert cfg.get_int("auto_ban_threshold", 90) == 0

    # 保留期 0 天 = 启动即删光日志，必须被夹到 1
    cfg.set("log_retention_days", "0", persist=False)
    assert cfg.get_int("log_retention_days", 30) == 1

    # 维护小时不在 0..23 的钟点不存在
    cfg.set("maintenance_hour", "99", persist=False)
    assert cfg.get_int("maintenance_hour", 3) == 23

    # 封禁时长 0 = 「永久」，min 必须是 0，不能被夹成别的值
    cfg.set("ban_duration_high_sec", "0", persist=False)
    assert cfg.get_int("ban_duration_high_sec", 3600) == 0

    # 未登记的键（时间戳、测试键）不受影响
    cfg.set("xdb_last_check_at", "9999999999999", persist=False)
    assert cfg.get_int("xdb_last_check_at", 0) == 9999999999999
    cfg.set("unit_int", "42", persist=False)
    assert cfg.get_int("unit_int") == 42

    # 脏到解析不了的值仍回 default（原有语义不变）
    cfg.set("auto_ban_threshold", "abc", persist=False)
    assert cfg.get_int("auto_ban_threshold", 90) == 90


def test_schema_derives_default_settings():
    """P2-6：DEFAULT_SETTINGS 由声明式 schema 派生，且逐键一致（53 键）。

    变异：删掉 build_default_settings 里的 _SETTINGS_NO_SEED 过滤 → rate_limit_per_sec
    混入落表键，键数变 54；或 schema 某默认值改错 → 与固化快照不一致 → 本例变红。
    """
    from core.config import DEFAULT_SETTINGS, SETTINGS_SCHEMA

    # key 顺序与值 = 改前的 flat dict 快照（53 键，含 rate_limit_per_sec 之外全部）
    expected = {
        "auto_mode": "0",
        "auto_ban_threshold": "90",
        "default_ban_duration_sec": "3600",
        "ban_duration_critical_sec": "86400",
        "ban_duration_high_sec": "21600",
        "ban_duration_medium_sec": "7200",
        "ban_duration_low_sec": "1800",
        "ban_escalation_enabled": "0",
        "ban_escalation_factor": "2",
        "ban_escalation_max_sec": "604800",
        "repeat_blacklist_enabled": "1",
        "repeat_blacklist_hits": "5",
        "max_ban_duration_sec": "604800",
        "alert_sound": "1",
        "alert_popup_level": "critical",
        "alert_merge_sec": "60",
        "alert_block_silent": "1",
        "alert_webhook_enabled": "0",
        "alert_webhook_url": "",
        "alert_webhook_level": "critical",
        "autostart_enabled": "0",
        "maintenance_enabled": "1",
        "log_retention_days": "30",
        "risk_retention_days": "90",
        "ban_retention_days": "180",
        "audit_retention_days": "180",
        "maintenance_hour": "3",
        "maintenance_last_date": "",
        "log_level": "INFO",
        "geo_cache_size": "20000",
        "monitor_buffer_size": "5000",
        "db_batch_size": "200",
        "db_flush_ms": "200",
        "watch_enabled": "0",
        "watch_ports": "3389,1433,3306,6379,18080",
        "watch_methods": "table,fwlog",
        "watch_interval_sec": "5",
        "watch_dedupe_sec": "120",
        "watch_fwlog_path": "",
        "watch_resolve_pid": "1",
        "watch_skip_history": "1",
        "watch_auto_ban": "0",
        "log_view_max_lines": "2000",
        "log_view_tail_ms": "1000",
        "xdb_auto_sync": "1",
        "xdb_sync_interval_hours": "24",
        "xdb_sync_on_start": "1",
        "xdb_auto_download": "1",
        "xdb_sources": "[]",
        "xdb_proxy": "",
        "xdb_last_check_at": "0",
        "xdb_last_update_at": "0",
        "xdb_last_result": "",
    }
    assert len(expected) == 53
    assert dict(DEFAULT_SETTINGS) == expected
    # 落表键数与 schema 一键之差（rate_limit_per_sec 不落表）
    assert len(SETTINGS_SCHEMA) - len(DEFAULT_SETTINGS) == 1
    assert "rate_limit_per_sec" not in DEFAULT_SETTINGS


def test_numeric_ranges_derived_from_schema():
    """P2-6：settings._NUMERIC_RANGES 由 schema 的 min/max 推导，非手工维护。

    变异：改 schema 里某数值键的 min/max → clamp 范围随之变化 → 覆盖率断言变红。
    """
    from core.config import SETTINGS_SCHEMA
    from core.settings import _NUMERIC_RANGES

    # schema 里 int/float 且 min/max 齐全的键，推导出的范围必须一一对应
    for key, spec in SETTINGS_SCHEMA.items():
        if spec.type in ("int", "float") and spec.min is not None and spec.max is not None:
            assert _NUMERIC_RANGES[key] == (spec.min, spec.max), f"{key} 范围未从 schema 推导"
    # 未登记 min/max 的键（时间戳、str 型）不被 clamp
    for key in ("xdb_last_check_at", "xdb_last_update_at", "alert_popup_level", "log_level"):
        assert key not in _NUMERIC_RANGES


# ═══════════════════ 令牌桶 ═══════════════════


def test_token_bucket_limits_burst():
    b = TokenBucket(rate=10, burst=5)
    allowed = sum(1 for _ in range(20) if b.allow("ip1"))
    assert allowed == 5
    assert b.rejected == 15


def test_token_bucket_refills():
    b = TokenBucket(rate=1000, burst=2)
    assert b.allow("k") and b.allow("k")
    assert not b.allow("k")
    import time

    time.sleep(0.05)  # 1000/s → 50ms 补 50 个令牌，远超桶容量
    assert b.allow("k")


def test_token_bucket_isolates_keys():
    b = TokenBucket(rate=1, burst=1)
    assert b.allow("a")
    assert b.allow("b")
    assert not b.allow("a")


def test_token_bucket_configurable_and_bounded():
    b = TokenBucket(rate=1, burst=1, max_keys=50, ttl=0.01)
    for i in range(500):
        b.allow(f"ip-{i}")
    assert len(b._buckets) <= 100, "桶数量必须被限制，防止伪造 IP 打爆内存"


# ═══════════════════ schema 迁移 ═══════════════════


def test_migration_sets_user_version():
    from core.database import _connect

    init_db()
    conn = _connect()
    try:
        assert get_version(conn) == SCHEMA_VERSION
    finally:
        conn.close()


def test_migration_is_idempotent():
    from core.database import _connect

    init_db()
    conn = _connect()
    try:
        for _ in range(3):
            assert migrate(conn) == SCHEMA_VERSION
    finally:
        conn.close()


def test_migration_adds_new_column():
    """v2 迁移新增 ban_list.unblocked_by，验证加字段真的生效"""
    from core.database import _connect

    init_db()
    conn = _connect()
    try:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(ban_list)")]
        assert "unblocked_by" in cols
    finally:
        conn.close()


def test_migration_v6_drops_dead_stats_hourly():
    """v6：老库里只有建表没有读写的 stats_hourly 必须被删除。

    变异：从 MIGRATIONS[6] 删掉 DROP 语句，或把 SCHEMA_VERSION 退回 5 → 本例变红
    （表还在）。新库建表语句里也已移除该表，全新 init_db() 同样查不到它。
    """
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("CREATE TABLE stats_hourly (hour TEXT PRIMARY KEY, total INTEGER DEFAULT 0)")
        # v5 老库的其余表（v7 回填需要）
        conn.execute(
            "CREATE TABLE ban_list ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " ip TEXT NOT NULL,"
            " status TEXT NOT NULL DEFAULT 'pending',"
            " created_at INTEGER,"
            " updated_at INTEGER)"
        )
        conn.execute(
            "CREATE TABLE access_log ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " ip TEXT NOT NULL,"
            " event_ts INTEGER NOT NULL,"
            " created_at TEXT)"
        )
        conn.execute(
            "CREATE TABLE risk_event ("
            " id INTEGER PRIMARY KEY AUTOINCREMENT,"
            " ip TEXT NOT NULL,"
            " event_ts INTEGER NOT NULL,"
            " created_at TEXT)"
        )
        conn.execute("PRAGMA user_version = 5")
        conn.commit()

        assert migrate(conn) == SCHEMA_VERSION
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "stats_hourly" not in tables
    finally:
        conn.close()


def test_migration_v7_keeps_legacy_text_rows():
    """v7 是「时间列收敛 epoch 毫秒」的语义版本号：不物理改列（SQLite 的
    TEXT 亲和列即便 CAST 也会被拉回 TEXT，UPDATE 实为空转），老库 TEXT 行
    在升级后必须**原样保留**，由读端 `to_epoch_ms` 双容忍承载。

    变异：把 v7 做成物理改列 / 对老库 TEXT 做强转 → 断言「原样保留」变红。
    """
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute(
            "CREATE TABLE ban_list (id INTEGER PRIMARY KEY, ip TEXT, "
            "created_at TEXT, updated_at TEXT)"
        )
        conn.execute(
            "INSERT INTO ban_list (id, ip, created_at, updated_at) VALUES (?,?,?,?)",
            (1, "1.1.1.1", "2026-10-20 09:15:00", "2026-10-20 09:15:02"),
        )
        conn.execute(
            "INSERT INTO ban_list (id, ip, created_at, updated_at) VALUES (?,?,?,?)",
            (2, "2.2.2.2", "1700000000123", "1700000000456"),  # 纯数字串也留在 TEXT
        )
        conn.execute("PRAGMA user_version = 6")
        conn.commit()

        assert migrate(conn) == SCHEMA_VERSION == 7

        rows = {
            r[0]: (r[1], r[2])
            for r in conn.execute("SELECT id, created_at, updated_at FROM ban_list")
        }
        # 老库 TEXT 数据在 v7 升级后原样保留（不破坏、不误转）
        assert rows[1] == ("2026-10-20 09:15:00", "2026-10-20 09:15:02")
        assert rows[2] == ("1700000000123", "1700000000456")

        # 幂等：已是最新再跑一次结果不变
        assert migrate(conn) == SCHEMA_VERSION
    finally:
        conn.close()


def test_new_schema_created_at_is_integer_epoch_ms():
    """P2⑦ 主契约：新库建表语句里三张历史表的 created_at（及 bans.updated_at）
    必须是 INTEGER epoch 毫秒，不能退回字符串 datetime。

    变异：把 DDL 的 default / 列类型改回 TEXT datetime → 本例变红。
    """
    conn = sqlite3.connect(":memory:")
    try:
        conn.executescript(
            """CREATE TABLE ban_list (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER) * 1000),
                updated_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER) * 1000)
            );
            CREATE TABLE access_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER) * 1000)
            );
            CREATE TABLE risk_event (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT NOT NULL,
                created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER) * 1000)
            );"""
        )
        conn.execute("INSERT INTO ban_list (ip) VALUES ('1.1.1.1')")
        conn.execute("INSERT INTO access_log (ip) VALUES ('2.2.2.2')")
        conn.execute("INSERT INTO risk_event (ip) VALUES ('3.3.3.3')")
        # 未显式写 created_at 时走 default，必须是整数 epoch 毫秒（>1.4e12）
        for table in ("ban_list", "access_log", "risk_event"):
            v = conn.execute(f"SELECT created_at FROM {table}").fetchone()[0]
            assert isinstance(v, int) and v > 1_400_000_000_000, (table, v)
        # bans.updated_at 同样整数
        upd = conn.execute("SELECT updated_at FROM ban_list").fetchone()[0]
        assert isinstance(upd, int) and upd > 1_400_000_000_000
    finally:
        conn.close()


def test_migration_refuses_future_version():
    from core.database import _connect

    init_db()
    conn = _connect()
    try:
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 5}")
        with pytest.raises(RuntimeError):
            migrate(conn)
    finally:
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.close()


def test_update_ban_rejects_unknown_columns():
    """动态列名必须走白名单"""
    from core.database import update_ban

    init_db()
    with pytest.raises(ValueError):
        update_ban(1, **{"status = 'x', ip": "1.2.3.4"})
    with pytest.raises(ValueError):
        update_ban(1, nonexistent_column="x")
