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
        conn.execute("PRAGMA user_version = 5")
        conn.commit()

        assert migrate(conn) == SCHEMA_VERSION
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "stats_hourly" not in tables
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
