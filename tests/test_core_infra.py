"""设置缓存、令牌桶、schema 迁移的测试"""

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
