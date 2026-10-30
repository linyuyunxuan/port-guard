"""数据库维护（VACUUM / REINDEX / 备份 / 恢复）的数据层守门。

这里钉的都是「错了会静默毁数据」的点，不是功能覆盖率：

1. **备份必须是一致性快照**。库跑在 WAL 模式下，磁盘上的 `port_guard.db` 只是
   已 checkpoint 的部分，新数据还在 `-wal` 里。用例先把数据写进 WAL、再打备份，
   然后直接开备份文件数行数 —— 用 `shutil.copy2` 的实现会在这里少行。
2. **恢复必须先停写入器**。写入器握着长连接，不停就换文件在 Windows 上直接
   PermissionError；侥幸成功也会把后到的数据写进旧文件的句柄。用例断言
   `stop_writer` 一定发生在替换文件之前。
3. **恢复要重新初始化 + 刷新设置缓存**。备份可能来自另一时刻的库，不 reload
   的话界面和业务读到的还是旧库的值。
4. **恢复前必先备份；备份失败就中止**。没有退路的覆盖不可接受。

恢复是破坏性的，所以这些用例**只碰临时库**（`fresh_db` 已经把整个 data 目录
指到 tmp 下），且绝不出现在 `selftest.py` 里 —— 自检脚本跑的是真实数据。
"""

import os
import sqlite3

import pytest

from app import maintenance
from core import database, db_writer
from core import settings as cfg
from core.config import db_path
from core.models import (
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_UNBANNED,
    AccessRecord,
    BanRecord,
    now_ms,
)


@pytest.fixture(autouse=True)
def env(fresh_db, tmp_path, monkeypatch):
    """每个用例：建表（fresh_db 只清文件不建表）+ 一套独立的备份目录。

    备份目录必须独立：它是 session 级的临时目录，不隔离的话上一个用例的
    `port_guard.*.bak` 会让「保留 3 份」这类计数断言随机飘。
    """
    database.init_db()
    d = tmp_path / "backup"
    d.mkdir()
    monkeypatch.setattr(maintenance, "backup_dir", lambda: str(d))
    return d


def _insert(n: int, tag: str = "a") -> None:
    """单事务批量插入（不是测写入器，别为几百行开几百条连接）"""
    conn = database._connect()
    try:
        for i in range(n):
            database.insert_access_log_sql(
                conn,
                AccessRecord(ip=f"10.0.0.{i % 250}", path=f"/{tag}/{i}", event_ts=now_ms()),
            )
        conn.commit()
    finally:
        conn.close()


def _count_rows(path: str) -> int:
    """直接开一个库文件数访问记录（用来验证备份文件里到底有什么）"""
    conn = sqlite3.connect(path)
    try:
        return int(conn.execute("SELECT COUNT(*) FROM access_log").fetchone()[0])
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════
#  整理 / 重建索引
# ═══════════════════════════════════════════════════════════


def test_vacuum_reclaims_space_and_keeps_db_usable():
    _insert(1200, tag="x" * 700)  # 约 0.9MB，够让 VACUUM 有东西可回收
    database.clear_all_logs()
    before = database.db_size()["total"]

    ok, msg = maintenance.vacuum_db()
    assert ok, msg
    after = database.db_size()["total"]
    assert after < before, f"VACUUM 没有回收空间：{before} → {after}"

    # 库还得能读能写（VACUUM 失败时最常见的表现就是「文件没了」）
    _insert(3)
    assert database.count_access_logs() == 3

    # VACUUM 不能在事务里执行 —— 连一个干净连接确认 `_connect()` 不会隐式开事务
    conn = database._connect()
    try:
        assert conn.in_transaction is False
    finally:
        conn.close()


def test_reindex_keeps_indexes_and_data():
    _insert(50)
    ok, msg = maintenance.reindex_db()
    assert ok, msg
    assert database.count_access_logs() == 50

    conn = database._connect()
    try:
        names = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    finally:
        conn.close()
    # 索引被重建而不是被丢掉（REINDEX 后的老坑：只剩 sqlite_autoindex）
    assert {"idx_access_ip", "idx_access_ts", "idx_ban_status"} <= names


def test_db_size_counts_wal_and_shm():
    holder = database.connect_for_writer()  # 压住 WAL，别让 close 时 checkpoint
    try:
        _insert(20)
        sz = database.db_size()
        assert sz["main"] > 0
        assert sz["wal"] > 0, "写入后 -wal 应该有内容"
        assert sz["total"] == sz["main"] + sz["wal"] + sz["shm"]
    finally:
        holder.close()


# ═══════════════════════════════════════════════════════════
#  备份
# ═══════════════════════════════════════════════════════════


def test_backup_is_a_consistent_snapshot_not_a_file_copy():
    """WAL 里还有未 checkpoint 的数据时，备份必须把它们带上。

    这正是「不能用 shutil.copy2」的原因：只拷主文件会得到一份丢掉最后几批
    写入的旧快照，而用户以为它是最新的。
    """
    holder = database.connect_for_writer()  # 模拟写入器那条长连接
    try:
        _insert(30)
        wal = db_path() + "-wal"
        assert os.path.getsize(wal) > 0

        ok, bak = maintenance.backup_db()
        assert ok, bak
        assert _count_rows(bak) == 30

        # 反证：同一时刻只拷主文件会少行（这条断言就是「为什么不用 copy」）
        naive = os.path.join(os.path.dirname(bak), "naive.db")
        with open(db_path(), "rb") as f, open(naive, "wb") as g:
            g.write(f.read())
        assert _count_rows(naive) < 30
        os.remove(naive)
    finally:
        holder.close()


def test_backup_file_is_self_contained():
    _insert(5)
    ok, bak = maintenance.backup_db()
    assert ok, bak
    # 自带 -wal / -shm 的备份等于残缺：别人只拿走这一个文件就恢复不了
    assert not os.path.exists(bak + "-wal")
    assert not os.path.exists(bak + "-shm")
    assert _count_rows(bak) == 5


def test_two_backups_in_same_second_do_not_overwrite_each_other():
    """同秒连点两次「立即备份」，后一份不能把前一份盖掉 ——
    那份可能正是唯一能回退的副本（离线库那边踩过同一个坑）。"""
    _insert(1)
    ok1, p1 = maintenance.backup_db()
    ok2, p2 = maintenance.backup_db()
    assert ok1 and ok2
    assert p1 != p2
    assert os.path.exists(p1) and os.path.exists(p2)


def test_list_backups_ignores_offline_lib_backups():
    """备份目录是共用的：离线库的 .bak 绝不能出现在「数据库备份」列表里 ——
    点恢复就会把 11MB 的归属地库盖到数据库上。"""
    _insert(1)
    ok, bak = maintenance.backup_db()
    assert ok, bak
    with open(os.path.join(maintenance.backup_dir(), "ip2region_v4.1700000000.bak"), "wb") as f:
        f.write(b"not a database")

    rows = maintenance.list_db_backups()
    assert [r["file"] for r in rows] == [os.path.basename(bak)]


def test_cleanup_keeps_newest_backups():
    d = maintenance.backup_dir()
    for ts in range(5):
        with open(os.path.join(d, f"port_guard.{1700000000 + ts}.bak"), "wb") as f:
            f.write(b"x")

    assert maintenance.cleanup_db_backups(keep=3) == 2
    left = sorted(os.listdir(d))
    assert left == [f"port_guard.{1700000000 + ts}.bak" for ts in (2, 3, 4)]


# ═══════════════════════════════════════════════════════════
#  恢复
# ═══════════════════════════════════════════════════════════


def test_restore_roundtrip():
    _insert(3, tag="before")
    ok, bak = maintenance.backup_db()
    assert ok, bak
    _insert(2, tag="after")
    assert database.count_access_logs() == 5

    ok, msg = maintenance.restore_db(bak)
    assert ok, msg
    assert database.count_access_logs() == 3


def test_restore_backs_up_current_db_first():
    _insert(2)
    ok, bak = maintenance.backup_db()
    assert ok, bak
    _insert(3)
    before = len(maintenance.list_db_backups())

    ok, msg = maintenance.restore_db(bak)
    assert ok, msg

    rows = maintenance.list_db_backups()
    assert len(rows) == before + 1, "恢复前必须自动备份当前库，否则恢复不可撤销"
    # 最新那份 = 被换掉之前的状态（5 行）
    newest = rows[0]["path"]
    assert newest != bak
    assert _count_rows(newest) == 5
    # 提示语里要能看见「恢复了哪个、顺手备份了哪个」
    assert os.path.basename(bak) in msg


def test_restore_can_skip_pre_backup():
    _insert(2)
    ok, bak = maintenance.backup_db()
    assert ok, bak
    before = len(maintenance.list_db_backups())

    ok, msg = maintenance.restore_db(bak, backup_current=False)
    assert ok, msg
    assert len(maintenance.list_db_backups()) == before


def test_restore_missing_backup_is_reported_and_changes_nothing():
    _insert(4)
    ok, msg = maintenance.restore_db(os.path.join(maintenance.backup_dir(), "nope.bak"))
    assert not ok
    assert "不存在" in msg
    assert database.count_access_logs() == 4


def test_restore_aborts_when_pre_backup_fails(monkeypatch):
    """备份失败还继续覆盖，就是「没有退路的破坏性操作」——必须中止。"""
    _insert(5)
    ok, bak = maintenance.backup_db()
    assert ok, bak

    monkeypatch.setattr(maintenance, "backup_db", lambda: (False, "磁盘已满"))
    ok, msg = maintenance.restore_db(bak)
    assert not ok
    assert "已中止" in msg
    assert database.count_access_logs() == 5
    # 暂存文件不能留在数据目录里
    assert not os.path.exists(db_path() + ".restore")


def test_restore_stops_writer_before_replacing_files(monkeypatch):
    _insert(1)
    ok, bak = maintenance.backup_db()
    assert ok, bak

    order = []
    real_stop = db_writer.stop_writer

    def fake_stop(timeout: float = 5.0) -> None:
        order.append("stop")
        real_stop(timeout=timeout)

    real_replace = maintenance._replace_with_retry

    def fake_replace(src: str, dst: str, attempts: int = 20) -> None:
        order.append("replace")
        real_replace(src, dst, attempts)

    monkeypatch.setattr(db_writer, "stop_writer", fake_stop)
    monkeypatch.setattr(maintenance, "_replace_with_retry", fake_replace)

    ok, msg = maintenance.restore_db(bak, backup_current=False)
    assert ok, msg
    assert order == ["stop", "replace"], "必须先停写入器再换文件，顺序反了会丢数据"


def test_restore_restarts_writer():
    _insert(1)
    ok, bak = maintenance.backup_db()
    assert ok, bak

    old = db_writer.start_writer()
    assert old.running
    try:
        ok, msg = maintenance.restore_db(bak, backup_current=False)
        assert ok, msg
        new = db_writer.peek_writer()
        # 换了文件就必须换连接：旧写入器手里那份是已经被替换掉的旧文件
        assert new is not None and new is not old
        assert new.running
    finally:
        db_writer.stop_writer(timeout=5)


def test_restore_reloads_settings_from_restored_db():
    cfg.set("listen_port", "18080")
    ok, bak = maintenance.backup_db()
    assert ok, bak

    cfg.set("listen_port", "19090")
    assert cfg.get("listen_port") == "19090"

    ok, msg = maintenance.restore_db(bak, backup_current=False)
    assert ok, msg
    # 设置缓存不刷新的话，界面与业务会一直用「旧库」的值
    assert cfg.get("listen_port") == "18080"


def test_stats_snapshot_returns_counts_with_single_connection():
    """stats_snapshot 必须一条连接返回四项计数，且数值正确（替代原来每 1.5s
    开 3 次连接的 count_today / count_active_bans / count_risk_unhandled）。"""
    _insert(4, tag="s")
    conn = database._connect()
    try:
        conn.execute("UPDATE access_log SET risk_score=80 WHERE id=1")
        conn.execute(
            "INSERT INTO risk_event (ip, risk_score, risk_level, event_ts) "
            "VALUES ('1.2.3.4', 80, 'high', ?)",
            (now_ms(),),
        )
        conn.execute(
            "INSERT INTO risk_event (ip, risk_score, risk_level, handled, event_ts) "
            "VALUES ('1.2.3.5', 40, 'medium', 1, ?)",
            (now_ms(),),
        )
        conn.execute("INSERT INTO ban_list (ip, status) VALUES ('9.9.9.9', 'active')")
        conn.commit()
    finally:
        conn.close()

    s = database.stats_snapshot()
    assert s["today_total"] == 4
    assert s["today_risk"] == 1  # 仅 id=1 被改成 risk_score>0
    assert s["active_bans"] == 1
    assert s["unhandled"] == 1  # 两条 risk_event 中仅 1 条未处理


def test_stats_snapshot_light_mode_skips_today_scan():
    """P1-4：include_today=False 时跳过今日两项全扫，仍返回顶栏/状态栏需要的
    active_bans / unhandled；今日两项置 0（调用方在监控页不可见时不消费）。"""
    _insert(4, tag="s")
    conn = database._connect()
    try:
        conn.execute("INSERT INTO ban_list (ip, status) VALUES ('9.9.9.9', 'active')")
        conn.execute(
            "INSERT INTO risk_event (ip, risk_score, risk_level, event_ts) "
            "VALUES ('1.2.3.4', 80, 'high', ?)",
            (now_ms(),),
        )
        conn.commit()
    finally:
        conn.close()

    s = database.stats_snapshot(include_today=False)
    assert s["today_total"] == 0
    assert s["today_risk"] == 0
    assert s["active_bans"] == 1
    assert s["unhandled"] == 1
    # 默认仍是全量（既有调用方语义不变）
    s2 = database.stats_snapshot()
    assert s2["today_total"] == 4
    assert s2["active_bans"] == 1


def test_count_today_merges_risk_and_total_in_one_scan():
    """P1-5：count_today 必须用单条查询同时拿到今日总数与风险数，不得对今日
    access_log 全扫两次（攻击期仪表盘每 1.5s 都跑，两次全扫是纯浪费）。"""
    database.init_db()
    base = now_ms()
    database.insert_access_log(AccessRecord(ip="1.1.1.1", event_ts=base, risk_score=50))
    database.insert_access_log(AccessRecord(ip="2.2.2.2", event_ts=base, risk_score=0))
    database.insert_access_log(AccessRecord(ip="3.3.3.3", event_ts=base, risk_score=10))
    # 昨天的，不应计入今日
    database.insert_access_log(
        AccessRecord(ip="4.4.4.4", event_ts=base - 86400 * 1000, risk_score=99)
    )
    total, risk = database.count_today()
    assert total == 3
    assert risk == 2


def test_find_active_ban_by_ip_uses_cache(monkeypatch):
    """P1-1：find_active_ban_by_ip 必须走内存缓存，同一 TTL 窗口内多次查询只回源
    （active_ban_ip_map）一次，而不是每条记录都开一条新连接。"""
    database.init_db()
    calls = {"n": 0}
    real_map = database.active_ban_ip_map

    def counting_map():
        calls["n"] += 1
        return real_map()

    monkeypatch.setattr(database, "active_ban_ip_map", counting_map)
    database.insert_ban(BanRecord(ip="5.5.5.5", status=STATUS_ACTIVE, source="auto"))
    database.invalidate_active_ban_cache()
    # 同一窗口内多次查询（含不存在的 IP）只回源一次
    a = database.find_active_ban_by_ip("5.5.5.5")
    b = database.find_active_ban_by_ip("6.6.6.6")
    assert a is not None and a.ip == "5.5.5.5"
    assert b is None
    assert calls["n"] == 1


def test_find_active_ban_cache_invalidated_on_status_change(monkeypatch):
    """封禁状态变化（update_ban 带 status）必须让缓存失效，下一次查询重新回源。"""
    database.init_db()
    calls = {"n": 0}
    real_map = database.active_ban_ip_map

    def counting_map():
        calls["n"] += 1
        return real_map()

    monkeypatch.setattr(database, "active_ban_ip_map", counting_map)
    database.invalidate_active_ban_cache()
    assert database.find_active_ban_by_ip("7.7.7.7") is None
    assert calls["n"] == 1
    # 状态变更触发失效（这里用不存在的 id 只验证失效逻辑，不影响断言）
    database.update_ban(999, status=STATUS_ACTIVE)
    assert database.find_active_ban_by_ip("7.7.7.7") is None
    assert calls["n"] == 2


def test_query_bans_pushes_status_in_and_expire_down():
    """P1-2：query_bans 必须支持多状态 IN 与 expire_before 下推，让封禁页
    「已到期」筛选在数据库侧完成，而不是把全表拉回内存逐行过滤。"""
    database.init_db()
    now = now_ms()
    database.insert_ban(
        BanRecord(ip="1.1.1.1", status=STATUS_ACTIVE, expire_at=now - 1000, source="auto")
    )
    database.insert_ban(
        BanRecord(ip="2.2.2.2", status=STATUS_EXPIRED, expire_at=now - 2000, source="auto")
    )
    database.insert_ban(
        BanRecord(ip="3.3.3.3", status=STATUS_ACTIVE, expire_at=now + 86400000, source="auto")
    )
    database.insert_ban(
        BanRecord(ip="4.4.4.4", status=STATUS_UNBANNED, expire_at=now - 3000, source="auto")
    )
    database.insert_ban(
        BanRecord(ip="5.5.5.5", status=STATUS_ACTIVE, expire_at=0, source="auto")
    )  # 永久
    rows = database.query_bans(
        status=(STATUS_ACTIVE, STATUS_EXPIRED),
        expire_before=now,
        exclude_permanent=True,
    )
    assert {r.ip for r in rows} == {"1.1.1.1", "2.2.2.2"}


def test_restore_aborts_when_writer_queue_not_drained(monkeypatch):
    """队列里还有在途数据时恢复：旧 writer 仍持有旧库文件的孤立句柄，会把它
    排空到已被替换的文件里 → 数据静默丢失；两个 writer 还会抢同一把写锁。

    必须放弃恢复、保持当前库不变、绝不允许 _replace_with_retry 发生。
    """
    _insert(2)
    ok, bak = maintenance.backup_db()
    assert ok, bak

    old = db_writer.start_writer()
    assert old.running
    try:
        # 让 flush 直接报告「没排空」，模拟队列无法在超时内清空
        monkeypatch.setattr(old, "flush", lambda timeout=10.0: False)

        replace_called = []
        real_replace = maintenance._replace_with_retry

        def fake_replace(src: str, dst: str, attempts: int = 20) -> None:
            replace_called.append(1)
            real_replace(src, dst, attempts)

        monkeypatch.setattr(maintenance, "_replace_with_retry", fake_replace)

        ok, msg = maintenance.restore_db(bak, backup_current=False)
        assert not ok
        assert "取消恢复" in msg or "丢失" in msg
        assert not replace_called, "队列未清空时绝不允许替换文件（会丢数据）"
        # 当前库保持不变
        assert database.count_access_logs() == 2
    finally:
        db_writer.stop_writer(timeout=30)
