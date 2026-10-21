"""
PortGuard — SQLite 数据层

职责边界：
- 本模块只做「原始读写」，不做缓存（缓存见 core.settings）
- 写入热点（每条上报）不走这里，而是走 core.db_writer 的单写线程 + 攒批事务
- 读操作使用短连接（各线程各自建连），配合 WAL 天然线程安全
- 时间统一存 epoch 毫秒（event_ts / expire_at）

`insert_*_sql(conn, ...)` 是「纯执行」版本：由调用方提供连接与事务边界，
供批量写入器复用；`insert_*` 是同名的自建连便捷版本，供低频调用与测试。
"""

import datetime
import json
import os
import sqlite3
import threading
from typing import Any, Dict, List, Optional, Tuple

from core.config import BIND_ALL_HOSTS, DEFAULT_SETTINGS, db_path
from core.logger import get_logger
from core.models import (
    STATUS_ACTIVE,
    STATUS_EXPIRED,
    STATUS_FAILED,
    STATUS_UNBANNED,
    AccessRecord,
    BanRecord,
    GeoInfo,
    RiskResult,
    ms_to_str,
    now_ms,
)

log = get_logger(__name__)

_init_lock = threading.Lock()
_initialized = False


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path(), timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


def connect_for_writer() -> sqlite3.Connection:
    """
    批量写入器专用的长连接。
    isolation_level=None（自动提交）以便写入器自己用 BEGIN/COMMIT 划分批次事务；
    busy_timeout 放大到 30s，避免偶发锁等待直接失败。
    """
    conn = sqlite3.connect(db_path(), timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


# ═══════════════════════════════════════════════════════════
#  建表
# ═══════════════════════════════════════════════════════════

SCHEMA = """
CREATE TABLE IF NOT EXISTS access_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ip            TEXT NOT NULL,
    remote_port   INTEGER,
    local_port    INTEGER NOT NULL DEFAULT 0,
    protocol      TEXT NOT NULL DEFAULT 'http',
    method        TEXT,
    path          TEXT,
    status_code   INTEGER,
    user_agent    TEXT,
    bytes         INTEGER DEFAULT 0,
    host          TEXT,
    server_name   TEXT,
    tags          TEXT,
    country       TEXT,
    province      TEXT,
    city          TEXT,
    isp           TEXT,
    iso           TEXT,
    risk_score    INTEGER DEFAULT 0,
    risk_level    TEXT DEFAULT 'normal',
    matched_rules TEXT,
    event_ts      INTEGER NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_access_ip  ON access_log(ip);
CREATE INDEX IF NOT EXISTS idx_access_ts  ON access_log(event_ts);
CREATE INDEX IF NOT EXISTS idx_access_lvl ON access_log(risk_level);

CREATE TABLE IF NOT EXISTS risk_event (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    access_id     INTEGER,
    ip            TEXT NOT NULL,
    local_port    INTEGER DEFAULT 0,
    path          TEXT,
    risk_score    INTEGER NOT NULL,
    risk_level    TEXT NOT NULL,
    matched_rules TEXT,
    summary       TEXT,
    geo           TEXT,
    handled       INTEGER NOT NULL DEFAULT 0,
    event_ts      INTEGER NOT NULL,
    created_at    TEXT NOT NULL DEFAULT (datetime('now','localtime'))
);
CREATE INDEX IF NOT EXISTS idx_event_ip      ON risk_event(ip);
CREATE INDEX IF NOT EXISTS idx_event_handled ON risk_event(handled);
CREATE INDEX IF NOT EXISTS idx_event_ts      ON risk_event(event_ts);

CREATE TABLE IF NOT EXISTS ban_list (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ip          TEXT NOT NULL,
    rule_name   TEXT,
    reason      TEXT,
    risk_score  INTEGER DEFAULT 0,
    source      TEXT NOT NULL DEFAULT 'manual',
    status      TEXT NOT NULL DEFAULT 'active',
    duration_sec INTEGER,
    expire_at   INTEGER,
    created_at  TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    updated_at  TEXT NOT NULL DEFAULT (datetime('now','localtime')),
    error_msg   TEXT
);
CREATE INDEX IF NOT EXISTS idx_ban_ip     ON ban_list(ip);
CREATE INDEX IF NOT EXISTS idx_ban_status ON ban_list(status);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS stats_hourly (
    hour       TEXT PRIMARY KEY,
    total      INTEGER DEFAULT 0,
    risk_count INTEGER DEFAULT 0,
    unique_ip  INTEGER DEFAULT 0
);
"""


def init_db() -> None:
    global _initialized
    with _init_lock:
        if _initialized:
            return
        conn = _connect()
        try:
            conn.executescript(SCHEMA)
            # 默认设置（INSERT OR IGNORE：不覆盖用户已改过的值）
            for k, v in DEFAULT_SETTINGS.items():
                conn.execute("INSERT OR IGNORE INTO settings(key, value) VALUES (?, ?)", (k, v))
            conn.commit()

            # schema 版本迁移（原实现只有 CREATE TABLE IF NOT EXISTS，
            # 表已存在时新增字段会静默失败）
            from core.migrations import migrate

            migrate(conn)

            _fix_insecure_legacy_settings(conn)
        finally:
            conn.close()
        _initialized = True


def reset_init_state() -> None:
    """清掉进程内的「已初始化」标记，让下一次 `init_db()` 重新建表 + 跑迁移。

    唯一的使用场景是**整份替换库文件之后**（设置页「数据库维护 → 恢复备份」）：
    文件已经换成另一份、多半还是老版本 schema，但进程内的 `_initialized` 仍是
    True，`init_db()` 会立刻返回，迁移永远不跑 —— 恢复出来的老库缺列，之后每条
    查询都炸在 `no such column` 上。`tests/conftest.py` 的 `fresh_db` 出于同样
    的理由直接改 `_initialized`，这里给它一个公开入口，免得再多一处偷改私有量。
    """
    global _initialized
    with _init_lock:
        _initialized = False


def _fix_insecure_legacy_settings(conn: sqlite3.Connection) -> None:
    """
    老库一次性安全迁移：把「监听 0.0.0.0 且 API Key 为空」这个敞口组合
    收敛回只监听本机，并留下提示标记。

    为什么必须做：DEFAULT_SETTINGS 用的是 INSERT OR IGNORE，改默认值只对
    新装用户生效；老库会一直保持不安全组合。局域网任意主机可伪造上报 →
    规则打满分 → 若开了自动封禁，就变成「借 PortGuard 之手封掉任意 IP」。
    """
    try:
        rows = {
            r["key"]: r["value"]
            for r in conn.execute(
                "SELECT key, value FROM settings WHERE key IN ('listen_host','api_key','_security_migrated_v110')"
            )
        }
    except Exception:
        return
    if rows.get("_security_migrated_v110") == "1":
        return

    host = (rows.get("listen_host") or "").strip()
    key = (rows.get("api_key") or "").strip()
    if host in BIND_ALL_HOSTS and not key:
        conn.execute("UPDATE settings SET value = ? WHERE key = 'listen_host'", ("127.0.0.1",))
        log.warning(
            "安全迁移：检测到「监听 0.0.0.0 且未设置 API Key」，"
            "已将监听地址收敛为 127.0.0.1。如需局域网上报，"
            "请在设置页打开「允许局域网访问」并设置 API Key。"
        )
    conn.execute(
        "INSERT INTO settings(key, value) VALUES ('_security_migrated_v110','1') "
        "ON CONFLICT(key) DO UPDATE SET value = '1'"
    )
    conn.commit()


# ═══════════════════════════════════════════════════════════
#  设置
# ═══════════════════════════════════════════════════════════


def get_setting(key: str, default: str = "") -> str:
    conn = _connect()
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default
    finally:
        conn.close()


def get_setting_optional(key: str) -> Optional[str]:
    """
    键不存在时返回 None（区别于「值恰好是空字符串」）。

    仅供 core.settings 的缓存层使用：它需要区分「库里真没有这个键」和
    「值就是空的」，以免把调用方传入的 default 当成值缓存下来。
    """
    conn = _connect()
    try:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None
    finally:
        conn.close()


def set_setting(key: str, value: str) -> None:
    conn = _connect()
    try:
        conn.execute(
            "INSERT INTO settings(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, str(value)),
        )
        conn.commit()
    finally:
        conn.close()


def get_int_setting(key: str, default: int = 0) -> int:
    try:
        return int(get_setting(key, str(default)))
    except Exception:
        return default


def get_bool_setting(key: str, default: bool = False) -> bool:
    return get_setting(key, "1" if default else "0") == "1"


def get_all_settings() -> Dict[str, str]:
    conn = _connect()
    try:
        return {r["key"]: r["value"] for r in conn.execute("SELECT key, value FROM settings")}
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════
#  访问日志
# ═══════════════════════════════════════════════════════════

_INSERT_ACCESS_SQL = """
INSERT INTO access_log
   (ip, remote_port, local_port, protocol, method, path, status_code,
    user_agent, bytes, host, server_name, tags,
    country, province, city, isp, iso,
    risk_score, risk_level, matched_rules, event_ts)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
"""


def insert_access_log_sql(conn: sqlite3.Connection, rec: AccessRecord) -> int:
    """
    纯执行版本（不建连、不提交）：由批量写入器在事务内反复调用。
    返回该行 rowid（同一连接内立即有效，可用于关联 risk_event）。
    """
    geo = rec.geo or GeoInfo()
    cur = conn.execute(
        _INSERT_ACCESS_SQL,
        (
            rec.ip,
            rec.remote_port,
            rec.local_port,
            rec.protocol,
            rec.method,
            rec.path,
            rec.status_code,
            rec.user_agent,
            rec.size,
            rec.host,
            rec.server_name,
            json.dumps(rec.tags, ensure_ascii=False),
            geo.country,
            geo.province,
            geo.city,
            geo.isp,
            geo.iso,
            rec.risk_score,
            rec.risk_level,
            json.dumps(rec.matched_rules, ensure_ascii=False),
            rec.event_ts,
        ),
    )
    return int(cur.lastrowid or 0)


def insert_access_log(rec: AccessRecord) -> int:
    """便捷版本：自建连接 + 单条提交（低频调用/测试用，勿放进上报热点路径）"""
    conn = _connect()
    try:
        rid = insert_access_log_sql(conn, rec)
        conn.commit()
        return rid
    finally:
        conn.close()


def _row_to_access(r: sqlite3.Row) -> AccessRecord:
    try:
        tags = json.loads(r["tags"]) if r["tags"] else {}
    except Exception:
        tags = {}
    try:
        matched = json.loads(r["matched_rules"]) if r["matched_rules"] else []
    except Exception:
        matched = []
    return AccessRecord(
        id=r["id"],
        ip=r["ip"],
        remote_port=r["remote_port"],
        local_port=r["local_port"],
        protocol=r["protocol"],
        method=r["method"],
        path=r["path"],
        status_code=r["status_code"],
        user_agent=r["user_agent"],
        size=r["bytes"] or 0,
        host=r["host"],
        server_name=r["server_name"],
        tags=tags,
        event_ts=r["event_ts"],
        geo=GeoInfo(
            ip=r["ip"],
            country=r["country"] or "",
            province=r["province"] or "",
            city=r["city"] or "",
            isp=r["isp"] or "",
            iso=r["iso"] or "",
            found=bool(r["country"]),
        ),
        risk_score=r["risk_score"] or 0,
        risk_level=r["risk_level"] or "normal",
        matched_rules=matched,
        suggest_ban=(r["risk_level"] in ("high", "critical")),
    )


def _access_where(
    keyword: str = "",
    level: str = "",
    port: Optional[int] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
) -> Tuple[str, List[Any]]:
    """访问日志的 WHERE 片段（不含 `WHERE 1=1`），供查询与计数**共用**。

    为什么必须共用：`count_access_logs` 要回答「共 N 条 / 第 x/y 页」，
    一旦它和列表查询各写一份条件，改一处漏一处就会变成「显示 200 条、
    分页却说 3 页」这种最难自查的错。测试里有一条专门盯这个
    （`tests/test_query_access.py::test_count_matches_query`）。

    ⚠️ `keyword` 是 `%kw%` 前缀通配，`ip / path / user_agent` 三列的
    LIKE 都**走不了索引**（`idx_access_ip` 只对 `ip = ?` 有效），
    所以调用方要把单页条数压住，别让它扫全表。
    """
    sql = ""
    args: List[Any] = []
    if keyword:
        sql += " AND (ip LIKE ? OR path LIKE ? OR user_agent LIKE ?)"
        like = f"%{keyword}%"
        args += [like, like, like]
    if level:
        sql += " AND risk_level = ?"
        args.append(level)
    if port:
        sql += " AND local_port = ?"
        args.append(port)
    if since_ts is not None:
        sql += " AND event_ts >= ?"
        args.append(int(since_ts))
    if until_ts is not None:
        sql += " AND event_ts < ?"
        args.append(int(until_ts))
    return sql, args


def query_access_logs(
    limit: int = 500,
    offset: int = 0,
    keyword: str = "",
    level: str = "",
    port: Optional[int] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
) -> List[AccessRecord]:
    """按条件取历史访问记录（最新在前）。

    `since_ts` / `until_ts` 是 epoch 毫秒的**左闭右开**区间
    （`event_ts >= since_ts AND event_ts < until_ts`），与 `query_risk_events`
    同口径：右端取开区间，是为了让「结束日期」直接传「次日零点」，
    否则选到 10-19 这天时 23:59:59.999 会漏掉。

    `offset` 配合 `count_access_logs` 做分页：先 count 拿总数，再按
    `offset = 页码 * limit` 逐页取。
    """
    where, args = _access_where(keyword, level, port, since_ts, until_ts)
    # `where` 里只有固定片段，所有外部值都走参数绑定（见 _access_where）
    sql = "SELECT * FROM access_log WHERE 1=1" + where  # noqa: S608
    sql += " ORDER BY event_ts DESC, id DESC LIMIT ? OFFSET ?"
    args += [limit, offset]
    conn = _connect()
    try:
        return [_row_to_access(r) for r in conn.execute(sql, args)]
    finally:
        conn.close()


def count_access_logs(
    keyword: str = "",
    level: str = "",
    port: Optional[int] = None,
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
) -> int:
    """与 `query_access_logs` **同条件**的总条数（分页用）。"""
    where, args = _access_where(keyword, level, port, since_ts, until_ts)
    sql = "SELECT COUNT(*) c FROM access_log WHERE 1=1" + where  # noqa: S608
    conn = _connect()
    try:
        return int(conn.execute(sql, args).fetchone()["c"])
    finally:
        conn.close()


def count_today() -> Tuple[int, int]:
    """返回 (今日访问数, 今日风险数)"""
    today = datetime.date.today()
    start = int(datetime.datetime(today.year, today.month, today.day).timestamp() * 1000)
    conn = _connect()
    try:
        total = conn.execute(
            "SELECT COUNT(*) c FROM access_log WHERE event_ts >= ?", (start,)
        ).fetchone()["c"]
        risk = conn.execute(
            "SELECT COUNT(*) c FROM access_log WHERE event_ts >= ? AND risk_score > 0", (start,)
        ).fetchone()["c"]
        return int(total), int(risk)
    finally:
        conn.close()


def delete_old_access(days: int) -> int:
    if days <= 0:
        return 0
    cutoff = now_ms() - days * 86400 * 1000
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM access_log WHERE event_ts < ?", (cutoff,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


#: 允许被保留期清理**自动**删掉的封禁状态。
#
# 这一组是白名单而不是黑名单，原因：ban_list 的 status 里唯一「对应一条真实
# 存在的 Windows 防火墙规则」的是 active。删掉 active 记录只是删了记账，
# 防火墙里的规则还在，从此变成没人认领的无主规则（只能靠对账兜底发现）。
# 反过来，写死「只删这三种终态」意味着将来新增状态时**默认不被清理** ——
# 新增状态出 bug 的后果顶多是库变大，不会静默制造无主规则。
CLEANABLE_BAN_STATUS = (STATUS_UNBANNED, STATUS_EXPIRED, STATUS_FAILED)


def delete_old_risk_events(days: int) -> int:
    """
    删除超过保留期的风险事件，返回删除条数。

    ⚠️ 保留期**刻意独立于** access_log（`risk_retention_days` 默认比
    `log_retention_days` 长）：事件是规则算出来的结论，流水是原始事实。
    共用 30 天的话，「这台机器三个月前被判过严重风险」这件事会比流水更早消失，
    而事件页的「未处理」计数也会在某天早上突然掉一大截，很难解释。
    """
    if days <= 0:
        return 0
    cutoff = now_ms() - days * 86400 * 1000
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM risk_event WHERE event_ts < ?", (cutoff,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def delete_old_bans(days: int) -> int:
    """
    删除超过保留期的**终态**封禁记录，返回删除条数。

    三条硬边界（缺一条就是线上事故）：
    1. `active` **永不清理** —— 它对应一条真实存在的防火墙规则，删库记录会让
       规则变无主（既不能被到期巡检解封，也不会出现在「已封禁」列表里）；
    2. `pending` **永不清理** —— 它是「插库 → 调防火墙 → 回填 active/failed」
       之间的瞬态，进程被杀就会残留。把它清掉等于替用户做了一次「这次封禁
       没发生过」的决定，而这个决定本不该由清理任务来做；
    3. 其余状态（`failed` / `expired` / `unbanned`）才是可清理的终态。

    ⚠️ 时间列是字符串：`created_at` 由 `datetime('now','localtime')` 生成
    （见 SCHEMA），格式 `YYYY-MM-DD HH:MM:SS`，定长下字典序即时间序，所以
    这里只能写 `datetime(created_at) < datetime('now','localtime','-N days')`。
    这是 ban_list 的历史包袱，与全项目 epoch 毫秒口径不一致，改表结构要另开
    一次迁移。
    """
    if days <= 0:
        return 0
    placeholders = ", ".join("?" for _ in CLEANABLE_BAN_STATUS)
    conn = _connect()
    try:
        cur = conn.execute(
            # 状态数量固定且来自模块级常量元组，不是外部输入
            f"DELETE FROM ban_list WHERE status IN ({placeholders}) "  # noqa: S608
            "AND datetime(created_at) < datetime('now','localtime',?)",
            [*CLEANABLE_BAN_STATUS, f"-{int(days)} days"],
        )
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def delete_old_audit(days: int) -> int:
    """
    删除超过保留期的审计记录，返回删除条数。

    审计表本身也是无界增长的：自动封禁、到期巡检、定期清理都会持续写入。
    不给它保留期，等于一边修「派生表永久增长」一边新造一张永久增长的表。
    默认 180 天 —— 足够覆盖一次季度审计回溯。
    """
    if days <= 0:
        return 0
    cutoff = now_ms() - days * 86400 * 1000
    conn = _connect()
    try:
        cur = conn.execute("DELETE FROM audit_log WHERE ts < ?", (cutoff,))
        conn.commit()
        return cur.rowcount
    finally:
        conn.close()


def vacuum() -> None:
    """整理数据库文件并回收磁盘（长期运行 + 大量删除后建议偶尔执行）。

    VACUUM 会把整库重写一遍，**不能在事务里执行**（否则报
    `cannot VACUUM from within a transaction`），所以这里用独立短连接、
    既不 BEGIN 也不 commit。

    收尾补一次 `wal_checkpoint(TRUNCATE)`：VACUUM 之后 `-wal` 里还留着旧的
    页帧，不截断的话「整理完磁盘没变小」的观感就来自这个文件（它不会自己缩）。
    """
    conn = _connect()
    try:
        conn.execute("VACUUM")
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    finally:
        conn.close()


def reindex() -> None:
    """重建全部索引。

    长期运行 + 频繁删改之后索引 B 树会有空洞和碎片，查询退化成更多页读取；
    `REINDEX` 重建后体积与耗时回到初始水平。比 VACUUM 快得多（只重写索引，
    不动数据页），但仍是全表量级的写操作 —— 界面侧同样要放到后台线程。
    """
    conn = _connect()
    try:
        conn.execute("REINDEX")
    finally:
        conn.close()


def analyze() -> None:
    """收集查询计划统计（写入 `sqlite_stat1`），让优化器挑到更合适的索引。

    可选动作，界面没有单独入口：本工具的数据量级（几万~几百万行）下，SQLite
    默认的「无统计信息」启发式已经够用，跑一次 ANALYZE 要把每个索引整份扫一遍，
    收益与耗时不成比例。保留给脚本 / 排障时手动调用。
    """
    conn = _connect()
    try:
        conn.execute("ANALYZE")
    finally:
        conn.close()


def db_size() -> Dict[str, int]:
    """数据库占用的磁盘字节数：主库 + `-wal` + `-shm` + 合计。

    为什么三个一起算：WAL 模式下刚写完的大批数据还在 `-wal` 里，只看主库会
    明显偏小（清理完尤其明显）；`-shm` 是共享内存索引，通常几十 KB，但它的
    有无会让「整理前 / 整理后」的对比凭空抖动。文件不存在按 0 计 —— 首次启动
    时两个 sidecar 还没建出来。
    """
    base = db_path()
    out: Dict[str, int] = {"main": 0, "wal": 0, "shm": 0, "total": 0}
    for key, suffix in (("main", ""), ("wal", "-wal"), ("shm", "-shm")):
        try:
            out[key] = os.path.getsize(base + suffix)
        except OSError:
            out[key] = 0
        out["total"] += out[key]
    return out


def clear_all_logs() -> None:
    conn = _connect()
    try:
        conn.execute("DELETE FROM access_log")
        conn.execute("DELETE FROM risk_event")
        conn.commit()
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════
#  风险事件
# ═══════════════════════════════════════════════════════════

_INSERT_RISK_SQL = """
INSERT INTO risk_event
   (access_id, ip, local_port, path, risk_score, risk_level,
    matched_rules, summary, geo, handled, event_ts)
VALUES (?,?,?,?,?,?,?,?,?,0,?)
"""


def insert_risk_event_sql(
    conn: sqlite3.Connection, rec: AccessRecord, result: RiskResult, access_id: Optional[int] = None
) -> int:
    """纯执行版本（不建连、不提交），供批量写入器在事务内调用"""
    cur = conn.execute(
        _INSERT_RISK_SQL,
        (
            access_id,
            rec.ip,
            rec.local_port,
            rec.path,
            result.score,
            result.level,
            json.dumps(result.matched_rules, ensure_ascii=False),
            result.reason,
            (rec.geo or GeoInfo()).to_json(),
            rec.event_ts,
        ),
    )
    return int(cur.lastrowid or 0)


def insert_risk_event(
    rec: AccessRecord, result: RiskResult, access_id: Optional[int] = None
) -> int:
    """便捷版本：自建连接 + 单条提交"""
    conn = _connect()
    try:
        rid = insert_risk_event_sql(conn, rec, result, access_id)
        conn.commit()
        return rid
    finally:
        conn.close()


def query_risk_events(
    limit: int = 500,
    offset: int = 0,
    level: str = "",
    handled: Optional[int] = None,
    keyword: str = "",
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """按条件取风险事件。

    `since_ts` / `until_ts` 是 epoch 毫秒的**左闭右开**区间
    （`event_ts >= since_ts AND event_ts < until_ts`）。右端取开区间是为了让
    「结束日期」能直接传「次日零点」——否则选到 10-19 这一天时，
    10-19 23:59:59.999 的事件会漏掉，而毫秒精度下手写 +86399999 很容易算错。
    """
    sql = "SELECT * FROM risk_event WHERE 1=1"
    args: List[Any] = []
    if level:
        sql += " AND risk_level = ?"
        args.append(level)
    if handled is not None:
        sql += " AND handled = ?"
        args.append(handled)
    if keyword:
        sql += " AND (ip LIKE ? OR summary LIKE ?)"
        args += [f"%{keyword}%", f"%{keyword}%"]
    if since_ts is not None:
        sql += " AND event_ts >= ?"
        args.append(int(since_ts))
    if until_ts is not None:
        sql += " AND event_ts < ?"
        args.append(int(until_ts))
    sql += " ORDER BY event_ts DESC, id DESC LIMIT ? OFFSET ?"
    args += [limit, offset]
    conn = _connect()
    try:
        out = []
        for r in conn.execute(sql, args):
            d = dict(r)
            try:
                d["matched_rules"] = json.loads(d["matched_rules"]) if d["matched_rules"] else []
            except Exception:
                d["matched_rules"] = []
            d["geo"] = GeoInfo.from_json(d.get("geo"))
            out.append(d)
        return out
    finally:
        conn.close()


def set_risk_handled(event_id: int, handled: int) -> None:
    conn = _connect()
    try:
        conn.execute("UPDATE risk_event SET handled = ? WHERE id = ?", (handled, event_id))
        conn.commit()
    finally:
        conn.close()


def set_risk_handled_batch(event_ids: List[int], handled: int) -> int:
    """批量改处理状态（确认 / 忽略），返回实际更新的行数。

    一次事务 + executemany：勾选 2000 条时逐条提交会产生 2000 次 fsync，
    在机械盘或杀软驻留的机器上能卡住界面好几秒。
    """
    ids = [int(i) for i in event_ids]
    if not ids:
        return 0
    conn = _connect()
    try:
        cur = conn.executemany(
            "UPDATE risk_event SET handled = ? WHERE id = ?", [(handled, i) for i in ids]
        )
        conn.commit()
        return int(cur.rowcount or 0)
    finally:
        conn.close()


def set_risk_handled_by_ip(ip: str, handled: int = 1) -> int:
    """把某个 IP 的**未处理**事件整批改状态，返回实际更新的行数。

    封禁成功后必须调一次：否则用户封完 IP 回到事件页一看，同一批 IP 还挂在
    「未处理」里，会以为封禁没生效（这正是「状态不跟着操作变」的主要来源）。

    两个刻意的收窄：
    · **只动 `handled = 0`**：被人工「忽略」过的事件是明确判断，封禁不该把它
      翻成「已确认」；
    · **`ip = ?` 等值匹配**：`query_bans` 那种 `ip LIKE %kw%` 会把 1.2.3.4
      和 1.2.3.40 一起改掉。
    """
    key = (ip or "").strip()
    if not key:
        return 0
    conn = _connect()
    try:
        cur = conn.execute(
            "UPDATE risk_event SET handled = ? WHERE ip = ? AND handled = 0", (handled, key)
        )
        conn.commit()
        return int(cur.rowcount or 0)
    finally:
        conn.close()


def delete_risk_events(event_ids: List[int]) -> int:
    """批量删除风险事件，返回删除行数。

    只删 risk_event，**不动 access_log**：访问流水是原始事实（统计、报表、
    「一共来过多少次」都靠它），事件是规则算出来的派生结论。删事件表示
    「这条我不认」，不应该连带把访问记录也抹掉。
    """
    ids = [int(i) for i in event_ids]
    if not ids:
        return 0
    conn = _connect()
    try:
        cur = conn.executemany("DELETE FROM risk_event WHERE id = ?", [(i,) for i in ids])
        conn.commit()
        return int(cur.rowcount or 0)
    finally:
        conn.close()


def count_risk_unhandled() -> int:
    conn = _connect()
    try:
        return int(
            conn.execute("SELECT COUNT(*) c FROM risk_event WHERE handled = 0").fetchone()["c"]
        )
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════
#  封禁列表
# ═══════════════════════════════════════════════════════════

# ban_list 允许被 update_ban 更新的列（白名单，防动态列名注入）
_BAN_UPDATABLE = {
    "ip",
    "rule_name",
    "reason",
    "risk_score",
    "source",
    "status",
    "duration_sec",
    "expire_at",
    "error_msg",
    "unblocked_by",
}


def insert_ban(rec: BanRecord) -> int:
    conn = _connect()
    try:
        cur = conn.execute(
            """INSERT INTO ban_list
               (ip, rule_name, reason, risk_score, source, status,
                duration_sec, expire_at, error_msg)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                rec.ip,
                rec.rule_name,
                rec.reason,
                rec.risk_score,
                rec.source,
                rec.status,
                rec.duration_sec,
                rec.expire_at,
                rec.error_msg,
            ),
        )
        conn.commit()
        return int(cur.lastrowid or 0)
    finally:
        conn.close()


def update_ban(ban_id: Optional[int], **fields) -> None:
    """
    更新封禁记录。
    列名来自 kwargs，原实现直接 `f"{k} = ?"` 拼接 —— 当前调用点值可控，
    但这属于「一旦有人传入外部数据就变成注入点」的写法，故加白名单。
    ban_id 为空表示记录尚未落库（如 prepare() 刚构造出来），此时无事可做。
    """
    if not fields:
        return
    if ban_id is None:
        log.warning("update_ban 收到空 id，已忽略：%s", sorted(fields))
        return
    bad = set(fields) - _BAN_UPDATABLE
    if bad:
        raise ValueError(f"不允许更新的列: {sorted(bad)}")
    fields["updated_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cols = ", ".join(f"{k} = ?" for k in fields)
    conn = _connect()
    try:
        # 列名来自 _BAN_UPDATABLE 白名单（上面已校验），值全部走参数绑定，
        # 故此处 f-string 拼接的是「白名单内的固定列名」，不存在注入面。
        conn.execute(
            f"UPDATE ban_list SET {cols} WHERE id = ?",  # noqa: S608
            [*list(fields.values()), ban_id],
        )
        conn.commit()
    finally:
        conn.close()


def _row_to_ban(r: sqlite3.Row) -> BanRecord:
    # unblocked_by 是 v2 迁移才加的列。这里按列名先判一次再取，避免拿到
    # 老库（或测试里手工建的、没跑迁移的表）时 KeyError 把整个列表页打崩。
    keys = r.keys()
    return BanRecord(
        id=r["id"],
        ip=r["ip"],
        rule_name=r["rule_name"] or "",
        reason=r["reason"] or "",
        risk_score=r["risk_score"] or 0,
        source=r["source"],
        status=r["status"],
        duration_sec=r["duration_sec"],
        expire_at=r["expire_at"],
        created_at=r["created_at"] or "",
        updated_at=r["updated_at"] or "",
        error_msg=r["error_msg"] or "",
        unblocked_by=(r["unblocked_by"] or "") if "unblocked_by" in keys else "",
    )


def query_bans(limit: int = 1000, status: str = "", keyword: str = "") -> List[BanRecord]:
    sql = "SELECT * FROM ban_list WHERE 1=1"
    args: List[Any] = []
    if status:
        sql += " AND status = ?"
        args.append(status)
    if keyword:
        sql += " AND (ip LIKE ? OR reason LIKE ?)"
        args += [f"%{keyword}%", f"%{keyword}%"]
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    conn = _connect()
    try:
        return [_row_to_ban(r) for r in conn.execute(sql, args)]
    finally:
        conn.close()


def get_ban(ban_id: int) -> Optional[BanRecord]:
    conn = _connect()
    try:
        r = conn.execute("SELECT * FROM ban_list WHERE id = ?", (ban_id,)).fetchone()
        return _row_to_ban(r) if r else None
    finally:
        conn.close()


def find_active_ban_by_ip(ip: str) -> Optional[BanRecord]:
    conn = _connect()
    try:
        r = conn.execute(
            "SELECT * FROM ban_list WHERE ip = ? AND status = ? ORDER BY id DESC LIMIT 1",
            (ip, STATUS_ACTIVE),
        ).fetchone()
        return _row_to_ban(r) if r else None
    finally:
        conn.close()


def count_bans_by_ip(ip: str, since_ts: Optional[int] = None) -> int:
    """
    某 IP 的历史封禁次数（递增封禁策略用）。

    细节与理由：
    · **不看 status**：解封 / 到期 / 失败都算。要回答的是「这个 IP 是不是惯犯」，
      而不是「现在是否还在封禁中」。只数 active 的话，攻击者等解封后重来一次
      就又回到「第一次」，递增永远不生效。
    · **必须 `ip = ?` 等值**：`query_bans` 的 keyword 走 `ip LIKE %kw%`，
      `203.0.113.1` 会连带命中 `203.0.113.10~19`，拿来精确计数是错的。
    · since_ts 为 epoch 毫秒，只统计该时刻之后创建的记录。created_at 存的是
      `YYYY-MM-DD HH:MM:SS` 本地时间字符串（见 SCHEMA），定长格式下字典序即时间序。

    ⚠️ 调用点必须在 `insert_ban` **之前**：本函数不排除任何记录，插库后再数会把
    本次封禁自己数进去，第一次封禁就被当成第二次，时长直接翻倍。
    """
    sql = "SELECT COUNT(*) c FROM ban_list WHERE ip = ?"
    args: List[Any] = [ip]
    if since_ts:
        sql += " AND created_at >= ?"
        args.append(ms_to_str(since_ts))
    conn = _connect()
    try:
        return int(conn.execute(sql, args).fetchone()["c"])
    finally:
        conn.close()


def list_all_active_bans() -> List[BanRecord]:
    return query_bans(status=STATUS_ACTIVE, limit=100000)


def active_ban_ip_map() -> Dict[str, BanRecord]:
    """当前生效中的封禁，按 IP 索引 —— 界面行内按钮据此显示「已封禁」。

    页面在 refresh 里查**一次**给整张表用：逐行调 `find_active_ban_by_ip`
    在 200 行的表上就是 200 次建连 + 200 次查询，直接把渲染拖成秒级。
    """
    return {b.ip: b for b in list_all_active_bans()}


def list_expired_bans(now: Optional[int] = None) -> List[BanRecord]:
    """已到期但仍处于 active 的封禁"""
    now = now or now_ms()
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT * FROM ban_list WHERE status = ? AND expire_at IS NOT NULL AND expire_at <= ?",
            (STATUS_ACTIVE, now),
        )
        return [_row_to_ban(r) for r in rows]
    finally:
        conn.close()


def mark_ban_unbanned(
    ban_id: Optional[int], new_status: str = STATUS_UNBANNED, unblocked_by: Optional[str] = None
) -> None:
    """
    把封禁记录标记为「已解封」，可选同时记下是谁解的。

    `unblocked_by` 是 v2 迁移就加好的列，此前**一个写入点都没有** ——
    解封人字段长期空置，「谁在何时解封了谁」这个问题根本答不上来。
    口径见 app.audit 的 ACTOR_*（本地用户名 / system / http:<来源IP>）。
    """
    fields: Dict[str, Any] = {"status": new_status}
    if unblocked_by:
        fields["unblocked_by"] = str(unblocked_by)
    update_ban(ban_id, **fields)


def count_active_bans() -> int:
    conn = _connect()
    try:
        return int(
            conn.execute(
                "SELECT COUNT(*) c FROM ban_list WHERE status = ?", (STATUS_ACTIVE,)
            ).fetchone()["c"]
        )
    finally:
        conn.close()


def count_today_bans() -> int:
    today = datetime.date.today()
    start = datetime.datetime(today.year, today.month, today.day).strftime("%Y-%m-%d %H:%M:%S")
    conn = _connect()
    try:
        return int(
            conn.execute(
                "SELECT COUNT(*) c FROM ban_list WHERE created_at >= ?", (start,)
            ).fetchone()["c"]
        )
    finally:
        conn.close()


def delete_ban_record(ban_id: int) -> None:
    conn = _connect()
    try:
        conn.execute("DELETE FROM ban_list WHERE id = ?", (ban_id,))
        conn.commit()
    finally:
        conn.close()


def delete_ban_records(ban_ids: List[int]) -> int:
    """批量删除封禁记录，返回实际删除行数。

    只删数据库记录，不动已经写入 Windows 防火墙的规则——前者是记账，
    后者是既成事实。要撤规则必须走「解封」，否则防火墙里会留下无主规则。
    """
    ids = [int(i) for i in ban_ids]
    if not ids:
        return 0
    conn = _connect()
    try:
        cur = conn.executemany("DELETE FROM ban_list WHERE id = ?", [(i,) for i in ids])
        conn.commit()
        return int(cur.rowcount or 0)
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════
#  操作审计（audit_log）
# ═══════════════════════════════════════════════════════════
#
# 本模块只提供「原始读写」。**谁该在什么时候记一条**，是 app.audit 的职责 ——
# 埋点分散在各业务动作里，塞进这里的写函数会让它们被迫多收一个 actor 参数，
# 而这些函数被 GUI / 业务层 / 测试多处直接调用，签名一改全得跟着改。

_INSERT_AUDIT_SQL = """
INSERT INTO audit_log
   (ts, actor, action, target_type, target_id, summary, before_json, after_json, result, detail)
VALUES (?,?,?,?,?,?,?,?,?,?)
"""


def insert_audit(
    ts: int,
    actor: str,
    action: str,
    target_type: str = "",
    target_id: Optional[str] = None,
    summary: str = "",
    before_json: Optional[str] = None,
    after_json: Optional[str] = None,
    result: str = "ok",
    detail: str = "",
) -> int:
    """
    写一条审计记录，返回 rowid。失败会**抛出**——调用方（app.audit.record）
    负责兜住异常，因为审计写不进去绝不能反过来中断业务动作。
    """
    conn = _connect()
    try:
        cur = conn.execute(
            _INSERT_AUDIT_SQL,
            (
                int(ts),
                str(actor),
                str(action),
                str(target_type),
                None if target_id is None else str(target_id),
                str(summary),
                before_json,
                after_json,
                str(result),
                str(detail),
            ),
        )
        conn.commit()
        return int(cur.lastrowid or 0)
    finally:
        conn.close()


def _audit_where(
    actor: str = "",
    action: str = "",
    keyword: str = "",
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
) -> Tuple[str, List[Any]]:
    """与查询/计数共用的 WHERE 片段（全部走参数绑定）"""
    sql = ""
    args: List[Any] = []
    if actor:
        sql += " AND actor = ?"
        args.append(actor)
    if action:
        sql += " AND action = ?"
        args.append(action)
    if keyword:
        sql += " AND (summary LIKE ? OR detail LIKE ? OR target_id LIKE ?)"
        like = f"%{keyword}%"
        args += [like, like, like]
    if since_ts is not None:
        sql += " AND ts >= ?"
        args.append(int(since_ts))
    if until_ts is not None:
        sql += " AND ts < ?"
        args.append(int(until_ts))
    return sql, args


def query_audit(
    limit: int = 200,
    offset: int = 0,
    actor: str = "",
    action: str = "",
    keyword: str = "",
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """按条件取审计记录（最新在前）。`since_ts`/`until_ts` 为左闭右开 epoch 毫秒。"""
    where, args = _audit_where(actor, action, keyword, since_ts, until_ts)
    sql = "SELECT * FROM audit_log WHERE 1=1" + where  # noqa: S608
    sql += " ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?"
    args += [limit, offset]
    conn = _connect()
    try:
        return [dict(r) for r in conn.execute(sql, args)]
    finally:
        conn.close()


def count_audit(
    actor: str = "",
    action: str = "",
    keyword: str = "",
    since_ts: Optional[int] = None,
    until_ts: Optional[int] = None,
) -> int:
    """与 `query_audit` **同条件**的总条数（分页用）"""
    where, args = _audit_where(actor, action, keyword, since_ts, until_ts)
    sql = "SELECT COUNT(*) c FROM audit_log WHERE 1=1" + where  # noqa: S608
    conn = _connect()
    try:
        return int(conn.execute(sql, args).fetchone()["c"])
    finally:
        conn.close()


def list_audit_actors(limit: int = 50) -> List[str]:
    """
    列出出现过的 actor（供界面的「操作者」下拉框用），按最近出现排序。

    为什么不做成 `SELECT DISTINCT`：审计表会一直涨，「谁出现过」这个集合
    本身是有界的小集合，但 DISTINCT 会全表扫；按 ts 走索引取最近若干条再
    在 Python 里去重，实际更快也更符合「下拉框只放近期的人」的直觉。
    """
    conn = _connect()
    try:
        rows = conn.execute(
            "SELECT actor FROM audit_log ORDER BY ts DESC LIMIT ?", (max(1, int(limit)) * 20,)
        )
        seen: List[str] = []
        for r in rows:
            a = r["actor"]
            if a and a not in seen:
                seen.append(a)
                if len(seen) >= limit:
                    break
        return seen
    finally:
        conn.close()
