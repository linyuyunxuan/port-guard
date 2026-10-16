"""
PortGuard — 数据库 schema 版本迁移

原实现只有 `CREATE TABLE IF NOT EXISTS`：表已存在时，**新增字段不会生效
且没有任何提示**，线上表现是「字段明明加了却不生效」。

方案：用 SQLite 内建的 `PRAGMA user_version` 做版本号，
每版一组 DDL，启动时逐版补齐。版本号高于程序支持版本时直接报错，
避免用旧程序打开新库导致数据损坏。
"""

import sqlite3
from typing import Dict, List

from core.logger import get_logger

log = get_logger(__name__)

# 当前程序支持的 schema 版本（每加一版 +1 并在下方登记 DDL）
SCHEMA_VERSION = 2

# version -> DDL 列表（从上一版升级到该版需要执行的语句）
MIGRATIONS: Dict[int, List[str]] = {
    # v1：基线。老库（无 user_version）执行到这里只补索引，不动数据。
    1: [
        "CREATE INDEX IF NOT EXISTS idx_access_ip_level ON access_log(ip, risk_level)",
    ],
    # v2：给 ban_list 补「解封人/解封原因」审计字段（示例性迁移，验证链路可用）
    2: [
        "ALTER TABLE ban_list ADD COLUMN unblocked_by TEXT",
    ],
}


def get_version(conn: sqlite3.Connection) -> int:
    try:
        return int(conn.execute("PRAGMA user_version").fetchone()[0])
    except Exception:
        return 0


def _column_exists(conn: sqlite3.Connection, table: str, column: str) -> bool:
    try:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    except Exception:
        return False
    for r in rows:
        # row_factory 可能是 sqlite3.Row（按列名）或元组（索引 1 为列名）
        try:
            name = r["name"]
        except Exception:
            name = r[1]
        if str(name).lower() == column.lower():
            return True
    return False


def migrate(conn: sqlite3.Connection) -> int:
    """
    把库升级到 SCHEMA_VERSION，返回最终版本号。
    - 幂等：已是最新则什么都不做
    - 每步在一个事务里，失败即中断并抛出，不会留下半升级状态
    """
    cur = get_version(conn)
    if cur > SCHEMA_VERSION:
        raise RuntimeError(
            f"数据库版本 v{cur} 高于本程序支持的 v{SCHEMA_VERSION}，"
            f"请升级 PortGuard 后再打开该数据文件"
        )

    if cur == SCHEMA_VERSION:
        return cur

    log.info("开始数据库迁移：v%d -> v%d", cur, SCHEMA_VERSION)
    for ver in range(cur + 1, SCHEMA_VERSION + 1):
        stmts = MIGRATIONS.get(ver, [])
        for stmt in stmts:
            try:
                conn.execute(stmt)
            except sqlite3.OperationalError as e:
                # 「列已存在」属于可安全忽略的幂等情况（手工改过库的场景）
                msg = str(e).lower()
                if "duplicate column name" in msg or "already exists" in msg:
                    log.debug("迁移 v%d 跳过（已存在）: %s", ver, stmt[:80])
                    continue
                raise
        conn.execute(f"PRAGMA user_version = {ver}")
        conn.commit()
        log.info("数据库已迁移到 v%d", ver)
    return SCHEMA_VERSION
