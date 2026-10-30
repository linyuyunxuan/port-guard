"""
PortGuard — 数据与文件维护（不依赖 Qt）

- 访问日志（access_log）按保留天数清理
- 风险事件（risk_event）按**自己的**保留天数清理（比流水长，见核心说明）
- 封禁记录（ban_list）只清**终态**，且按**自己的**保留天数清理
- 审计记录（audit_log）按自己的保留天数清理（否则审计表自己就是新的无界表）
- 日志文件按保留天数清理（按日期滚动后的归档 + 历史遗留归档）
- 离线库备份保留最近 N 份，其余删除（否则每次同步都留一份 11~37MB 的副本）
- 下载临时目录清扫（异常中断可能留下 .part）
- 数据库维护：VACUUM（回收磁盘）/ REINDEX（重建索引）/ 一致性备份 / 整份恢复

⚠️ 大批量 DELETE 会让 WAL 文件涨到与被删数据同量级，且 SQLite **不会自动把
这部分空间还给文件系统**（只是留给后续写入复用）。想要真正回收磁盘，需要
在清理后执行一次 `VACUUM`（`vacuum_db()`，设置页「数据库维护」里的入口）。
"""

import contextlib
import os
import shutil
import sqlite3
import time
from typing import Any, Dict, List, Optional, Tuple

from app import audit
from core import database, db_writer
from core import settings as cfg
from core.config import (
    DEFAULT_AUDIT_RETENTION_DAYS,
    DEFAULT_BAN_RETENTION_DAYS,
    DEFAULT_LOG_RETENTION_DAYS,
    DEFAULT_RISK_RETENTION_DAYS,
    backup_dir,
    db_path,
    download_dir,
)
from core.database import (
    delete_old_access,
    delete_old_audit,
    delete_old_bans,
    delete_old_risk_events,
)
from core.logger import get_logger, log_file, logs_dir

log = get_logger(__name__)

# 每个库保留的备份份数
KEEP_BACKUPS_PER_FILE = 3

#: 数据库备份保留份数。与离线库同一取法：留 3 份足够覆盖「刚同步 / 刚清理 /
#: 上一次恢复」三个时间点，再多就是几百 MB × N 的净浪费。
KEEP_DB_BACKUPS = 3


def cleanup_logs(days: int = 0) -> int:
    """删除超过保留期的访问日志，返回删除条数"""
    days = days or cfg.get_int("log_retention_days", DEFAULT_LOG_RETENTION_DAYS)
    try:
        n = delete_old_access(days)
        if n:
            log.info("已清理 %d 条超过 %d 天的访问日志", n, days)
        return n
    except Exception:
        log.exception("清理过期日志失败")
        return 0


def cleanup_risk(days: int = 0) -> int:
    """
    删除超过保留期的**风险事件**，返回删除条数。

    ⚠️ 保留期**刻意独立**于访问日志（`risk_retention_days` 默认 90 天，
    比 `log_retention_days` 的 30 天长）。曾经踩过的坑：两者共用 30 天时，
    「这台机器三个月前被判过严重风险」会比流水更早消失，事件页的未处理计数
    还会在某天早上突然掉一大截。
    """
    days = days or cfg.get_int("risk_retention_days", DEFAULT_RISK_RETENTION_DAYS)
    try:
        n = delete_old_risk_events(days)
        if n:
            log.info("已清理 %d 条超过 %d 天的风险事件", n, days)
        return n
    except Exception:
        log.exception("清理过期风险事件失败")
        return 0


def cleanup_bans(days: int = 0) -> int:
    """
    删除超过保留期的**终态封禁记录**，返回删除条数。

    `active` / `pending` 永不清（见 `core.database.delete_old_bans` 的三条硬边界）：
    active 背后是一条真实存在的防火墙规则，pending 是「已插库、还没回填」的
    瞬态。把它们清掉等于替用户做「这次封禁没发生过」的决定。
    """
    days = days or cfg.get_int("ban_retention_days", DEFAULT_BAN_RETENTION_DAYS)
    try:
        n = delete_old_bans(days)
        if n:
            log.info("已清理 %d 条超过 %d 天的终态封禁记录", n, days)
        return n
    except Exception:
        log.exception("清理过期封禁记录失败")
        return 0


def cleanup_audit(days: int = 0) -> int:
    """
    删除超过保留期的审计记录，返回删除条数。

    审计表自己也在持续写入（自动封禁、到期巡检、定期清理都会记），不给它
    保留期就等于「修好三张无界表的同时新造第四张」。默认 180 天。
    """
    days = days or cfg.get_int("audit_retention_days", DEFAULT_AUDIT_RETENTION_DAYS)
    try:
        n = delete_old_audit(days)
        if n:
            log.info("已清理 %d 条超过 %d 天的审计记录", n, days)
        return n
    except Exception:
        log.exception("清理过期审计记录失败")
        return 0


def due_today() -> bool:
    """
    判断今天的定期清理是不是该跑了；判定通过时顺手把「今天已跑」落库。

    执行时刻由设置 `maintenance_hour`（0-23，默认 3 点）决定，跨天自动重置。
    首次运行（从没清理过）不受时刻限制，立即跑一次，免得新装用户等一天。

    总开关 `maintenance_enabled`（默认开）：关掉后只剩设置页的手动入口 ——
    有人就是不想让程序在夜里动数据库，这个开关必须给。

    放在这里而不是界面层：逻辑不依赖 Qt，可以直接单测（原实现埋在 QTimer
    回调里，除了跑起来看日志没有别的验证办法）。
    """
    if not cfg.get_bool("maintenance_enabled", True):
        return False
    now = time.localtime()
    today = time.strftime("%Y-%m-%d", now)
    last = (cfg.get("maintenance_last_date", "") or "").strip()
    if last == today:
        return False
    if last and now.tm_hour < cfg.get_int("maintenance_hour", 3):
        return False
    cfg.set("maintenance_last_date", today)
    return True


def apply_retention_preset(days: int) -> Dict[str, int]:
    """
    把「全部日志保留 N 天」一次写进四张表各自的设置项。

    用户要的是「1 天 / 3 天 / 7 天」这种一句话选完的档位（2026-10-22），
    而不是在四个 SpinBox 里逐个填 —— 但四张表的保留期**本质上是四个语义**
    （见 core.config.DEFAULT_*_RETENTION_DAYS），所以预设只是「一次写入四项」，
    底下那四项仍然是各自的真实取值，选「自定义」后依然可以分别调。

    返回写入的四个值（供界面回显）。
    """
    days = max(1, int(days))
    values: Dict[str, int] = {
        "log_retention_days": days,
        "risk_retention_days": days,
        "ban_retention_days": days,
        "audit_retention_days": days,
    }
    cfg.set_many(values)
    return values


def cleanup_log_files(days: int = 0) -> int:
    """
    删除超过保留期的日志文件（按日期），返回删除个数。

    为什么还要单独扫一遍：文件日志虽然是按天滚动的，但「滚动」只在**有日志
    写入**时才发生，而且旧版本用的是按大小滚动（portguard.log.1 ~ .5）。程序
    若长期不写日志、或经历过版本升级，logs/ 下就会留下永远不会被回收的归档。
    这里按 mtime 做一次兜底清扫，保证「日志保留 N 天」是真的 N 天。

    安全边界：绝不删除当前正在写入的 portguard.log —— 一是它是活跃句柄，
    二是 Windows 上删除在用文件本来也会失败。
    """
    days = max(1, int(days or cfg.get_int("log_retention_days", 30)))
    removed = 0
    try:
        d = logs_dir()
        active = os.path.basename(log_file()).lower()
        cutoff = time.time() - days * 86400
        for f in os.listdir(d):
            if f.lower() == active or ".log" not in f.lower():
                continue
            p = os.path.join(d, f)
            if not os.path.isfile(p):
                continue
            try:
                if os.path.getmtime(p) < cutoff:
                    os.remove(p)
                    removed += 1
            except OSError:
                log.exception("删除过期日志文件失败：%s", f)
        if removed:
            log.info("已清理 %d 个超过 %d 天的日志文件", removed, days)
    except Exception:
        log.exception("清理日志文件失败")
    return removed


def cleanup_backups(keep: int = KEEP_BACKUPS_PER_FILE) -> int:
    """每个离线库只保留最近 keep 份备份，返回删除文件数"""
    removed = 0
    try:
        d = backup_dir()
        groups: dict = {}
        for f in os.listdir(d):
            if "." not in f:
                continue
            name = f.rsplit(".", 2)[0] if f.count(".") >= 2 else f
            groups.setdefault(name, []).append(f)
        for _name, files in groups.items():
            files.sort(reverse=True)  # 文件名内含时间戳，倒序即最新在前
            for stale in files[keep:]:
                try:
                    os.remove(os.path.join(d, stale))
                    removed += 1
                except Exception:
                    log.exception("删除旧备份失败：%s", stale)
        if removed:
            log.info("已清理 %d 个过期离线库备份", removed)
    except Exception:
        log.exception("清理离线库备份失败")
    return removed


def cleanup_downloads() -> int:
    """清扫下载临时目录（.part / .new 残留）"""
    removed = 0
    try:
        d = download_dir()
        for f in os.listdir(d):
            p = os.path.join(d, f)
            if os.path.isfile(p) and (f.endswith((".part", ".new"))):
                try:
                    os.remove(p)
                    removed += 1
                except Exception:
                    pass
    except Exception:
        log.exception("清理下载临时目录失败")
    return removed


# ═══════════════════════════════════════════════════════════
#  数据库维护（VACUUM / 重建索引 / 备份与恢复）
# ═══════════════════════════════════════════════════════════


def format_size(n: int) -> str:
    """字节数 → 人读的大小。数据库动辄几百 MB，用 KB 表示没人看得懂。"""
    v = float(n or 0)
    if v < 1024:
        return f"{v:.0f} B"
    for unit in ("KB", "MB", "GB"):
        v /= 1024.0
        if v < 1024 or unit == "GB":
            return f"{v:.1f} {unit}"
    return f"{v:.1f} GB"


def _db_base_name() -> str:
    """备份文件名的主体（`port_guard`）。

    沿用离线库的 `{主体}.{时间戳}.bak` 命名：`cleanup_backups()` 用
    `rsplit(".", 2)[0]` 分组，这两种命名落在同一套规则里，各自的旧备份各删各的。
    """
    return os.path.splitext(os.path.basename(db_path()))[0]


def _is_db_backup(file_name: str) -> bool:
    return file_name.startswith(_db_base_name() + ".") and file_name.endswith(".bak")


def list_db_backups() -> List[Dict[str, Any]]:
    """列出可恢复的数据库备份，新的在前。

    只认 `port_guard.<时间戳>.bak` 这种命名 —— 备份目录里还躺着离线库的
    `ip2region_v4.<时间戳>.bak`，用 `*.bak` 一把捞会把它们列进「数据库备份」，
    用户点恢复就直接把 11MB 的归属地库盖到数据库上。
    """
    out: List[Dict[str, Any]] = []
    try:
        d = backup_dir()
        for f in os.listdir(d):
            if not _is_db_backup(f):
                continue
            p = os.path.join(d, f)
            try:
                st = os.stat(p)
            except OSError:
                continue
            out.append(
                {
                    "file": f,
                    "path": p,
                    "size": st.st_size,
                    "mtime": int(st.st_mtime * 1000),
                }
            )
    except Exception:
        log.exception("读取数据库备份失败")
        return []
    out.sort(key=lambda x: (x["mtime"], x["file"]), reverse=True)
    return out


def cleanup_db_backups(keep: int = KEEP_DB_BACKUPS) -> int:
    """只保留最近 keep 份数据库备份，返回删除个数。

    时间戳单调递增（同秒撞名会顺延，见 `backup_db`），所以按文件名倒序即
    「新的在前」，不必依赖 mtime —— 备份文件被复制 / 解压过之后 mtime 会乱。
    """
    removed = 0
    try:
        d = backup_dir()
        files = [f for f in os.listdir(d) if _is_db_backup(f)]
        files.sort(reverse=True)
        for stale in files[max(1, keep) :]:
            try:
                os.remove(os.path.join(d, stale))
                removed += 1
            except OSError:
                log.exception("删除旧数据库备份失败：%s", stale)
        if removed:
            log.info("已清理 %d 个过期数据库备份", removed)
    except Exception:
        log.exception("清理数据库备份失败")
    return removed


def backup_db() -> Tuple[bool, str]:
    """打一份**一致性快照**，成功返回 (True, 备份文件路径)，失败 (False, 原因)。

    ⚠️ 绝不能用 `shutil.copy2` 直接拷 `.db`：库跑在 WAL 模式下，写入器还有一条
    长连接，此刻磁盘上的 `port_guard.db` 只是「已 checkpoint 的那部分」，剩下的
    新数据还在 `-wal` 里 —— 只拷主文件会得到一份**丢掉最后几批写入**的旧快照；
    把三个文件一起拷又可能拿到写了一半的中间态（拷完主文件、WAL 又被追加）。
    `Connection.backup()` 由 SQLite 自己在读事务里逐页复制，天然是一个一致点，
    而且不需要停写入器（P2-7 的硬要求）。
    """
    base = db_path()
    if not os.path.exists(base):
        return False, f"数据库文件不存在：{base}"

    stamp = int(time.time())
    dst = os.path.join(backup_dir(), f"{_db_base_name()}.{stamp}.bak")
    while os.path.exists(dst):
        # 同一秒内连点两次「立即备份」，后一份会直接把前一份覆盖掉 ——
        # 而那份恰恰可能是唯一能回退的副本（离线库那边踩过同一个坑）
        stamp += 1
        dst = os.path.join(backup_dir(), f"{_db_base_name()}.{stamp}.bak")

    # 先写 .part 再改名：中途失败（磁盘满 / 被中断）不会在列表里留下一个
    # 看着正常、一恢复就报废的半截文件
    tmp = dst + ".part"
    try:
        src_conn = sqlite3.connect(base, timeout=10.0)
        try:
            src_conn.execute("PRAGMA busy_timeout=10000")
            dst_conn = sqlite3.connect(tmp)
            try:
                src_conn.backup(dst_conn)
                # 备份文件必须自包含：WAL 模式下 destination 也可能落到 WAL，
                # 那样单拿一个 .bak 出去就是残缺的
                dst_conn.execute("PRAGMA journal_mode=DELETE")
            finally:
                dst_conn.close()
        finally:
            src_conn.close()
        os.replace(tmp, dst)
    except Exception as e:
        log.exception("备份数据库失败")
        _remove_quietly(tmp)
        _remove_quietly(tmp + "-journal")
        return False, str(e)

    cleanup_db_backups()
    log.info("数据库已备份：%s（%s）", dst, format_size(os.path.getsize(dst)))
    return True, dst


def _remove_quietly(path: str) -> None:
    with contextlib.suppress(OSError):
        os.remove(path)


def _replace_with_retry(src: str, dst: str, attempts: int = 20) -> None:
    """`os.replace` 覆盖一个可能正被别的连接打开着的库文件。

    Windows 上「替换目标是打开状态」会直接 PermissionError（不是排队等锁），
    而本程序的统计定时器 / 页面刷新都是短连接，随时可能在那一瞬间开着一个读
    连接。这类占用只持续几毫秒，重试几次即可，否则恢复会随机失败在一个跟用户
    操作完全无关的时刻。
    """
    last: Optional[BaseException] = None
    for _ in range(attempts):
        try:
            os.replace(src, dst)
            return
        except PermissionError as e:  # 只重试「被占用」，其它错误立刻抛
            last = e
            time.sleep(0.1)
    raise RuntimeError(f"数据库文件仍被占用，替换失败：{last}")


def restore_db(path: str, backup_current: bool = True) -> Tuple[bool, str]:
    """用备份整份替换当前库，返回 (ok, 一句话结果)。

    **顺序是有讲究的，改之前先读完这段**：

    1. 先把待恢复的备份**复制到库目录下的暂存文件**。放在备份之前做，是因为
       备份完成后会回收旧备份（只留 3 份）—— 用户若挑中的正是最旧那份，
       它会在这中间被删掉，恢复就无从谈起；复制完成后再回收就伤不到它了。
    2. 备份当前库（`backup_current`）。恢复是**不可撤销**的覆盖，先留一条退路；
       备份失败时**中止恢复** —— 没有退路的破坏性操作不做。
    3. 停写入器。它握着一条长连接和一批可能未提交的数据，不停就换文件等于把
       正在写的库从脚下抽走：Windows 上复制会 PermissionError，侥幸成功也会把
       后到的数据写进旧文件的句柄（静默丢失）或直接报错。
    4. `os.replace` 覆盖主库 + 删掉 `-wal` / `-shm`。旧的 WAL 属于旧文件，
       留着它下次打开会拿旧页帧去「恢复」新文件。
    5. `reset_init_state()` + `init_db()` + `settings.invalidate()`：备份可能
       来自老版本，表结构要靠迁移补齐；设置缓存里还是旧库的值。
    6. 重启写入器（原本在跑才重启）。

    第 4 步失败也照样走 5、6：库还是原来那份（`os.replace` 是原子的），
    总好过整个程序从此不写库。
    """
    src = str(path or "")
    if not src or not os.path.isfile(src):
        return False, f"备份文件不存在：{src or '（空路径）'}"

    staging = db_path() + ".restore"
    try:
        _remove_quietly(staging)
        shutil.copyfile(src, staging)
    except Exception as e:
        log.exception("准备恢复文件失败")
        _remove_quietly(staging)
        return False, f"读取备份文件失败：{e}"

    pre = ""
    if backup_current:
        ok, msg = backup_db()
        if not ok:
            _remove_quietly(staging)
            return False, f"恢复前备份当前库失败，已中止：{msg}"
        pre = os.path.basename(msg)

    writer = db_writer.peek_writer()
    was_running = bool(writer and writer.running)
    # 恢复前必须把写入队列落盘、并确认写入器真的停稳：否则 stop 超时后旧 writer
    # 仍持有旧库文件的孤立句柄，会把它排空到已被替换的文件里 → 数据静默丢失；
    # 两个 writer 还会抢同一把 SQLite 写锁。队列里还有在途数据时直接放弃恢复，
    # 让原写入器继续写当前库（状态自洽、零丢失），用户稍后重试即可。
    # 注意：flush 只在 was_running 时调用（没在跑就不该碰写入器）。
    writer_drained = writer.flush(timeout=10.0) and writer.pending() == 0 if was_running else True
    if was_running and not writer_drained:
        log.error(
            "数据库恢复中止：写入队列未能在超时内清空（pending=%d），取消恢复以免丢失在途数据",
            writer.pending(),
        )
        return (
            False,
            "写入队列未能及时清空，已取消恢复以免丢失待写入数据，请稍后（队列清空后）重试",
        )

    db_writer.stop_writer(timeout=10.0)

    err = ""
    try:
        _replace_with_retry(staging, db_path())
        _remove_quietly(db_path() + "-wal")
        _remove_quietly(db_path() + "-shm")
    except Exception as e:
        log.exception("覆盖数据库文件失败")
        err = f"覆盖数据库文件失败：{e}"
    finally:
        _remove_quietly(staging)
        database.reset_init_state()
        try:
            database.init_db()
        except Exception as e:
            log.exception("恢复后初始化数据库失败")
            err = err or f"文件已替换，但重新初始化数据库失败：{e}（请重启程序）"
        cfg.invalidate()
        with contextlib.suppress(Exception):
            cfg.warm()  # 恢复后立刻会被高频读，预热一次省掉逐条回源
        if was_running:
            db_writer.start_writer()

    if err:
        return False, err
    name = os.path.basename(src)
    tail = f"（恢复前已备份当前库：{pre}）" if pre else ""
    log.info("数据库已从备份恢复：%s", name)
    return True, f"已恢复到 {name}{tail}"


def vacuum_db() -> Tuple[bool, str]:
    """整理数据库并回收磁盘，返回 (ok, 一句话结果)。

    ⚠️ 几百 MB 的库要跑几十秒，**调用方必须放到后台线程**（界面层已如此）。

    先 flush 一次写入器再动手：VACUUM 收尾需要短暂的排他锁，撞上一批正在提交的
    写入会一路等到 busy_timeout（30s），界面看着像卡死。
    """
    before = 0
    try:
        w = db_writer.peek_writer()
        if w is not None:
            w.flush(timeout=5.0)
        before = database.db_size()["total"]
        database.vacuum()
        after = database.db_size()["total"]
        msg = f"数据库已整理：{format_size(before)} → {format_size(after)}"
        log.info(msg)
        return True, msg
    except Exception as e:
        log.exception("整理数据库失败")
        return False, str(e)


def reindex_db() -> Tuple[bool, str]:
    """重建全部索引，返回 (ok, 一句话结果)。同样要放后台线程。"""
    try:
        w = db_writer.peek_writer()
        if w is not None:
            w.flush(timeout=5.0)
        before = database.db_size()["total"]
        database.reindex()
        after = database.db_size()["total"]
        msg = f"索引已重建：{format_size(before)} → {format_size(after)}"
        log.info(msg)
        return True, msg
    except Exception as e:
        log.exception("重建索引失败")
        return False, str(e)


#: `run_all()` 返回值的字段顺序。改这里必须同步改 gui/mixins.py 的解包。
RUN_ALL_FIELDS = ("访问记录", "风险事件", "封禁记录", "审计记录", "日志文件", "备份", "下载残留")


def run_all() -> Tuple[int, int, int, int, int, int, int]:
    """
    一次性维护（供定时器调用）。

    返回 (访问记录, 风险事件, 封禁记录, 审计记录, 日志文件, 备份, 下载残留)，
    字段顺序见 `RUN_ALL_FIELDS`。

    审计在**清理之后**记一次汇总，而且刻意放在最后：它是唯一会在本次清理中
    被自己删掉一部分的表，先记后清意味着刚写的这条可能立刻被删。
    """
    rows = cleanup_logs()
    risk = cleanup_risk()
    bans = cleanup_bans()
    files = cleanup_log_files()
    backups = cleanup_backups()
    downloads = cleanup_downloads()
    audits = cleanup_audit()
    total = rows + risk + bans + audits
    if total or files or backups or downloads:
        audit.record(
            audit.ACTION_DATA_CLEANUP,
            actor=audit.ACTOR_SYSTEM,
            target_type="data",
            summary=(
                f"定期清理：访问 {rows}、事件 {risk}、封禁 {bans}、审计 {audits}、"
                f"日志文件 {files}、备份 {backups}、下载残留 {downloads}"
            ),
            after={
                "access_log": rows,
                "risk_event": risk,
                "ban_list": bans,
                "audit_log": audits,
                "log_files": files,
                "backups": backups,
                "downloads": downloads,
            },
            detail=(
                "大批量删除会让 WAL 文件变大且不会自动归还磁盘，"
                "需要回收空间请在设置页执行数据库维护（VACUUM）"
            ),
        )
    return rows, risk, bans, audits, files, backups, downloads


def run_daily() -> Tuple[Tuple[int, int, int, int, int, int, int], bool, str]:
    """
    每日维护（供定时器调用）：先清理过期数据，**再打一份数据库备份**。

    返回 (run_all 的计数元组, 备份是否成功, 备份路径或失败原因)。

    为什么备份要挂在这里：`run_all` 只负责删，而备份一直是「用户想起来才点」
    （报告 F3 / S8）。一个每天自动删数据的工具必须有自动退路 —— 磁盘故障、
    误恢复、升级失败都需要一份能回退的完整快照。

    顺序不可反：**先清理再备份**。备份在清理之后才是一份「小而完整」的快照；
    反过来就等于每天白拷一遍马上要被删掉的历史数据（访问流水 30 天可能几百 MB）。

    备份失败不影响清理结果：清理已经提交，把失败原样报出去由上层记日志 / 提示；
    这里**不重试** —— 磁盘满时重试只是再失败一次，还会拖住下一轮定时器。
    """
    counts = run_all()
    ok, detail = backup_db()
    if ok:
        cleanup_db_backups()
        log.info("每日自动备份完成：%s", os.path.basename(detail))
    else:
        log.error("每日自动备份失败：%s", detail)
    return counts, ok, detail
