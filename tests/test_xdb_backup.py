"""PortGuard — 离线库备份与手动回滚（core/xdb_updater.py）

每条用例都对应一个「改回错误实现就会红」的具体回归：

| 用例                             | 挡住的回归                                             |
|----------------------------------|--------------------------------------------------------|
| 回滚前先备份当前库               | 去掉预备份 → 回滚不可撤销（回滚到旧库后新库再也找不回） |
| 当前库缺失时仍然允许回滚         | 备份失败就一律拒绝 → 库损坏时唯一的救援手段被堵死       |
| 分组按库名                       | 界面把 v4 / v6 的备份混在一起列                         |
| 分组口径与 cleanup_backups 一致  | 界面列着的备份正是下一轮清理要删的那份                  |
| 组内按 mtime 倒序                | 退回「按文件名倒序」——只在时间戳位数相同时才对          |
| 同秒内的两次备份不互相覆盖       | 换库紧接着回滚，唯一能回滚回去的副本被覆盖              |

`bak_dir` 把备份目录指向一个**每用例独立**的临时目录：`isolated_env` 是会话级
夹具，备份目录在整个 session 里是同一份，别的用例留下的备份会混进来，
「保留了哪几份」这类断言就没法写了。
"""

import os
import tempfile

import pytest

from app import maintenance
from core import config
from core import settings as cfg
from core import xdb_updater as U
from core.database import init_db

V4 = "ip2region_v4.xdb"
V6 = "ip2region_v6.xdb"


@pytest.fixture
def bak_dir(monkeypatch):
    d = tempfile.mkdtemp(prefix="portguard-bak-")
    monkeypatch.setattr(U, "backup_dir", lambda: d)
    monkeypatch.setattr(maintenance, "backup_dir", lambda: d)
    return d


def _write(path: str, data: bytes) -> None:
    with open(path, "wb") as f:
        f.write(data)


def _read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def _lib(name: str) -> str:
    return config.xdb_path(name)


def _make_backup(directory: str, name: str, stamp: int, content: bytes) -> str:
    """造一份指定时间戳的备份（文件名里的 ts 与 mtime 都按 stamp 写）"""
    path = os.path.join(directory, f"{name}.{stamp}.bak")
    _write(path, content)
    os.utime(path, (stamp, stamp))
    return path


def _backup_files(directory: str, name: str):
    return sorted(
        f for f in os.listdir(directory) if f.startswith(name + ".") and f.endswith(".bak")
    )


# ═══════════════════════════════════════════════════════════
#  backup_now（公开备份入口）
# ═══════════════════════════════════════════════════════════


def test_backup_now_copies_current_lib(isolated_env, bak_dir):
    init_db()
    cfg.warm()
    ok, info = U.backup_now(V4)
    assert ok, info
    assert os.path.isfile(info), f"应返回备份文件路径，实得 {info}"
    assert os.path.basename(info).startswith(V4 + ".")
    assert os.path.basename(info).endswith(".bak")
    assert _read(info) == _read(_lib(V4)), "备份内容必须就是当前库"


def test_backup_now_without_lib_reports_reason(isolated_env, bak_dir, monkeypatch):
    """当前库缺失时要给出原因，界面要原样展示（不能静默失败）"""
    init_db()
    cfg.warm()
    empty = os.path.join(bak_dir, "no-lib-here")
    os.makedirs(empty, exist_ok=True)
    monkeypatch.setattr(U, "xdb_path", lambda name: os.path.join(empty, name))

    ok, info = U.backup_now(V4)
    assert ok is False
    assert "当前没有可备份的库" in info


# ═══════════════════════════════════════════════════════════
#  回滚前必须先备份当前库（回滚不可撤销 = 安全事故）
# ═══════════════════════════════════════════════════════════


def test_restore_backup_saves_current_lib_first(isolated_env, bak_dir):
    """回滚前先备份当前库。

    少了这一步，回滚就是单向操作：回滚到旧库之后，原先那份新库只在磁盘上
    存在过，再也回不去。这条是「回滚不可撤销」这个点的唯一守线。

    不断言 `restore_backup` 的返回值：合成内容热加载多半失败（那正是 err 要
    展示给用户的原因），而「有没有先备份」与热加载成败无关。
    """
    init_db()
    cfg.warm()

    old = _read(_lib(V4))  # 真实库内容，作为「回滚目标」
    bak_old = U._backup(V4)
    assert bak_old and _read(bak_old) == old

    # 把当前库换成另一份内容（模拟一次换库），再回滚
    _write(_lib(V4), old + b"\n# newer\n")
    newer = _read(_lib(V4))
    assert newer != old
    before = set(_backup_files(bak_dir, V4))

    U.restore_backup(V4, bak_old)

    assert _read(_lib(V4)) == old, "当前库必须被恢复成备份的内容"

    added = set(_backup_files(bak_dir, V4)) - before
    assert added, "回滚前必须留一份当前库的备份，否则回滚不可撤销"
    assert any(_read(os.path.join(bak_dir, f)) == newer for f in added), (
        "新增的那份备份必须是回滚前的当前库内容（回滚错了还能再回滚回来）"
    )


def test_restore_backup_without_current_lib_still_restores(isolated_env, bak_dir, monkeypatch):
    """当前库缺失（损坏 / 被误删）时不能「因为没有东西可备份」就拒绝回滚 ——
    这种情况下回滚正是唯一的救援手段，堵死它等于把用户锁在坏库上。
    """
    init_db()
    cfg.warm()
    bak = U._backup(V4)
    assert bak

    empty = os.path.join(bak_dir, "rescued")
    os.makedirs(empty, exist_ok=True)
    monkeypatch.setattr(U, "xdb_path", lambda name: os.path.join(empty, name))

    U.restore_backup(V4, bak)

    assert _read(os.path.join(empty, V4)) == _read(bak), "当前库缺失时必须照样恢复"


def test_restore_backup_reports_hot_reload_failure(isolated_env, bak_dir, monkeypatch):
    """热加载失败时：文件**已经换成备份了**，err 必须把原因带出来。

    这条同时钉住「不能把 err 吞掉」：压成一句「回滚失败」，用户就不知道自己
    现在磁盘上是哪份库、要不要重启。
    """
    init_db()
    cfg.warm()
    bak = U._backup(V4)
    assert bak
    _write(_lib(V4), _read(_lib(V4)) + b"\n# newer\n")
    monkeypatch.setattr(U, "_reload_locator", lambda: (False, "模拟热加载失败"))

    ok, err = U.restore_backup(V4, bak)

    assert ok is False
    assert "模拟热加载失败" in err, f"热加载失败的原因必须原样带出来，实得 {err}"
    assert "热加载失败" in err
    assert _read(_lib(V4)) == _read(bak), "文件已经换成备份了，err 要说清这一点"


def test_restore_backup_missing_file_reports_reason(isolated_env, bak_dir):
    init_db()
    cfg.warm()
    ok, err = U.restore_backup(V4, os.path.join(bak_dir, "nope.1.bak"))
    assert ok is False
    assert "备份文件不存在" in err


# ═══════════════════════════════════════════════════════════
#  同秒内的两次备份不能互相覆盖
# ═══════════════════════════════════════════════════════════


def test_two_backups_in_one_second_do_not_overwrite(isolated_env, bak_dir):
    """换库紧接着回滚（同一秒内）时，第二份备份不能覆盖第一份 ——
    被覆盖的那份可能正是唯一能回滚回去的副本。
    """
    init_db()
    cfg.warm()
    a = U._backup(V4)
    _write(_lib(V4), _read(_lib(V4)) + b"\n# changed\n")
    b = U._backup(V4)

    assert a and b and a != b
    assert os.path.isfile(a) and os.path.isfile(b)
    assert _read(a) != _read(b), "两份备份内容不同，说明没有被互相覆盖"


# ═══════════════════════════════════════════════════════════
#  分组（界面按库分两段列）
# ═══════════════════════════════════════════════════════════


def test_backup_group_parses_library_name():
    assert U.backup_group("ip2region_v4.xdb.1760000000.bak") == "ip2region_v4.xdb"
    assert U.backup_group("ip2region_v6.xdb.1760000000.bak") == "ip2region_v6.xdb"
    # 认不出来的文件名原样返回，不能抛异常（备份目录里可能有别的东西）
    assert U.backup_group("readme") == "readme"


def test_group_backups_splits_by_library(isolated_env, bak_dir):
    init_db()
    cfg.warm()
    _make_backup(bak_dir, V4, 1760000000, b"v4-new")
    _make_backup(bak_dir, V4, 1750000000, b"v4-old")
    _make_backup(bak_dir, V6, 1760000000, b"v6-new")

    groups = U.group_backups()
    assert set(groups) == {V4, V6}, f"必须按库分组，实得 {sorted(groups)}"
    assert [x["file"] for x in groups[V4]] == [f"{V4}.1760000000.bak", f"{V4}.1750000000.bak"]
    assert [x["file"] for x in groups[V6]] == [f"{V6}.1760000000.bak"]


def test_group_backups_orders_by_mtime_not_by_filename(isolated_env, bak_dir):
    """组内新在前，且按 **mtime** 排而不是按文件名排。

    文件名里嵌的是 unix 秒级时间戳，倒序字符串比较只在「位数都一样」时才
    等价于时间倒序；这里特意让两者不一致，退回文件名排序就会红。
    """
    init_db()
    cfg.warm()
    # 文件名看起来更新，实际 mtime 更旧；反之亦然
    _make_backup(bak_dir, V4, 1800000000, b"newer-name")
    os.utime(os.path.join(bak_dir, f"{V4}.1800000000.bak"), (1700000000, 1700000000))
    _make_backup(bak_dir, V4, 1700000100, b"older-name")
    os.utime(os.path.join(bak_dir, f"{V4}.1700000100.bak"), (1800000100, 1800000100))

    files = [x["file"] for x in U.group_backups()[V4]]
    assert files == [f"{V4}.1700000100.bak", f"{V4}.1800000000.bak"], f"必须按 mtime 倒序：{files}"


def test_listed_backups_match_what_cleanup_keeps(isolated_env, bak_dir):
    """界面列的「最新 N 份」必须和 `cleanup_backups` 保留的那 N 份是同一批。

    两边分组 / 排序口径一旦漂移，界面上给用户看的那份备份，可能正是下一轮
    自动清理要删掉的那份 —— 用户点了回滚才发现文件已经没了。
    """
    init_db()
    cfg.warm()
    for i in range(5):
        _make_backup(bak_dir, V4, 1700000000 + i * 3600, b"v4-%d" % i)

    listed = [x["file"] for x in U.group_backups()[V4]]
    assert listed == [f"{V4}.{1700000000 + i * 3600}.bak" for i in (4, 3, 2, 1, 0)]

    maintenance.cleanup_backups(keep=3)
    remaining = set(_backup_files(bak_dir, V4))
    assert remaining == set(listed[:3]), (
        f"清理保留的（{sorted(remaining)}）与界面列出的最新 3 份（{listed[:3]}）不一致"
    )
