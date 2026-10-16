"""
pytest 公共装置

**隔离原则**：测试绝不触碰项目真实的 data/ 目录（那里有用户数据库、
离线库备份、日志）。做法是把 `core.config.project_dir()` 指到临时目录，
于是 user_data_dir() 随之落到 tmp/data，数据库 / 日志 / 清单 / 备份全部隔离；
只有读取内置 xdb 与 rules.json 时才映射回项目真实 data/（只读）。
"""

import os
import shutil
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core import config

_REAL_DATA = os.path.join(ROOT, "data")


@pytest.fixture(scope="session", autouse=True)
def isolated_env():
    mp = pytest.MonkeyPatch()
    root = tempfile.mkdtemp(prefix="portguard-test-")

    def fake_project_dir() -> str:
        return root

    def fake_resource_path(rel: str) -> str:
        rel_n = rel.replace("\\", "/")
        if rel_n.startswith("data/"):
            return os.path.join(_REAL_DATA, *rel_n.split("/")[1:])
        return os.path.join(root, *rel_n.split("/"))

    mp.setattr(config, "project_dir", fake_project_dir)
    mp.setattr(config, "resource_path", fake_resource_path)
    yield root
    mp.undo()
    shutil.rmtree(root, ignore_errors=True)


@pytest.fixture(autouse=True)
def fresh_db(isolated_env):
    """每个用例一套干净数据库，避免相互污染"""
    import time

    from core import database, db_writer, settings

    def _wipe():
        # 先确保没有残留的写入线程占着库文件，否则 Windows 上删不掉，
        # 就会把上一个用例的数据带进下一个（曾导致计数类断言莫名多出数据）
        db_writer.stop_writer(timeout=5)
        db_writer.set_writer(None)
        db = config.db_path()
        for suffix in ("", "-wal", "-shm"):
            for _ in range(10):
                try:
                    os.remove(db + suffix)
                    break
                except FileNotFoundError:
                    break
                except OSError:
                    time.sleep(0.05)
        database._initialized = False
        settings.invalidate()

    _wipe()
    yield
    _wipe()


@pytest.fixture
def no_sleep(monkeypatch):
    """把批量写入器的刷盘间隔压到最小，让测试跑得快"""
    from core import db_writer

    monkeypatch.setattr(db_writer.BatchWriter, "_flush_interval", 0.01)
