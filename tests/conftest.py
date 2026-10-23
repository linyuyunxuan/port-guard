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
def fresh_db(isolated_env, request):
    """
    每个用例一套干净数据库，避免相互污染。

    收尾带**护栏**：曾经踩过的坑是某个用例起了后台写入线程却没退干净，
    线程握着上一轮库文件的句柄，本夹具删不掉又默默往下走，于是随机出现
    「attempt to write a readonly database」或数据串到别的用例 —— 报出来的
    红和真正的缺陷毫无关系，极难查。现在这类情况会当场炸在**肇事用例**上。
    """
    import time

    from core import database, db_writer, pipeline, settings

    def _wipe():
        db = config.db_path()
        for suffix in ("", "-wal", "-shm"):
            path = db + suffix
            last_err = None
            for _ in range(10):
                try:
                    os.remove(path)
                    last_err = None
                    break
                except FileNotFoundError:
                    last_err = None
                    break
                except OSError as e:
                    last_err = e
                    time.sleep(0.05)
            if last_err is not None:
                raise RuntimeError(
                    f"数据库文件删不掉：{path}（{last_err}）。"
                    "十有八九还有后台写入线程握着它的句柄 —— 见护栏报错。"
                )
        database._initialized = False
        # 「拦截次数」是**进程内**计数，key 是封禁记录 id；库一删，id 会从 1
        # 重新开始，不清就会把上一个用例的次数算到下一个用例的同 id 记录上
        # （表现为「刚封的 IP 一命中就直接升黑名单」这种莫名其妙的红）。
        pipeline.reset_block_hits()
        settings.invalidate()

    def _stop_writers(writers):
        """
        停掉写入器，并断言这些线程**真的退出了**。

        `stop_writer()` 会把单例置 None，所以必须在停之前先把引用记下来，
        否则泄漏出去的线程再也查不到是谁起的。
        """
        db_writer.stop_writer(timeout=5)
        leaked = [w for w in writers if w is not None and w.running]
        if leaked:
            raise RuntimeError(
                f"写入线程在 5 秒内没有退出（用例：{request.node.nodeid}）。\n"
                "\n"
                "后果：线程握着即将被删掉的库文件句柄继续写，后续用例会随机报\n"
                "「attempt to write a readonly database」，或者上一个用例的数据\n"
                "串到下一个用例里 —— 报出来的红跟真正的问题毫无关系，极难查。\n"
                "\n"
                "怎么改（三选一）：\n"
                "  1. 测试里不要 start_writer()；确实需要落库就用 set_writer(...)\n"
                "     注入同步写入器（参考 tests/test_report_trust.py 里的\n"
                "     _InlineWriter），线程和长连接都不存在；\n"
                "  2. 确实要测后台线程，就在用例自己的 teardown 里 stop_writer()\n"
                "     并确认 writer.running 已经是 False；\n"
                "  3. 线程卡在建连重试上 —— 修根因，别在这里加大 timeout。\n"
            )

    # teardown 报错后 pytest 仍会继续跑下一个用例，所以 setup 也要查一次，
    # 免得上一个用例泄漏的线程把锅甩给下一个。
    _stop_writers([db_writer.peek_writer()])
    _wipe()
    yield
    _stop_writers([db_writer.peek_writer()])
    _wipe()


@pytest.fixture
def no_sleep(monkeypatch):
    """把批量写入器的刷盘间隔压到最小，让测试跑得快"""
    from core import db_writer

    monkeypatch.setattr(db_writer.BatchWriter, "_flush_interval", 0.01)


@pytest.fixture(autouse=True)
def stub_firewall_enabled(monkeypatch):
    """
    `firewall.block_ip` 现在会检查「Windows 防火墙是否真的开着」。

    这是**真实系统状态**，而本机（开发机 / CI）防火墙经常是关的 —— 不隔离的话，
    同一份用例在不同机器上一会儿绿一会儿红。这里统一打桩成「开着」，
    让单测只验证封禁逻辑本身。

    要测「防火墙关着时封禁必须失败」的用例，自己再 monkeypatch 成 False 即可
    （后打的桩覆盖这里）。
    """
    from core import firewall

    monkeypatch.setattr(firewall, "firewall_enabled", lambda force=False: True)
