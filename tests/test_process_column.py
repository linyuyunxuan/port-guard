"""PortGuard — 「进程归属」从采集到表格的一条线（2026-11-04 一等化）

背景：本机采集的两条通道都能回答「哪个本地服务在被访问」——
TCP 连接表按 PID 反查（`win_net.process_name`）、防火墙日志直接给进程路径。
但进程名此前只落在 `tags` 里，界面上看不到（监控页那一列是 1.2.0 之后就恒为
空的「服务器」）。现在它是监控页的一等列，本文件锁住三件事：

1. 两条通道的进程名口径一致（都只留文件名，因为进程列只有 112px）；
2. 表格单元格 / 搜索 / tooltip 都能看到它；
3. 取不到时显示「-」而不是空白（空白会被读成「这一列没数据」）。
"""

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.models import AccessRecord
from core.port_watcher import _proc_from_path


def test_proc_from_path_keeps_only_exe_name():
    """防火墙日志最后一列是完整路径，整条塞进 112px 的列只会被省略成 `C:\\Prog…`"""
    assert _proc_from_path(r"C:\Program Files\nginx\nginx.exe") == "nginx.exe"
    assert _proc_from_path(r'"C:\Windows\System32\svchost.exe"') == "svchost.exe"


def test_proc_from_path_tolerates_empty_values():
    """日志里进程列常见 `-`（系统包 / 无主连接），不能把它当成进程名显示"""
    assert _proc_from_path("") == ""
    assert _proc_from_path("-") == ""
    assert _proc_from_path(None) == ""


def test_access_record_process_property_reads_tags():
    rec = AccessRecord(ip="1.2.3.4", tags={"process": "mysqld.exe"})
    assert rec.process == "mysqld.exe"
    # 没有 tags / tags 里没有 process 时必须是空串，不能返回 "None"
    assert AccessRecord(ip="1.2.3.4").process == ""


def test_monitor_table_shows_process_and_falls_back_to_dash():
    from gui.page_monitor import COL_DISPOSITION, HEADERS, AccessTableModel
    from qtcompat import QApplication

    if not isinstance(QApplication.instance(), QApplication):
        QApplication([])
    model = AccessTableModel(capacity=500)
    proc_col = len(HEADERS) - 1  # 进程列是最后一列（原「服务器」）
    assert HEADERS[proc_col] == "进程"

    with_proc = AccessRecord(ip="1.2.3.4", tags={"process": "nginx.exe"})
    without = AccessRecord(ip="5.6.7.8")
    model.append_many([with_proc, without])

    assert model._cell_text(with_proc, proc_col) == "nginx.exe"
    # 取不到写「-」：留空会被当成「这一列没数据」，写「未知」又是在撒谎
    assert model._cell_text(without, proc_col) == "-"
    assert "进程：nginx.exe" in model._tooltip(with_proc)
    # 处置列不能因为进程列加入而错位
    assert model._cell_text(with_proc, COL_DISPOSITION) == "-"


def test_monitor_search_matches_process_name():
    """「按此进程筛选」的实现就是往搜索框填进程名，所以搜索必须认这一列"""
    from gui.page_monitor import AccessTableModel
    from qtcompat import QApplication

    if not isinstance(QApplication.instance(), QApplication):
        QApplication([])
    model = AccessTableModel(capacity=500)
    model.append_many(
        [
            AccessRecord(ip="1.2.3.4", tags={"process": "mysqld.exe"}),
            AccessRecord(ip="5.6.7.8", tags={"process": "nginx.exe"}),
        ]
    )

    model.set_filters(keyword="mysqld")
    assert model.rowCount() == 1
    assert model.record_at(0).ip == "1.2.3.4"
