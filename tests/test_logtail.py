"""日志增量跟读（core/logtail）测试

「运行日志」页要**在程序内**显示日志，靠的就是这个 tailer。
重点：半行、滚动、缓冲上限、结构化解析。
"""

import os

from core.logtail import LogLine, LogTailer, parse_line, read_last_lines

LINE_INFO = "2026-10-16 17:08:51 INFO    [MainThread] portguard.core.geo_locator: 定位库加载完成"
LINE_ERR = "2026-10-16 17:08:52 ERROR   [pg-writer] portguard.core.db_writer: 批量写入失败"


def _write(path, text, mode="a"):
    with open(path, mode, encoding="utf-8") as f:
        f.write(text)


# --------------------------------------------------------------------------- #
# 行解析
# --------------------------------------------------------------------------- #
def test_parse_structured_line():
    ln = parse_line(LINE_INFO)
    assert ln.ts == "2026-10-16 17:08:51"
    assert ln.level == "INFO"
    assert ln.thread == "MainThread"
    assert ln.logger == "portguard.core.geo_locator"
    assert ln.msg == "定位库加载完成"
    assert ln.level_rank == 1


def test_parse_error_level_rank():
    assert parse_line(LINE_ERR).level_rank == 3
    assert parse_line(LINE_ERR).level == "ERROR"


def test_parse_unstructured_line_becomes_raw():
    ln = parse_line("这是一行不认识格式的输出")
    assert ln.raw == "这是一行不认识格式的输出"
    assert ln.level == ""
    assert ln.level_rank == 1  # 未知级别按 INFO 处理，不会被 ERROR 过滤器误伤


def test_parse_strips_crlf():
    assert parse_line(LINE_INFO + "\r\n").raw == LINE_INFO


def test_unknown_level_rank_default():
    assert LogLine(level="NOTICE").level_rank == 1


# --------------------------------------------------------------------------- #
# 末尾读取
# --------------------------------------------------------------------------- #
def test_read_last_lines(tmp_path):
    p = str(tmp_path / "a.log")
    _write(p, "".join(f"line {i}\n" for i in range(100)), "w")
    got = read_last_lines(p, 5)
    assert got == [f"line {i}" for i in range(95, 100)]


def test_read_last_lines_missing_file(tmp_path):
    assert read_last_lines(str(tmp_path / "nope.log"), 5) == []
    assert read_last_lines("", 5) == []


# --------------------------------------------------------------------------- #
# Tailer
# --------------------------------------------------------------------------- #
def test_read_new_is_incremental(tmp_path):
    p = str(tmp_path / "a.log")
    _write(p, LINE_INFO + "\n", "w")
    t = LogTailer(p)
    assert len(t.read_new()) == 1
    assert t.read_new() == []
    _write(p, LINE_ERR + "\n")
    got = t.read_new()
    assert len(got) == 1 and got[0].level == "ERROR"
    assert t.read_bytes > 0


def test_partial_line_deferred(tmp_path):
    """日志是边写边刷的，末尾半行很常见，必须留到下次拼完整"""
    p = str(tmp_path / "a.log")
    _write(p, "", "w")
    t = LogTailer(p)
    _write(p, LINE_INFO[:30])
    assert t.read_new() == []
    _write(p, LINE_INFO[30:] + "\n")
    got = t.read_new()
    assert len(got) == 1
    assert got[0].raw == LINE_INFO


def test_rotation_resets_offset(tmp_path):
    """日志滚动（文件被重命名/重建，大小变小）时必须从头读新文件"""
    p = str(tmp_path / "a.log")
    _write(p, "".join(f"old {i}\n" for i in range(50)), "w")
    t = LogTailer(p)
    assert len(t.read_new()) == 50
    _write(p, "new 1\n", "w")  # 覆盖成更短的文件
    got = t.read_new()
    assert [x.raw for x in got] == ["new 1"]
    assert t.rotations == 1


def test_buffer_cap(tmp_path):
    p = str(tmp_path / "a.log")
    _write(p, "", "w")
    t = LogTailer(p, max_lines=100)
    _write(p, "".join(f"l{i}\n" for i in range(500)))
    t.read_new()
    assert len(t.buffer) == 100
    assert t.buffer[-1].raw == "l499"


def test_set_max_lines_shrinks_buffer(tmp_path):
    p = str(tmp_path / "a.log")
    _write(p, "".join(f"l{i}\n" for i in range(300)), "w")
    t = LogTailer(p, max_lines=200)
    t.read_new()
    assert len(t.buffer) == 200
    t.set_max_lines(120)
    assert len(t.buffer) == 120


def test_seed_from_tail_skips_history(tmp_path):
    """首次进页面：先把尾部铺到缓冲，并把偏移推到末尾，避免历史被当成新增"""
    p = str(tmp_path / "a.log")
    _write(p, "".join(f"l{i}\n" for i in range(300)), "w")
    t = LogTailer(p, max_lines=200)
    seeded = t.seed_from_tail()
    assert len(seeded) == 200
    assert seeded[-1].raw == "l299"
    assert t.read_new() == []  # 偏移已在末尾
    _write(p, "brand new\n")
    got = t.read_new()
    assert [x.raw for x in got] == ["brand new"]


def test_seed_from_tail_missing_file(tmp_path):
    t = LogTailer(str(tmp_path / "nope.log"))
    assert t.seed_from_tail() == []
    assert t.exists() is False


def test_set_path_resets(tmp_path):
    p1 = str(tmp_path / "a.log")
    p2 = str(tmp_path / "b.log")
    _write(p1, "one\n", "w")
    _write(p2, "two\n", "w")
    t = LogTailer(p1)
    assert len(t.read_new()) == 1
    t.set_path(p2)
    assert [x.raw for x in t.read_new()] == ["two"]
    t.set_path(p2)  # 同一个路径不应重置
    assert t.read_new() == []


def test_clear_buffer_keeps_offset(tmp_path):
    p = str(tmp_path / "a.log")
    _write(p, "one\ntwo\n", "w")
    t = LogTailer(p)
    t.read_new()
    t.clear_buffer()
    assert t.buffer == []
    _write(p, "three\n")
    assert [x.raw for x in t.read_new()] == ["three"]


def test_stats_shape(tmp_path):
    p = str(tmp_path / "a.log")
    _write(p, "x\n", "w")
    t = LogTailer(p)
    t.read_new()
    st = t.stats()
    assert st["exists"] is True
    assert st["buffered"] == 1
    assert st["read_bytes"] == os.path.getsize(p)


def test_blank_lines_skipped(tmp_path):
    p = str(tmp_path / "a.log")
    _write(p, "a\n\n   \nb\n", "w")
    t = LogTailer(p)
    got = t.read_new()
    assert [x.raw for x in got] == ["a", "b"]
