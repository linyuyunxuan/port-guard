"""Windows 防火墙安全日志（core/win_fwlog）测试

这是「能看见被 DROP 掉的扫描」的那条通道，解析错了就会漏掉最该抓的记录。
重点覆盖：
· 不同 Windows 版本的 `#Fields:` 头差异（必须按头解析，不能写死列号）
· 末列带空格的进程路径（简单 split() 会把整行切错位）
· 方向判定（SEND 行的 dst-port 是对端端口，拿它比对本机端口属于张冠李戴）
· 增量 tail 的三件麻烦事：半行、滚动、历史跳过
"""

import os

import pytest

from core.win_fwlog import (
    DEFAULT_LOG_PATH,
    FIELDS,
    FwLogEntry,
    FwLogTailer,
    enable_logging,
    filter_inbound,
    is_dropped_logging_enabled,
    logging_enabled,
    parse_line,
    parse_text,
)

HEADER = "#Fields: " + " ".join(FIELDS)

LINE_DROP = (
    "2026-10-16 09:00:01 DROP TCP 113.118.113.77 192.168.1.251 51514 18080 "
    "52 S 0 0 8192 - - - RECEIVE"
)
LINE_ALLOW = (
    "2026-10-16 09:00:03 ALLOW TCP 8.8.4.4 192.168.1.251 51000 18080 0 - 0 0 0 - - - RECEIVE"
)


def _entry(line: str) -> FwLogEntry:
    e = parse_line(line)
    assert e is not None, f"应当解析成功：{line}"
    return e


# --------------------------------------------------------------------------- #
# 解析
# --------------------------------------------------------------------------- #
def test_parse_basic_fields():
    e = _entry(LINE_DROP)
    assert e.action == "DROP"
    assert e.protocol == "TCP"
    assert e.src_ip == "113.118.113.77"
    assert e.dst_ip == "192.168.1.251"
    assert e.src_port == 51514
    assert e.dst_port == 18080
    assert e.size == 52
    assert e.tcpflags == "S"
    assert e.is_drop and e.is_tcp


def test_parse_allows_allow():
    e = _entry(LINE_ALLOW)
    assert e.action == "ALLOW"
    assert not e.is_drop


def test_parse_default_fields_matches_header():
    """内置默认字段顺序必须与微软文档一致，否则在没有 #Fields 头的增量读取下会错位"""
    assert FIELDS[:8] == [
        "date",
        "time",
        "action",
        "protocol",
        "src-ip",
        "dst-ip",
        "src-port",
        "dst-port",
    ]
    assert FIELDS[-1] == "path"


def test_parse_skips_comment_and_blank():
    assert parse_line("#Version: 1.5") is None
    assert parse_line("") is None
    assert parse_line("   ") is None


def test_parse_rejects_short_and_bad_action():
    assert parse_line("2026-10-16 09:00:01 DROP TCP") is None
    bad = LINE_DROP.replace(" DROP ", " HACK ")
    assert parse_line(bad) is None


def test_parse_tolerates_non_numeric_ports():
    line = LINE_DROP.replace(" 51514 18080 ", " - - ")
    e = _entry(line)
    assert e.src_port == 0 and e.dst_port == 0


def test_last_field_absorbs_spaces():
    """path 列保存进程完整路径，里面带空格；绝不能把整行切错位"""
    line = LINE_DROP.replace("- RECEIVE", "- C:\\\\Program Files\\\\My App\\\\svc.exe RECEIVE", 1)
    e = _entry(line)
    assert e.dst_port == 18080
    assert e.src_port == 51514
    assert "Program Files" in e.path


def test_direction_detection():
    assert _entry(LINE_DROP).direction == "RECEIVE"
    send = LINE_DROP.replace("RECEIVE", "SEND")
    assert _entry(send).direction == "SEND"
    dash = LINE_DROP.replace("RECEIVE", "-")
    assert _entry(dash).direction == ""


def test_event_ts_parsed_as_local_time():
    e = _entry(LINE_DROP)
    assert e.event_ts > 0
    import datetime

    dt = datetime.datetime.fromtimestamp(e.event_ts / 1000)
    assert (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second) == (
        2026,
        10,
        16,
        9,
        0,
        1,
    )


def test_event_ts_invalid_returns_zero():
    e = FwLogEntry(date="not-a-date", time="xx")
    assert e.event_ts == 0


def test_parse_text_honours_custom_field_header():
    """老版本 Windows 的列不同：必须按 #Fields 头解析"""
    header = "#Fields: date time action protocol src-ip dst-ip src-port dst-port size info"
    line = "2026-10-16 09:00:01 DROP TCP 1.2.3.4 10.0.0.1 1234 445 52 RECEIVE"
    out = parse_text(f"{header}\n{line}\n")
    assert len(out) == 1
    assert out[0].src_port == 1234
    assert out[0].dst_port == 445
    assert out[0].info == "RECEIVE"


def test_parse_text_carries_header_across_lines():
    body = "\n".join([HEADER, LINE_DROP, "#Software: x", LINE_ALLOW])
    out = parse_text(body)
    assert len(out) == 2
    assert {e.action for e in out} == {"DROP", "ALLOW"}


# --------------------------------------------------------------------------- #
# 入站过滤
# --------------------------------------------------------------------------- #
def test_filter_inbound_keeps_only_watched_ports_from_external():
    entries = parse_text(
        "\n".join(
            [
                HEADER,
                LINE_DROP,  # 18080，外部 → 命中
                LINE_ALLOW,  # 18080，外部 → 命中
                LINE_DROP.replace(" 18080 ", " 3389 "),  # 端口不在列表 → 排除
                LINE_DROP.replace("113.118.113.77", "192.168.1.9"),  # 内网来源 → 排除
            ]
        )
    )
    got = filter_inbound(entries, [18080])
    assert len(got) == 2
    assert all(e.dst_port == 18080 for e in got)


def test_filter_inbound_excludes_send_direction():
    """
    SEND 行的 dst-port 是**对端**端口，拿它比对本机监控端口是张冠李戴。
    同一行改成 RECEIVE 就应当被收下，以此锁定「按方向排除」这一行为。
    """
    send = parse_text("\n".join([HEADER, LINE_DROP.replace("RECEIVE", "SEND")]))
    recv = parse_text("\n".join([HEADER, LINE_DROP]))
    assert filter_inbound(send, [18080]) == []
    assert len(filter_inbound(recv, [18080])) == 1


def test_filter_inbound_empty_ports():
    assert filter_inbound(parse_text("\n".join([HEADER, LINE_DROP])), []) == []


# --------------------------------------------------------------------------- #
# 增量读取
# --------------------------------------------------------------------------- #
def _write(path, text, mode="a"):
    with open(path, mode, encoding="utf-8") as f:
        f.write(text)


def test_tailer_reads_only_new_lines(tmp_path):
    p = str(tmp_path / "pfirewall.log")
    _write(p, HEADER + "\n" + LINE_DROP + "\n", "w")
    t = FwLogTailer(p)
    first = t.read_new()
    assert len(first) == 1
    assert t.read_new() == []  # 没有新增
    _write(p, LINE_ALLOW + "\n")
    second = t.read_new()
    assert len(second) == 1 and second[0].action == "ALLOW"


def test_tailer_holds_partial_line(tmp_path):
    """末尾没写完的半行必须留到下次，不能当成一条残记录"""
    p = str(tmp_path / "pfirewall.log")
    _write(p, HEADER + "\n", "w")
    t = FwLogTailer(p)
    t.read_new()

    half = LINE_DROP[:40]
    _write(p, half)  # 没有换行
    assert t.read_new() == []

    _write(p, LINE_DROP[40:] + "\n")  # 补完
    got = t.read_new()
    assert len(got) == 1
    assert got[0].src_ip == "113.118.113.77"
    assert got[0].dst_port == 18080


def test_tailer_resets_on_truncate(tmp_path):
    """日志滚动 / 被清空后，偏移必须归零，否则会一直读一个不存在的偏移"""
    p = str(tmp_path / "pfirewall.log")
    _write(p, HEADER + "\n" + LINE_DROP + "\n", "w")
    t = FwLogTailer(p)
    assert len(t.read_new()) == 1

    _write(p, HEADER + "\n" + LINE_ALLOW + "\n", "w")  # 覆盖：文件变小
    got = t.read_new()
    assert len(got) == 1
    assert got[0].action == "ALLOW"


def test_tailer_missing_file_is_quiet(tmp_path):
    t = FwLogTailer(str(tmp_path / "nope.log"))
    assert t.read_new() == []
    assert t.exists() is False
    assert t.stats()["exists"] is False


def test_tailer_skip_to_end(tmp_path):
    """启动时必须跳过历史内容，否则一份旧日志会瞬间灌进几万条"新事件" """
    p = str(tmp_path / "pfirewall.log")
    _write(p, HEADER + "\n" + LINE_DROP + "\n" * 5, "w")
    t = FwLogTailer(p)
    skipped = t.skip_to_end()
    assert skipped == os.path.getsize(p)
    assert t.read_new() == []
    _write(p, LINE_ALLOW + "\n")
    got = t.read_new()
    assert len(got) == 1


def test_tailer_set_path_resets_offset(tmp_path):
    p1 = str(tmp_path / "a.log")
    p2 = str(tmp_path / "b.log")
    _write(p1, HEADER + "\n" + LINE_DROP + "\n", "w")
    _write(p2, HEADER + "\n" + LINE_ALLOW + "\n", "w")
    t = FwLogTailer(p1)
    assert len(t.read_new()) == 1
    t.set_path(p2)
    got = t.read_new()
    assert len(got) == 1 and got[0].action == "ALLOW"


def test_logging_enabled_reflects_file(tmp_path):
    p = str(tmp_path / "x.log")
    assert logging_enabled(p) is False
    _write(p, "x", "w")
    assert logging_enabled(p) is True


def test_default_log_path_is_windows_location():
    assert DEFAULT_LOG_PATH.endswith("pfirewall.log")
    assert "LogFiles" in DEFAULT_LOG_PATH
    assert "Firewall" in DEFAULT_LOG_PATH


@pytest.mark.skipif(os.name != "nt", reason="仅 Windows")
def test_logging_state_shape():
    from core.win_fwlog import logging_state

    st = logging_state()
    assert "path" in st and "exists" in st


# --------------------------------------------------------------------------- #
# 丢弃连接日志是否真的在记（P0-2：只开通道但系统层未记 → 扫描漏检）
# --------------------------------------------------------------------------- #
def test_is_dropped_logging_enabled_zh(monkeypatch):
    monkeypatch.setattr(
        "core.win_fwlog.logging_state",
        lambda: {"raw": {"记录被丢弃的连接": "启用", "记录成功的连接": "禁用"}},
    )
    # 强制绕过 30s 缓存，确保重新探测
    monkeypatch.setattr("core.win_fwlog._dropped_state_cache", (0.0, False))
    assert is_dropped_logging_enabled() is True


def test_is_dropped_logging_enabled_en(monkeypatch):
    monkeypatch.setattr(
        "core.win_fwlog.logging_state",
        lambda: {"raw": {"Log dropped packets": "Enable", "Log successful connections": "Disable"}},
    )
    monkeypatch.setattr("core.win_fwlog._dropped_state_cache", (0.0, False))
    assert is_dropped_logging_enabled() is True


def test_is_dropped_logging_enabled_off(monkeypatch):
    monkeypatch.setattr(
        "core.win_fwlog.logging_state",
        lambda: {"raw": {"记录被丢弃的连接": "禁用", "记录成功的连接": "禁用"}},
    )
    monkeypatch.setattr("core.win_fwlog._dropped_state_cache", (0.0, False))
    assert is_dropped_logging_enabled() is False


def test_is_dropped_logging_enabled_unreadable(monkeypatch):
    def _boom():
        raise RuntimeError("netsh 不可用")

    monkeypatch.setattr("core.win_fwlog.logging_state", _boom)
    monkeypatch.setattr("core.win_fwlog._dropped_state_cache", (0.0, False))
    # 读不到状态：宁可报「未启用」让界面提示，也不要谎报安全
    assert is_dropped_logging_enabled() is False


def test_enable_logging_defaults_to_dropped(monkeypatch):
    captured = []

    def fake_run(cmd, *a, **k):
        captured.append(list(cmd))
        return 0, ""

    monkeypatch.setattr("core.win_fwlog._run", fake_run)
    ok, _err = enable_logging()
    assert ok
    joined = " ".join(" ".join(c) for c in captured)
    assert "droppedconnections" in joined and "enable" in joined
