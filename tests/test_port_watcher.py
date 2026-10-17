"""本机多端口访问观察器（core/port_watcher）测试

这是把两条采集通道合成一条事件流的地方，最要紧的两件事：
1. **跨通道去重**：同一次访问可能既在 TCP 表里 ESTABLISHED、又在防火墙日志里 ALLOW；
   去重键如果把通道名也算进去，一次访问就会变成两条记录、告警翻倍、风险分重复累积
2. **产出的记录与业务系统上报同构**：必须真的走进 core.pipeline，
   否则「本机看到的」和「上报看到的」结论会不一致
"""

import os

import pytest

from core import port_watcher as PW
from core import win_fwlog, win_net
from core.config import LEVEL_NORMAL
from core.event_bus import bus
from core.models import AccessRecord, GeoInfo
from core.port_watcher import PortWatcher, WatchConfig, parse_methods, parse_ports, ports_to_text

HEADER = "#Fields: " + " ".join(win_fwlog.FIELDS)


# --------------------------------------------------------------------------- #
# 配置解析
# --------------------------------------------------------------------------- #
def test_parse_ports_variants():
    assert parse_ports("18080,3389") == [18080, 3389]
    assert parse_ports("18080，3389") == [18080, 3389]
    assert parse_ports("18080 3389") == [18080, 3389]
    assert parse_ports([18080, 3389]) == [18080, 3389]
    assert parse_ports(" 18080 , 3389 ") == [18080, 3389]


def test_parse_ports_drops_invalid_and_dedupes():
    assert parse_ports("18080,abc,99999,0,-1,18080") == [18080]
    assert parse_ports("") == []
    assert parse_ports(None) == []


def test_ports_to_text_roundtrip():
    assert parse_ports(ports_to_text([1, 2, 3])) == [1, 2, 3]


def test_parse_methods_variants():
    assert parse_methods("table") == ["table"]
    assert parse_methods("fwlog,table") == ["fwlog", "table"]
    assert parse_methods("table，fwlog") == ["table", "fwlog"]
    # 非法值一律丢弃；全非法时退回 table（至少保证有一个可用通道）
    assert parse_methods("bogus") == ["table"]
    assert parse_methods("") == ["table"]
    assert parse_methods(None) == ["table"]
    assert parse_methods("fwlog,bogus") == ["fwlog"]


def test_watch_config_from_settings_defaults():
    c = WatchConfig.from_settings()
    assert isinstance(c.ports, list)
    assert c.methods
    assert c.interval_sec >= 1.0
    assert c.dedupe_sec >= 0
    assert c.enabled in (True, False)


# --------------------------------------------------------------------------- #
# 采集：TCP 连接表通道
# --------------------------------------------------------------------------- #
class _FakeConn:
    def __init__(self, local_port=18080, remote_ip="113.118.113.77", remote_port=51514, pid=0):
        self.proto = "tcp"
        self.local_ip = "192.168.1.251"
        self.local_port = local_port
        self.remote_ip = remote_ip
        self.remote_port = remote_port
        self.state = win_net.STATE_ESTABLISHED
        self.pid = pid


def _watcher(tmp_path, ports=(18080,), **kw):
    cfg = WatchConfig(
        enabled=True,
        ports=list(ports),
        methods=list(kw.pop("methods", ["table"])),
        fwlog_path=str(tmp_path / "pfirewall.log"),
        **kw,
    )
    return PortWatcher(cfg)


@pytest.fixture(autouse=True)
def _clean_bus():
    """每个用例前后清空事件总线，避免相互串味"""
    for drain in (bus.drain_access, bus.drain_risk, bus.drain_alert, bus.drain_ban):
        drain(10000)
    yield
    for drain in (bus.drain_access, bus.drain_risk, bus.drain_alert, bus.drain_ban):
        drain(10000)


def test_poll_table_emits_and_dedupes(tmp_path, monkeypatch):
    monkeypatch.setattr(win_net, "inbound_connections", lambda *a, **k: [_FakeConn()])
    w = _watcher(tmp_path)
    assert w._poll_table(w.config) == 1
    st = w.stats()
    assert st["table_hits"] == 1 and st["emitted"] == 1

    # 同一连接再次轮询：必须被去重（否则一次长连接会无限刷记录）
    assert w._poll_table(w.config) == 0
    assert w.stats()["deduped"] == 1
    assert w.stats()["emitted"] == 1


def test_poll_table_emitted_record_is_pipeline_output(tmp_path, monkeypatch):
    """采到的记录必须走完 pipeline：有归属地、有风险级别、进过事件总线"""
    monkeypatch.setattr(win_net, "inbound_connections", lambda *a, **k: [_FakeConn()])
    w = _watcher(tmp_path)
    w._poll_table(w.config)
    recs = bus.drain_access()
    assert len(recs) == 1
    rec = recs[0]
    assert rec.ip == "113.118.113.77"
    assert rec.local_port == 18080
    assert rec.remote_port == 51514
    assert rec.protocol == "tcp"
    assert rec.risk_level == LEVEL_NORMAL
    assert rec.matched_rules == []  # 自采的 TCP 记录不该被「空 UA」规则误判
    assert rec.tags["source"] == "local-watch"
    assert rec.tags["channel"] == "table"
    assert rec.tags["action"] == "ESTABLISHED"


def test_poll_table_resolves_process_name(tmp_path, monkeypatch):
    monkeypatch.setattr(win_net, "inbound_connections", lambda *a, **k: [_FakeConn(pid=4242)])
    monkeypatch.setattr(win_net, "process_name", lambda pid: "nginx.exe")
    w = _watcher(tmp_path, resolve_pid=True)
    w._poll_table(w.config)
    rec = bus.drain_access()[0]
    assert rec.tags["pid"] == 4242
    assert rec.tags["process"] == "nginx.exe"


def test_poll_table_skips_pid_lookup_when_disabled(tmp_path, monkeypatch):
    monkeypatch.setattr(win_net, "inbound_connections", lambda *a, **k: [_FakeConn(pid=4242)])
    monkeypatch.setattr(win_net, "process_name", lambda pid: "should-not-be-called")
    w = _watcher(tmp_path, resolve_pid=False)
    w._poll_table(w.config)
    rec = bus.drain_access()[0]
    assert "process" not in rec.tags


def test_poll_table_noop_when_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(win_net, "available", lambda: False)
    w = _watcher(tmp_path)
    assert w._poll_table(w.config) == 0


# --------------------------------------------------------------------------- #
# 采集：防火墙日志通道
# --------------------------------------------------------------------------- #
def _fwlog(tmp_path, lines):
    p = tmp_path / "pfirewall.log"
    with open(p, "w", encoding="utf-8") as f:
        f.write(HEADER + "\n")
        for ln in lines:
            f.write(ln + "\n")
    return str(p)


DROP_18080 = (
    "2026-10-16 09:00:01 DROP TCP 113.118.113.77 192.168.1.251 51514 18080 "
    "52 S 0 0 8192 - - - RECEIVE"
)
ALLOW_18080 = (
    "2026-10-16 09:00:03 ALLOW TCP 8.8.4.4 192.168.1.251 51000 18080 0 - 0 0 0 - - - RECEIVE"
)
DROP_3389 = (
    "2026-10-16 09:00:05 DROP TCP 45.155.205.233 192.168.1.251 40000 3389 "
    "40 S 0 0 8192 - - - RECEIVE"
)


def test_poll_fwlog_emits_only_watched_ports(tmp_path):
    _fwlog(tmp_path, [DROP_18080, DROP_3389])
    w = _watcher(tmp_path, methods=["fwlog"])
    assert w._poll_fwlog(w.config) == 1
    rec = bus.drain_access()[0]
    assert rec.ip == "113.118.113.77"
    assert rec.local_port == 18080
    assert rec.remote_port == 51514
    assert rec.tags["channel"] == "fwlog"
    assert rec.tags["action"] == "DROP"
    assert rec.tags["tcpflags"] == "S"


def test_poll_fwlog_dedupes_repeated_drops(tmp_path):
    """同一来源反复重试扫描时只报一条，否则日志会被同一次扫描刷爆"""
    _fwlog(tmp_path, [DROP_18080, DROP_18080, DROP_18080])
    w = _watcher(tmp_path, methods=["fwlog"])
    assert w._poll_fwlog(w.config) == 1
    assert w._poll_fwlog(w.config) == 0
    assert w.stats()["deduped"] == 2


def test_poll_fwlog_no_data(tmp_path):
    _fwlog(tmp_path, [])
    w = _watcher(tmp_path, methods=["fwlog"])
    assert w._poll_fwlog(w.config) == 0


# --------------------------------------------------------------------------- #
# 跨通道去重（最容易写错的地方）
# --------------------------------------------------------------------------- #
def test_same_connection_seen_by_both_channels_reported_once(tmp_path, monkeypatch):
    """
    连接表说 ESTABLISHED、防火墙日志说 ALLOW —— 这是**同一次访问**。
    两条通道报出来必须只有一条记录，否则告警翻倍、风险分被重复累积。
    """
    monkeypatch.setattr(
        win_net,
        "inbound_connections",
        lambda *a, **k: [_FakeConn(local_port=18080, remote_ip="8.8.4.4", remote_port=51000)],
    )
    _fwlog(tmp_path, [ALLOW_18080])
    w = _watcher(tmp_path, methods=["table", "fwlog"])

    assert w._poll_table(w.config) == 1
    assert w._poll_fwlog(w.config) == 0, "同一次连接不应被第二条通道重复上报"

    recs = bus.drain_access()
    assert len(recs) == 1
    # 先到的是连接表通道，标签就应当是它
    assert recs[0].tags["channel"] == "table"
    assert w.stats()["deduped"] == 1


def test_different_connections_not_deduped(tmp_path, monkeypatch):
    monkeypatch.setattr(
        win_net,
        "inbound_connections",
        lambda *a, **k: [_FakeConn(remote_ip="1.1.1.1", remote_port=1000)],
    )
    _fwlog(tmp_path, [DROP_18080])  # 另一个来源 113.118.113.77:51514
    w = _watcher(tmp_path, methods=["table", "fwlog"])
    w._poll_table(w.config)
    w._poll_fwlog(w.config)
    assert len(bus.drain_access()) == 2


def test_dedupe_key_is_channel_agnostic():
    k = PW._conn_key(18080, "8.8.4.4", 51000)
    assert k == (18080, "8.8.4.4", 51000)
    assert PW._conn_key(18080, "8.8.4.4", 51000) == k


def test_dedupe_window_expiry(tmp_path, monkeypatch):
    """去重窗口过后，同一来源的新一轮访问应当再次上报"""
    monkeypatch.setattr(win_net, "inbound_connections", lambda *a, **k: [_FakeConn()])
    w = _watcher(tmp_path, dedupe_sec=0)  # 窗口 0 = 永不去重
    assert w._poll_table(w.config) == 1
    assert w._poll_table(w.config) == 1
    assert w.stats()["deduped"] == 0


def test_seen_map_is_pruned_when_huge(tmp_path):
    w = _watcher(tmp_path)
    with w._lock:
        for i in range(50001):
            w._seen[(18080, f"10.0.0.{i % 250}", i + 1)] = -1e9  # 早已过期
    assert w._dedupe((18080, "1.2.3.4", 9), w.config) is True
    with w._lock:
        assert len(w._seen) < 50001


# --------------------------------------------------------------------------- #
# 产出记录结构
# --------------------------------------------------------------------------- #
def test_emit_builds_expected_record(tmp_path):
    w = _watcher(tmp_path)
    w._emit(
        ip="113.118.113.77",
        local_port=18080,
        remote_port=51514,
        protocol="tcp",
        size=0,
        channel=PW.METHOD_TABLE,
        action="ESTABLISHED",
        pid=99,
        process="svc.exe",
        extra={"tcpflags": "S"},
        ts=0,
    )
    rec = bus.drain_access()[0]
    assert isinstance(rec, AccessRecord)
    assert rec.event_ts > 0  # ts=0 时补当前时间
    assert rec.tags["pid"] == 99
    assert rec.tags["process"] == "svc.exe"
    assert rec.tags["tcpflags"] == "S"
    assert rec.geo is not None and isinstance(rec.geo, GeoInfo)


def test_emit_no_remote_port(tmp_path):
    w = _watcher(tmp_path)
    w._emit(ip="1.2.3.4", local_port=18080, remote_port=0, protocol="tcp", channel="table")
    assert bus.drain_access()[0].remote_port is None


# --------------------------------------------------------------------------- #
# 生命周期与统计
# --------------------------------------------------------------------------- #
def test_start_stop_lifecycle(tmp_path):
    w = _watcher(tmp_path, ports=[])
    assert w.running is False
    w.start()
    try:
        assert w.running is True
        assert w.stats()["running"] is True
    finally:
        w.stop()
    assert w.running is False
    assert w.stats()["running"] is False


def test_stats_shape(tmp_path):
    w = _watcher(tmp_path)
    st = w.stats()
    for key in (
        "running",
        "polls",
        "table_hits",
        "fwlog_hits",
        "emitted",
        "deduped",
        "errors",
        "ports",
        "methods",
        "interval_sec",
        "dedupe_sec",
        "log_offset",
        "log_exists",
    ):
        assert key in st, f"stats 缺少 {key}"


def test_update_config_repoints_tailer(tmp_path):
    w = _watcher(tmp_path)
    new_path = str(tmp_path / "other.log")
    c = WatchConfig(fwlog_path=new_path, methods=["fwlog"], ports=[18080])
    w.update_config(c, restart=False)
    assert w.config.fwlog_path == new_path
    assert w._tailer.path == new_path


def test_reload_from_settings_returns_config():
    c = PW.reload_from_settings(restart=False)
    assert isinstance(c, WatchConfig)
    PW.set_watcher(None)


def test_get_watcher_is_singleton():
    PW.set_watcher(None)
    a = PW.get_watcher()
    b = PW.get_watcher()
    assert a is b
    PW.set_watcher(None)


def test_method_labels_cover_all():
    for m in PW.ALL_METHODS:
        assert m in PW.METHOD_LABEL


@pytest.mark.skipif(os.name != "nt", reason="仅 Windows")
def test_real_table_poll_does_not_crash(tmp_path, monkeypatch):
    """真实读一次连接表并跑完整条链路，确认不会因真实数据形状而炸"""
    w = _watcher(tmp_path, ports=list(range(1, 65536)))
    n = w._poll_table(w.config)
    assert n >= 0
