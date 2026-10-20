"""本机 TCP 连接表读取（core/win_net）测试

重点覆盖两处最容易写错、又最难在真实环境里察觉的地方：
1. **字节序**：端口与 IPv4 地址在网络字节序里，转换错了会得到
   「端口 20480」这种看着像数据、其实全错的结果
2. **地址过滤**：内网 / 回环 / 未指定地址必须被排除，否则采集噪音会淹掉真信号
"""

import ipaddress
import socket
import struct
import sys

import pytest

from core import win_net
from core.win_net import (
    STATE_ESTABLISHED,
    STATE_LISTEN,
    TcpConn,
    _addr4,
    _addr6,
    _port,
    inbound_connections,
    is_external_ip,
)


# --------------------------------------------------------------------------- #
# 字节序
# --------------------------------------------------------------------------- #
def test_port_byte_order_common_values():
    # 网络字节序里端口 80 = 0x50 0x00，按小端读成 DWORD 就是 0x5000
    assert _port(0x5000) == 80
    # 端口 18080 = 0x46A0 → 内存 0xA0 0x46 → DWORD 0xA046
    assert _port(0xA046) == 18080
    assert _port(0xBB01) == 443
    # 高 16 位是保留位（有时被协议栈写脏），必须被丢掉
    assert _port(0xFFFF5000) == 80


def test_port_roundtrip_for_all_values():
    """对全部 65535 个端口做一次往返，确保转换是双射而不是「碰巧对几个」"""
    for p in range(1, 65536):
        dw = struct.unpack("<I", struct.pack(">H", p) + b"\x00\x00")[0]
        assert _port(dw) == p, f"端口 {p} 转换错误"


def test_addr4_is_network_order():
    # 127.0.0.1 在内存里是 7F 00 00 01，按小端读为 0x0100007F
    assert _addr4(0x0100007F) == "127.0.0.1"
    assert _addr4(0x0101A8C0) == "192.168.1.1"


def test_addr4_roundtrip():
    for text in ("0.0.0.0", "8.8.8.8", "113.118.113.77", "255.255.255.255", "10.0.0.1"):
        packed = ipaddress.IPv4Address(text).packed
        dw = struct.unpack("<I", packed)[0]
        assert _addr4(dw) == text


def test_addr6_basic():
    raw = ipaddress.IPv6Address("2001:db8::1").packed
    assert _addr6(raw) == "2001:db8::1"
    assert _addr6(ipaddress.IPv6Address("::1").packed) == "::1"


def test_addr6_strips_zone_index():
    """
    zone index（%接口号）必须被剥掉。

    Python 3.8 的 `ipaddress` 不支持 scoped 地址（`fe80::1%12` 直接 ValueError），
    而交付栈正是 3.8（Win7 SP1 / Server 2008 R2 上限）。保留 %14 会让链路上的
    IP 解析全部失败，所以这里连「解析得过」一起断言，而不只是比对字符串。
    """
    raw = ipaddress.IPv6Address("fe80::1").packed
    got = _addr6(raw)
    assert got == "fe80::1"
    assert "%" not in got
    ipaddress.ip_address(got)  # 3.8 上也不许抛


def test_addr6_never_emits_zone_index_for_any_address():
    """任意地址都不得带 %：这是一条「交付栈能解析」的硬底线"""
    for text in ("::1", "fe80::1", "2001:db8::1", "::", "ff02::1"):
        got = _addr6(ipaddress.IPv6Address(text).packed)
        assert got == text
        assert "%" not in got
        ipaddress.ip_address(got)


# --------------------------------------------------------------------------- #
# 结构体尺寸（与 winsock2.h 对齐）
# --------------------------------------------------------------------------- #
def test_struct_sizes_match_windows_headers():
    assert win_net._ROW4_SIZE == 24  # MIB_TCPROW_OWNER_PID：6 个 DWORD
    assert win_net._ROW6_SIZE == 56  # MIB_TCP6ROW_OWNER_PID：16+4+4+16+4+4+4+4


# --------------------------------------------------------------------------- #
# 地址判定
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.1.2.3",
        "172.16.5.5",
        "192.168.1.100",
        "169.254.1.1",
        "0.0.0.0",
        "::1",
        "fe80::1",
        "fc00::1",
        "::",
    ],
)
def test_is_external_ip_rejects_local(ip):
    assert not is_external_ip(ip)


@pytest.mark.parametrize("ip", ["8.8.8.8", "113.118.113.77", "45.155.205.233", "2001:4860::1"])
def test_is_external_ip_accepts_public(ip):
    assert is_external_ip(ip)


def test_is_external_ip_handles_scope_and_garbage():
    assert not is_external_ip("fe80::1%12")  # 带 scope 的链路本地地址
    assert not is_external_ip("")
    assert not is_external_ip("not-an-ip")


# --------------------------------------------------------------------------- #
# 过滤逻辑（monkeypatch 掉真实连接表，避免依赖本机网络状态）
# --------------------------------------------------------------------------- #
def _mk(local_port, remote_ip, remote_port, state=STATE_ESTABLISHED, proto="tcp", pid=1):
    return TcpConn(
        proto=proto,
        local_ip="192.168.1.10",
        local_port=local_port,
        remote_ip=remote_ip,
        remote_port=remote_port,
        state=state,
        pid=pid,
    )


def test_inbound_connections_filters(monkeypatch):
    rows = [
        _mk(18080, "113.118.113.77", 51514),  # 命中：外部地址连我们的端口
        _mk(18080, "192.168.1.50", 51515),  # 排除：内网来源
        _mk(18080, "127.0.0.1", 51516),  # 排除：回环
        _mk(3389, "8.8.8.8", 40000),  # 排除：端口不在监控列表
        _mk(18080, "45.1.2.3", 0),  # 排除：对端端口为 0（LISTEN 类行）
        _mk(18080, "1.2.3.4", 5000, state=STATE_LISTEN),  # 排除：非 ESTABLISHED
        _mk(18080, "5.6.7.8", 6000, proto="tcp6"),  # 命中（IPv6）
    ]
    monkeypatch.setattr(win_net, "tcp_table", lambda include_v6=True: list(rows))
    got = inbound_connections([18080, 22], established_only=True, external_only=True)
    assert [c.remote_ip for c in got] == ["113.118.113.77", "5.6.7.8"]


def test_inbound_connections_can_include_non_external(monkeypatch):
    monkeypatch.setattr(
        win_net, "tcp_table", lambda include_v6=True: [_mk(18080, "192.168.1.50", 51515)]
    )
    assert inbound_connections([18080], external_only=False)
    assert not inbound_connections([18080], external_only=True)


def test_inbound_connections_empty_ports(monkeypatch):
    monkeypatch.setattr(win_net, "tcp_table", lambda include_v6=True: [_mk(18080, "8.8.8.8", 1)])
    assert inbound_connections([]) == []


def test_tcp_table_returns_empty_off_windows(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert win_net.tcp_table() == []
    assert win_net.available() is False
    assert "非 Windows" in win_net.unavailable_reason()


@pytest.mark.skipif(sys.platform != "win32", reason="仅 Windows")
def test_tcp_table_reads_real_data():
    """真实读一次连接表：行数 > 0，且端口都在合法范围（可捕捉字节序错误）"""
    rows = win_net.tcp_table()
    assert rows, "Windows 上至少应能读到若干连接"
    for c in rows:
        assert 0 <= c.local_port <= 65535, f"本地端口越界：{c.local_port}（字节序可疑）"
        assert 0 <= c.remote_port <= 65535, f"远端端口越界：{c.remote_port}（字节序可疑）"
        # 地址必须能被解析回合法 IP，否则说明地址字节序处理错了。
        # 交付栈是 py3.8：ipaddress 不认 scoped 地址，所以也顺带守住「不带 %接口号」
        assert "%" not in c.local_ip and "%" not in c.remote_ip
        ipaddress.ip_address(c.local_ip)
        ipaddress.ip_address(c.remote_ip)
    assert any(c.state == STATE_LISTEN for c in rows), "本机应当至少有一个 LISTEN 端口"


def test_state_label():
    assert _mk(80, "1.2.3.4", 5, state=STATE_LISTEN).state_label == "LISTEN"
    assert _mk(80, "1.2.3.4", 5).state_label == "ESTABLISHED"
    assert _mk(80, "1.2.3.4", 5, state=999).state_label == "999"


def test_conn_key_is_channel_agnostic():
    a = _mk(18080, "1.2.3.4", 5555)
    assert a.key == ("tcp", 18080, "1.2.3.4", 5555)
    # 同样的地址/端口，换个地址族，key 仍然区分得开（proto 不同）
    b = _mk(18080, "1.2.3.4", 5555, proto="tcp6")
    assert a.key != b.key


def test_listening_ports_shape():
    ports = win_net.listening_ports()
    assert isinstance(ports, dict)
    for p, rows in ports.items():
        assert 1 <= p <= 65535
        assert rows and all(r.state == STATE_LISTEN for r in rows)


def test_process_name_never_raises():
    """进程名只是锦上添花的展示字段，任何情况都不能抛异常"""
    assert isinstance(win_net.process_name(0), str)
    assert isinstance(win_net.process_name(-1), str)
    assert isinstance(win_net.process_name(999999999), str)


def test_socket_ntohs_matches_our_port_conversion():
    """把实现与标准库对齐，防止有人「优化」成别的写法"""
    for p in (80, 443, 3389, 18080, 65535):
        dw = struct.unpack("<I", struct.pack(">H", p) + b"\x00\x00")[0]
        assert _port(dw) == socket.ntohs(dw & 0xFFFF) == p
