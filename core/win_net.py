"""
PortGuard — 本机 TCP 连接表读取（ctypes 直调 iphlpapi，零第三方依赖、零系统改动）

作用：不依赖任何业务系统上报，直接从内核拿到「此刻谁连着本机哪些端口」。
这是双通道采集里的**被动轮询通道**：

  优点：零系统改动、**不需要管理员权限**、不依赖任何外部组件，
        在 Windows 7 SP1 / Server 2008 R2 上开箱可用（本工具的系统下限）。
  短板：只能看见**仍然存活**的连接（ESTABLISHED）。
        被防火墙 DROP 掉的扫描、已经挥手关闭的连接都看不到 ——
        这部分由 core/win_fwlog.py 的防火墙日志通道补齐。

实现：GetExtendedTcpTable（iphlpapi.dll）
  · AF_INET  + TCP_TABLE_OWNER_PID_ALL(5) → MIB_TCPTABLE_OWNER_PID
  · AF_INET6 + TCP_TABLE_OWNER_PID_ALL(5) → MIB_TCP6TABLE_OWNER_PID
两种表都带 owning PID，所以还能回答「是本机哪个进程占着这个端口」。

字节序（踩坑点，两条都必须对，否则端口会显示成 20480 这种鬼数字）：
  · 端口字段是 DWORD，但端口号以**网络字节序**存放在其低 16 位里
    → port = socket.ntohs(dwPort & 0xFFFF)
  · IPv4 地址字段是 DWORD，内存里就是 4 个地址字节
    → 用 struct.pack("<I", dwAddr) 取回字节再交给 IPv4Address

非 Windows 平台不导入本模块的重量级部分，`available()` 返回 False，
便于在 CI / 开发机上跑测试。
"""

import contextlib
import ctypes
import ipaddress
import socket
import struct
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional

from core.logger import get_logger

log = get_logger(__name__)

AF_INET = 2
AF_INET6 = 23
TCP_TABLE_OWNER_PID_ALL = 5
_ERROR_INSUFFICIENT_BUFFER = 122

# MIB_TCP_STATE
STATE_CLOSED = 1
STATE_LISTEN = 2
STATE_SYN_SENT = 3
STATE_SYN_RCVD = 4
STATE_ESTABLISHED = 5
STATE_FIN_WAIT1 = 6
STATE_FIN_WAIT2 = 7
STATE_CLOSE_WAIT = 8
STATE_CLOSING = 9
STATE_LAST_ACK = 10
STATE_TIME_WAIT = 11
STATE_DELETE_TCB = 12

STATE_LABEL = {
    STATE_CLOSED: "CLOSED",
    STATE_LISTEN: "LISTEN",
    STATE_SYN_SENT: "SYN_SENT",
    STATE_SYN_RCVD: "SYN_RCVD",
    STATE_ESTABLISHED: "ESTABLISHED",
    STATE_FIN_WAIT1: "FIN_WAIT1",
    STATE_FIN_WAIT2: "FIN_WAIT2",
    STATE_CLOSE_WAIT: "CLOSE_WAIT",
    STATE_CLOSING: "CLOSING",
    STATE_LAST_ACK: "LAST_ACK",
    STATE_TIME_WAIT: "TIME_WAIT",
    STATE_DELETE_TCB: "DELETE_TCB",
}

# 进程名查询用的常量
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_MAX_PATH = 1024


@dataclass
class TcpConn:
    """一条 TCP 连接（合并 IPv4 / IPv6 两种表）"""

    proto: str  # "tcp" 或 "tcp6"
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: int
    pid: int = 0

    @property
    def state_label(self) -> str:
        return STATE_LABEL.get(self.state, str(self.state))

    @property
    def key(self) -> tuple:
        """去重 / 比对用的稳定标识"""
        return (self.proto, self.local_port, self.remote_ip, self.remote_port)

    def __str__(self) -> str:
        return (
            f"{self.proto} {self.local_ip}:{self.local_port}"
            f" <- {self.remote_ip}:{self.remote_port} {self.state_label}"
        )


# ═══════════════════════════════════════════════════════════
#  结构体（与 winsock2.h 逐字段对齐）
# ═══════════════════════════════════════════════════════════


class _MIB_TCPROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("dwState", ctypes.c_uint32),
        ("dwLocalAddr", ctypes.c_uint32),
        ("dwLocalPort", ctypes.c_uint32),
        ("dwRemoteAddr", ctypes.c_uint32),
        ("dwRemotePort", ctypes.c_uint32),
        ("dwOwningPid", ctypes.c_uint32),
    ]


class _MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    _fields_ = [
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", ctypes.c_uint32),
        ("dwLocalPort", ctypes.c_uint32),
        ("ucRemoteAddr", ctypes.c_ubyte * 16),
        ("dwRemoteScopeId", ctypes.c_uint32),
        ("dwRemotePort", ctypes.c_uint32),
        ("dwState", ctypes.c_uint32),
        ("dwOwningPid", ctypes.c_uint32),
    ]


_ROW4_SIZE = ctypes.sizeof(_MIB_TCPROW_OWNER_PID)  # 24
_ROW6_SIZE = ctypes.sizeof(_MIB_TCP6ROW_OWNER_PID)  # 56

_iphlpapi = None
_kernel32 = None
_load_error = ""

# 「非 Windows」这条原因要能被 available() / unavailable_reason() 一致地引用。
# 不能只靠 _libs() 里的赋值：一旦本机成功加载过一次 DLL，_libs() 会在开头
# 直接返回缓存句柄，不再经过平台判断，于是出现「available() 说不可用、
# unavailable_reason() 却给不出原因」的矛盾结果。
_REASON_NOT_WINDOWS = "非 Windows 平台，不支持读取本机 TCP 连接表"


def _libs():
    """惰性加载 DLL（非 Windows 平台保持 None，模块仍可导入）"""
    global _iphlpapi, _kernel32, _load_error
    if _iphlpapi is not None:
        return _iphlpapi, _kernel32
    if sys.platform != "win32":
        _load_error = _REASON_NOT_WINDOWS
        return None, None
    try:
        _iphlpapi = ctypes.WinDLL("iphlpapi.dll")
        _iphlpapi.GetExtendedTcpTable.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_int,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_uint32,
        ]
        _iphlpapi.GetExtendedTcpTable.restype = ctypes.c_uint32
        _kernel32 = ctypes.WinDLL("kernel32.dll")
    except Exception as e:  # pragma: no cover —— 仅异常环境
        _load_error = f"加载 iphlpapi.dll 失败: {e}"
        log.exception("加载 iphlpapi.dll 失败")
        return None, None
    return _iphlpapi, _kernel32


def available() -> bool:
    """本模块在当前机器上是否可用"""
    if sys.platform != "win32":
        return False
    iphlpapi, _ = _libs()
    return iphlpapi is not None


def unavailable_reason() -> str:
    """不可用的原因；可用时返回空串。

    平台判断放在最前面，保证与 ``available()`` 的口径一致 ——
    否则调用方「先问能不能用、再问为什么不能用」时会拿到空原因。
    """
    if sys.platform != "win32":
        return _REASON_NOT_WINDOWS
    _libs()
    return _load_error


# ═══════════════════════════════════════════════════════════
#  字节序转换
# ═══════════════════════════════════════════════════════════


def _port(dw: int) -> int:
    """DWORD 里的网络字节序端口 → 主机序整数"""
    return socket.ntohs(dw & 0xFFFF)


def _addr4(dw: int) -> str:
    return str(ipaddress.IPv4Address(struct.pack("<I", dw & 0xFFFFFFFF)))


def _addr6(raw) -> str:
    """
    16 字节地址 → IPv6 文本。**不带 zone index（%接口号）**。

    MIB_TCP6ROW 里除了地址还有 dwScopeId，过去会拼成 `fe80::1%14`（RFC 4007 的
    scoped 地址写法）。这个写法在交付栈上会直接炸：Python 3.8 的 `ipaddress`
    不支持 scoped 地址（3.9 才支持），`ipaddress.ip_address("fe80::1%14")` 抛
    ValueError —— 而 Windows 7 SP1 / Server 2008 R2 只能跑 3.8，正好是我们要
    覆盖的下限系统。链路上凡是解析 IP 的地方（`core.validators.normalize_ip`、
    `core.geo_locator.lookup`）都会因此失败。

    剥掉它不损失可用信息：只有链路本地地址（fe80::/10）才带 scope_id，而它
    本来就被 `is_external_ip` 判为「非外部地址」过滤掉了；数据模型里也没有
    字段能承载「哪个网卡」，留着只会让下游解析失败。
    """
    return str(ipaddress.IPv6Address(bytes(raw)))


def _state_name(v: int) -> str:
    return STATE_LABEL.get(v, str(v))


# ═══════════════════════════════════════════════════════════
#  连接表读取
# ═══════════════════════════════════════════════════════════


def _query_raw(af: int) -> Optional[bytes]:
    """取一张原始表缓冲区，失败返回 None"""
    iphlpapi, _ = _libs()
    if iphlpapi is None:
        raise OSError(_load_error or "iphlpapi 不可用")

    size = ctypes.c_uint32(0)
    # 第一次调用只为拿所需缓冲区大小，必然返回 ERROR_INSUFFICIENT_BUFFER
    ret = iphlpapi.GetExtendedTcpTable(
        None, ctypes.byref(size), False, af, TCP_TABLE_OWNER_PID_ALL, 0
    )
    if ret not in (0, _ERROR_INSUFFICIENT_BUFFER):
        raise OSError(f"GetExtendedTcpTable 查询大小失败，错误码 {ret}")
    if size.value == 0:
        return None
    buf = ctypes.create_string_buffer(size.value)
    ret = iphlpapi.GetExtendedTcpTable(
        buf, ctypes.byref(size), False, af, TCP_TABLE_OWNER_PID_ALL, 0
    )
    if ret != 0:
        raise OSError(f"GetExtendedTcpTable 读取失败，错误码 {ret}")
    return buf.raw[: size.value]


def _rows_v4() -> List[TcpConn]:
    raw = _query_raw(AF_INET)
    if not raw:
        return []
    # MIB_TCPTABLE_OWNER_PID { DWORD dwNumEntries; MIB_TCPROW_OWNER_PID table[]; }
    n = ctypes.c_uint32.from_buffer_copy(raw, 0).value
    out: List[TcpConn] = []
    off = 4
    for _ in range(n):
        if off + _ROW4_SIZE > len(raw):
            break
        row = _MIB_TCPROW_OWNER_PID.from_buffer_copy(raw, off)
        off += _ROW4_SIZE
        out.append(
            TcpConn(
                proto="tcp",
                local_ip=_addr4(row.dwLocalAddr),
                local_port=_port(row.dwLocalPort),
                remote_ip=_addr4(row.dwRemoteAddr),
                remote_port=_port(row.dwRemotePort),
                state=row.dwState,
                pid=row.dwOwningPid,
            )
        )
    return out


def _rows_v6() -> List[TcpConn]:
    raw = _query_raw(AF_INET6)
    if not raw:
        return []
    n = ctypes.c_uint32.from_buffer_copy(raw, 0).value
    out: List[TcpConn] = []
    off = 4
    for _ in range(n):
        if off + _ROW6_SIZE > len(raw):
            break
        row = _MIB_TCP6ROW_OWNER_PID.from_buffer_copy(raw, off)
        off += _ROW6_SIZE
        out.append(
            TcpConn(
                proto="tcp6",
                local_ip=_addr6(row.ucLocalAddr),
                local_port=_port(row.dwLocalPort),
                remote_ip=_addr6(row.ucRemoteAddr),
                remote_port=_port(row.dwRemotePort),
                state=row.dwState,
                pid=row.dwOwningPid,
            )
        )
    return out


def tcp_table(include_v6: bool = True) -> List[TcpConn]:
    """
    读回本机完整 TCP 连接表（含 LISTEN）。

    任一地址族读取失败不影响另一族：把异常吞掉并记日志，
    因为真实环境里 v6 表偶尔会因协议栈未启用而返回错误码，
    不应该连累 v4 的结果。非 Windows 平台返回空列表。
    """
    if sys.platform != "win32":
        return []
    out: List[TcpConn] = []
    try:
        out.extend(_rows_v4())
    except Exception as e:
        log.warning("读取 IPv4 TCP 连接表失败：%s", e)
    if include_v6:
        try:
            out.extend(_rows_v6())
        except Exception as e:
            log.debug("读取 IPv6 TCP 连接表失败（忽略）：%s", e)
    return out


def listening_ports() -> Dict[int, List[TcpConn]]:
    """当前处于 LISTEN 的端口 → 监听它的连接行（可能多个，v4/v6 各一）"""
    out: Dict[int, List[TcpConn]] = {}
    for c in tcp_table():
        if c.state == STATE_LISTEN and c.local_port:
            out.setdefault(c.local_port, []).append(c)
    return out


# ═══════════════════════════════════════════════════════════
#  地址判定
# ═══════════════════════════════════════════════════════════


def is_external_ip(ip: str) -> bool:
    """
    是否属于「外部地址」：既不是内网/回环/保留地址，也不是未指定地址。

    注意与 core.rule_engine.is_never_ban 的区别：那个是「永不许封禁」的
    安全底线（含 0.0.0.0/8、224.0.0.0/4 等），语义更宽；这里只关心
    「这条连接是不是来自本机之外」，用于过滤采集噪音。
    """
    if not ip:
        return False
    # 剥掉 zone index（%接口号）：连接表侧已在 _addr6 剥过，这里是为防火墙日志等
    # 其它来源兜底 —— 它们也可能给出 scoped 的链路本地地址
    bare = ip.split("%", 1)[0]
    try:
        addr = ipaddress.ip_address(bare)
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_private or addr.is_link_local or addr.is_unspecified)


def inbound_connections(
    ports: List[int],
    established_only: bool = True,
    external_only: bool = True,
) -> List[TcpConn]:
    """
    挑出「外部地址正连着本机这些端口」的连接。

    判定：local_port ∈ ports 且 remote 是外部地址（默认）。
    只看 ESTABLISHED 是因为 SYN_RCVD 等半开状态在轮询间隔内极易重复出现，
    会把同一来源刷成很多条。
    """
    wanted = {int(p) for p in ports if str(p).isdigit()}
    if not wanted:
        return []
    out: List[TcpConn] = []
    for c in tcp_table():
        if c.local_port not in wanted:
            continue
        if established_only and c.state != STATE_ESTABLISHED:
            continue
        if c.remote_port == 0:
            continue
        if external_only and not is_external_ip(c.remote_ip):
            continue
        out.append(c)
    return out


# ═══════════════════════════════════════════════════════════
#  PID → 进程名（best-effort，失败退回空串）
# ═══════════════════════════════════════════════════════════

_pid_name_cache: Dict[int, str] = {}


def process_name(pid: int) -> str:
    """
    由 PID 取进程可执行文件名。取不到就返回空串 —— 这只是个锦上添花的
    展示字段，任何失败都不该影响采集主流程。
    """
    if not pid:
        return ""
    cached = _pid_name_cache.get(pid)
    if cached is not None:
        return cached
    if sys.platform != "win32":
        return ""
    _, kernel32 = _libs()
    if kernel32 is None:
        return ""
    name = ""
    handle = None
    try:
        kernel32.OpenProcess.restype = ctypes.c_void_p
        kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, 0, int(pid))
        if not handle:
            # 老系统（含 Server 2008 R2 之前的 XP 内核）不支持 LIMITED_INFORMATION
            handle = kernel32.OpenProcess(0x0400, 0, int(pid))  # PROCESS_QUERY_INFORMATION
        if handle:
            size = ctypes.c_uint32(_MAX_PATH)
            buf = ctypes.create_unicode_buffer(_MAX_PATH)
            kernel32.QueryFullProcessImageNameW.argtypes = [
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_wchar_p,
                ctypes.POINTER(ctypes.c_uint32),
            ]
            if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                name = buf.value.rsplit("\\", 1)[-1]
    except Exception:
        name = ""
    finally:
        if handle:
            with contextlib.suppress(Exception):
                kernel32.CloseHandle(ctypes.c_void_p(handle))
    # 只缓存成功结果：非管理员时大量进程会因 ACCESS_DENIED 取不到名字，
    # 一旦缓存空串，用户之后再提权运行也永远解不出来了。
    if name:
        _pid_name_cache[pid] = name
    return name
