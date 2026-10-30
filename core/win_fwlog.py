"""
PortGuard — Windows 防火墙安全日志解析（pfirewall.log）

这是双通道采集里的**防火墙日志通道**，与 core/win_net.py 的 TCP 表轮询互补：

  TCP 表轮询   ：只能看见「仍然连着」的连接（ESTABLISHED）
  防火墙日志   ：连**被 DROP 掉的扫描**都会留痕（这正是最想抓的部分）

代价：
  · 需要 Windows 防火墙的「安全日志」被打开（默认关闭）—— 需管理员开启一次
  · 日志按大小滚动，历史窗口有限
  · 只有在防火墙里**记日志**的连接才出现（已放行的 inbound 需要同时开
    allowedconnections 才会记账）

日志格式（Windows 7 / Server 2008 R2 起一致）：
    #Fields: date time action protocol src-ip dst-ip src-port dst-port size
             tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path
    2013-10-11 00:00:00 DROP TCP 192.168.1.5 10.0.0.1 1234 445 52 S 0 0 8192 - - - RECEIVE

因为 `#Fields:` 头只在文件创建时写一次，增量读取时通常看不到它，
所以本模块**内置默认字段顺序**，同时在读到 `#Fields:` 时动态覆盖。

关于编码：日志用系统 ANSI 代码页写盘，含非 ASCII 时用 utf-8 解会乱码，
但 IP / 端口 / 动作这些我们真正关心的字段全是 ASCII，故统一
`utf-8 + errors=replace` 解码，宁可丢个把汉字也不让解析崩掉。
"""

import datetime
import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.logger import get_logger

log = get_logger(__name__)

# Windows 防火墙默认日志位置
DEFAULT_LOG_PATH = os.path.join(
    # Windows 环境变量查找不区分大小写，写 SYSTEMROOT 与系统里的 SystemRoot 等价
    os.environ.get("SYSTEMROOT", r"C:\Windows"),
    "System32",
    "LogFiles",
    "Firewall",
    "pfirewall.log",
)

# 默认字段顺序（读不到 #Fields 头时使用）
FIELDS: List[str] = [
    "date",
    "time",
    "action",
    "protocol",
    "src-ip",
    "dst-ip",
    "src-port",
    "dst-port",
    "size",
    "tcpflags",
    "tcpsyn",
    "tcpack",
    "tcpwin",
    "icmptype",
    "icmpcode",
    "info",
    "path",
]

ACTION_ALLOW = "ALLOW"
ACTION_DROP = "DROP"

_CREATE_NO_WINDOW = 0x08000000

# 需要出现在字段里的最小集合，缺任何一个都说明这不是一行合法日志
_REQUIRED = ("date", "time", "action", "protocol", "src-ip", "dst-ip", "src-port", "dst-port")


@dataclass
class FwLogEntry:
    """一行防火墙日志"""

    action: str = ""
    protocol: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    size: int = 0
    tcpflags: str = ""
    info: str = ""
    path: str = ""
    date: str = ""
    time: str = ""
    raw: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)

    @property
    def event_ts(self) -> int:
        """把 date+time 合成 epoch 毫秒；失败则回退 0（调用方会补当前时间）"""
        s = f"{self.date} {self.time}".strip()
        if not s:
            return 0
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
            try:
                return int(datetime.datetime.strptime(s, fmt).timestamp() * 1000)
            except ValueError:
                continue
        return 0

    @property
    def direction(self) -> str:
        """
        报文方向：RECEIVE（入站）/ SEND（出站）/ 空。

        为什么单独抽一个属性：微软的字段头把最后一列命名为 `path`，
        但真实日志里这一列放的其实是 `RECEIVE` / `SEND` / `-`（历史命名混乱）。
        这里两种可能的位置都探一遍，拿到什么算什么。
        """
        for v in (self.path, self.info):
            if v.strip().upper() in ("RECEIVE", "SEND"):
                return v.strip().upper()
        return ""

    @property
    def is_drop(self) -> bool:
        return self.action.upper() == ACTION_DROP

    @property
    def is_tcp(self) -> bool:
        return self.protocol.upper() == "TCP"

    def __str__(self) -> str:
        return (
            f"{self.action} {self.protocol} "
            f"{self.src_ip}:{self.src_port} -> {self.dst_ip}:{self.dst_port}"
        )


# ═══════════════════════════════════════════════════════════
#  解析
# ═══════════════════════════════════════════════════════════


def _split_fields(line: str, fields: List[str]) -> List[str]:
    """
    按字段数切分：最后一个字段吃掉剩余全部内容。

    为什么不是简单 split()：`path` 字段保存进程完整路径，里面**有空格**
    （C:\\Program Files\\...）。直接 split 会把它切碎并让整行错位。
    """
    n = len(fields)
    if n <= 0:
        return []
    parts = line.split(None, n - 1)
    if len(parts) < n:
        parts += [""] * (n - len(parts))
    return parts


def _to_int(v: Any, default: int = 0) -> int:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return default


def parse_line(line: str, fields: Optional[List[str]] = None) -> Optional[FwLogEntry]:
    """
    解析一行日志。非法行返回 None（绝不抛异常 —— 日志里混进半行是常态）。
    """
    line = (line or "").strip()
    if not line or line.startswith("#"):
        return None
    fields = fields or FIELDS
    if len(line.split()) < 6:
        return None
    vals = _split_fields(line, fields)
    d = dict(zip(fields, vals))
    if any(k not in d for k in _REQUIRED):
        return None
    action = d.get("action", "").strip().upper()
    if action not in (ACTION_ALLOW, ACTION_DROP):
        return None
    known = set(FIELDS)
    return FwLogEntry(
        action=action,
        protocol=d.get("protocol", "").strip().upper(),
        src_ip=d.get("src-ip", "").strip(),
        dst_ip=d.get("dst-ip", "").strip(),
        src_port=_to_int(d.get("src-port")),
        dst_port=_to_int(d.get("dst-port")),
        size=_to_int(d.get("size")),
        tcpflags=d.get("tcpflags", "").strip(),
        info=d.get("info", "").strip(),
        path=d.get("path", "").strip(),
        date=d.get("date", "").strip(),
        time=d.get("time", "").strip(),
        raw=line,
        extra={k: v for k, v in d.items() if k not in known},
    )


def parse_text(text: str, fields: Optional[List[str]] = None) -> List[FwLogEntry]:
    """解析一整段文本（含 #Fields 头）。测试与一次性读取都走这里。"""
    cur = list(fields) if fields else list(FIELDS)
    out: List[FwLogEntry] = []
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            continue
        if s.startswith("#"):
            low = s.lower()
            if low.startswith("#fields:"):
                got = s.split(":", 1)[1].split()
                if got:
                    cur = got
            continue
        e = parse_line(s, cur)
        if e is not None:
            out.append(e)
    return out


def filter_inbound(entries: List[FwLogEntry], ports: List[int]) -> List[FwLogEntry]:
    """
    挑出「打到本机被监控端口上的入站包」。

    判定依据是 **dst_port ∈ 监控端口**：入站报文的目的是本机端口，
    所以目标端口就是我们的端口，源地址才是要观察的外部 IP。

    两道排除：
    · 源地址在本机 → 是自己连自己，没有观察价值
    · 明确标了 SEND（出站）→ SEND 行的 dst-port 是**对端**端口，
      拿它跟本机监控端口比对属于张冠李戴，必须排除。
      （只有真切到 direction 才排除；老版本日志没有该列时保持放行。）
    """
    from core.win_net import is_external_ip

    wanted = {int(p) for p in ports if str(p).isdigit()}
    if not wanted:
        return []
    out: List[FwLogEntry] = []
    for e in entries:
        if e.dst_port not in wanted:
            continue
        if e.direction == "SEND":
            continue
        if not is_external_ip(e.src_ip):
            continue
        out.append(e)
    return out


# ═══════════════════════════════════════════════════════════
#  增量读取（tail）
# ═══════════════════════════════════════════════════════════


class FwLogTailer:
    """
    增量读取防火墙日志。

    设计要点：
    · 记录已消费的字节偏移，每次只读新追加的部分 —— 日志文件动辄几十 MB，
      每次全量读会直接把采集线程拖死
    · 末尾可能是**没写完的半行**，只消费到最后一个换行符为止，半行留到下次
    · 文件被重建 / 截断（大小小于当前偏移）时自动从头开始，字段头也重置
    · 非 Windows 或文件不存在时安静返回空列表
    """

    def __init__(self, path: Optional[str] = None):
        self._path = path or DEFAULT_LOG_PATH
        self._offset = 0
        self._fields: List[str] = list(FIELDS)
        self.read_bytes = 0
        self.lines_seen = 0

    @property
    def path(self) -> str:
        return self._path

    def set_path(self, path: str) -> None:
        self._path = path or DEFAULT_LOG_PATH
        self.reset()

    def reset(self) -> None:
        self._offset = 0
        self._fields = list(FIELDS)

    def skip_to_end(self) -> int:
        """
        把读取位置直接推到文件末尾并返回跳过的字节数。

        用途：观察器**启动时**必须丢掉历史日志 —— 否则一份 50 MB 的旧日志
        会在启动瞬间被当成几万条"新事件"灌进规则引擎和数据库。
        """
        self.reset()
        try:
            if self.exists():
                self._offset = os.path.getsize(self._path)
        except OSError:
            self._offset = 0
        return self._offset

    def exists(self) -> bool:
        try:
            return os.path.isfile(self._path)
        except Exception:
            return False

    def read_new(self) -> List[FwLogEntry]:
        """读取自上次以来新增的完整行，解析为日志条目"""
        if not self.exists():
            return []
        try:
            size = os.path.getsize(self._path)
        except OSError:
            return []
        if size < self._offset:
            # 文件被清空或重建：从头来
            log.info("防火墙日志已重建（%d -> %d 字节），从头开始读取", self._offset, size)
            self.reset()
        if size == self._offset:
            return []
        try:
            with open(self._path, "rb") as f:
                f.seek(self._offset)
                chunk = f.read(size - self._offset)
        except OSError as e:
            log.debug("读取防火墙日志失败：%s", e)
            return []
        if not chunk:
            return []

        consumed = len(chunk)
        if not chunk.endswith(b"\n"):
            idx = chunk.rfind(b"\n")
            if idx < 0:
                # 整块全是半行，等下一次
                return []
            consumed = idx + 1
            chunk = chunk[:consumed]
        self._offset += consumed
        self.read_bytes += consumed

        text = chunk.decode("utf-8", "replace")
        out: List[FwLogEntry] = []
        for raw in text.splitlines():
            s = raw.strip()
            if not s:
                continue
            if s.startswith("#"):
                if s.lower().startswith("#fields:"):
                    got = s.split(":", 1)[1].split()
                    if got:
                        self._fields = got
                continue
            entry = parse_line(s, self._fields)
            if entry is not None:
                out.append(entry)
        self.lines_seen += len(out)
        return out

    def stats(self) -> Dict[str, Any]:
        return {
            "path": self._path,
            "exists": self.exists(),
            "offset": self._offset,
            "read_bytes": self.read_bytes,
            "lines_seen": self.lines_seen,
        }


# ═══════════════════════════════════════════════════════════
#  防火墙日志开关（需要管理员）
# ═══════════════════════════════════════════════════════════


def _run(cmd: List[str], timeout: int = 20) -> Tuple[int, str]:
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
            check=False,
            creationflags=(_CREATE_NO_WINDOW if sys.platform == "win32" else 0),
        )
    except subprocess.TimeoutExpired:
        return -1, "命令执行超时"
    except FileNotFoundError as e:
        return -2, f"未找到命令: {e}"
    except Exception as e:
        return -3, f"命令执行失败: {e}"
    raw = (p.stdout or b"") + (p.stderr or b"")
    for enc in ("mbcs", "gbk", "utf-8"):
        try:
            return p.returncode, raw.decode(enc)
        except Exception:
            continue
    return p.returncode, raw.decode("utf-8", "replace")


def logging_enabled(path: Optional[str] = None) -> bool:
    """能否读到日志文件（最直接的可用性判据）"""
    return os.path.isfile(path or DEFAULT_LOG_PATH)


def enable_logging(
    path: Optional[str] = None,
    max_size_kb: int = 4096,
    log_dropped: bool = True,
    log_allowed: bool = False,
) -> Tuple[bool, str]:
    """
    打开防火墙安全日志（需要管理员权限）。

    参数取舍：默认只记 **被丢弃的连接**（log_dropped=True）与 **不记已放行**
    （log_allowed=False）—— 这一组合能抓到扫描/爆破，又不会因为正常业务的
    每一次连接把日志文件写爆。需要观察「谁在正常访问某端口」时再打开它。

    返回 (成功, 错误信息)
    """
    target = path or DEFAULT_LOG_PATH
    errs: List[str] = []
    cmds = [
        ["netsh", "advfirewall", "set", "allprofiles", "logging", "filename", target],
        [
            "netsh",
            "advfirewall",
            "set",
            "allprofiles",
            "logging",
            "droppedconnections",
            "enable" if log_dropped else "disable",
        ],
        [
            "netsh",
            "advfirewall",
            "set",
            "allprofiles",
            "logging",
            "allowedconnections",
            "enable" if log_allowed else "disable",
        ],
        [
            "netsh",
            "advfirewall",
            "set",
            "allprofiles",
            "logging",
            "maxfilesize",
            str(max(1, int(max_size_kb))),
        ],
    ]
    for c in cmds:
        code, out = _run(c)
        if code != 0:
            errs.append(f"{' '.join(c[-2:])}: {out.strip()[:160]}")
    if errs:
        log.warning("开启防火墙日志失败：%s", " | ".join(errs))
        return False, " | ".join(errs)
    log.info("已开启防火墙安全日志：%s（丢弃=%s 放行=%s）", target, log_dropped, log_allowed)
    return True, ""


def disable_logging() -> Tuple[bool, str]:
    """关闭防火墙安全日志（需要管理员权限）"""
    errs: List[str] = []
    for c in (
        ["netsh", "advfirewall", "set", "allprofiles", "logging", "droppedconnections", "disable"],
        ["netsh", "advfirewall", "set", "allprofiles", "logging", "allowedconnections", "disable"],
    ):
        code, out = _run(c)
        if code != 0:
            errs.append(f"{' '.join(c[-2:])}: {out.strip()[:160]}")
    if errs:
        return False, " | ".join(errs)
    return True, ""


def logging_state() -> Dict[str, Any]:
    """读取当前日志配置（不需要管理员）"""
    state: Dict[str, Any] = {"path": DEFAULT_LOG_PATH, "exists": False, "size": 0}
    code, out = _run(["netsh", "advfirewall", "show", "allprofiles", "logging"])
    if code == 0:
        # 输出形如：
        #   公用配置文件 日志记录:
        #   ----------------------------------------------------------------------
        #   记录被丢弃的连接: 启用
        #   记录成功的连接: 禁用
        #   日志文件路径: C:\Windows\System32\LogFiles\Firewall\pfirewall.log
        info: Dict[str, str] = {}
        for line in out.splitlines():
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            info[k.strip().lstrip("\ufeff")] = v.strip()
        state["raw"] = info
        for k, v in info.items():
            if "路径" in k or "path" in k.lower():
                state["path"] = v
    p = state["path"]
    try:
        if p and os.path.isfile(p):
            state["exists"] = True
            state["size"] = os.path.getsize(p)
    except Exception:
        pass
    return state


# ── 丢弃连接日志是否真的在记（带短暂缓存，避免每次轮询都 spawn netsh） ──
_dropped_state_cache: Tuple[float, bool] = (0.0, False)
_DROPPED_STATE_TTL = 30.0


def is_dropped_logging_enabled() -> bool:
    """Windows 防火墙是否真的在记录「被丢弃的连接」（不需要管理员权限）。

    这是 fwlog 通道能否采到扫描/爆破的关键：只开了采集通道、但系统层「丢弃连接」
    日志没启用，日志文件不会更新，扫描探测类攻击就被漏检。

    ``logging_enabled`` 只看日志**文件是否存在**（旧文件可能一直躺那），不足以判定
    「当前在记」，故用本函数读 netsh 的 logging 配置。结果带 30s TTL 缓存，适合
    被 2s 一次的状态刷新反复调用。
    """
    global _dropped_state_cache
    now = time.monotonic()
    ts, val = _dropped_state_cache
    if now - ts < _DROPPED_STATE_TTL:
        return val
    result = _probe_dropped_logging_enabled()
    _dropped_state_cache = (now, result)
    return result


def _probe_dropped_logging_enabled() -> bool:
    try:
        state = logging_state()
    except Exception:
        return False
    raw = state.get("raw") or {}
    for k, v in raw.items():
        key = k.lower()
        # 兼容中英文 Windows：「记录被丢弃的连接」/「Log dropped packets」
        if "丢弃" in k or "drop" in key:
            return "启用" in v or "enable" in v.lower()
    return False
