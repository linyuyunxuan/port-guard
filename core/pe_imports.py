"""PE 导入表解析与 DLL 依赖就近解析（纯标准库，可打包进 exe 内运行）。

为什么需要它
------------
窗口化打包程序在开发机上跑得通、拷到别的电脑却报

    DLL load failed while importing QtCore: 找不到指定的模块

的原因几乎只有一个：某个**硬导入**的 DLL 在目标机解析不到。开发机通常装了
Microsoft Visual C++ 运行库甚至 Visual Studio，产物里缺的 DLL 会被
``C:\\Windows\\System32`` 悄悄兜住，所以本机永远看不出问题。

Windows 解析依赖是**按搜索路径上下文**进行的，不是「整个目录树里有没有」：

1. 加载某 DLL 时先搜它**自己所在目录**（CPython 用
   ``LOAD_WITH_ALTERED_SEARCH_PATH`` 加载扩展模块，因此该目录对其整条依赖链生效）
2. ``_internal``（PyInstaller 的附加目录，启动时已加入搜索路径）
3. 已用 ``os.add_dll_directory`` 注册的目录、``PATH``
4. ``System32`` 等系统目录

因此「DLL 存在于产物某个角落」并不等于「运行时能找到」。本模块据此把每个
未解析项分成三类：

- ``risk``    产物内没有、只在本机 System32 找到，且**不属于 Windows 自带组件**
              → 只能是 VC++ 运行库/开发环境带来的，干净机器上必崩
- ``weak``    只在**兄弟目录**里找到（依赖 PATH / add_dll_directory 生效）→ 脆弱
- ``missing`` 产物内没有，本机 System32 也没有

另外记录了「系统自带但**有最低系统版本要求**」的组件（如 ``icuuc.dll`` 需要
Windows 10 1703+），这类在旧系统上会变成 ``risk``，是「本机能跑、老机器不能跑」
最隐蔽的一类原因。
"""

from __future__ import annotations

import os
import struct
from collections import defaultdict
from typing import Iterable

PE_SUFFIXES = (".dll", ".pyd", ".exe")

# Windows 自带模块（含 api-ms-win-* / ext-ms-* 系列）。这些不进产物也没关系。
OS_KNOWN: frozenset[str] = frozenset(
    {
        "advapi32",
        "authz",
        "avicap32",
        "avrt",
        "bcrypt",
        "bcryptprimitives",
        "bluetoothapis",
        "bthprops",
        "cabinet",
        "cfgmgr32",
        "comctl32",
        "comdlg32",
        "credui",
        "crypt32",
        "cryptbase",
        "cryptui",
        "d2d1",
        "d3d11",
        "d3d12",
        "d3d9",
        "d3dcompiler_47",
        "dbghelp",
        "dcomp",
        "dhcpcsvc",
        "dhcpcsvc6",
        "dnsapi",
        "dsound",
        "dsrole",
        "dwmapi",
        "dwrite",
        "dxgi",
        "dxva2",
        "gdi32",
        "gdi32full",
        "glu32",
        "hid",
        "icu",
        "icuin",
        "icuuc",
        "imagehlp",
        "imm32",
        "iphlpapi",
        "kernel32",
        "kernelbase",
        "ktmw32",
        "magnification",
        "mgmtapi",
        "mpr",
        "mprapi",
        "mscoree",
        "msi",
        "msimg32",
        "mscms",
        "mstask",
        "mswsock",
        "msvcrt",
        "ncrypt",
        "ncryptsslp",
        "ndfapi",
        "netapi32",
        "netprofm",
        "newdev",
        "normaliz",
        "ntdll",
        "ole32",
        "oleaut32",
        "opengl32",
        "pcacli",
        "pdh",
        "powrprof",
        "prntvpt",
        "propsys",
        "psapi",
        "rasapi32",
        "rometadata",
        "rpcrt4",
        "rtutils",
        "sechost",
        "secur32",
        "sensapi",
        "setupapi",
        "sfc",
        "shcore",
        "shell32",
        "shlwapi",
        "slc",
        "sspicli",
        "tapi32",
        "traffic",
        "twinapi",
        "ucrtbase",
        "uiautomationcore",
        "urlmon",
        "user32",
        "userenv",
        "usp10",
        "uxtheme",
        "version",
        "virtdisk",
        "wecapi",
        "wer",
        "wevtapi",
        "winhttp",
        "wininet",
        "winmm",
        "winspool",
        "wintrust",
        "winusb",
        "wlanapi",
        "wlanui",
        "wldap32",
        "wnvapi",
        "ws2_32",
        "wsock32",
        "wtsapi32",
    }
)

# 系统自带、但不是所有 Windows 版本都有的组件：DLL 名 → (最低系统要求说明,)
# 命中时在报告里单独提醒，用于解释「本机能跑、目标机不能跑」。
OS_MIN_VERSION: dict[str, str] = {
    "icuuc.dll": "Windows 10 1703（Creators Update）起才有",
    "icuin.dll": "Windows 10 1703（Creators Update）起才有",
    "icu.dll": "Windows 10 1903（May 2019 Update）起才有",
    "bcryptprimitives.dll": "Windows 8 起才有",
    "d3d12.dll": "Windows 10 起才有",
    "api-ms-win-core-winrt-l1-1-0.dll": "Windows 8 起才有",
    "api-ms-win-core-winrt-error-l1-1-1.dll": "Windows 8 起才有",
    "api-ms-win-core-synch-l1-2-0.dll": "Windows 8 起才有",
}


def system32_dirs() -> list[str]:
    root = os.environ.get("SYSTEMROOT", r"C:\Windows")
    return [os.path.join(root, "System32"), os.path.join(root, "SysWOW64")]


def is_os_component(dll: str) -> bool:
    low = dll.lower()
    if low.startswith(("api-ms-", "ext-ms-")):
        return True
    return low.rsplit(".", 1)[0] in OS_KNOWN


def is_available(dll: str) -> bool:
    """本机能否提供该 DLL。

    先查 System32/SysWOW64 是否有物理文件；``api-ms-win-*`` 这类 API set 没有
    对应文件（由加载器按 apiset schema 解析），所以再退回 LoadLibrary 实测，
    否则会误报「本机也没有」。
    """
    if any(os.path.exists(os.path.join(d, dll)) for d in system32_dirs()):
        return True
    if os.name != "nt" or not dll.lower().endswith(".dll"):
        return False
    try:
        import ctypes

        ctypes.WinDLL(dll)
        return True
    except Exception:
        return False


# --------------------------------------------------------------------------- #
# PE 解析
# --------------------------------------------------------------------------- #
def _open_pe(path: str):
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        # 读不到（被安全软件隔离、拷贝不完整、权限不足）一律当成「无法解析」，
        # 由调用方按缺失处理，不要在这里抛出去打断整轮扫描。
        return None
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        return None
    coff = e_lfanew + 4
    n_sections = struct.unpack_from("<H", data, coff + 2)[0]
    size_opt = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:  # PE32+
        dd_off = opt + 112
    elif magic == 0x10B:  # PE32
        dd_off = opt + 96
    else:
        return None
    secs: list[tuple[int, int, int]] = []
    sec_off = opt + size_opt
    for i in range(n_sections):
        base = sec_off + i * 40
        if base + 40 > len(data):
            break
        v_size, v_addr, r_size, r_ptr = struct.unpack_from("<IIII", data, base + 8)
        secs.append((v_addr, max(v_size, r_size), r_ptr))
    return data, dd_off, secs


def _import_directory(data: bytes, dd_off: int, secs, index: int) -> list[str]:
    """读取目录项 index 指向的导入表。index=1 硬导入，index=13 延迟导入。"""
    entry = dd_off + index * 8
    if entry + 8 > len(data):
        return []
    rva, size = struct.unpack_from("<II", data, entry)
    if not rva or not size:
        return []

    def rva_to_off(off_rva: int) -> int | None:
        for v_addr, v_size, r_ptr in secs:
            if v_addr <= off_rva < v_addr + v_size:
                return off_rva - v_addr + r_ptr
        return None

    table_off = rva_to_off(rva)
    if table_off is None:
        return []

    names: list[str] = []
    # 延迟导入描述符的 DLL 名字段在 +4，步长 8；普通导入描述符在 +12，步长 20
    name_field = 4 if index == 13 else 12
    step = 8 if index == 13 else 20
    for k in range(4096):
        desc = table_off + k * step
        if desc + step > len(data) or not any(data[desc : desc + step]):
            break
        name_off = rva_to_off(struct.unpack_from("<I", data, desc + name_field)[0])
        if name_off is None:
            continue
        end = data.find(b"\0", name_off)
        name = data[name_off:end].decode("ascii", "replace").strip().lower()
        if "." in name:
            names.append(name)
    return names


def imports(path: str) -> tuple[set[str], set[str]]:
    """返回 (硬导入集合, 延迟导入集合)，均为小写 DLL 名。失败时返回空集合。"""
    parsed = _open_pe(path)
    if not parsed:
        return set(), set()
    data, dd_off, secs = parsed
    return (
        set(_import_directory(data, dd_off, secs, 1)),
        set(_import_directory(data, dd_off, secs, 13)),
    )


def hard_imports(path: str) -> set[str]:
    """只返回硬导入（小写 DLL 名）。"""
    return imports(path)[0]


# --------------------------------------------------------------------------- #
# 依赖就近解析
# --------------------------------------------------------------------------- #
class DepIssue:
    """一条「运行时可能解析不到」的依赖记录。"""

    __slots__ = ("callers", "dep", "kind", "note")

    def __init__(self, dep: str, kind: str) -> None:
        self.dep = dep
        self.kind = kind  # risk / weak / missing
        self.callers: set[str] = set()
        self.note = OS_MIN_VERSION.get(dep, "")

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"<DepIssue {self.dep} {self.kind} x{len(self.callers)}>"


def scan_bundle(root: str) -> tuple[dict[str, DepIssue], int]:
    """扫描打包目录，返回 (问题字典 {DLL 名: DepIssue}, 扫描到的 PE 文件数)。

    判定「稳定可解析」的目录：文件自身所在目录、``_internal``、产物根目录。
    其余情况按 risk / weak / missing 分类。
    """
    root = os.path.abspath(root)
    where: dict[str, set[str]] = defaultdict(set)
    files: list[tuple[str, str]] = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if not name.lower().endswith(PE_SUFFIXES):
                continue
            rel_dir = os.path.relpath(dirpath, root)
            rel_dir = "" if rel_dir == "." else rel_dir.replace("\\", "/")
            rel_file = f"{rel_dir}/{name}" if rel_dir else name
            where[name.lower()].add(rel_dir)
            files.append((rel_file, os.path.join(dirpath, name)))

    stable_extra = {"", "_internal"}
    sys_dirs = system32_dirs()
    issues: dict[str, DepIssue] = {}

    for rel_file, abs_path in files:
        own_dir = os.path.dirname(rel_file).replace("\\", "/")
        try:
            deps = hard_imports(abs_path)
        except OSError:
            continue
        for dep in deps:
            if is_os_component(dep):
                continue
            dirs = where.get(dep)
            if dirs and (own_dir in dirs or (dirs & stable_extra)):
                continue
            if dirs:
                kind = "weak"
            elif any(os.path.exists(os.path.join(d, dep)) for d in sys_dirs):
                kind = "risk"
            else:
                kind = "missing"
            issues.setdefault(dep, DepIssue(dep, kind)).callers.add(rel_file)

    return issues, len(files)


def os_version_deps(root: str) -> dict[str, set[str]]:
    """找出「依赖系统自带、但有最低版本要求」的组件，返回 {DLL: 谁在依赖}。

    这类依赖不算产物缺陷，但在旧系统上会直接导致加载失败，必须在报告里点名。
    """
    result: dict[str, set[str]] = defaultdict(set)
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if not name.lower().endswith(PE_SUFFIXES):
                continue
            full = os.path.join(dirpath, name)
            try:
                deps = hard_imports(full)
            except OSError:
                continue
            for dep in deps:
                if dep in OS_MIN_VERSION:
                    result[dep].add(os.path.relpath(full, root).replace("\\", "/"))
    return dict(result)


def bundled_names(root: str) -> set[str]:
    """产物内所有 PE 文件名（小写）。"""
    found: set[str] = set()
    for _dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if name.lower().endswith(PE_SUFFIXES):
                found.add(name.lower())
    return found


def format_issues(issues: Iterable[DepIssue], limit: int = 4) -> list[str]:
    """把问题列表格式化成便于阅读的多行文本。"""
    order = {"risk": 0, "missing": 1, "weak": 2}
    lines: list[str] = []
    for issue in sorted(issues, key=lambda i: (order.get(i.kind, 9), i.dep)):
        callers = sorted(issue.callers)
        head = ", ".join(callers[:limit])
        tail = "" if len(callers) <= limit else f"  等 {len(callers)} 处"
        note = f"（{issue.note}）" if issue.note else ""
        lines.append(f"[{issue.kind}] {issue.dep}{note} ← {head}{tail}")
    return lines
