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

import os
import struct
from collections import defaultdict
from typing import Dict, FrozenSet, Iterable, List, Optional, Set, Tuple

PE_SUFFIXES = (".dll", ".pyd", ".exe")

# Windows 自带模块（含 api-ms-win-* / ext-ms-* 系列）。这些不进产物也没关系。
OS_KNOWN: FrozenSet[str] = frozenset(
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
OS_MIN_VERSION: Dict[str, str] = {
    "icuuc.dll": "Windows 10 1703（Creators Update）起才有",
    "icuin.dll": "Windows 10 1703（Creators Update）起才有",
    "icu.dll": "Windows 10 1903（May 2019 Update）起才有",
    "bcryptprimitives.dll": "Windows 8 起才有",
    "d3d12.dll": "Windows 10 起才有",
    "dcomp.dll": "Windows 8 起才有",
    "shcore.dll": "Windows 8 起才有",
    "api-ms-win-core-winrt-l1-1-0.dll": "Windows 8 起才有",
    "api-ms-win-core-winrt-error-l1-1-1.dll": "Windows 8 起才有",
    "api-ms-win-core-synch-l1-2-0.dll": "Windows 8 起才有",
}

# --------------------------------------------------------------------------- #
# Windows 7 SP1 / Server 2008 R2 兼容闸门
# --------------------------------------------------------------------------- #
# 本项目的交付底线是 Win7 SP1 / Server 2008 R2，所以「产物引用了老系统上
# 根本不存在的组件」必须是**硬失败**，而不是提醒。
#
# 这跟 OS_MIN_VERSION 的区别：OS_MIN_VERSION 是「有些机器上没有」，
# 这里列的是「底线系统上一定没有」——出现即等于「支持 Win7」这句承诺不成立。
#
# 名单是实测出来的，不是抄的：PySide2 5.15.2 的 Qt5Core.dll 硬导入 25 个 DLL，
# 其中**不含** icuuc / shcore / bcryptprimitives；而 PySide6 的 Qt6Core.dll
# 硬导入 icuuc.dll 和 api-ms-win-core-synch-l1-2-0.dll —— 这正是 Qt6 永远
# 跑不了 Win7 的根本原因（Qt6Core.dll 被静态绑定到 UCRT 的 ICU 上）。
WIN7_BLOCKERS: Dict[str, str] = {
    "icuuc.dll": "ICU 库，Windows 10 1703 起才随系统提供（Qt6 硬依赖 → Win7 必然加载失败）",
    "icuin.dll": "ICU 库，Windows 10 1703 起才随系统提供",
    "icu.dll": "ICU 合并库，Windows 10 1903 起才随系统提供",
    "bcryptprimitives.dll": "Windows 8 起才随系统提供",
    "d3d12.dll": "Windows 10 起才随系统提供",
    "dcomp.dll": "Windows 8 起才随系统提供",
    "shcore.dll": "Windows 8 起才随系统提供（Qt5 缩放 API 若改成硬导入会在这里暴露）",
    "api-ms-win-core-synch-l1-2-0.dll": "Windows 8 起才有的 API set",
    "api-ms-win-core-winrt-l1-1-0.dll": "Windows 8 起才有的 WinRT API set",
    "api-ms-win-core-winrt-error-l1-1-1.dll": "Windows 8 起才有的 WinRT API set",
}

# Win7 上「系统不提供、必须随包携带或预装」的运行时。
# 这些是 VC++ 2015+ 运行库 / 通用 CRT，Win7 需要单独装 KB2999226 或
# VC++ 2015-2022 可再发行组件；产物里没带就必然出现「找不到指定的模块」。
LEGACY_REDIST: FrozenSet[str] = frozenset(
    {
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "msvcp140.dll",
        "msvcp140_1.dll",
        "msvcp140_2.dll",
        "concrt140.dll",
    }
)

# 通用 CRT 在 Win7 上以 api-ms-win-crt-*.dll 的形式被引用，同样需要 UCRT 更新
REDIST_PREFIXES = ("api-ms-win-crt-",)

# PortGuard 真正会加载的文件（按 basename 匹配，顺序即 Qt 的加载顺序）。
#
# 为什么需要这份清单：Qt 的 wheel 里塞了大量「装得到、用不上」的模块 ——
# Qt5Bluetooth、qsgd3d12backend（Qt Quick 的 D3D12 后端）、sqldrivers、mediaservice…
# 它们**只在用到对应功能时才被加载**，而本项目一个都不用。若不加区分，
# 闸门会因为这些插件里引用了 d3d12/dcomp/api-ms-win-core-winrt-* 而整片飘红，
# 真正的问题（核心 DLL 引用了 Win7 上没有的组件）反而被噪音埋掉。
#
# 不在清单里的照旧报出来，但归为「提示」而不是「阻断」——见 LegacyAudit.advisory。
APP_LOAD_PATH: FrozenSet[str] = frozenset(
    {
        # Qt 核心（PySide6 线路）
        "qt6core.dll",
        "qt6gui.dll",
        "qt6widgets.dll",
        "qt6network.dll",
        "qt6svg.dll",
        # Qt 核心（PySide2 线路 —— 交付用的 Win7 线路）
        "qt5core.dll",
        "qt5gui.dll",
        "qt5widgets.dll",
        "qt5network.dll",
        "qt5svg.dll",
        # Python 绑定层
        "shiboken2.abi3.dll",
        "shiboken6.abi3.dll",
        # 必定加载的 Qt 插件（平台插件与图片格式）
        "qwindows.dll",
        "qwindowsd.dll",
        "qico.dll",
        "qsvg.dll",
        "qjpeg.dll",
        "qgif.dll",
    }
)


def system32_dirs() -> List[str]:
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
    secs: List[Tuple[int, int, int]] = []
    sec_off = opt + size_opt
    for i in range(n_sections):
        base = sec_off + i * 40
        if base + 40 > len(data):
            break
        v_size, v_addr, r_size, r_ptr = struct.unpack_from("<IIII", data, base + 8)
        secs.append((v_addr, max(v_size, r_size), r_ptr))
    return data, dd_off, secs


def _import_directory(data: bytes, dd_off: int, secs, index: int) -> List[str]:
    """读取目录项 index 指向的导入表。index=1 硬导入，index=13 延迟导入。"""
    entry = dd_off + index * 8
    if entry + 8 > len(data):
        return []
    rva, size = struct.unpack_from("<II", data, entry)
    if not rva or not size:
        return []

    def rva_to_off(off_rva: int) -> Optional[int]:
        for v_addr, v_size, r_ptr in secs:
            if v_addr <= off_rva < v_addr + v_size:
                return off_rva - v_addr + r_ptr
        return None

    table_off = rva_to_off(rva)
    if table_off is None:
        return []

    names: List[str] = []
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


def imports(path: str) -> Tuple[Set[str], Set[str]]:
    """返回 (硬导入集合, 延迟导入集合)，均为小写 DLL 名。失败时返回空集合。"""
    parsed = _open_pe(path)
    if not parsed:
        return set(), set()
    data, dd_off, secs = parsed
    return (
        set(_import_directory(data, dd_off, secs, 1)),
        set(_import_directory(data, dd_off, secs, 13)),
    )


def hard_imports(path: str) -> Set[str]:
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
        self.callers: Set[str] = set()
        self.note = OS_MIN_VERSION.get(dep, "")

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"<DepIssue {self.dep} {self.kind} x{len(self.callers)}>"


def scan_bundle(root: str) -> Tuple[Dict[str, DepIssue], int]:
    """扫描打包目录，返回 (问题字典 {DLL 名: DepIssue}, 扫描到的 PE 文件数)。

    判定「稳定可解析」的目录：文件自身所在目录、``_internal``、产物根目录。
    其余情况按 risk / weak / missing 分类。
    """
    root = os.path.abspath(root)
    where: Dict[str, Set[str]] = defaultdict(set)
    files: List[Tuple[str, str]] = []
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
    issues: Dict[str, DepIssue] = {}

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


def os_version_deps(root: str) -> Dict[str, Set[str]]:
    """找出「依赖系统自带、但有最低版本要求」的组件，返回 {DLL: 谁在依赖}。

    这类依赖不算产物缺陷，但在旧系统上会直接导致加载失败，必须在报告里点名。
    """
    result: Dict[str, Set[str]] = defaultdict(set)
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


def bundled_names(root: str) -> Set[str]:
    """产物内所有 PE 文件名（小写）。"""
    found: Set[str] = set()
    for _dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if name.lower().endswith(PE_SUFFIXES):
                found.add(name.lower())
    return found


class LegacyAudit:
    """Windows 7 SP1 / Server 2008 R2 兼容性审计结果。"""

    __slots__ = (
        "advisory",
        "blockers",
        "load_path",
        "needs_ucrt",
        "redist_bundled",
        "redist_missing",
        "scanned",
    )

    def __init__(self, load_path: Optional[FrozenSet[str]] = None) -> None:
        self.advisory: Dict[str, Set[str]] = {}
        self.blockers: Dict[str, Set[str]] = {}
        self.load_path: FrozenSet[str] = APP_LOAD_PATH if load_path is None else load_path
        self.redist_bundled: Set[str] = set()
        self.redist_missing: Set[str] = set()
        self.needs_ucrt = False
        self.scanned = 0

    @property
    def ok(self) -> bool:
        """产物到底能不能在底线系统上跑。

        只看两条硬性条件：**应用会加载的**文件不能引用 Win8+ 才有的组件，
        以及不能缺需要随包携带的运行库。

        两点说明：
        · UCRT（``api-ms-win-crt-*``）属于**部署前置条件**而不是产物缺陷 ——
          它在 Win7 上由 KB2999226 提供，不随包携带，因此只提示不判失败。
        · 未被应用加载的 Qt 插件（scenegraph/qtbluetooth/sqldrivers…）里的
          引用归到 ``advisory``，不判失败：那些 DLL 只在用到对应功能时才被加载，
          拿它们卡死发布等于对着用不上的代码开罚单。
        """
        return not self.blockers and not self.redist_missing

    def summary(self) -> str:
        if not self.ok:
            parts: List[str] = []
            if self.blockers:
                parts.append("引用了老系统不存在的组件：" + "、".join(sorted(self.blockers)))
            if self.redist_missing:
                parts.append("缺少需随包携带的运行库：" + "、".join(sorted(self.redist_missing)))
            return "；".join(parts)
        if self.needs_ucrt:
            return "产物可在 Windows 7 SP1 / Server 2008 R2 及以上运行（Win7 需先装 KB2999226）"
        return "产物可在 Windows 7 SP1 / Server 2008 R2 及以上运行"


def legacy_audit(root: str, *, load_path: Optional[FrozenSet[str]] = None) -> LegacyAudit:
    """审计产物能否在 Windows 7 SP1 / Server 2008 R2 上加载。

    两条判定线（都能在**开发机**上跑出来，不依赖一台真的 Win7）：

    1. **禁区组件**：应用加载路径上的 PE 硬导入了 ``WIN7_BLOCKERS`` 里的 DLL。
       这些组件在底线上不存在，加补丁也变不出来，属于硬失败。
       不在 ``load_path``（默认 ``APP_LOAD_PATH``）上的引用只记进 ``advisory``。
    2. **缺运行库**：产物引用了 VC++ 运行库 / UCRT（``LEGACY_REDIST`` 与
       ``api-ms-win-crt-*``），但产物内没带对应文件。开发机装了 VC++ 运行库
       会把它兜住，所以本机永远看不出问题；干净 Win7 上必崩。

    边界：这里**不判断** ``vcruntime140`` 这类由 ``scan_bundle`` 归到 ``risk``
    的情况，两边结论可能重叠但角度不同 —— ``scan_bundle`` 关心「就近能不能解析」，
    这里关心「系统版本来不来得及提供」。
    """
    audit = LegacyAudit(load_path)
    names = bundled_names(root)

    # 运行库是否随包携带：只看产物内有没有同名文件，不看本机 System32
    wanted = set(LEGACY_REDIST)
    for n in names:
        if n in LEGACY_REDIST or n.startswith(REDIST_PREFIXES):
            audit.redist_bundled.add(n)
    wanted -= audit.redist_bundled

    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            if not name.lower().endswith(PE_SUFFIXES):
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace("\\", "/")
            audit.scanned += 1
            # 判断这个文件是不是「应用真的会加载」的那批
            on_path = name.lower() in audit.load_path
            # 运行库自身（ucrtbase / vcruntime / api-ms-win-crt-*）引用的 API set
            # 不单独报：它们的可操作项是「Win7 先装 KB2999226 / VC++ 运行库」，
            # 已经由 needs_ucrt 那条提示覆盖；再说成「用不上的插件」反而误导。
            importer_is_redist = name.lower() in LEGACY_REDIST or name.lower().startswith(
                REDIST_PREFIXES
            )
            try:
                deps = hard_imports(full)
            except OSError:
                continue
            for dep in deps:
                if dep in WIN7_BLOCKERS:
                    if on_path:
                        audit.blockers.setdefault(dep, set()).add(rel)
                    elif not importer_is_redist:
                        audit.advisory.setdefault(dep, set()).add(rel)
                elif dep.startswith(REDIST_PREFIXES):
                    audit.needs_ucrt = True
                elif dep in wanted:
                    # 有人在用、产物里又没带 → Win7 上解析不到
                    audit.redist_missing.add(dep)

    return audit


def format_legacy_audit(audit: LegacyAudit, limit: int = 4) -> List[str]:
    """把兼容性审计结果格式化成便于阅读的多行文本。"""
    lines: List[str] = []
    for dep in sorted(audit.blockers):
        callers = sorted(audit.blockers[dep])
        head = ", ".join(callers[:limit])
        tail = "" if len(callers) <= limit else f"  等 {len(callers)} 处"
        lines.append(f"[win7-阻断] {dep}（{WIN7_BLOCKERS[dep]}）← {head}{tail}")
    for dep in sorted(audit.redist_missing):
        lines.append(f"[win7-运行库] {dep} 产物内未携带，Win7 需预装 VC++ 2015-2022 运行库")
    if audit.redist_bundled:
        lines.append("  · 已随包携带：" + ", ".join(sorted(audit.redist_bundled)))
    if audit.needs_ucrt:
        lines.append("  · 依赖通用 C 运行库（api-ms-win-crt-*）：Win7 需先装 KB2999226")
    for dep in sorted(audit.advisory):
        callers = sorted(audit.advisory[dep])
        head = ", ".join(callers[:limit])
        tail = "" if len(callers) <= limit else f"  等 {len(callers)} 处"
        lines.append(
            f"[提示·不阻断] {dep} 被 {head}{tail} 引用；该模块不在应用加载路径上，"
            "只在用到对应功能时才加载"
        )
    return lines


def format_issues(issues: Iterable[DepIssue], limit: int = 4) -> List[str]:
    """把问题列表格式化成便于阅读的多行文本。"""
    order = {"risk": 0, "missing": 1, "weak": 2}
    lines: List[str] = []
    for issue in sorted(issues, key=lambda i: (order.get(i.kind, 9), i.dep)):
        callers = sorted(issue.callers)
        head = ", ".join(callers[:limit])
        tail = "" if len(callers) <= limit else f"  等 {len(callers)} 处"
        note = f"（{issue.note}）" if issue.note else ""
        lines.append(f"[{issue.kind}] {issue.dep}{note} ← {head}{tail}")
    return lines
