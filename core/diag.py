"""启动自诊断：回答「为什么这台电脑上跑不起来」。

使用场景
--------
把打包好的目录拷到其它电脑运行，最常见的一类失败是：

    DLL load failed while importing QtCore: 找不到指定的模块

它的根因永远是「某个硬导入的 DLL 在这台机器上解析不到」，但具体是哪一个
从报错里看不出来。本模块做三件事：

1. 打印程序与系统的基本环境（系统版本/内部版本号是最关键的线索）
2. 扫一遍产物内的依赖闭包，指出缺哪个、谁在依赖它
3. 按真实加载方式（``LOAD_WITH_ALTERED_SEARCH_PATH``）实际 LoadLibrary
   一遍 Qt 关键库，拿到准确的 WinError

全过程只依赖标准库，**绝不 import PySide6** —— 出问题时 PySide6 本身就是
装不上的那一个。

用法：
    PortGuard.exe --diag        # 打包版
    python main.py --diag       # 源码版
"""

import contextlib
import ctypes
import os
import sys
import time
from typing import List, Optional, Tuple, TypedDict

from core.pe_imports import (
    format_issues,
    format_legacy_audit,
    is_available,
    legacy_audit,
    os_version_deps,
    scan_bundle,
    system32_dirs,
)


class WindowsInfo(TypedDict):
    """系统版本信息。字段类型明确，避免上游拿到 object 再到处 int()。"""

    product: str
    display: str
    build: int
    ubr: int
    name: str


# Windows 内部版本号 → 市场版本名（判断「系统是否够新」用）
_BUILD_NAMES: List[Tuple[int, str]] = [
    (10240, "Windows 10 1507 (RTM)"),
    (10586, "Windows 10 1511"),
    (14393, "Windows 10 1607 / Server 2016"),
    (15063, "Windows 10 1703"),
    (16299, "Windows 10 1709"),
    (17134, "Windows 10 1803"),
    (17763, "Windows 10 1809 / Server 2019"),
    (18362, "Windows 10 1903"),
    (18363, "Windows 10 1909"),
    (19041, "Windows 10 2004"),
    (19042, "Windows 10 20H2"),
    (19043, "Windows 10 21H1"),
    (19044, "Windows 10 21H2"),
    (19045, "Windows 10 22H2"),
    (20348, "Windows Server 2022"),
    (22000, "Windows 11 21H2"),
    (22621, "Windows 11 22H2"),
    (22631, "Windows 11 23H2"),
    (26100, "Windows 11 24H2 / Server 2025"),
]

# 两条运行时线路的最低系统要求（内部版本号）。
#
# 差别来自 Qt 核心库的硬导入：
#   · PySide6 6.12 的 Qt6Core.dll 硬导入 icuuc.dll，而 icuuc.dll 是
#     Windows 10 1703 才加入的系统组件 → 最低 15063（Qt 官方支持基线 1809）
#   · PySide2 5.15 的 Qt5Core.dll 只依赖 VC++ 运行库，**不导入 icuuc**，
#     所以这条线能一路下到 Windows 7 SP1 / Server 2008 R2（内部版本 7601）
# 数字是实测 PE 导入表得出的，不是查文档抄的。
_QT6_MIN_BUILD = 15063
_QT6_RECOMMENDED_BUILD = 17763
_QT5_MIN_BUILD = 7601
_QT5_RECOMMENDED_BUILD = 9600  # Windows 8.1 / Server 2012 R2

# 兼容旧调用点：不传 binding 时按 Qt6 线路判定
_MIN_BUILD = _QT6_MIN_BUILD
_RECOMMENDED_BUILD = _QT6_RECOMMENDED_BUILD

# 绑定名 → (核心 DLL 前缀, shiboken 目录名)
_QT_LINES = {
    "PySide6": ("Qt6", "shiboken6"),
    "PySide2": ("Qt5", "shiboken2"),
}


def _detect_binding(app_dir: str) -> str:
    """判断当前跑的是哪条 Qt 线路。产物内优先，其次看已安装的绑定。"""
    for binding in ("PySide6", "PySide2"):
        if _find_dir(app_dir, binding):
            return binding
    return ""


def _qt_probe_names(binding: str) -> List[str]:
    """按线路给出要实测加载的 Qt 库清单（前一个成功才说明后一个依赖满足）。"""
    prefix = _QT_LINES.get(binding, _QT_LINES["PySide6"])[0]
    return [
        f"{prefix}Core.dll",
        f"{prefix}Gui.dll",
        f"{prefix}Widgets.dll",
        f"{prefix}Network.dll",
        f"{prefix}Svg.dll",
    ]


def _logs_dir() -> str:
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, "PortGuard", "logs")


def show_message(title: str, text: str, *, error: bool = False) -> None:
    """用 ctypes 弹一个原生消息框。

    刻意不用 tkinter / PySide6：前者打包时被排除，后者正是可能加载失败的那个。
    """
    if sys.platform != "win32":
        print(f"{title}\n{text}", file=sys.stderr)
        return
    try:
        flags = 0x10 if error else 0x40  # MB_ICONERROR / MB_ICONINFORMATION
        ctypes.windll.user32.MessageBoxW(None, text, title, flags | 0x40000)
    except Exception:
        with contextlib.suppress(Exception):
            print(f"{title}\n{text}", file=sys.stderr)


def windows_info() -> WindowsInfo:
    """读取真实系统版本。不用 sys.getwindowsversion()：没有声明 supportedOS
    清单时它会被兼容性垫片伪装成 Windows 8。"""
    product = "" if sys.platform == "win32" else sys.platform
    display = ""
    build = 0
    ubr = 0
    if sys.platform == "win32":
        with contextlib.suppress(Exception):
            import winreg

            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
            ) as key:

                def read(name: str) -> str:
                    with contextlib.suppress(OSError):
                        return str(winreg.QueryValueEx(key, name)[0])
                    return ""

                product = read("ProductName") or "Windows"
                display = read("DisplayVersion") or read("ReleaseId")
                raw_build = read("CurrentBuildNumber") or read("CurrentBuild")
                build = int(raw_build) if raw_build.isdigit() else 0
                raw_ubr = read("UBR")
                ubr = int(raw_ubr) if raw_ubr.isdigit() else 0
        if not build:
            # 没有声明 supportedOS 清单时 sys.getwindowsversion() 会被兼容性垫片
            # 伪装成 Windows 8，只能当兜底
            with contextlib.suppress(Exception):
                v = sys.getwindowsversion()
                product = product or f"Windows {v.major}.{v.minor}"
                build = int(v.build)

    # Win11 的 ProductName 注册表项仍写着 "Windows 10"，按内部版本号纠正
    if build >= 22000 and "Windows 10" in product:
        product = product.replace("Windows 10", "Windows 11")
    label = ""
    for threshold, name in _BUILD_NAMES:
        if build >= threshold:
            label = name
    return WindowsInfo(product=product, display=display, build=build, ubr=ubr, name=label)


def os_verdict(build: int, binding: str = "PySide6") -> Tuple[bool, str]:
    """按线路判定系统版本是否满足要求。默认按 Qt6（PySide6）线路。"""
    if not build:
        return True, "无法确定系统版本，跳过版本判定"
    qt5 = binding == "PySide2"
    minimum = _QT5_MIN_BUILD if qt5 else _QT6_MIN_BUILD
    recommended = _QT5_RECOMMENDED_BUILD if qt5 else _QT6_RECOMMENDED_BUILD

    if build < minimum:
        if qt5:
            return False, (
                f"系统过低（内部版本 {build}）——当前是 PySide2（Qt5）线路，"
                "最低支持 Windows 7 SP1 / Server 2008 R2（内部版本 7601）。"
                "本机无法运行，需升级系统或改用其它电脑。"
            )
        return False, (
            f"系统过低（内部版本 {build}）——PySide6 所用的 Qt6Core.dll 硬依赖 "
            "icuuc.dll，而该组件从 Windows 10 1703（内部版本 15063）起才随系统提供。"
            "本机无法运行，需升级系统，或改用 PySide2（Qt5）线路的产物。"
        )
    if build < recommended:
        if qt5:
            return True, (
                f"可用（内部版本 {build}）——已达到 Windows 7 SP1 底线，"
                "建议 Windows 8.1（9600）及以上，TLS 与高分屏缩放更稳。"
            )
        return True, (
            f"勉强可用（内部版本 {build}），低于 Qt 官方支持的 Windows 10 1809（17763），"
            "可能出现界面异常，建议升级。"
        )
    return True, f"满足要求（内部版本 {build}）"


def _find_file(name: str, *dirs: str) -> str:
    for d in dirs:
        candidate = os.path.join(d, name)
        if os.path.exists(candidate):
            return candidate
    return ""


def probe_load(path: str) -> Tuple[bool, str]:
    """按扩展模块的真实加载方式（LOAD_WITH_ALTERED_SEARCH_PATH）加载 DLL。

    关键点：Python 3.8+ 的 ctypes 默认用 LOAD_LIBRARY_SEARCH_DEFAULT_DIRS，
    **不搜索 DLL 自身所在目录**，会得出比实际更悲观的结论。CPython 加载扩展
    模块用的是 LOAD_WITH_ALTERED_SEARCH_PATH，这里必须对齐。
    """
    try:
        ctypes.WinDLL(path, winmode=0x00000008)  # LOAD_WITH_ALTERED_SEARCH_PATH
        return True, "OK"
    except OSError as exc:
        err = getattr(exc, "winerror", None) or 0
        msg = (getattr(exc, "strerror", None) or str(exc)).strip()
        return False, f"[WinError {err}] {msg}"
    except Exception as exc:  # pragma: no cover - 兼容非 Windows
        return False, str(exc)


def run(app_dir: Optional[str] = None, *, deep: bool = True) -> Tuple[int, str, str]:
    """执行诊断。

    返回 ``(退出码, 完整报告, 结论摘要)``。退出码 0 表示未发现阻塞性问题。
    """
    app_dir = os.path.abspath(app_dir or os.environ.get("_MEIPASS") or _guess_app_dir())
    frozen = bool(getattr(sys, "frozen", False))
    binding = _detect_binding(app_dir)
    is_qt5 = binding == "PySide2"
    lines: List[str] = []
    problems: List[str] = []

    def add(text: str = "") -> None:
        lines.append(text)

    add(f"PortGuard 环境自诊断   {time.strftime('%Y-%m-%d %H:%M:%S')}")
    add("=" * 64)

    # ---- 程序自身 ----
    add("【程序】")
    add(f"  运行方式     : {'打包 exe' if getattr(sys, 'frozen', False) else '源码'}")
    add(
        f"  程序目录     : {os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.getcwd()}"
    )
    add(f"  资源目录     : {app_dir}")
    add(f"  Python       : {sys.version.split()[0]} ({'64' if sys.maxsize > 2**32 else '32'} 位)")
    add(f"  Qt 线路      : {binding or '未检测到（可能不是 GUI 进程）'}")
    try:
        from core.firewall import is_admin

        add(f"  管理员权限   : {is_admin()}")
    except Exception:
        add("  管理员权限   : 未知")
    add()

    # ---- 系统 ----
    win = windows_info()
    add("【系统】")
    add(f"  产品         : {win['product']}")
    add(f"  版本         : {win['display'] or '-'}   内部版本 {win['build']}.{win['ubr']}")
    add(f"  识别为       : {win['name'] or '-'}")
    ok_os, verdict = os_verdict(win["build"], binding or "PySide6")
    add(f"  版本判定     : {'✓' if ok_os else '✗'} {verdict}")
    if not ok_os:
        problems.append("系统版本低于当前线路的最低要求")
    add()

    # ---- 关键运行库 ----
    add("【关键运行库】")
    sysdirs = system32_dirs()
    qt_dir = _find_dir(app_dir, binding) if binding else ""
    shiboken_dir = _find_dir(app_dir, _QT_LINES.get(binding, ("", ""))[1]) if binding else ""
    runtime = [
        ("MSVCP140.dll", [qt_dir, shiboken_dir, app_dir]),
        ("MSVCP140_1.dll", [qt_dir, app_dir]),
        ("MSVCP140_2.dll", [qt_dir, app_dir]),
        ("VCRUNTIME140.dll", [app_dir, qt_dir, shiboken_dir]),
        ("VCRUNTIME140_1.dll", [app_dir, qt_dir, shiboken_dir]),
    ]
    for name, dirs in runtime:
        where = _find_file(name, *[d for d in dirs if d])
        add(f"  {'✓' if where else '✗'} {name:<20} {where or '产物内缺失'}")
        if not where:
            problems.append(f"产物内缺少 {name}")
    # 系统组件部分：icuuc 只对 Qt6 线路是必需的，Qt5 线路引用它反而是回归信号
    for name in ("icuuc.dll", "icuin.dll", "ucrtbase.dll", "msvcp140.dll", "vcruntime140.dll"):
        where = _find_file(name, *sysdirs)
        ok = bool(where) or is_available(name)
        tag = where or ("由系统提供（API set）" if ok else "系统也缺失")
        need = not is_qt5 and name in ("icuuc.dll", "icuin.dll")
        add(f"  {'✓' if ok else ('✗' if need else '·')} {name:<20} {tag}")
        if need and not ok:
            problems.append(f"系统缺少 {name}（Windows 10 1703 以下没有）")
    if is_qt5:
        add("  · PySide2（Qt5）线路不依赖 icuuc.dll —— 这正是它能跑 Win7 的原因")
    add()

    # ---- 依赖闭包 ----
    # 只对打包产物扫描：源码运行时 app_dir 是仓库根目录，扫进去会把 dist/、build/
    # 里的旧产物也算进来，结论失真。
    if not frozen:
        add("【依赖闭包】源码运行，跳过产物依赖扫描（打包后再跑一次才有意义）")
        add()
    else:
        try:
            issues, n_pe = scan_bundle(app_dir)
        except Exception as exc:  # pragma: no cover
            issues, n_pe = {}, 0
            add(f"【依赖闭包】扫描失败：{exc}")
        else:
            add(f"【依赖闭包】扫描 {n_pe} 个 PE 文件")
            if not issues:
                add("  ✓ 所有非系统硬导入都能在产物内就近解析")
            for line in format_issues(issues.values()):
                add(f"  {line}")
            for issue in issues.values():
                if issue.kind in ("risk", "missing"):
                    problems.append(f"依赖解析失败：{issue.dep}")
        add()

        # 系统自带但有最低版本要求的组件：点名，避免在旧机器上莫名其妙
        ver_deps = os_version_deps(app_dir)
        if ver_deps:
            add("【对系统版本有要求的依赖】")
            for dep in sorted(ver_deps):
                files = sorted(ver_deps[dep])
                ok = is_available(dep)
                add(f"  {'✓' if ok else '✗'} {dep:<22} 被 {files[0]} 依赖")
                if not ok:
                    problems.append(f"本机缺少 {dep}")
            add()

        # Windows 7 SP1 / Server 2008 R2 兼容性闸门。
        # 与「依赖闭包」的区别：那一节问「产物内能不能就近解析」，这一节问
        # 「底线系统到底有没有这个组件」——口径不同，结论可能不重叠。
        try:
            audit = legacy_audit(app_dir)
        except Exception as exc:  # pragma: no cover
            add(f"【Win7 兼容性】审计失败：{exc}")
        else:
            add(f"【Win7 兼容性】扫描 {audit.scanned} 个 PE 文件")
            for line in format_legacy_audit(audit):
                add(f"  {line}")
            if audit.ok:
                add(f"  ✓ {audit.summary()}")
            for dep in audit.blockers:
                problems.append(f"引用了 Win7 上不存在的 {dep}")
            for dep in sorted(audit.redist_missing):
                problems.append(f"缺少需随包携带的 {dep}")
            add()

    # ---- 实际加载探测 ----
    if deep and qt_dir:
        add("【实际加载探测】（按扩展模块的真实加载方式）")
        for name in _qt_probe_names(binding):
            path = os.path.join(qt_dir, name)
            if not os.path.exists(path):
                continue
            ok, detail = probe_load(path)
            add(f"  {'✓' if ok else '✗'} {name:<16} {detail}")
            if not ok:
                problems.append(f"{name} 加载失败：{detail}")
        add()

    # ---- 结论 ----
    add("【结论】")
    if problems:
        for item in problems:
            add(f"  ✗ {item}")
        summary = "；".join(problems[:3])
    else:
        add("  ✓ 未发现阻塞性问题")
        summary = "未发现阻塞性问题"
    add()
    add(f"报告目录：{_logs_dir()}")

    report = "\n".join(lines)
    return (1 if problems else 0), report, summary


def write_report(report: str) -> str:
    """把报告落盘到 %APPDATA%/PortGuard/logs/diag-*.txt，返回文件路径。"""
    directory = _logs_dir()
    try:
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, f"diag-{time.strftime('%Y%m%d-%H%M%S')}.txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(report)
        return path
    except OSError:
        return ""


def _guess_app_dir() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(here)


def _find_dir(root: str, name: str) -> str:
    """定位 PySide6 / shiboken6 目录：先看产物内，再看已安装位置。"""
    candidate = os.path.join(root, name)
    if os.path.isdir(candidate):
        return candidate
    with contextlib.suppress(Exception):
        import importlib.util

        spec = importlib.util.find_spec(name)
        if spec and spec.origin:
            return os.path.dirname(os.path.abspath(spec.origin))
    return ""
