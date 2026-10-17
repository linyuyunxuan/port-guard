r"""检查打包产物的 DLL 依赖是否「拷到别的电脑也能跑」。

背景
----
窗口程序在开发机上跑得通、拷到别的电脑却报

    DLL load failed while importing QtCore: 找不到指定的模块

的原因几乎只有一个：某个**硬导入**的 DLL 在目标机解析不到。开发机通常装了
Microsoft Visual C++ 运行库甚至 Visual Studio，产物里缺的 DLL 会被
C:\Windows\System32 悄悄兜住，所以本机永远看不出问题。

判定逻辑与运行时的 ``PortGuard.exe --diag`` 完全共用 ``core/pe_imports.py``，
两个入口不会得出不同结论。

用法
----
    python tools/check_dll_deps.py                       # 默认 dist/PortGuard
    python tools/check_dll_deps.py dist_smoke/PortGuardSmoke
    python tools/check_dll_deps.py <某个 Python 环境的 Lib/site-packages>
        # 打包前就能验：直接扫依赖目录，提前发现「这条线路能不能下到 Win7」

退出码：0 = 无 risk 且通过 Win7 兼容闸门；1 = 有 risk，或引用了 Win7 上
不存在的组件 / 缺少需随包携带的运行库。
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, List

from core.pe_imports import (
    OS_MIN_VERSION,
    DepIssue,
    format_issues,
    format_legacy_audit,
    is_available,
    legacy_audit,
    os_version_deps,
    scan_bundle,
)

_HINTS = {
    "risk": (
        "!! RISK —— 产物内没有、只在本机 System32 找到（且不属于 Windows 自带组件）\n"
        "   干净机器上必然缺失 → 就是「找不到指定的模块」的真凶"
    ),
    "missing": "?? MISSING —— 产物内没有，本机 System32 也没有（可能是可选/延迟加载）",
    "weak": (
        "~~ WEAK —— 只在兄弟目录里找到（依赖 PATH/add_dll_directory，脆弱）\n"
        "   本机能跑可能只是运气好；建议平铺到 _internal 根目录"
    ),
}
_ORDER = ("risk", "missing", "weak")


def main(argv: List[str]) -> int:
    args = [a for a in argv[1:] if not a.startswith("-")]
    root = args[0] if args else os.path.join("dist", "PortGuard")
    if not os.path.isdir(root):
        print(f"[x] 找不到产物目录：{root}")
        return 1
    root = os.path.abspath(root)

    issues, n_pe = scan_bundle(root)
    print(f"分析目录：{root}")
    print(f"扫描 PE 文件：{n_pe} 个\n")

    grouped: Dict[str, List[DepIssue]] = {k: [] for k in _ORDER}
    for issue in issues.values():
        grouped.setdefault(issue.kind, []).append(issue)

    for kind in _ORDER:
        items = grouped.get(kind) or []
        if not items:
            continue
        print(_HINTS.get(kind, kind))
        for line in format_issues(items, limit=3):
            print(f"   - {line[len(f'[{kind}] ') :]}")
        print()

    # 系统自带、但有最低版本要求的组件：不算缺陷，却是「老机器上莫名失败」的元凶
    versioned = os_version_deps(root)
    if versioned:
        print("注意 —— 以下依赖由系统提供，但需要在较新的 Windows 上才有：")
        for dep in sorted(versioned):
            mark = "本机可用" if is_available(dep) else "本机也没有"
            callers = ", ".join(sorted(versioned[dep])[:2])
            print(f"   - {dep:<22} {OS_MIN_VERSION.get(dep, '')}；{mark}；被 {callers} 依赖")
        print()

    # Windows 7 SP1 / Server 2008 R2 兼容闸门。
    # 判定口径与上面两节不同：上面问「产物内能不能就近解析」，这一节问
    # 「底线系统到底有没有这个组件」——所以即使上面全绿，这里也可能红。
    audit = legacy_audit(root)
    print("Win7 / Server 2008 R2 兼容性：")
    for line in format_legacy_audit(audit):
        print(f"   - {line}")
    print(f"   {'OK' if audit.ok else 'NG'}：{audit.summary()}")
    print()

    if not (grouped.get("risk") or grouped.get("missing")):
        print("OK：产物内所有非系统硬导入都能就近解析。")
        print("    （若目标机仍失败，请在那台机器上跑 PortGuard.exe --diag 看系统版本）")

    return 1 if (grouped.get("risk") or not audit.ok) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
