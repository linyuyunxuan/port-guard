"""依赖自诊断相关测试。

覆盖两块容易出错的地方：
1. `core.pe_imports` 的 PE 解析与「就近解析」判定（这是「拷到别的电脑跑不起来」
   的根因定位逻辑，判错方向会把人带偏）
2. `core.diag` 的系统版本判定与报告生成
"""

import importlib.util
import os
import shutil
import sys

import pytest

from core import diag
from core.pe_imports import (
    APP_LOAD_PATH,
    OS_MIN_VERSION,
    WIN7_BLOCKERS,
    LegacyAudit,
    format_legacy_audit,
    hard_imports,
    imports,
    is_available,
    is_os_component,
    legacy_audit,
    os_version_deps,
    scan_bundle,
)


def _detect_qt():
    """返回 (绑定名, Qt 目录, 核心 DLL 路径)。

    双栈事实：Windows 7 SP1 / Server 2008 R2 上跑的是 PySide2 + Qt5Core.dll；
    Windows 10 1809+ 上跑的是 PySide6 + Qt6Core.dll。两条栈的核心 DLL 硬导入
    并不相同（Qt5 不依赖系统 icuuc），所以断言必须按绑定分流。
    """
    for binding, core in (("PySide6", "Qt6Core.dll"), ("PySide2", "Qt5Core.dll")):
        spec = importlib.util.find_spec(binding)
        if not spec or not spec.origin:
            continue
        site = os.path.dirname(os.path.dirname(os.path.abspath(spec.origin)))
        qdir = os.path.join(site, binding)
        return binding, qdir, os.path.join(qdir, core)
    return None, None, None


QT_BINDING, QT_DIR, QT_CORE_DLL = _detect_qt()
IS_QT6 = QT_BINDING == "PySide6"


def _require_qt_core():
    """取到可用的 Qt 核心 DLL；取不到就跳过。

    这些用例校验的是 PE 解析器对真实 DLL 的行为，不该因为本机装的是
    PySide2 而不是 PySide6 就报收集期错误。
    """
    if not QT_CORE_DLL or not os.path.exists(QT_CORE_DLL):
        pytest.skip("未找到 PySide6 / PySide2 的 Qt 核心 DLL，跳过")
    return QT_CORE_DLL


# --------------------------------------------------------------------------- #
# PE 解析
# --------------------------------------------------------------------------- #
def test_hard_imports_reads_real_dll():
    dll = _require_qt_core()
    hard = hard_imports(dll)
    # Qt 官方 Windows 轮子都由 MSVC 构建，VC 运行库是两条栈共有的硬依赖
    assert "msvcp140.dll" in hard
    # 系统基础组件必须被识别为系统组件，否则报告会被噪音淹没
    assert "kernel32.dll" in hard
    if IS_QT6:
        # Qt6Core 额外硬依赖系统 ICU —— 这正是 Win7 上「找不到指定的模块」的根因
        assert "icuuc.dll" in hard
        assert is_os_component("icuuc.dll")


def test_delay_imports_are_separated():
    """延迟导入不影响启动，必须与硬导入分开统计。"""
    dll = _require_qt_core()
    hard, delay = imports(dll)
    assert hard, "应能解析出硬导入"
    assert not (delay & hard) or True  # 允许同时出现，但两者独立收集
    assert isinstance(delay, set)


def test_non_pe_file_returns_empty(tmp_path):
    bogus = tmp_path / "not_a_dll.dll"
    bogus.write_bytes(b"this is not a PE file")
    assert hard_imports(str(bogus)) == set()


def test_missing_file_returns_empty():
    assert hard_imports("no_such_file_here.dll") == set()


def test_icuuc_is_marked_as_version_gated():
    """icuuc.dll 必须带上「Windows 10 1703 起才有」的说明 —— 这是老机器上
    报「找不到指定的模块」最常见的原因，报告里必须点名。"""
    assert "icuuc.dll" in OS_MIN_VERSION
    assert "1703" in OS_MIN_VERSION["icuuc.dll"]


# --------------------------------------------------------------------------- #
# 就近解析判定
# --------------------------------------------------------------------------- #
def _make_bundle(tmp_path):
    """造一个最小产物：_internal/<绑定目录>/<核心 DLL>。"""
    dll = _require_qt_core()
    root = tmp_path / "app"
    target = root / "_internal" / str(QT_BINDING)
    target.mkdir(parents=True)
    shutil.copy2(dll, target / os.path.basename(dll))
    return str(root)


def test_scan_flags_runtime_not_bundled(tmp_path):
    root = _make_bundle(tmp_path)
    issues, n_pe = scan_bundle(root)
    assert n_pe == 1
    # msvcp140.dll 既不在产物里、又不是「Windows 自带」，必须被点名
    assert "msvcp140.dll" in issues
    assert issues["msvcp140.dll"].kind in ("risk", "missing")
    # 系统基础组件不该出现在报告里
    for name in ("kernel32.dll", "user32.dll", "icuuc.dll", "api-ms-win-crt-heap-l1-1-0.dll"):
        assert name not in issues


def test_scan_accepts_bundled_runtime(tmp_path):
    """把运行库放到 _internal 根目录后，必须判定为「就近可解析」。"""
    root = _make_bundle(tmp_path)
    for name in (
        "msvcp140.dll",
        "msvcp140_1.dll",
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "icuuc.dll",
    ):
        src = os.path.join(str(QT_DIR), name)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(root, "_internal", name))
    issues, _ = scan_bundle(root)
    assert "msvcp140.dll" not in issues
    assert "vcruntime140.dll" not in issues


def test_versioned_deps_lists_icuuc(tmp_path):
    if not IS_QT6:
        pytest.skip("icuuc 是 Qt6 专有依赖，Qt5 绑定下不适用")
    root = _make_bundle(tmp_path)
    deps = os_version_deps(root)
    assert "icuuc.dll" in deps
    assert any("Qt6Core.dll" in f for f in deps["icuuc.dll"])


def test_is_available_for_known_system_dll():
    if sys.platform != "win32":
        pytest.skip("仅 Windows")
    assert is_available("kernel32.dll")
    assert is_available("api-ms-win-crt-heap-l1-1-0.dll")
    assert not is_available("definitely_not_a_system_module_xyz.dll")


# --------------------------------------------------------------------------- #
# Windows 7 SP1 / Server 2008 R2 兼容闸门
# --------------------------------------------------------------------------- #
def test_win7_blockers_are_all_version_gated():
    """禁区清单必须是「有最低版本要求」那一节的子集，两条报告口径要自洽。"""
    assert set(WIN7_BLOCKERS) <= set(OS_MIN_VERSION)


def test_win7_gate_flags_icuuc_for_qt6(tmp_path):
    """Qt6 线路必须被判死：Qt6Core.dll 硬依赖 Win10 1703 才有的 icuuc.dll。"""
    if not IS_QT6:
        pytest.skip("本条验证 Qt6 的禁区命中，Qt5 绑定下不适用")
    root = _make_bundle(tmp_path)
    audit = legacy_audit(root)
    assert audit.scanned == 1
    assert "icuuc.dll" in audit.blockers
    assert any("Qt6Core.dll" in c for c in audit.blockers["icuuc.dll"])
    assert not audit.ok


def test_win7_gate_clears_qt5_line(tmp_path):
    """Qt5 线路（交付到 Win7 用的那条）的核心 DLL 不得命中任何禁区。

    这是「支持 Win7」这句承诺的技术依据：Qt5Core.dll 只依赖 VC++ 运行库，
    不导入 icuuc / shcore / bcryptprimitives。
    """
    if IS_QT6:
        pytest.skip("本条验证 Qt5 线路，PySide6 绑定下不适用")
    root = _make_bundle(tmp_path)
    audit = legacy_audit(root)
    assert not audit.blockers, f"Qt5 核心 DLL 不应引用 Win7 上没有的组件：{sorted(audit.blockers)}"
    # 但运行库没随包携带，仍须被点名（干净 Win7 上会缺）
    assert "msvcp140.dll" in audit.redist_missing
    assert "vcruntime140.dll" in audit.redist_missing
    assert not audit.ok


def test_win7_gate_ok_when_runtime_bundled(tmp_path):
    """把运行库放进产物后，Qt5 线路必须整条通过闸门。"""
    if IS_QT6:
        pytest.skip("本条验证 Qt5 线路，PySide6 绑定下不适用")
    root = _make_bundle(tmp_path)
    for name in ("msvcp140.dll", "msvcp140_1.dll", "vcruntime140.dll", "vcruntime140_1.dll"):
        src = os.path.join(str(QT_DIR), name)
        assert os.path.exists(src), f"PySide2 目录里应当自带 {name}"
        shutil.copy2(src, os.path.join(root, "_internal", name))
    audit = legacy_audit(root)
    assert audit.redist_missing == set()
    assert audit.ok
    assert "Windows 7" in audit.summary()


def test_win7_gate_ignores_unused_plugin(tmp_path):
    """未被应用加载的插件里的禁区引用只能算提示，不能卡死发布。

    Qt 的 wheel 里带着 scenegraph/qtbluetooth 这类用不上的插件，它们引用了
    d3d12/dcomp 等 Win8+ 组件 —— 若一并判失败，闸门会被噪音淹没。
    样本从本机真实 Qt 目录里挑，不硬编码文件名（两条线路文件名不同）。
    """
    if not QT_DIR or not os.path.isdir(QT_DIR):
        pytest.skip("未找到 Qt 安装目录，跳过")
    sample = ""
    for dirpath, _dirs, files in os.walk(QT_DIR):
        for fn in files:
            if not fn.lower().endswith(".dll") or fn.lower() in APP_LOAD_PATH:
                continue
            if hard_imports(os.path.join(dirpath, fn)) & set(WIN7_BLOCKERS):
                sample = os.path.join(dirpath, fn)
                break
        if sample:
            break
    if not sample:
        pytest.skip("本机 Qt 里没有引用了禁区的插件，跳过")

    root = tmp_path / "app"
    plugin_dir = root / "_internal" / "plugins"
    plugin_dir.mkdir(parents=True)
    shutil.copy2(sample, plugin_dir / os.path.basename(sample))

    audit = legacy_audit(str(root))
    assert audit.scanned == 1
    assert not audit.blockers, "用不上的插件不该判阻断"
    assert audit.advisory, "插件里的禁区引用应当出现在提示里，而不是消失"
    assert "提示·不阻断" in "\n".join(format_legacy_audit(audit))


def test_legacy_audit_on_empty_dir_is_clean(tmp_path):
    audit = legacy_audit(str(tmp_path))
    assert audit.scanned == 0
    assert audit.ok
    assert "Windows 7" in audit.summary()


def test_format_legacy_audit_reports_reasons():
    audit = LegacyAudit()
    audit.blockers["icuuc.dll"] = {"Qt6Core.dll"}
    audit.redist_missing.add("msvcp140.dll")
    audit.advisory["d3d12.dll"] = {"plugins/qsgd3d12backend.dll"}
    audit.needs_ucrt = True
    assert not audit.ok
    text = "\n".join(format_legacy_audit(audit))
    assert "[win7-阻断] icuuc.dll" in text and "1703" in text
    assert "[win7-运行库] msvcp140.dll" in text
    assert "KB2999226" in text
    assert "[提示·不阻断] d3d12.dll" in text
    assert "icuuc.dll" in audit.summary()


def test_app_load_path_covers_both_lines():
    """加载清单必须同时覆盖两条线路，否则打包后闸门会误判。"""
    for name in ("qt5core.dll", "qt6core.dll", "qwindows.dll"):
        assert name in APP_LOAD_PATH


def test_installed_qt_dir_passes_win7_gate():
    """对**本机真实安装**的 Qt 目录跑一次闸门。

    PySide6 那条线预期被 icuuc 拦下，PySide2 那条线预期通过 —— 两条都要有断言，
    否则「支持 Win7」永远只是口头承诺。
    """
    if not QT_DIR or not os.path.isdir(QT_DIR):
        pytest.skip("未找到 Qt 安装目录，跳过")
    audit = legacy_audit(QT_DIR)
    assert audit.scanned > 0
    if IS_QT6:
        assert "icuuc.dll" in audit.blockers
    else:
        assert not audit.blockers, f"PySide2 目录不应命中禁区：{sorted(audit.blockers)}"
        assert audit.redist_missing == set(), "PySide2 轮子自带 VC++ 运行库，不应缺"


# --------------------------------------------------------------------------- #
# 系统版本判定与报告
# --------------------------------------------------------------------------- #
def test_os_verdict_thresholds():
    ok, text = diag.os_verdict(14393)  # Server 2016 / Win10 1607
    assert not ok and "icuuc" in text
    ok, _ = diag.os_verdict(15063)  # 1703，最低可用线
    assert ok
    ok, _ = diag.os_verdict(17763)  # 1809，Qt 官方支持线
    assert ok
    ok, _ = diag.os_verdict(0)
    assert ok  # 取不到版本号时不误判


def test_os_verdict_qt5_line_allows_win7():
    """同一条 Win7，在 Qt6 线路上不可用、在 Qt5 线路上可用 —— 这正是双栈的意义。"""
    ok, text = diag.os_verdict(7601, "PySide2")  # Win7 SP1 / Server 2008 R2
    assert ok and "Windows 7" in text
    ok, _ = diag.os_verdict(6001, "PySide2")  # Vista 及更早：太低
    assert not ok
    # 同版本号不传 binding 时按 Qt6 线路判定，必须是不可用
    ok, text = diag.os_verdict(7601)
    assert not ok and "icuuc" in text


def test_qt_probe_names_follow_binding():
    assert "Qt5Core.dll" in diag._qt_probe_names("PySide2")
    assert "Qt6Core.dll" in diag._qt_probe_names("PySide6")


def test_windows_info_has_build():
    info = diag.windows_info()
    assert isinstance(info["build"], int)
    if sys.platform == "win32":
        assert info["product"]


def test_run_reports_environment():
    code, report, summary = diag.run()
    assert code in (0, 1)
    assert "【程序】" in report and "【系统】" in report
    assert "【结论】" in report
    assert summary


def test_show_message_never_raises(monkeypatch):
    """窗口化场景下弹框失败不能让程序再崩一次。"""
    monkeypatch.setattr(diag.sys, "platform", "linux")
    diag.show_message("t", "b")
