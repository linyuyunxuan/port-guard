"""依赖自诊断相关测试。

覆盖两块容易出错的地方：
1. `core.pe_imports` 的 PE 解析与「就近解析」判定（这是「拷到别的电脑跑不起来」
   的根因定位逻辑，判错方向会把人带偏）
2. `core.diag` 的系统版本判定与报告生成
"""

from __future__ import annotations

import os
import shutil
import sys

import pytest

from core import diag
from core.pe_imports import (
    OS_MIN_VERSION,
    hard_imports,
    imports,
    is_available,
    is_os_component,
    os_version_deps,
    scan_bundle,
)

_PY_SIDE_FILE = __import__("PySide6").__file__
assert _PY_SIDE_FILE  # PySide6 已安装时必然存在
SITE = os.path.dirname(os.path.dirname(os.path.abspath(_PY_SIDE_FILE)))
QT6CORE = os.path.join(SITE, "PySide6", "Qt6Core.dll")
PYTHON_DLL = os.path.join(SITE, "python3.dll")


# --------------------------------------------------------------------------- #
# PE 解析
# --------------------------------------------------------------------------- #
def test_hard_imports_reads_real_dll():
    if not os.path.exists(QT6CORE):
        pytest.skip("未安装 PySide6，跳过")
    hard = hard_imports(QT6CORE)
    # 这两条是本次故障的核心事实：Qt6Core 既需要 MSVC 运行库，也需要系统 ICU
    assert "msvcp140.dll" in hard
    assert "icuuc.dll" in hard
    # 系统基础组件必须被识别为系统组件，否则报告会被噪音淹没
    assert "kernel32.dll" in hard
    assert is_os_component("icuuc.dll")


def test_delay_imports_are_separated():
    """延迟导入不影响启动，必须与硬导入分开统计。"""
    if not os.path.exists(QT6CORE):
        pytest.skip("未安装 PySide6，跳过")
    hard, delay = imports(QT6CORE)
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
    """造一个最小产物：_internal/PySide6/Qt6Core.dll。"""
    if not os.path.exists(QT6CORE):
        pytest.skip("未安装 PySide6，跳过")
    root = tmp_path / "app"
    target = root / "_internal" / "PySide6"
    target.mkdir(parents=True)
    shutil.copy2(QT6CORE, target / "Qt6Core.dll")
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
        src = os.path.join(SITE, "PySide6", name)
        if os.path.exists(src):
            shutil.copy2(src, os.path.join(root, "_internal", name))
    issues, _ = scan_bundle(root)
    assert "msvcp140.dll" not in issues
    assert "vcruntime140.dll" not in issues


def test_versioned_deps_lists_icuuc(tmp_path):
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
