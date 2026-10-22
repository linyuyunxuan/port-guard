"""开机自启与启动期崩溃兜底的护栏。

开机自启不是「锦上添花」：封禁时长只记在库里，防火墙规则本身没有到期时间，
只有本程序的 60 秒巡检会去删规则。进程没在跑 = 到期的封禁永远不解除，而且
界面上没有任何痕迹。所以「登录后能不能自动接上」是长期稳定性的必要条件。

这里用替身覆盖注册表读写（绝不碰真实 HKCU\\...\\Run —— 跑测试不该改用户的
登录启动项），只验证编排逻辑：补写、修正旧路径、删多余项、读不出不猜。
"""

import sys
from typing import Optional, Tuple

import pytest

from core import autostart


@pytest.fixture
def registry(monkeypatch):
    """把注册表换成内存里的一个字符串；返回读写用的「假注册表」对象"""

    class FakeRegistry:
        def __init__(self) -> None:
            self.value: Optional[str] = ""  # "" = 没登记；None = 读不出来
            self.writes: list = []
            self.deletes: int = 0

        # —— 与 core.autostart 的三个私有函数同签名 ——
        def read(self) -> Optional[str]:
            return self.value

        def write(self, command: str) -> Tuple[bool, str]:
            self.writes.append(command)
            self.value = command
            return True, ""

        def delete(self) -> Tuple[bool, str]:
            self.deletes += 1
            self.value = ""
            return True, ""

    fake = FakeRegistry()
    monkeypatch.setattr(autostart, "supported", lambda: True)
    monkeypatch.setattr(autostart, "_read_value", fake.read)
    monkeypatch.setattr(autostart, "_write_value", fake.write)
    monkeypatch.setattr(autostart, "_delete_value", fake.delete)
    return fake


def test_command_line_is_quoted() -> None:
    """路径带空格（C:\\Program Files\\...）不加引号会被拆成两个参数"""
    cmd = autostart.command_line()
    assert cmd.startswith('"') and '"' in cmd[1:], cmd
    if not getattr(sys, "frozen", False):
        assert cmd.rstrip().endswith('"')
        assert "main.py" in cmd


def test_sync_writes_when_enabled_but_absent(registry) -> None:
    ok, why = autostart.sync(desired=True)
    assert ok and why == ""
    assert registry.writes == [autostart.command_line()]


def test_sync_rewrites_when_path_changed(registry) -> None:
    """程序换过目录/版本：旧登记会让登录时启动一个不存在的路径"""
    registry.value = '"D:/old/PortGuard.exe"'
    ok, _ = autostart.sync(desired=True)
    assert ok
    assert registry.writes == [autostart.command_line()]


def test_sync_is_idempotent(registry) -> None:
    autostart.sync(desired=True)
    registry.writes.clear()
    autostart.sync(desired=True)
    assert registry.writes == [], "已经正确登记时不该反复写注册表"


def test_sync_removes_when_disabled(registry) -> None:
    autostart.sync(desired=True)
    ok, _ = autostart.sync(desired=False)
    assert ok and registry.deletes == 1 and registry.value == ""


def test_sync_without_value_is_a_noop(registry) -> None:
    ok, _ = autostart.sync(desired=False)
    assert ok and registry.deletes == 0


def test_is_enabled_distinguishes_unknown_from_off(registry) -> None:
    """读不出来必须返回 None：设置页据此写「读不到」，不能画成「已关闭」"""
    assert autostart.is_enabled() is False
    registry.value = None
    assert autostart.is_enabled() is None
    registry.value = '"/x/PortGuard.exe"'
    assert autostart.is_enabled() is True


def test_is_current_target_detects_stale_path(registry) -> None:
    registry.value = '"D:/old/PortGuard.exe"'
    assert autostart.is_current_target() is False
    registry.value = autostart.command_line()
    assert autostart.is_current_target() is True


# ═══════════════════ 启动期兜底：不许再用 tkinter ═══════════════════


def test_main_never_imports_tkinter() -> None:
    """spec 的 excludes 把 tkinter 排除了：窗口化运行时它连错误框都弹不出来

    2026-10-22 的评测里，「初始化失败零痕迹」就是这一条 ——
    `import tkinter.messagebox` 在打包产物里必然失败，然后异常被自己的
    `except` 吞掉，现场表现是「双击没反应，日志也没有堆栈」。
    """
    import os

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "main.py"), encoding="utf-8") as fh:
        source = fh.read()
    assert "import tkinter" not in source
    assert "tkinter.messagebox" not in source
