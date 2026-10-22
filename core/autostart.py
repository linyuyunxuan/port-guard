"""PortGuard — 开机自启（HKCU 的 Run 键）

## 为什么这件小事值得单开一个模块

封禁时长完全靠**进程活着时的 60 秒巡检**来兑现：Windows 防火墙规则本身没有
「到期时间」这个属性。所以进程一旦没了（关机、崩溃、被任务管理器结束），
那些规则会一直生效，而且没有任何东西会去删它们 —— 既拦住了可能早就该放行的
地址，也没人知道。

开机自启至少把「重启后自动接上」这件事补上：登录即启动 → 启动 1.5 秒后补跑
一次到期巡检 + 黑名单补封 → 该解的解开、该封的补上。

## 为什么用 HKCU 而不是计划任务

- HKCU\\...\\Run 不需要管理员权限就能写，也不在磁盘上留调度器残留；
- 计划任务要 `/RL HIGHEST` 才能拿到管理员权限，而那等于每次登录都静默提权，
  比 UAC 确认更危险；本程序是 `requireAdministrator` 清单，登录时本来就会弹
  一次 UAC，Run 键把这次弹窗放在用户刚登录、有意愿点「是」的时刻。

**代价必须写进设置页**：开启后每次登录都会请求管理员权限。所以默认关闭，
由用户自己权衡（7×24 服务器通常希望开）。

模块只碰一个注册表值，读失败一律返回 None（未知），不假装「没开启」——
否则设置页会把「读不到」画成「已关闭」，用户以为关掉了其实还开着。
"""

import os
import sys
from typing import Optional, Tuple

from core.logger import get_logger

log = get_logger(__name__)

#: 注册表位置：当前用户的登录启动项
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
#: 值名（同一台机器上多份 PortGuard 只会保留最后一个，这是刻意的）
VALUE_NAME = "PortGuard"


def supported() -> bool:
    """只有 Windows 有这套机制（其余平台一律当作「不支持」）"""
    return sys.platform == "win32"


def command_line() -> str:
    """登录时要执行的命令行

    · 打包后：直接是可执行文件本身（`sys.executable` 就是 exe）；
    · 源码运行：解释器 + main.py，这样开发机也能验证开关是否真的生效。
    两条分支都带引号：默认安装路径 `C:\\Program Files\\...` 里有空格，
    不加引号会被 Windows 按空格拆成两个参数。
    """
    if getattr(sys, "frozen", False):
        return f'"{os.path.abspath(sys.executable)}"'
    main_py = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "main.py")
    return f'"{os.path.abspath(sys.executable)}" "{main_py}"'


# ── 注册表读写（薄到可以整体替换，便于测试）──


def _read_value() -> Optional[str]:
    """读注册表里登记的命令；键/值不存在返回 ""，读不出来返回 None"""
    if not supported():
        return None
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
            try:
                value, _kind = winreg.QueryValueEx(key, VALUE_NAME)
            except FileNotFoundError:
                return ""
            return str(value or "")
    except OSError:
        log.debug("读取开机自启注册表失败", exc_info=True)
        return None


def _write_value(command: str) -> Tuple[bool, str]:
    if not supported():
        return False, "当前系统不支持开机自启（仅 Windows）"
    try:
        import winreg

        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, VALUE_NAME, 0, winreg.REG_SZ, command)
    except OSError as e:
        return False, f"写入注册表失败：{e}"
    return True, ""


def _delete_value() -> Tuple[bool, str]:
    if not supported():
        return False, "当前系统不支持开机自启（仅 Windows）"
    try:
        import winreg

        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, VALUE_NAME)
    except FileNotFoundError:
        return True, ""  # 本来就没有：目标状态已达成
    except OSError as e:
        return False, f"删除注册表项失败：{e}"
    return True, ""


# ── 对外接口 ──


def registered_command() -> str:
    """当前登记的命令行（"" = 没开启；None = 读不出来）"""
    value = _read_value()
    return "" if value is None else value.strip()


def is_enabled() -> Optional[bool]:
    """是否已开启；None = 读不出来（设置页要显示「未知」而不是「已关闭」）"""
    value = _read_value()
    if value is None:
        return None
    return bool(str(value).strip())


def is_current_target() -> Optional[bool]:
    """登记的命令是否就是**现在这个程序**（换目录/换版本后要为 False）"""
    value = _read_value()
    if value is None:
        return None
    return str(value).strip() == command_line()


def apply(enabled: bool) -> Tuple[bool, str]:
    """开 / 关开机自启，返回 (成功, 失败原因)"""
    if not supported():
        return False, "当前系统不支持开机自启（仅 Windows）"
    if enabled:
        return _write_value(command_line())
    return _delete_value()


def sync(desired: Optional[bool] = None) -> Tuple[bool, str]:
    """让注册表与设置项一致（启动时调用一次）

    · 设置开着但注册表没值 → 补写；
    · 设置开着但登记的是旧路径（程序挪过目录 / 换了版本）→ 覆盖；
    · 设置关着但注册表还有值 → 删掉（用户可能在上次运行后手工清过设置）。
    """
    if not supported():
        return True, ""
    if desired is None:
        from core import settings as cfg

        desired = cfg.get_bool("autostart_enabled", False)

    current = _read_value()
    if current is None:
        return False, "读取开机自启状态失败"
    current = str(current).strip()

    if desired:
        if current == command_line():
            return True, ""
        return _write_value(command_line())
    if current:
        return _delete_value()
    return True, ""
