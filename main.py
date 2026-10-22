"""
PortGuard 端口访问防御工具 — 程序入口

用法：
    python main.py                 # 普通权限，仅监控 + 建议
    （以管理员身份运行）            # 启用封禁/解封功能
    python main.py --diag          # 环境自诊断：查「为什么这台电脑跑不起来」

本环境使用专用虚拟环境：
    C:/Users/Administrator/.workbuddy/binaries/python/envs/portguard/Scripts/python.exe main.py
"""

import contextlib
import os
import sys
import traceback
from typing import List

# 保证以 `python main.py` 或打包 exe 方式运行时都能 import 到包内模块
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# 被替身流顶掉的 std 流名（窗口化运行时 stdout/stderr 为 None）
_PATCHED_STREAMS: List[str] = []


def _importable(mod: str) -> bool:
    try:
        __import__(mod)
        return True
    except Exception:
        return False


def _local_venvs() -> List[str]:
    """列出本目录下已经存在的 venv 解释器（用于「你用错 Python 了」的提示）。"""
    found = []
    for name in ("portguard38", "portguard"):
        exe = os.path.join(_HERE, "envs", name, "Scripts", "python.exe")
        if os.path.exists(exe):
            found.append(exe)
    return found


def _check_deps(interactive: bool = True) -> bool:
    missing = []
    for mod, label in (("ip2region", "ip2region(py)"),):
        if not _importable(mod):
            missing.append(label)

    # Qt 绑定二选一：PySide6（Windows 10 1809+）/ PySide2（Windows 7 SP1+）。
    # 具体选哪个由 qtcompat 决定，这里只确认至少有一个可用。
    if not any(_importable(m) for m in ("PySide6", "PySide2")):
        missing.append("PySide6 或 PySide2")
    if missing:
        # 这一屏是本项目最常见的「起不来」：机器上装了多个 Python，
        # 随手 `python main.py` 命中的那个没装依赖。只说「缺少依赖」会让人
        # 去 pip install，结果装到另一个解释器里，越修越乱。所以把当前
        # 解释器和本目录里现成的环境一起列出来。
        lines = [
            "缺少依赖：" + "、".join(missing),
            "",
            f"当前解释器：{sys.executable}",
        ]
        local = _local_venvs()
        if local:
            lines += ["", "本目录里已装好的环境（用这里的解释器跑）："]
            lines += [f"  {p}" for p in local]
        lines += [
            "",
            "推荐做法：",
            "  · 双击 start.bat / start_as_admin.bat —— 启动器会自动挑对解释器",
            "  · 或在本目录执行 install.bat 自动创建环境",
        ]
        msg = "\n".join(lines)
        if not interactive:
            # 无人在场的自动化场景不弹窗：模态对话框会让流水线直接挂住
            print(msg, file=sys.stderr)
            return False
        # 用 ctypes 弹原生框：tkinter 在打包时被 excludes 排除，窗口化运行时
        # 一旦走到这里就会「连错误提示都弹不出来」。
        try:
            from core.diag import show_message

            show_message("PortGuard 启动失败", msg, error=True)
        except Exception:
            print(msg, file=sys.stderr)
        return False
    return True


def _init_backend() -> None:
    """
    在任何界面出现之前把后端准备好：
    1. 日志系统（这样后面所有异常都有痕迹，不再静默吞掉）
    2. 数据库 + schema 迁移 + 老库安全收敛
    3. 设置缓存预热
    4. 批量写入器启动（把每条一次事务压成每批一次）
    """
    from core.logger import get_logger, log_file, setup

    setup()
    log = get_logger("main")

    from core.database import init_db

    init_db()

    from core import settings as cfg

    n = cfg.warm()

    from core.db_writer import start_writer

    start_writer()

    log.info("PortGuard 后端就绪（配置项 %d 条）", n)

    # 工作日志：把本次运行的环境记清楚。排障时最耗时的往往不是错误本身，
    # 而是分不清「打包 exe」还是「源码运行」、有没有管理员权限。
    from core.config import APP_VERSION, user_data_dir
    from core.firewall import is_admin

    log.info(
        "PortGuard %s 启动：运行方式=%s 管理员=%s",
        APP_VERSION,
        "打包 exe" if getattr(sys, "frozen", False) else "源码",
        is_admin(),
    )
    log.info("数据目录=%s 日志文件=%s", user_data_dir(), log_file())
    if _PATCHED_STREAMS:
        log.info(
            "当前进程没有控制台（窗口化运行的正常现象），已为 %s 挂上安全空流",
            "/".join(_PATCHED_STREAMS),
        )

    # 开机自启：让注册表与设置项一致（补写缺失 / 修正换过路径的旧登记 / 删掉多余项）。
    # 不做这件事的后果：用户勾了「开机自动启动」、程序却因为换目录没生效，
    # 而重启后没人跑到期巡检 —— 到期封禁会一直生效，且界面上没有任何痕迹。
    with contextlib.suppress(Exception):
        from core import autostart

        ok, why = autostart.sync()
        if not ok:
            log.warning("开机自启同步失败：%s", why)
        else:
            log.info("开机自启：%s", "已登记" if autostart.is_enabled() else "未开启")


def _run_diag() -> int:
    """`--diag`：把「为什么这台电脑跑不起来」查清楚并落盘。

    交付现场反馈最多的现象是把打包目录拷到别的电脑后提示
    「DLL load failed while importing QtCore: 找不到指定的模块」——
    根因是目标机缺少某个系统组件（最常见的两个：没装 VC++ 运行库、
    系统版本过低没有 icuuc.dll）。窗口程序没有控制台，光靠报错框看不出是哪一种，
    所以这里跑一遍依赖诊断，弹窗给结论、同时把完整报告写进日志目录。
    """
    from core import diag

    # 加 --quiet 可跳过弹窗（自动化/流水线里用；窗口程序没有控制台，
    # 弹窗会一直挂着等点击）
    quiet = "--quiet" in sys.argv
    code, report, summary = diag.run()
    path = diag.write_report(report)
    # 窗口程序没有可用的 stdout，打印失败是正常现象，不能因此中断诊断
    with contextlib.suppress(Exception):
        print(report, flush=True)
    if not quiet:
        tail = f"\n\n完整报告：\n{path}" if path else ""
        diag.show_message(
            "PortGuard 环境自诊断",
            f"{summary}{tail}",
            error=code != 0,
        )
    return code


def _qt_import_failed(exc: BaseException, detail: str) -> int:
    """Qt 绑定导入失败时的兜底。

    窗口化打包程序走到这里，默认是 PyInstaller 的英文崩溃框：「Failed to execute
    script 'main' due to unhandled exception」。现场看到这句话只能猜，所以改成
    写日志 + 跑依赖诊断 + 给中文结论。
    """
    summary = str(exc)
    report = ""
    try:
        from core import diag

        _, report, summary = diag.run()
    except Exception:
        pass

    try:
        from core.logger import get_logger, log_file

        log = get_logger("main")
        log.error("Qt 绑定导入失败，界面无法启动：\n%s", detail)
        if report:
            log.error("依赖自诊断结果：\n%s", report)
        log.info("日志文件：%s", log_file())
    except Exception:
        pass

    path = ""
    try:
        from core import diag

        body = f"Qt 绑定导入失败，界面无法启动。\n\n{detail[:1500]}\n\n{report}"
        path = diag.write_report(body)
        diag.show_message(
            "PortGuard 启动失败",
            "无法加载界面组件（Qt）。\n\n"
            f"诊断结论：{summary}\n\n"
            "常见原因：\n"
            "  1) 目标电脑缺少 Microsoft Visual C++ 运行库\n"
            "  2) 系统版本与 Qt 版本不匹配（Qt6 需 Windows 10 1809 以上；\n"
            "     Windows 7 SP1 / Server 2008 R2 需使用 PySide2 版产物）\n"
            "  3) 拷贝不完整，缺 _internal 目录下的 DLL\n\n"
            + (f"完整报告：\n{path}" if path else "详情见日志"),
            error=True,
        )
    except Exception:
        print(detail, file=sys.stderr)
    return 3


def _enable_firewall_cli() -> int:
    """
    `--enable-firewall`：安全启用 Windows 防火墙并对齐封禁，然后退出。

    为什么要有这个开关：「封禁了却拦不住」最常见的根因是 **Windows 防火墙三个配置
    文件全关** —— 规则写得再对也不参与过滤。界面里有对应按钮，但无桌面场景
    （远程部署、计划任务、装完立刻初始化）点不到按钮，这条命令补的就是它。

    打包版是无控制台程序，控制台看不到输出，所以结果同时写进
    `%TEMP%/pg_enable_fw.log`，方便安装脚本与人工排查。
    """
    import os
    import tempfile

    from app import ban_service
    from core import firewall

    lines: list = []

    def say(text: str = "") -> None:
        lines.append(text)
        print(text)

    say(f"管理员权限: {firewall.is_admin()}")
    say(f"启用前 profile: {firewall.format_profiles(firewall.profiles_state(force=True))}")
    ok, err, detail = firewall.enable_firewall()
    say(f"enable_firewall -> {ok} | {err}")
    if ok:
        created = len(detail.get("created") or [])
        after = firewall.format_profiles(detail.get("profiles_after"))
        say(f"新放行规则 {created} 条；启用后 profile: {after}")
        say(f"封禁对齐: {ban_service.format_reenforce(ban_service.reenforce_all())}")
    say(f"最终 profile: {firewall.format_profiles(firewall.profiles_state(force=True))}")
    log_path = os.path.join(tempfile.gettempdir(), "pg_enable_fw.log")
    try:
        with open(log_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")
        say(f"结果已写入 {log_path}")
    except OSError as e:
        say(f"写日志失败：{e}")
    return 0 if ok else 1


def main() -> int:
    # 第一件事：窗口化运行（pythonw / 打包后 console=False）没有控制台，
    # `sys.stdout` 与 `sys.stderr` 都是 None。第三方库会直接调用
    # 第三方库若调用 `sys.stdout.isatty()`，一旦为 None 就抛
    # AttributeError，把整个功能连带拖崩，且报错信息完全指错方向。
    from core.logger import ensure_std_streams

    global _PATCHED_STREAMS
    _PATCHED_STREAMS = ensure_std_streams()

    # 自诊断必须排在一切依赖检查之前：它要回答的正是「依赖为什么起不来」
    if "--diag" in sys.argv:
        return _run_diag()

    if not _check_deps():
        return 2

    try:
        _init_backend()
    except Exception:
        err = traceback.format_exc()
        # 兜底链刻意不用 tkinter：打包时 tkinter 被 spec 的 excludes 排除了
        # （_smoke.spec / port_guard.spec），窗口化运行又没有 stderr ——
        # 原来的写法会让「初始化失败」表现为「双击没反应，日志里也没有堆栈」。
        # 现在：先落盘完整堆栈，再用 ctypes 弹原生框把文件路径告诉用户。
        path = ""
        try:
            from core import diag

            path = diag.write_crash("PortGuard 初始化后端失败\n\n" + err)
        except Exception:
            pass
        msg = f"初始化后端失败，程序无法启动。\n\n{err[:1500]}"
        if path:
            msg += f"\n\n完整堆栈已写入：\n{path}"
        try:
            from core.diag import show_message

            show_message("PortGuard 启动失败", msg, error=True)
        except Exception:
            print(err, file=sys.stderr)
        return 1

    # 无人值守初始化：安全启用防火墙 + 对齐封禁，然后退出（不起界面）
    if "--enable-firewall" in sys.argv:
        # 单实例互斥必须在**改防火墙之前**拿到。
        # 原来这条分支在 `acquire()` 之前就 return 了，于是 CLI 与界面可以同时
        # 改防火墙与封禁记录 —— 进程内的 `firewall._exec_lock` 挡不住跨进程，
        # 两个 netsh 同时删同一批规则会互相把对方的规则名读成「已不存在」。
        # 短暂等 3 秒是为了覆盖「安装脚本和开机自启几乎同时启动」这种正常竞态；
        # 等不到就明确报错退出，而不是硬着头皮改。
        try:
            from core.single_instance import acquire as _acquire

            if not _acquire(wait_sec=3.0):
                print(
                    "PortGuard 已在运行，本次不执行 --enable-firewall。"
                    "请先从托盘退出程序，或直接用界面里的「启用防火墙」。"
                )
                return 2
        except Exception:
            # 互斥体不可用（非 Windows / 极端权限问题）不该挡住初始化
            pass
        return _enable_firewall_cli()

    # Qt 导入必须单独兜住：这是「拷到别的电脑就跑不起来」的唯一现场。
    # 走到这里说明 Python 与被打包的运行库都正常（否则连这个 try 都进不来），
    # 所以失败几乎必然出在 Qt 的依赖链上。
    try:
        from qtcompat import QApplication, QFont, QMessageBox, Qt, exec_app
    except ImportError as exc:
        return _qt_import_failed(exc, traceback.format_exc())

    # 高分屏缩放：Qt5 需要显式打开，Qt6 默认已开。
    # 注意 Qt6 里这个枚举虽然还在，但已标记 deprecated，设了会打一条
    # DeprecationWarning 到 stderr（控制台启动时可见，纯噪音），所以按栈判断。
    from qtcompat import IS_QT6 as _IS_QT6

    if not _IS_QT6 and hasattr(Qt.ApplicationAttribute, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)

    app = QApplication(sys.argv)
    app.setApplicationName("PortGuard")
    app.setApplicationDisplayName("PortGuard 端口访问防御工具")
    app.setQuitOnLastWindowClosed(False)  # 关闭窗口后驻留托盘

    app.setFont(QFont("Microsoft YaHei UI", 10))
    app.setStyle("Fusion")

    # 单实例保护（避免两个实例同时操作防火墙与数据库）。
    # 用 Windows 命名互斥体而不是 QSharedMemory —— PySide2（Qt5）没有导出
    # QSharedMemory，而一套产物要同时支持 Qt5/Qt6，见 core/single_instance.py。
    try:
        from core.single_instance import acquire

        if not acquire():
            QMessageBox.information(
                None, "PortGuard", "PortGuard 已经在运行中（请查看系统托盘图标）。"
            )
            return 0
    except Exception:
        try:
            from core.logger import get_logger

            get_logger("main").warning("单实例保护不可用（不影响正常使用）", exc_info=True)
        except Exception:
            pass

    try:
        from gui.main_window import MainWindow

        win = MainWindow()
        win.show()
        return exec_app(app)
    except Exception:
        err = traceback.format_exc()
        try:
            from core.logger import get_logger

            get_logger("main").error("界面启动失败：\n%s", err)
        except Exception:
            pass
        try:
            QMessageBox.critical(None, "PortGuard 启动失败", err[:3000])
        except Exception:
            print(err, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
