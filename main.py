"""
PortGuard 端口访问防御工具 — 程序入口

用法：
    python main.py                 # 普通权限，仅监控 + 建议
    （以管理员身份运行）            # 启用封禁/解封功能

本环境使用专用虚拟环境：
    C:/Users/Administrator/.workbuddy/binaries/python/envs/portguard/Scripts/python.exe main.py
"""

import contextlib
import os
import sys
import traceback

# 保证以 `python main.py` 或打包 exe 方式运行时都能 import 到包内模块
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# 单实例锁对象必须持有到进程结束：QSharedMemory 一旦被 GC 回收，
# 共享内存段就被释放，"另一个实例" 的判断随之失效。
_shm = None

# 被替身流顶掉的 std 流名（窗口化运行时 stdout/stderr 为 None）
_PATCHED_STREAMS: list[str] = []


def _check_deps(interactive: bool = True) -> bool:
    missing = []
    for mod, label in (
        ("PySide6", "PySide6"),
        ("fastapi", "fastapi"),
        ("uvicorn", "uvicorn"),
        ("ip2region", "ip2region(py)"),
    ):
        try:
            __import__(mod)
        except Exception:
            missing.append(label)
    if missing:
        msg = "缺少依赖：" + ", ".join(missing) + "\n\n请先执行：\npip install -r requirements.txt"
        if not interactive:
            # 自动化场景（如 --selfcheck）不弹窗：模态对话框会让流水线直接挂住
            print(msg, file=sys.stderr)
            return False
        try:
            import tkinter.messagebox as mb

            mb.showerror("PortGuard 启动失败", msg)
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


def _selfcheck() -> int:
    """
    交付冒烟自检：在「模拟无控制台」的条件下，把接收服务真正启停一次。

    为什么做成命令行开关（`PortGuard.exe --selfcheck`）：
    打包后的窗口程序（`console=False`）没法自动化点击界面，而「窗口化 + std 流为
    None」恰恰是唯一能让接收服务启动失败的环境 —— uvicorn 的彩色 formatter 会执行
    `sys.stdout.isatty()`，std 流为 None 时抛 AttributeError，被 dictConfig 包成
    「Unable to configure formatter 'default'」。上一版打包验证就是因为只看了
    「后端就绪」而漏掉了这条路径。退出码可直接被脚本/流水线断言。

    结果同时写入日志文件（窗口程序没有 stdout，靠 print 是看不到的）。
    """
    import socket

    from core.logger import get_logger, log_file

    log = get_logger("main")

    saved_out, saved_err = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = None, None
    ok = False
    detail = ""
    port = 0
    try:
        from core.logger import ensure_std_streams

        patched = ensure_std_streams()
        from core import report_server
        from core import settings as cfg

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = int(s.getsockname()[1])
        s.close()

        # 用回环地址 + 现有 Key，避免为跑个自检而改动用户设置
        cfg.set("listen_host", "127.0.0.1", persist=False)
        ok = report_server.start_server(port, cfg.get("api_key", ""))
        detail = report_server.get_start_error_detail() or report_server.get_start_error()
        report_server.stop_server()
        log.info("自检：std 流兜底=%s 无控制台启动接收服务 %s", patched, "通过" if ok else "失败")
    except Exception:
        detail = traceback.format_exc()
    finally:
        sys.stdout, sys.stderr = saved_out, saved_err

    log.info("自检结束：%s（端口 %d）", "通过" if ok else "失败", port)
    if not ok:
        log.error("自检失败原因：\n%s", detail)
    with contextlib.suppress(Exception):
        print(f"PortGuard 自检：{'通过' if ok else '失败'}（细节见 {log_file()}）", flush=True)
    return 0 if ok else 1


def main() -> int:
    # 第一件事：窗口化运行（pythonw / 打包后 console=False）没有控制台，
    # `sys.stdout` 与 `sys.stderr` 都是 None。第三方库会直接调用
    # `sys.stdout.isatty()`（uvicorn 的彩色 formatter 就是），一旦为 None 就抛
    # AttributeError，把整个功能连带拖崩，且报错信息完全指错方向。
    from core.logger import ensure_std_streams

    global _PATCHED_STREAMS
    _PATCHED_STREAMS = ensure_std_streams()

    selfcheck = "--selfcheck" in sys.argv

    if not _check_deps(interactive=not selfcheck):
        return 2

    try:
        _init_backend()
    except Exception:
        err = traceback.format_exc()
        if selfcheck:
            print(err, file=sys.stderr)
            return 1
        try:
            import tkinter.messagebox as mb

            mb.showerror("PortGuard 启动失败", f"初始化后端失败：\n\n{err[:2000]}")
        except Exception:
            print(err, file=sys.stderr)
        return 1

    # 交付冒烟：只验证「无控制台下接收服务能否启动」，不起 Qt 界面
    if selfcheck:
        return _selfcheck()

    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import QApplication, QMessageBox

    if hasattr(Qt.ApplicationAttribute, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)

    app = QApplication(sys.argv)
    app.setApplicationName("PortGuard")
    app.setApplicationDisplayName("PortGuard 端口访问防御工具")
    app.setQuitOnLastWindowClosed(False)  # 关闭窗口后驻留托盘

    app.setFont(QFont("Microsoft YaHei UI", 9))
    app.setStyle("Fusion")

    # 单实例保护（避免重复占用上报端口）
    try:
        from PySide6.QtCore import QSharedMemory

        global _shm
        _shm = QSharedMemory("PortGuard_SingleInstance_v1")
        if not _shm.create(1):
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
        return app.exec()
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
