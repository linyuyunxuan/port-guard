"""
PortGuard 端口访问防御工具 — 程序入口

用法：
    python main.py                 # 普通权限，仅监控 + 建议
    （以管理员身份运行）            # 启用封禁/解封功能

本环境使用专用虚拟环境：
    C:/Users/Administrator/.workbuddy/binaries/python/envs/portguard/Scripts/python.exe main.py
"""
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


def _check_deps() -> bool:
    missing = []
    for mod, label in (("PySide6", "PySide6"), ("fastapi", "fastapi"),
                       ("uvicorn", "uvicorn"), ("ip2region", "ip2region(py)")):
        try:
            __import__(mod)
        except Exception:
            missing.append(label)
    if missing:
        msg = ("缺少依赖：" + ", ".join(missing) +
               "\n\n请先执行：\npip install -r requirements.txt")
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
    from core.logger import get_logger, setup
    setup()
    log = get_logger("main")

    from core.database import init_db
    init_db()

    from core import settings as cfg
    n = cfg.warm()

    from core.db_writer import start_writer
    start_writer()

    log.info("PortGuard 后端就绪（配置项 %d 条）", n)


def main() -> int:
    if not _check_deps():
        return 2

    try:
        _init_backend()
    except Exception:
        err = traceback.format_exc()
        try:
            import tkinter.messagebox as mb
            mb.showerror("PortGuard 启动失败", f"初始化后端失败：\n\n{err[:2000]}")
        except Exception:
            print(err, file=sys.stderr)
        return 1

    from PySide6.QtCore import Qt
    from PySide6.QtGui import QFont
    from PySide6.QtWidgets import QApplication, QMessageBox

    if hasattr(Qt.ApplicationAttribute, "AA_EnableHighDpiScaling"):
        QApplication.setAttribute(Qt.ApplicationAttribute.AA_EnableHighDpiScaling, True)

    app = QApplication(sys.argv)
    app.setApplicationName("PortGuard")
    app.setApplicationDisplayName("PortGuard 端口访问防御工具")
    app.setQuitOnLastWindowClosed(False)   # 关闭窗口后驻留托盘

    app.setFont(QFont("Microsoft YaHei UI", 9))
    app.setStyle("Fusion")

    # 单实例保护（避免重复占用上报端口）
    try:
        from PySide6.QtCore import QSharedMemory
        global _shm
        _shm = QSharedMemory("PortGuard_SingleInstance_v1")
        if not _shm.create(1):
            QMessageBox.information(None, "PortGuard",
                                    "PortGuard 已经在运行中（请查看系统托盘图标）。")
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
