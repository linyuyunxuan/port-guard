"""两栈离屏启动冒烟：证明 MainWindow 能在 PySide2 / PySide6 上真正构建出来。

用法（对应栈的解释器执行）：
  envs\\portguard38\\Scripts\\python.exe _design\\boot_smoke.py   # PySide2
  envs\\portguard\\Scripts\\python.exe    _design\\boot_smoke.py   # PySide6
"""

import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.getcwd())

import qtcompat  # noqa: E402
from qtcompat import QApplication, QtGui  # noqa: E402

app = QApplication([])
QtGui.QFontDatabase.addApplicationFont("C:/Windows/Fonts/msyh.ttc")

from gui.main_window import MainWindow  # noqa: E402

win = MainWindow()
win.resize(1360, 860)
win.show()
app.processEvents()

binding = qtcompat.BINDING_DESC
print(
    "OK %s 窗口=%dx%d py=%s"
    % (
        binding,
        win.width(),
        win.height(),
        ".".join(str(v) for v in sys.version_info[:2]),
    )
)
