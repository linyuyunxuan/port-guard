"""
PortGuard — Qt 绑定兼容层

一套产物要覆盖 Windows 7 SP1 / Server 2008 R2 与 Windows 10 / 11，
而 Qt 6 的最低系统要求是 Windows 10 1809（Qt6Core.dll 硬导入 icuuc.dll，
该文件从 Windows 10 1703 才存在）。因此按运行环境自动选择绑定：

    Windows 10 1809+   →  PySide6（Qt 6）
    Windows 7 SP1+     →  PySide2（Qt 5.15）

两代绑定的差异全部收口在本模块，业务代码只从这里取符号：

1. **模块归属**
   QAction 在 Qt6 属于 QtGui，在 Qt5 还留在 QtWidgets。业务代码无感知。

2. **枚举写法**
   Qt6 的 scoped enum（`Qt.AlignmentFlag.AlignCenter`）在 PySide2 5.15.2 上
   同样可用（项目用到的 23 个表达式已逐个实测通过），**不需要任何适配**。
   业务代码统一使用 scoped 写法即可 —— 既能通过 mypy，也能跑在 Qt5 上。

3. **应用入口**
   QApplication.exec() 在 PySide2 上不存在（只有 exec_()），由 exec_app() 统一。

用法：业务模块一律 `from qtcompat import QTimer, Qt, ...`，
不要直接 import PySide6 / PySide2。
"""

from typing import TYPE_CHECKING, Any, List

QT_API: str = ""
IS_QT6: bool = False

# mypy 只分析 TYPE_CHECKING 分支：全项目统一按 PySide6（Qt6）的类型检查。
# 运行期的 try/except 落在 else 分支，mypy 视为不可达、不会报 PySide2 缺失。
if TYPE_CHECKING:
    from PySide6 import QtCore, QtGui, QtWidgets
else:
    try:
        from PySide6 import QtCore, QtGui, QtWidgets

        QT_API, IS_QT6 = "PySide6", True
    except ImportError:  # pragma: no cover —— 取决于运行环境
        try:
            from PySide2 import QtCore, QtGui, QtWidgets
        except ImportError as exc:  # pragma: no cover
            raise ImportError(
                "未找到可用的 Qt 绑定。Windows 10 1809+ 请装 PySide6，"
                "Windows 7 SP1+ 请装 PySide2：pip install -r requirements.txt"
            ) from exc
        QT_API, IS_QT6 = "PySide2", False

QT_VERSION: str = str(QtCore.qVersion())
QT_RUNTIME: str = str(getattr(QtCore, "__version__", ""))
BINDING_DESC: str = f"{QT_API} / Qt {QT_VERSION}"


def exec_app(app: Any) -> int:
    """QApplication 事件循环入口：Qt6 用 exec()，Qt5 两者都有但以 exec_() 兼容。"""
    run = getattr(app, "exec", None) or app.exec_
    return int(run())


# ═══════════════════════════════════════════════════════════
#  QtCore
# ═══════════════════════════════════════════════════════════

Qt = QtCore.Qt
Signal = QtCore.Signal
Property = QtCore.Property
QTimer = QtCore.QTimer
QSize = QtCore.QSize
QRect = QtCore.QRect
QDate = QtCore.QDate
QPointF = QtCore.QPointF
QModelIndex = QtCore.QModelIndex
QPersistentModelIndex = QtCore.QPersistentModelIndex
QAbstractTableModel = QtCore.QAbstractTableModel
QEasingCurve = QtCore.QEasingCurve
QPropertyAnimation = QtCore.QPropertyAnimation
# 注意：这里刻意不导出 QSharedMemory —— PySide2（Qt5）根本没有导出这个类。
# 单实例保护改用 Windows 命名互斥体实现，见 core/single_instance.py。

# ═══════════════════════════════════════════════════════════
#  QtGui
# ═══════════════════════════════════════════════════════════

QBrush = QtGui.QBrush
QColor = QtGui.QColor
QFont = QtGui.QFont
QFontMetrics = QtGui.QFontMetrics
QIcon = QtGui.QIcon
QPainter = QtGui.QPainter
QPen = QtGui.QPen
QPixmap = QtGui.QPixmap
QPolygonF = QtGui.QPolygonF

# ═══════════════════════════════════════════════════════════
#  QtWidgets
# ═══════════════════════════════════════════════════════════

QAbstractItemView = QtWidgets.QAbstractItemView
QApplication = QtWidgets.QApplication
QCheckBox = QtWidgets.QCheckBox
QComboBox = QtWidgets.QComboBox
QDateEdit = QtWidgets.QDateEdit
QDialog = QtWidgets.QDialog
QDialogButtonBox = QtWidgets.QDialogButtonBox
QDoubleSpinBox = QtWidgets.QDoubleSpinBox
QFileDialog = QtWidgets.QFileDialog
QFormLayout = QtWidgets.QFormLayout
QFrame = QtWidgets.QFrame
QGridLayout = QtWidgets.QGridLayout
QGroupBox = QtWidgets.QGroupBox
QHBoxLayout = QtWidgets.QHBoxLayout
QHeaderView = QtWidgets.QHeaderView
QLabel = QtWidgets.QLabel
QLayout = QtWidgets.QLayout
QLineEdit = QtWidgets.QLineEdit
QMainWindow = QtWidgets.QMainWindow
QMenu = QtWidgets.QMenu
QMessageBox = QtWidgets.QMessageBox
QPlainTextEdit = QtWidgets.QPlainTextEdit
QProgressBar = QtWidgets.QProgressBar
QPushButton = QtWidgets.QPushButton
QScrollArea = QtWidgets.QScrollArea
QSizePolicy = QtWidgets.QSizePolicy
QSpinBox = QtWidgets.QSpinBox
QSplitter = QtWidgets.QSplitter
QStackedWidget = QtWidgets.QStackedWidget
QStatusBar = QtWidgets.QStatusBar
QStyle = QtWidgets.QStyle
QStyledItemDelegate = QtWidgets.QStyledItemDelegate
QStyleOptionViewItem = QtWidgets.QStyleOptionViewItem
QSystemTrayIcon = QtWidgets.QSystemTrayIcon
QTabWidget = QtWidgets.QTabWidget
QTableView = QtWidgets.QTableView
QTableWidget = QtWidgets.QTableWidget
QTableWidgetItem = QtWidgets.QTableWidgetItem
QTextEdit = QtWidgets.QTextEdit
QToolButton = QtWidgets.QToolButton
QVBoxLayout = QtWidgets.QVBoxLayout
QWidget = QtWidgets.QWidget
QKeySequence = QtGui.QKeySequence

# ═══════════════════════════════════════════════════════════
#  模块归属有差异的两个类：Qt6 在 QtGui，Qt5 在 QtWidgets
# ═══════════════════════════════════════════════════════════
# 静态类型由上面的 TYPE_CHECKING 分支给出，运行期按绑定实际归属取值。
if TYPE_CHECKING:
    from PySide6.QtGui import QAction, QShortcut
elif IS_QT6:
    QAction, QShortcut = QtGui.QAction, QtGui.QShortcut
else:  # pragma: no cover —— 仅在 Qt5 绑定下走到
    QAction, QShortcut = QtWidgets.QAction, QtWidgets.QShortcut


# ═══════════════════════════════════════════════════════════
#  Qt5 兼容：补上 exec() 别名
# ═══════════════════════════════════════════════════════════
# Qt6 把这些类的事件循环入口统一叫 exec()；Qt5 **一个 exec() 都没有**，
# 只有 exec_()（QApplication / QDialog / QMenu / QMessageBox / QFileDialog
# 逐个验证过）。这里补一个纯 Python 转发函数，让 dlg.exec() / menu.exec(pos) /
# app.exec() 在 Qt5 上也能用 —— 否则每新写一个对话框都可能在老系统上炸，
# 而且报错位置离真正原因很远。
#   · QMessageBox / QFileDialog / QWizard 都是 QDialog 的子类，注入一次即可
#     通过 MRO 继承；
#   · QMenu 自己定义了事件循环，需要单独注入。
def _forward_exec(self: Any, *args: Any, **kwargs: Any) -> Any:
    """Qt5 专供：把 exec() 转发给 exec_()。"""
    return self.exec_(*args, **kwargs)


def _inject_exec_aliases() -> List[str]:
    patched: List[str] = []
    for cls in (QApplication, QDialog, QMenu):
        if hasattr(cls, "exec"):
            continue
        # 目标必须是 Qt 类型，普通赋值写不出来，只能 setattr
        setattr(cls, "exec", _forward_exec)  # noqa: B010
        patched.append(f"{cls.__name__}.exec")
    return patched


# 注入结果，供 --diag / 自检打印（Qt6 下恒为空）
EXEC_ALIASES: List[str] = [] if IS_QT6 else _inject_exec_aliases()
