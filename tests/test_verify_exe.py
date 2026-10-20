"""交付验证脚本 `tools/verify_exe.py` 的两处假红缺陷回归测试。

两处缺陷都在「验证逻辑本身」而不是产物：

1. **step 10 把 Qt6 写死**：产物走 Qt5 还是 Qt6 由打包时的绑定决定，
   探测出来的库名随之不同（`Qt5Core.dll` / `Qt6Core.dll`）。写死 Qt6 会让
   Qt5 产物永远红；反过来「两个名字任一命中就算过」又会让这项退化成永远绿。
   正确口径是先从 `--diag` 报告里读出线路，再断言对应那条线。
2. **`_log_since` 不认日志轮转**：日志按天轮转（改名旧文件 + 新建同名文件），
   跨天首跑时旧偏移量大于新文件长度，`seek()` 落到末尾之后 → 读到空串 →
   step 04/05 假失败，而日志里标志位明明写着「通过」。

这里用「伪造一个轮转前后的日志文件」把 offset 逻辑单独钉住，不需要真跑 exe。
"""

import importlib.util
import os

import pytest

_SCRIPT = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools", "verify_exe.py"
)


def _load_verify_exe():
    """按文件路径加载 `tools/verify_exe.py`。

    刻意不写 `from tools import verify_exe`：`tools/` 没有 `__init__.py`，
    mypy 扫全项目时会把同一个文件同时算成 `verify_exe` 和 `tools.verify_exe`
    两个模块，直接报「Source file found twice」把 CI 的类型门禁卡死。
    按路径动态加载就绕开了这个命名冲突。
    """
    spec = importlib.util.spec_from_file_location("_verify_exe_under_test", _SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verify_exe = _load_verify_exe()


def _write(path, text, mode="a"):
    with open(path, mode, encoding="utf-8") as f:
        f.write(text)


def _rotate(path):
    """模拟 TimedRotatingFileHandler.doRollover()：旧文件改名带日期、再新建同名空文件。

    关键是**文件名不变、内容换成新文件** —— 只认字节偏移的实现看不出这件事。
    """
    os.replace(path, path + ".2026-10-19")
    with open(path, "w", encoding="utf-8"):
        pass


@pytest.fixture
def log_file(tmp_path, monkeypatch):
    """把脚本的 LOG_FILE 指到临时文件，避免碰真实 %APPDATA% 日志。"""
    p = tmp_path / "portguard.log"
    p.write_text("", encoding="utf-8")
    monkeypatch.setattr(verify_exe, "LOG_FILE", str(p))
    return p


# --------------------------------------------------------------------------- #
# _log_since：增量读取与轮转
# --------------------------------------------------------------------------- #
def test_log_since_reads_only_appended_part(log_file):
    """没有轮转时只返回新追加的那一段（防止上一轮标志位「假通过」）。"""
    _write(str(log_file), "旧一轮：后端就绪\n")
    mark = verify_exe._log_mark()

    _write(str(log_file), "本轮：自检结束：通过\n")
    text = verify_exe._log_since(mark)
    assert "本轮：自检结束：通过" in text
    # 关键断言：上一轮的内容不能再出现，否则「后端就绪」这类标志位会被旧值蒙混过关
    assert "旧一轮" not in text


def test_log_since_detects_rotation_by_inode(log_file):
    """轮转后新文件比旧偏移短 —— 必须从头读全文，否则标志位被静默丢掉。

    这正是交付时实测到的那次假失败：旧 portguard.log 有几千字节，
    跨天轮转后新文件只有几百字节，seek(旧偏移) 直接落到末尾之后。
    """
    _write(str(log_file), "上一轮很长很长的日志\n" * 200)
    mark = verify_exe._log_mark()
    assert mark.size > 1000

    _rotate(str(log_file))
    _write(str(log_file), "自检：无控制台启动接收服务 通过\n自检结束：通过\n")

    text = verify_exe._log_since(mark)
    assert "自检结束：通过" in text


def test_log_since_detects_rotation_even_when_new_file_is_longer(log_file):
    """轮转后新文件已经长得比旧偏移还长 —— 仍必须读到开头的标志位。

    这条专门钉住「只判变短」的不完整修法：新文件写得快时，等到读取那一刻
    它可能已经超过旧偏移，偏移恰好落在正文中间，前半段被截掉且不报错。
    """
    _write(str(log_file), "上一轮日志\n" * 100)
    old_size = verify_exe._log_mark().size

    _rotate(str(log_file))
    head = "运行方式=打包 exe\n无控制台启动接收服务 通过\n"
    _write(str(log_file), head + "填充\n" * (old_size // 2 + 100))
    assert log_file.stat().st_size > old_size, "用例前提：新文件应比旧偏移更长"

    text = verify_exe._log_since(verify_exe.LogMark(0, old_size))
    assert "运行方式=打包 exe" in text
    assert "无控制台启动接收服务 通过" in text


def test_log_since_missing_file_returns_empty(log_file):
    """日志还没生成时不该抛异常。"""
    os.remove(str(log_file))
    assert verify_exe._log_since(verify_exe.LogMark(0, 0)) == ""


# --------------------------------------------------------------------------- #
# _diag_binding：先读线路，再决定断言哪条线
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("line", "expect"),
    [
        ("  Qt 线路      : PySide2", "PySide2"),
        ("  Qt 线路      : PySide6", "PySide6"),
        ("  Qt 线路：PySide2", "PySide2"),
        ("  Qt 线路      : 未检测到（可能不是 GUI 进程）", "未检测到（可能不是 GUI 进程）"),
        ("  Python       : 3.8.10 (64 位)", ""),
    ],
)
def test_diag_binding(line, expect):
    assert verify_exe._diag_binding(line) == expect


def test_diag_binding_missing_line_is_fail_not_silent():
    """读不到线路时调用方拿到空串 → step 10 判失败，而不是静默放过。"""
    binding = verify_exe._diag_binding("【程序】\n  运行方式     : 打包 exe\n")
    assert binding == ""
    assert verify_exe.QT_LIB_PREFIX.get(binding, "") == ""


@pytest.mark.parametrize(
    ("binding", "prefix"),
    [("PySide2", "Qt5"), ("PySide6", "Qt6")],
)
def test_qt_prefix_follows_binding(binding, prefix):
    """断言名必须跟着线路走：Qt5 产物不该去要求 Qt6Core.dll。"""
    assert verify_exe.QT_LIB_PREFIX[binding] == prefix
