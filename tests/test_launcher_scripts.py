"""启动器守门：批处理必须 CRLF + 纯 ASCII，而且真的能启动程序。

为什么单独守这一层（两条都是真实事故）：

1. **纯 LF 换行**：cmd.exe 按 CRLF 切行，文件只有 LF 时会把一行拆到两个
   缓冲区块里，于是出现「'08' 不是内部或外部命令」这种鬼报错，末尾还
   会掉进一个裸 Python REPL —— 用户看到的就是「双击 start.bat 没反应」。

2. **文件里有中文**：cmd 解析批处理时对多字节字符的偏移处理是错的，
   中段开始整行错位，半行被当成命令执行。所以 .bat 一律不写中文，
   面向用户的中文文案交给 `launcher_help.txt` 与 Python 层输出。

这两条在任何 Python 单测里都照不出来（Python 读文件不关心 cmd 的解析器），
只能对文件字节做断言 + 真跑一次 `start.bat`。
"""

import os
import subprocess
import sys
from pathlib import Path
from typing import List

import pytest

ROOT = Path(__file__).resolve().parents[1]
BATS: List[Path] = sorted(ROOT.glob("*.bat"))
BAT_NAMES = [p.name for p in BATS]

# start.bat 是唯一带参数直通（main.py %*）的入口，能用来做端到端冒烟
SELFCHECK_TIMEOUT = 180


def _known_interpreter() -> str:
    """找一个本机能用的解释器，用来判断端到端用例该不该跳过。"""
    candidates = [
        ROOT / "envs" / "portguard38" / "Scripts" / "python.exe",
        ROOT / "envs" / "portguard" / "Scripts" / "python.exe",
        Path(os.path.expanduser("~"))
        / ".workbuddy"
        / "binaries"
        / "python"
        / "envs"
        / "portguard38"
        / "Scripts"
        / "python.exe",
        Path(os.path.expanduser("~"))
        / ".workbuddy"
        / "binaries"
        / "python"
        / "envs"
        / "portguard"
        / "Scripts"
        / "python.exe",
    ]
    for path in candidates:
        if path.exists():
            return str(path)
    return ""


def test_launcher_files_present() -> None:
    # 缺一个都说明有人误删了入口
    assert {"start.bat", "start_as_admin.bat", "install.bat"} <= set(BAT_NAMES)
    assert (ROOT / "_find_python.bat").exists()
    assert (ROOT / "launcher_help.txt").exists()


@pytest.mark.parametrize("name", BAT_NAMES)
def test_bat_has_no_bare_lf(name: str) -> None:
    raw = (ROOT / name).read_bytes()
    assert raw.count(b"\n") == raw.count(b"\r\n"), (
        f"{name} 里有裸 LF 换行，cmd 会把一行拆成两段执行；"
        "请把文件存成 CRLF（或让 git 按 .gitattributes 重新检出）"
    )


@pytest.mark.parametrize("name", BAT_NAMES)
def test_bat_is_pure_ascii(name: str) -> None:
    raw = (ROOT / name).read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf"), (
        f"{name} 不能带 UTF-8 BOM，cmd 会把 BOM 当成命令的一部分"
    )
    for lineno, line in enumerate(raw.split(b"\r\n"), start=1):
        bad = [(i, b) for i, b in enumerate(line) if b > 127]
        assert not bad, (
            f"{name}:{lineno} 有非 ASCII 字节（{bad[:3]}）。"
            "cmd 解析多字节字符会错位，中文文案请放到 launcher_help.txt 或 Python 里"
        )


@pytest.mark.parametrize("name", ["start.bat", "start_as_admin.bat"])
def test_launchers_use_shared_finder(name: str) -> None:
    text = (ROOT / name).read_text(encoding="ascii")
    # 解释器探测只应有一份实现，否则两条入口迟早给出不同结论
    assert "_find_python.bat" in text
    assert "main.py" in text


def test_help_text_is_utf8() -> None:
    text = (ROOT / "launcher_help.txt").read_text(encoding="utf-8")
    assert "start.bat" in text
    assert "install.bat" in text


@pytest.mark.skipif(sys.platform != "win32", reason="批处理只在 Windows 上可执行")
def test_start_bat_runs_selfcheck() -> None:
    """真的执行 start.bat：证明「双击能起来」而不是「文件长得像能起来」。"""
    if not _known_interpreter():
        pytest.skip("本机没有可用的 venv，跳过启动器端到端冒烟")

    # 走 .bat 而不是直接调 python：这一层要验的正是 cmd 的解析结果
    proc = subprocess.run(
        ["cmd", "/c", str(ROOT / "start.bat"), "--selfcheck"],
        cwd=str(ROOT),
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=SELFCHECK_TIMEOUT,
    )
    out = proc.stdout.decode("utf-8", "replace")
    assert proc.returncode == 0, f"start.bat --selfcheck 退出码 {proc.returncode}\n{out[-3000:]}"
    # 自检本身要在日志里留「通过」，避免只看退出码
    assert "自检结束：通过" in out or "自检：通过" in out, out[-3000:]
    # 曾经的病灶：解释器探测失败会掉进裸 REPL，输出里会出现 >>> 提示符
    assert ">>>" not in out, f"启动器掉进了交互式 REPL：\n{out[-2000:]}"
