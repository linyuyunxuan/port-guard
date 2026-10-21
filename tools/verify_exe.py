"""打包产物（onedir exe）运行验证 —— 验证 dist 里那个 exe 真的能跑起来。

为什么需要它：源码跑通不代表打包产物跑通。真实踩过的坑 ——

判定「跑起来了」不能只看进程存活：窗口化程序崩溃时会弹错误框并一直卡住，
进程同样「活着」。必须看日志里的启动标志位。

两道检查：
- `exe --diag --quiet`：环境诊断必须能在产物里跑通（拷到别的电脑排障就靠它）
- 正常启动一次：验证真实 Qt 插件能加载、完整界面链路不报错

用法：
    python tools/verify_exe.py                    # 默认验 dist/PortGuard/PortGuard.exe
    python tools/verify_exe.py --exe path/to.exe  # 验别的产物（如免提权冒烟版）
    python tools/verify_exe.py --desktop          # 不设离屏，直接在本机桌面跑

退出码：0 = 全部通过；1 = 有检查未通过；2 = 提权被拒绝或失败；3 = 提权后超时未见结果
"""

import argparse
import ctypes
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import traceback
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_EXE = os.path.join(PROJECT, "dist", "PortGuard", "PortGuard.exe")
DATA_DIR = os.path.join(os.environ.get("APPDATA", ""), "PortGuard")
LOG_FILE = os.path.join(DATA_DIR, "logs", "portguard.log")

OK_MARK = "后端就绪"
FROZEN_MARK = "运行方式=打包 exe"
BAD_MARKS = (
    "界面启动失败",
    "初始化后端失败",
    "自检结束：失败",
    "Traceback (most recent call last)",
)

# Qt 绑定名 → 该线路会加载的 Qt 库前缀（决定 step 10 该断言哪几个名字）
QT_LIB_PREFIX = {"PySide6": "Qt6", "PySide2": "Qt5"}

ERR_CANCELLED = 1223
CREATE_NO_WINDOW = 0x08000000


# ═══════════════════════════════════════════════════════════
#  结果收集与输出
# ═══════════════════════════════════════════════════════════


class Recorder:
    def __init__(self) -> None:
        self.steps: List[Dict[str, Any]] = []

    def add(self, name: str, ok: bool, detail: object = "") -> None:
        self.steps.append({"step": name, "ok": bool(ok), "detail": str(detail)[:800]})

    def all_ok(self) -> bool:
        return all(bool(s["ok"]) for s in self.steps)


def print_result(result: Dict[str, Any]) -> None:
    print(f"=== PortGuard 打包产物验证 | exe={result.get('exe')} ===", flush=True)
    for s in result.get("steps", []):
        flag = "PASS" if s["ok"] else "FAIL"
        detail = f"  |  {s['detail']}" if s["detail"] else ""
        print(f"{flag}  {s['step']}{detail}", flush=True)
    print(f"总体：{'通过' if result.get('ok') else '未全部通过'}", flush=True)
    tail = result.get("log_tail", "")
    if tail:
        print("--- 日志尾部 ---", flush=True)
        print(tail, flush=True)


def _write_json(path: str, result: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"RESULT_FILE={path}", flush=True)


def _read_json(path: str) -> Optional[Dict[str, Any]]:
    for _ in range(20):
        try:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else None
        except (OSError, ValueError):
            time.sleep(0.25)
    return None


# ═══════════════════════════════════════════════════════════
#  提权
# ═══════════════════════════════════════════════════════════


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # pragma: no cover - 依赖真实 Windows
        return False


def elevate_and_wait(exe: str, out_path: str, timeout: int) -> int:
    """以管理员身份重启自己（exe 清单要求提权，从非提权进程启动会被系统直接拒绝）。"""
    if os.path.exists(out_path):
        os.remove(out_path)

    params = subprocess.list2cmdline(
        [os.path.abspath(__file__), "--no-elevate", "--exe", exe, "--out", out_path]
    )
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, PROJECT, 1)
    except Exception as e:  # pragma: no cover - 依赖真实 Windows
        print(f"[提权异常] {e}；未启动任何进程。", flush=True)
        return 2

    if ret <= 32 or ret == ERR_CANCELLED:
        print(f"[提权被拒绝] ShellExecuteW 返回 {ret}（1223 = 用户在 UAC 点了取消）。", flush=True)
        return 2

    print("[已提权] 等待管理员进程写入结果……", flush=True)
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(out_path):
            result = _read_json(out_path)
            if result is not None:
                print_result(result)
                print(f"RESULT_FILE={out_path}", flush=True)
                return 0 if result.get("ok") else 1
        time.sleep(1)
    print(f"[超时] {timeout} 秒内未见结果文件：{out_path}", flush=True)
    return 3


# ═══════════════════════════════════════════════════════════
#  辅助
# ═══════════════════════════════════════════════════════════


class LogMark(NamedTuple):
    """「这个日志文件已经读到哪儿」的标记。"""

    inode: int
    size: int


def _log_mark() -> LogMark:
    """记录日志文件当前末尾，供 `_log_since` 只读增量。

    为什么不能只记字节偏移：日志走的是 `TimedRotatingFileHandler`，按天轮转 ——
    做法是**把旧文件改名加日期后缀、再新建一个同名空文件**。文件名全程不变，
    但文件已经不是同一个了。只认偏移量时，跨天后的首次运行会踩一个很隐蔽的坑：
    上一天留下的大偏移量比新文件还长，`seek()` 直接落到文件末尾之后，
    `read()` 返回空串，于是自检段里所有启动标志位都「看不见」——
    表现成 step 04/05 假失败（实际日志里标志位明明写着「通过」）。

    记 inode 就能识破「同名但换了个文件」。Windows 上 `st_ino` 由
    `os.stat` 从 NTFS 文件索引取回，改名不会变、新建必然变。
    """
    try:
        st = os.stat(LOG_FILE)
    except OSError:
        # 文件还不存在：用 (0, 0) 表示，之后一旦出现就会因 inode 不同而全文重读
        return LogMark(0, 0)
    return LogMark(st.st_ino, st.st_size)


def _log_since(mark: LogMark) -> str:
    """只读本次运行追加的那一段，避免被上一轮的标志位「假通过」。

    轮转判定用两条或条件，缺一不可：
    · **inode 变了** —— 文件被换掉了（跨天轮转的标准形态）；
    · **文件比记录的偏移还短** —— 兜住 inode 拿不到 0（个别文件系统 / 旧 Python）
      的情况，至少「明显变短」还能识别。
    只判「变短」是不够的：新文件写得快的时候，等到读取那一刻它可能已经长得比
    旧偏移还长，偏移恰好落在正文中间，前半段（往往正是启动标志位）会被静默截掉。
    """
    try:
        st = os.stat(LOG_FILE)
    except OSError:
        return ""
    rotated = st.st_ino != mark.inode or st.st_size < mark.size
    with open(LOG_FILE, "rb") as f:
        f.seek(0 if rotated else mark.size)
        return f.read().decode("utf-8", "replace")


def _snapshot(root: str) -> Dict[str, Tuple[int, float]]:
    snap: Dict[str, Tuple[int, float]] = {}
    if not os.path.isdir(root):
        return snap
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            try:
                st = os.stat(p)
            except OSError:
                continue
            snap[os.path.relpath(p, root)] = (st.st_size, round(st.st_mtime, 1))
    return snap


def _kill(image: str) -> None:
    subprocess.run(
        ["taskkill", "/F", "/IM", image],
        capture_output=True,
        check=False,
        creationflags=CREATE_NO_WINDOW,
    )


def _run_diag(exe: str, timeout: int = 120) -> Tuple[Optional[int], str]:
    """跑 `--diag --quiet`：验证「拷到别的电脑」时的排障入口在打包产物里可用。

    必须带 `--quiet`：窗口程序没有控制台，不带它会弹出一个模态框一直挂着。
    """
    try:
        p = subprocess.run(
            [exe, "--diag", "--quiet"],
            cwd=os.path.dirname(exe),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        return p.returncode, ""
    except subprocess.TimeoutExpired:
        return None, f"--diag 超过 {timeout} 秒未退出（缺 --quiet？）"
    except Exception as e:
        return None, f"启动失败：{e}"


def _diag_reports() -> set:
    """现有诊断报告文件名集合（用来识别本次新写出的那一份）。"""
    try:
        return {n for n in os.listdir(os.path.join(DATA_DIR, "logs")) if n.startswith("diag-")}
    except OSError:
        return set()


def _read_newest_report(before: set) -> Tuple[str, str]:
    directory = os.path.join(DATA_DIR, "logs")
    fresh = sorted(_diag_reports() - before)
    if not fresh:
        return "", ""
    path = os.path.join(directory, fresh[-1])
    try:
        with open(path, encoding="utf-8") as fh:
            return path, fh.read()
    except OSError:
        return path, ""


def _diag_binding(report: str) -> str:
    """从 `--diag` 报告里读出实际 Qt 线路（PySide6 / PySide2），读不到返回空串。

    为什么必须先读线路再断言：产物走 Qt5 还是 Qt6 由打包时的绑定决定，
    两条线的探测结果分别是 `Qt5Core.dll` / `Qt6Core.dll`。旧实现把两个名字都
    写死成 Qt6，Qt5 产物在这一项上永远红；而如果反过来「Qt5 或 Qt6 命中一个就算
    过」，这一项又会退化成永远绿的装饰性断言 —— 连「产物里根本没有 Qt」都拦不住。
    所以线路必须从报告原文里取，取不到就是无法判定，直接判失败。

    返回值是冒号后面那一段原文（如 `PySide2`、`未检测到（可能不是 GUI 进程）`），
    由调用方用 `QT_LIB_PREFIX` 校验是不是已知线路 —— 这样判失败时能把实际读到的
    内容原样写进结果，排障时不用再去翻报告。
    """
    m = re.search(r"Qt 线路\s*[:：]\s*(.+)", report)
    return m.group(1).strip() if m else ""


# ═══════════════════════════════════════════════════════════
#  检查项
# ═══════════════════════════════════════════════════════════


def run_checks(exe: str, watch: int, desktop: bool) -> Dict[str, Any]:
    rec = Recorder()
    result: Dict[str, Any] = {"exe": exe, "admin": is_admin(), "steps": rec.steps}
    image = os.path.basename(exe)
    proc: Optional[subprocess.Popen] = None

    try:
        rec.add("01 打包产物存在", os.path.isfile(exe), exe)
        if not os.path.isfile(exe):
            result["ok"] = False
            return result

        # 单实例锁：残留进程会让新进程直接弹「已在运行」然后退出
        _kill(image)
        time.sleep(1)

        before = _snapshot(DATA_DIR)
        rec.add("02 记录运行前用户数据快照", True, f"文件数={len(before)} 目录={DATA_DIR}")

        # ── 第一道：环境自诊断（拷到别的电脑排障就靠它，必须能在产物里跑通）──
        reports_before = _diag_reports()
        code_diag, err_diag = _run_diag(exe)
        rec.add("03 --diag 退出码为 0", code_diag == 0, f"退出码={code_diag} {err_diag}".strip())
        dpath, dtext = _read_newest_report(reports_before)
        rec.add("04 --diag 写出了报告文件", bool(dpath), dpath or "未见新的 diag-*.txt")
        rec.add(
            "05 报告含系统版本与依赖闭包",
            "【系统】" in dtext and "【依赖闭包】" in dtext,
            f"{len(dtext)} 字符",
        )
        # 按报告里读出的线路断言对应的两个库：Qt5 产物断言 Qt5Core/Qt5Widgets，
        # Qt6 产物断言 Qt6Core/Qt6Widgets。读不出线路就判失败并说明，
        # 绝不「两个名字任一命中就算过」——那等于永远绿。
        binding = _diag_binding(dtext)
        prefix = QT_LIB_PREFIX.get(binding, "")
        if not prefix:
            rec.add(
                "06 Qt 关键库按真实加载方式探测成功",
                False,
                f"报告里读不到 Qt 线路（原值={binding or '空'}），无法判定该断言哪条线",
            )
        else:
            probes = [f"{prefix}Core.dll", f"{prefix}Widgets.dll"]
            rec.add(
                "06 Qt 关键库按真实加载方式探测成功",
                all(f"✓ {p}" in dtext for p in probes),
                "；".join(
                    next(
                        (ln.strip() for ln in dtext.splitlines() if f"✓ {p}" in ln),
                        f"未探测到 {p}",
                    )
                    for p in probes
                ),
            )

        # ── 第二道：正常启动，验证真实 Qt 插件与完整界面链路 ──
        mark2 = _log_mark()
        env = dict(os.environ)
        if not desktop:
            env["QT_QPA_PLATFORM"] = "offscreen"  # 离屏，不在自动化环境里弹窗
        proc = subprocess.Popen(
            [exe],
            cwd=os.path.dirname(exe),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        elapsed, died_at = 0, None
        for i in range(max(1, watch)):
            time.sleep(1)
            elapsed = i + 1
            if proc.poll() is not None:
                died_at = elapsed
                break
        rec.add(
            f"07 正常启动后存活 {max(1, watch)} 秒",
            died_at is None,
            f"存活 {elapsed} 秒"
            + (f"，第 {died_at} 秒退出，码={proc.returncode}" if died_at else ""),
        )

        text2 = _log_since(mark2)
        rec.add(
            "08 后端就绪标志位出现",
            OK_MARK in text2,
            next(
                (ln.strip() for ln in text2.splitlines() if OK_MARK in ln), f"未找到「{OK_MARK}」"
            ),
        )
        rec.add(
            "09 确认运行的是打包产物（sys.frozen）",
            FROZEN_MARK in text2,
            next(
                (ln.strip() for ln in text2.splitlines() if FROZEN_MARK in ln),
                f"未找到「{FROZEN_MARK}」",
            ),
        )
        hits2 = [m for m in BAD_MARKS if m in text2]
        rec.add("10 界面启动段无失败/异常痕迹", not hits2, f"命中={hits2}")

        after = _snapshot(DATA_DIR)
        new = sorted(set(after) - set(before))
        changed = sorted(k for k in set(after) & set(before) if after[k] != before[k])
        rec.add(
            "11 运行期写出用户数据（新建或更新）",
            bool(new or changed),
            f"新建={new[:8]} 变更={changed[:8]}",
        )

        result["log_tail"] = "\n".join(text2.splitlines()[-20:])
    except Exception:
        result["error"] = traceback.format_exc()
        rec.add("XX 未预期异常", False, result["error"])
    finally:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except Exception:
                subprocess.run(
                    ["taskkill", "/F", "/PID", str(proc.pid)],
                    capture_output=True,
                    check=False,
                    creationflags=CREATE_NO_WINDOW,
                )
        time.sleep(1)
        _kill(image)
        time.sleep(0.5)
        leftover = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {image}", "/NH"],
            capture_output=True,
            check=False,
            creationflags=CREATE_NO_WINDOW,
        ).stdout
        rec.add("12 收尾无残留进程", image.encode() not in leftover, f"镜像={image}")

    result["ok"] = rec.all_ok()
    return result


# ═══════════════════════════════════════════════════════════
#  入口
# ═══════════════════════════════════════════════════════════


def _parse_args(argv: Optional[List[str]]) -> argparse.Namespace:
    default_out = os.path.join(tempfile.gettempdir(), "portguard-verify", "exe_result.json")
    p = argparse.ArgumentParser(description="PortGuard 打包产物运行验证")
    p.add_argument("--exe", default=DEFAULT_EXE, help=f"被测 exe（默认 {DEFAULT_EXE}）")
    p.add_argument("--watch", type=int, default=20, help="正常启动后观察秒数（默认 20）")
    p.add_argument("--desktop", action="store_true", help="在本机桌面运行（默认离屏）")
    p.add_argument("--out", default=default_out, help=f"结果 JSON 路径（默认 {default_out}）")
    p.add_argument("--no-elevate", action="store_true", help="不自行请求提权")
    p.add_argument(
        "--timeout", type=int, default=300, help="等待提权子进程写结果的秒数（默认 300）"
    )
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    exe = os.path.abspath(args.exe)
    out_path = os.path.abspath(args.out)

    if not args.no_elevate and not is_admin():
        return elevate_and_wait(exe, out_path, args.timeout)

    result = run_checks(exe, args.watch, args.desktop)
    _write_json(out_path, result)
    print_result(result)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
