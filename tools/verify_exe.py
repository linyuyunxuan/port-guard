"""打包产物（onedir exe）运行验证 —— 验证 dist 里那个 exe 真的能跑起来。

为什么需要它：源码跑通不代表打包产物跑通。真实踩过的坑 ——

1. 打包成窗口程序（`console=False`）后 `sys.stdout`/`sys.stderr` 是 `None`，
   uvicorn 的彩色 formatter 会执行 `sys.stdout.isatty()` 并抛 AttributeError，
   被 `dictConfig` 包成「Unable to configure formatter 'default'」，
   接收服务在绑定端口之前就炸了。**这条路径只在窗口化 exe 里出现。**
2. 判定「跑起来了」不能只看进程存活：窗口化程序崩溃时会弹错误框并一直卡住，
   进程同样「活着」。必须看日志里的启动标志位。

两道检查：
- `exe --selfcheck`：在「无控制台」条件下真启停一次接收服务，用退出码断言
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
import subprocess
import sys
import tempfile
import time
import traceback
from typing import Any, Dict, List, Optional, Tuple

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_EXE = os.path.join(PROJECT, "dist", "PortGuard", "PortGuard.exe")
DATA_DIR = os.path.join(os.environ.get("APPDATA", ""), "PortGuard")
LOG_FILE = os.path.join(DATA_DIR, "logs", "portguard.log")

OK_MARK = "后端就绪"
SELFCHECK_MARK = "无控制台启动接收服务 通过"
SELFCHECK_END = "自检结束：通过"
FROZEN_MARK = "运行方式=打包 exe"
BAD_MARKS = (
    "界面启动失败",
    "初始化后端失败",
    "自检结束：失败",
    "Traceback (most recent call last)",
)

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


def _log_offset() -> int:
    return os.path.getsize(LOG_FILE) if os.path.isfile(LOG_FILE) else 0


def _log_since(offset: int) -> str:
    """只读本次运行追加的那一段，避免被上一轮的标志位「假通过」"""
    if not os.path.isfile(LOG_FILE):
        return ""
    with open(LOG_FILE, "rb") as f:
        f.seek(offset)
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


def _run_selfcheck(exe: str, timeout: int = 180) -> Tuple[Optional[int], str]:
    try:
        p = subprocess.run(
            [exe, "--selfcheck"],
            cwd=os.path.dirname(exe),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            check=False,
        )
        return p.returncode, ""
    except subprocess.TimeoutExpired:
        return None, f"--selfcheck 超过 {timeout} 秒未退出"
    except Exception as e:
        return None, f"启动失败：{e}"


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

        # ── 第一道：无控制台自检（唯一能覆盖「窗口化 + std 流为 None」的路径）──
        off1 = _log_offset()
        code, err = _run_selfcheck(exe)
        text1 = _log_since(off1)
        rec.add("03 --selfcheck 退出码为 0", code == 0, f"退出码={code} {err}".strip())

        rec.add(
            "04 自检覆盖了无控制台启动接收服务",
            SELFCHECK_MARK in text1 and SELFCHECK_END in text1,
            next(
                (ln.strip() for ln in text1.splitlines() if SELFCHECK_MARK in ln),
                "未找到自检通过标志",
            ),
        )

        rec.add(
            "05 确认运行的是打包产物（sys.frozen）",
            FROZEN_MARK in text1,
            next(
                (ln.strip() for ln in text1.splitlines() if FROZEN_MARK in ln),
                f"未找到「{FROZEN_MARK}」",
            ),
        )

        hits1 = [m for m in BAD_MARKS if m in text1]
        rec.add("06 自检段无失败/异常痕迹", not hits1, f"命中={hits1}")

        # ── 第二道：正常启动，验证真实 Qt 插件与完整界面链路 ──
        off2 = _log_offset()
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

        text2 = _log_since(off2)
        rec.add(
            "08 后端就绪标志位出现",
            OK_MARK in text2,
            next(
                (ln.strip() for ln in text2.splitlines() if OK_MARK in ln), f"未找到「{OK_MARK}」"
            ),
        )
        hits2 = [m for m in BAD_MARKS if m in text2]
        rec.add("09 界面启动段无失败/异常痕迹", not hits2, f"命中={hits2}")

        after = _snapshot(DATA_DIR)
        new = sorted(set(after) - set(before))
        changed = sorted(k for k in set(after) & set(before) if after[k] != before[k])
        rec.add(
            "10 运行期写出用户数据（新建或更新）",
            bool(new or changed),
            f"新建={new[:8]} 变更={changed[:8]}",
        )

        result["log_tail"] = "\n".join((text1 + text2).splitlines()[-20:])
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
        rec.add("11 收尾无残留进程", image.encode() not in leftover, f"镜像={image}")

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
