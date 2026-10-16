"""真实防火墙链路验证 —— 对系统防火墙实跑一次「封禁 → 解封」，而不是 mock。

为什么需要它：单元测试把 `core.firewall` 的命令拼装全部打桩了，那只能证明
「生成了正确的命令」，证明不了「Windows 真的接受了这条规则」。本脚本用
RFC 5737 文档保留地址 `198.51.100.1`（TEST-NET-2，任何真实网络都不会路由到它）
实跑一遍，跑完立即删除。

安全边界（改动本文件时务必保持）：
- 只操作 `PortGuard_Block_` 前缀的规则，且只删除本脚本自己创建的那一条（按名字）
- **绝不调用 `unblock_all()`**，因此不会触碰用户既有规则；脚本会断言基线规则集未变
- 无论成功失败都在 `finally` 里兜底清理；不落库、不改设置

用法：
    python tools/verify_firewall.py               # 自动请求提权（会弹 UAC）
    python tools/verify_firewall.py --no-elevate  # 已在管理员终端里，直接跑
    python tools/verify_firewall.py --out D:/tmp/r.json

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
from typing import Any, Dict, List, Optional

PROJECT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT not in sys.path:
    sys.path.insert(0, PROJECT)

from core import firewall as fw

# RFC 5737 TEST-NET-2：文档保留地址，恒不可路由
TEST_IP = "198.51.100.1"
# 命令注入载荷：原实现会真的执行后半截，等于在输入框打字即可提权执行命令
INJECTION = '1.2.3.4"; Start-Process calc; #'
# 内网地址：规则引擎硬保护，任何情况下都拒绝封禁
PROTECTED = "192.168.1.10"

# ShellExecuteW 的 ERROR_CANCELLED（注意它 > 32，不能只看「返回码 > 32 即成功」）
ERR_CANCELLED = 1223


# ═══════════════════════════════════════════════════════════
#  结果收集与输出
# ═══════════════════════════════════════════════════════════


class Recorder:
    def __init__(self) -> None:
        self.steps: List[Dict[str, Any]] = []

    def add(self, name: str, ok: bool, detail: object = "") -> None:
        self.steps.append({"step": name, "ok": bool(ok), "detail": str(detail)[:500]})

    def all_ok(self) -> bool:
        return all(bool(s["ok"]) for s in self.steps)


def print_result(result: Dict[str, Any]) -> None:
    print(
        f"=== PortGuard 防火墙链路验证 | 管理员={result.get('admin')} "
        f"| 收尾规则数={result.get('final_rule_count')} ===",
        flush=True,
    )
    for s in result.get("steps", []):
        flag = "PASS" if s["ok"] else "FAIL"
        detail = f"  |  {s['detail']}" if s["detail"] else ""
        print(f"{flag}  {s['step']}{detail}", flush=True)
    print(f"总体：{'通过' if result.get('ok') else '未全部通过'}", flush=True)


def _write_json(path: str, result: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"RESULT_FILE={path}", flush=True)


def _read_json(path: str) -> Optional[Dict[str, Any]]:
    """容忍子进程正在写文件的瞬间（读到半个 JSON 就重试）"""
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


def elevate_and_wait(out_path: str, timeout: int) -> int:
    """
    以管理员身份重启自己，然后轮询结果文件。

    为什么不用「子进程 + wait」：`ShellExecuteW(runas)` 拿不到子进程句柄，
    要等它就得用 `ShellExecuteExW` + `WaitForSingleObject`，那会把父进程无限期
    吊在 UAC 上（实测曾卡住 15 分钟）。改成轮询结果文件后，UAC 没人理也只是
    超时退出，不会挂死流水线。
    """
    if os.path.exists(out_path):
        os.remove(out_path)

    params = subprocess.list2cmdline([os.path.abspath(__file__), "--no-elevate", "--out", out_path])
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, PROJECT, 1)
    except Exception as e:  # pragma: no cover - 依赖真实 Windows
        print(f"[提权异常] {e}；未对防火墙做任何改动。", flush=True)
        return 2

    if ret <= 32 or ret == ERR_CANCELLED:
        print(
            f"[提权被拒绝] ShellExecuteW 返回 {ret}"
            "（1223 = 用户在 UAC 点了取消）。未对防火墙做任何改动。",
            flush=True,
        )
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
#  检查项
# ═══════════════════════════════════════════════════════════


def run_checks() -> Dict[str, Any]:
    rec = Recorder()
    result: Dict[str, Any] = {"admin": fw.is_admin(), "test_ip": TEST_IP, "steps": rec.steps}
    created_name = ""

    try:
        rec.add("00 具备管理员权限", bool(result["admin"]))
        rec.add("01 防火墙命令可用", fw.firewall_available())

        baseline = set(fw.list_rule_names())
        rec.add("02 记录封禁前基线（用户既有规则）", True, f"PortGuard 规则数={len(baseline)}")

        ok, name, err = fw.block_ip(TEST_IP, note="PortGuard 链路验证（临时，验证后自动删除）")
        created_name = name if ok else ""
        rec.add(f"03 封禁 {TEST_IP}", ok, name or err)

        names = set(fw.list_rule_names())
        hit = bool(name) and name in names
        rec.add("04 规则确实写入系统防火墙", hit, f"同名命中={hit}")

        ok2, err2 = fw.unblock_by_name(name)
        if ok2:
            created_name = ""
        rec.add("05 按规则名解封", ok2, err2)

        names2 = set(fw.list_rule_names())
        gone = bool(name) and name not in names2
        rec.add("06 规则已从系统防火墙移除", gone, f"剩余 PortGuard 规则={len(names2)}")

        ok3, n3, e3 = fw.block_ip(INJECTION)
        rec.add("07 命令注入被拒绝（不返回规则名）", (not ok3) and (not n3), e3)

        ok4, n4, e4 = fw.block_ip(PROTECTED)
        rec.add("08 内网地址被硬保护，拒绝封禁", (not ok4) and (not n4), e4)

        names3 = set(fw.list_rule_names())
        rec.add(
            "09 两类拒绝均未在系统里留下规则",
            names3 == names2,
            f"新增={sorted(names3 - names2)} 丢失={sorted(names2 - names3)}",
        )
        rec.add(
            "10 用户既有规则未被触碰",
            baseline <= names3,
            f"基线={len(baseline)} 现在={len(names3)}",
        )
    except Exception:
        result["error"] = traceback.format_exc()
        rec.add("XX 未预期异常", False, result["error"])
    finally:
        if created_name:
            try:
                okc, errc = fw.unblock_by_name(created_name)
                rec.add("ZZ 兜底清理测试规则", okc, created_name if okc else errc)
            except Exception:
                rec.add("ZZ 兜底清理失败", False, traceback.format_exc())
        result["final_rule_count"] = len(fw.list_rule_names())

    result["ok"] = rec.all_ok() and bool(result["admin"])
    return result


# ═══════════════════════════════════════════════════════════
#  入口
# ═══════════════════════════════════════════════════════════


def _parse_args(argv: Optional[List[str]]) -> argparse.Namespace:
    default_out = os.path.join(tempfile.gettempdir(), "portguard-verify", "firewall_result.json")
    p = argparse.ArgumentParser(description="PortGuard 真实防火墙链路验证（会改动本机防火墙）")
    p.add_argument("--out", default=default_out, help=f"结果 JSON 路径（默认 {default_out}）")
    p.add_argument(
        "--no-elevate", action="store_true", help="不自行请求提权（已在管理员终端里时用）"
    )
    p.add_argument(
        "--timeout", type=int, default=300, help="等待提权子进程写结果的秒数（默认 300）"
    )
    return p.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    out_path = os.path.abspath(args.out)

    if not args.no_elevate and not fw.is_admin():
        return elevate_and_wait(out_path, args.timeout)

    if not fw.is_admin():
        print(
            "需要管理员权限才能改动 Windows 防火墙。请改用管理员终端运行，"
            "或去掉 --no-elevate 让脚本自行请求提权。未做任何改动。",
            flush=True,
        )
        return 2

    result = run_checks()
    _write_json(out_path, result)
    print_result(result)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
