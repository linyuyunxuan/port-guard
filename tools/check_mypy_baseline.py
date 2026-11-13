"""
CI mypy 基线门禁：允许既有类型债务，拦截任何新增或扩散。

背景
----
本项目在 mypy 2.4.0 下有 7 个既有 error，集中在 4 个文件（见 BASELINE）。
团队口径是「既有债务不新增即放行」，而非「0 error」。但 `mypy .` 只要有
error 就 exit 1，CI 裸跑必然变红；若用 continue-on-error 或全局
ignore_errors 一刀切豁免，又会漏掉真正的新增 error。

本脚本用「基线多重集」判定同时满足两点：
  * 允许 error 减少（有人还掉既有债务不该让 CI 红）；
  * 拒绝任何新增 error —— 包括落在白名单文件里的新增，以及扩散到
    白名单之外任何文件的 error。

判定单位是 (归一化文件名, 行号, error code) 的多重集：基线里每个指纹
允许出现的次数固定，当前结果里同一指纹超过该次数即「新增」；出现基线
里没有的指纹（新文件 / 新 code / 新行）同样「新增」。这比「总数 <= 7」
严格 —— 后者在「修掉 1 个旧 error 又新增 1 个」时会误放行。

用法
----
    python tools/check_mypy_baseline.py

脚本自行调用 `python -m mypy . -O json --no-incremental`（mypy 2.4.0 的
结构化输出参数是 `-O json` / `--output json`，不是 `--output-format=json`），
解析 JSON Lines，无需管道或外部包装。退出码：
    0  当前 error 是基线多重集的子集（或为空）
    1  检测到越界/新增 error，或 mypy 本身执行失败 / 输出无法解析
"""

import json
import os
import subprocess
import sys
from typing import Any, Dict, FrozenSet, List, Tuple

# 既有基线：mypy 2.4.0 下全量 `mypy . -O json` 的 7 条 error。
# 每条 = (归一化路径, 行号, error code) -> 允许出现次数。
# 维护说明：只有当这些债务被「修掉」时才删条目；若因重构导致行号漂移，
# 改本表并注明原因。绝不放宽次数、绝不把新文件加进白名单来掩盖问题。
Fingerprint = Tuple[str, int, str]

BASELINE: Dict[Fingerprint, int] = {
    ("app/maintenance.py", 466, "union-attr"): 2,
    ("app/maintenance.py", 470, "union-attr"): 1,
    ("tests/test_table_base.py", 116, "arg-type"): 1,
    ("tests/test_alerts.py", 25, "func-returns-value"): 1,
    ("tests/test_process_column.py", 31, "arg-type"): 1,
    ("tests/test_process_column.py", 80, "union-attr"): 1,
}

# 白名单：基线涉及的 4 个文件，仅用于把「越界」与「白名单内新增」分开
# 报错。判定本身以 BASELINE 多重集为准，不靠这个集合做豁免。
WHITELIST_FILES: FrozenSet[str] = frozenset(fp[0] for fp in BASELINE)

BASELINE_TOTAL = sum(BASELINE.values())

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _norm_path(raw: str) -> str:
    """mypy 在 Windows 输出反斜杠路径，统一成正斜杠并去掉 ./ 前缀。"""
    path = raw.replace("\\", "/")
    while path.startswith("./"):
        path = path[2:]
    return path


def _run_mypy() -> Tuple[int, str, str]:
    cmd = [sys.executable, "-m", "mypy", ".", "-O", "json", "--no-incremental"]
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, check=False)
    return proc.returncode, proc.stdout, proc.stderr


def _parse_rows(output: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        obj = json.loads(line)
        if not isinstance(obj, dict):
            raise ValueError(f"mypy 输出了非对象 JSON 行：{line!r}")
        rows.append(obj)
    return rows


def _fingerprint(row: Dict[str, Any]) -> Fingerprint:
    try:
        return (
            _norm_path(str(row["file"])),
            int(row["line"]),
            str(row["code"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError(f"mypy error 行缺少 file/line/code 字段：{row!r}") from exc


def main() -> int:
    rc, out, err = _run_mypy()
    # mypy 退出码：0 无 error、1 有 error、2 用法/内部错误。
    # 2（或任何非 0/1）必须视为失败 —— 绝不能让空输出被当成「0 error」放行。
    if rc not in (0, 1):
        print(f"mypy 执行失败（exit={rc}），无法进行基线判定：", file=sys.stderr)
        print(err.strip(), file=sys.stderr)
        return 1

    try:
        rows = _parse_rows(out)
    except ValueError as exc:
        print(f"无法解析 mypy 输出，基线判定失败：{exc}", file=sys.stderr)
        return 1

    errors = [row for row in rows if row.get("severity") == "error"]

    seen: Dict[Fingerprint, int] = {}
    violations: List[str] = []
    for row in errors:
        fp = _fingerprint(row)
        path, line, code = fp
        message = str(row.get("message", ""))
        count_so_far = seen.get(fp, 0)
        seen[fp] = count_so_far + 1
        allowed = BASELINE.get(fp, 0)
        if path not in WHITELIST_FILES:
            violations.append(
                f"  [越界] {path}:{line}  [{code}] {message}  （基线白名单之外的文件）"
            )
        elif count_so_far >= allowed:
            violations.append(
                f"  [新增] {path}:{line}  [{code}] {message}  （基线仅允许 {allowed} 条，已超出）"
            )

    print(f"mypy 基线判定：当前 {len(errors)} 条 error / 基线允许 {BASELINE_TOTAL} 条")
    print("白名单文件：" + ", ".join(sorted(WHITELIST_FILES)))

    if violations:
        print(f"检测到 {len(violations)} 条越界/新增 error，CI 判定失败：")
        for item in violations:
            print(item)
        print("请修复这些类型问题；确属既有债务行号漂移时，同步更新 BASELINE 并说明原因。")
        return 1

    if len(errors) < BASELINE_TOTAL:
        print("OK：当前 error 少于基线（既有债务被部分偿还），无新增、无扩散，放行。")
    else:
        print("OK：当前 error 与基线一致，无新增、无扩散，放行。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
