"""
PortGuard — Python 3.8 兼容性守线

交付栈必须是 Python 3.8 + PySide2，唯一理由是它能装进 Windows 7 SP1 /
Server 2008 R2（Python 3.9 起不再支持 Win7；Qt 6 最低要求 Win10 1809）。
而开发机通常跑 3.13 —— 很容易出现「在开发机上写得很爽、拷到客户机器上
import 就炸」。本文件就是拦这件事的。

为什么不用现成工具：
  · mypy 已不再支持 3.8 目标（最低只能到 3.10），挡不住 PEP 604 联合类型；
  · ruff 的 target-version 只影响「升级建议」，不会因为用了新语法而报错。

所以自己做三层扫描（每一层都对应一类真实会炸的写法）：

  1. 语法层   ast.parse(feature_version=(3, 8)) —— 抓 match / except* / type 语句
  2. 注解层   注解里出现 `X | Y`（PEP 604）或内置泛型下标（list[str]）。
              这两样在 3.8 上是**函数定义时**就抛 TypeError，import 即失败，
              是最隐蔽也最常见的一种（本文件就是为它而生的）。
  3. API 层   deny-list 扫 3.9+ 才有的标准库成员。

新增代码踩坑时，往对应的表里加一条即可。
"""

import ast
import pathlib
from typing import List, Tuple

PROJECT_ROOT = pathlib.Path(__file__).resolve().parent.parent

SKIP_DIRS = {
    "ip2region",  # 上游 vendored 代码（见 NOTICE），不按本项目规范要求
    "build",
    "build_smoke",
    "dist",
    "dist_smoke",
    "envs",  # 本地虚拟环境（第三方依赖），不是项目代码
    ".venv",
    "venv",
    ".git",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "node_modules",
}

# 在 3.8 上「作为注解时不可求值」的内置泛型。3.9 起 list[str] 才合法。
BUILTIN_GENERICS = {"list", "dict", "tuple", "set", "frozenset", "type"}

# 3.9+ 才有的标准库**模块**：在 3.8 上是 ImportError。
TOO_NEW_MODULES = {
    "zoneinfo": "3.9 zoneinfo 模块",
    "graphlib": "3.9 graphlib 模块",
    "tomllib": "3.11 tomllib 模块",
}

# 模块限定成员：`<模块>.<成员>` 形式。用「模块名 + 成员名」配对，
# 避免把同名的局部变量或自定义方法误判（同理，项目里就有名叫 batched 的变量）。
TOO_NEW_QUALIFIED = {
    ("itertools", "pairwise"): "3.10 itertools.pairwise",
    ("itertools", "batched"): "3.12 itertools.batched",
    ("enum", "StrEnum"): "3.11 enum.StrEnum",
    ("asyncio", "TaskGroup"): "3.11 asyncio.TaskGroup",
    ("typing", "TypeAliasType"): "3.12 typing.TypeAliasType",
}

# 内置类型上新增的方法。只按**调用点**判定（`x.removeprefix(...)`），
# 因为不调用就无害，这样也不会误伤同名变量。
TOO_NEW_METHODS = {
    "removeprefix": "3.9 str.removeprefix",
    "removesuffix": "3.9 str.removesuffix",
    "bit_count": "3.10 int.bit_count",
}


def project_files() -> List[pathlib.Path]:
    """项目自身的 Python 文件（不含 vendored 代码与构建产物）。"""
    out = []
    for path in PROJECT_ROOT.rglob("*.py"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        out.append(path)
    return sorted(out)


def rel(path: pathlib.Path) -> str:
    return str(path.relative_to(PROJECT_ROOT)).replace("\\", "/")


def annotations_of(tree: ast.AST) -> List[Tuple[ast.expr, int]]:
    """收集所有「会被解释器求值」的注解节点及其行号。

    只收这三处：函数参数、函数返回值、带注解的赋值。
    变量注解（AnnAssign）在模块/类层级也是当场求值的，所以必须一起算。
    """
    found: List[Tuple[ast.expr, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.arg) and node.annotation is not None:
            found.append((node.annotation, node.annotation.lineno))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None:
            found.append((node.returns, node.returns.lineno))
        elif isinstance(node, ast.AnnAssign) and node.annotation is not None:
            found.append((node.annotation, node.annotation.lineno))
    return found


# ═══════════════════════════════════════════════════════════
#  第 1 层：语法
# ═══════════════════════════════════════════════════════════


def test_syntax_parses_as_python38() -> None:
    files = project_files()
    assert len(files) > 20, f"扫描到的文件太少（{len(files)}），目录判断可能出错"

    bad: List[str] = []
    for path in files:
        src = path.read_text(encoding="utf-8")
        try:
            ast.parse(src, filename=str(path), feature_version=(3, 8))
        except SyntaxError as exc:
            bad.append(f"{rel(path)}:{exc.lineno} {exc.msg}")

    assert not bad, "以下文件用了 Python 3.8 解析不了的语法：\n  " + "\n  ".join(bad)


# ═══════════════════════════════════════════════════════════
#  第 2 层：注解（PEP 604 联合类型 / 内置泛型下标）
# ═══════════════════════════════════════════════════════════


def test_annotations_are_evaluable_on_python38() -> None:
    union_hits: List[str] = []
    generic_hits: List[str] = []

    for path in project_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for ann, lineno in annotations_of(tree):
            for node in ast.walk(ann):
                if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
                    union_hits.append(f"{rel(path)}:{lineno}")
                if (
                    isinstance(node, ast.Subscript)
                    and isinstance(node.value, ast.Name)
                    and node.value.id in BUILTIN_GENERICS
                ):
                    generic_hits.append(f"{rel(path)}:{lineno} -> {node.value.id}[...]")

    problems = []
    if union_hits:
        problems.append(
            "以下注解用了 `X | Y`（PEP 604，Python 3.10 起才支持；"
            "3.8 会在函数定义时抛 TypeError）—— 请改用 Optional[X] / Union[X, Y]：\n  "
            + "\n  ".join(union_hits)
        )
    if generic_hits:
        problems.append(
            "以下注解用了内置泛型下标（3.9 起才支持；"
            "3.8 会在函数定义时抛 TypeError）—— 请改用 typing.List / Dict / Tuple：\n  "
            + "\n  ".join(generic_hits)
        )
    assert not problems, "\n\n".join(problems)


def test_from_future_annotations_is_not_used_as_crutch() -> None:
    """`from __future__ import annotations` 只把求值推迟，不是兼容方案。

    FastAPI / pydantic 这类会调用 typing.get_type_hints() 的库，最终仍要真的
    求值一遍注解 —— 那时 `list[str]` 在 3.8 上照样炸。所以本项目不靠它兜底，
    注解一律写成 3.8 当场可求值的形式（上一条用例守的就是这个）。
    这里只确保它没被当成兼容手段扩散进来。
    """
    offenders: List[str] = []
    for path in project_files():
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src, filename=str(path))
        for node in tree.body:
            if isinstance(node, ast.ImportFrom) and node.module == "__future__":
                names = {a.name for a in node.names}
                if "annotations" in names:
                    offenders.append(rel(path))
    assert not offenders, (
        "以下文件依赖 `from __future__ import annotations` 来规避 3.8 注解限制：\n  "
        + "\n  ".join(offenders)
        + "\n请直接把注解写成 typing.List / Optional 形式，别让 get_type_hints() 时炸掉。"
    )


# ═══════════════════════════════════════════════════════════
#  第 3 层：3.9+ 标准库 API
# ═══════════════════════════════════════════════════════════


def test_no_python39_plus_stdlib_api() -> None:
    hits: List[str] = []

    for path in project_files():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                mod = getattr(node, "module", None) or ""
                head = mod.split(".")[0] if mod else ""
                for alias in node.names:
                    top = (alias.name or head).split(".")[0]
                    if top in TOO_NEW_MODULES:
                        hits.append(
                            f"{rel(path)}:{node.lineno} import {top} —— {TOO_NEW_MODULES[top]}"
                        )

            elif isinstance(node, ast.Attribute):
                # itertools.pairwise / enum.StrEnum 这类模块限定成员
                if isinstance(node.value, ast.Name):
                    key = (node.value.id, node.attr)
                    if key in TOO_NEW_QUALIFIED:
                        hits.append(
                            f"{rel(path)}:{node.lineno} {node.value.id}.{node.attr}"
                            f" —— {TOO_NEW_QUALIFIED[key]}"
                        )

            elif isinstance(node, ast.Call):
                func = node.func
                # x.removeprefix(...) / n.bit_count() 这类内置类型新方法
                if isinstance(func, ast.Attribute) and func.attr in TOO_NEW_METHODS:
                    hits.append(
                        f"{rel(path)}:{node.lineno} .{func.attr}(...) —— {TOO_NEW_METHODS[func.attr]}"
                    )
                # @dataclass(slots=True) 是 3.10 才有的参数
                name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
                if name == "dataclass" and any(kw.arg == "slots" for kw in node.keywords):
                    hits.append(f"{rel(path)}:{node.lineno} dataclass(slots=...) —— 3.10 起支持")

    assert not hits, "以下位置用了 Python 3.8 上没有的标准库 API：\n  " + "\n  ".join(hits)
