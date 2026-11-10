"""把 PyInstaller 产物打成发布 zip，并生成 `.sha256` 校验文件。

为什么单独写一个脚本而不是手敲 `zip`：这个包每次上线都要重打，手敲的后果是
「这次多了目录条目、下次压缩级别不一样」，而 zip 内部结构会影响解压后的文件
权限与「解压即用」的观感（空目录条目会让资源管理器里多一堆文件夹）。

约定（历次发布一致，别改）：
  · 包内顶层目录固定为 `PortGuard/`，与 exe 名一致 —— 用户解压得到一个文件夹；
  · **不写目录条目**，只有文件条目；
  · 全部 DEFLATED（compresslevel=9），不存 STORED；
  · 同名 `.sha256` 文件内容是 `<小写哈希>  <文件名>`，与 `sha256sum -c` 兼容。

交付合规材料（v1.9.4 起，别删）：
  · `delivery/` 下的客户文档与许可全文、仓库根的 `NOTICE`、`VERSION.txt`
    都是**交付包的固定组成**，缺任何一份都直接拒绝出包；
  · `SHA256SUMS.txt` 由脚本按包内实际内容生成，客户可逐文件核对；
  · 中文客户文档在包内写成 UTF-8 BOM，避免旧版记事本按 ANSI 显示乱码；
    许可全文保持上游原字节，便于与官方 wheel 逐字比对。

用法：
    python tools/pack_release.py                       # dist/PortGuard → dist/PortGuard-v1.3.0.zip
    python tools/pack_release.py --src dist/PortGuard --version 1.2.1
"""

import argparse
import hashlib
import os
import sys
import zipfile
from typing import List, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    # 直接用 `python tools/pack_release.py` 跑时 sys.path[0] 是 tools/，
    # 不补这一行就 import 不到 core（下面要读 APP_VERSION 当默认版本号）
    sys.path.insert(0, ROOT)

TOP_DIR = "PortGuard"
DELIVERY_DIR = os.path.join(ROOT, "delivery")
NOTICE_SRC = os.path.join(ROOT, "NOTICE")

# 包内相对路径 → 仓库内源文件；顺序固定，保证两次打包条目顺序一致
DELIVERY_FILES: Tuple[str, ...] = (
    "00_README.txt",
    "01_DEPLOY.txt",
    "02_TERMS.txt",
    "03_INTEGRITY.txt",
    "04_CHANGELOG.txt",
    "licenses/LICENSE-LGPL-3.0.txt",
    "licenses/LICENSE-GPL-3.0.txt",
    "licenses/LICENSE-Apache-2.0.txt",
)

# 这些是给客户看的中文文档，包内需要 UTF-8 BOM
_BOM_DOCS = frozenset(
    {
        "00_README.txt",
        "01_DEPLOY.txt",
        "02_TERMS.txt",
        "03_INTEGRITY.txt",
        "04_CHANGELOG.txt",
        "NOTICE.txt",
        "VERSION.txt",
        "SHA256SUMS.txt",
    }
)


def _iter_files(src: str):
    """按稳定顺序遍历文件（排序是为了两次打包得到一致的条目顺序）"""
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames.sort()
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, src).replace("\\", "/")
            yield full, rel


def _sha256(path: str, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _delivery_bytes(rel: str, src_path: str) -> bytes:
    """客户文档加 BOM；许可全文保持原字节。"""
    with open(src_path, "rb") as fh:
        raw = fh.read()
    if rel not in _BOM_DOCS:
        return raw
    text = raw.decode("utf-8")
    # 仓库里的文档统一 LF，包内也用 LF（记事本现代版本能正常显示）
    return ("\ufeff" + text.replace("\r\n", "\n")).encode("utf-8")


def _collect(version: str) -> List[Tuple[str, bytes]]:
    """收集需要写进包的内存条目；缺任何一份交付材料都直接失败。"""
    items: List[Tuple[str, bytes]] = []
    for rel in DELIVERY_FILES:
        path = os.path.join(DELIVERY_DIR, rel)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"缺少交付材料：{path}")
        items.append((f"{TOP_DIR}/{rel}", _delivery_bytes(rel, path)))
    if not os.path.isfile(NOTICE_SRC):
        raise FileNotFoundError(f"缺少交付材料：{NOTICE_SRC}")
    items.append((f"{TOP_DIR}/NOTICE.txt", _delivery_bytes("NOTICE.txt", NOTICE_SRC)))
    items.append(
        (
            f"{TOP_DIR}/VERSION.txt",
            ("\ufeffPortGuard v" + version + "\n").encode("utf-8"),
        )
    )
    return items


def _sums_text(version: str, entries: List[Tuple[str, str]]) -> bytes:
    lines = [
        f"\ufeff# PortGuard v{version} · 包内文件 SHA256 校验清单",
        "# 校验方法：certutil -hashfile <文件> SHA256，与下面的哈希比对。",
        "# 本清单本身不参与校验；压缩包整体的哈希见同包外的 .sha256 文件。",
    ]
    for arcname, digest in sorted(entries):
        lines.append(f"{digest}  {arcname}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def pack(src: str, version: str, out_dir: str = "") -> int:
    if not os.path.isdir(src):
        print(f"源目录不存在：{src}")
        return 2
    exe = os.path.join(src, TOP_DIR + ".exe")
    if not os.path.isfile(exe):
        print(f"源目录里没有 {TOP_DIR}.exe，可能打错了目录：{src}")
        return 2

    try:
        memory = _collect(version)
    except FileNotFoundError as exc:
        print(f"交付材料不完整，拒绝出包：{exc}")
        return 3

    out_dir = out_dir or os.path.join(ROOT, "dist")
    os.makedirs(out_dir, exist_ok=True)
    out_zip = os.path.join(out_dir, f"{TOP_DIR}-v{version}.zip")

    # 逐文件算哈希，供包内 SHA256SUMS.txt 使用；不把大文件读进内存
    all_entries: List[Tuple[str, str]] = []
    for full, rel in _iter_files(src):
        arcname = f"{TOP_DIR}/{rel}"
        all_entries.append((arcname, _sha256(full)))
    for arcname, data in memory:
        all_entries.append((arcname, hashlib.sha256(data).hexdigest()))
    sums = _sums_text(version, all_entries)

    n_files = 0
    raw = 0
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for full, rel in _iter_files(src):
            # 顶层目录名固定为 PortGuard，与 exe 同名；写文件条目不写目录条目
            zf.write(full, arcname=f"{TOP_DIR}/{rel}")
            n_files += 1
            raw += os.path.getsize(full)
        for arcname, data in memory:
            zf.writestr(arcname, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
            n_files += 1
            raw += len(data)
        zf.writestr(
            f"{TOP_DIR}/SHA256SUMS.txt",
            sums,
            compress_type=zipfile.ZIP_DEFLATED,
            compresslevel=9,
        )
        n_files += 1
        raw += len(sums)

    size = os.path.getsize(out_zip)
    digest = _sha256(out_zip)
    sha_path = out_zip + ".sha256"
    with open(sha_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"{digest}  {os.path.basename(out_zip)}\n")

    print(f"源目录：{src}")
    print(f"文件数：{n_files}（原始 {raw / 1048576:.2f} MiB）")
    print(f"交付材料：{len(memory) + 1} 份（含 SHA256SUMS.txt）")
    print(f"输出  ：{out_zip}")
    print(f"体积  ：{size / 1048576:.2f} MiB（压缩率 {size / raw * 100:.1f}%）")
    print(f"SHA256：{digest}")
    print(f"校验单：{sha_path}")
    return 0


def main(argv=None) -> int:
    from core.config import APP_VERSION

    p = argparse.ArgumentParser(description="打包 PortGuard 发布 zip")
    p.add_argument("--src", default=os.path.join(ROOT, "dist", TOP_DIR))
    p.add_argument("--version", default=APP_VERSION)
    p.add_argument("--out-dir", default="", help="输出目录，默认 dist/（测试可指定临时目录）")
    args = p.parse_args(argv)
    return pack(args.src, args.version, args.out_dir)


if __name__ == "__main__":
    sys.exit(main())
