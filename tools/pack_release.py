"""把 PyInstaller 产物打成发布 zip，并生成 `.sha256` 校验文件。

为什么单独写一个脚本而不是手敲 `zip`：这个包每次上线都要重打，手敲的后果是
「这次多了目录条目、下次压缩级别不一样」，而 zip 内部结构会影响解压后的文件
权限与「解压即用」的观感（空目录条目会让资源管理器里多一堆文件夹）。

约定（历次发布一致，别改）：
  · 包内顶层目录固定为 `PortGuard/`，与 exe 名一致 —— 用户解压得到一个文件夹；
  · **不写目录条目**，只有文件条目；
  · 全部 DEFLATED（compresslevel=9），不存 STORED；
  · 同名 `.sha256` 文件内容是 `<小写哈希>  <文件名>`，与 `sha256sum -c` 兼容。

用法：
    python tools/pack_release.py                       # dist/PortGuard → dist/PortGuard-v1.3.0.zip
    python tools/pack_release.py --src dist/PortGuard --version 1.2.1
"""

import argparse
import hashlib
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    # 直接用 `python tools/pack_release.py` 跑时 sys.path[0] 是 tools/，
    # 不补这一行就 import 不到 core（下面要读 APP_VERSION 当默认版本号）
    sys.path.insert(0, ROOT)

TOP_DIR = "PortGuard"


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


def pack(src: str, version: str) -> int:
    if not os.path.isdir(src):
        print(f"源目录不存在：{src}")
        return 2
    exe = os.path.join(src, TOP_DIR + ".exe")
    if not os.path.isfile(exe):
        print(f"源目录里没有 {TOP_DIR}.exe，可能打错了目录：{src}")
        return 2

    out_zip = os.path.join(ROOT, "dist", f"{TOP_DIR}-v{version}.zip")
    n_files = 0
    raw = 0
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for full, rel in _iter_files(src):
            # 顶层目录名固定为 PortGuard，与 exe 同名；写文件条目不写目录条目
            zf.write(full, arcname=f"{TOP_DIR}/{rel}")
            n_files += 1
            raw += os.path.getsize(full)

    size = os.path.getsize(out_zip)
    digest = _sha256(out_zip)
    sha_path = out_zip + ".sha256"
    with open(sha_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(f"{digest}  {os.path.basename(out_zip)}\n")

    print(f"源目录：{src}")
    print(f"文件数：{n_files}（原始 {raw / 1048576:.2f} MiB）")
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
    args = p.parse_args(argv)
    return pack(args.src, args.version)


if __name__ == "__main__":
    sys.exit(main())
