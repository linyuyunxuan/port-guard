"""检查打包产物里到底有没有「这段新代码」。

为什么需要它：`verify_exe.py` 只能证明「exe 起得来」，证明不了「起的是这一版」。
曾经因为忘了重打包，验收全绿而用户拿到的还是旧包 —— 这一层就是防那个。

做法：把 exe 尾部的 CArchive 拆开拿到 `PYZ.pyz` → 用 ZlibArchive 逐模块解出
code object → `marshal.dumps()` 后在字节里搜字面量。字面量必须选**本轮新增**
的界面文案或审计动作名，改不掉的才可靠。

用法：
    python tools/peek_packaged_code.py dist/PortGuard/PortGuard.exe \
        "事件激增，已临时降到最近" "ban.recover" "max_ban_duration_sec"
"""

import marshal
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def _pyi_lib():
    """找到 PyInstaller 安装目录（用本脚本所在环境的那个）"""
    for p in sys.path:
        cand = os.path.join(p, "PyInstaller", "archive", "readers.py")
        if os.path.isfile(cand):
            return os.path.dirname(os.path.dirname(cand))
    raise SystemExit("找不到 PyInstaller（请在打包用的那个 Python 环境里运行本脚本）")


def load_pyz(exe: str, workdir: str):
    """返回 (ZlibArchive 读取器, pyz 落盘路径)"""
    lib = _pyi_lib()
    if lib not in sys.path:
        sys.path.insert(0, lib)
    from PyInstaller.archive.readers import CArchiveReader, ZlibArchiveReader

    car = CArchiveReader(exe)
    blob = car.extract("PYZ.pyz")
    if blob is None:
        raise SystemExit("exe 里没有 PYZ.pyz，可能不是 PyInstaller 产物")
    os.makedirs(workdir, exist_ok=True)
    pyz_path = os.path.join(workdir, "PYZ.pyz")
    with open(pyz_path, "wb") as fh:
        fh.write(blob)
    return ZlibArchiveReader(pyz_path), pyz_path


def module_literals(zarc, name: str) -> bytes:
    """把一个模块的 code object 序列化，用于做字面量搜索"""
    try:
        code = zarc.extract(name)
    except Exception:
        return b""
    if code is None:
        return b""
    return marshal.dumps(code)


def scan(exe: str, needles) -> int:
    workdir = os.path.join(os.environ.get("TEMP", "."), "pg_peek")
    zarc, pyz_path = load_pyz(exe, workdir)
    toc = list(zarc.toc)
    print(f"PYZ 模块数：{len(toc)}")

    # 只扫「本项目」的模块，别把整个标准库 marshal 一遍（几百 MB，慢且没意义）
    targets = [n for n in toc if n.startswith(("gui.", "core.", "app.", "main"))]
    print(f"待扫项目模块：{len(targets)}")

    blobs = {}
    for name in targets:
        b = module_literals(zarc, name)
        if b:
            blobs[name] = b

    rc = 0
    for needle in needles:
        raw = needle.encode("utf-8")
        hits = [n for n, b in blobs.items() if raw in b]
        if hits:
            print(f"  OK  {needle!r} → {', '.join(sorted(hits)[:4])}")
        else:
            print(f"  缺失 {needle!r}")
            rc = 1
    print("PYZ 落盘：", pyz_path)
    return rc


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2:
        print(__doc__)
        return 2
    return scan(argv[0], argv[1:])


if __name__ == "__main__":
    sys.exit(main())
