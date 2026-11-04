"""PortGuard — 作者 / 版本信息的三处一致性

同一组信息出现在三个地方，任何一处漂移都会变成「程序里写 1.9.0、
exe 属性里写 1.8.0」这种没法自查的小毛病：

1. `core/config.py`：程序内显示（关于页 / 托盘 / 侧栏 tooltip）；
2. `version_info.txt`：Windows 可执行文件的版本资源（右键 → 属性 → 详细信息）；
3. `README.md`：仓库首页。

这里把 1 ↔ 2 钉成用例（README 是文档，不参与门禁）。
`version_info.txt` 是 PyInstaller 的 VSVersionInfo 表达式，用替身类 eval 出来，
不依赖 PyInstaller 装没装。
"""

import os

from core.config import APP_AUTHOR, APP_CONTACT, APP_NAME, APP_VERSION

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VERSION_FILE = os.path.join(ROOT, "version_info.txt")


class _Stub:
    """替身：只记录构造参数，供下面按字段取值"""

    def __init__(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs


def _load_version_info() -> _Stub:
    with open(VERSION_FILE, encoding="utf-8") as f:
        text = f.read()
    names = (
        "VSVersionInfo",
        "FixedFileInfo",
        "StringFileInfo",
        "StringTable",
        "StringStruct",
        "VarFileInfo",
        "VarStruct",
    )
    return eval(text, dict.fromkeys(names, _Stub))


def _string_table(info: _Stub) -> dict:
    """VSVersionInfo(kids=[StringFileInfo([StringTable(键, [StringStruct...])])]) → {键: 值}"""
    tables = info.kwargs["kids"][0].args[0]
    return {s.args[0]: s.args[1] for s in tables[0].args[1]}


def test_version_info_matches_config():
    info = _load_version_info()
    table = _string_table(info)

    assert table["FileVersion"] == APP_VERSION
    assert table["ProductVersion"] == APP_VERSION
    assert table["ProductName"] == APP_NAME
    assert table["OriginalFilename"] == f"{APP_NAME}.exe"


def test_version_info_carries_author_and_contact():
    table = _string_table(_load_version_info())

    # 公司 / 版权 / 备注三处都指向同一个人：用户在资源管理器里随便点开哪一栏
    # 都能看到作者信息，不必猜「CompanyName 为空是不是没做」
    assert table["CompanyName"] == APP_AUTHOR
    assert APP_AUTHOR in table["LegalCopyright"]
    assert APP_AUTHOR in table["Comments"]
    assert APP_CONTACT in table["Comments"]


def test_version_info_file_version_tuple_matches():
    """filevers / prodvers 是整数元组，必须与 APP_VERSION 逐段一致。

    只写字符串版本的话，资源管理器「文件版本」一栏会对不上 —— PyInstaller
    取的是 FixedFileInfo，不是 StringStruct。
    """
    info = _load_version_info()
    ffi = info.kwargs["ffi"]
    want = tuple(int(x) for x in APP_VERSION.split("."))

    assert ffi.kwargs["filevers"][: len(want)] == want
    assert ffi.kwargs["prodvers"][: len(want)] == want
