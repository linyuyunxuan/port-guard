"""PortGuard — 纯 IP 列表导出（一行一个，给别的防火墙 / 黑名单系统）

与 CSV 导出（`tests/test_export_csv.py`）是两件事，分开测：
CSV 要给人看（BOM、中文、表头），IP 列表要给机器读（无 BOM、无表头、`\\n`）。
这里的判据全部对着「导入方怎么读」写，不对着「文件长得好不好看」写。
"""

import os

import pytest

from app.export_csv import ExportError, collect_ip_lines, export_ip_list


def test_collect_dedupes_and_keeps_order():
    """同一 IP 有多条封禁记录（过期后又封一次）时只能出现一次，且顺序与表格一致"""
    got = collect_ip_lines(
        ["203.0.113.7", "198.51.100.2", "203.0.113.7", "  198.51.100.2  ", "", None]
    )
    assert got == ["203.0.113.7", "198.51.100.2"]


def test_collect_keeps_cidr_as_is():
    """网段记录不能被拆开或归一化成网络地址 —— 导入方要的是它原本的写法"""
    assert collect_ip_lines(["1.2.3.0/24"]) == ["1.2.3.0/24"]


def test_export_writes_one_ip_per_line_without_bom(tmp_path):
    path = tmp_path / "ips.txt"
    n = export_ip_list(str(path), ["1.2.3.4", "2408:8000::1"])

    assert n == 2
    raw = path.read_bytes()
    # 无 BOM：否则导入方拿到的是 `\ufeff1.2.3.4`
    assert not raw.startswith(b"\xef\xbb\xbf")
    # 固定 \n：`open(..., "w")` 在 Windows 上会翻成 \r\n，多数导入脚本不 trim \r
    assert b"\r" not in raw
    assert raw.decode("utf-8") == "1.2.3.4\n2408:8000::1\n"


def test_export_empty_writes_empty_file(tmp_path):
    path = tmp_path / "none.txt"
    n = export_ip_list(str(path), [])

    assert n == 0
    assert path.read_bytes() == b""


def test_export_rejects_missing_directory(tmp_path):
    with pytest.raises(ExportError) as e:
        export_ip_list(str(tmp_path / "no-such-dir" / "ips.txt"), ["1.2.3.4"])
    assert "目录不存在" in str(e.value)


def test_export_never_writes_partial_file_on_bad_path(tmp_path):
    """路径非法时不能先建出一个空文件再报错（用户会以为导出成功了）"""
    target = os.path.join(str(tmp_path), "missing", "ips.txt")
    with pytest.raises(ExportError):
        export_ip_list(target, ["1.2.3.4"])
    assert not os.path.exists(target)
