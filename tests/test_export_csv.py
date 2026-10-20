"""CSV 导出的编码 / 换行 / 序列化口径守门。

这几件事一旦写错都**不会报错**，只会让导出的文件在 Excel 里变成乱码或
每行之间多一个空行 —— 用户会以为「软件导出来的东西是坏的」，而开发机上
用文本编辑器看又一切正常。所以每条都钉死到字节级：

1. `utf-8-sig` 的 BOM（前 3 字节 `EF BB BF`）必须在；
2. 行终止符必须**恰好**是 `\r\n`（`open()` 漏掉 `newline=""` 就会变成 `\r\r\n`）；
3. `geo` / `matched_rules` 这类 JSON 字段必须序列化成中文可读文本，
   而不是把 JSON 原文倒进单元格；
4. 两种时间口径（事件表 epoch 毫秒、封禁表 `YYYY-MM-DD HH:MM:SS` 字符串）
   不能混。

界面层的按钮与弹框在 `_design/` 的离屏探针里走查，这里只钉数据层。
"""

import codecs
import csv
import datetime
import json

import pytest

from app.export_csv import (
    BAN_CSV_HEADERS,
    EVENT_CSV_HEADERS,
    FLUSH_EVERY,
    SUG_CSV_HEADERS,
    ExportError,
    export_rows,
    iter_ban_rows,
    iter_event_rows,
    iter_sug_rows,
    sanitize_cell,
)
from core.models import BanRecord, GeoInfo


def _read(path):
    """按 csv 语义读回：`newline=""` 交给 csv 处理行内引号"""
    with open(str(path), newline="", encoding="utf-8-sig") as f:
        return list(csv.reader(f))


# ═══════════════════════════════════════════════════════════
#  编码与换行
# ═══════════════════════════════════════════════════════════


def test_empty_rows_still_writes_header_only(tmp_path) -> None:
    """0 条数据也要产出一个只有表头的文件，而不是空文件或异常"""
    target = tmp_path / "empty.csv"
    n = export_rows(str(target), ["IP", "归属地"], iter([]))
    assert n == 0
    rows = _read(target)
    assert rows == [["IP", "归属地"]]


def test_bom_present_and_content_survives_excel(tmp_path) -> None:
    """中文必须带 BOM 写出。

    变异验证：把 `ENCODING` 改成 `utf-8`，本条会红（前 3 字节变成 `E6 9F A5`）。
    """
    target = tmp_path / "cn.csv"
    export_rows(str(target), ["IP", "归属地"], [["1.2.3.4", "中国·广东省·深圳市"]])
    raw = target.read_bytes()
    assert raw.startswith(codecs.BOM_UTF8), "缺少 utf-8-sig BOM，Excel 双击会乱码"
    assert "中国·广东省·深圳市" in raw.decode("utf-8-sig")


def test_line_terminator_is_exactly_crlf(tmp_path) -> None:
    """行终止符只能是 `\\r\\n`。

    变异验证：删掉 `open(..., newline="")`，Python 会把 csv 写出的 `\\n`
    再翻译一次，`\\r\\n` 变成 `\\r\\r\\n` —— 本条会红。
    """
    target = tmp_path / "crlf.csv"
    export_rows(str(target), ["A", "B"], [["1", "2"], ["3", "4"]])
    body = target.read_bytes()[len(codecs.BOM_UTF8) :]
    assert b"\r\r\n" not in body, '出现了 \\r\\r\\n：open() 少了 newline=""'
    # 把合法的 \r\n 去掉后，不应再残留任何裸 \r 或裸 \n
    assert b"\r" not in body.replace(b"\r\n", b"")
    assert b"\n" not in body.replace(b"\r\n", b"")
    assert body.count(b"\r\n") == 3  # 表头 + 2 行数据


def test_header_only_file_has_no_trailing_blank_line(tmp_path) -> None:
    target = tmp_path / "one.csv"
    export_rows(str(target), ["A"], [])
    body = target.read_bytes()[len(codecs.BOM_UTF8) :]
    assert body == b"A\r\n"


# ═══════════════════════════════════════════════════════════
#  分批写出
# ═══════════════════════════════════════════════════════════


def test_large_stream_is_written_in_batches_with_correct_count(tmp_path) -> None:
    """跨过多个 flush 批次后行数仍然精确（1234 > FLUSH_EVERY × 2）"""
    target = tmp_path / "big.csv"

    def gen():
        for i in range(1234):
            yield [i, "第 " + str(i) + " 行"]

    n = export_rows(str(target), ["序号", "内容"], gen())
    assert n == 1234
    rows = _read(target)
    assert len(rows) == 1235  # 表头 + 1234
    assert rows[1] == ["0", "第 0 行"]
    assert rows[-1] == ["1233", "第 1233 行"]


def test_each_batch_is_flushed_to_disk(tmp_path) -> None:
    """写满一批就要落盘，不能全攒在内存里。

    为什么在意：导出几万条时如果只在 close 时一次性落盘，中途「另存为」
    的进度条（或用户看文件大小）永远不动，进程被杀就什么都留不下。
    这里在生成器里另开一个句柄读文件 —— 只有真的 flush 过才看得见前
    500 行。

    变异验证：删掉 `if written % FLUSH_EVERY == 0: f.flush()`，本条会红
    （盘上还是 0 字节）。
    """
    target = tmp_path / "flush.csv"
    seen = {}

    def gen():
        for i in range(600):
            if i == FLUSH_EVERY:
                # 此刻应已写完表头 + 前 FLUSH_EVERY 行并落盘
                seen["rows"] = len(_read(target))
            yield [i]

    n = export_rows(str(target), ["I"], gen())
    assert n == 600
    assert seen["rows"] == FLUSH_EVERY + 1


def test_rows_are_written_before_the_generator_finishes(tmp_path) -> None:
    """边取边写：生成器中途抛错时，前面已产出的行必须已经在文件里。

    变异验证：把实现改成 `rows = list(row_iter)` 再写，抛错会发生在写文件
    之前，文件要么不存在要么只有表头 —— 本条会红。
    """
    target = tmp_path / "lazy.csv"

    def gen():
        yield [1]
        yield [2]
        raise RuntimeError("数据源中途出错")

    with pytest.raises(RuntimeError):
        export_rows(str(target), ["I"], gen())
    assert _read(target) == [["I"], ["1"], ["2"]]


# ═══════════════════════════════════════════════════════════
#  单元格序列化
# ═══════════════════════════════════════════════════════════


def test_sanitize_cell_none_and_numbers() -> None:
    """None 不能写成字符串 "None"（那样筛选时空值会变成有值）"""
    assert sanitize_cell(None) == ""
    assert sanitize_cell(0) == "0"
    assert sanitize_cell("") == ""


def test_sanitize_cell_json_fields_are_not_raw() -> None:
    """`access_log.tags` 这类 JSON 对象要落成 JSON 文本，不能是 repr"""
    tags = {"zone": "dmz", "note": "内网"}
    assert json.loads(sanitize_cell(tags)) == tags


def test_sanitize_cell_strips_newlines(tmp_path) -> None:
    """单元格内换行会让一条记录在 Excel 里占两行，必须压成空格"""
    target = tmp_path / "nl.csv"
    export_rows(str(target), ["A"], [["第一行\n第二行"]])
    assert _read(target)[1] == ["第一行 第二行"]


# ═══════════════════════════════════════════════════════════
#  路径与错误
# ═══════════════════════════════════════════════════════════


def test_missing_directory_raises_readable_error(tmp_path) -> None:
    target = tmp_path / "no_such_dir" / "a.csv"
    with pytest.raises(ExportError) as ei:
        export_rows(str(target), ["A"], [])
    assert "目录不存在" in str(ei.value)


def test_unwritable_path_raises_readable_error(tmp_path) -> None:
    """把目录当文件路径传：必须给中文原因，而不是裸 OSError"""
    with pytest.raises(ExportError) as ei:
        export_rows(str(tmp_path), ["A"], [])
    msg = str(ei.value)
    assert "无法写入文件" in msg


def test_empty_path_raises(tmp_path) -> None:
    with pytest.raises(ExportError):
        export_rows("   ", ["A"], [])


def test_empty_headers_raises(tmp_path) -> None:
    with pytest.raises(ExportError):
        export_rows(str(tmp_path / "x.csv"), [], [])


# ═══════════════════════════════════════════════════════════
#  三张业务表的列口径
# ═══════════════════════════════════════════════════════════


def _event_row(**kw):
    r = {
        "id": 7,
        "event_ts": 1700000000000,
        "risk_level": "critical",
        "ip": "45.33.32.156",
        "geo": GeoInfo(
            ip="45.33.32.156",
            country="美国",
            province="加利福尼亚州",
            city="弗里蒙特",
            isp="Linode",
            iso="US",
            found=True,
        ),
        "local_port": 3389,
        "path": "/admin/login",
        "risk_score": 92,
        "matched_rules": ["port_scan", "rate_limit"],
        "handled": 1,
        "summary": "端口扫描 + 高频请求",
    }
    r.update(kw)
    return r


def test_event_rows_serialize_json_and_time() -> None:
    """geo / matched_rules / event_ts 三处都不能把原始存储形态漏出去"""
    row = next(iter_event_rows([_event_row()]))
    assert len(row) == len(EVENT_CSV_HEADERS)
    cells = dict(zip(EVENT_CSV_HEADERS, row))
    # geo 是 JSON 反序列化出来的对象 -> 完整一行归属地（不是表格里的紧凑版）
    assert cells["归属地"] == "美国·加利福尼亚州·弗里蒙特·Linode"
    # matched_rules 是 JSON 数组 -> 中文规则名
    assert cells["命中规则"] == "端口扫描、高频请求"
    expected = datetime.datetime.fromtimestamp(1700000000).strftime("%Y-%m-%d %H:%M:%S")
    assert cells["时间"] == expected
    assert cells["风险等级"] == "严重"
    assert cells["处理状态"] == "已确认"


def test_event_rows_handle_missing_geo_and_unknown_level() -> None:
    row = next(iter_event_rows([_event_row(geo=None, risk_level="weird", path="", handled=9)]))
    cells = dict(zip(EVENT_CSV_HEADERS, row))
    assert cells["归属地"] == "未知"
    assert cells["风险等级"] == "weird"  # 未知等级原样保留，不吞掉
    assert cells["请求路径"] == "/"
    assert cells["处理状态"] == "-"


def test_ban_rows_keep_db_time_strings_and_format_epoch() -> None:
    """ban_list 的时间是 `YYYY-MM-DD HH:MM:SS` 字符串，不能当 epoch 毫秒再转一次"""
    b = BanRecord(
        id=12,
        ip="203.0.113.10",
        rule_name="PortGuard_Block_203.0.113.10",
        reason="暴力破解",
        risk_score=88,
        source="auto",
        status="active",
        duration_sec=3600,
        expire_at=1700003600000,
        created_at="2026-10-20 09:15:00",
        updated_at="2026-10-20 09:15:02",
    )
    row = next(iter_ban_rows([b]))
    assert len(row) == len(BAN_CSV_HEADERS)
    cells = dict(zip(BAN_CSV_HEADERS, row))
    assert cells["创建时间"] == "2026-10-20 09:15:00"
    assert cells["更新时间"] == "2026-10-20 09:15:02"
    assert cells["到期时间"] == datetime.datetime.fromtimestamp(1700003600).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    assert cells["时长"] == "1 小时"
    assert cells["状态"] == "已封禁"
    assert cells["来源"] == "自动"


def test_ban_rows_permanent_and_unbanned() -> None:
    forever = BanRecord(id=1, ip="1.1.1.1", duration_sec=None, expire_at=None, status="active")
    unbanned = BanRecord(id=2, ip="2.2.2.2", expire_at=None, status="unbanned")
    rows = list(iter_ban_rows([forever, unbanned]))
    assert dict(zip(BAN_CSV_HEADERS, rows[0]))["到期时间"] == "永久"
    assert dict(zip(BAN_CSV_HEADERS, rows[0]))["创建时间"] == "-"
    assert dict(zip(BAN_CSV_HEADERS, rows[1]))["到期时间"] == "-"


def test_sug_rows_columns() -> None:
    row = next(iter_sug_rows([_event_row(handled=0, summary="")]))
    assert len(row) == len(SUG_CSV_HEADERS)
    cells = dict(zip(SUG_CSV_HEADERS, row))
    assert cells["风险等级"] == "严重"
    assert cells["归属地"] == "美国·加利福尼亚州·弗里蒙特·Linode"
    assert cells["封禁原因"] == "命中风险规则"  # 摘要为空时给默认理由


def test_table_row_cells_all_serializable(tmp_path) -> None:
    """三张表的行都要能真的写进文件（列数一致、不含 None 字面量）"""
    target = tmp_path / "all.csv"
    rows = list(iter_event_rows([_event_row()]))
    n = export_rows(str(target), EVENT_CSV_HEADERS, rows)
    assert n == 1
    written = _read(target)
    assert len(written) == 2
    assert len(written[1]) == len(EVENT_CSV_HEADERS)
    assert "None" not in ",".join(written[1])
