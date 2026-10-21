"""
PortGuard — CSV 导出公共能力（无 Qt，可脱离界面单测）

原来只有 IP 查询页有一份一次性导出（`gui/page_iplookup.py`），风险事件 /
封禁记录 / 封禁建议三张业务表都没有出口。抽出来时把三条容易踩的坑钉死：

1. **编码必须是 `utf-8-sig`**：不带 BOM 的话 Excel 双击打开会把中文读成乱码，
   而「导出来给同事看」是这个功能唯一的用途。
2. **`open()` 必须传 `newline=""`**：否则 Windows 下 Python 会把 `\n` 再翻译
   一次，csv 自带的 `\r\n` 变成 `\r\r\n`，每行之间多一个空行。
3. **数据从内存缓存取，不遍历 QTableWidget**：表格里是被列宽截断的显示值
   （归属地只留「广东省 深圳市」、时间省掉年份），且 tooltip 里的完整值
   在导出场景取不到 —— 导出必须拿完整值。

行数据用**生成器**传入（`row_iter`）：业务表可能有几千条，一次性 list 化再
写会让导出瞬间的内存峰值翻几倍；边取边写 + 每批 flush 才是稳的做法。
"""

import csv
import json
import os
from typing import Any, Iterable, Iterator, List, Optional, Sequence

from core.config import LEVEL_LABEL
from core.models import (
    HANDLED_LABEL,
    BanRecord,
    GeoInfo,
    disposition_label,
    disposition_of,
    ms_to_str,
)
from core.rules_meta import rule_label
from core.validators import safe_text

#: 写出编码。utf-8-sig = UTF-8 + BOM，Excel 双击不乱码
ENCODING = "utf-8-sig"

#: 每写满这么多行 flush 一次。太小则频繁落盘，太大则失去分批的意义
FLUSH_EVERY = 500

#: 单元格 / 路径的长度上限。Excel 单格上限 32767，这里只为挡住超长 UA
#: 或日志炸弹把一行撑到几 MB
CELL_MAXLEN = 4000
PATH_MAXLEN = 1000


class ExportError(Exception):
    """导出失败，`str(e)` 可直接弹给用户看"""


# ═══════════════════════════════════════════════════════════
#  写出
# ═══════════════════════════════════════════════════════════


def sanitize_cell(value: Any) -> str:
    """把任意值变成可安全写进 CSV 单元格的文本。

    · `None` -> 空串（`safe_text` 负责，不写 "None" / "null" 这类噪音）
    · 字典 / 列表 -> JSON 文本（`access_log.tags`、`matched_rules` 这类
      JSON 字段若不处理，导出就是一堆原文）
    · 其余 -> 去控制字符与换行的文本。换行必须去掉：单元格内换行在
      Excel 里会撑成多行，肉眼读起来像「多了一条记录」
    """
    if isinstance(value, (dict, list, tuple)):
        return safe_text(json.dumps(value, ensure_ascii=False), maxlen=CELL_MAXLEN)
    return safe_text(value, maxlen=CELL_MAXLEN)


def _check_path(raw: Any) -> str:
    """校验导出路径。空路径 / 目录不存在都要给中文原因，不能让用户看 OSError。"""
    path = safe_text(raw, maxlen=PATH_MAXLEN)
    if not path:
        raise ExportError("导出路径为空，无法导出")
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        raise ExportError(f"导出目录不存在：{parent}")
    return path


def export_rows(
    path: Any,
    headers: Sequence[Any],
    row_iter: Iterable[Sequence[Any]],
    title: str = "",
) -> int:
    """
    把 `row_iter` 逐行写进 CSV，返回实际写出的**数据行数**（不含表头）。

    - 编码 `utf-8-sig`、`newline=""`、csv 默认 excel dialect（行终止 `\r\n`）
    - 分批写出，每 `FLUSH_EVERY` 行 flush 一次
    - 失败抛 `ExportError`（消息可直接弹给用户）；`title` 只用于文案

    `row_iter` 是生成器，所以「有多少行」要等写完才知道 —— 空数据也会写出
    一个只有表头的文件，而不是报错（表头本身是有效交付物）。
    """
    target = _check_path(path)
    label = title or "数据"
    head = [sanitize_cell(h) for h in headers]
    if not head:
        raise ExportError(f"导出{label}失败：列名不能为空")

    written = 0
    try:
        with open(target, "w", newline="", encoding=ENCODING) as f:
            w = csv.writer(f)
            w.writerow(head)
            for row in row_iter:
                w.writerow([sanitize_cell(c) for c in row])
                written += 1
                if written % FLUSH_EVERY == 0:
                    f.flush()
    except OSError as e:
        # 打不开（目录不存在 / 只读 / 被占用 / 传了个目录进来）与写到一半失败
        # 合并成一条：用户能做的动作都是「换个路径或先关掉占用的文件」
        raise ExportError(f"无法写入文件（{e.strerror or e}）：{target}") from e
    return written


# ═══════════════════════════════════════════════════════════
#  单元格序列化
# ═══════════════════════════════════════════════════════════


def _ts_cell(ms: Any) -> str:
    """epoch 毫秒 -> `YYYY-MM-DD HH:MM:SS`。

    事件表的时间口径就是 epoch 毫秒；这里是唯一一处换算，避免每个调用方
    各写一遍 `datetime.fromtimestamp`。
    """
    try:
        return ms_to_str(int(ms) if ms else None)
    except (TypeError, ValueError):
        return "-"


def _level_cell(level: Any) -> str:
    """风险等级 key -> 中文（`critical` -> 严重）"""
    key = str(level or "")
    return LEVEL_LABEL.get(key, key or "-")


def _geo_cell(geo: Optional[GeoInfo]) -> str:
    """归属地对象 -> 一行完整归属地（不是表格里的紧凑版）"""
    return geo.display if geo else "未知"


def _rules_cell(rules: Any) -> str:
    """命中规则 ID 列表 -> 「端口扫描、高频请求」这样的中文串"""
    if not rules:
        return ""
    return "、".join(rule_label(str(r)) for r in rules)


def _db_time_cell(text: Any) -> str:
    """`ban_list.created_at / updated_at` 的归一化。

    这两列在库里已经是 `YYYY-MM-DD HH:MM:SS` 字符串（`datetime('now','localtime')`
    写出来的），和事件表的 epoch 毫秒**不同源**。这里只做空值归一，不重新解析
    再格式化 —— 重新格式化要猜时区，而猜错就会让「什么时候封的」读错。
    """
    s = str(text or "").strip()
    return s or "-"


# ═══════════════════════════════════════════════════════════
#  三张业务表的列定义与行构造
# ═══════════════════════════════════════════════════════════

EVENT_CSV_HEADERS = [
    "事件ID",
    "时间",
    "风险等级",
    "来源IP",
    "归属地",
    "目标端口",
    "请求路径",
    "评分",
    "命中规则",
    "处理状态",
    "处置结果",
    "摘要",
]

BAN_CSV_HEADERS = [
    "ID",
    "IP",
    "封禁原因",
    "来源",
    "评分",
    "状态",
    "时长",
    "到期时间",
    "创建时间",
    "更新时间",
    "防火墙规则名",
    "错误信息",
]

SUG_CSV_HEADERS = [
    "事件ID",
    "时间",
    "风险等级",
    "来源IP",
    "归属地",
    "目标端口",
    "评分",
    "封禁原因",
]


def iter_event_rows(rows: Sequence[Any]) -> Iterator[List[Any]]:
    """风险事件（`core.database.query_risk_events` 的 dict）-> CSV 行"""
    for r in rows:
        yield [
            r.get("id"),
            _ts_cell(r.get("event_ts")),
            _level_cell(r.get("risk_level")),
            r.get("ip"),
            _geo_cell(r.get("geo")),
            r.get("local_port"),
            r.get("path") or "/",
            r.get("risk_score", 0),
            _rules_cell(r.get("matched_rules")),
            HANDLED_LABEL.get(r.get("handled", 0), "-"),
            disposition_label(disposition_of(r)),
            r.get("summary") or "",
        ]


def iter_ban_rows(rows: Sequence[BanRecord]) -> Iterator[List[Any]]:
    """封禁记录（`BanRecord`）-> CSV 行

    时长 / 状态 / 来源都用模型上的 `*label` 属性，和表格里显示的是同一套
    中文；到期时间用 `expire_label`，因为它已经处理了「永久 / 已解封」。
    """
    for b in rows:
        yield [
            b.id,
            b.ip,
            b.reason,
            b.source_label,
            b.risk_score,
            b.status_label,
            b.duration_label,
            b.expire_label,
            _db_time_cell(b.created_at),
            _db_time_cell(b.updated_at),
            b.rule_name,
            b.error_msg,
        ]


def iter_sug_rows(rows: Sequence[Any]) -> Iterator[List[Any]]:
    """封禁建议（未处理的高危风险事件）-> CSV 行

    与风险事件同源，但列更少：建议表只回答「要不要封」，命中规则与处理状态
    在这里没有信息量。
    """
    for r in rows:
        yield [
            r.get("id"),
            _ts_cell(r.get("event_ts")),
            _level_cell(r.get("risk_level")),
            r.get("ip"),
            _geo_cell(r.get("geo")),
            r.get("local_port"),
            r.get("risk_score", 0),
            r.get("summary") or "命中风险规则",
        ]
