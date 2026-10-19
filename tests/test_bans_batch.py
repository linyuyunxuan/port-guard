"""封禁管理页批量能力的数据层守门：批量删除封禁记录 + 勾选列三态。

界面行为在 `_design/_bans_probe.py` 里做离屏验证（全选按钮可用性、批量解封
只碰已封禁记录、建议按 IP 去重），这里只钉数据层的两条语义：

1. **delete_ban_records 只删数据库记录**：封禁记录是「记账」，防火墙规则是
   「既成事实」。批量删记录绝不能顺手去动防火墙，否则会出现无主规则。
2. **空列表是合法输入**：勾选列在筛选变化后可能一张都不剩，此时按钮点了
   也不该炸。
"""

import pytest

from core import database
from core.models import BanRecord, STATUS_ACTIVE, STATUS_UNBANNED


@pytest.fixture(autouse=True)
def _schema(fresh_db):
    """fresh_db 只清库文件、不建表，这里补一次建表（建在临时库里）。"""
    database.init_db()
    yield


def _mk_ban(ip: str, status: str = STATUS_ACTIVE) -> int:
    rec = BanRecord(ip=ip, reason="测试封禁", risk_score=90, source="manual", status=status)
    ban_id = database.insert_ban(rec)
    assert ban_id is not None
    return int(ban_id)


def test_delete_ban_records_removes_only_selected():
    a = _mk_ban("45.33.32.156")
    b = _mk_ban("8.8.8.8")
    n = database.delete_ban_records([a])
    assert n == 1
    rows = database.query_bans()
    assert [r.id for r in rows] == [b]


def test_delete_ban_records_empty_list_is_noop():
    _mk_ban("45.33.32.156")
    assert database.delete_ban_records([]) == 0
    assert len(database.query_bans()) == 1


def test_delete_ban_records_keeps_unbanned_history():
    """解封后的记录是审计痕迹，批量删除要能删它，但别的记录不能被牵连。"""
    _mk_ban("45.33.32.156", STATUS_ACTIVE)
    unbanned = _mk_ban("8.8.8.8", STATUS_UNBANNED)
    assert database.delete_ban_records([unbanned]) == 1
    rows = database.query_bans()
    assert len(rows) == 1 and rows[0].status == STATUS_ACTIVE
