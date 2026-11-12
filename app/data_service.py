"""
PortGuard — 数据服务层（不依赖 Qt）

为什么单独抽出来
----------------
项目分层硬约定：`core`（无界面无 Qt）← `app`（无 Qt 的服务编排）← `gui`（只展示）。
修复前，多个 gui 页面直接 `from core.database import ...` 做**破坏性删除 / 清空**，
并在界面层就地埋审计。这带来两个问题：

1. **依赖方向被打破** —— gui 直接碰 core 底库，core 的写语义一旦变化要牵连界面，
   且「谁在什么时候删了多少数据」这类**审计**本应跟业务动作绑定，不该散落在
   视图代码里；
2. **审计口径不统一** —— 每条破坏性路径的成功 / 失败埋点各自在界面层手写，
   难以保证「失败也留痕」「before/after 快照」这些规则处处一致。

本模块把 GUI 里所有破坏性删除 / 清空操作及其审计语义收口到 app 层：gui 只调用
这里的业务函数，再也不直接 import core.database 做写操作，从而恢复
`core ← app ← gui` 的单向依赖。

设计要点：
- **每个写操作 = 业务 + 审计**：先执行 core 的真实删除，成功则记成功审计
  （带 before 快照 / after 条数），异常则记失败审计再 `raise`，让界面可以
  呈现错误但审计留痕不丢失；
- **审计写失败绝不能中断业务**（见 `app/audit.record` 的说明），因此这里的
  `audit.record` 调用无需 try/except；
- 只读查询（分页、统计、导出）中与「审计页」相关的收口放到 `app/audit.py`
  （`count_records` / `query_records` / `list_actors`），本模块专注破坏性写操作。
"""

from typing import Optional


def clear_access_logs(
    *,
    keyword: str,
    level: str,
    port: Optional[int],
    since_ts: Optional[int],
    until_ts: Optional[int],
    all_rows: bool,
    scope_desc: str,
    matched_total: int,
) -> int:
    """
    按条件清空历史访问记录（「历史访问」页的清空功能）。

    `scope_desc` / `matched_total` 由界面层算好传入，用于审计留痕（用户
    看到的是「清空 XX 范围内的 N 条」，审计也要按这个口径记录）。
    返回实际删除条数；失败时记失败审计并 `raise` 交给界面呈现。
    """
    from app import audit

    try:
        from core.database import delete_access_logs

        deleted = delete_access_logs(
            keyword=keyword,
            level=level,
            port=port,
            since_ts=since_ts,
            until_ts=until_ts,
            all_rows=all_rows,
        )
    except Exception as e:
        audit.record(
            audit.ACTION_DATA_CLEAR,
            target_type="access",
            summary=f"清空访问列表失败（{scope_desc}）：{e}",
            result=audit.RESULT_FAIL,
            detail=str(e),
        )
        raise
    audit.record(
        audit.ACTION_DATA_CLEAR,
        target_type="access",
        summary=f"清空访问列表：{scope_desc}，删除 {deleted} 条",
        before={"scope": scope_desc, "matched": matched_total},
        after={"deleted": deleted},
    )
    return deleted


def delete_ban_records_by_ids(ids: list, snapshot: list) -> int:
    """
    批量删除封禁记录（只删库记录，不改动防火墙规则）。

    `snapshot` 是删除前对选中记录关键字段整条留档的列表，用于审计 before。
    成功记审计，失败记失败审计并 `raise`。
    """
    from app import audit

    try:
        from core.database import delete_ban_records

        n = delete_ban_records(ids)
    except Exception as e:
        audit.record(
            audit.ACTION_BAN_DELETE,
            target_type="ban",
            summary=f"删除 {len(ids)} 条封禁记录失败：{e}",
            result=audit.RESULT_FAIL,
            detail=str(e),
        )
        raise
    audit.record(
        audit.ACTION_BAN_DELETE,
        target_type="ban",
        summary=f"删除 {n} 条封禁记录（仅删库记录，未改动防火墙规则）",
        before={"bans": snapshot},
        after={"count": n},
        detail="防火墙规则未改动",
    )
    return n


def delete_ban_record_single(ban_id: int) -> None:
    """
    单条删除封禁记录（与现状一致，不记审计 —— 现状就没有，保持语义不变）。

    注意与批量删除 `delete_ban_records_by_ids` 区分：单条路径是表格行级按钮，
    与现状一致不带审计，不要画蛇添足。
    """
    from core.database import delete_ban_record

    delete_ban_record(ban_id)


def delete_risk_events_by_ids(ids: list, snapshot: list) -> int:
    """
    批量删除风险事件（只删事件，不影响访问流水与统计）。

    `snapshot` 是删除前对选中事件关键字段整条留档的列表，用于审计 before。
    成功记审计，失败记失败审计并 `raise`。
    """
    from app import audit

    try:
        from core.database import delete_risk_events

        n = delete_risk_events(ids)
    except Exception as e:
        audit.record(
            audit.ACTION_EVENT_DELETE,
            target_type="event",
            summary=f"删除 {len(ids)} 条风险事件失败：{e}",
            result=audit.RESULT_FAIL,
            detail=str(e),
        )
        raise
    audit.record(
        audit.ACTION_EVENT_DELETE,
        target_type="event",
        summary=f"删除 {n} 条风险事件",
        before={"events": snapshot},
        after={"count": n},
    )
    return n


def clear_all_logs_with_audit() -> None:
    """
    清空全部访问日志与风险事件（设置页，全项目破坏性最大的按钮）。

    封禁列表不受影响。业务成功后记审计留痕；`clear_all_logs` 失败时由
    `core.database` 抛出的异常直接向上传播（与改动前界面层行为一致，
    设置页同样不 catch），与 `app/audit.record` 的「写失败不中断业务」
    约定不冲突。
    """
    from app import audit
    from core.database import clear_all_logs

    clear_all_logs()
    audit.record(
        audit.ACTION_DATA_CLEAR,
        target_type="data",
        summary="清空全部访问日志与风险事件（封禁列表不受影响）",
    )
