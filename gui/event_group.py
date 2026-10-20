"""PortGuard — 风险事件「同类合并」的纯逻辑层（零 Qt，可单测）

背景（2026-10-20 用户反馈）：同一个 IP 短时间内对同一管理端口发起多次 TCP 连接，
每次连接的远端端口不同，在库里就是多条独立的 access_log / risk_event。事件表
不显示远端端口，于是这几行看起来一字不差，用户以为是重复显示。

处理原则：
- **库里不合并**。每条连接是原始事实，访问流水、审计、导出都要能还原到单次；
  合并只发生在事件页的展示层。
- 合并键是「来源特征」：IP + 本机端口 + 路径 + 等级 + 评分 + 命中规则 + 处理状态。
  处理状态必须参与分键 —— 已确认的 3 条和未处理的 2 条摞成一行，状态列就撒谎了。
- 组内代表取**最新**一条（时间列显示最近一次发生），成员按时间倒序排列。
"""

from typing import Any, Dict, List, Tuple


def _num(v: Any) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def group_key(r: Dict[str, Any]) -> Tuple:
    """两条事件「看起来一样」的判据。改这里必须同步改 tests/test_event_group.py"""
    return (
        r.get("ip") or "",
        r.get("local_port"),
        r.get("path") or "",
        r.get("risk_level") or "",
        _num(r.get("risk_score")),
        _num(r.get("handled")),
        tuple(r.get("matched_rules") or []),
    )


def _ts(r: Dict[str, Any]) -> int:
    return _num(r.get("event_ts"))


def merge_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """把同组事件折叠成一行。

    返回的每个元素是**代表行的浅拷贝**（不改动传入 dict），额外带上：
    - group_count：组内事件条数（=1 时与原行等价）
    - member_ids：组内全部事件 id，按时间倒序
    - members：组内全部原始行，按时间倒序（事件页批量操作、详情明细用）

    组间顺序 = 输入中该组首次出现的顺序（SQL 按事件时间倒序返回，
    所以也就是「最近发生的组在前」）。
    """
    groups: Dict[Tuple, Dict[str, Any]] = {}
    order: List[Dict[str, Any]] = []
    for r in rows:
        k = group_key(r)
        g = groups.get(k)
        if g is None:
            g = {"members": []}
            groups[k] = g
            order.append(g)
        g["members"].append(r)

    out: List[Dict[str, Any]] = []
    for g in order:
        members = sorted(g["members"], key=lambda m: (_ts(m), _num(m.get("id"))), reverse=True)
        rep = dict(members[0])
        rep["member_ids"] = [_num(m.get("id")) for m in members]
        rep["members"] = members
        rep["group_count"] = len(members)
        out.append(rep)
    return out


def flatten_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """把（可能已合并的）显示行摊平成原始事件行。

    导出 CSV 与审计快照走这里 —— 它们要的是逐条事实，不是折叠后的分组。
    未合并的行（没有 members 键）原样保留。
    """
    out: List[Dict[str, Any]] = []
    for r in rows:
        members = r.get("members")
        if members:
            out.extend(members)
        else:
            out.append(r)
    return out
