"""PortGuard — 风险事件「同类合并」的纯逻辑层（零 Qt，可单测）

背景（2026-10-20 用户反馈）：同一个 IP 短时间内对同一管理端口发起多次 TCP 连接，
每次连接的远端端口不同，在库里就是多条独立的 access_log / risk_event。事件表
不显示远端端口，于是这几行看起来一字不差，用户以为是重复显示。

2026-10-22 二次反馈（截图：120.194.187.190:1024 占满 27 行）：
原先的分键把 path / 等级 / 评分 / 命中规则也算进去，而扫描器打同一端口时会换着
路径来（`/`、`/admin`、`/login`…），命中规则随之不同 —— 结果就是 27 行「看起来
一模一样」的记录仍然各自成行。对用户而言那 27 条就是**一件事**：某个 IP 在打我的
某个端口。

所以现在的判据收敛为：
- **同来源 IP + 同目标端口 + 同处理状态** → 一行；
- 等级 / 评分 / 命中规则用组内**最高水位**（`peak_*`）呈现 —— 一组里最危险到过
  什么程度，比「最近一次恰好只是 low」更有意义；
- 处理状态必须留在键里：已确认的和未处理的摞成一行，状态列就撒谎了。

处理原则不变：
- **库里不合并**。每条连接是原始事实，访问流水、审计、导出都要能还原到单次；
  合并只发生在展示层。
- 组内代表取**最新**一条（时间列显示最近一次发生），成员按时间倒序排列。

⚠️ 这里与实时监控页的 `AccessTableModel.group_key` **不是同一个键**：那边有
`protocol`（TCP/UDP 同端口是两种服务），而 `risk_event` 表压根没存协议列，
所以事件页只能按 IP + 端口 + 处理状态聚合。别把两边强行统一。
"""

from typing import Any, Dict, List, Tuple


def _num(v: Any) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return 0


def group_key(r: Dict[str, Any]) -> Tuple:
    """两条事件「是同一件事」的判据。改这里必须同步改 tests/test_event_group.py

    只有 IP、端口、处理状态三项 —— 详见模块文档里 2026-10-22 那条。
    """
    return (
        r.get("ip") or "",
        r.get("local_port"),
        _num(r.get("handled")),
    )


def _ts(r: Dict[str, Any]) -> int:
    return _num(r.get("event_ts"))


def merge_rows(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """把同组事件折叠成一行。

    返回的每个元素是**代表行的浅拷贝**（不改动传入 dict），额外带上：
    - group_count：组内事件条数（=1 时与原行等价）
    - member_ids：组内全部事件 id，按时间倒序
    - members：组内全部原始行，按时间倒序（详情明细、批量操作展开用）
    - peak_score / peak_level / peak_rules：组内最高水位（评分最高那条的）
    - first_ts / last_ts：组内最早 / 最晚发生时间（epoch 毫秒）

    组间顺序 = 输入中该组首次出现的顺序（SQL 按事件时间倒序返回，
    所以也就是「最近发生的组在前」）。
    """
    groups: Dict[Tuple, List[Dict[str, Any]]] = {}
    order: List[Tuple] = []
    for r in rows:
        k = group_key(r)
        bucket = groups.get(k)
        if bucket is None:
            groups[k] = bucket = []
            order.append(k)
        bucket.append(r)

    out: List[Dict[str, Any]] = []
    for k in order:
        members = sorted(groups[k], key=lambda m: (_ts(m), _num(m.get("id"))), reverse=True)
        rep = dict(members[0])
        # 最高水位：先比评分，同分取较晚的那条（同分时「最近一次最严重」更贴近现状）
        peak = max(members, key=lambda m: (_num(m.get("risk_score")), _ts(m)))
        rep["member_ids"] = [_num(m.get("id")) for m in members]
        rep["members"] = members
        rep["group_count"] = len(members)
        rep["peak_score"] = _num(peak.get("risk_score"))
        rep["peak_level"] = peak.get("risk_level") or rep.get("risk_level") or ""
        rep["peak_rules"] = list(peak.get("matched_rules") or [])
        rep["first_ts"] = min(_ts(m) for m in members)
        rep["last_ts"] = max(_ts(m) for m in members)
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
