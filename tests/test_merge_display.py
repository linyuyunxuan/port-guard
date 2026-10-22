"""同 IP + 同端口合并显示的守门用例（2026-10-22 用户反馈）。

背景：用户截图里 120.194.187.190:1024 把「实时监控」和「待确认封禁建议」各刷了
27 行，而那 27 次连接在用户眼里是**一件事**。要求：只显示一条，点详情看明细。

这批用例盯四件事：
1. 同 IP + 同端口 + 同协议 → 一行（路径不同也算同一件）；
2. 不同端口 / 不同 IP / 不同协议 / 不同处理状态 → 必须分开（合并错了比不合并更糟）；
3. 组内成员一条都不能丢（详情要逐条列出来）；
4. 环形缓冲溢出后重建视图，合并关系不能错乱（这是增量维护最容易写错的地方）。
"""

import time
from typing import Any, Dict, List

import pytest

from core.models import AccessRecord
from gui.page_monitor import AccessTableModel

BASE_TS = int(time.mktime((2026, 10, 22, 13, 50, 0, 0, 0, -1)) * 1000)


def _rec(
    ts: int = BASE_TS,
    ip: str = "120.194.187.190",
    port: int = 1024,
    proto: str = "tcp",
    path: str = "/",
    score: int = 100,
    level: str = "critical",
) -> AccessRecord:
    return AccessRecord(
        event_ts=ts,
        ip=ip,
        local_port=port,
        protocol=proto,
        remote_port=51000,
        path=path,
        risk_score=score,
        risk_level=level,
        matched_rules=["geo_admin_port"],
    )


def _model(capacity: int = 5000) -> AccessTableModel:
    return AccessTableModel(capacity)


# ── 合并 ──


def test_same_ip_port_collapses_to_one_row(qapp):
    m = _model()
    m.append_many([_rec(ts=BASE_TS + i * 1000) for i in range(27)])
    assert m.rowCount() == 1, "同 IP 同端口同协议必须只有一行"
    assert m.total == 27, "缓冲里仍要保留 27 条原始记录"
    assert m.count_at(0) == 27
    assert len(m.members_at(0)) == 27


def test_time_cell_shows_repeat_count(qapp):
    m = _model()
    m.append_many([_rec(ts=BASE_TS + i * 1000) for i in range(3)])
    cell = m.data(m.index(0, 0))
    assert cell.endswith("×3"), f"时间列必须标 ×N，实际 {cell!r}"


def test_different_path_still_merges(qapp):
    """扫描器换路径打同一端口 = 同一件事（旧判据在这里会拆成多行）"""
    m = _model()
    m.append_many(
        [
            _rec(ts=BASE_TS, path="/"),
            _rec(ts=BASE_TS + 1000, path="/admin"),
            _rec(ts=BASE_TS + 2000, path="/login"),
        ]
    )
    assert m.rowCount() == 1
    assert m.count_at(0) == 3


def test_different_score_still_merges(qapp):
    m = _model()
    m.append_many([_rec(ts=BASE_TS, score=40, level="high"), _rec(ts=BASE_TS + 1, score=100)])
    assert m.rowCount() == 1


def test_same_batch_is_merged(qapp):
    """一次 append_many 里就是同一 IP 的几十条 —— 批内也必须合并"""
    m = _model()
    m.append_many([_rec(ts=BASE_TS + i) for i in range(50)])
    assert m.rowCount() == 1
    assert m.count_at(0) == 50


def test_representative_is_latest(qapp):
    m = _model()
    m.append_many([_rec(ts=BASE_TS + i * 1000) for i in range(5)])
    rep = m.record_at(0)
    assert rep is not None
    assert rep.event_ts == BASE_TS + 4000, "行内时间应是最近一次"


# ── 不合并（合并错了比不合并更糟） ──


def test_different_port_splits(qapp):
    m = _model()
    m.append_many([_rec(port=1024), _rec(port=3389)])
    assert m.rowCount() == 2


def test_different_ip_splits(qapp):
    m = _model()
    m.append_many([_rec(ip="1.1.1.1"), _rec(ip="2.2.2.2")])
    assert m.rowCount() == 2


def test_different_protocol_splits(qapp):
    """同端口的 TCP 与 UDP 是两种服务，合成一行协议列就撒谎了"""
    m = _model()
    m.append_many([_rec(proto="tcp"), _rec(proto="udp")])
    assert m.rowCount() == 2


# ── 开关与筛选 ──


def test_merge_off_lists_every_record(qapp):
    m = _model()
    m.append_many([_rec(ts=BASE_TS + i) for i in range(4)])
    assert m.rowCount() == 1
    m.set_merge(False)
    assert m.rowCount() == 4
    assert m.count_at(0) == 1
    m.set_merge(True)
    assert m.rowCount() == 1
    assert m.count_at(0) == 4, "开关来回切不能丢组内成员"


def test_filter_rebuild_keeps_groups(qapp):
    m = _model()
    m.append_many([_rec(ts=BASE_TS + i, ip="120.194.187.190") for i in range(10)])
    m.append_many([_rec(ts=BASE_TS + i, ip="10.0.0.1", port=22) for i in range(3)])
    assert m.rowCount() == 2
    m.set_filters(keyword="120.194")
    assert m.rowCount() == 1
    assert m.count_at(0) == 10
    m.set_filters(keyword="")
    assert m.rowCount() == 2


def test_members_at_out_of_range_is_empty(qapp):
    m = _model()
    m.append_many([_rec()])
    assert m.members_at(99) == []
    assert m.count_at(99) == 0


def test_clear_resets_groups(qapp):
    m = _model()
    m.append_many([_rec(ts=BASE_TS + i) for i in range(5)])
    m.clear()
    assert m.rowCount() == 0
    assert m.total == 0
    m.append_many([_rec(ts=BASE_TS + 100)])
    assert m.rowCount() == 1
    assert m.count_at(0) == 1, "清空后重新计数，不能接着旧的 ×5"


def test_ring_buffer_overflow_rebuilds_correctly(qapp):
    """环形缓冲满后整表重建：不能出现重复行或丢成员"""
    # capacity 有 500 的下限（生产不会传更小的值），所以这里按 500 造满
    m = AccessTableModel(capacity=500)
    m.append_many([_rec(ts=BASE_TS + i) for i in range(500)])
    assert m.rowCount() == 1 and m.count_at(0) == 500
    m.append_many([_rec(ts=BASE_TS + 1000 + i) for i in range(3)])
    assert m.total == 500, "环形缓冲容量固定"
    assert m.rowCount() == 1
    assert m.count_at(0) == 500, "挤掉最旧的 3 条后仍是同一组，共 500 条"


def test_overflow_keeps_distinct_groups(qapp):
    m = AccessTableModel(capacity=500)
    m.append_many([_rec(ts=BASE_TS + i, ip=f"10.0.{i // 250}.{i % 250}") for i in range(500)])
    assert m.rowCount() == 500
    m.append_many([_rec(ts=BASE_TS + 1000 + i, ip=f"10.9.9.{i}") for i in range(3)])
    assert m.rowCount() == 500, "旧组被挤出缓冲后必须整行消失，不能留空壳"
    ips = {m.record_at(i).ip for i in range(m.rowCount())}  # type: ignore[union-attr]
    assert {f"10.9.9.{i}" for i in range(3)} <= ips, "新记录必须都在"
    assert "10.0.0.0" not in ips, "最早的那条已被挤出缓冲"


def test_members_are_in_chronological_order(qapp):
    """模型存的是「按发生顺序」—— tooltip 的「首次 / 最近」两个端点靠这个顺序"""
    m = _model()
    m.append_many([_rec(ts=BASE_TS + i * 1000) for i in range(4)])
    assert [r.event_ts for r in m.members_at(0)] == [BASE_TS + i * 1000 for i in range(4)]


def test_detail_dialog_shows_newest_first(qapp):
    """弹窗承诺「仅列出最近 N 条」—— 截出来的就必须是最近的，不能是最老的"""
    from core.models import ms_to_str
    from gui.event_detail import AccessDetailDialog
    from qtcompat import QTableWidget

    m = _model()
    m.append_many([_rec(ts=BASE_TS + i * 1000) for i in range(5)])
    dlg = AccessDetailDialog(m.members_at(0))
    assert "5 次" in dlg.windowTitle()
    table = dlg.findChild(QTableWidget)
    assert table is not None and table.rowCount() == 5
    first_cell = table.item(0, 0)
    last_cell = table.item(4, 0)
    assert first_cell is not None and last_cell is not None
    assert first_cell.text() == ms_to_str(BASE_TS + 4000), "第一行应是最近一次"
    assert last_cell.text() == ms_to_str(BASE_TS), "最后一行应是最早一次"


def test_monitor_show_detail_passes_every_member(qapp, monkeypatch):
    """双击合并行打开的详情必须是组内全部 27 次，不能只给代表那一条"""
    from gui import page_monitor

    captured: List[List[Any]] = []

    class _FakeDialog:
        def __init__(self, recs, parent=None) -> None:
            captured.append(list(recs))

        def exec(self) -> int:
            return 0

    monkeypatch.setattr(page_monitor, "AccessDetailDialog", _FakeDialog)
    m = _model()
    m.append_many([_rec(ts=BASE_TS + i) for i in range(27)])

    # 只测这一个方法，不走 MonitorPage.__init__（那要搭一整页控件）
    host = page_monitor.MonitorPage.__new__(page_monitor.MonitorPage)
    host.model = m
    host._show_detail(0)
    assert len(captured[0]) == 27, "只传代表那一条的话，详情里就只剩一次连接"


# ── 封禁建议页合并 ──


def _evt(id: int, ts: int, ip: str = "120.194.187.190", port: int = 1024) -> Dict[str, Any]:
    return {
        "id": id,
        "event_ts": ts,
        "ip": ip,
        "local_port": port,
        "risk_level": "critical",
        "risk_score": 100,
        "handled": 0,
        "matched_rules": ["geo_admin_port"],
        "summary": "命中规则：管理端口归属地检测",
    }


class _Sort:
    def apply(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return list(rows)


class _SuggestionHost:
    """`BansPage._load_suggestions` 的最小替身：只提供它真正会碰到的那几个属性"""

    def __init__(self, log: List[int]) -> None:
        self._log = log
        self._banned: Dict[str, Any] = {}
        self._sug_rows_src: List[Dict[str, Any]] = []
        self._sug_rows: List[Dict[str, Any]] = []
        self.sug_sort = _Sort()

    def _render_suggestions(self) -> None:
        self._log.append(len(self._sug_rows))


def test_ban_suggestions_are_merged(monkeypatch):
    """27 条建议 → 1 项（对应 1 条防火墙规则），标题要同时给出两个数"""
    from gui import page_bans

    rows = [_evt(i, BASE_TS + i * 1000) for i in range(1, 28)]
    monkeypatch.setattr(page_bans, "query_risk_events", lambda **kw: rows)
    monkeypatch.setattr(page_bans, "active_ban_ip_map", dict)

    rendered: List[int] = []
    host = _SuggestionHost(rendered)
    page_bans.BansPage._load_suggestions(host)  # type: ignore[arg-type]

    assert rendered == [1], "合并后只应渲染 1 项建议"
    assert host._sug_rows_src[0]["group_count"] == 27
    assert len(host._sug_rows_src[0]["members"]) == 27


def test_ban_suggestion_merge_failure_falls_back(monkeypatch):
    """合并只是展示优化：它出错不能让整页刷不出来"""
    from gui import page_bans

    rows = [_evt(i, BASE_TS + i * 1000) for i in range(1, 4)]
    monkeypatch.setattr(page_bans, "query_risk_events", lambda **kw: rows)
    monkeypatch.setattr(page_bans, "active_ban_ip_map", dict)

    def _boom(_rows):
        raise RuntimeError("merge 坏了")

    monkeypatch.setattr(page_bans, "merge_rows", _boom)

    rendered: List[int] = []
    page_bans.BansPage._load_suggestions(_SuggestionHost(rendered))  # type: ignore[arg-type]
    assert rendered == [3], "退回逐条展示"


def test_ignore_single_group_row_marks_all_members(monkeypatch):
    """右键「忽略该建议」落在合并行上：组内每一条都要标记

    只标记代表那条的话，刷新后剩下的 26 条又以同一条建议冒出来 ——
    用户会认为「忽略根本没生效」，然后去点第二次。
    """
    from gui import page_bans

    batch: List[List[int]] = []
    single: List[int] = []

    def _fake_batch(ids, handled):
        batch.append(list(ids))
        return 0

    def _fake_single(i, handled):
        single.append(int(i))
        return True

    monkeypatch.setattr(page_bans, "set_risk_handled_batch", _fake_batch)
    monkeypatch.setattr(page_bans, "set_risk_handled", _fake_single)

    members = [_evt(i, BASE_TS + i) for i in range(1, 4)]
    group = {"id": 27, "ip": "120.194.187.190", "members": members, "group_count": 3}

    class _Host:
        def refresh(self) -> None:
            pass

    page_bans.BansPage._ignore(_Host(), group)  # type: ignore[arg-type]
    assert batch == [[1, 2, 3]], "合并行必须摊平成组内每一条"
    assert single == []


def test_batch_ignore_expands_group_members(monkeypatch):
    """勾一条合并行去「批量忽略」，组内 27 条必须全部标记，否则刷新后又冒出来"""
    from gui import page_bans

    captured: List[List[int]] = []

    def _fake_batch(ids, handled):
        captured.append(list(ids))
        return 0

    monkeypatch.setattr(page_bans, "set_risk_handled_batch", _fake_batch)

    merged = [_evt(i, BASE_TS + i) for i in range(1, 4)]
    group = {"id": 27, "ip": "120.194.187.190", "members": merged, "group_count": 3}

    class _Host:
        def __init__(self) -> None:
            self._sug_rows = [group]
            self.sug_hint = type("_L", (), {"setText": lambda self, t: None})()

        def _checked_suggestions(self) -> List[Dict[str, Any]]:
            return [group]

        def refresh(self) -> None:
            pass

    page_bans.BansPage._batch_ignore_suggestions(_Host())  # type: ignore[arg-type]
    assert captured == [[1, 2, 3]], "必须摊平成组内每一条事件的 id"


@pytest.fixture()
def qapp():
    """离屏 QApplication（模型层不需要窗口，但 QAbstractTableModel 需要实例）"""
    from qtcompat import QApplication

    app = QApplication.instance() or QApplication([])
    yield app
