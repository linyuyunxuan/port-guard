"""离屏渲染 7 个页面的当前状态截图 → _design/after/N_*.png

用法（项目根下）：
    set QT_QPA_PLATFORM=offscreen && python _design/render_shots.py
    set QT_QPA_PLATFORM=offscreen && python _design/render_shots.py --width 1200
    # 开发栈：C:\\Users\\Administrator\\.workbuddy\\binaries\\python\\envs\\portguard\\Scripts\\python.exe
    # 交付栈：C:\\Users\\Administrator\\.workbuddy\\binaries\\python\\envs\\portguard38\\Scripts\\python.exe

输出目录：--width 1360（默认）→ `_design/after/`；其它宽度 → `_design/after/w{width}/`，
这样两档并存、不互相覆盖。同时打印每张主表的「横向滚动条最大值 + 实际列宽」，
用于核对 02_ux_spec P0-2 的「1200 宽无横滚、弹性列 ≥150」。

用途：视觉走查用（表格是否截断 / 徽章是否垂直居中 / focus 是否可见 / 有无第 5 色相）。
这是设计阶段的工具脚本，不属于产品代码。
"""

import argparse
import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# 监控页只吃事件泵的实时数据（不回读数据库），要截出「10 列 + 斑马纹 + 各类徽章」
# 必须自己喂一批样本，否则表格永远是空的、走查看不出任何列宽问题。
SEED = [
    # (ip, local_port, protocol, method, path, status, risk_level, score, rules)
    ("113.118.113.77", 18080, "http", "GET", "/api/products", 200, "normal", 0, []),
    ("45.33.32.156", 8080, "http", "POST", "/admin/login", 401, "medium", 45, ["scanner_ua"]),
    ("8.8.8.8", 3389, "tcp", "", "", 0, "low", 20, ["port_scan"]),
    ("1.1.1.1", 443, "https", "HEAD", "/", 200, "normal", 0, []),
    (
        "203.0.113.10",
        18080,
        "http",
        "GET",
        "/../../etc/passwd",
        403,
        "high",
        75,
        ["path_traversal"],
    ),
    ("198.51.100.7", 8080, "http", "POST", "/wp-login.php", 500, "critical", 95, ["brute_force"]),
]


def seed_monitor(win) -> None:
    """灌入样本访问记录（仅用于截图，不落库）"""
    import datetime

    from core.geo_locator import get_locator
    from core.models import AccessRecord

    loc = get_locator()
    recs = []
    now_ms = int(datetime.datetime.now().timestamp() * 1000)
    for i in range(24):
        ip, port, proto, method, path, status, level, score, rules = SEED[i % len(SEED)]
        r = AccessRecord(
            ip=ip,
            remote_port=50000 + i,
            local_port=port,
            protocol=proto,
            method=method,
            path=path,
            status_code=status or None,
            user_agent="Mozilla/5.0 (Windows NT 10.0)",
            size=1024 * (i + 1),
            server_name="web-01",
            event_ts=now_ms - (24 - i) * 7000,
        )
        r.geo = loc.lookup(ip)
        r.risk_level = level
        r.risk_score = score
        r.matched_rules = list(rules)
        recs.append(r)

    win.page_monitor.append_records(recs)
    win.page_logs.append_access(recs)
    # set_stats 现在是 (total, risk, bans) —— 早期版本还带「观察中 / 端口」两个参数，
    # 脚本没跟着改，会在 seed 阶段直接 TypeError（截图一张都出不来）
    win.page_monitor.set_stats(41, 27, 3)


def seed_bans(win) -> None:
    """给「封禁建议」表灌几条**仅内存**的样本行。

    不写数据库：这台机器上跑的是真实用户的库，截图工具没有资格往里插事件。
    直接构造 _sug_rows 再调一次 _render_suggestions()，效果与真数据一致
    （表格渲染只认这几个键），标题里的计数、按钮的启用态也会跟着变 ——
    空表截图看不出「标题行挤不挤」这种布局问题，等于白截。
    """
    import datetime

    page = win.page_bans
    now_ms = int(datetime.datetime.now().timestamp() * 1000)
    raw = [
        ("198.51.100.7", 8080, 95, "critical", "命中暴力破解规则：1 分钟内 42 次登录失败", 12),
        ("203.0.113.10", 18080, 75, "high", "命中路径穿越规则：/../../etc/passwd", 3),
        ("45.33.32.156", 9001, 100, "critical", "命中扫描器特征（sqlmap UA）+ 端口探测", 1),
    ]
    rows = []
    for i, (ip, port, score, level, summary, n) in enumerate(raw):
        rows.append(
            {
                "id": 9000 + i,
                "ip": ip,
                "local_port": port,
                "risk_score": score,
                "risk_level": level,
                "peak_score": score,
                "peak_level": level,
                "summary": summary,
                "event_ts": now_ms - (i + 1) * 90_000,
                "group_count": n,
                "geo": None,
            }
        )
    page._sug_rows = rows
    page._sug_rows_src = rows
    page._render_suggestions()


# 弹性列的最小宽度判据（02_ux_spec.md P0-2）。按表头文字指定，不按列序号 ——
# 列序调整（如「严重度永远第 2 列」）时判据不该跟着改。
ELASTIC_MIN = {
    "监控": {"请求": 150},
    "事件": {"路径": 150},
    "封禁建议": {"原因": 160},
    "封禁记录": {"原因": 180},
}

# 逐格省略检测：这些列一旦出现省略号就是缺陷（判据值 = 该列的「最差值」，
# 不依赖当前样本；实际还会和样本里最长的那条取较大者，样本换了也不会漏）。
# 路径 / 请求 / 原因 / 归属地 / 命中规则 / 服务器 允许 Qt elide，不在此表内。
NO_ELIDE = {
    "时间": "23:59:59",
    "风险": "严重",
    "等级": "严重",
    "端口": "18080",
    "协议": "HTTPS",
    "状态": "已封禁",
    "评分": "100",
    "ID": "9999",
    "时长": "永久",
    # 封禁记录表头是「到期时间 / 创建时间」。早先这里写的是「到期 / 创建」，
    # 键名与表头不一致 → 时间列从来没被这条判据检查过，于是 124px 把
    # `2026-10-20 09:27` 裁成 `09…` 一直没人发现。表头改名时这里必须跟着改。
    "到期时间": "2099-12-31 23:59",
    "创建时间": "2099-12-31 23:59",
    "到期": "2099-12-31 23:59",
    "创建": "2099-12-31 23:59",
}
# 同名列在不同表语义不同：监控的「状态」是 HTTP 状态码、事件页是处理状态、
# 记录页才是封禁状态 —— 共用一份最差值会把「200」误判成 3 个汉字（假阳性）。
NO_ELIDE_BY_TABLE = {
    ("监控", "状态"): "999",
    ("事件", "状态"): "未处理",
    # 事件页原「等级」列 2026-10-27 改名为「等级 / 命中规则」（规则名并进来），
    # 键名必须跟着改 —— 早先「到期 / 创建」就是这样失配过，那条判据空转了两版。
    ("事件", "等级 / 命中规则"): "严重",
    ("封禁记录", "状态"): "已封禁",
}
# 理论最差值但现实达不到（5 位封禁记录 ID 要攒 10 万条）：只 WARN，不判 FAIL
SOFT_WORST = {"ID": "99999"}
# 已知边界（视觉终验留档，暂不处理）：封禁记录 ID 列 48px 在 Consolas 下
# 「9999」正好需 28 = 可用 28，0 余量压线通过。若某机无 Consolas 回退到雅黑
# （数字更宽）4 位就会裁 —— 2008 R2 起 Consolas 是系统自带，风险低，且 ID 只是
# 序号、裁了不影响判断。真要处理时按「破 1 万条」一并做：ID 48→56、来源 76→62。
# 这两列由 QStyledItemDelegate 自绘 18px 徽章（不是文字），判据是
# 「徽章文字宽 + 左右 padding 12 ≤ 列宽」，用 elide 判会假阳性。
BADGE_COLUMNS = {"风险", "等级", "等级 / 命中规则"}
ELIDE_PAD = 20  # 20 = QSS 左右各 8（共 16）+ Qt 渲染实测损耗 4
# （1px item frame + 2px elide 给「…」的余量 + hinting 抖动）。
# ⚠️ 不要按 theme 的 16 改小：协议列 56px 时 HTTPS 实测会裁（8× 放大是 `HTT…`），
# 取 16 会算成 40≥37 → 假过，把真缺陷放过去。此值为实测标定，勿调小。


# 用户自定义文本列：允许省略（表格 tooltip 兜底），但超过可用宽时打 WARN。
# 绝不进 exit code —— 它是可变长文本，进硬门禁会逼后来者「加宽列」或「截断规则名」，
# 前者抢走「请求」的弹性空间，后者丢信息，两个方向都错。
# 2026-10-27：「命中规则」列并进「等级」列后本表为空 —— 规则名的宽度判据改由
# 下面的 check_badge_note 负责（它按徽章 + 规则名的整组宽度算）。
WARN_ON_ELIDE: tuple = ()
# WARN 收窄：同表同列只报一次、全局最多 3 条，避免一台机器上几十条长名刷屏
WARN_MAX = 3

# 「允许省略」的列（可变长语义文本）。前提是**有 tooltip 兜底**：省略本身可接受，
# 「省略了又没有途径看全文」才是缺陷 —— 命中规则/路径正是运维判断风险依据的字段。
# 这条是硬判据：它把「为了过门禁去加宽列」的歪路堵死，正确解法只剩补 tooltip。
ALLOW_ELIDE = ("请求", "路径", "原因", "归属地", "服务器")

# 徽章 + 规则名（事件页「等级 / 命中规则」列）的整组预算。
# 常量与 gui/widgets.py 的 BADGE_H_PAD / BADGE_GAP 对齐；最差规则名取
# 「管理端口归属地检测 +N」—— 单条最长 9 字 + 多条时的 `+N` 后缀。
BADGE_NOTE_ROLE = 2  # Qt.ItemDataRole.UserRole + 2
BADGE_LEFT = 10
BADGE_GAP = 8
BADGE_NOTE_WORST = "管理端口归属地检测 +3"
#: 已知带规则名的列（表里没有样本行时也得按这个判：0 行 ≠ 通过）
BADGE_NOTE_COLUMNS = {"等级 / 命中规则"}


def check_badge_note(table, name: str, width: int, headers: list, failures: list) -> None:
    """徽章右侧带规则名的列：整组（内距 + 徽章 + 间隙 + 规则名 + 内距）必须放得下。

    这条是 2026-10-27 加的：规则名从独立一列并进等级列后，一旦有人把等级列
    调窄，被截的就不是「一列长文本」而是**每一行的风险原因**，而且列表里
    看不出这是缺陷（省略号看起来很像「规则名本来就这么长」）。
    """
    from qtcompat import QFontMetrics, Qt

    for col, col_name in enumerate(headers):
        model = table.model()
        rows = model.rowCount() if model is not None else 0
        names = []
        has_role = False
        for r in range(min(rows, 60)):
            val = model.data(model.index(r, col), Qt.ItemDataRole.UserRole + BADGE_NOTE_ROLE)
            if val:
                has_role = True
                names.append(str(val))
        if not has_role and col_name not in BADGE_NOTE_COLUMNS:
            continue
        font = _cell_font(table, col)
        note_font = type(font)(font)
        note_font.setPixelSize(12)
        note_font.setBold(False)
        fm_note = QFontMetrics(note_font)
        # 判据取「样本里最宽的一条」与内置最差值中的宽者：按字符数比会被
        # 「判定风险：r-b8065e47」这类窄字符迷惑（14 字符但比 9 个汉字宽）。
        names.append(BADGE_NOTE_WORST)
        note = max(names, key=lambda s: fm_note.horizontalAdvance(s))
        note_px = fm_note.horizontalAdvance(note)
        pill = max(34, QFontMetrics(font).horizontalAdvance("严重") + 12)
        need = BADGE_LEFT + pill + BADGE_GAP + note_px + BADGE_LEFT
        avail = table.columnWidth(col)
        ok = need <= avail
        print(
            f"    {col_name}（徽章+规则名）: 规则「{note}」整组需{need}px 可用{avail}px"
            f" {'OK' if ok else '省略'}"
        )
        if not ok:
            failures.append(
                f'FAIL {width} {name} {col_name} 规则名放不下: "{note}" 需{need}px>可用{avail}px'
            )


def _cell_tooltip(table, row: int, col: int) -> str:
    """单元格 tooltip：QTableWidget 走 item.toolTip()，模型驱动表走 ToolTipRole"""
    from qtcompat import Qt

    if hasattr(table, "item"):
        item = table.item(row, col)
        if item is not None:
            return str(item.toolTip() or "")
    model = table.model()
    if model is None:
        return ""
    val = model.data(model.index(row, col), Qt.ItemDataRole.ToolTipRole)
    return "" if val is None else str(val)


def check_tooltip(table, name: str, width: int, headers: list, failures: list) -> None:
    """允许省略的列必须有 tooltip 兜底（每列报一次，行号取第一条违规）"""
    model = table.model()
    rows = model.rowCount() if model is not None else 0
    if not rows:
        print("    兜底检测: 无数据行，未覆盖（0 行 ≠ 通过）")
        return
    for col, col_name in enumerate(headers):
        if col_name not in ALLOW_ELIDE:
            continue
        bad = None
        for r in range(rows):
            if not _cell_tooltip(table, r, col).strip():
                bad = r
                break
        if bad is None:
            print(f"    {col_name}: tooltip 兜底 OK（{rows} 行）")
        else:
            failures.append(f"FAIL {width} {name} {col_name} 省略无兜底: row={bad}")


def _cell_font(table, col: int):
    """取该列实际生效的字体（FontRole 优先）—— 用 table.font() 会把
    「字体没覆盖」误报成「宽度不够」，反过来也识别不出根因。"""
    from qtcompat import Qt

    model = table.model()
    if model is not None:
        for r in range(min(model.rowCount(), 8)):
            font = model.data(model.index(r, col), Qt.ItemDataRole.FontRole)
            if font is not None:
                return font
    return table.font()


def _worst_text(table, col: int, default: str) -> str:
    """判据文字 = max(最差值常量, 样本里最长的一条)，按渲染宽度比较"""
    from qtcompat import QFontMetrics, Qt

    fm = QFontMetrics(_cell_font(table, col))
    worst = default
    model = table.model()
    if model is None:
        return worst
    for r in range(min(model.rowCount(), 60)):
        txt = model.data(model.index(r, col), Qt.ItemDataRole.DisplayRole)
        if txt is None:
            continue
        txt = str(txt)
        if fm.horizontalAdvance(txt) > fm.horizontalAdvance(worst):
            worst = txt
    return worst


def check_elide(table, name: str, width: int, headers: list, failures: list, warns: list) -> None:
    """逐列比对「最差值渲染宽度」与「可用内容宽度」，超了就报省略缺陷"""
    from qtcompat import QFontMetrics

    for col, col_name in enumerate(headers):
        default = NO_ELIDE_BY_TABLE.get((name, col_name)) or NO_ELIDE.get(col_name)
        if default is None:
            continue
        font = _cell_font(table, col)
        fm = QFontMetrics(font)
        text = _worst_text(table, col, default)
        need = fm.horizontalAdvance(text)
        col_w = table.columnWidth(col)
        if col_name in BADGE_COLUMNS:
            need += 12
            avail = col_w
        else:
            avail = col_w - ELIDE_PAD
        ok = need <= avail
        print(
            f"    {col_name}: 字体={font.family()} {font.pixelSize()}px "
            f"最差「{text[:20]}」需{need}px 可用{avail}px {'OK' if ok else '省略'}"
        )
        if not ok:
            failures.append(
                f'FAIL {width} {name} {col_name} 省略: "{text[:20]}" 需{need}px>可用{avail}px'
            )
        soft = SOFT_WORST.get(col_name)
        if soft:
            soft_need = fm.horizontalAdvance(soft) + (12 if col_name in BADGE_COLUMNS else 0)
            if soft_need > avail:
                warns.append(
                    f"WARN {name}.{col_name}「{soft}」需{soft_need}px>可用{avail}px（现实可达，仅提示）"
                )

    # 软判据：自定义文本列（命中规则）只用「当前数据里最长的一条」判，超了给 WARN
    for col, col_name in enumerate(headers):
        if col_name not in WARN_ON_ELIDE:
            continue
        fm = QFontMetrics(_cell_font(table, col))
        text = _worst_text(table, col, "")
        if not text:
            continue
        need = fm.horizontalAdvance(text)
        avail = table.columnWidth(col) - ELIDE_PAD
        tag = "OK" if need <= avail else "超宽"
        print(
            f"    {col_name}（自定义文本，仅提示）: 最长「{text[:12]}」需{need}px 可用{avail}px {tag}"
        )
        if need > avail:
            warns.append(
                f"WARN {name}.{col_name}「{text[:12]}」需{need}px>可用{avail}px"
                f"（可变长文本，建议在配置页限长而非加宽列）"
            )


def report_tables(win, width: int) -> bool:
    """体检主表：横滚必须为 0、弹性列 ≥ 下限、不该省略的列不得出现省略号。

    返回是否全部通过（供退出码用）。
    注意：`exit 0` 只代表这三类可机器判的缺陷不存在 —— 徽章底与斑马是否同色、
    徽章是否在 30px 行内垂直居中、focus 是否可见且零位移、横幅是否整条描边、
    状态列语义色，仍由视觉人工走查（无可靠机器判据，硬做会假阳性）。
    """
    from qtcompat import Qt

    print(f"--- {width}px 表格体检 ---")
    targets = (
        ("监控", win.page_monitor, "table"),
        ("事件", win.page_events, "table"),
        ("封禁建议", win.page_bans, "sug_table"),
        ("封禁记录", win.page_bans, "table"),
    )
    failures = []
    warns = []
    for name, page, attr in targets:
        table = getattr(page, attr, None)
        if table is None:
            failures.append(f"FAIL {width} {name}.{attr} 不存在")
            continue
        try:
            model = table.model()
            n = model.columnCount() if model is not None else 0
            headers = []
            for i in range(n):
                h = model.headerData(i, Qt.Orientation.Horizontal)
                headers.append("" if h is None else str(h))
            widths = [table.columnWidth(i) for i in range(n)]
            hbar = table.horizontalScrollBar().maximum()
            print(f"{name}.{attr}: 横滚={hbar} 列数={n} 列宽={widths} 合计={sum(widths)}")
        except Exception as exc:
            failures.append(f"FAIL {width} {name}.{attr} 读取失败 {type(exc).__name__}: {exc}")
            continue

        if hbar > 0:
            failures.append(f"FAIL {width} {name} 横向滚动条={hbar}>0")
        mins = ELASTIC_MIN.get(name, {})
        for col_name, min_w in mins.items():
            if col_name not in headers:
                failures.append(f"FAIL {width} {name} 找不到弹性列「{col_name}」（表头={headers}）")
                continue
            actual = widths[headers.index(col_name)]
            if actual < min_w:
                failures.append(f"FAIL {width} {name} {col_name}={actual}<{min_w}")
        try:
            check_elide(table, name, width, headers, failures, warns)
        except Exception as exc:
            failures.append(f"FAIL {width} {name} 省略检测失败 {type(exc).__name__}: {exc}")
        try:
            check_badge_note(table, name, width, headers, failures)
        except Exception as exc:
            failures.append(f"FAIL {width} {name} 规则名检测失败 {type(exc).__name__}: {exc}")
        try:
            check_tooltip(table, name, width, headers, failures)
        except Exception as exc:
            failures.append(f"FAIL {width} {name} 兜底检测失败 {type(exc).__name__}: {exc}")

    if warns:
        for line in warns[:WARN_MAX]:
            print(line)
        if len(warns) > WARN_MAX:
            print(f"（另有 {len(warns) - WARN_MAX} 条 WARN 未列出，仅提示不进退出码）")
    for line in failures:
        print(line)
    if failures:
        print(f"--- {len(failures)} 项未达标 ---")
    else:
        print(f"--- {width}px 表格体检全部通过 ---")
    print()
    return not failures


def main(argv=None) -> int:
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, root)

    ap = argparse.ArgumentParser(description="离屏渲染 PortGuard 7 个页面截图")
    ap.add_argument(
        "--width", type=int, default=1360, help="窗口宽度，默认 1360；走查 1200 档传 1200"
    )
    ap.add_argument("--height", type=int, default=820, help="窗口高度，默认 820")
    args = ap.parse_args(argv)

    from qtcompat import QApplication, QtGui

    app = QApplication(sys.argv)
    # 字体必须在 QApplication 之后加载，否则 QSS 的 font-family 已按 fallback 求值
    QtGui.QFontDatabase.addApplicationFont("C:/Windows/Fonts/msyh.ttc")

    import main as app_main

    app_main._init_backend()

    from gui.main_window import MainWindow

    win = MainWindow()
    win.resize(args.width, args.height)
    win.show()
    app.processEvents()

    seed_monitor(win)
    seed_bans(win)

    if args.width == 1360:
        out_dir = os.path.join(root, "_design", "after")
    else:
        out_dir = os.path.join(root, "_design", "after", f"w{args.width}")
    os.makedirs(out_dir, exist_ok=True)

    pages = [
        ("0_shell", None),
        ("1_monitor", 0),
        ("2_events", 1),
        ("3_access", 2),
        ("4_bans", 3),
        ("5_rules", 4),
        ("6_iplookup", 5),
        ("7_logs", 6),
        ("8_settings", 7),
    ]
    for name, idx in pages:
        if idx is not None:
            win._switch_page(idx)
            app.processEvents()
            app.processEvents()
        if idx == 3:
            # 站内切页会触发 refresh（按真实库重载，把上面灌的样本冲掉），
            # 所以样本必须在切页**之后**再灌一次，否则截图里是空表
            seed_bans(win)
            app.processEvents()
        path = os.path.join(out_dir, name + ".png")
        win.grab().save(path)
        print(f"{path}  {os.path.getsize(path)} bytes")

    print()
    return 0 if report_tables(win, args.width) else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
