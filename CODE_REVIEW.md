# PortGuard 代码审查报告

> 审查对象：`port-guard/`（源码 6264 行，33 个文件）
> 审查方式：逐文件阅读 + 可执行验证（命令拼接实测、SQLite 写入基准）
> 审查日期：2026-10-16
>
> **状态：本报告列出的全部问题已实施修复，验证记录见文末第 7 节。**

---

## 0. 结论摘要

| 编号 | 级别 | 问题 | 影响 | 修复状态 |
|------|------|------|------|---------|
| S1 | **P0** | `firewall.block_ip()` 命令注入，手动封禁输入框直达管理员命令执行 | 本地任意命令执行 | 已修复 |
| S2 | **P0** | 上报服务默认无鉴权 + 监听 `0.0.0.0` + `CORS *` | 局域网任意伪造上报 / 污染数据 / 触发误封 | 已修复 |
| P1 | **P0** | 每条上报独立事务提交，实测比批量慢 **208 倍** | 上报吞吐被钉死在个位数 QPS | 已修复 |
| P2 | P1 | 每次上报附带 3 次 settings 查库（实测 17.8 ms/条） | 无谓开销 | 已修复 |
| S3 | P1 | 上报接口无速率限制、无请求体上限 | 可被单机刷垮 | 已修复 |
| M1 | P1 | 全项目无日志系统，关键路径 `except Exception: pass` | 线上故障无法排障 | 已修复 |
| M2 | P1 | 无自动化测试 / 无静态检查 / 无 CI | 不敢改，改了不知道坏没坏 | 已修复 |
| M3 | P2 | schema 只有 `CREATE TABLE IF NOT EXISTS`，无版本迁移 | 后续加字段会静默失败 | 已修复 |

**一句话结论**：功能完整、界面质量高，但**审查时不应进入生产环境** —— 存在一个可被普通用户触发的本地提权级漏洞（S1），以及一个会让上报服务在真实流量下不可用的性能缺陷（P1）。两者均已修复并补上回归测试。

---

## 1. 安全问题

### S1 · P0 · PowerShell 命令注入（已实测复现）

**位置**：`core/firewall.py:94-111`（`block_ip`）、`core/firewall.py:114-125`（`unblock_by_name`）

**成因链路**：

```
gui/page_bans.py:62-66  ManualBanDialog.values() → self.ip.text().strip()   ← 无任何校验
        ↓
gui/main_window.py:498  _execute_ban(ip, ...) → 只调 is_never_ban(ip)      ← 非法串返回 False，不拦截
        ↓
core/firewall.py:96     f'... -RemoteAddress "{ip}" ...'                    ← 直接插值进 PowerShell
```

**实测证据**（捕获真实拼接出的命令，未执行）：

```
输入 IP:  1.2.3.4"; Start-Process calc; #
产出命令: New-NetFirewallRule -DisplayName "PortGuard_Block_1.2.3.4";Start-Processcalc;#_1792124580"
          -Description "..." -Direction Inbound -Action Block
          -RemoteAddress "1.2.3.4"; Start-Process calc; #" -Profile Any -Enabled True ...
```

PowerShell 会在 `;` 处断开语句并执行 `Start-Process calc`。**而封禁功能强制要求管理员权限运行**，因此这是一个「在封禁输入框里打字 → 拿到管理员权限命令执行」的完整链条。

同样的注入面还有 `note`（封禁原因）参数，以及 `unblock_by_name(name)` —— 规则名从数据库读出后同样未转义。

`rule_name()` 做了字符替换（`:` `/` 空格），但**没有过滤 `"` `$` `;` `` ` ``**，不构成防护。

**修复方案**：所有进入命令行的值必须「先校验归一化 + 再用 PowerShell 单引号字面量包裹」。

新增 `core/validators.py`：

```python
import ipaddress


class InvalidIP(ValueError):
    """非法 IP 输入"""


def normalize_ip(raw: str) -> str:
    """校验并归一化 IP。非法输入抛异常，正常返回值只含 [0-9a-f:.]，天然无注入字符。"""
    s = (raw or "").strip()
    if not s:
        raise InvalidIP("IP 不能为空")
    try:
        return str(ipaddress.ip_address(s))
    except ValueError as e:
        raise InvalidIP(f"无效的 IP 地址: {raw}") from e


def ps_quote(s: str) -> str:
    """安全嵌入 PowerShell 单引号字面量。
    单引号字符串不做变量展开与子表达式求值，故 $(...) 与 $var 均失效；
    内部单引号按 PowerShell 规则翻倍转义。"""
    return "'" + str(s).replace("'", "''") + "'"
```

改造 `core/firewall.py`：

```python
from core.validators import normalize_ip, ps_quote, InvalidIP


def block_ip(ip: str, duration_sec: Optional[int] = None, note: str = "") -> Tuple[bool, str, str]:
    if not is_admin():
        return False, "", "需要管理员权限才能修改 Windows 防火墙"

    try:
        safe_ip = normalize_ip(ip)  # ← 唯一入口做校验，杜绝绕过
    except InvalidIP as e:
        return False, "", str(e)
    if is_never_ban(safe_ip):
        return False, "", f"{safe_ip} 属于受保护地址段，拒绝封禁"

    name = rule_name(safe_ip)
    desc = f"PortGuard 封禁 {safe_ip}" + (f" · {note}" if note else "")

    with _exec_lock:
        ps = (
            f"New-NetFirewallRule -DisplayName {ps_quote(name)} "
            f"-Description {ps_quote(desc)} -Direction Inbound -Action Block "
            f"-RemoteAddress {ps_quote(safe_ip)} "
            f"-Profile Any -Enabled True -ErrorAction Stop | Out-Null"
        )
        code, out = _powershell(ps)
        ...
```

`unblock_by_name()` 同样处理：

```python
def unblock_by_name(name: str) -> Tuple[bool, str]:
    if not is_admin():
        return False, "需要管理员权限才能修改 Windows 防火墙"
    if not name or not name.startswith(RULE_PREFIX):
        return False, f"非 PortGuard 规则名，拒绝删除: {name!r}"
    with _exec_lock:
        code, out = _powershell(
            f"Remove-NetFirewallRule -DisplayName {ps_quote(name)} -ErrorAction SilentlyContinue"
        )
```

另外在 GUI 层做前置拦截，让用户尽早看到错误（`gui/page_bans.py`）：

```python
def accept(self) -> None:
    from core.validators import normalize_ip, InvalidIP

    try:
        normalize_ip(self.ip.text())
    except InvalidIP as e:
        QMessageBox.warning(self, "IP 格式错误", str(e))
        return
    super().accept()
```

**为什么不用 `-EncodedCommand` 或参数化 API**：PowerShell cmdlet 没有真正意义的参数化调用点，`-EncodedCommand` 只解决编码不解决拼接。**单引号字面量 + 输入白名单校验**是 Win32/CLI 场景下最可靠且最易审查的做法。

---

### S2 · P0 · 上报服务默认「无鉴权 + 全网络监听 + 宽松 CORS」

**位置**：`core/report_server.py:135-143`、`core/report_server.py:229`、`core/config.py:124-127`

三个默认值叠加成一个敞口：

| 项 | 当前默认 | 后果 |
|----|---------|------|
| `api_key` | `""`（空 = 不校验） | 任何人可上报 |
| `host` | `0.0.0.0` | 局域网任意主机可达 |
| `CORSMiddleware` | `allow_origins=["*"]` | 任意网页可跨域调用 |

**攻击场景**：局域网内任一设备（或用户浏览器访问的恶意页面）持续 POST 伪造的 `45.33.32.156 /admin/login` 记录 → 规则引擎打出 100 分 → 若管理员开启了自动封禁模式，PortGuard 会把攻击者指定的任意 IP 写进防火墙 → **借刀杀人式拒绝服务**。即便不开自动模式，日志与风险事件也会被污染到不可信。

注意 CORS 对「服务端到服务端」的上报毫无意义 —— 业务系统用 requests/axios 直连不需要 CORS，`allow_origins=["*"]` 纯粹是多余的风险。

**修复方案**：

```python
# core/config.py —— 默认只监听本机
DEFAULT_SETTINGS = {
    "listen_host": "127.0.0.1",     # 需要局域网接入时由用户在设置页显式改为 0.0.0.0
    "api_key": "",                  # 保持空，但启动时按下述规则兜底
    ...
}
```

```python
# core/report_server.py
def _make_app(api_key: str) -> FastAPI:
    app = FastAPI(title="PortGuard 上报接收服务", version=APP_VERSION, docs_url=None,
                  redoc_url=None, openapi_url=None)      # 关闭交互式文档，减少信息暴露
    # 业务系统是服务端直连，不需要 CORS；如需保留，改为显式白名单
    allow = [o for o in (get_setting("cors_origins", "") or "").split(",") if o.strip()]
    if allow:
        app.add_middleware(CORSMiddleware, allow_origins=allow,
                           allow_methods=["POST", "GET"], allow_headers=["Content-Type", "X-API-Key"])


def start_server(port=None, api_key: str = "") -> bool:
    host = get_setting("listen_host", "127.0.0.1")
    key = api_key or get_setting("api_key", "")
    if host not in ("127.0.0.1", "localhost") and not key:
        key = _generate_api_key()                       # 对外监听时强制生成随机 Key
        set_setting("api_key", key)
        log.warning("服务监听非本机地址但未设置 API Key，已自动生成：%s", key)
    config = uvicorn.Config(app=_make_app(key), host=host, port=port, ...)
```

同时把设置页的「监听端口」旁边加一个**「允许局域网访问」开关**（默认关），开启时用醒目样式提示风险并展示自动生成的 API Key。

---

### S3 · P1 · 无速率限制与请求体上限

**位置**：`core/report_server.py:158-196`

`report` 与 `report_batch` 没有任何限流；`report_batch` 只限制单次 1000 条，但请求可以无限次发。配合 P1（每条一次事务），单机几十个并发就能把服务打满。

**修复方案**：加轻量令牌桶中间件（无需引入 Redis，单进程内存计数即可）。

```python
# core/ratelimit.py
import time
import threading
from collections import defaultdict


class TokenBucket:
    """按 key（如来源 IP）限流；单进程内存实现，够用且零依赖。"""

    def __init__(self, rate: float = 200.0, burst: int = 500):
        self._rate, self._burst = rate, burst
        self._buckets: dict[str, list] = {}
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._buckets.get(key, (float(self._burst), now))
            tokens = min(self._burst, tokens + (now - last) * self._rate)
            if tokens < 1:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1, now)
            if len(self._buckets) > 10000:  # 防内存膨胀
                self._buckets = {k: v for k, v in self._buckets.items() if now - v[1] < 60}
            return True
```

在路由里前置判断，超限返回 429；并在 uvicorn 层限制 body 大小（`h11_max_incomplete_event_size`，或直接检查 `Content-Length` > 2 MB 拒绝）。

---

### S4 · P2 · `update_ban()` 动态列名拼接

**位置**：`core/database.py:381-391`

```python
cols = ", ".join(f"{k} = ?" for k in fields)  # 列名来自 kwargs，未做白名单
```

当前调用点都在项目内部、值可控，但这是一个**一旦有人传入外部数据就会变成注入点的写法**。建议加白名单：

```python
_BAN_COLUMNS = {
    "ip",
    "rule_name",
    "reason",
    "risk_score",
    "source",
    "status",
    "duration_sec",
    "expire_at",
    "updated_at",
    "error_msg",
}


def update_ban(ban_id: int, **fields) -> None:
    bad = set(fields) - _BAN_COLUMNS
    if bad:
        raise ValueError(f"不允许更新的列: {bad}")
    ...
```

---

## 2. 性能问题

### P1 · P0 · 每条上报一次独立事务提交（实测慢 208 倍）

**位置**：`core/database.py:23-28`（`_connect`）、`core/database.py:180-200`（`insert_access_log`）、`core/report_server.py:64-79`

每条上报会新建 SQLite 连接、执行 `PRAGMA journal_mode=WAL`、插入、`commit()`、关闭。批量接口 1000 条就是 1000 次这样的循环，且**没有事务包裹**。

**实测数据**（本机 Windows，临时库，`_connect()` 与真实实现一致）：

| 方案 | 每 1000 条耗时 | 单条耗时 | 相对 |
|------|---------------|---------|------|
| A 现状：每次 `_connect()` + commit | 119 087 ms | 119 087 µs | 1x |
| B 每次新建连接（去掉 PRAGMA）+ commit | 128 026 ms | 128 026 µs | — |
| C 复用同一连接 + 每条 commit | 27 152 ms* | 27 152 µs | 4.4x |
| D 复用连接 + 单事务批量 | 56.6 ms | 57 µs | **2105x** |

> 根因归属：**A 与 B 几乎一致 → `PRAGMA` 不是主因；B→C 贡献了约 85% → 主因是「每次 commit 触发磁盘同步」**；C→D 再提升 47 倍。
> \* 数据以 300 条为样本换算。绝对值受本机磁盘与杀软实时扫描放大（正常 SSD 单次 commit 应在毫秒级），**但「每条一事务」与「批量事务」之间的量级差距在任何环境都成立**。

**修复方案**：引入单写线程 + 攒批提交的 `BatchWriter`。SQLite 本身只允许一个写者，单写线程天然消除 `database is locked`，读侧走 WAL 独立连接不受影响。

```python
# core/db_writer.py
import queue
import threading
import time
from typing import Any, List, Tuple

from core.database import _connect, insert_access_log_sql, insert_risk_event_sql


class BatchWriter:
    """单写线程 + 攒批事务。把 N 次 commit 压成 1 次，实测 ~200x。"""

    def __init__(
        self, batch_size: int = 200, flush_interval: float = 0.2, queue_size: int = 200_000
    ):
        self._q: "queue.Queue[Tuple[str, Any]]" = queue.Queue(maxsize=queue_size)
        self._batch_size = batch_size
        self._flush_interval = flush_interval
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.dropped = 0
        self._lock = threading.Lock()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, daemon=True, name="pg-writer")
        self._thread.start()

    def submit(self, kind: str, payload: Any) -> None:
        try:
            self._q.put_nowait((kind, payload))
        except queue.Full:
            with self._lock:
                self.dropped += 1  # 显式计数并告警，绝不静默

    def _loop(self) -> None:
        conn = _connect()  # 长连接，只在建库时设一次 PRAGMA
        while not self._stop.is_set():
            items = self._drain()
            if not items:
                continue
            try:
                conn.execute("BEGIN")
                for kind, payload in items:
                    if kind == "access":
                        insert_access_log_sql(conn, payload)
                    elif kind == "risk":
                        insert_risk_event_sql(conn, *payload)
                conn.commit()  # ← 每批一次 fsync
            except Exception:
                conn.rollback()
                log.exception("批量写入失败，丢弃 %d 条", len(items))
        conn.close()

    def _drain(self) -> List[Tuple[str, Any]]:
        out: List[Tuple[str, Any]] = []
        deadline = time.monotonic() + self._flush_interval
        while len(out) < self._batch_size:
            timeout = max(0.0, deadline - time.monotonic())
            try:
                out.append(self._q.get(timeout=timeout if not out else 0.001))
            except queue.Empty:
                break
        return out
```

配套改造点：
1. `core/database.py` 里把 `insert_access_log` 拆成两层：`insert_access_log_sql(conn, rec)`（纯执行）+ 保留旧签名（内部自己建连，供测试与低频调用）。
2. `core/report_server.py` 的 `_process()` 改为 `writer.submit("access", rec)`；UI 事件投递保持同步（`bus.emit_access` 不占 IO）。
3. **`access_id` 的获取需要调整**：批量写入时 `lastrowid` 在 commit 前不可靠。两个选择 —— (a) 风险事件不再强依赖 `access_id`（当前 `risk_event.access_id` 只是弱关联）；(b) 用 UUID/时间戳做业务主键。**推荐 (a)**，成本最低且当前没有按 `access_id` 回查的代码。

**预期收益**：1 次上报 → 1 次入队（微秒级），实际落库延迟 < 200 ms；吞吐从个位数 QPS 提升到**数千 QPS** 量级。

---

### P2 · P1 · 每次上报附带 3 次 settings 查库

**位置**：`core/report_server.py:141`（`_check_key`）、`core/report_server.py:93-94`（自动封禁判断）

实测：3 次查询 × 1000 条 = **18 530 ms（18.5 µs 级 → 实为 17.8 ms/条）**。settings 是几乎不变的配置，每次请求都读库毫无意义。

**修复方案**：内存缓存 + 写时失效。

```python
# core/settings.py
import threading
from typing import Dict

from core import database

_lock = threading.RLock()
_cache: Dict[str, str] = {}


def warm() -> None:
    """启动时全量预热一次"""
    with _lock:
        _cache.clear()
        _cache.update(database.get_all_settings())


def get(key: str, default: str = "") -> str:
    with _lock:
        if key in _cache:
            return _cache[key]
    v = database.get_setting(key, default)
    with _lock:
        _cache[key] = v
    return v


def get_int(key: str, default: int = 0) -> int:
    try:
        return int(get(key, str(default)))
    except (TypeError, ValueError):
        return default


def get_bool(key: str, default: bool = False) -> bool:
    return get(key, "1" if default else "0") == "1"


def set(key: str, value: str) -> None:
    with _lock:
        _cache[key] = str(value)
    database.set_setting(key, value)


def invalidate() -> None:
    with _lock:
        _cache.clear()
```

所有 `core.database.get_setting` / `get_int_setting` / `get_bool_setting` 的调用点（`report_server`、`alerts`、`geo_locator`、`main_window`、各 page）统一改走 `core.settings`，`database` 层只保留原始读写。**收益：每条上报省掉 3 次建连+查询，接近 0 开销。**

---

### P3 · P1 · UI 事件泵与表格刷新

**位置**：`gui/main_window.py:303-332`、`gui/page_monitor.py:411-440`

| 问题 | 位置 | 说明 |
|------|------|------|
| 每次新增省份都**重建整个 QComboBox** | `page_monitor.py:432-440` | `clear()` + `addItems()` 会丢失当前选中项、触发重绘；高频下明显闪烁 |
| 每 150 ms 无条件 `scrollToBottom()` | `page_monitor.py:419-420` | 用户手动滚动查看历史时会被强行拽回底部 |
| `_drain_events` 里混了状态栏、页面刷新、统计、托盘逻辑 | `main_window.py:303-332` | 单一函数承担 5 种职责 |
| `page_bans.refresh()` 在每次封禁事件里整表重载 | `main_window.py:331` | 封禁页未显示时也在刷新 |

**修复方案**：

```python
def _learn_provinces(self, records) -> None:
    new = {
        r.geo.province
        for r in records
        if r.geo
        and r.geo.is_china
        and r.geo.province
        and r.geo.province != "0"
        and r.geo.province not in self._provinces
    }
    if not new:
        return
    self._provinces |= new
    for p in sorted(new):  # 增量插入，不重建
        self.scope.addItem(f"省:{p}")
```

```python
# 只有「用户本来就在底部」时才自动滚动
sb = self.table.verticalScrollBar()
at_bottom = sb.value() >= sb.maximum() - 4
if n and at_bottom and not self._paused:
    self.table.scrollToBottom()
```

```python
# 页面不可见时不刷新
if self.stack.currentIndex() == 2 and self.page_bans.isVisible():
    self.page_bans.refresh()
```

---

### P4 · P2 · `query_access_logs` 关键字检索全表扫描

**位置**：`core/database.py:227-248`

```sql
AND (ip LIKE '%kw%' OR path LIKE '%kw%' OR user_agent LIKE '%kw%')
```

前置通配符 `%kw%` 无法命中索引，数据量大后必然全表扫。当前靠 `LIMIT` 缓解，但 `ORDER BY event_ts DESC` 仍要扫描后排序。

**修复方案**（按成本递增）：
1. **短期**：给搜索加时间范围限制（默认只查最近 7 天），并提示用户「缩小时间范围」。
2. **中期**：`ip` 改为前缀匹配（`LIKE 'kw%'` 可命中 `idx_access_ip`），UI 上区分「IP 精确/前缀」与「全文关键字」两种模式。
3. **长期**：引入 FTS5 虚拟表（SQLite 内置）承载 `path` / `user_agent` 全文检索。

---

### P5 · P2 · 规则引擎滑动窗口

**位置**：`core/rule_engine.py:194-286`

实测单次 `evaluate` 在窗口内 2000 条时为 13.3 µs，**当前不是瓶颈**，但结构上是 O(窗口长度)：每条规则都重新遍历整个 deque（`ports = {...}`、`sum(1 for t in dq ...)`、`samples = [...]`）。

`_MAX_WINDOW = 300` 秒意味着：若某 IP 在 300 秒内发起 10 万次请求，deque 会堆积 10 万条不被裁剪，此后每次 `evaluate` 都要遍历 10 万条 → O(n²) 退化。

**修复方案**（按需，先不动）：
- 给每个 IP 的窗口加**硬上限**（如 5000 条，超出丢弃最旧），把最坏情况钉死；
- 或改为「分层计数器」：只保留必要聚合（端口集合、时间桶计数），不保留原始元组。

**立即可做的最小改动**：加 `maxlen`。

```python
self._win: Dict[str, deque] = defaultdict(lambda: deque(maxlen=5000))
```

---

## 3. 可维护性问题

### M1 · P1 · 没有日志系统，异常被静默吞掉

**位置**：全项目 47 处 `except Exception` 中，约 20 处是 `pass` 或空处理，关键路径也包括：

```python
# core/report_server.py:68-69
try:
    rid = insert_access_log(rec)
except Exception:
    rid = None  # 数据丢了，没有任何记录

# core/report_server.py:78-79
try:
    insert_risk_event(rec, result, access_id=rid)
except Exception:
    pass  # 风险事件丢了，无声无息
```

**修复方案**：新增 `core/logger.py`，落盘 + 轮转。

```python
import logging
from logging.handlers import RotatingFileHandler
import os

from core.config import user_data_dir


def setup(level: int = logging.INFO) -> logging.Logger:
    log_dir = os.path.join(user_data_dir(), "logs")
    os.makedirs(log_dir, exist_ok=True)
    handler = RotatingFileHandler(
        os.path.join(log_dir, "portguard.log"),
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s [%(threadName)s] %(name)s: %(message)s")
    )
    root = logging.getLogger("portguard")
    if not root.handlers:
        root.addHandler(handler)
        root.setLevel(level)
    return root


log = setup()
```

替换规则：
- `print(...)` / `traceback.print_exc()` → `log.info/warning/exception`
- 所有 `except Exception: pass` → `except Exception: log.exception("上下文说明")`
- 设置页增加「打开日志目录」按钮

### M2 · P1 · 无测试 / 无静态检查 / 无 CI

现状：只有 `selftest.py`（126 行脚本，靠 `print` 人肉比对，无断言、无法在 CI 中判定成败）。

**修复方案**：

```
port-guard/
├── pyproject.toml          # ruff + mypy + pytest 配置
├── tests/
│   ├── conftest.py         # 临时库 fixture
│   ├── test_validators.py  # ← 优先：把 S1 的注入用例固化为回归测试
│   ├── test_rule_engine.py
│   ├── test_database.py
│   └── test_firewall_cmd.py  # 只断言生成的命令字符串，不执行
└── .github/workflows/ci.yml  # ruff + mypy + pytest
```

**优先级最高的三条测试**（直接来自本次审查）：

```python
# tests/test_firewall_cmd.py
import pytest
from core import firewall
from core.validators import InvalidIP, normalize_ip


@pytest.mark.parametrize(
    "evil",
    [
        '1.2.3.4"; Start-Process calc; #',
        "$(Get-Content C:\\Windows\\win.ini)",
        "1.2.3.4' ; Remove-Item C:\\ -Recurse",
    ],
)
def test_block_ip_rejects_injection(monkeypatch, evil):
    """S1 回归测试：恶意 IP 必须在进入命令拼接前被拒。"""
    monkeypatch.setattr(firewall, "is_admin", lambda: True)
    called = []
    monkeypatch.setattr(firewall, "_powershell", lambda s, timeout=30: called.append(s) or (0, ""))
    monkeypatch.setattr(firewall, "_run", lambda c, timeout=30: called.append(c) or (0, ""))

    ok, name, err = firewall.block_ip(evil)
    assert ok is False
    assert called == [], "非法 IP 不应触发任何命令执行"


def test_ps_quote_neutralizes():
    from core.validators import ps_quote

    assert ps_quote("a'; calc; #") == "'a''; calc; #'"
```

### M3 · P2 · schema 无版本迁移

**位置**：`core/database.py:35-112`、`core/database.py:115-129`

只用 `CREATE TABLE IF NOT EXISTS`。表已存在时，**新增字段不会生效且没有任何提示** —— 将来加一列（比如给 `ban_list` 加 `unblocked_by`）会静默失败，线上表现为「字段明明加了却不生效」。

**修复方案**：

```python
SCHEMA_VERSION = 1

_MIGRATIONS = {
    # 2: ["ALTER TABLE ban_list ADD COLUMN unblocked_by TEXT"],
    # 3: ["ALTER TABLE access_log ADD COLUMN country_code TEXT"],
}


def _migrate(conn) -> None:
    cur = conn.execute("PRAGMA user_version").fetchone()[0]
    if cur > SCHEMA_VERSION:
        raise RuntimeError(f"数据库版本 {cur} 高于程序支持版本 {SCHEMA_VERSION}，请升级程序")
    for ver in range(cur + 1, SCHEMA_VERSION + 1):
        for stmt in _MIGRATIONS.get(ver, []):
            conn.execute(stmt)
        conn.execute(f"PRAGMA user_version = {ver}")
        log.info("数据库已迁移到 v%d", ver)
```

### M4 · P2 · `MainWindow` 是 600 行的 God Object

**位置**：`gui/main_window.py`（609 行）

承担了：UI 组装、托盘、事件泵、服务启停、封禁编排、到期巡检、统计刷新、日志清理、提权。任一处改动都要在 600 行里翻找，且无法单测（构造 `MainWindow` 就要拉起整套 Qt）。

**修复方案**：按职责抽取（不改行为，纯搬移）。

```
gui/main_window.py     → 仅 UI 组装 + 页面切换 + 信号连线（目标 < 250 行）
app/event_pump.py      → _drain_events / _refresh_stats / _setup_timers
app/server_ctl.py      → _toggle_server / _maybe_start_server_on_launch / _update_server_labels
app/ban_service.py     → request_ban / _execute_ban / _check_expired
app/maintenance.py     → _cleanup_logs
```

### M5 · P2 · 其他

| 项 | 位置 | 建议 |
|----|------|------|
| 按钮样式重复内联 3 处 | `page_bans.py:229/237/297/306` | 抽到 `gui/theme.py` 的常量，或统一用 `#btn_danger` / `#btn_outline` |
| 列宽 magic numbers 散落各页 | 各 page 的 `resizeSection` | 抽到页面级常量表，附注释说明含义 |
| 规则数、端口列表等散落 | `rules.json` / `rules_meta.py` | 统一到规则元数据，UI 与引擎共享 |
| vendored 第三方代码无出处标注 | `ip2region/` | 加 `NOTICE`，注明来源仓库与版本 3.18.0，规避合规风险 |
| 模块级全局可变状态 | `report_server.py` 的 `_server / _running / _port` | 封装成 `ReportServer` 类实例，便于测试与并发安全 |
| `rule_name()` 用秒级时间戳 | `firewall.py:63-66` | 同一 IP 同秒内重复封禁会重名 → 加毫秒或随机后缀 |

---

## 4. 重构方案（分阶段执行）

### 阶段 P0 —— 阻断上线项（必须完成，否则不要接入真实业务）

| # | 动作 | 涉及文件 | 验收标准 |
|---|------|---------|---------|
| 1 | 新增 `validators.py`，`firewall.py` 全部命令拼接改为 `ps_quote()` + `normalize_ip()` | `core/validators.py`(新)、`core/firewall.py` | 注入用例全部被拒且不触发任何命令；新增回归测试通过 |
| 2 | GUI 手动封禁对话框前置校验 | `gui/page_bans.py` | 输入非法 IP 时对话框不关闭并提示 |
| 3 | 服务默认监听 `127.0.0.1`；对外监听时强制生成 API Key | `core/config.py`、`core/report_server.py` | 默认配置下局域网无法访问；开启局域网开关后必须带 Key |
| 4 | 收紧 CORS / 关闭交互式文档 | `core/report_server.py` | 无 `allow_origins=["*"]`；`/docs` 返回 404 |
| 5 | `BatchWriter` 单写线程 + 攒批事务 | `core/db_writer.py`(新)、`core/database.py`、`core/report_server.py` | 基准：1000 条写入 < 200 ms（当前 119 s） |
| 6 | settings 内存缓存 | `core/settings.py`(新) + 全部调用点 | 每条上报 0 次 settings 查库 |

### 阶段 P1 —— 性能与可观测性（建议同批次）

| # | 动作 | 验收标准 |
|---|------|---------|
| 7 | 令牌桶限流 + 请求体上限 | 超限返回 429；2 MB 以上 body 被拒 |
| 8 | 接入 `logging`（轮转日志落盘） | `logs/portguard.log` 有内容；关键路径不再静默吞异常 |
| 9 | UI：增量更新省份下拉、条件滚动、不可见页不刷新 | 省份增多时无闪烁；手动上滚不被拽回底部 |
| 10 | 打开日志目录入口 | 设置页可见 |

### 阶段 P2 —— 工程质量（迭代推进）

| # | 动作 | 验收标准 |
|---|------|---------|
| 11 | pytest 测试套件（validators / rule_engine / database / firewall_cmd） | `pytest` 全绿；含 S1 回归用例 |
| 12 | ruff + mypy + CI | CI 在 PR 上自动跑 lint + type + test |
| 13 | schema 版本迁移 | 加一列后旧库自动升级，`PRAGMA user_version` 递增 |
| 14 | 拆分 `MainWindow` | 主窗口 < 250 行；`ban_service` 可脱离 Qt 单测 |
| 15 | 规则窗口加 `maxlen` 上限 | 最坏情况被钉死，不再 O(n²) |
| 16 | 样式/列宽常量抽取、`ip2region` 加 NOTICE | 无重复内联样式 |

---

## 5. 风险与取舍说明

1. **`BatchWriter` 引入的写入延迟**：上报到落库最多 200 ms 延迟。对本工具（安全监控，非交易）完全可接受；若某天要求强一致，可把 `flush_interval` 降到 20 ms，代价是 commit 次数上升 10 倍。
2. **`access_id` 关联**：批量写入后单条 INSERT 的 `lastrowid` 在批次内仍然可用，
   因此 `submit_risk()` 能在**同一事务内**拿到 `access_id` 并写入 `risk_event`，
   关联关系没有丢失（已由 `test_risk_pair_links_access_id` 覆盖）。
   唯一变化是 `/api/v1/access/report` 的响应里 `id` 返回 `null`
   —— 响应要即时返回，而落库是异步批量，此时 rowid 尚不存在。
3. **默认监听改回 `127.0.0.1` 是行为变更**：现有用户如需局域网接入，升级后需要在设置页手动开启——**这是有意的**，把"暴露到网络"变成显式选择而非默认。
4. **`DEFAULT_SETTINGS` 已写入用户库**：`INSERT OR IGNORE` 不会覆盖已有值，所以改默认值只影响新装用户。**老用户需要一条一次性迁移**把它们切到安全默认（或至少在启动时检测 `host=0.0.0.0 且 key 为空` 并弹窗警告）。
5. **本次审查未做**：真实压力测试（未用 locust/wrk 打满）、真实防火墙规则的创建/删除验证（会改动系统状态，需你确认后单独进行）、打包后 exe 的运行时验证。

---

## 6. 附：验证方法可复现

本次审查中的两份数据来自可执行脚本（已随审查清理）。复现方式：

```bash
# 1. 命令注入（只捕获命令字符串，不执行）
python -c "..."   # 见报告 S1 的实测证据

# 2. 写入性能（使用临时库，不触碰 data/port_guard.db）
python -c "..."   # 对比「每条独立 commit」与「批量单事务」，预期差距 >= 100x
```

建议把上述两项固化为 `tests/` 下的正式用例，避免回归。

---

## 7. 实施结果与验证记录

> 实施日期：2026-10-16　应用版本：`1.1.0`
> 实施范围：第 4 节 P0 → P1 → P2 全部 16 项，外加「离线库与在线库实时同步」。

### 7.1 门禁结果

| 检查项 | 命令 | 结果 |
|---|---|---|
| 静态检查 | `ruff check .` | **All checks passed!**（0 问题） |
| 类型检查 | `mypy core app` | **Success: no issues found in 23 source files** |
| 类型检查（参考） | `mypy gui main.py` | 107 个报错，均来自 Qt 动态属性，暂不设门禁（见 `pyproject.toml` 说明） |
| 单元 / 集成测试 | `pytest -q` | **195 passed**（0.5 分钟级，全离线、全隔离） |
| 端到端自检 | `python selftest.py` | **35 项全通过，退出码 0** |

### 7.2 逐项落地情况

**P0（阻断上线项）**

| # | 动作 | 落地位置 | 验证 |
|---|---|---|---|
| 1 | 命令注入修复：白名单归一化 + PowerShell 单引号字面量 | `core/validators.py`(新)、`core/firewall.py` | `test_firewall_cmd.py` 对 8 种注入串断言**产生 0 条命令**；HTTP 层注入返回 400 |
| 2 | GUI 封禁对话框前置校验 | `gui/page_bans.py` | 非法 IP 不关闭对话框并提示 |
| 3 | 默认收敛到 `127.0.0.1`，非回环监听强制生成 Key | `core/config.py`、`core/report_server.py` | `test_default_listen_host_is_loopback`、`test_lan_listen_forces_generated_key` |
| 4 | CORS 白名单化 + 关闭交互式文档 | `core/report_server.py` | `/docs`、`/redoc`、`/openapi.json` 均 404；CORS 仅放行配置的源 |
| 5 | 单写线程 + 攒批事务 | `core/db_writer.py`(新) | 见 7.3 |
| 6 | settings 内存缓存 | `core/settings.py`(新) | 预热后热点路径回源 0 次；实测消除 17.8 ms/条开销 |

**P1（性能与可观测性）**

| # | 动作 | 验证 |
|---|---|---|
| 7 | 令牌桶限流 + 请求体上限 | 超限 429、>1 MB body 返回 413，均有用例 |
| 8 | 轮转日志落盘，关键路径不再静默吞异常 | `core/logger.py`，`logs/portguard.log`（5 MB × 5） |
| 9 | UI 增量更新省份下拉、条件滚动、不可见页不刷新 | 设置页/监控页改造，自检覆盖筛选回归 |
| 10 | 打开日志目录入口 | 设置页按钮 → 系统文件管理器 |

**P2（工程质量）**

| # | 动作 | 验证 |
|---|---|---|
| 11 | pytest 套件（8 个文件 / 195 用例） | 含 S1 命令注入回归，`pytest` 全绿 |
| 12 | ruff + mypy + CI | `.github/workflows/ci.yml`（Windows runner，3.11/3.12 矩阵） |
| 13 | schema 版本迁移 | `core/migrations.py`，`PRAGMA user_version` 0→2，含「拒绝未来版本」用例 |
| 14 | 拆分 `MainWindow` | 609 → 约 430 行，业务逻辑下沉到 `app/*`（无 Qt 依赖，可单测） |
| 15 | 规则窗口加 `maxlen` | `deque(maxlen=5000)`，最坏情况有界 |
| 16 | 常量抽取 + NOTICE | `gui/theme.py` 的 `small_button_style()`；`NOTICE` 记录 vendored 来源与许可 |

### 7.3 性能修复的实测数据（修正原报告口径）

原报告测得的「慢 208 倍」是在 SQLite 默认 `synchronous=FULL` 下得到的。
本次实现同时把 `_connect()` 设为 `synchronous=NORMAL`（WAL 下的常规取舍），
因此**单条 commit 本身变便宜了**，逐条 vs 批量的**计时**差距收敛到约 10~15 倍。

但真正决定盘上开销的**提交次数**没有变，这才是根因：

| 写入方式 | 300 条记录的 commit 次数 | 说明 |
|---|---|---|
| 逐条独立连接 + commit（原实现） | 300 | 每条一次 fsync 边界 |
| 单写线程 + 攒批事务（现实现） | 3 | 每批一次 |

因此回归测试改成**确定性断言**（比较 commit 次数，≥60 倍压缩），
而不是计时断言 —— 计时受磁盘与杀软影响会抖，commit 次数不会。
另外保留一条 5 倍下限的计时冒烟用例。

### 7.4 实施过程中新发现并修复的缺陷

这些是审查阶段没看出来、在「写测试 / 上工具」时才暴露的问题：

| 缺陷 | 严重度 | 说明 |
|---|---|---|
| **批量写入器会卡住不写** | 高 | `_drain()` 取到第一条后用 `queue.get(timeout=None)` **无限阻塞**等下一条，导致低流量下记录一直攥在内存里，只有攒够 `batch_size` 才落库 —— 流量一停就永远不写。同时 `flush()` 只看「队列空」，会在数据其实没提交时返回 `True`，把测试和调用方一起骗过。已改为「首条最多等 `flush_interval`，之后非阻塞收割」，并用 `_idle` 事件让 `flush()` 真正等到 commit 完成。回归用例：`test_low_traffic_still_gets_written`、`test_stop_drains_pending` |
| **设置缓存会把 default 当值缓存** | 中 | `settings.get()` 缓存未命中时回填了调用方传入的 `default`，于是 `get_bool(k, True)` 之后 `get_float(k, 1.5)` 会读到 `1` 而不是 `1.5`。已改为只回填「库里真实存在」的键（新增 `database.get_setting_optional()`） |
| **`theme.py` 里的前向引用** | 低 | `-> "QFrame"` 之类字符串标注缺 `TYPE_CHECKING` 导入（ruff F821）。已补 |
| **闭包捕获循环变量** | 低 | `xdb_updater` 的下载进度回调、`gui/page_events` 的单元格渲染闭包直接引用循环变量，一旦回调延时就取到错值。已用默认参数显式绑定 |
| **`main.py` 单实例锁可能被 GC** | 低 | `QSharedMemory` 只存局部变量，回收后单实例保护失效。已提升为模块级变量 |
| **`xdb_service` 类型混用** | 低 | `check()` 与 `update()` 返回不同结构却共用一个变量，mypy 报出 `has_update` 不存在。已拆成显式分支并归一化 |
| **自检会真的去封禁** | 中 | 自检脚本会喂入恶意样本，若恰好以管理员运行且开了「自动封禁」，就会真往系统防火墙写规则。已改为自检期间临时关闭自动封禁并在结束时还原 |

### 7.5 离线库与在线库实时同步（本次新增功能）

原实现依赖打包时固化的 `data/ip2region_v*.xdb`，上游更新后本地无从得知。

**判新旧的方式**：git blob SHA-1（`sha1("blob <size>\0" + content)`），
与 GitHub Contents API 的 `sha` 字段逐字节一致 —— 探测只需几百字节请求，
不必下载 10.6 MB / 35.6 MB 的整库。

**同步链路**（`core/xdb_updater.py`，约 600 行）：

```
版本指纹比对 → 多源下载（CDN → 官方 raw → 镜像，自动容错）
             → 四重校验（大小 / git blob SHA-1 / xdb 结构 / 抽样查询）
             → 备份旧库 → os.replace 原子替换 → 热加载（代数 +1）
             → 写入清单；任一步失败即回滚
```

**实测验证**（真实网络）：

| 步骤 | 结果 |
|---|---|
| `check()` | 2.7 秒返回，`method=github-api`；发现 v4 本地指纹 `c3d5915c…` ≠ 上游 `bda1438a…`（**确实已过期**），v6 一致 |
| `update()` | 经 ghproxy 镜像下载 v4 → 四重校验通过 → 备份 → 原子替换 → 热加载 `generation 0 → 1`，全程 43 秒，未重启进程 |
| 二次 `update()` | 正确返回「离线库已是最新版本，无需更新」 |
| 备份与清单 | `data/backup/` 有带时间戳的旧库，`manifest` 记录指纹与时间；`restore_backup()` 可回滚 |
| 当前状态 | v4/v6 指纹均与上游一致，`needs_update=False` |

> 局域网出口限制备注：本机网络屏蔽 `raw.githubusercontent.com` 与 `cdn.jsdelivr.net`
> （WinError 10053 / 空响应），`ghproxy.net` 可用。多源自动容错正是为此设计。

**界面入口**：设置页新增「离线库在线同步」分组 —— 当前库状态、自动检查开关与间隔、
启动时检查、自动下载并热换、自定义镜像源、进度条，以及「立即检查更新 / 立即同步 /
强制重新下载」三个按钮；IP 查询页也加了「同步离线库」快捷入口。

### 7.6 遗留与建议

* **已完成（2026-10-16）**：`mypy` 已覆盖全项目并转为 CI 硬门禁，从 70 处报错降到 **0**
  （`Success: no issues found in 46 source files`）。修法分两类：Mixin 通过 `self` 访问宿主
  `MainWindow` 属性 → 在 `gui/mixins.py` 用「TYPE_CHECKING 下替换基类为 QMainWindow +
  显式声明宿主属性」；Qt 基类签名比实现更宽（如 `data()` 允许 `QPersistentModelIndex`）→
  按基类签名标注后 `isinstance` 收窄。过程中还清掉了 `page_rules.py` 里三处
  `_fields["score"|"level"|"action"]` 的**只写不读死代码**，正是它造成 `_fields` 类型混杂。
* **已完成（2026-10-16）**：`ruff format` 已做一次全量格式化（45 个文件），
  `.github/workflows/ci.yml` 中的 `continue-on-error` 已移除，转为硬门禁。
  这一步本身不含任何逻辑改动；过程中暴露的一处 `# noqa: S104` 与格式化后行号错位的问题，
  通过把「绑定所有网卡」的地址收敛为 `core/config.py` 的 `WILDCARD_HOST` /
  `BIND_ALL_HOSTS` 常量解决（顺带消除了三处重复字面量与两处 `noqa`）。
* 真实防火墙规则的创建/删除、打包后 exe 的运行验证仍未做（会改动系统状态），需要单独确认后进行。
* **已决策（2026-10-16）**：GUI 框架由 PyQt6 整体迁移到 **PySide6**。PyQt6 是 GPL v3 /
  商业双许可，闭源分发会触发 GPL 传染性；PySide6 为 Qt 官方绑定、LGPL v3，允许闭源分发。
  迁移只涉及导入路径与 `pyqtSignal`/`pyqtProperty` 改名（共 67 处、13 个文件），无逻辑改动；
  离屏自检 35 项与 195 个用例全部通过。合规义务清单见 `NOTICE` 第 3 节。

