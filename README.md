# PortGuard 端口访问防御工具

Windows 桌面端「端口访问防御工具」：**业务系统把访问记录上报给本工具 → 本工具用离线 IP 库识别来源归属地 → 规则引擎打分 → 给出封禁建议 → 人工确认后写入 Windows 防火墙**。

基于本仓库（ip2region 3.18.0）自带的离线 IP 定位库与 Python 查询客户端实现，**IP 归属地查询全程离线，不依赖任何外部服务**。

---

## 一、快速开始

```bat
:: 1) 首次安装依赖（已安装可跳过）
install.bat

:: 2) 普通权限启动：仅监控 + 生成封禁建议
start.bat

:: 3) 管理员权限启动：启用封禁 / 解封功能
start_as_admin.bat
```

或直接用虚拟环境运行：

```bat
C:\Users\Administrator\.workbuddy\binaries\python\envs\portguard\Scripts\python.exe main.py
```

> `install.bat` 读的是 `requirements.txt`，其中 GUI 依赖写的是 **PySide6-Essentials**
> （Qt 官方绑定，LGPL v3，允许闭源分发）。**不要**再手工 `pip install PySide6` ——
> 完整版会额外拉入 Addons / WebEngine / Pdf 约 380 MB，本项目一个都用不到。
> 两个包的导入路径相同，都是 `PySide6.*`。

---

## 二、让业务系统上报访问记录

工具启动后内置一个 HTTP 接收服务，**默认只监听 `127.0.0.1:18080`**（仅本机业务系统可上报）。
需要局域网内其它机器上报时，到「设置 → 接收服务」打开「允许局域网访问」——
此时会**强制要求 API Key**（界面会自动生成一个，复制到业务系统的 `X-API-Key` 请求头）。

> 为什么不默认监听 `0.0.0.0`：上报接口可以直接影响封禁决策。若暴露在局域网且无鉴权，
> 内网任意主机都能伪造上报把某个 IP 的规则打到满分，进而「借 PortGuard 之手」封掉它。
> 因此默认收敛为本机，局域网访问必须显式开启并带 Key。

### 接口

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/v1/access/report` | 单条上报（返回本次风险判定） |
| POST | `/api/v1/access/batch` | 批量上报（单次 ≤ 1000 条） |
| GET | `/api/v1/health` | 健康检查（含写入器与限流状态） |
| GET | `/api/v1/version` | 版本 / 规则数 / 监听端口 |
| GET | `/api/v1/banned/{ip}` | 查询某 IP 是否处于封禁中 |
| POST | `/api/v1/rules/reload` | 让服务重载规则文件 |

鉴权：设置了 API Key 后，所有接口都要求请求头 `X-API-Key: <key>`，不匹配返回 401。
限流：默认每 IP 300 次/秒、突发 600（设置页可调，`0` 表示关闭），超限返回 429。
请求体：默认上限 8 MB，超限返回 413。
`/docs`、`/redoc`、`/openapi.json` 均**已关闭**（减少信息暴露面）。

### 请求体

```json
{
  "ip": "113.118.113.77",
  "remote_port": 54321,
  "local_port": 3000,
  "protocol": "http",
  "method": "POST",
  "path": "/admin/login",
  "status_code": 401,
  "user_agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
  "bytes": 512,
  "timestamp": "2026-10-16T10:15:00+08:00",
  "host": "api.example.com",
  "server_name": "xcl-pos",
  "tags": {"biz": "order", "trace_id": "abc123"}
}
```

* 必填：`ip`、`local_port`
* `timestamp` 支持 ISO8601（带或不带时区）与 epoch 毫秒 / 秒；不传则用服务端接收时间
* 若配置了 API Key，需带请求头 `X-API-Key: <你的密钥>`

### 响应

```json
{"success": true, "data": {"id": 1287, "ip": "113.118.113.77",
 "geo": "中国·广东省·深圳市·电信", "risk_score": 0, "risk_level": "normal",
 "matched_rules": [], "suggest_ban": false}}
```

### curl 示例

```bash
curl -X POST http://127.0.0.1:18080/api/v1/access/report \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"45.33.32.156\",\"local_port\":8080,\"method\":\"POST\",\"path\":\"/admin/login\",\"status_code\":401,\"user_agent\":\"sqlmap/1.7\"}"
```

### 业务系统接入（Python，见 `examples/report_client.py`）

要点：**上报失败绝不能影响业务主流程**，务必加超时并吞掉异常。

```python
import datetime
import requests

PORTGUARD_URL = "http://127.0.0.1:18080/api/v1/access/report"


def report_access(
    client_ip, local_port, path, status_code, user_agent="", method="GET", server_name="xcl-pos"
):
    try:
        requests.post(
            PORTGUARD_URL,
            json={
                "ip": client_ip,
                "local_port": local_port,
                "protocol": "http",
                "method": method,
                "path": path,
                "status_code": status_code,
                "user_agent": user_agent,
                "bytes": 0,
                "server_name": server_name,
                "timestamp": datetime.datetime.now().astimezone().isoformat(),
            },
            timeout=1.0,
        )
    except Exception:
        pass  # 熔断：上报失败不影响业务
```

---

## 三、内置风险规则

规则可在界面「规则配置」页启停与调参，保存后即时生效；也可直接编辑 `data/rules.json`。

| 规则 | 触发条件（默认） | 分值 | 等级 |
| --- | --- | --- | --- |
| 黑名单命中 | 来源 IP 在黑名单中 | 100 | 严重 |
| 端口扫描 | 同 IP 30 秒内访问 ≥15 个不同端口 | 80 | 严重 |
| 敏感路径爆破 | 60 秒内 `/admin`、`/login` 等敏感路径返回 401/403 ≥10 次 | 70 | 高 |
| 境外访问管理端口 | 归属地在境外且访问 22/3389/1433/3306/6379/8080 等 | 65 | 高 |
| 高频请求 | 同 IP 10 秒内请求 ≥50 次 | 60 | 高 |
| 扫描器特征 | UA 为空或命中 nmap / sqlmap / masscan / nikto / curl 等 | 45 | 中 |
| 错误风暴 | 60 秒内 4xx+5xx 占比 ≥70% 且样本 ≥20 | 40 | 中 |
| 异常 HTTP 方法 | TRACE / PUT / DELETE / CONNECT / PATCH | 30 | 低 |
| 超大请求体 | 单次请求体 ≥5 MB | 25 | 低 |

评分映射：`≥90 严重` / `≥65 高` / `≥40 中` / `≥20 低`，多规则命中累加，单条封顶 100。
`高` 与 `严重` 会生成**封禁建议**（不自动执行，除非手动开启「自动模式」）。

**白名单优先**：命中白名单的 IP 直接豁免且永不封禁。内网 / 回环 / 保留地址段（`127.0.0.0/8`、`192.168.0.0/16`…）受硬保护，永远无法被封禁。

---

## 四、离线 IP 库的在线同步（保持与上游同步）

离线库（`data/ip2region_v4.xdb` / `ip2region_v6.xdb`）会随上游仓库更新，
本工具内置**在线同步**能力，可以在不重启、不重装的前提下把离线库换成最新版。

**判新旧的方式（关键设计）**：用 git blob SHA-1 做内容指纹比对 ——
`sha1("blob <size>\0" + 文件内容)`，与 GitHub Contents API 返回的 `sha` 逐字节一致。
所以「探测是否有新版本」只需要几百字节的请求，**不需要下载整个库**
（v4 约 10.6 MB、v6 约 35.6 MB）。

**同步流程**（任一步失败都不动正式库）：

```
版本指纹比对  →  多源下载（CDN → 官方 → 镜像，自动容错）
             →  四重校验：文件大小 / git blob SHA-1 / xdb 结构 / 抽样查询
             →  备份旧库到 data/backup/
             →  原子替换（os.replace，同盘原子）
             →  热加载新库（代数 +1，无需重启进程）
```

* 失败自动回滚到旧库；正在进行的上报不受影响（新老 searcher 都是只读内存对象）
* 界面入口：「设置 → 离线库在线同步」有 **立即检查更新 / 立即同步 / 强制重新下载**，
  以及自动检查（可设间隔，默认 24 小时）、启动时检查、自动下载并热换三个开关
* 进度通过事件总线推到界面（进度条 + 阶段文案），全程不阻塞 UI
* 可将下载源换成自定义镜像（必须是 https 且在白名单主机内，防 SSRF）
* 命令行验证：

```bat
python -c "from core import xdb_updater as U; c=U.check(); print(c.method, c.message)"
```

---

## 五、封禁机制

* 仅操作**以 `PortGuard_Block_` 为前缀**的自有规则，不会误伤系统或第三方规则
* 优先 `New-NetFirewallRule`（原生支持 IPv6），失败自动回退 `netsh advfirewall`
* 规则命名：`PortGuard_Block_<IP>_<毫秒时间戳>_<随机后缀>`（同毫秒重复封禁也不会重名）
* **所有拼进命令行的值都先过 `core.validators`**：IP 先做白名单归一化，文本走
  PowerShell 单引号字面量。非法输入直接拒绝，**不会产生任何命令**
* 支持封禁时长与到期自动解封（每分钟巡检）
* 「与防火墙对账」按钮可清理数据库中已失效的记录
* 需要管理员权限；普通权限下监控与判定照常，封禁按钮不生效并给出提示

---

## 六、界面

| 页面 | 作用 |
| --- | --- |
| 实时监控 | 实时访问流水（时间 / IP / 归属地 / 端口 / 路径 / UA / 命中规则 / 风险），统计卡片、多维筛选、右键快捷操作 |
| 风险事件 | 命中规则的记录，可按等级与处理状态筛选，支持确认 / 忽略 / 一键封禁 |
| 封禁管理 | 待确认建议区 + 已封禁列表，手动封禁、解封、一键全部解封、防火墙对账 |
| 规则配置 | 9 条规则可视化启停调参 + 黑 / 白名单（支持 CIDR）编辑 |
| IP 查询 | 单条 / 批量归属地查询，支持 IPv4 + IPv6，可导出 CSV |
| 设置 | 接收服务（端口 / 局域网开关 / API Key）、离线库在线同步、封禁策略、限流、告警、数据保留 |

界面截图见 `screenshots/`。

---

## 七、项目结构

```
port-guard/
├── main.py                 程序入口（后端先就绪 → 单实例保护 → 托盘常驻）
├── selftest.py             离屏端到端自检（真实环境冒烟，37 项检查）
├── pyproject.toml          ruff / mypy / pytest 统一配置（工程规范的锚点）
├── NOTICE                  第三方代码与数据来源、许可说明
├── .github/workflows/ci.yml  CI：ruff check + ruff format + mypy + pytest 四道门禁
├── requirements.txt        运行时依赖
├── requirements-dev.txt    开发依赖（pytest / ruff / mypy / httpx）
├── install.bat / start.bat / start_as_admin.bat
├── app.manifest            PyInstaller 用的管理员权限清单
├── port_guard.spec         PyInstaller 打包配置
├── assets/                 图标等资源
├── data/                   运行时数据（xdb 库、rules.json、名单、db、backup/、download/）
├── ip2region/              内置的 ip2region Python 客户端（vendored，上游 Apache-2.0）
├── core/
│   ├── config.py           路径与常量（含离线库同步的源与白名单）
│   ├── logger.py           工作日志（按天滚动 + 5MB 兜底 + 保留天数可配）
│   ├── validators.py       输入校验与命令安全（IP 归一化 / PowerShell 单引号转义）
│   ├── models.py           领域模型
│   ├── database.py         SQLite 数据层（WAL + 迁移入口 + 批量插入 SQL）
│   ├── migrations.py       schema 版本迁移（PRAGMA user_version）
│   ├── settings.py         设置内存缓存（写穿透）
│   ├── db_writer.py        单写线程 + 攒批事务写入器
│   ├── geo_locator.py      归属地查询（整库入内存 + LRU + 热换库）
│   ├── rule_engine.py      规则引擎（滑动窗口 + 评分）
│   ├── ratelimit.py        令牌桶限流
│   ├── firewall.py         Windows 防火墙执行器
│   ├── report_server.py    FastAPI 上报接收服务
│   ├── xdb_updater.py      离线库在线同步（指纹比对 / 下载 / 校验 / 回滚）
│   ├── alerts.py           托盘 / 声音 / 弹窗告警
│   └── event_bus.py        跨线程事件总线
├── app/                    无 Qt 依赖的业务层（供 GUI 与测试共用）
│   ├── ban_service.py      封禁唯一校验入口与执行流程
│   ├── xdb_service.py      离线库同步的后台调度
│   ├── server_ctl.py       上报服务启停
│   └── maintenance.py      日志 / 备份 / 临时文件清理
├── gui/                    PySide6 界面（主题 / 主窗口 + mixins / 6 个页面 / 通用控件）
├── tools/                  真实环境验证脚本（自行请求提权，不改动仓库状态）
│   ├── verify_firewall.py  真实防火墙「封禁 → 解封」全链路
│   ├── verify_exe.py       打包产物运行验证（--selfcheck + 正常启动）
│   └── check_dll_deps.py   静态核对产物依赖闭包（找「缺哪个 DLL」）
└── tests/                  pytest 用例（隔离环境，全离线）
```

---

## 八、技术要点

* **线程模型**：Qt 主线程（唯一可操作控件）+ uvicorn 后台线程 + 规则评估 +
  批量写入线程 + 防火墙子进程。后台线程只往队列投递事件，主线程用定时器批量消费，
  从根上避免跨线程崩溃
* **写入路径**：每条上报都丢进 `BatchWriter` 队列，由唯一的写线程按批（默认 200 条 / 200ms）
  提交。SQLite 只允许一个写者，单写线程同时消除了 `database is locked`
* **设置读取**：`core.settings` 进程内缓存 + 写穿透，上报热点路径不再查库
  （原实现每条上报查 3 次 settings 表）
* **命令安全**：所有进命令行的值先经 `core.validators` 白名单归一化 +
  PowerShell 单引号字面量包装（`$(...)`、反引号、`;` 全部失效）
* **归属地查询**：启动时一次性校验 xdb，整库读入内存后用 `new_with_buffer`
  构造无状态 Searcher（线程安全、可全局共享），实测加载约 60ms、单次查询微秒级；
  支持在线同步后**热换库**（代数 +1，不重启进程）
* **时间统一存 epoch 毫秒** 用于滑动窗口计算，展示层再转本地时间
* **SQLite 开启 WAL + `synchronous=NORMAL`**：读侧短连接，写侧单长连接；
  NORMAL 是 WAL 下的常规取舍（极端断电可能丢最后几批日志，但不会损坏库）
* **高频爆发保护**：事件队列满时丢弃最旧数据；表格批量刷新 + 5000 行环形缓冲，
  滑动窗口按 IP 限长（`deque(maxlen=5000)`）避免内存无界增长

---

## 九、测试与自检

### 单元 / 集成测试（CI 门禁）

```bat
python -m pytest -q                 :: 全部用例
python -m pytest -q --cov           :: 带覆盖率
```

用例全部**离线、隔离**运行：`tests/conftest.py` 把 `config.project_dir()` 指到临时目录，
只有读内置 xdb 与 rules.json 时才映射回真实 `data/`（只读），
因此跑测试绝不会碰你的数据库、备份和日志。

覆盖重点：

| 文件 | 覆盖内容 |
| --- | --- |
| `test_validators.py` | IP 归一化、PowerShell 转义、URL 白名单边界 |
| `test_firewall_cmd.py` | **S1 命令注入回归**：恶意输入必须产生 0 条命令 |
| `test_db_writer.py` | 攒批写入、commit 次数、低流量落库、停止时排空 |
| `test_core_infra.py` | 设置缓存、令牌桶、schema 迁移、老库安全收敛 |
| `test_rule_engine.py` | 各规则触发与不触发、窗口隔离、白名单豁免 |
| `test_geo_and_xdb.py` | 定位器、热换库、指纹计算、下载四重校验、备份回滚 |
| `test_ban_service.py` | 封禁校验入口、内网硬保护 |
| `test_report_server.py` | 默认收敛、鉴权、限流、请求体上限、CORS、错误处理 |
| `test_logger_startup.py` | **无控制台启动回归**（std 流为 None）、启动失败归因、日志按日期清理 |

### 端到端自检（真实环境冒烟，交付前跑）

```bat
python selftest.py
```

覆盖：后端初始化 → 设置缓存 → 定位库 → **在线同步模块** → 正常/恶意判定 →
批量落库 → 主窗口与 6 个页面 → 筛选回归 → 封禁校验（拒绝注入 / 内网保护）→
服务启停与真实 HTTP 接口 → **无控制台启动回归** → 日志清理 → 统计。全部通过时退出码为 0。

> 自检会临时关闭「自动封禁」并在结束时还原，避免以管理员身份跑自检时真的写防火墙规则。

### 交付前无控制台冒烟（打包产物用）

```bat
dist\PortGuard\PortGuard.exe --selfcheck
```

在「模拟无控制台」（把 `sys.stdout` / `sys.stderr` 置为 None）的条件下真正启停一次接收服务，
退出码 0 即通过，细节写在日志文件里。

为什么要单列这一条：打包后的窗口程序（`console=False`）**没有 stdout**，`print` 看不到，
界面点击也没法自动化，而「窗口化 + std 流为 None」恰恰是唯一能让接收服务启动失败的环境
（uvicorn 的彩色 formatter 会执行 `sys.stdout.isatty()`）。

### 拷到别的电脑跑不起来？先跑环境自诊断

```bat
dist\PortGuard\PortGuard.exe --diag            :: 弹窗给结论 + 完整报告落盘
dist\PortGuard\PortGuard.exe --diag --quiet    :: 不弹窗（流水线/自动化用）
```

现象通常是：**开发机上运行正常，拷到别的电脑却弹**

```
Failed to execute script 'main' due to unhandled exception:
DLL load failed while importing QtCore: 找不到指定的模块。
```

根因只有一个：Qt 的某个**硬导入** DLL 在那台机器上解析不到。而开发机多半装过
Microsoft Visual C++ 运行库甚至 Visual Studio，缺的东西会被 `C:\Windows\System32`
悄悄兜住，所以在本机永远复现不出来。

`--diag` 会打印系统内部版本号、逐个探测运行库、扫描产物依赖闭包，并**按扩展模块的真实
加载方式**（`LOAD_WITH_ALTERED_SEARCH_PATH`）实际 LoadLibrary 一遍 Qt 关键库，直接点名
是缺哪个 DLL、谁在依赖它。完整报告写入 `%APPDATA%\PortGuard\logs\diag-*.txt`。

开发机上想静态核对依赖（不必运行 exe）：

```bat
python tools\check_dll_deps.py dist\PortGuard
```

它只认硬导入，并按「DLL 自身目录 / `_internal` / System32」的真实搜索上下文解析，而不是
「整个目录树里有没有」——这两者的差别正是「本机能跑、别处不能跑」的成因。

### 真实环境验证脚本（`tools/`，交付前跑）

上面两条都还有盲区：单元测试把防火墙命令**全部打了桩**（只能证明「命令拼对了」，
证明不了「Windows 真的接受了这条规则」），自检脚本也没法覆盖打包产物。这两个脚本补上：

```bat
:: 1. 真实防火墙链路：用文档保留地址 198.51.100.1 实跑「封禁 → 写入系统 → 解封 → 移除」
python tools\verify_firewall.py

:: 2. 打包产物运行验证：--selfcheck（无控制台启停接收服务）+ 正常启动一次（真实 Qt 插件）
python tools\verify_exe.py
```

两个脚本都会**自行请求提权**（弹 UAC），退出码 `0` 通过 / `1` 有检查未通过 /
`2` 提权被拒绝 / `3` 提权后超时未见结果；逐项结果与日志尾部会打印出来，同时写一份 JSON
到 `%TEMP%\portguard-verify\`。已在管理员终端里时加 `--no-elevate` 跳过提权。

安全边界：`verify_firewall.py` 只操作 `PortGuard_Block_` 前缀的规则，且**只删除自己刚创建
的那一条**（按名字），绝不调用 `unblock_all()`，并会断言你的既有规则集一条未变；无论成功
失败都在 `finally` 里兜底清理。`verify_exe.py` 默认离屏运行（`QT_QPA_PLATFORM=offscreen`），
加 `--desktop` 才会在本机桌面弹窗。

---

## 十、开发规范

```bat
:: 静态检查（CI 门禁，必须全绿）
ruff check .

:: 格式化（CI 门禁；本地直接执行即可自动排版）
ruff format .

:: 类型检查（CI 门禁，覆盖全项目，必须全绿）
mypy .
```

* 规则配置统一在 `pyproject.toml`，不要在各自机器上各配一套
* **四道门禁**：`ruff check` / `ruff format --check` / `mypy .` / `pytest` 全部必须全绿。
  其中 `ruff format` 可本地直接跑来自动排版，不必手工调格式
* 新增「拼进命令行」的值 → 必须先在 `core/validators.py` 加校验/转义
* 新增「会影响判定逻辑」的改动 → 必须补 `tests/` 用例
* 日志统一走 `core.logger.get_logger()`，不要用裸 `print` 或静默 `except: pass`

---

## 十一、打包为 exe

```bat
pyinstaller port_guard.spec
```

产物在 `dist/PortGuard/`。打包后只读资源（xdb、rules.json 默认值）随包分发，运行时数据写入 `%APPDATA%/PortGuard/`。

> 离线 IP 库（两个 xdb 合计约 46 MB）**不入版本库**，打包脚本会自动跳过不存在的资源。
> 新克隆的仓库在打包前请先运行一次同步，或把上游仓库 `data/` 下的 xdb 复制过来。

### 运行环境要求（实测结论，不要凭感觉）

| 项 | 要求 | 依据 |
| --- | --- | --- |
| 系统 | **Windows 10 1703（内部版本 15063）起**；推荐 1809（17763）起 | `Qt6Core.dll` 把 `icuuc.dll` 列为**硬导入**，而 `icuuc.dll` 是 Windows 10 1703 才加入的系统组件 |
| 架构 | 64 位（x64） | 打包产物为 x64 |
| VC++ 运行库 | **无需预装**（已随包分发并平铺到 `_internal`） | `MSVCP140*` / `VCRUNTIME140*` 由 PySide6 轮子提供，spec 里平铺到 `_internal` 根目录 |

**Win7 / Win8.1 / Server 2008 R2 / Server 2012 R2 / Server 2016 / Win10 1607 及更早都不支持**，
且**无法通过补 DLL 解决**：这些系统缺少 `icuuc.dll`（以及 Win7 上还缺 `bcryptprimitives.dll`、
`api-ms-win-core-winrt-*` 等），`import PySide6.QtCore` 必然报「找不到指定的模块」。
PySide6 6.12（Qt 6.10）本身也不再支持这些系统。要部署到这类机器，只有两条路：
升级/更换目标机系统，或者把界面栈降到 Python 3.8 + PySide2（Qt 5.15）另建一套老系统构建。

---

## 十二、日志与排障

工作日志统一写在**一个文件**里（uvicorn 自己的输出也并入其中，不用两头找）：

| 项 | 值 |
| --- | --- |
| 位置 | `%APPDATA%/PortGuard/logs/portguard.log`（源码运行是 `data/logs/`） |
| 滚动 | **按天**滚动，单片超过 5 MB 时再按大小补滚一次（防日志风暴写满磁盘） |
| 保留 | 每天默认 3 点自动清理，保留天数与执行时刻都在**设置页 → 数据管理**可改 |
| 内容 | 程序启停、服务启停与失败原因、自动封禁、离线库同步、定期清理结果 |

设置页「数据管理」里可以直接改「日志保留」天数与「自动清理时刻」，也可以点
「清理过期日志」立刻执行一次（同时清访问记录与磁盘上的过期日志文件）。

排障时优先看日志里这几行：

```text
PortGuard 1.1.0 启动：运行方式=打包 exe 管理员=True
数据目录=... 日志文件=...
接收服务已启动：http://127.0.0.1:18080（API Key 未启用，日志 ...）
接收服务启动失败：... | <归因与下一步建议>（日志：...）
```

> 启动失败时会给出**归因**而不是笼统猜测：端口被占用会提示用
> `netstat -ano | findstr :端口` 查占用进程；权限不足会提示保留端口段；
> 程序内部错误会明确说明「与端口无关」。完整堆栈始终写进日志文件。

---

## 十三、注意事项

* 封禁需要**管理员权限**，请在 `start_as_admin.bat` 中启动
* 「自动封禁模式」默认**关闭**。开启后会跳过人工确认直接写防火墙，请先确认规则的评分阈值
* 上报服务默认只监听 `127.0.0.1`。需要局域网访问时到设置页打开开关，
  系统会**自动生成 API Key**（必须复制给业务系统，否则会上报 401）
* 单次扫描器探测（如一条 sqlmap 请求）只会**告警**，不会建议封禁；
  持续爆破（窗口型规则）才会升级为封禁建议 —— 这是刻意设计，避免误伤
* IP 归属地数据来自 `data/ip2region_v*.xdb`，精度到城市，不保证 100% 准确；
  可开启在线同步保持最新
* 第三方代码与许可见 `NOTICE`。**GUI 使用 PySide6（LGPL v3），因此允许闭源分发**；
  此前用的 PyQt6 是 GPL v3 / 商业双许可，闭源分发会触发 GPL 传染性，已整体迁移
* 依赖里装的是 **PySide6-Essentials** 而非完整版 PySide6：界面只用到 QtCore / QtGui /
  QtWidgets / QtNetwork / QtSvg，都在 Essentials 内；不装 Addons / WebEngine / Pdf，
  `site-packages/PySide6` 从约 656 MB 降到约 215 MB。导入路径仍是 `PySide6.*`，代码零改动
