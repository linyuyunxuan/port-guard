# PortGuard 端口访问防御工具

Windows 桌面端「端口访问防御工具」：**本机自动采集端口访问 → 用离线 IP 库识别来源归属地 → 规则引擎打分 → 给出封禁建议 → 人工确认后写入 Windows 防火墙**。

数据只有一条来源：**本机采集**（TCP 连接表 + 防火墙日志）。1.2.0 起不再内置 HTTP 上报接收服务 —— 它要求业务系统改代码配合，而真正要防的扫描器、爆破流量根本不会走业务系统的上报路径；留着反而多出一个「能被伪造上报借刀封 IP」的攻击面。

基于 ip2region 3.18.0 的离线定位库与内置查询客户端实现，**IP 归属地查询本身全程离线**，
不依赖任何外部服务；库文件随交付包附带，在线同步只是可选的更新手段（见「十三、注意事项」与 `delivery/01_DEPLOY.txt`）。

---

## 一、快速开始

```bat
:: 1) 首次安装依赖（已安装可跳过）
install.bat

:: 2) 源码运行：普通权限（仅监控 + 生成封禁建议）
start.bat

:: 3) 源码运行：管理员权限（启用封禁 / 解封）
start_as_admin.bat
```

> **v1.9.5 起正式交付的 exe 也默认以普通权限启动**（`asInvoker`），即只读 /
> 观察模式：监控、风险、历史、统计与导出全部可用，不弹 UAC。写防火墙的动作
> 由用户主动触发提权（封禁管理页「以管理员身份重启」），或用随包的
> `delivery/start-as-admin.bat` 以管理员启动。客户部署口径见
> `delivery/01_DEPLOY.txt` 与 `delivery/03_INTEGRITY.txt`。

或直接用虚拟环境运行（**别用 PATH 上那个 `python`** —— 这台机器上通常有多个，
随手 `python main.py` 命中的多半没装本项目的依赖）：

```bat
envs\portguard\Scripts\python.exe main.py
```

启动器（`start.bat` / `start_as_admin.bat`）会自己做三件事：逐个探测候选解释器 →
**真的去 import PySide2 / PySide6 验证** → 挑第一个能用的。探测顺序是
仓库内 `envs\portguard38` → 仓库内 `envs\portguard` → 用户目录下的托管 venv →
`py -3.8` → `py -3` → PATH 上的 `python`。全都不行时会打印逐个尝试过的路径并给出装法。

> `install.bat` 读的是 `requirements.txt`，其中 GUI 依赖按 Python 版本自动二选一：
> `PySide6-Essentials`（≥3.9）或 `PySide2==5.15.2.1`（<3.9）。两者都是 LGPL v3，
> 允许闭源分发。**不要**再手工 `pip install PySide6` —— 完整版会额外拉入
> Addons / WebEngine / Pdf 约 380 MB，本项目一个都用不到。

### 要装到 Windows 7 / Server 2008 R2 上？

那台机器跑不了 Qt6，需要用**老系统线路**（Python 3.8 + PySide2 5.15）。
同一套代码，`qtcompat.py` 会自动选绑定，业务代码零改动：

```bat
install.bat delivery     :: 建 envs\portguard38（Python 3.8 + PySide2）
start.bat                :: 启动器会优先选中它
```

两条线路的支持范围、以及**打包前必跑的 Win7 兼容闸门**见
「十一、打包为 exe → 运行环境要求」。一句话版本：Qt6 线需要 Win10 1703+，
Qt5 线从 Win7 SP1 起（Win7 上要先装 KB2999226）。

> **维护批处理的硬约束**：`*.bat` 必须是 **CRLF 换行 + 纯 ASCII**。
> 只有 LF 时 cmd 会把一行拆成两段执行（典型症状：`'08' 不是内部或外部命令`
> 后面跟一个裸 Python REPL）；文件里出现中文时 cmd 的字节偏移会错位，
> 中段开始整行乱飞。中文文案一律放 `launcher_help.txt` 或 Python 层。
> 这两条由 `tests/test_launcher_scripts.py` 守着，改完跑一遍 pytest 即可。

---

## 二、本机端口访问观察（唯一数据来源）

工具在本机自己采集访问记录，识别来源归属地，再交给同一套规则引擎判定 —— **业务系统不需要做任何改造**。

打开「设置 → 本机端口访问观察」，填上要盯的端口（例如 `3389,1433,3306`），点「立即启用观察」。

### 两条采集通道（可单选，也可同时开）

| 通道 | 原理 | 需要管理员 | 能抓到什么 |
| --- | --- | --- | --- |
| **TCP 连接表轮询**（默认） | 调 `GetExtendedTcpTable`（iphlpapi）读本机连接表，按本地端口筛出**已建立**的入站连接 | 否 | 正在连上的访问。**不改动系统任何状态**，零权限要求 |
| **防火墙连接日志** | 增量读 `%SYSTEMROOT%\System32\LogFiles\Firewall\pfirewall.log` | 是（需先开启日志记录） | 被防火墙**丢弃/放行**的访问，**包括扫描器打过来的、根本没连上的包** |

两条通道各有盲区，所以推荐**两个都开**：

* 只开连接表：扫端口的人（SYN 扫一下就换下一个）根本不会建立连接，你就看不见他
* 只开防火墙日志：日志默认是关闭的，且需要管理员才能开；连接表则随时可用

**跨通道自动去重**：去重键是 `(本地端口, 来源 IP, 来源端口)`，**不含通道名** ——
否则同一次访问被两条通道各记一条，风险分会翻倍累加，同一件事告警两次。

### 采集到的记录长这样

```
2026-10-19 09:00:01  |  113.118.113.77:40000 → 本机:3389  |  中国·广东省·深圳市·电信  |  高(65)  |  [本机采集·防火墙日志(DROP)]  |  管理端口归属地检测
```

采集到的记录统一走 `core/pipeline.py` 这一条链路（归属地 → 规则打分 → 落库 → 投递界面 →
告警 → 按策略自动封禁），两条通道的判定口径完全一致。

### 两个刻意的保守设计

* **不看 UA 判扫描器**。TCP 层记录没有 UA 这个概念，而规则引擎里「UA 为空 = 扫描器」
  （+45 分）在 HTTP 场景下才成立。若直接套用，每条 TCP 记录都会被无脑加分。因此该规则
  加了 `has_http_context()` 前置判断：只有协议是 http/https，或带 method/path 时才认为有 HTTP 语义
* **默认不自动封禁**。观察到的记录默认只出建议，自动封禁需单独勾选并满足阈值。
  毕竟来源是网络层，误判代价高于业务侧上报

监控端口、采集通道、采样间隔、去重时间窗都在设置页，改完保存即生效（观察线程会重启）。

---

## 三、内置风险规则

规则可在界面「规则配置」页启停与调参，保存后即时生效；也可直接编辑 `data/rules.json`。

| 规则 | 触发条件（默认） | 分值 | 等级 |
| --- | --- | --- | --- |
| 拦截（黑名单 / 拦截规则） | 来源 IP 命中人工维护的拦截规则或旧黑名单 | 100（**直接拦截**，见下） | 严重 |
| 端口扫描 | 同 IP 30 秒内访问 ≥15 个不同端口 | 80 | 严重 |
| 敏感路径爆破 | 60 秒内 `/admin`、`/login` 等敏感路径返回 401/403 ≥10 次 | 70 | 高 |
| 管理端口归属地检测 | 按「归属地范围」判断来源 IP 访问 22/3389/1433/3306/6379/8080 等管理端口（默认**仅限境内**，可改境外 / 境内+境外） | 65 | 高 |
| 高频请求 | 同 IP 10 秒内请求 ≥50 次 | 60 | 高 |
| 扫描器特征 | UA 为空或命中 nmap / sqlmap / masscan / nikto / curl 等 | 45 | 中 |
| 错误风暴 | 60 秒内 4xx+5xx 占比 ≥70% 且样本 ≥20 | 40 | 中 |
| 异常 HTTP 方法 | TRACE / PUT / DELETE / CONNECT / PATCH | 30 | 低 |
| 超大请求体 | 单次请求体 ≥5 MB | 25 | 低 |

评分映射：`≥90 严重` / `≥65 高` / `≥40 中` / `≥20 低`，多规则命中累加，单条封顶 100。
`高` 与 `严重` 会生成**封禁建议**（不自动执行，除非手动开启「自动模式」）。

> **关于「管理端口归属地检测」的范围**：默认是 **仅限境内** —— 只监听本机的部署里，
> 能打到 3389 / 1433 这类端口的绝大多数是境内来源（境外 IP 基本到不了内网）。
> 需要连境外一起盯，在规则页把它改成 **境内+境外** 即可；只想保留原来的境外口径就选 **仅限境外**。
> 归属地未知的内网 / 保留地址在任何范围下都不参与判定，避免本机与局域网访问被误加分。

**拦截优先，其次放行**：命中「拦截」规则（或旧黑名单）的来源**直接拦截** —— 不看评分、
不看「自动封禁」开关与阈值，即使同时命中「放行」规则或「仅观察」模式也照拦。
命中「放行」规则（或旧白名单）则直接豁免、永不封禁，已经在防火墙里的封禁会在保存规则时解除。
内网 / 回环 / 保留地址段（`127.0.0.0/8`、`192.168.0.0/16`…）受硬保护，永远无法被封禁。

> 2026-10-23 起**黑名单 / 白名单不再是独立入口**，统一由下面「访问规则」里的
> 「拦截 / 放行」两个动作表达。旧的名单条目会在启动时自动迁移成等价规则
> （原文件备份在 `data/backup/lists-migrate-<时间>/`），迁移后名单文件被清空。

### 访问规则（拦截 / 放行 / 判定风险 …）

「规则配置 → 访问规则」用于表达这类需求：**拦住 203.0.113.7**、**河南、山西的 IP 可以访问 8080，其它来源照常判风险**。

每条规则包含三部分，都能在界面上增删改，也可以直接改 `data/rules.json` 的 `region_rules`：

| 部分 | 说明 |
| --- | --- |
| **动作** | `block` 拦截（**命中即直接封禁**：立即写 Windows 防火墙永久规则，不看评分与自动封禁开关）/ `allow` 放行（**仅限所选区域通行，其他区域访问所选端口直接写入防火墙拦截**；不填端口则只豁免不拦截）/ `watch` 仅关注（只留痕、不改分）/ `downgrade` 降级（按系数打折）/ `suggest_ban` 判定风险（**仅针对所选区域拦截**：加分可生成封禁建议，其他区域不受影响） |
| **生效端口** | 留空 = 对所有端口生效；填了则只对这些端口生效（**放行 8080 不会连带放行 3389**）。`allow` 动作**必须**填端口：不限定端口的放行只豁免、不拦截 |
| **匹配条件** | 省 / 市 / 国家 / 运营商 / CIDR 网段 / IP 前缀 / 仅限境内；多条件之间是「且」的关系 |

保存规则后会在后台做一次**防火墙校准**：`block` 目标没有封禁就补写（永久），`allow` 目标有封禁就解除。
只有精确 IP（含 `/32`、`/128`）会被预置规则，网段条目在命中时实时生效 —— 界面会列出跳过的网段。

几个设计上的取舍：

* **省名双向包含匹配**：写「河南」和「河南省」都能命中（`c in a or a in c`），不用记标准写法
* **归属地未知时不放行**：「说不清是哪儿」不等于「是河南」，宁可放过风险也不凭不知道就白名单。
  但纯 IP 维度的条件（CIDR / IP 前缀）不依赖归属地，未知时照样生效
* **什么都不填的规则不生效**：一条没配任何条件的规则等价于「匹配全部地址」，属于误配，直接忽略
* **随包示例规则默认关闭**：`data/rules.json` 里带了两条示例（河南放行 / 山西仅关注），
  但都是 `enabled: false` —— 示例若默认开启，会静默改变所有用户的放行行为
* 非法网段、非法动作不会让规则引擎罢工：非法项跳过并记日志，动作非法时降级为 `watch`

> 区域规则的放行判定**优先于所有评分规则**：管理员显式配了放行，就按放行算。

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

* 失败自动回滚到旧库；正在进行的查询不受影响（新老 searcher 都是只读内存对象）
* 界面入口：「设置 → 离线库在线同步」有 **立即检查更新 / 立即同步 / 强制重新下载**，
  以及自动检查（可设间隔，默认 24 小时）、启动时检查、自动下载并热换三个开关
* 进度通过事件总线推到界面（进度条 + 阶段文案），全程不阻塞 UI
* 自定义镜像源可填**多条**：设置页下拉里列出所有已填地址，可增删、按顺序优先尝试，自定义源全失败再落到内置源。必须是 https，且不许指向内网 / 环回地址（防 SSRF）
* 命令行验证：

```bat
python -c "from core import xdb_updater as U; c=U.check(); print(c.method, c.message)"
```

---

## 五、封禁机制

* 仅操作**以 `PortGuard_Block_` 为前缀**的自有规则，不会误伤系统或第三方规则
* 优先 `New-NetFirewallRule`（原生支持 IPv6），失败自动回退 `netsh advfirewall`
* 规则命名：`PortGuard_Block_<IP>`（固定名，同一 IP 只对应一条规则）；
  另有一组 `PortGuard_Allow_<协议>_<端口>` 放行规则。旧版带时间戳后缀的规则名
  仍可被识别与清理，但不再新生成
* **所有拼进命令行的值都先过 `core.validators`**：IP 先做白名单归一化，文本走
  PowerShell 单引号字面量。非法输入直接拒绝，**不会产生任何命令**
* 支持封禁时长与到期自动解封（每分钟巡检）
* 「与防火墙对账」按钮可清理数据库中已失效的记录
* 需要管理员权限；普通权限（交付 exe 默认的观察模式）下监控与判定照常，
  封禁按钮会提示提权，不会假装成功
* **已拦截的 IP 再次访问时不再打扰**：不再弹窗 / 不冒托盘气泡 / 不响铃，
  只在封禁记录上累加「拦截次数」（表格里状态后面显示 `×N`，鼠标悬停看最近一次）
* **惯犯自动升级**：封禁期间又被拦下 N 次（默认 5 次，设置页可改）的 IP，
  自动写成一条**拦截规则**并把封禁改为**永久** —— 攻击者等不到「到期后重来一轮」，
  同时记一条审计、只提示一次（规则页能看见，也能停用）。

---

## 六、界面

| 页面 | 作用 |
| --- | --- |
| 实时监控 | 实时访问流水（时间 / IP / 归属地 / 端口 / 路径 / UA / 命中规则 / 风险 / **进程**），统计卡片、多维筛选、右键快捷操作 |
| 风险事件 | 命中规则的记录，可按等级与处理状态筛选，支持确认 / 忽略 / 一键封禁 |
| 封禁管理 | 待确认建议区 + 已封禁列表（含 **IP 归属地**），手动封禁、解封、一键全部解封、防火墙对账（已在封禁中的 IP 不会再出现在「待确认建议」里，标题会说明藏了几项）；**导出 IP 列表**（一行一个、无表头，可直接导入其它防火墙 / 黑名单系统） |
| 规则配置 | 8 条规则可视化启停调参 + **访问规则**（按 IP / 网段 / 归属地定义拦截、放行、降级、判风险；原黑 / 白名单已并入拦截 / 放行动作） |
| IP 查询 | 单条 / 批量归属地查询，支持 IPv4 + IPv6，可导出 CSV |
| 运行日志 | **在程序内直接看日志**（不是「打开日志文件夹」）：程序运行日志 + 端口访问日志两条流，可按级别筛选、关键字搜索、暂停滚动、一键清空显示 |
| 设置 | **本机端口访问观察**（监控端口 / 采集通道 / 采样间隔 / 去重）、离线库在线同步（含自定义镜像源）、封禁策略、限流、数据保留 |

### 快捷键与角标

* `Ctrl+1…8` 切页；`Ctrl+F` 把焦点送到**当前页**的搜索框（并全选，直接打字即替换）；`F1` 打开关于 / 快捷键帮助
* 侧栏「风险事件」右侧的角标 = 未处理事件数（琥珀），「封禁管理」右侧的角标 = 待确认建议数（红）。
  两个数字都由统计节拍（2 秒）刷新，处理完自动消失 —— 不必再靠状态栏那行小字发现待办
* 表格右键统一提供「查询该 IP 归属地 / 查看该 IP 的历史访问 / 复制 IP」；
  监控页另有「按此 IP 筛选」「按此进程筛选」——后者等价于把进程名填进搜索框

### 运行日志页说明

这一页是为「出了问题要立刻看，不想再去翻文件」准备的，两条流分开：

| 流 | 来源 | 内容 |
| --- | --- | --- |
| 程序运行日志 | 增量读 `%APPDATA%\PortGuard\logs\portguard.log` | 启停、观察线程、离线库同步、自动封禁、异常堆栈 |
| 端口访问日志 | 事件总线实时推送 | 本机采集到的访问记录（含通道、动作、进程名） |

工具条上有：来源切换 / 级别过滤（DEBUG~CRITICAL）/ 关键字搜索 / 暂停 / 自动滚动 /
清空显示 / 「打开日志文件夹」（**次要**入口，日志文件本身仍按天滚动落盘）。

日志文件按天滚动、单片超 5MB 再按大小兜底，保留天数与每天清理时刻都能在设置页改。

界面截图见 `screenshots/`。

---

## 七、项目结构

```
port-guard/
├── main.py                 程序入口（后端先就绪 → 单实例保护 → 托盘常驻）
├── selftest.py             离屏端到端自检（真实环境冒烟，44 项检查）
├── pyproject.toml          ruff / mypy / pytest 统一配置（工程规范的锚点）
├── NOTICE                  第三方代码与数据来源、许可说明
├── .github/workflows/ci.yml  CI：ruff check + ruff format + mypy + pytest 四道门禁
├── requirements.txt        运行时依赖
├── requirements-dev.txt    开发依赖（pytest / ruff / mypy）
├── install.bat / start.bat / start_as_admin.bat
├── _find_python.bat        启动器共用的解释器探测（CRLF + 纯 ASCII，勿加中文）
├── launcher_help.txt       找不到运行环境时的中文说明（UTF-8，由 type 输出）
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
│   ├── rule_engine.py      规则引擎（滑动窗口 + 评分 + 区域规则）
│   ├── rules_meta.py       规则中文名与区域规则命中标记的翻译
│   ├── ratelimit.py        令牌桶限流
│   ├── firewall.py         Windows 防火墙执行器
│   ├── pipeline.py         统一处理链路（归属地 → 打分 → 落库 → 投递 → 告警 → 自动封禁）
│   ├── win_net.py          本机 TCP 连接表读取（ctypes 调 iphlpapi，零权限）
│   ├── win_fwlog.py        防火墙连接日志解析 + 增量读取 + 日志开关
│   ├── port_watcher.py     本机端口访问观察（双通道采集 + 跨通道去重）
│   ├── logtail.py          日志文件增量读取（程序内看日志用）
│   ├── xdb_updater.py      离线库在线同步（指纹比对 / 下载 / 校验 / 回滚）
│   ├── pe_imports.py       PE 导入表解析与依赖就近判定（含 Win7 兼容闸门）
│   ├── diag.py             环境自诊断（--diag）
│   ├── alerts.py           托盘 / 声音 / 弹窗告警
│   └── event_bus.py        跨线程事件总线
├── app/                    无 Qt 依赖的业务层（供 GUI 与测试共用）
│   ├── ban_service.py      封禁唯一校验入口与执行流程
│   ├── list_migration.py   旧黑 / 白名单并入拦截 / 放行规则 + 防火墙校准
│   ├── xdb_service.py      离线库同步的后台调度
│   └── maintenance.py      日志 / 备份 / 临时文件清理
├── qtcompat.py             Qt 绑定兼容层（PySide6 / PySide2 导入期选择）
├── gui/                    界面（主题 / 主窗口 + mixins / 7 个页面 / 通用控件）
│   ├── region_rules.py     访问规则编辑器（拦截 / 放行 / 降级 / 判风险）
│   └── page_logs.py        运行日志页（程序日志 + 端口访问日志）
├── tools/                  真实环境验证脚本（自行请求提权，不改动仓库状态）
│   ├── verify_firewall.py  真实防火墙「封禁 → 解封」全链路
│   ├── verify_exe.py       打包产物运行验证（--diag --quiet + 正常启动）
│   └── check_dll_deps.py   静态核对产物依赖闭包 + Win7 兼容闸门
└── tests/                  pytest 用例（隔离环境，全离线）
```

---

## 八、技术要点

* **线程模型**：Qt 主线程（唯一可操作控件）+ 采集线程 + 规则评估 +
  批量写入线程 + 防火墙子进程。后台线程只往队列投递事件，主线程用定时器批量消费，
  从根上避免跨线程崩溃
* **写入路径**：每条记录都丢进 `BatchWriter` 队列，由唯一的写线程按批（默认 200 条 / 200ms）
  提交。SQLite 只允许一个写者，单写线程同时消除了 `database is locked`
* **设置读取**：`core.settings` 进程内缓存 + 写穿透，采集热点路径不再查库
  （原实现每条记录查 3 次 settings 表）
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
* **双 Qt 栈（同一套代码，两条线路）**：`qtcompat.py` 在导入期探测可用绑定 ——
  有 PySide6 就用 Qt6（Win10 1809+），否则退回 PySide2/Qt5（**Win7 SP1 / Server 2008 R2 起**）。
  两条线路的业务代码完全一致，差异只在这一层。见「十一、打包为 exe → 运行环境要求」
* **本机采集走 ctypes 直接调系统 API**，不引入 psutil 之类的额外依赖：
  `GetExtendedTcpTable`（iphlpapi）读连接表；无管理员权限也能用
* **采集侧的两个字节序陷阱**（已用测试锁死）：`MIB_TCPROW_OWNER_PID.dwLocalPort` 是
  **网络字节序**存在低 16 位里 → 必须 `socket.ntohs(dwPort & 0xFFFF)`；地址字段是小端
  DWORD → `struct.pack("<I", dwAddr)` 才能转成 `IPv4Address`。行大小 IPv4 = 24 字节、
  IPv6 = 56 字节
* **防火墙日志解析要自带字段顺序**：`#Fields:` 表头只在文件创建时写一次，
  增量读取的后续片段里没有表头 —— 必须内置默认字段序，否则第 N 次读取会全解析错。
  且**最后一列会吞掉空格**（进程路径形如 `C:\Program Files\...`），不能简单按空格切分
* **区域规则命中标记的翻译**：命中标记编码成 `region_<动作>:<规则id>`，
  由 `rules_meta.rule_label()` 反查用户填的规则名 —— 用注册表注入而不是让
  `models` 反向 import `rule_engine`，避免循环依赖

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
| `test_settings_xdb_sources.py` | 自定义镜像源下拉：多条增删、老键迁移、上限、脏标记语义 |
| `test_theme.py` | 浅色底与字号下限（改回深色 / 缩回小字会红） |
| `test_logger_startup.py` | **无控制台启动回归**（std 流为 None）、启动失败归因、日志按日期清理 |
| `test_win_net.py` | 连接表字节序（65535 个端口全量往返）、结构体尺寸 24/56、地址格式、入站筛选 |
| `test_win_fwlog.py` | 日志表头缺失兜底、**最后一列含空格**、方向判定、增量读取、文件被截断 |
| `test_logtail.py` | 结构化解析、增量读取、半行缓存、**日志轮转**、缓冲上限、尾部预填 |
| `test_port_watcher.py` | 配置解析、两条通道、**跨通道去重**、处理链路输出、生命周期 |
| `test_region_rules.py` | 区域规则四种动作、生效端口限定、全部匹配维度、未知归属地、非法网段/动作容错、随包示例规则合法性 |
| `test_diag.py` | PE 解析、就近判定、**Win7 兼容闸门（Qt6 被拦 / Qt5 放行）**、系统版本判定（双线路） |
| `test_py38_compat.py` | Python 3.8 语法与 API 兼容（老系统线路不能用新语法） |

### CI 矩阵实测结论与三条环境差异（v1.9.5）

**本地全绿 ≠ CI 全绿。** 三套栈彼此不同，任何只在其中一套上验过的结论都不算数：

| 栈 | 解释器 / Qt | 用途 |
| --- | --- | --- |
| 开发栈（本机） | Python 3.13 + PySide6 6.12 | 日常门禁、单测 |
| CI 矩阵 | Python 3.11 / 3.12 + PySide6-Essentials 6.12（`windows-latest`） | 四步门禁 |
| 交付栈 | Python 3.8 + PySide2 5.15.2.1 | 打进 exe、跑在 Win7/2008R2 |

v1.9.5 发布时，CI 里 `pytest` 步骤第一次真正跑完，一次暴露了三条被前面步骤
（或本地环境）遮住的既有缺陷。以下均为实测结论，不是推测：

| # | 现象 | 根因 | 现在的做法 |
| --- | --- | --- | --- |
| 1 | 两矩阵同时红在「类型检查」step，`UnicodeEncodeError: 'charmap' codec` | GitHub Windows runner 的 pwsh 把 Python stdout 设成 **cp1252**，基线门禁脚本打印中文时抛异常；mypy 判定本身其实已 PASS | `ci.yml` job 级 `PYTHONIOENCODING: "utf-8"`；`tools/check_mypy_baseline.py` 自带 `_force_utf8_stdio()`（stdout/stderr `reconfigure`），脚本不依赖宿主编码 |
| 2 | py3.11 `3 failed`：`TypeError: can't apply this __setattr__ to DataPage object` | `object.__setattr__` 是 wrapper descriptor，会检查 `tp_setattro`；shiboken 类型覆盖了该 slot，**CPython 3.11/3.12 拒绝、3.13 放宽**，PySide2 交付栈则必抛。本地 1108 全绿把缺陷遮了一整个版本 | `gui/page_settings.py` 的扁平转发路径改用 `setattr(page, name, value)`；**不能**改成 `super().__setattr__`（super 作用于父页 self，会写错对象） |
| 3 | py3.12 `--timeout=180` 超时，栈停在 `QMessageBox.warning` | 用例读**真实注册表**：runner 上 `core/autostart._read_value()` 返回 `None` → `sync()` 返回失败 → `save()` 弹模态框，offscreen 下无人关闭 → 无限阻塞 | `tests/test_settings_xdb_sources.py` 用 autouse fixture 打桩 `autostart._read_value/_write_value/_delete_value`；**绝不 patch `sync` 本身**（`test_autostart.py` 直接调它，会全红）。与 `conftest.py` 的 `stub_firewall_enabled` 同一条原则：用例结果不能随机器状态漂移 |

写 CI 门禁/工具脚本时请记住两条：**新增门禁脚本要用
`PYTHONIOENCODING=cp1252 python <脚本>` 实跑一次**（本地 UTF-8 会掩盖编码崩溃）；
`try/except/pass` 会被 ruff `SIM105` 拦下，用 `contextlib.suppress`。

v1.9.5 最终 CI（run `43390471113`，`a408858`）两矩阵四步全绿，
各 `1107 passed, 3 skipped`、0 failed。3 个 skip 是环境性跳过
（`test_diag.py` Qt5 线路 ×2、`test_launcher_scripts.py` runner 无可用 venv ×1），
本地开发栈是 `1108 passed, 2 skipped`，差异属环境、不是削弱手段。
新增/改动用例后，请把「两矩阵是否都跑到 pytest 结束」当成放行条件 ——
曾经连续三次 push run 全红，但都停在更早的 step，问题被层层遮住。

### 端到端自检（真实环境冒烟，交付前跑）

```bat
python selftest.py
```

覆盖：后端初始化 → 设置缓存 → 定位库 → **在线同步模块** → 正常/恶意判定 →
批量落库 → 主窗口与 7 个页面（含**区域规则页签**、**运行日志页**、**端口观察组**）→
筛选回归 → 封禁校验（拒绝注入 / 内网保护）→
**std 流兜底回归**（窗口化下 std 为 None）→ 日志清理 → 统计。全部通过时退出码为 0。

> 自检会临时关闭「自动封禁」并在结束时还原，避免以管理员身份跑自检时真的写防火墙规则。

### 交付前打包产物冒烟

1.2.0 起 `--selfcheck` 参数随上报服务一起移除（它唯一的价值是验证「窗口化 + std 流为 None」
下第三方库不会崩，而现在程序**不再拉起任何服务端组件**）。对应能力拆成两处：
`--diag --quiet` 验依赖链（见下一节），`tools\verify_exe.py` 验真实启动（见「真实环境验证脚本」）。

顺带说明为什么还要留 std 流兜底：打包后的窗口程序（`console=False`）**没有 stdout**，
`print` 看不到、界面点击也没法自动化，而某些第三方库仍会调用 `sys.stdout.isatty()`，
一旦为 None 就抛 AttributeError。`core.logger.ensure_std_streams()` 在 `main()` 第一行
就把两条流补成可写的替身流，这条由 `tests/test_logger_startup.py` 与自检守着。

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

:: 2. 打包产物运行验证：--diag --quiet（不弹窗）+ 正常启动一次（真实 Qt 插件）
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

:: 类型检查（CI 门禁，按既有债务基线判定，不要裸跑 mypy .）
python tools/check_mypy_baseline.py
```

* 规则配置统一在 `pyproject.toml`，不要在各自机器上各配一套
* **四道门禁**：`ruff check` / `ruff format --check` / 类型检查基线门禁 / `pytest` 全部必须全绿。
  其中 `ruff format` 可本地直接跑来自动排版，不必手工调格式。
  类型检查**不要裸跑 `mypy .`**：mypy 2.4.0 下有 7 条既有 error（4 个文件），
  裸跑必然 exit 1。`tools/check_mypy_baseline.py` 用 `(文件, 行号, error code)`
  多重集判定，允许既有债务减少、拒绝任何新增或扩散到白名单之外；工具版本钉死在
  `requirements-dev.txt`，自装更高版本会报额外噪音
* 新增「拼进命令行」的值 → 必须先在 `core/validators.py` 加校验/转义
* 新增「会影响判定逻辑」的改动 → 必须补 `tests/` 用例
* 日志统一走 `core.logger.get_logger()`，不要用裸 `print` 或静默 `except: pass`

---

## 十一、打包为 exe

```bat
pyinstaller port_guard.spec
```

产物在 `dist/PortGuard/`。打包后只读资源（xdb、rules.json 默认值）随包分发，运行时数据写入 `%APPDATA%/PortGuard/`。

> 离线 IP 库（两个 xdb 合计约 46 MB）**不纳入 Git 版本库**，但**已随交付包附带**：
> `port_guard.spec` 会跳过不存在的资源，所以打包前必须把两个 xdb 放到 `data/` 下，
> 否则打出来的包在纯内网首启时没有离线库。客户侧口径见 `delivery/01_DEPLOY.txt`。

正式交付包请用 `tools/pack_release.py` 生成（见「十四、对外交付包与客户材料」），
不要直接把 `dist/PortGuard/` 压缩发出去 —— 客户文档、许可全文与逐文件校验单
都是打包脚本注入的固定组成。

### ⚠️ PySide2 线路要求「纯 ASCII 的 Python 环境路径」

打包机上的 Python 环境目录**不能含中文**（仓库/源码目录含中文没关系，只有装 PySide2 的那个环境不行）。

原因：PySide2 5.15.2.1 的 `QLibraryInfo.location(PrefixPath)` 会把非 ASCII 字符替换成 `?`
（实测 `ip防火墙` → `ip???`）。PyInstaller 的 `hook-PySide2.py` 拿到这个残缺路径后
`pathlib.Path(...).resolve()` 直接抛：

```
OSError: [WinError 123] 文件名、目录名或卷标语法不正确。: '...\ip???-2region-3.18.0\...\PySide2'
```

用目录联接（junction）、`subst` 盘符映射指过去**无效** —— Qt 从 `Qt5Core.dll` 的真实加载路径推导，
Windows 的 `GetModuleFileName` 会把联接解开，拿到的还是中文真实路径。只能把环境真的放在
ASCII 路径下（例如 `C:\pg\venv38`），源目录可以是中文/联接。PySide6 线路没有这个问题。

因此**重建交付 exe 必须用纯 ASCII 路径里的交付栈解释器**，
绝对不能用仓库内 `envs\portguard38`（它在中文目录下）：

```bat
PYTHONPATH= C:/Users/Administrator/pg/venv38/Scripts/python.exe -m PyInstaller --noconfirm --clean port_guard.spec
```

`PYTHONPATH=` 用于清掉宿主注入的 shim，不能省；构建日志须见
`[port_guard.spec] 检测到 Qt 绑定：PySide2（目录 C:\Users\Administrator\pg\...）`。
重建前删 `build/port_guard` + `dist/PortGuard`，否则 Analysis 缓存会把旧代码打进包。

**改了产品代码就必须重建 exe + 重打 zip**。源码修好而二进制仍带旧字节码，
会造成同版本号两个行为体、验收证据与实际交付物错位（交付栈 PySide2 恰恰是必抛
`object.__setattr__` 的那条栈）。验新字节码要落到目标函数自身的 `co_names`：
解析 exe 的 PYZ 取 `gui.page_settings`，递归找 `co_name == '__setattr__'`，
确认命中 `setattr` 且**不含** `object`。不要只搜整模块字节里的 `b'object'` ——
`_subpages()` 还有 `object.__getattribute__`，会造成假阳性。
辅助工具：`tools/peek_packaged_code.py dist/PortGuard/PortGuard.exe "1.9.5" "BanCoordinator"`。

### 运行环境要求（实测结论，不要凭感觉）

同一套代码，**两条 Qt 线路**，由 `qtcompat.py` 在导入期自动选择：

| 线路 | 绑定 | 最低系统 | 推荐 | 依据（实测 PE 导入表） |
| --- | --- | --- | --- | --- |
| **Qt6（默认）** | PySide6 6.12 / Python 3.13 | Windows 10 1703（内部版本 15063） | Windows 10 1809（17763） | `Qt6Core.dll` 把 `icuuc.dll` 列为**硬导入**，而 `icuuc.dll` 是 Windows 10 1703 才加入的系统组件 |
| **Qt5（老系统线）** | PySide2 5.15.2 / Python 3.8.10 | **Windows 7 SP1 / Server 2008 R2（7601）** | Windows 8.1（9600） | `Qt5Core.dll` 硬导入 25 个 DLL，**不含** `icuuc.dll`、`shcore.dll`、`bcryptprimitives.dll`，只依赖 VC++ 运行库 |

| 项 | 要求 | 依据 |
| --- | --- | --- |
| 架构 | 64 位（x64） | 两条线路的产物都是 x64 |
| VC++ 运行库 | **无需预装**（两个轮子都自带并随包分发） | PySide2 / PySide6 轮子里的 `MSVCP140*` / `VCRUNTIME140*` 会被平铺到 `_internal` 根目录 |
| 通用 C 运行库（仅 Win7 线） | **需要 KB2999226**（或预装 VC++ 2015-2022 可再发行组件） | Win7 不自带 UCRT，而 Python 3.8 与 Qt5 都引用 `api-ms-win-crt-*` |

**所以「支持哪些系统」取决于你打包的是哪条线路**（官方离线交付包固定用 Qt5 / PySide2 线，
开发机跑测试用 Qt6 线）：

* **Qt6 线路**：Win10 1703 以下（含 Win7 / Win8.1 / Server 2012 R2 / Server 2016 / Win10 1607）
  **一律跑不起来，且无法通过补 DLL 解决** —— 缺的是系统组件，不是缺文件。
* **Qt5 线路**：Win7 SP1 / Server 2008 R2 起可用；Win7 上**先装 KB2999226**
  （Windows 自带的更新，或直接装 VC++ 2015-2022 可再发行组件）。

### 打包前先验一遍：Win7 兼容闸门

```bat
:: 扫条目目录（打包前就能验，不依赖真的有一台 Win7）
python tools\check_dll_deps.py  <某个环境的 Lib\site-packages\PySide2>
python tools\check_dll_deps.py  dist\PortGuard

:: 打包产物自诊断里也带这一节（--diag 报告中的「【Win7 兼容性】」）
dist\PortGuard\PortGuard.exe --diag --quiet
```

闸门把这些组件视为**阻断**（它们在底线上根本不存在）：

`icuuc.dll` / `icuin.dll` / `icu.dll` / `bcryptprimitives.dll` / `d3d12.dll` / `dcomp.dll` /
`shcore.dll` / `api-ms-win-core-winrt-*` / `api-ms-win-core-synch-l1-2-0.dll`。

判定有个刻意的设计：**只对「应用真的会加载」的文件判阻断**，其余归为「提示·不阻断」。
Qt 的 wheel 里塞了 `qsgd3d12backend`（Qt Quick 的 D3D12 后端）、`Qt5Bluetooth`、`sqldrivers`
这类本项目一个都用不上的模块，它们确实引用了 `d3d12`/`dcomp`/WinRT API ——
若一并判失败，闸门会被噪音淹没，真正的问题反而看不见。加载清单见
`core/pe_imports.py` 的 `APP_LOAD_PATH`。

本机实测结论（可直接复现）：PySide2 目录**通过**闸门（4 条提示均为用不上的插件），
CPython 3.8 解释器与全部 23 个扩展模块命中禁区 **0 项**；PySide6 目录被 `icuuc.dll` 拦下。

---

## 十二、日志与排障

工作日志统一写在**一个文件**里（所有模块的日志都走同一个 logger，不用两头找）：

| 项 | 值 |
| --- | --- |
| 位置 | `%APPDATA%/PortGuard/logs/portguard.log`（源码运行是 `data/logs/`） |
| 滚动 | **按天**滚动，单片超过 5 MB 时再按大小补滚一次（防日志风暴写满磁盘） |
| 保留 | 每天默认 3 点自动清理；保留期在**设置页 → 数据管理**可选 **1 / 3 / 7 / 30 / 90 / 180 天**预设或逐表自定义，自动清理也有总开关 |
| 内容 | 程序启停、服务启停与失败原因、自动封禁、离线库同步、定期清理结果、本机端口观察启停 |

**不想翻文件的话，直接在程序里看**：「运行日志」页把两个流并排显示 ——
程序运行日志（增量读上面这个文件）+ 端口访问日志（事件总线实时推送），
支持级别过滤、关键字搜索、暂停与一键清空。见「六、界面 → 运行日志页说明」。

设置页「数据管理」里可以直接改「日志保留」天数与「自动清理时刻」，也可以点
「清理过期日志」立刻执行一次（同时清访问记录与磁盘上的过期日志文件）。

排障时优先看日志里这几行：

```text
PortGuard <当前版本> 启动：运行方式=打包 exe 管理员=True
数据目录=... 日志文件=...
本机端口观察已启用：端口=3389,1433 通道=连接表+防火墙日志
防火墙规则写入失败：... | <归因与下一步建议>（日志：...）
```

> 写入失败时会给出**归因**而不是笼统猜测：防火墙 profile 全关会直接点名（这是
> 「规则写进去了却拦不住」最常见的根因）；非管理员会说明权限不足；
> 描述字符被 netsh 拒绝会自动降级为无描述重建。完整堆栈始终写进日志文件。

---

## 十三、注意事项

* 封禁 / 解封等写防火墙的动作需要**管理员权限**：交付 exe 默认为
  `asInvoker` 观察模式，需要时用封禁管理页「以管理员身份重启」或包内
  `start-as-admin.bat` 切换；顶栏「权限」可查看完整能力边界
* 「自动封禁模式」默认**关闭**。开启后会跳过人工确认直接写防火墙，请先确认规则的评分阈值
* 程序**不开放任何监听端口**。告警默认只在本地呈现（托盘气泡 / 提示音 / 风险事件页），
  **没有模态告警弹窗**；默认配置下不向外部发送告警（Webhook 开关关闭且地址为空）
* 但存在两类可选 / 可关闭的出站行为，安全评审时务必如实说明：
  ① 设置页「防护与告警」可启用 Webhook 外部推送，把风险事件文本 POST 到
  **管理员自行填写**的地址（默认关闭）；② 离线库在线同步默认开启，启动约 3 秒后
  向白名单主机发起出站 HTTPS 检查 / 下载，可在「设置 → 数据与离线库」关闭
  `xdb_auto_sync` / `xdb_sync_on_start` / `xdb_auto_download` 三个开关。
  纯内网首启不需要联网：离线库已随包附带。详见 `delivery/01_DEPLOY.txt` 第五节、
  `delivery/03_INTEGRITY.txt` 第四节
* 单次扫描器探测（如一条 sqlmap 请求）只会**告警**，不会建议封禁；
  持续爆破（窗口型规则）才会升级为封禁建议 —— 这是刻意设计，避免误伤
* IP 归属地数据来自 `data/ip2region_v*.xdb`，精度到城市，不保证 100% 准确；
  可开启在线同步保持最新
* 第三方代码与许可见 `NOTICE`（交付包内改名为 `NOTICE.txt`）。
  **正式交付包使用 PySide2 5.15.2.1（LGPL v3），因此允许闭源分发**，
  LGPL v3 / GPL v3 / Apache-2.0 全文随包附在 `licenses/`；此前用的 PyQt6 是
  GPL v3 / 商业双许可，闭源分发会触发 GPL 传染性，已整体迁移
* 开发栈装的是 **PySide6-Essentials** 而非完整版 PySide6：界面只用到 QtCore / QtGui /
  QtWidgets / QtNetwork / QtSvg，都在 Essentials 内；不装 Addons / WebEngine / Pdf，
  `site-packages/PySide6` 从约 656 MB 降到约 215 MB。导入路径仍是 `PySide6.*`，代码零改动
* **交付到 Win7 / Server 2008 R2 的正式包就是 PySide2 那条线（Python 3.8）**，
  见「十一、打包为 exe → 运行环境要求」。Qt6 那条线只用于开发与测试，
  在这些系统上无解，补 DLL 也没用 —— 缺的是系统组件
* 「本机端口访问观察」的**防火墙日志通道需要管理员权限**，且要先开启日志记录；
  连接表通道不需要权限。两条通道各有盲区，建议同时启用
* 观察到的记录**默认只出建议、不自动封禁**：来源是网络层，没有 HTTP 语义，误判代价更高
* 「UA 为空 = 扫描器」这条规则**只对 HTTP 场景生效**。本机采集到的 TCP 记录没有 UA
  这个概念，若套用会给每条记录无脑加 45 分
* 访问规则的优先级是 **拦截 > 放行 > 评分规则**：拦截命中直接封禁（不看评分、不看自动
  封禁开关），放行命中直接豁免。请确认规则名称与生效端口填写正确，尤其是留空端口 =
  对所有端口生效
* 随包的示例访问规则**默认关闭**，启用前请按自己的实际情况改成真实网段

---

## 十四、对外交付包与客户材料

正式交付形态是**离线 zip**（包内顶层固定为 `PortGuard/`），不是仓库源码。
自 v1.9.4 起由 `tools/pack_release.py` 生成，下列内容是**固定组成**：
打包脚本会逐项检查，缺任何一份直接拒绝出包。

| 包内文件 | 用途 |
| --- | --- |
| `00_README.txt` | 交付清单与阅读顺序 |
| `01_DEPLOY.txt` | 部署 / 升级 / 卸载 / 权限 / 内网首启 / 故障自查 |
| `02_TERMS.txt` | 最终用户使用条款（含 LGPL 组件替换方式） |
| `03_INTEGRITY.txt` | 整包与逐文件校验方法、发布者身份现状 |
| `04_CHANGELOG.txt` | 与版本绑定的更新日志 |
| `start-as-admin.bat` | 需写防火墙时以管理员启动（CRLF + 纯 ASCII） |
| `NOTICE.txt` | 第三方组件与许可清单（仓库根 `NOTICE` 改名而来） |
| `VERSION.txt` | 本包版本号，与关于页 / exe 版本资源一致 |
| `SHA256SUMS.txt` | 包内逐文件 SHA256，由打包脚本按实际内容生成 |
| `licenses/` | LGPL v3 / GPL v3 / Apache-2.0 许可全文 |

源材料在仓库 `delivery/` 与根 `NOTICE`；包外同名 `.sha256` 是整包校验单，
须与 zip 一起交付。压缩约定不变：无目录条目、全部 DEFLATED、无 STORED。

**当前交付基线**：开发栈全量 `pytest` **1053 passed / 2 skipped**、
两栈离屏自检 `selftest.py` 全过、`tools/stress.py refresh` PASS；
静态检查 `ruff check` / `ruff format --check` 全绿，
`mypy` 存量基线 7 errors / 4 files（零新增即通过）；
交付合规护栏 12 项，已做 7 组变异验证（每组都能让护栏变红）。
`docs/` 下三份评测 / 压测报告是 **v1.1~v1.2 时期的历史快照**，其中的
209 / 762 / 866 / 889 等测试数字不代表当前版本；
`screenshots/` 已按 v1.9.4 重拍，覆盖总览 + 8 个业务页共 9 张。
以本节与 `04_CHANGELOG.txt` 为准。

**已知限制**（对客户如实披露，见 `delivery/03_INTEGRITY.txt`）：
exe 未做 Authenticode 数字签名、无应用内自动升级；许可 / 试用由采购文件约定。
v1.9.5 已提供只读 / 观察模式，默认普通权限启动，写防火墙按需主动提权。

---

## 作者与联系

| 项 | 内容 |
| --- | --- |
| 作者 | 林玉云轩 |
| 联系方式 | 1416161819 |
| 程序版本 | v1.9.5 |

* 程序内入口：`F1` 或侧栏底部版本号 → 「关于」页，第一栏就是作者与联系方式；
* exe 文件属性：右键 `PortGuard.exe` → 属性 → 详细信息，同样带作者 / 联系方式；
* 这两处与 `core/config.py` 的 `APP_AUTHOR` / `APP_CONTACT` 同源，
  `version_info.txt` 与代码不一致时 `tests/test_version_info.py` 会变红。
