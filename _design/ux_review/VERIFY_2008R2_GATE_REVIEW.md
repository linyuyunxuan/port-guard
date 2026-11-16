# PortGuard v1.9.5 · 2008R2 干净机验证清单「假绿」复核 + 工具化交付

复核人：严过关（测试质量官）
复核日期：2026-11-16
性质：**文档复核 + 脚本工具化**。本轮**没有**在 Windows Server 2008 R2 上执行任何命令。
基线文档：`_design/ux_review/RELEASE_VERIFICATION_v1.9.5.md`（§1 能力边界 / §4 30 项清单 / §5 签字页 / §6 发布闸门）
对照快照：`_design/ux_review/RELEASE_REVIEW_v1.9.5.md`

---

## 0. 验证结果（我实际做了什么）

| 检查项 | 方法 | 结果 |
|---|---|---|
| 读全 §4 的 30 项、§5 签字页、§6 闸门 | Read `RELEASE_VERIFICATION_v1.9.5.md` 全文 310 行 | 通过，30 项 = A5+B4+C5+D5+E4+F4+G3 |
| 读原评审快照 | Read `RELEASE_REVIEW_v1.9.5.md` 全文 294 行 | 通过 |
| 核实 `--diag --quiet` 的真实语义，**不猜** | Read `main.py:151-177`（`_run_diag` 返回 `diag.run()` 的 code）、`main.py:284-285`、`main.py` 末行 `sys.exit(main())` | 确认：**退出码 0 = 无阻塞性问题**，是 locale 无关的权威判据 |
| 核实 diag 报告落盘位置与关键行文字 | Read `core/diag.py:120-122, 244-425` | 确认：`%APPDATA%\PortGuard\logs\diag-YYYYMMDD-HHMMSS.txt`，UTF-8 |
| 核实 A4 的「产物内缺少 / 系统也缺失」是否可靠 | Read `core/diag.py:303-318`、`core/pe_imports.py:269-286, 498-524`；Read `delivery/01_DEPLOY.txt:9-10` | **确认是假红陷阱**，见 P0-1 |
| 核实 F2 的 `FileName` 判据 | Read `core/win_fwlog.py:504-532`；本机实测 `netsh advfirewall show allprofiles logging` | **确认输出本地化 + 3 行**，见 P0-5 |
| 核实 D3/E3/G1 的 netsh 判据 | Read `core/firewall.py:51, 114-130, 573-600, 769`、`delivery/01_DEPLOY.txt:66-68` | 确认输出本地化、规则名 ASCII，须按名集合差 |
| 核实 E2 的数据库路径与审计落点 | Read `delivery/01_DEPLOY.txt:52-68, 102-116`、`core/config.py:123-126`、`core/pipeline.py:230-256`、`app/audit.py:76` | **确认路径写错、`RESULT_FAIL` 不是落盘字符串**，见 P0-2 |
| 核实 B3 页面数 | Read `gui/main_window.py:73-110` | **确认是 9 页，不是 7 页**，见 P0-7 |
| 核实 C1/C3 最差值字面量 | Read `_design/render_shots.py:143-184` | 确认 `23:59:59×27` 无空格 |
| 核实 C4 字体链 | Read `gui/theme.py:131-137`；本机实测 `C:\Windows\Fonts` + 注册表 Fonts 键 | **确认「文件存在 ≠ 家族可用」**：本机 `msyhui.ttc` 不存在，但注册表有 `Microsoft YaHei & Microsoft YaHei UI (TrueType)` |
| 核实 B1 日志滚动 | Read `core/logger.py:99-111, 151-161`；本机实测 `portguard.log*` 共 14 个文件 | 确认须扫全部归档 |
| 核实包内交付材料格式 | `unzip -l / -p dist/PortGuard-v1.9.5.zip` + 侧车 cat | 侧车 = `<hash>  PortGuard-v1.9.5.zip`；`VERSION.txt` / `SHA256SUMS.txt` 有 UTF-8 BOM |
| 交付脚本字节合规 | PowerShell 读字节逐字节校验 | `.bat` 2271 B / `.ps1` 40244 B，**0 个非 ASCII 字节，全部 LF 均为 CRLF，无 BOM** |
| 交付脚本语法 | `[System.Management.Automation.Language.Parser]::ParseFile()` | **0 errors** |
| 交付脚本结构冒烟 | 在 **Win10 18363** 上 `cmd /c verify_2008r2.bat` 跑 4 轮 | 第 1 轮抓到并修掉 3 个真 bug（见下）；末轮 exit 0、无本地化报错、报告纯 ASCII、42 条判据齐全。**这不是 2008R2 验证** |
| 冒烟抓到的 bug 1 | `R` 是 PowerShell 内置别名（`Invoke-History`），别名优先于函数 → 61 条证据行全部没写进报告 | 已改名为 `Note` |
| 冒烟抓到的 bug 2 | netsh logging 的 3 行相同路径被去重成 1 行 → F2「3 个配置文件」会假红 | 已取消去重，实测恢复为 3 行 |
| 冒烟抓到的 bug 3 | 注册表字体值名可同时含两个家族（`…YaHei & …YaHei UI…`），`if/elseif` 漏判 | 已改为两个独立 `if` |
| 冒烟抓到的 bug 4（外部） | 本机 sandbox 禁用 `reg.exe` | 已改用 PowerShell 自带 `Get-ItemProperty`，不再依赖外部 reg |
| 冒烟产物清理 | `rm` 掉 Win10 生成的 `verify_2008r2_report.txt` | 已清理，目录内只剩 2 个交付脚本，**不会误当成 2008R2 证据** |
| `dist/` 与产品代码零改动 | 改动前后两次算 zip SHA256 | 均为 `d27beea6bdd67685700d2161aa2b86100ba718da9690cdb4d1a28d77cba17684` |

> **明确声明**：脚本只在 Win10 上做过结构冒烟（证明它能跑完、不报错、报告是 ASCII）。
> **没有**在 2008R2 上跑过，也没有执行任何发布动作、没改产品代码、没动 `dist/` 里的包。

---

## 1. 交付物

| 文件 | 说明 |
|---|---|
| `_design/ux_review/verify_2008r2.bat` | 双击入口。**CRLF 行尾 + 纯 ASCII + 无 BOM**；只调用 Windows 自带命令 |
| `_design/ux_review/verify_2008r2.ps1` | 取证主体。**纯 ASCII + CRLF + 无 BOM**，PowerShell 2.0 语法 |
| `_design/ux_review/VERIFY_2008R2_GATE_REVIEW.md` | 本文（复核结论 / 人工目视清单 / 签字页对照表） |

**使用方式**：把两个脚本一起拷到含 `PortGuard-v1.9.5.zip`、`.sha256` 侧车、解压出的 `PortGuard\` 的**纯 ASCII 路径**目录，双击 `.bat`。

| 命令 | 用途 |
|---|---|
| `verify_2008r2.bat` | FULL 全量取证 → `verify_2008r2_report.txt` |
| `verify_2008r2.bat SAVEBASE` | **E2 之前**保存规则名基线 → `pg_rules_baseline.txt` |
| `verify_2008r2.bat DIFF` 或再跑一次 FULL | **E2 之后**读基线做精确名集合差 |
| `verify_2008r2.bat FULL "D:\fwlogs\pfirewall.log" "1.2.3.4"` | 同时校验 F2 自定义路径、D3 测试 IP 的精确规则名 |

**脚本只读边界**：只跑 `ver` / `systeminfo` / `certutil -hashfile` / `Get-ItemProperty` / `Get-ChildItem` / `netsh ... show ...` / `PortGuard.exe --diag --quiet`。**没有** `netsh ... set/add/delete`、**没有**写数据库、**没有**改产品文件、**没有**重打包、**没有**启动 GUI。控制台与报告文件强制 ASCII（`Ascii()` 把非 ASCII 替换成 `?`，落盘用 `[Text.Encoding]::ASCII`）。

**结论三态**：`PASS` / `FAIL` / `NEEDS-VISUAL`。所有视觉项恒为 `NEEDS-VISUAL`；脚本不签字、不改 §5。

---

## 2. 发现的问题（确认的，按严重度）

> 「确认的 bug」与「怀疑」严格分开：本节全部有 `文件:行号` 或实测证据；怀疑项在 §3。

### P0 — 会让签字页误判（必须改文字才能用这份清单）

#### P0-1 · **A4**：`无「产物内缺少 / 系统也缺失」` 是**确认的假红 + 漏字 + 字形判据不可靠**（重点）

证据：
- `core/diag.py:305` 的逐 DLL 行写的是 **`产物内缺失`**（失），`:307` 写进结论的是 **`产物内缺少`**（少）。清单只列了「缺少」，用 `findstr` 搜它会漏掉逐 DLL 行的「缺失」。
- `core/diag.py:309-314`：Qt5 线路下 `need=False`，`is_available()` 返回 False 时打的是 `· <dll> 系统也缺失`，**不进 problems**。
- `core/pe_imports.py:269-286` `is_available()` 先找 System32 物理文件再 LoadLibrary；`delivery/01_DEPLOY.txt:9-10` 明写「2008R2 需已安装 KB2999226，该系统不自带 UCRT」；`core/pe_imports.py:506-507` 明写「UCRT 属部署前置条件…只提示不判失败」。
  → **一台真正干净的 2008R2（未装 KB2999226）会合法地出现 `· ucrtbase.dll  系统也缺失`，而 `【结论】` 仍是 `✓ 未发现阻塞性问题`、退出码 0**。按现文字 A4 会被判 FAIL（假红）；若为了让它变绿而装 UCRT，这台机就不再是「干净机」，整个 §1 的能力边界前提被破坏。
- 「五项全 ✓」「版本判定 ✓」是 U+2713 字形，UTF-8 报告里是 `E2 9C 93`，cp936/437 控制台下 `findstr` 匹配不可靠。
- `core/diag.py:205-210`：7601 走的是「**可用**（内部版本 7601）——已达到 Windows 7 SP1 底线，建议 Windows 8.1」，**不是**「满足要求」。照「满足要求」找会误判。
- **漏项**：A4 完全没查 `【Win7 兼容性】` 段（`core/diag.py:356-373`、`core/pe_imports.py:498-524`），而那才是「这台老系统能不能跑」的结构性闸门；也没查本次是否新增 `crash-*.txt`（`main.py:302`）。

**A4 期望结果改为（逐字替换）**：
> 报告落盘且为**本次新生成**的 `%APPDATA%\PortGuard\logs\diag-YYYYMMDD-HHMMSS.txt`；`PortGuard.exe --diag --quiet` **退出码 = 0**（`main.py:151-177` 返回 `diag.run()` 的 code，末尾 `sys.exit(main())`）—— 这是权威判据；`Qt 线路 = PySide2`；`版本判定` 行带 ✓（7601 走「可用…建议 Win8.1」，不是「满足要求」）；`MSVCP140.dll` / `MSVCP140_1.dll` / `MSVCP140_2.dll` / `VCRUNTIME140.dll` / `VCRUNTIME140_1.dll` 五行带 ✓；出现「PySide2（Qt5）线路不依赖 icuuc.dll」；`【Win7 兼容性】` 段以 ✓ 收尾且**无** `[win7-阻断]` / `[win7-运行库]` 行；`【结论】` 段无 ✗ 行、含「未发现阻塞性问题」；本次运行**未新增** `crash-*.txt`。若出现「系统也缺失」，须记录**具体 DLL 名**：Qt5 线路下 `ucrtbase.dll` 属 `01_DEPLOY.txt` 第一节的部署前置条件（KB2999226），退出码仍为 0 时**不得据此判 FAIL**，改为记录并由人确认 UCRT 状态；出现「产物内缺失」或「产物内缺少」则 FAIL。

#### P0-2 · **E2**：`data/portguard.db` 在交付包里**根本不存在**；`RESULT_FAIL` 不是落盘字符串（重点）

证据：`delivery/01_DEPLOY.txt:57` 写的是 `%APPDATA%\PortGuard\port_guard.db`；`core/config.py:123-126` `user_data_dir()` 打包后 = `%APPDATA%/PortGuard`。干净机没有源码树，没有 `data/` 目录。
`app/audit.py:76` 定义的是 `RESULT_FAIL = "fail"`，审计行存在 **SQLite 库里**（`01_DEPLOY.txt:57`），不在文本日志里；干净机没有 Python / 没有 SQLite 浏览器，**打不开**。清单写「（`RESULT_FAIL`）」会让现场去找一个永远不存在的字符串。
`core/pipeline.py:234,246` 的真实落盘文本是 `自动封禁：写入 pending 记录失败 ip=…` 与 summary `自动封禁 <ip> 失败：写入封禁记录失败，未创建防火墙规则`。
另外两个假绿：`01_DEPLOY.txt:47` 明写「默认只出建议、不自动封禁」，清单没给「触发一次自动封禁」的具体方法；程序运行时给 DB 文件加只读**不会撤销已打开的可写句柄**，注入可能根本没生效 → E3 空结论。

**E2 操作/期望改为（逐字替换）**：
> 操作：先**退出程序**（含托盘）→ 对 `%APPDATA%\PortGuard\port_guard.db` 设只读（或对该目录加拒绝写 ACL）→ 用新建临时文件失败确认确实不可写 → 重新启动 → 在设置页开启自动封禁并配一条高分规则 → 造一次真实命中触发自动封禁。
> 期望：`portguard.log*` 出现 `自动封禁：写入 pending 记录失败 ip=`（`core/pipeline.py:234`）；并在 **设置 → 操作审计 → 导出 CSV** 中查到一条 `result=fail`、summary 含 `失败：写入封禁记录失败，未创建防火墙规则` 的记录（`core/pipeline.py:246`、`app/audit.py:76`），附 CSV 文件/截图。**同时确认注入确实触发**（上述两条都在），否则 E3 不得判 PASS。

#### P0-3 · **D4 / E3 / G1**：「0 行命中 = 通过」的经典假绿（重点）

证据：`core/firewall.py:583-584` 原文写着「netsh 的输出是本地化的（「规则名:」/「Rule Name:」随语言变）」。`netsh` 失败、输出为空、或本地化后 `findstr` 没命中，都会得到 0 行；D4「规则消失」、G1「无残留」、E3「不得新增」会直接判 PASS。
另：E3 说「不得新增任何规则」，但只靠行数/计数 —— **删一条再加一条，计数不变仍是 PASS**。必须用精确规则名集合差。
另：E3 自称「无孤儿规则的唯一判据」，但缺了「E2 失败确实发生」这个前提，是空结论。

**统一新增一条准备条件判据，并逐项改文字**：
> 凡以「0 命中 / 计数不变」作为「消失 / 无新增」结论，必须在**同一轮**先跑阳性对照 `netsh advfirewall show allprofiles`（退出码 0 且输出非空），并确认 `netsh advfirewall firewall show rule name=all` 退出码 0、输出非空；否则判 **NEEDS-VISUAL**，不得判 PASS。结论必须用**精确规则名集合差**（E1 基线文件 vs 当前清单，逐条列出 NEW / REMOVED 名字），不得用行数、计数或日志文件大小。

- **D4** 改为：`等待 ≥ 1 个到期巡检周期并记录实际等待时间`；封禁记录页状态变「已解封」并截图；**精确名集合差显示恰好移除 1 条 `PortGuard_Block_<D2 测试 IP>`、新增 0 条**；且阳性对照通过。只写「>1 分钟」不够——到期解封由巡检节拍驱动，不是 60 秒定时器。
- **E3** 改为：`先确认 E2 两条失败证据都在（日志 marker + 审计 CSV）`；再跑 D3 查询并要求**阳性对照通过**；`NEW 集合中 PortGuard_Block_* 为 0 条`（同时列出 `PortGuard_Allow_*` 的新增）；否则 FAIL。删除「唯一判据」的说法——它是「失败已发生 + 集合无新增」两个条件的合取。
- **G1** 改为：`阳性对照通过后，PortGuard_Block_* 与 PortGuard_Allow_* 合计 0 条`；并写明须在 `01_DEPLOY.txt:102-116` 的**第 2 步（先解封/删规则）完成之后、第 4 步（删程序目录）之前**取证，否则会失去应用内解封入口。

#### P0-4 · **E1**：基线沿用 D3 清单，时序自相矛盾

D4/D5 已经删过规则，E1 却写在 E 组、要求「记录 D 阶段基线：D3 的规则清单」。若真沿用 D3 的旧清单，E3 的集合差会把 D4 移除的那条算成 REMOVED，结论失真。且「记录」是散文，不是可 diff 的产物。

**E1 改为（逐字替换）**：
> **在 E2 注入失败之前、且在任何自动封禁触发之前**，重新采集一次当前 `netsh` 规则名清单，写入 `pg_rules_baseline.txt`（含时间戳、阳性对照状态、逐条规则名，一行一个）。**不得沿用 D3 的旧清单**（D4/D5 已改变规则集）。

#### P0-5 · **F2**：`FileName` 单数 + 3 个配置文件 + 本地化（重点）

证据：
- `core/win_fwlog.py:509-523` 的注释给出中文输出样例 `日志文件路径: C:\Windows\...\pfirewall.log`，代码用 `if "路径" in k or "path" in k.lower()` 双兼容 —— **产品自己都不敢假定标签叫 `FileName`**。
- 本机实测 `netsh advfirewall show allprofiles logging` 输出 **3 行** `FileName`（Domain/Private/Public），值相同。清单写单数「FileName 等于…」，只要有一行是自定义路径就可能被判 PASS。
- `core/win_fwlog.py:516-521` 用 dict 按标签建键，3 个同名键**互相覆盖**，产品读侧只取最后一档 → 更要求 3 行一致。
- `netsh set allprofiles logging filename` 应同时改 3 档；只改一档就是 M5 未修净。

**F2 期望改为（逐字替换）**：
> `netsh advfirewall show allprofiles logging` 退出码 0 且输出非空（阳性对照）。**不要按标签名找**（输出随 OS 语言/版本变化）；从原文抽取所有以盘符或 `%systemroot%` 开头、以 `.log` 结尾的路径值，**必须找到 3 行**（不要去重），3 行**全部**等于 F1 里逐字记下的自定义路径；少于 3 行判 NEEDS-VISUAL，不得判 PASS；任一行仍是 `%SYSTEMROOT%\System32\LogFiles\Firewall\pfirewall.log`（`core/win_fwlog.py:41-48` 的 DEFAULT_LOG_PATH）则 FAIL。截图/报告须同时留下 3 行原文。

#### P0-6 · **B1**：「无错误字符串」不是启动成功的证据

`core/logger.py:99-111, 160-161`：日志按天滚动成 `portguard.log.YYYY-MM-DD` / `_2`；本机实测有 **14 个** `portguard.log*`、历史归档里有 8 条 Traceback。只 grep `portguard.log` 会漏归档；而如果 exe 双击没反应、日志压根没写，「无 Traceback / 无 CRITICAL」同样成立 → 假绿。

**B1 期望改为（逐字替换）**：
> ① 日志目录存在且 `portguard.log*` 在**本次操作时间窗内有新增字节**；② 出现正向启动行 `PortGuard 1.9.5 启动：运行方式=打包 exe 管理员=False` 且时间戳落在本次窗口；③ 满足 ①② 之后，才在**全部** `portguard.log*`（含按天归档）中检查 `界面启动失败` / `Traceback` / `CRITICAL` 均为 0；④ 15s 内主窗口可见、不白屏（截图）。顺序不得颠倒。

#### P0-7 · **B3**：7 个页面 → 实际 **9 个**，且「统计」不是页面（确认漏项）

证据：`gui/main_window.py:73-82` `NAV_ITEMS` 8 项：实时监控 / 风险事件 / 历史访问 / **封禁管理** / **规则配置** / IP 查询 / 运行日志 / 设置；`:95-110` `PAGE_OVERVIEW = 8` 是 stack 的第 9 个 widget（总览台）。清单列的「统计」不是 stack 页面。而 D/E/F 阶段恰恰要在**封禁管理 / 设置**页操作，B3 没验它们能打开就进 D，是顺序漏项。

**B3 期望改为（逐字替换）**：
> 逐页切换 **9 个**页面：总览台 / 实时监控 / 风险事件 / 历史访问 / 封禁管理 / 规则配置 / IP 查询 / 运行日志 / 设置；每页可打开、不崩、不白屏、不出现红色「封禁状态读取失败」横幅（`01_DEPLOY.txt:28-31, 141-143`）；逐页截图留证。

#### P0-8 · **C4**：断言了未经证实的字体回退，且漏掉 125% DPI 组合（重点）

证据：`gui/theme.py:134` 有 4 个候选 `"Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI", sans-serif`。Qt 的 QSS 字体回退**是静默的**：不记录实际选中了哪个家族；如果 `Microsoft YaHei` 家族没注册，Qt 可能落到 `Segoe UI`（2008R2 上有）或 `sans-serif`，度量**不是** §3.2 在 Win10 `Microsoft YaHei UI` 下测的那一套。清单写「QSS 回退到 `Microsoft YaHei` 后…」把未验证的假设写成了判据。
本机实测证据：`C:\Windows\Fonts\msyhui.ttc` **不存在**，但注册表 `HKLM\...\Fonts` 里有 `Microsoft YaHei & Microsoft YaHei UI (TrueType)` → **文件存在性 ≠ 家族可用性**，A5 只看文件不够。
另：§1 第 3 条明写 OS 层差异包含「**125% DPI / 旧版 DWM 下的取整**」，但 C4 只要求「重做 C1/C3」，**没有 C2（125% DPI / 1200×800）**，字体回退 + 高分屏取整这个最坏组合完全没覆盖。

**C4 期望改为（逐字替换）**：
> C4 判据是「**最差文本列在 2008R2 上仍不截断**」，**不得**以字体文件名、或「QSS 回退到 Microsoft YaHei」这一断言代替。A5 须同时给出文件清单与注册表家族名；两者不一致时判 NEEDS-VISUAL 并由人确认 Qt 实际解析到的家族。须在 **C1 / C2 / C3 的全部三种窗口+DPI 组合（含 125% DPI、1200×800）下重做**，并与 Win10 交付栈基线截图（`_design/ux_review/z_port.png`、`z_https_table.png`、`z_monitor_table.png`、`1_monitor.png`、`2_events.png`、`4_bans.png`）并排对比。每次记录 DPI、窗口尺寸、是否注销重登。失败按 §6 回滚（改列宽 → 两栈+目标机三者取大值 → 重建 exe → 新哈希 → 本清单全部重跑）。

---

### P1 — 判据不严密 / 现场不可执行（建议一并改）

| 项 | 问题 | 修订建议（精确文字） |
|---|---|---|
| **A1** | `winver` 是 GUI 弹窗、控制台无输出；`findstr /i "OS"` 在中文系统靠本地化标签；无空值护栏 | 改为「`ver` 的数值 token = `6.1.7601` **且** 注册表 `CurrentBuildNumber=7601` **且** `CSDVersion` 含 `Service Pack 1`（本地化时接受 `SP1` 或 winver 截图）；三条都取到才 PASS，任一取不到判 NEEDS-VISUAL」。 |
| **A2** | 「与侧车一致」——侧车与包一起被替换时仍然一致；`certutil` 失败时输出无 hash，也可能被当成「无 mismatch」 | 改为「`certutil -hashfile` 提取到 **64 位十六进制**，且与侧车哈希、**已知常量 `d27beea6…`** 三方一致；侧车内文件名须为 `PortGuard-v1.9.5.zip`；任一不一致 FAIL，取不到哈希判 NEEDS-VISUAL」。 |
| **A3** | 「0 mismatch」在清单为空/截断时天然成立（0 行也算通过） | 改为「记录实际条目数（已知构建为 **174**，见 §3.3）、已校验数、缺失数、不匹配数；条目数 = 0 判 **FAIL**；缺失=0 且不匹配=0 且已校验>0 才 PASS。注意 `SHA256SUMS.txt` 带 UTF-8 BOM、前 3 行 `#` 注释须跳过；路径相对解压根目录保持不变」。 |
| **A5** | 字体文件 ≠ 已注册家族（本机实测证伪） | 改为「同时记录 `C:\Windows\Fonts` 下 `msyhui.ttc` / `msyh.ttc` / `consola.ttf` 文件存在性，**以及** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts` 中 `Microsoft YaHei UI` / `Microsoft YaHei` / `Consolas` 家族值名；文件与家族不一致时判 NEEDS-VISUAL」。 |
| **B2** | `04_CHANGELOG.txt` 第 1 行是 `PortGuard · 更新日志`，`1.9.5` 首次出现在**第 8 行**；`VERSION.txt` 有 BOM | 改为「`VERSION.txt`（跳过 BOM）、`04_CHANGELOG.txt` 中**首个 `vX.Y.Z` 版本号**、zip 文件名、`PortGuard.exe` 属性→文件版本、程序「关于」页，五处均为 `1.9.5`」。 |
| **B4** | 「观察模式下不写防火墙」只靠顶栏文字 | 改为「B4 前后各跑一次 `netsh advfirewall firewall show rule name=all`，`PortGuard_Block_*` / `PortGuard_Allow_*` **均为 0 条**（阳性对照通过）；并阅读顶栏「权限」列出的可做/需管理员动作」。 |
| **C1 / C3** | 清单写 `23:59:59 ×27`（带空格），真实最差值是 `23:59:59×27`（**无空格**，`_design/render_shots.py:149`）；「造出/灌入样本」没给方法 | 改为「最差值逐字采用 `_design/render_shots.py:146-184` 的 `NO_ELIDE` / `NO_ELIDE_BY_TABLE`：`23:59:59×27`（监控，无空格）、`11-14 11:24:03 ×100`（事件）、`2400:3200:baba::1`、`18080`、`HTTPS`、`2099-12-31 23:59`、`999`、`100`、`[自动] 命中规则：判定风险：1024`；并写明灌样本的入口（导入/造连接），否则判据不可复验」。 |
| **C2** | 2008R2 改 DPI 通常需**注销重新登录**才生效；「各重试一次」组合含糊；截图未含列头 | 改为「分别在 (1360×860, 100%) / (1200×800, 100%) / (1360×860, 125%) 三种组合各做一次；每次改 DPI 后注销重登，截图须含 DPI 设置或 `LogPixels` 值；截图必须包含**列头与整列**、不得裁切或横向滚动隐藏」。 |
| **C5** | 无截图要求 | 补「截图须显示 hover 后的 tooltip 全文，文件名 `PG195_C5_*`」。 |
| **D2** | 「出现一条 active 记录」可能是上一次的旧记录；没记录测试 IP 供 D3/D4/E3 用 | 改为「**恰好新增 1 条** active 记录（记下 ban ID 与测试 IPv4，逐字写入证据索引）；明确**只用 IPv4**（S9：2008R2 IPv6 规则名不可逆，不在 v1.9.5 承诺内）」。 |
| **D3** | 只查 `PortGuard_Block_*`，漏 `PortGuard_Allow_*`（`core/firewall.py:769`）；「存在」不验属性；本地化输出 | 改为「从原文抽取全部 `PortGuard_Block_*` **与** `PortGuard_Allow_*` 规则名（不依赖 `Rule Name:` 标签）；再 `show rule name=<精确名>` 核 `Enabled=Yes` / `Action=Block` / `RemoteIP=<测试 IP>`；产品自身用的是 `name=PortGuard_Block_*` 通配（`core/firewall.py:591`），两种口径都留证」。 |
| **D5** | 「立即」无时间界；同样 0 行假绿 | 改为「手动解封后 ≤5s 内精确名集合差显示该规则 REMOVED、且记录状态同步；阳性对照通过」。 |
| **E4** | 「界面列表没有幽灵记录」可能被筛选/分页掩盖；没确认 DB 已恢复可写 | 改为「清空筛选、翻遍所有分页截图；恢复 DB 可写后**用一次成功手动封禁证明可写**（D2 式，规则出现）；再跑一次 netsh 清点确认库↔防火墙两侧一致」。 |
| **F1** | 「提示已开启」不是生效证据；没记下逐字路径 | 改为「逐字记录 F1 里输入的自定义路径（写入证据索引）、截图成功提示；确认该路径**不是**默认 `…\System32\LogFiles\Firewall\pfirewall.log`；记下操作前 PID」。 |
| **F3** | 「能读到数据」可能是历史行；**按日志文件变大取增量是假绿**（别处流量也会让它变大） | 改为「记录操作前 `pfirewall.log` 的**行数/偏移**，造一次新的被拦截连接，要求监控页出现**时间戳落在本次操作窗口内的新解析行**；并确认增长发生在 **F1 自定义路径文件**上，不是默认文件（`core/win_fwlog.py:426-428` 明写 `logging_enabled()` 只看文件存在，旧文件会一直躺着）」。 |
| **F4** | 没重跑 F2/F3 判据；「不需重启程序」未验证 | 改为「改回默认路径再开启后，**重跑 F2 + F3 的全部判据**（3 行均为默认路径、新拦截数据仍出现）；**进程 PID 前后一致**以证明热更新未重启（`PortWatcher.sync_fwlog_path()`）」。 |
| **G2** | 「按文档单独处理」无判据；且与「全程保留日志/报告/截图」冲突 | 改为「**仅在全部证据已拷出虚拟机之后**执行；先列出 `%APPDATA%\PortGuard\` 完整清单并截图；G2 只做人工确认，脚本不得删除任何文件」。 |
| **G3** | **确认矛盾**：回滚到 A 之前的快照会**销毁 A~G 的全部证据**，而 §5 签字页要「证据文件」；且「确认无静默副作用」放在回滚之后根本无从检查 | 改为「G3 是**最后一步**：回滚前必须把 `portguard.log*`、`diag-*.txt`、`crash-*.txt`、全部截图、F3 日志样本、E2 审计 CSV、`pg_rules_baseline.txt`、`verify_2008r2_report.txt` 拷到**虚拟机/快照之外**；注册表 / 服务 / 开机自启（HKCU Run）的检查**移到回滚之前**完成并截图；回滚后不得再补任何证据」。 |
| **§5 签字页** | ① 机器信息缺：KB2999226 / UCRT 状态（A4 判读依赖它）、OS 语言与区域（netsh 本地化依赖它）、DPI 证据、diag 报告路径、净机证明方式；②「SHIP：30 项全 PASS 或 N/A」过宽，C4/E3/F2/G1 不应允许 N/A；③「CONDITIONAL：仅 C4 失败」假定只有列宽受影响，但字体回退可能影响 B3 全部页面、C5 tooltip、对话框与状态栏 | ① 机器信息表增 5 行；② 改为「C4 / E3 / F2 / G1 不得填 N/A；任何 N/A 须逐项写明书面理由并由复核人签字」；③ CONDITIONAL 补「若 C4 失败，须重新评估 B3 全部 9 页、C5、所有对话框与状态栏的文字完整性，不限于 3 张表」。 |
| **§6 签字后** | 只说附 zip + 侧车 + 签字页 | 补「同时归档证据包（报告 + 截图 + 日志 + CSV + 基线文件 + 证据索引），否则签字页的『证据文件』列无法追溯」。 |

### P2 — 可选

- **D5** 已含在 P1；另建议给「立即」一个明确秒数。
- **A1** 建议保留 `winver` 截图编号格，但把命令判据换成 `ver` + 注册表 + `systeminfo` 三方互证。
- **C1/C2/C3** 建议规定截图为无损 PNG、全窗口含标题栏与状态栏。
- **G1** 建议在 `01_DEPLOY.txt` 第七节顺序之外，单独留一张「卸载前规则清单」截图。

---

## 3. 我怀疑、但本轮无法证实（**不要和上面混在一起**）

1. 2008R2 上 `netsh advfirewall firewall show rule name=all` 是否接受 `name=all`、输出行数/格式是否与 Win10 一致 —— 未证实。脚本已规避：从原文抓 ASCII 规则名，不解析标签，并加阳性对照。
2. 2008R2 是否默认装有 Windows PowerShell 2.0（一般随系统提供，但本会话未核实）。若无，`.bat` 会打印**纯 ASCII** 错误并退出，需人工清单兜底。
3. 2008R2 上 `certutil -hashfile … SHA256` 输出是连续 64 位十六进制还是空格分隔 —— 未实机确认；脚本两种格式都兼容。
4. 2008R2 注册表字体值名的确切写法（是否也用 `Microsoft YaHei & Microsoft YaHei UI (TrueType)` 这种合并命名）—— 未证实；脚本在「文件/家族不一致」时判 `NEEDS-VISUAL` 而非自动 FAIL。
5. 2008R2 未装 KB2999226 时 `--diag` 是否一定打印 `· ucrtbase.dll 系统也缺失` —— 由代码路径推定，未实机确认；脚本把它标为 `NEEDS-VISUAL` 并要求人工记录具体 DLL 名。

---

## 4. 必须人工目视、不可自动化的项 + 证据要求

### 4.1 证据命名规范（统一，纯 ASCII 文件名）

```
PG195_<ITEM>_<DPI>pct_<WxH>_<SEQ>.png
```
例：`PG195_C1_100pct_1360x860_01.png`、`PG195_C2_125pct_1360x860_01.png`、`PG195_B3_100pct_1360x860_03.png`。

另外强制两份索引/佐证：
- `PG195_EVIDENCE_INDEX.txt`（纯 ASCII）：逐行 `<ITEM> <文件名> <证明什么>`，并登记机器名、OS 内部版本、DPI、窗口尺寸、操作时间窗、F1 自定义路径原文、D2 测试 IPv4、E2 CSV 路径。
- `PG195_DPI_SETTING.png` + 索引里记录 `HKCU\Control Panel\Desktop\LogPixels` 实测值（证明 125% 真的生效）。

截图通则：**无损 PNG、整窗口（含标题栏 + 状态栏）、包含列头与整列、不得裁切、不得用横向滚动隐藏列**；C4 的截图必须与 §3.2 的 Win10 交付栈基线图**并排可比**（同尺寸、同 DPI、同样本）。

### 4.2 逐项清单

| 项 | 为什么不能自动化 | 窗口尺寸 / DPI | 画面必须包含 | 截图名 |
|---|---|---|---|---|
| **A1**（winver 截图） | `winver` 是 GUI 弹窗 | — | 版本 6.1.7601 / SP1 字样 | `PG195_A1_winver_01.png` |
| **B1** | 主窗口是否 15s 内出现、是否白屏 | 1360×860 / 100% | 完整主窗口 + 任务栏时钟（证明时间窗） | `PG195_B1_100pct_1360x860_01.png` |
| **B2**（关于页） | 程序内版本号是 GUI 文本 | 1360×860 / 100% | 关于页版本号 | `PG195_B2_100pct_1360x860_01.png` |
| **B3** | 9 个页面逐个打开、不崩不白屏 | 1360×860 / 100% | 每页一张，共 9 张 | `PG195_B3_100pct_1360x860_01..09.png` |
| **B4** | 「权限」面板措辞需人读 | 1360×860 / 100% | 顶栏权限展开态 | `PG195_B4_100pct_1360x860_01.png` |
| **C1** | 列是否省略（`…`）只能看 | **1360×860 / 100%** | 监控页含 `18080` / `HTTPS` / `2400:3200:baba::1` / `23:59:59×27`，列头+整列 | `PG195_C1_100pct_1360x860_01.png` |
| **C2** | 同上 + DPI 取整 | **1200×800 / 100%** 与 **1360×860 / 125%** | 两张，各含 DPI 佐证 | `PG195_C2_100pct_1200x800_01.png`、`PG195_C2_125pct_1360x860_01.png` |
| **C3** | 事件/封禁建议/封禁记录三张表 | 1360×860 / 100% | 三张表最差值列 | `PG195_C3_100pct_1360x860_01..03.png` |
| **C4**（**核心**） | QSS 字体回退静默、Qt 不记录实际家族；必须人眼判「有没有截断」 | **C1/C2/C3 的全部三种组合** | 与 Win10 基线并排可比的同尺寸同 DPI 截图，记录注销重登 | `PG195_C4_100pct_1360x860_01.png`、`PG195_C4_100pct_1200x800_01.png`、`PG195_C4_125pct_1360x860_01.png` |
| **C5** | tooltip 是否显示全文 | 1360×860 / 100% | hover 态 + tooltip 全文 | `PG195_C5_100pct_1360x860_01.png` |
| **D1** | UAC 弹窗 + 提权后顶栏状态 | 1360×860 / 100% | UAC 对话框、提权后顶栏 | `PG195_D1_100pct_1360x860_01..02.png` |
| **D2** | 「恰好新增 1 条 active 记录」需人读 | 1360×860 / 100% | 封禁记录页新增行 + 测试 IP | `PG195_D2_100pct_1360x860_01.png` |
| **D4** | 「已解封」状态是 UI 文本 | 1360×860 / 100% | 记录状态已解封 + 任务栏时间（证明等待时长） | `PG195_D4_100pct_1360x860_01.png` |
| **D5** | 手动解封后的状态同步 | 1360×860 / 100% | 解封前后对比 | `PG195_D5_100pct_1360x860_01..02.png` |
| **E2**（审计 CSV） | 审计行在 SQLite 里，干净机无 Python，只能从 GUI 导出 | 1360×860 / 100% | 设置→操作审计 导出 CSV 的界面 + CSV 文件本身 | `PG195_E2_100pct_1360x860_01.png` + `PG195_E2_audit.csv` |
| **E4** | 封禁列表可能被筛选/分页掩盖 | 1360×860 / 100% | 清空筛选后的每一页 | `PG195_E4_100pct_1360x860_01..NN.png` |
| **F1** | 成功提示 + 实际显示路径 | 1360×860 / 100% | 设置页提示与自定义路径原文 | `PG195_F1_100pct_1360x860_01.png` |
| **F3** | 监控页是否出现**新**数据行 | 1360×860 / 100% | 带本次时间窗时间戳的新行 | `PG195_F3_100pct_1360x860_01.png` |
| **F4** | 热更新未重启（PID 前后一致） | 1360×860 / 100% | 任务管理器 PID 前后两张 + 监控页新行 | `PG195_F4_100pct_1360x860_01..03.png` |
| **G2** | 用户数据目录清单需人工确认不误删 | — | `%APPDATA%\PortGuard\` 完整列表 | `PG195_G2_dir_01.png` |
| **G3** | 回滚前的副作用检查 + 证据外拷 | — | 注册表 Run 项 / 服务 / 开机自启截图、证据外拷清单 | `PG195_G3_prerollback_01..03.png` |

> 脚本对以上每一项都输出 `NEEDS-VISUAL`，**不会**替人打勾。

---

## 5. 「脚本结果 → §5 签字页」对照表

脚本只写 `verify_2008r2_report.txt`（+ `pg_rules_baseline.txt`）。**它不修改 §5 签字页**。下表说明哪些格可以由脚本结果**照抄填入**，哪些必须人填。

### 5.1 机器信息表

| 签字页格子 | 脚本能给什么 | 谁填 |
|---|---|---|
| 机器名 / 是否虚拟机 | 无 | **必须人填**（附虚拟机快照名） |
| OS 全称 + 内部版本 | `A1_OS_VERSION` 的 ver/CurrentBuildNumber/systeminfo token | 脚本给数值，**人填全称并核对 winver 截图** |
| `winver` 截图编号 | 无 | **必须人填**：`PG195_A1_winver_01.png` |
| 是否干净机（无 Python / 无旧版 PortGuard） | 无（脚本不探测 Python） | **必须人填**，附证据：无 Python 命令输出、无残留规则基线 |
| DPI 设置 | 无 | **必须人填**，附 `PG195_DPI_SETTING.png` + `LogPixels` 值 |
| 包 SHA256（须为 `d27beea6…`） | `A2_ZIP_SHA256` 的三方比对结果 | **脚本自动填**（用报告里的 ACTUAL ZIP SHA256 原值） |
| **建议新增**：KB2999226 / UCRT 状态 | `A4_NO_SYSTEM_MISSING` 的 NEEDS-VISUAL 提示 + 具体 DLL 名 | **必须人填** |
| **建议新增**：OS 语言/区域 | 无 | **必须人填**（决定 netsh 输出本地化判据） |
| **建议新增**：diag 报告路径 | `A4 NEW REPORT PATH` | 脚本自动填 |
| **建议新增**：F1 自定义路径 / D2 测试 IPv4 | 命令行入参回显 | 人在证据索引里填，脚本不代填 |

### 5.2 结果汇总表（30 项）

| 项 | 脚本产出 | PASS/FAIL/证据文件列 | 必须人填 |
|---|---|---|---|
| A1 | `A1_OS_VERSION`、`A1_SP1` | PASS/FAIL 可照抄；证据文件 = 报告 + winver 截图 | winver 截图编号、SP1 本地化确认 |
| A2 | `A2_ZIP_SHA256` | 全自动 | — |
| A3 | `A3_PER_FILE_SUMS`（条目数/校验数/缺失/不匹配） | 全自动 | — |
| A4 | `A4_*` 共 10 个子判据 | 全自动（**以 `A4_DIAG_EXIT_0` 为准**） | 「系统也缺失」时的具体 DLL 与 UCRT 结论 |
| A5 | `A5_*` + `C4_PRECONDITION` | 文件/家族证据自动 | 文件与家族不一致时的 `NEEDS-VISUAL` 结论 |
| B1 | `B1_FATAL_MARKERS`、`B1_STARTUP_LINE` | 日志判据自动 | **主窗口 15s 可见、不白屏**必须人填 |
| B2 | `B2_FILE_VERSIONS` | 四处文件版本自动 | **关于页**版本号必须人填 |
| B3 | 无（`B3_ALL_9_PAGES` = NEEDS-VISUAL） | — | **9 页全部人填** |
| B4 | 无 | — | **权限面板措辞 + 前后规则清点**人填 |
| C1 | 无 | — | **全部人填** |
| C2 | 无 | — | **全部人填**（含注销重登证明） |
| C3 | 无 | — | **全部人填** |
| C4 | `C4_PRECONDITION` 仅给前提 | 前提可照抄 | **C4 结论必须人填，不得由脚本代判** |
| C5 | 无 | — | **全部人填** |
| D1 | 无 | — | **全部人填** |
| D2 | 无（`D3_MATCH_TEST_IP` 可辅助） | 规则名辅助 | **「恰好新增 1 条 active」人填** |
| D3 | `D3_BLOCK_RULE_EXISTS`、`D3_MATCH_TEST_IP`、`RULE NAMES *` | 存在性可照抄 | **Enabled / Action / RemoteIP 属性人填** |
| D4 | `D4_RULE_REMOVED_EVIDENCE`（集合差） | 规则移除可照抄 | **「已解封」状态 + 等待时长人填** |
| D5 | `D5_MANUAL_UNBLOCK` = NEEDS-VISUAL + 集合差 | — | **状态同步与 ≤5s 人填** |
| E1 | `E1_BASELINE_SAVED` | 全自动（SAVEBASE 模式） | — |
| E2 | `E2_FAILURE_INJECTION_FIRED`（日志 marker） | 日志 marker 可照抄 | **注入是否真的发生 + 审计 CSV 行必须人填** |
| E3 | `E3_NO_ORPHAN_RULES`（集合差 + E2 前提 + 阳性对照） | **全自动，但仅在 E2 已确认后有效** | 若脚本给 NEEDS-VISUAL，人必须补做 |
| E4 | 无 | — | **清筛选/翻页 + DB 恢复可写验证人填** |
| F1 | 无 | — | **提示 + 逐字路径人填** |
| F2 | `F2_NETSH_CMD` / `F2_NOT_DEFAULT_PATH` / `F2_ALL_PROFILES_CUSTOM`（3 行比对） | **全自动**（须传 F1 路径作为第 2 参） | 未传路径时的 NEEDS-VISUAL 由人补 |
| F3 | 无 | — | **本次时间窗内的新解析行人填** |
| F4 | 无 | — | **重跑 F2+F3 结果 + PID 一致人填** |
| G1 | `G1_NO_RESIDUAL`（当前态快照 + 阳性对照） | 全自动（须在卸载后重跑 FULL） | 卸载顺序确认人填 |
| G2 | 无 | — | **全部人填** |
| G3 | 无 | — | **全部人填**（含证据外拷清单） |

### 5.3 最终裁决 / 签字

| 格子 | 谁填 |
|---|---|
| SHIP / NO SHIP / CONDITIONAL 勾选 | **必须人填**。脚本即使全 PASS 也不得代勾 |
| 各组 PASS / FAIL / N/A 计数 | 自动子判据的计数可照抄；**NEEDS-VISUAL 项一律人填** |
| N/A 书面理由 | **必须人填**（C4/E3/F2/G1 不得 N/A） |
| 执行人 / 日期 / 签字 / 复核 | **必须人填** |

> 一句话：**脚本只负责「证据」和「可判定的子结论」，签字页的 PASS/FAIL 与最终裁决永远由人写。**

---

## 6. 未覆盖的场景（我没能验证的）

- **2008R2 实机**：本会话无干净机（已查证本机 Win10 18363、无 Hyper-V/VMware/VirtualBox/虚拟机目录/进程），**全部 30 项一项都没在目标机上跑过**。
- **PowerShell 2.0 运行时**：语法用 Win10 的 PS5.1 解析器校验为 0 errors，且刻意避开 PS3+ 语法（`Get-Content -Raw` / `Get-FileHash` / `-NoNewline` / `$PSScriptRoot`），但**没有在 PS2.0 上执行过**。
- **2008R2 本地化 netsh / certutil 输出**：见 §3。
- **A3 的 174 次 certutil 在 2008R2 上的耗时**：本机因缺 `SHA256SUMS.txt` 未触发，未实测耗时。
- **C4 实际字体回退结果**：只能靠真机目视，脚本与本报告均无法回答。
- **界面七态**（加载/空/错/部分/超长/重复点击/中途取消）：清单 §4 未把它们列为独立判据，本轮也没补测；建议下一版清单纳入 B3/C 组的空态与超长输入。

---

## 7. 放行结论

❌ **不可上线**（维持 §0 的 `CONDITIONAL → 待签字`）。

理由不是「脚本没跑」，而是两条：
1. **§4 清单本身有 8 处会让签字页误判的确认缺陷**（P0-1 ~ P0-8），尤其 A4 的假红、E2 的路径/审计不可读、D4/E3/G1 的 0 行假绿、F2 的单数 FileName、B3 的页面数、C4 的未证实断言。照现清单签字，存在「全项打勾但仍有问题」的真实风险。
2. **2008R2 干净机实机验证仍未执行**，§5 签字页空白。

**必须修完才能上线的（按顺序）**：
1. 按 §2 的逐字修订改写 `RELEASE_VERIFICATION_v1.9.5.md` §4 的 A1/A2/A3/A4/A5/B1/B2/B3/B4/C1/C2/C3/C4/D2/D3/D4/D5/E1/E2/E3/E4/F1/F2/F3/F4/G1/G2/G3，并补 §5 机器信息 5 行与裁决条件。
2. 把 `verify_2008r2.bat` + `.ps1` 连同本文一起归档到 `_design/ux_review/`（已完成）；签字前**不要**把它们写进 `delivery/` 或产品代码目录。
3. 在真正的 2008R2 干净机上：先快照 → 跑 `SAVEBASE` → 按修订后的清单做 B~F → 跑 FULL/DIFF → 按 §4 命名留齐截图与 CSV → G3 回滚**之前**把证据拷出虚机。
4. 回收 §5 签字页，按 §7 对照表填格；C4/E3/F2/G1 不得 N/A。
5. 才按 §6 发布。

**同类排查**：我搜了全项目，以下位置有与本次「假绿」同源的写法，建议一并留意（本轮不改产品代码）：
- `core/firewall.py:583-584` 已明确写「netsh 输出本地化」→ 凡是靠 `findstr` 中文/英文标签判定的地方都要换成「从原文抓 ASCII 规则名」。
- `core/win_fwlog.py:516-524` 用 dict 收 3 个同名标签，最后一档覆盖前两档 → F2 才必须验 3 行一致。
- `core/win_fwlog.py:426-428` `logging_enabled()` 只看文件存在 → 任何「文件变大 = 有数据」的判据都会假绿（F3）。
- `core/pe_imports.py:498-524` `LegacyAudit.ok` 只看 blockers 与 redist_missing，UCRT 只提示 → A4 的字符串判据与它口径不一致。
- `core/logger.py:99-111` 按天滚动 → 任何只 grep `portguard.log`（不带 `*`）的判据都会漏归档（B1/E2）。
- `_design/render_shots.py:143-184` 的 `NO_ELIDE` 字面量是唯一真源 → C1/C3 的手写样本必须逐字对齐，否则测的是另一串文本。

---

## 附：脚本自检记录（供复核）

| 轮次 | 结果 |
|---|---|
| 字节校验 | `.bat` 2271 B / `.ps1` 40244 B；非 ASCII 字节 0；LF 与 CRLF 数相等；无 BOM |
| PS 语法解析 | `Parser::ParseFile()` → 0 errors |
| Win10 结构冒烟 第 1 轮 | 抓到 `R` 别名吞掉 61 条证据行 → 已改名 `Note` |
| 第 2 轮 | 抓到 `reg.exe` 被 sandbox 禁用、A1 失去判据 → 改用 `Get-ItemProperty` + systeminfo 兜底 |
| 第 3 轮 | 抓到 F2 路径去重把 3 行压成 1 行、字体 `if/elseif` 漏判 → 均已修 |
| 第 4 轮（终） | `bat exit 0`；无本地化报错；报告纯 ASCII；42 条判据（PASS=5 / FAIL=4 / NEEDS-VISUAL=33，均为 Win10 应有结果）；F2 恢复 3 行；A5 冲突正确判 NEEDS-VISUAL |
| 清理 | 已删除 Win10 冒烟生成的 `verify_2008r2_report.txt` 与可能的 `pg_rules_baseline.txt`，**目录内仅剩 2 个交付脚本** |
| 包完整性 | 改动前后 zip SHA256 恒为 `d27beea6bdd67685700d2161aa2b86100ba718da9690cdb4d1a28d77cba17684` |
