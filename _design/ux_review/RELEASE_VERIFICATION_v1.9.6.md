# PortGuard v1.9.6 · 2008R2 干净机验证清单（正式签单）

复核人：严过关（测试质量官）
编制日期：2026-11-16
性质：**正式签单**。本文件把 `VERIFY_2008R2_GATE_REVIEW.md` §2 的逐字修订**实际写进清单正文**，替代 v1.9.5 那份存在 8 处 P0 假绿判据的旧清单用于签字。
修订基线：`_design/ux_review/RELEASE_VERIFICATION_v1.9.5.md`（v1.9.5 原件**保留不动**）
修订来源：`_design/ux_review/VERIFY_2008R2_GATE_REVIEW.md` §2（P0-1 ~ P0-8、P1 表格、§5 / §6 建议）
仓库根：`D:/WorkBuddy/ip防火墙-2region-3.18.0/port-guard`

> **本轮没有在 Windows Server 2008 R2 上执行任何命令**，本机是 Win10 18363。所有 30 项均为待执行签单，不是已通过的结果。

---

## 0. 结论与真实发布状态

**v1.9.5 已经正式发布过了，且发的是修复前的旧包。** 这不是「尚未发布、闸门关闭」的状态，按旧口径写签字页会直接失真。

远端（只读 GET 核实）事实：

| 项 | 值 |
|---|---|
| Release | `PortGuard-v1.9.5`，id `443972998`，`draft=false` / `prerelease=false` |
| 发布时间 | `2026-11-13T08:14:49Z` |
| 主资产 SHA256 | `2a322b4673a2042d26ea44d1f79230462a3a467d68237169fe6e5af174efac84` |
| 下载次数 | `download_count=2` |
| tag 指向 | `PortGuard-v1.9.5` → `a4088580d0a6f0842b2d6ab324f7e356a74a24d8`，**未含 M1~M5 修复** |
| 本地对照 | `HEAD = ae6d54c7…`（= 远端 main）、`HEAD^ = a4088580…` |
| v1.9.6 远端状态 | `GET /releases/tags/PortGuard-v1.9.6` → **404**；`GET /git/ref/tags/PortGuard-v1.9.6` → **404**（均已只读确认） |

用户已拍板：**另起 v1.9.6 重发，旧 v1.9.5 在 Release 说明里标注作废**。原因是同 tag / 同文件名换哈希会造成「同一版本号两个行为体」，验收证据与实际交付物错位。tag / Release name = `PortGuard-v1.9.6`。

> **发布裁决：CONDITIONAL → 待签字。** §4 的 30 项全部 PASS 且回收 §5 签字页之前，不要创建 `PortGuard-v1.9.6` Release、不要推 tag、不要对外分发任何包。取证脚本即使全 PASS 也不构成放行。

**§0 与 v1.9.5 原件的差异**：v1.9.5 原件 §0 与附录中「尚未发布、闸门关闭」的表述在 2026-11-16 已不属实（线上 Release 确实存在且已下载 2 次），本签单**删除该不实表述**，改按 §6 的三层作废口径书写。本轮**没有**执行任何新的发布动作、没有改动任何远端状态。

---

## 1. 能力边界（沿用 v1.9.5 §1，列宽未改）

| 维度 | 本机（v1.9.5 历史验证） | 2008R2 干净机（未验证） |
|---|---|---|
| 操作系统 | Windows 10 专业版 10.0.18363 | Windows Server 2008 R2 SP1 / 6.1.7601 |
| Python / Qt | 交付栈 py3.8.8 + PySide2 5.15.2.1 | 无 Python，只用打包产物 |
| 界面字体 | 有 `Microsoft YaHei UI`（实测 15px） | **没有** `Microsoft YaHei UI`；`gui/theme.py:134` 的 QSS 回退链为 `"Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI", sans-serif`，**Qt 实际选中哪个家族是静默的、不会记录** |
| 防火墙命令 | netsh 可用（Win10 分支） | netsh 分支 + 无 `Get-NetFirewallRule` |
| 运行库 | VC++ 运行库齐备 | 需现场确认 `MSVCP140*.dll` / `VCRUNTIME140*.dll`；2008R2 不自带 UCRT，需 KB2999226 |
| 「干净」 | 否：有 venv、源码、旧包、历史数据库 | 是：无 Python、无旧版 PortGuard、无残留规则 |

**没做到的「OS 层差异」**（v1.9.6 同样未覆盖）：① `netsh advfirewall` 在 6.1 上的输出格式与回退分支；② **字体回退**（C4 硬检查项）；③ 125% DPI / 旧版 DWM 下的取整；④ 干净机上 VC++ 运行库与 UAC 策略；⑤ 「无旧版残留」前提下的首次安装路径。

**列宽未改**：v1.9.6 沿用 v1.9.5 的两栈取大值列宽（见 §3.2），因此 §3 的字体度量实测数据继续有效；但**这不等于 C4 已通过** —— 2008R2 上的实际字体家族仍需真机目视。

---

## 2. M1~M5 修复落点（沿用 v1.9.5 §2）

| # | 缺陷 | 修复落点 | 护栏测试 |
|---|---|---|---|
| **M1** | 自动封禁写库失败仍建防火墙规则 | `core/pipeline.py`：`insert_ban` 异常时写 `ACTION_BAN_AUTO` 失败审计并 `return False`，不再调 `block_ip` | `tests/test_pipeline_auto_ban.py` 2 条；变异 `return False` → `pass` 转红 |
| **M2** | 监控/事件/封禁列截断 + 体检判据本身错误 | `gui/page_monitor.py` / `page_events.py` / `page_bans.py` 列宽按两栈取大值重定；`_design/render_shots.py` 改用 `QFontMetrics.elidedText()`、`ELIDE_PAD=22`、补 worst-case、0 行 tooltip 判 FAIL | `tests/test_ui_layout.py` 17 passed；两栈 1360px 体检 |
| **M3** | 忽略风险事件审计口径随页面而异 | 新增 `app/data_service.set_risk_handled()`（成功/失败都审计 + before 快照）；4 个 GUI 调用点收口 | `tests/test_audit.py` 3 条 |
| **M4** | OpenSSL / PSF 许可缺失 | `delivery/licenses/` 新增 2 份上游全文；`NOTICE` / `02_TERMS.txt` / `00_README.txt` / `04_CHANGELOG.txt` / `README.md` / `tools/pack_release.py` 同步 | `tests/test_delivery_compliance_20261110.py`：`DELIVERY_FILES == 11` |
| **M5** | 防火墙日志写入/读取路径不一致 | 新增 `core/win_fwlog.resolve_log_path()` 作唯一真源；`PortWatcher.sync_fwlog_path()` 热更新 tailer；`gui/page_settings._enable_fwlog()` 把同一 `target` 传给 `enable_logging(path=target)` 并回显实际路径 | `tests/test_win_fwlog.py` 3 条 |

> 以上为 v1.9.5 的**修复落点事实**。v1.9.6 重建 exe 后，必须重新确认这些字面量仍在新 PYZ 内（见 §3.3）。

---

## 3. 已完成的验证（v1.9.5 历史证据 + v1.9.6 已重做实测）

### 3.1 全量门禁（v1.9.5 历史结果表；v1.9.6 结论见 §7）

| 项 | v1.9.5 结果 |
|---|---|
| ruff check / ruff format | `All checks passed!` / `148 files already formatted` |
| mypy | 回到基线 `Found 7 errors in 4 files`（既有债务，非新增） |
| 全量测试 | `1119 passed, 2 skipped`（基线 1108 → +11 条护栏） |
| 两栈 selftest | 44 项全部通过（**v1.9.5 历史值**；v1.9.6 实测两栈均 **45** 项全过，见 §7 门禁基线行） |
| 压测 | `RESULT: PASS`（**仅为 v1.9.5 历史值，不是 v1.9.6 结论**；v1.9.6 复跑两次 FAIL、本机 CPU 96.5~100% 满载 → 判「**无法判定 / 待 QA 空闲环境复核**」，见 §7 门禁基线行） |
| 两栈 `render_shots.py` 1360px 体检 | 两栈均全绿，EXIT=0 |
| 封禁页探针 | 两栈 `OK 封禁页批量功能自检通过` |

> **v1.9.6 不得沿用以上 v1.9.5 历史结果签字**：重建 exe + 重打 zip 后**已重跑全量门禁**，结论见 §7「门禁基线」行（ruff 双绿 / mypy 7 errors 基线 / pytest 1119 passed, 2 skipped / 两栈 selftest 45 项 / 两栈 `render_shots.py` 体检全绿 / PYZ 15 项 PASS / 完整启动冒烟 PASS）。**唯一开放项**：`tools/stress.py refresh` 判「无法判定 / 待 QA 空闲环境复核」，不判回归、不写 PASS，不得据此勾选 SHIP；本表压测那格仅为历史值（见该格括注）。**§4 的 2008R2 干净机 30 项仍全部待执行。**

### 3.2 交付栈 PySide2 字体度量专项（数据沿用，列宽未改）

实测证明评审里建议的 `64 / 76 / 184` 不能照抄：

| 最差文本 | 开发栈 PySide6 / py3.13 | 交付栈 PySide2 / py3.8 | 差异 |
|---|---|---|---|
| 界面字体解析 | `Microsoft YaHei UI 14px` | `Microsoft YaHei UI 15px` | 字号 +1px |
| IPv6 `2400:3200:baba::1` | 118px | **133px** | **+12.7%** |
| 「严重」 | 40px | 42px | +5% |
| 评分 `100` | 21px | 24px | +14% |
| 状态「已封禁」 | 42px | 45px | +7% |
| 徽章+规则名整组 | 196px | 198px | +1% |

最终列宽按**两栈取大值**定，**v1.9.6 未改列宽**，数据继续有效：

```
gui/page_monitor.py  COL_WIDTHS = [96, 52, 160, 98, 64, 76, 209, 52, 130, 70, 96]
gui/page_events.py   COL_WIDTHS = [37, 146, 200, 158, 112, 58, 156, 46, 80, 106]
gui/page_bans.py     BAN_WIDTHS = [33, 158, 240, 116, 56, 46, 88, 132, 132, 96]
gui/page_bans.py     SUG_WIDTHS = [37, 138, 69, 158, 122, 70, 53, 170, 129]
```

交付栈 1360px 监控页逐列余量（真实内缩 22px = QSS padding 18 + FocusFrameHMargin 4）：时间 `23:59:59×27` 74/71 余 3；来源 IP 138/133 余 5；端口 `18080` 42/35 余 7；协议 `HTTPS` 54/37 余 17；状态 `999` 30/21 余 9。

**残留**：以上数字是在 Win10 的 `Microsoft YaHei UI` 下测得。2008R2 无该字体，QSS 回退后的水平度量需真机确认 → 见 §4 / C4。**这些数字不能代替 C4 判据。**

### 3.3 产物重建与一致性（v1.9.6 已重建，待 2008R2 签字）

- **新包 SHA256：`dcee40cf00b05ccfb402bb9436c01545e2362f90b659b0e711ef05de369394da`**。由交付栈重建 exe（`venv38` + PySide2）+ 重打 zip 后产生，**已由 team-lead 独立复验并填入本格、§5 签字页「包 SHA256」格、以及 `verify_expect.txt` 的 `EXPECTED_ZIP_SHA`**；实测 55,723,580 B / 175 entries / `VERSION.txt=PortGuard v1.9.6` / 侧车一致。此值与任何 v1.9.5 历史哈希无关（历史哈希的作废口径见 §6.2），**不得沿用旧值**。
- **PYZ 字节码校验已重做（v1.9.6 实测 `RESULT: PASS`，15 项全 OK）**：用**同一个 py3.8 交付栈解释器**读重建后的 `PYZ.pyz`，`core.config` 字面量 `['1.9.6']`；`gui.page_settings.__setattr__` 的 `co_names` 含 `setattr` 不含 `object`（按 README:579-582 落到目标函数，避开整模块字节的假阳性）；四张表列宽与源码逐项命中；M1/M3/M5 新字面量在包内。**v1.9.5 的旧 PASS 未沿用。**
- `SHA256SUMS.txt` 的条目数、`VERSION.txt`、`04_CHANGELOG.txt` 首个版本条目标题、zip 条目总数都会随新包变化；`verify_expect.txt` 的 `EXPECTED_SUMS_ENTRIES` 须按**新包实测**填写，不得照抄历史值。**2026-11-16 只读实测**（`dist/PortGuard-v1.9.6.zip` 内 `PortGuard/SHA256SUMS.txt`）：哈希行 **174**、总行 177（含 3 行 `#` 注释 / 标题）。注意这与「zip 175 entries、14 份交付材料」**不是同一个数** —— `EXPECTED_SUMS_ENTRIES` 的实测参考值是 **174**，已由 team-lead 核对并写入 `verify_expect.txt` 的 `EXPECTED_SUMS_ENTRIES=174`。
- **以下 v1.9.6 验证均已完成**：`--diag --quiet` exit 0 + 无参完整启动 15s 存活（启动行 `PortGuard 1.9.6 启动：运行方式=打包 exe 管理员=False`，坏痕迹 0）；`tools/pack_release.py --version 1.9.6` 退出码 0；zip 顶层仅 `PortGuard/`、无目录条目、无 STORED、清单逐项哈希 0 mismatch；`_internal/` 内 `PySide2/` + `shiboken2/` 在位、无 PySide6；三个仓库外验证脚本在 `PYTHONIOENCODING=cp1252` 下各实跑 exit 0。

---

## 3A. 发布前闸门复核摘要（新增）

### 3A.1 CI 里没有自动发布路径

| 位置 | 实际内容 | 判定 |
|---|---|---|
| `ci.yml:9-13` | `on: push branches ["**"]` / `pull_request` / `workflow_dispatch` | **无 `release:` 触发、无 `tags` 过滤** |
| `ci.yml:19-109` | 唯一 job `lint-and-test`：准备离线 IP 库 / `setup-python` / 安装依赖 / 依赖瘦身校验 / `ruff check` / `ruff format` / mypy 基线门禁 / `pytest` + 覆盖率 / 上传覆盖率 artifact | **全是门禁，无 publish / upload-release / tag / 推包动作** |

**结论：CI 不会自动发布，发布是纯手工动作。** 因此闸门只能靠本签单 + 书面授权落实，不能指望 workflow 拦截；任何「CI 绿了就能发」的说法都是假绿。

### 3A.2 8 条对外写操作清单（与发布闸门复核对齐）

来源：**安基石的发布闸门复核**（团队内部结论，仓库内无对应文档）。按「动作 / 不可逆点 / 是否需二次授权」列全，**编号以本表为准**（§6.3 引用的动作编号一律指本表；本表是 8 条对外写操作的**唯一权威清单**，§6.3 只是本表的执行时序展开，两者冲突时以本表为准）。

| # | 动作 | 不可逆点 | 是否需二次授权 |
|---|---|---|---|
| 1 | `git add` + `git commit`（26 个 M = 20 项修复相关 + 6 处 v1.9.6 版本联动；另加 2 份新许可全文与 `_design/ux_review/` 取证材料） | 本地提交对象，push 后即公开 | 否（签字后既定），但它是后续所有对外动作的前提 |
| 2 | `git push origin main`（或 API `PATCH /git/refs/heads/main`） | 远端指针前进、public repo 立刻可克隆 | **是** |
| 3 | `POST /git/refs` 单独建 `PortGuard-v1.9.6` tag（可选，默认不发生） | tag 是公开永久引用 | **是**；`POST /releases` 会自动建同名 tag |
| 4 | `POST /releases` 建 `PortGuard-v1.9.6` | public Release 立刻可见、可下载、被索引 | **是（A 核心写动作）** |
| 5 | `POST {upload_url}?name=...`：**第 1 批 ×2**（zip / 侧车）随 #4 同批；**第 2 批 ×1**（**已回收的已签**签字页）在 2008R2 30 项全 PASS 后补传 | 资产公开可下载、digest 永久留痕；**签字页须为回收的已签版本，空白模板不得作为资产上传**；`verify_expect.txt` **永不**作为 Release 资产（上传即与 zip + 侧车同批下发、锚点独立性事实失效）。**分两批是为破时序鸡生蛋**：签字页里的锚点三值要先于验证到达干净机，签字页本身又要等验证完成后才存在 | **是（随 #4 同批；第 2 批需再次授权）** |
| 6 | `PATCH /releases/443972998` 给旧 v1.9.5 标作废 | 覆盖原 body 全文、改 `updated_at` | **是，且必须单独书面授权**（与零 DELETE/PATCH 冲突，不纳入发布脚本；`PATCH` 的 body 是整体替换，须先 GET 回原 body 拼接后再提交） |
| 7 | 通知已下载 2 次的对象 | 对外沟通一经发出不可撤回 | **是** |
| 8 | 归档签字页到 `_design/ux_review/` | 仓库内公开证据 | 否（可随 #1 一起 commit） |

**授权拆分**：#2 / #4 / #5 一次签「**A 路径发布授权**」；**#6 单独签**；**#7 单独签**；**#3 默认不发生**。**本轮 8 条零执行**（严格只读，未动任何远端状态）。

> **顺序约束（必须）**：发布后快照逐字段比对须排在 **#6 之前**，否则 `PATCH` 改了 v1.9.5 的 body，会与「既有 3 条 Release 全字段任何 diff 判失败」自相矛盾。

---

## 4. 2008R2 干净机验证清单（正式签单 · 逐项判定）

> 本节已把 `VERIFY_2008R2_GATE_REVIEW.md` §2 的**逐字修订实际写进正文**，不是附在文档后面的「修订建议」。逐项映射与覆盖率见 §4.1。

### 准备条件

- 一台**干净**的 Windows Server 2008 R2 SP1（内部版本 7601，x64）虚拟机，先做快照便于回滚；
- 机上**没有** Python、没有 venv、没有源码、没有旧版 PortGuard、没有 `PortGuard_Block_*` / `PortGuard_Allow_*` 残留规则；
- 准备一个**管理员**账号与一个**普通用户**账号；
- 把 `PortGuard-v1.9.6.zip` + `PortGuard-v1.9.6.zip.sha256` 拷到本机**纯 ASCII 验证目录，且该目录内只能有这一个 `PortGuard-v*.zip`**（`dist/` 里同时存在 1.9.4 / 1.9.5 / 1.9.6 三个包，脚本自动探测到多个候选会判 ambiguous 硬 FAIL；验证目录若确有多个包，须用 `.bat` 第 4 参显式指定 zip 路径）；
- **`verify_expect.txt`（独立期望锚点）须经 Release 公告 / 签字页等独立渠道单独送达，不得与 zip + 侧车同批生成后一起下发**。字段：`EXPECTED_ZIP_SHA=dcee40cf00b05ccfb402bb9436c01545e2362f90b659b0e711ef05de369394da`、`EXPECTED_VERSION=1.9.6`、`EXPECTED_SUMS_ENTRIES=174`。三者同批下发即锚点失效，A2 退回假绿；**仓库内 `_design/ux_review/verify_expect.txt` 为发布方母版（已填真实值），仅用于生成 Release 公告 / 签字页中的数值，不是送达件、不作为 Release 资产**；验证方须在 2008R2 干净机上经独立渠道人工抄入三值、生成自己机器上的 `verify_expect.txt`，并在 §5 登记渠道与证据**【编码要求，缺了会误判成「包坏了」】**：脚本 `verify_2008r2.ps1:207` 用 `ReadAllText(path, Encoding.ASCII)` 读 expect 文件，故该文件**必须纯 ASCII / 无 BOM / CRLF**。记事本另存时选「**ANSI**」或「**UTF-8 无 BOM**」，**不得选「Unicode (UTF-16)」**（key 会带 `\0` 交错）；若存成 UTF-8 带 BOM，首个 key 会变成 `???EXPECTED_ZIP_SHA`。两种情形都会让 `fieldsOk=False` → `A2_ZIP_SHA256` **硬 FAIL**——这是脚本 fail-closed 的**正确行为**（防假绿），**不是包损坏**；排查时先查 expect 文件编码与字段是否完整，不要去怀疑 zip。（`A2_EXPECT_PROVENANCE` 恒 `NEEDS-VISUAL`）；**时序前提（必须先于 §4 执行）**：Release 公告正文要等 Release 发布后才存在，而 §4 必须先跑完才能回收签字页 → 若锚点只走 Release 公告，就会「要等 Release 才拿得到锚点、要拿锚点才跑得了 §4」的鸡生蛋。**破法**：发布方在**发布前**把三值经**独立渠道**（不经过 GitHub Release 的载体，如发布方直接邮件 / IM 发送给验证方）先行交付，验证方据此在干净机上抄录生成 expect 文件；Release 公告正文里的三值作为**事后可核对副本**，不作为唯一来源。**该前置交付本身即 §5「独立送达渠道与证据」格要记录的内容**。
- 解压到**纯 ASCII 路径**（例 `C:\PG\`）。中文路径会让 Qt 的 `QLibraryInfo.PrefixPath` 推导失败；
- 全程保留 `portguard.log*`、`diag-*.txt`、`crash-*.txt` 与截图作为证据；
- **统一准备条件判据（原 §2 P0-3，适用于 D4 / E3 / G1 及一切「0 命中」结论）**：凡以「0 命中 / 计数不变」作为「消失 / 无新增」结论，必须在**同一轮**先跑阳性对照 `netsh advfirewall show allprofiles`（退出码 0 且输出非空），并确认 `netsh advfirewall firewall show rule name=all` 退出码 0、输出非空；否则判 **NEEDS-VISUAL**，不得判 PASS。结论必须用**精确规则名集合差**（E1 基线文件 vs 当前清单，逐条列出 NEW / REMOVED 名字），**不得用行数、计数或日志文件大小**。

### A. 环境与完整性

| # | 操作 | 期望结果 | PASS/FAIL |
|---|---|---|---|
| A1 | `ver` + 注册表 `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion` + `systeminfo` 三方互证；另留 `winver` 截图 | `ver` 的数值 token = `6.1.7601` **且** 注册表 `CurrentBuildNumber=7601` **且** `CSDVersion` 含 `Service Pack 1`（本地化时接受 `SP1` 或 winver 截图）；三条都取到才 PASS，**任一取不到判 NEEDS-VISUAL**。不得靠 `findstr /i "OS"` 的本地化标签 | ☐ |
| A2 | `certutil -hashfile PortGuard-v1.9.6.zip SHA256`；读 `PortGuard-v1.9.6.zip.sha256`；读独立渠道送达的 `verify_expect.txt` | `certutil` 提取到 **64 位十六进制**，且与侧车哈希、**`verify_expect.txt` 的 `EXPECTED_ZIP_SHA`（独立锚点，值 `dcee40cf00b05ccfb402bb9436c01545e2362f90b659b0e711ef05de369394da`）三方一致**；侧车内文件名须为 `PortGuard-v1.9.6.zip`；`EXPECTED_VERSION` 须等于从 zip 文件名解析出的 `1.9.6`；`EXPECTED_SUMS_ENTRIES` 须等于 `SHA256SUMS.txt` 实际行数；任一不一致 FAIL。**取不到哈希、或 `verify_expect.txt` 缺失 / 字段不全 / 格式错 / 仍是占位 → `A2_ZIP_SHA256 FAIL`（不得判 NEEDS-VISUAL、不得人肉放行）**。取证脚本自动完成三方比对，锚点送达渠道由人在 §5 记录 | ☐ |
| A3 | 按 `03_INTEGRITY.txt` 校验 `SHA256SUMS.txt` | 记录实际条目数（由 `verify_expect.txt` 的 `EXPECTED_SUMS_ENTRIES` 给出，**不使用硬编码常量**）、已校验数、缺失数、不匹配数；**条目数 = 0 判 FAIL**；条目数 ≠ 期望值判 **FAIL**；缺失=0 且不匹配=0 且已校验>0 才 PASS。注意 `SHA256SUMS.txt` 带 UTF-8 BOM、前 3 行 `#` 注释须跳过；路径相对解压根目录保持不变 | ☐ |
| A4 | `C:\PG\PortGuard\PortGuard.exe --diag --quiet` | 报告落盘且为**本次新生成**的 `%APPDATA%\PortGuard\logs\diag-YYYYMMDD-HHMMSS.txt`；`PortGuard.exe --diag --quiet` **退出码 = 0**（`main.py:151-177` 返回 `diag.run()` 的 code，末尾 `sys.exit(main())`）—— **这是权威判据**；`Qt 线路 = PySide2`；`版本判定` 行带 ✓（7601 走「可用…建议 Win8.1」，不是「满足要求」）；`MSVCP140.dll` / `MSVCP140_1.dll` / `MSVCP140_2.dll` / `VCRUNTIME140.dll` / `VCRUNTIME140_1.dll` 五行带 ✓；出现「PySide2（Qt5）线路不依赖 icuuc.dll」；**`【Win7 兼容性】` 段以 ✓ 收尾且无 `[win7-阻断]` / `[win7-运行库]` 行**；`【结论】` 段无 ✗ 行、含「未发现阻塞性问题」；**本次运行未新增 `crash-*.txt`**。若出现「系统也缺失」，须记录**具体 DLL 名**：Qt5 线路下 `· ucrtbase.dll 系统也缺失` 属 `01_DEPLOY.txt` 第一节的部署前置条件（KB2999226），**退出码仍为 0 时不得据此判 FAIL**，改为记录并由人确认 UCRT 状态；**为消除该行而安装 UCRT / KB2999226 会破坏「干净机」前提，不得这样做**。出现「产物内缺失」或「产物内缺少」则 FAIL | ☐ |
| A5 | 确认 `C:\Windows\Fonts` 下字体清单 **+** 注册表 Fonts 键 | 同时记录 `C:\Windows\Fonts` 下 `msyhui.ttc` / `msyh.ttc` / `consola.ttf` 文件存在性，**以及** `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Fonts` 中 `Microsoft YaHei UI` / `Microsoft YaHei` / `Consolas` 家族值名；**预期无 `msyhui.ttc`** → C4 必须做；**文件存在 ≠ 家族可用**，文件与家族不一致时判 NEEDS-VISUAL 并由人确认 Qt 实际解析到的家族 | ☐ |

### B. 普通权限启动（观察模式）

| # | 操作 | 期望结果 | PASS/FAIL |
|---|---|---|---|
| B1 | 用**普通用户**双击 `PortGuard.exe`（不提权、不弹 UAC） | ① 日志目录存在且 `portguard.log*` 在**本次操作时间窗内有新增字节**；② 出现正向启动行 `PortGuard <VERSION> 启动：运行方式=打包 exe 管理员=False`（`<VERSION>` = 从 zip 文件名解析的版本，时间戳落在本次窗口）；③ 满足 ①② 之后，才在**全部** `portguard.log*`（含按天归档 `portguard.log.YYYY-MM-DD` / `_2`）中检查 `界面启动失败` / `Traceback` / `CRITICAL` 均为 0；④ 15s 内主窗口可见、不白屏（截图）。**顺序不得颠倒**；只 grep `portguard.log`（不带 `*`）会漏归档；「无错误字符串」本身不是启动成功的证据。**取证脚本对启动行恒判 `NEEDS-VISUAL`（`B1_WINDOW_PROOF` + `B1_STARTUP_LINE`），不自动 PASS**：历史日志里同版本的启动行长得一模一样，脚本又不启动 GUI，无法把日志行绑定到本次操作时间窗；**本次操作时间窗必须人登记在 `PG196_EVIDENCE_INDEX.txt`** | ☐ |
| B2 | 「关于」页 + 文件四处互证 | `VERSION.txt`（跳过 BOM）、`04_CHANGELOG.txt` **第一个行首版本条目标题**（形如 `v1.9.6 · …`）、zip 文件名、`PortGuard.exe` 属性→文件版本、程序「关于」页，五处均为 `1.9.6`（= zip 文件名解析值 = `verify_expect.txt` 的 `EXPECTED_VERSION`）。**不得取「全文第一个 `vX.Y.Z`」**：v1.9.6 的 CHANGELOG 说明文字里含历史版本（「本日志自 `v1.9.2` 起随交付包提供」），取全文首个会把 `v1.9.2` 当成当前版本判 FAIL；历史条目标题（`v1.9.5` / `v1.9.4` …）排在下方，**只认最靠前的行首条目标题**。取证脚本已按此口径实现并留 `B2 CHANGELOG v-tokens` 诊断行 | ☐ |
| B3 | 逐页切换 | 逐页切换 **9 个**页面：**总览台 / 实时监控 / 风险事件 / 历史访问 / 封禁管理 / 规则配置 / IP 查询 / 运行日志 / 设置**；每页可打开、不崩、不白屏、不出现红色「封禁状态读取失败」横幅（`01_DEPLOY.txt:28-31, 141-143`）；逐页截图留证。**「统计」不是 stack 页面；D/E/F 阶段恰要在封禁管理 / 设置页操作，B3 必须先验它们能打开** | ☐ |
| B4 | 顶栏「权限」查看 + 前后规则清点 | 明确列出「当前可做什么 / 哪些动作需要管理员」；B4 前后各跑一次 `netsh advfirewall firewall show rule name=all`，`PortGuard_Block_*` / `PortGuard_Allow_*` **均为 0 条**（阳性对照通过）；观察模式下不写防火墙 | ☐ |

### C. 视觉验收 · M2（PySide2 真机，重点）

| # | 操作 | 期望结果 | PASS/FAIL |
|---|---|---|---|
| C1 | 窗口 **1360×860、100% DPI**；最差值**逐字**采用 `_design/render_shots.py:146-184` 的 `NO_ELIDE` / `NO_ELIDE_BY_TABLE` | `23:59:59×27`（监控，**无空格**）、`2400:3200:baba::1`、`18080`、`HTTPS`、`2099-12-31 23:59`、`999`、`100`、`[自动] 命中规则：判定风险：1024`；端口列完整 `18080`、协议列完整 `HTTPS`、来源 IP 完整、时间完整，**无 `…` 省略**；**写明灌样本的入口（导入/造连接）**，否则判据不可复验；截图留证 | ☐ |
| C2 | 三种窗口 + DPI 组合各做一次 | 分别在 **(1360×860, 100%) / (1200×800, 100%) / (1360×860, 125%)** 三种组合各做一次；**每次改 DPI 后注销重登**，截图须含 DPI 设置或 `LogPixels` 值；截图必须包含**列头与整列**、不得裁切或横向滚动隐藏；有界列不得被截断 | ☐ |
| C3 | 事件页 / 封禁建议页 / 封禁记录页同样用最差值 | `11-14 11:24:03 ×100`、IPv6、`2099-12-31 23:59`、`[自动] 命中规则：判定风险：1024`；有界列（时间 / IP / 端口 / 评分 / 状态 / 两列到期创建）全部完整；**最差值逐字对齐 `_design/render_shots.py`（唯一真源）**，手写样本不得变形 | ☐ |
| **C4** | **字体回退专项**：A5 确认字体现状后，在 C1 / C2 / C3 的**全部三种组合**下重做 | C4 判据是「**最差文本列在 2008R2 上仍不截断**」，**不得**以字体文件名、或「QSS 回退到 `Microsoft YaHei`」这一未经证实的断言代替。A5 须同时给出文件清单与注册表家族名；两者不一致时判 NEEDS-VISUAL 并由人确认 Qt 实际解析到的家族。须在 **C1 / C2 / C3 全部三种窗口+DPI 组合（含 125% DPI、1200×800）下重做**，并与 Win10 交付栈基线截图（`z_port.png`、`z_https_table.png`、`z_monitor_table.png`、`1_monitor.png`、`2_events.png`、`4_bans.png`）**并排对比**（同尺寸、同 DPI、同样本）。每次记录 DPI、窗口尺寸、是否注销重登。失败按 §6 回滚 | ☐ |
| C5 | 悬停长归属地 / 请求 / 进程 / 原因列 | 允许省略，但 tooltip 必须能看全文；不可出现「省略了又没有途径看全文」；**截图须显示 hover 后的 tooltip 全文**，文件名 `PG196_C5_*` | ☐ |

> C1 里的 IPv6 **只作为显示文本**，不要触发 IPv6 封禁：S9 指出 2008R2 上 IPv6 规则名不可逆，该项不在 v1.9.6 承诺范围内。
> 证据命名统一 `PG196_<ITEM>_<DPI>pct_<WxH>_<SEQ>.png`（v1.9.5 复核文档里的 `PG195_` 前缀仅用于历史证据）；另需 `PG196_EVIDENCE_INDEX.txt`（逐行 `<ITEM> <文件名> <证明什么>`，并登记机器名、OS 内部版本、DPI、窗口尺寸、操作时间窗、F1 自定义路径原文、D2 测试 IPv4、E2 CSV 路径）与 `PG196_DPI_SETTING.png` + `LogPixels` 实测值。截图为无损 PNG、整窗口含标题栏/状态栏、含列头与整列、不得裁切或横向滚动隐藏。

### D. 管理员权限 + 防火墙闭环

| # | 操作 | 期望结果 | PASS/FAIL |
|---|---|---|---|
| D1 | 用 `start-as-admin.bat` 启动 | UAC 弹出、确认后进入管理员态；顶栏权限状态变更 | ☐ |
| D2 | 手动封禁一个**测试用 IPv4**，时长设 1 分钟 | **恰好新增 1 条** active 记录（**记下 ban ID 与测试 IPv4，逐字写入证据索引**），无报错；明确**只用 IPv4**（S9：2008R2 IPv6 规则名不可逆，不在 v1.9.6 承诺内） | ☐ |
| D3 | `netsh advfirewall firewall show rule name=all` | 从原文抽取全部 `PortGuard_Block_*` **与** `PortGuard_Allow_*` 规则名（**不依赖 `Rule Name:` 标签**，输出随 OS 语言本地化）；再 `show rule name=<精确名>` 核 `Enabled=Yes` / `Action=Block` / `RemoteIP=<测试 IP>`；产品自身用 `name=PortGuard_Block_*` 通配（`core/firewall.py:591`），**两种口径都留证**；2008R2 无 `Get-NetFirewallRule`，**必须走 netsh 回退** | ☐ |
| D4 | 等待到期 | **等待 ≥ 1 个到期巡检周期并记录实际等待时间**（到期解封由巡检节拍驱动，不是 60 秒定时器，只写「>1 分钟」不够）；封禁记录页状态变「已解封」并截图；**精确名集合差显示恰好移除 1 条 `PortGuard_Block_<D2 测试 IP>`、新增 0 条**；且**阳性对照通过**；0 行命中 / 计数不变判 NEEDS-VISUAL，不得判 PASS | ☐ |
| D5 | 再建一条封禁，手动点「解封」 | 手动解封后 **≤5s 内**精确名集合差显示该规则 REMOVED、且记录状态同步；阳性对照通过 | ☐ |

### E. M1 黑盒回归（无源码注入，靠制造写库失败）

| # | 操作 | 期望结果 | PASS/FAIL |
|---|---|---|---|
| E1 | **在 E2 注入失败之前、且在任何自动封禁触发之前**，重新采集一次当前 `netsh` 规则名清单 | 写入 `pg_rules_baseline.txt`（含时间戳、阳性对照状态、逐条规则名，一行一个），取证脚本 `SAVEBASE` 模式生成。**不得沿用 D3 的旧清单**（D4/D5 已改变规则集，否则 E3 的集合差会把 D4 移除的那条算成 REMOVED） | ☐ |
| E2 | 先**退出程序**（含托盘）→ 对 **`%APPDATA%\PortGuard\port_guard.db`** 设只读（或对该目录加拒绝写 ACL）→ **用新建临时文件失败确认确实不可写** → 重新启动 → 在设置页**开启自动封禁**并配一条高分规则 → 造一次真实命中触发自动封禁 | `portguard.log*` 出现 `自动封禁：写入 pending 记录失败 ip=`（`core/pipeline.py:234`）；并在 **设置 → 操作审计 → 导出 CSV** 中查到一条 **`result=fail`**、summary 含 `失败：写入封禁记录失败，未创建防火墙规则` 的记录（`core/pipeline.py:246`、`app/audit.py:76`），**附 CSV 文件/截图**。同时确认**注入确实触发**（上述两条都在），否则 E3 不得判 PASS。**注**：交付包没有 `data/portguard.db`；`RESULT_FAIL = "fail"` 是 SQLite 列值，不是文本日志字符串；干净机无 Python，审计行只能从 GUI 导出 CSV 读；默认「只出建议、不自动封禁」（`01_DEPLOY.txt:47`）必须先开启；运行中给已打开 DB 加只读不会撤销已持有的可写句柄，故必须先退出程序 | ☐ |
| E3 | 再跑一次 netsh 查询 | **先确认 E2 两条失败证据都在（日志 marker + 审计 CSV）**；再跑 D3 查询并要求**阳性对照通过**；**`NEW` 集合中 `PortGuard_Block_*` 为 0 条**（同时列出 `PortGuard_Allow_*` 的新增）；否则 FAIL。**删除「唯一判据」的说法** —— 它是「失败已发生 + 集合无新增」两个条件的合取；0 行命中 / 计数不变判 NEEDS-VISUAL，不得判 PASS | ☐ |
| E4 | 恢复数据库可写，确认界面封禁列表里也没有幽灵记录 | **清空筛选、翻遍所有分页截图**；恢复 DB 可写后**用一次成功手动封禁证明可写**（D2 式，规则出现）；再跑一次 netsh 清点确认库 ↔ 防火墙两侧一致 | ☐ |

### F. M5 黑盒回归（日志写读同源）

| # | 操作 | 期望结果 | PASS/FAIL |
|---|---|---|---|
| F1 | 设置页把「防火墙日志路径」改为自定义路径（例 `D:\fwlogs\pfirewall.log`），点「开启防火墙日志」 | **逐字记录输入的自定义路径**（写入证据索引）、截图成功提示；确认该路径**不是**默认 `…\System32\LogFiles\Firewall\pfirewall.log`；**记下操作前 PID** | ☐ |
| F2 | `netsh advfirewall show allprofiles logging` | 退出码 0 且输出非空（阳性对照）。**不要按标签名找**（输出随 OS 语言/版本变化；`core/win_fwlog.py:509-523` 产品自己用 `if "路径" in k or "path" in k.lower()` 双兼容）；从原文**抽取所有**以盘符或 `%systemroot%` 开头、以 `.log` 结尾的路径值，**必须找到 3 行（Domain/Private/Public，不要去重）**，3 行**全部逐字等于** F1 里记下的自定义路径；**少于 3 行判 NEEDS-VISUAL，不得判 PASS**；任一行仍是 `%SYSTEMROOT%\System32\LogFiles\Firewall\pfirewall.log`（`core/win_fwlog.py:41-48`）则 FAIL。截图/报告须同时留下 3 行原文 | ☐ |
| F3 | 造一次被拦截的连接，观察监控页「防火墙日志」通道 | 记录操作前 `pfirewall.log` 的**行数/偏移**，造一次新的被拦截连接，要求监控页出现**时间戳落在本次操作窗口内的新解析行**；并确认增长发生在 **F1 自定义路径文件**上，不是默认文件。**按「日志文件变大」取增量是假绿**（别处流量也会让它变大；`logging_enabled()` 只看文件存在，旧文件会一直躺着） | ☐ |
| F4 | 改回默认路径再开启一次 | **重跑 F2 + F3 的全部判据**（3 行均为默认路径、新拦截数据仍出现）；**进程 PID 前后一致**以证明热更新未重启（`PortWatcher.sync_fwlog_path()`） | ☐ |

### G. 卸载与残留

| # | 操作 | 期望结果 | PASS/FAIL |
|---|---|---|---|
| G1 | 按 `01_DEPLOY.txt` 卸载步骤处理 | **阳性对照通过后**，`PortGuard_Block_*` 与 `PortGuard_Allow_*` 合计 **0 条**；须在 `01_DEPLOY.txt:102-116` 的**第 2 步（先解封/删规则）完成之后、第 4 步（删程序目录）之前**取证，否则会失去应用内解封入口；0 行命中判 NEEDS-VISUAL | ☐ |
| G2 | 检查用户数据目录 | **仅在全部证据已拷出虚拟机之后**执行；先列出 `%APPDATA%\PortGuard\` 完整清单并截图；G2 只做人工确认，**脚本不得删除任何文件** | ☐ |
| G3 | 回滚到 A 之前的虚拟机快照 | **G3 是最后一步**：回滚前必须把 `portguard.log*`、`diag-*.txt`、`crash-*.txt`、全部截图、F3 日志样本、E2 审计 CSV、`pg_rules_baseline.txt`、`verify_2008r2_report.txt` 拷到**虚拟机 / 快照之外**；注册表 / 服务 / 开机自启（HKCU Run）的检查**移到回滚之前**完成并截图；**回滚后不得再补任何证据** | ☐ |

### 4.1 §2 逐字修订落实映射表（30 项覆盖率）

> 「确认的 bug」与「怀疑」严格分开：下表全部对应 §2 有 `文件:行号` 或实测证据的修订；怀疑项仍留在复核文档 §3，未写成判据。

| 项 | §2 来源 | 落实方式 | 关键变化 |
|---|---|---|---|
| A1 | P1 | **逐字改写** | `winver`/`findstr OS` → `ver` + 注册表 `CurrentBuildNumber` + `CSDVersion` 三方互证，取不到判 NEEDS-VISUAL |
| A2 | P1 + team-lead 纠正 1 | **逐字改写** | 两方 → **三方比对**（certutil / 侧车 / `verify_expect.txt` 独立锚点）；expect 缺失/格式错 = `A2_ZIP_SHA256 FAIL`，不得 NEEDS-VISUAL、不得人肉放行 |
| A3 | P1 | **逐字改写** | 补「0 行 = FAIL」、条目数须等于 `EXPECTED_SUMS_ENTRIES`（外置，不写死常量）、BOM 与 `#` 注释跳过 |
| A4 | P0-1 | **逐字改写** | 以 `--diag --quiet` **退出码 0** 为权威判据；补 `【Win7 兼容性】` 段与 `crash-*.txt`；`· ucrtbase.dll 系统也缺失` 在退出码 0 时不得自动 FAIL，并说明装 UCRT 破坏干净机前提；修正「缺失/缺少」两种写法与 U+2713 字形不可靠 |
| A5 | P1 | **逐字改写** | 文件清单 **+** 注册表家族名；文件与家族不一致判 NEEDS-VISUAL |
| B1 | P0-6 + 真实包冒烟复核 | **逐字改写** | 本次时间窗新增字节 + 正向启动行（版本从 zip 名解析）+ 扫全部 `portguard.log*` 归档 + 15s 主窗口；顺序不得颠倒；**脚本同步把「匹配启动行即 PASS」降级为 NEEDS-VISUAL + `B1_WINDOW_PROOF`**（历史同版本启动行会冒充，实测已复现） |
| B2 | P1 + v1.9.6 新包适配 | **逐字改写** | 五处版本互证（跳过 BOM）；CHANGELOG **只取首个行首版本条目标题**，不得取全文首个 `vX.Y.Z`（说明文字含历史版本，取错会在正确包上假红）；脚本同步修复 |
| B3 | P0-7 | **逐字改写** | 7 页 → **9 页名单**；「统计」不是页面 |
| B4 | P1 | **逐字改写** | 补前后各一次 netsh 清点、0 条 + 阳性对照 |
| C1 | P1 | **逐字改写** | 最差值逐字对齐 `render_shots.py`（`23:59:59×27` 无空格）+ 灌样本入口 |
| C2 | P1 | **逐字改写** | 三种窗口+DPI 组合、注销重登、`LogPixels` 佐证、截图含列头整列 |
| C3 | P1 | **逐字改写** | 三张表最差值逐字对齐唯一真源 |
| C4 | P0-8 | **逐字改写** | 判据改为「最差文本列仍不截断」；**不得以字体名 / 回退断言代替**；C1/C2/C3 三种组合全做；与 Win10 基线并排对比 |
| C5 | P1 | **逐字改写** | 补 tooltip 全文截图要求 |
| D1 | —（§2 未提修订） | **原文保留** | 保持 v1.9.5 原文 |
| D2 | P1 | **逐字改写** | 「恰好新增 1 条」、记 ban ID 与测试 IPv4、只用 IPv4 |
| D3 | P1 | **逐字改写** | 抽 `Block_*` **与** `Allow_*`、不依赖本地化标签、核 Enabled/Action/RemoteIP、两种口径留证 |
| D4 | P0-3 | **逐字改写** | 「≥ 1 个到期巡检周期」+ 记录实际等待时间 + 精确名集合差 + 阳性对照 + 0 行判 NEEDS-VISUAL |
| D5 | P1 | **逐字改写** | ≤5s 界 + 集合差 + 状态同步 + 阳性对照 |
| E1 | P0-4 | **逐字改写** | 基线改为 **E2 注入之前重采**，写入 `pg_rules_baseline.txt`，不得沿用 D3 |
| E2 | P0-2 | **逐字改写** | 真实路径 `%APPDATA%\PortGuard\port_guard.db` + 退出程序→设只读→验证不可写→重启→开启自动封禁→设置页导出审计 CSV 查 `result=fail`；去掉 `RESULT_FAIL` 字符串与 `data/portguard.db` |
| E3 | P0-3 | **逐字改写** | E2 两条证据前提 + 阳性对照 + NEW 集合差 + 删「唯一判据」；0 行判 NEEDS-VISUAL |
| E4 | P1 | **逐字改写** | 清筛选/翻页 + DB 恢复可写后用成功手动封禁证明 + 两侧一致复核 |
| F1 | P1 | **逐字改写** | 逐字记录路径、排除默认路径、记 PID |
| F2 | P0-5 | **逐字改写** | 抽 **3 行路径不去重**、全部逐字等于 F1、**<3 行判 NEEDS-VISUAL**、任一行默认路径 FAIL、留 3 行原文 |
| F3 | P1 | **逐字改写** | **去掉「文件变大」**；要求本次时间窗内新解析行 + 增长发生在 F1 自定义路径文件 |
| F4 | P1 | **逐字改写** | 重跑 F2+F3 全部判据 + PID 前后一致 |
| G1 | P0-3 | **逐字改写** | 阳性对照 + 两类规则合计 0 + 卸载顺序窗口 + 0 行判 NEEDS-VISUAL |
| G2 | P1 | **逐字改写** | 仅在证据外拷之后、先列完整清单、脚本不得删文件 |
| G3 | P1 | **逐字改写** | **回滚前证据外拷**、副作用检查移到回滚之前、回滚后不得补证据 |

**覆盖率统计**：§4 共 30 项（A5+B4+C5+D5+E4+F4+G3），**逐项核对 30/30 = 100%**；其中按 §2 逐字改写 **29 项**、§2 未提修订而**原文保留 1 项（D1）**。§2 的修订条目（P0-1~P0-8 共 8 处 + P1 表格 18 行含 §5/§6 建议 + P2 可选）**100% 落进本签单正文**（P2 作为截图通则并入 C 组说明）。

> 与 team-lead 口径的差异说明：指令写「27 项改写、3 项保留」，我按 §2 逐条核对得到 **29 改写 / 1 保留**。差异 2 项，原因是我把 P0-3 的 D4 / E3 / G1 三项全部计入、并把 P1 表格里 `C1 / C3` 合并行拆成两项分别落实。若应按 27/3 口径，请指明哪 2 项应改回原文，我再调整；**当前版本按「§2 有修订文字就落实」处理，不擅自保留有缺陷的判据**。

---

## 5. 签字页

**机器信息**（`【新增】` 5 行为本轮按 §2 / team-lead 要求补齐）

| 项 | 填写 |
|---|---|
| 机器名 / 是否虚拟机 | |
| OS 全称 + 内部版本 | |
| `winver` 截图编号 | |
| 是否干净机（无 Python / 无旧版 PortGuard） | |
| DPI 设置 | |
| 包 SHA256（须为 `dcee40cf00b05ccfb402bb9436c01545e2362f90b659b0e711ef05de369394da`） | |
| **【新增】KB2999226 / UCRT 状态（A4 判读依赖）** | |
| **【新增】OS 语言 / 区域（netsh 输出本地化依赖）** | |
| **【新增】DPI 证据（`PG196_DPI_SETTING.png` + `LogPixels` 实测值）** | |
| **【新增】diag 报告路径（`%APPDATA%\PortGuard\logs\diag-YYYYMMDD-HHMMSS.txt`，本次新生成那份）** | |
| **【新增】净机证明方式（无 Python 命令输出 / 无残留规则基线 / 虚拟机快照名）** | |
| **【新增】`verify_expect.txt` 独立送达渠道与证据（锚点 provenance）** | |
| **【新增】锚点前置交付时间戳（须早于 §4 首项执行）** | |
| **【新增】F1 自定义路径原文 / D2 测试 IPv4** | |

**人工确认格（不可自动化，必须人填）**

| 格子 | 填写 |
|---|---|
| **【人工确认】旧 v1.9.5 已标注作废（附证据链接 / 截图）** | ☐ 是　☐ 否　证据：____________________　执行人：______　日期：______ |

> 该格**不可由脚本判定**：需要人去线上 Release `443972998` 目视确认作废说明已生效并留链接/截图。取证脚本对此恒为 `NEEDS-VISUAL`，不会代勾。

**结果汇总**

| 分组 | 项目数 | PASS | FAIL | N/A | 证据文件 | 执行人 | 日期 |
|---|---|---|---|---|---|---|---|
| A 环境与完整性 | 5 | | | | | | |
| B 普通权限启动 | 4 | | | | | | |
| C 视觉验收 M2 | 5 | | | | | | |
| D 防火墙闭环 | 5 | | | | | | |
| E M1 孤儿规则 | 4 | | | | | | |
| F M5 日志同源 | 4 | | | | | | |
| G 卸载残留 | 3 | | | | | | |
| **合计** | **30** | | | | | | |

**最终裁决**（勾选其一，**必须由人手写**）

- ☐ **SHIP**：30 项全 PASS 或 N/A 且有书面理由 → 允许按 §6 发布。**C4 / E3 / F2 / G1 不得填 N/A**；任何 N/A 须逐项写明书面理由并由复核人签字；**取证脚本即使全 PASS 也不得代勾 SHIP**。
- ☐ **NO SHIP**：存在 FAIL → 回到修复流程，重建 exe、重打包、产生新哈希，本清单重新全跑。
- ☐ **CONDITIONAL**：仅 C4 失败 → 按「两栈 + 目标机字体」三者取大值重定列宽，重跑 §3 后再来一次；**若 C4 失败，须重新评估 B3 全部 9 页、C5、所有对话框与状态栏的文字完整性，不限于 3 张表**。

签字：____________　复核：____________　日期：____________

### 5.4 「脚本结果 → 签字页」对照表（v1.9.6 口径）

脚本只写 `verify_2008r2_report.txt`（+ `pg_rules_baseline.txt`），**不修改本签字页**。下表说明哪些格可照抄、哪些必须人填。

**机器信息表**

| 签字页格子 | 脚本能给什么 | 谁填 |
|---|---|---|
| 机器名 / 是否虚拟机 | 无 | **必须人填**（附快照名） |
| OS 全称 + 内部版本 | `A1_OS_VERSION` 的 ver / CurrentBuildNumber / systeminfo token | 脚本给数值，**人填全称并核对 winver 截图** |
| `winver` 截图编号 | 无 | **必须人填**：`PG196_A1_winver_01.png` |
| 是否干净机 | 无（脚本不探测 Python） | **必须人填**，附证据 |
| DPI 设置 / **【新增】DPI 证据** | 无 | **必须人填**，附 `PG196_DPI_SETTING.png` + `LogPixels` |
| 包 SHA256 | `A2_ZIP_SHA256` 三方比对 + 报告里的 `A2 CERTUTIL ACTUAL SHA256` 原值 | 脚本给数值，**人填 `dcee40cf00b05ccfb402bb9436c01545e2362f90b659b0e711ef05de369394da` 实测值并核对 `verify_expect.txt`**；**哈希不符单元格不可人肉放行** |
| **【新增】KB2999226 / UCRT 状态** | `A4_NO_SYSTEM_MISSING` 的 NEEDS-VISUAL 提示 + 具体 DLL 名 | **必须人填** |
| **【新增】OS 语言 / 区域** | 无 | **必须人填** |
| **【新增】diag 报告路径** | 报告里的 `A4 NEW REPORT PATH` | 脚本自动填 |
| **【新增】净机证明方式** | 无 | **必须人填** |
| **【新增】`verify_expect.txt` 独立送达渠道** | `A2_EXPECT_PROVENANCE` 恒为 NEEDS-VISUAL | **必须人填**（记录渠道 + 证据；脚本不代判） |
| **【新增】F1 路径 / D2 测试 IPv4** | 命令行入参回显 | 人在 `PG196_EVIDENCE_INDEX.txt` 填 |
| **【人工确认】旧 v1.9.5 已标注作废** | 无 | **必须人填，不可自动化**（附证据链接/截图） |

**30 项结果汇总表**

| 项 | 脚本产出 | 可照抄 | 必须人填 |
|---|---|---|---|
| A1 | `A1_OS_VERSION`、`A1_SP1` | PASS/FAIL 可照抄 | winver 截图编号、SP1 本地化确认 |
| A2 | `A2_ZIP_SHA256`、`A2_EXPECT_PRESENT/FORMAT`、`A2_HASH_MATCH`、`A2_ANCHOR_MATCH`、`A2_VERSION_MATCH` | **全自动**（三方比对） | **锚点独立送达渠道人填**；哈希不符不可人肉放行 |
| A3 | `A3_PER_FILE_SUMS`、`A3_MANIFEST_COUNT` | 全自动 | — |
| A4 | `A4_*` 共 10 个子判据 | 全自动（**以 `A4_DIAG_EXIT_0` 为准**） | 「系统也缺失」时的具体 DLL 与 UCRT 结论 |
| A5 | `A5_*` + `C4_PRECONDITION` | 文件/家族证据自动 | 文件与家族不一致时的 NEEDS-VISUAL 结论 |
| B1 | `B1_FATAL_MARKERS`（自动）、`B1_WINDOW_PROOF` / `B1_STARTUP_LINE`（恒 NEEDS-VISUAL） | fatal markers 结论可照抄 | **本次操作时间窗、启动行时间戳是否落在窗口内、主窗口 15s 可见不白屏**必须人填；启动行脚本不自动 PASS |
| B2 | `B2_FILE_VERSIONS` | 四处文件版本自动 | **关于页**版本号必须人填 |
| B3 | 无（`B3_ALL_9_PAGES` = NEEDS-VISUAL） | — | **9 页全部人填** |
| B4 | 无 | — | **权限面板措辞 + 前后规则清点**人填 |
| C1 / C2 / C3 / C5 | 无 | — | **全部人填**（C2 含注销重登证明） |
| C4 | `C4_PRECONDITION` 仅给前提 | 前提可照抄 | **C4 结论必须人填，不得由脚本代判；不得填 N/A** |
| D1 | 无 | — | **全部人填** |
| D2 | 无（`D3_MATCH_TEST_IP` 可辅助） | 规则名辅助 | **「恰好新增 1 条 active」人填** |
| D3 | `D3_BLOCK_RULE_EXISTS`、`D3_MATCH_TEST_IP`、`RULE NAMES *` | 存在性可照抄 | **Enabled / Action / RemoteIP 属性人填** |
| D4 | `D4_RULE_REMOVED_EVIDENCE`（集合差） | 规则移除可照抄 | **「已解封」状态 + 实际等待时长人填** |
| D5 | `D5_MANUAL_UNBLOCK` = NEEDS-VISUAL + 集合差 | — | **状态同步与 ≤5s 人填** |
| E1 | `E1_BASELINE_SAVED` | 全自动（SAVEBASE 模式） | — |
| E2 | `E2_FAILURE_INJECTION_FIRED`（日志 marker） | 日志 marker 可照抄 | **注入是否真的发生 + 审计 CSV `result=fail` 行必须人填** |
| E3 | `E3_NO_ORPHAN_RULES`（集合差 + E2 前提 + 阳性对照） | **全自动，但仅在 E2 已确认后有效**；不得填 N/A | 脚本给 NEEDS-VISUAL 时人必须补做 |
| E4 | 无 | — | **清筛选/翻页 + DB 恢复可写验证人填** |
| F1 | 无 | — | **提示 + 逐字路径人填** |
| F2 | `F2_NETSH_CMD` / `F2_NOT_DEFAULT_PATH` / `F2_ALL_PROFILES_CUSTOM`（3 行比对） | **全自动**（须传 F1 路径作为第 2 参）；不得填 N/A | 未传路径时的 NEEDS-VISUAL 由人补 |
| F3 / F4 | 无 | — | **本次时间窗内的新解析行 / 重跑 F2+F3 + PID 一致人填** |
| G1 | `G1_NO_RESIDUAL`（当前态快照 + 阳性对照） | 全自动（须在卸载后重跑 FULL）；不得填 N/A | 卸载顺序确认人填 |
| G2 / G3 | 无 | — | **全部人填**（含证据外拷清单） |
| 最终裁决 SHIP / NO SHIP / CONDITIONAL | 无 | — | **必须人填**；脚本全 PASS 也不代勾 |
| N/A 书面理由 | 无 | — | **必须人填**（C4/E3/F2/G1 不得 N/A） |
| 执行人 / 日期 / 签字 / 复核 | 无 | — | **必须人填** |

> 一句话：**脚本只负责「证据」和「可判定的子结论」；签字页的 PASS/FAIL、锚点独立渠道、旧版作废确认与最终裁决永远由人写。**

---

## 6. 发布闸门（Gate）

### 6.1 当前状态（2026-11-16，只读核实）

- 远端 `PortGuard-v1.9.5` Release（id `443972998`）**已正式发布**：`published_at=2026-11-13T08:14:49Z`，`draft=false`，主资产 digest `2a322b46…efac84`，`download_count=2`，tag → `a4088580…`（未含 M1~M5）。
- 本地 `HEAD = ae6d54c7…` = 远端 main；`HEAD^ = a4088580…`。
- `GET /releases/tags/PortGuard-v1.9.6` → **404**；`GET /git/ref/tags/PortGuard-v1.9.6` → **404**（v1.9.6 尚未发布、tag 未创建）。
- `dist/` 里现有 `PortGuard-v1.9.4.zip`、`PortGuard-v1.9.5.zip`（`d27beea6…84`）、新增 `PortGuard-v1.9.6.zip`（`dcee40cf00b05ccfb402bb9436c01545e2362f90b659b0e711ef05de369394da`）及各自侧车；三个旧包**保持不动**，本轮未覆盖任何既有包。

### 6.2 三层作废（必须闭环）

1. **线上 `PortGuard-v1.9.5` 资产 `2a322b4673a2042d26ea44d1f79230462a3a467d68237169fe6e5af174efac84` 作废**：它是修复前构建、tag 指向的 commit 不含 M1~M5、且未经 2008R2 干净机验证；**作废声明草稿 `DEPRECATION_NOTICE_v1.9.5.md` 已备妥但尚未公开；标注 Release / 发公告 / 通知已下载 2 次对象均需单独书面授权，本轮零执行**；**已下载 2 次的告知与处置需单独书面授权**（§3A.2 #6 旧 Release 标作废、#7 通知下载对象，两项均需单独书面授权）。
2. **本地 v1.9.5 候选包 `d27beea6bdd67685700d2161aa2b86100ba718da9690cdb4d1a28d77cba17684` 作废**：虽含 M1~M5，但同 tag / 同文件名两个哈希 = 「同一版本号两个行为体」，验收证据与交付物错位。**不得**用它替换线上资产，也**不得**再以 1.9.5 名义发布。
3. **以 v1.9.6 新哈希为准**：tag / Release name = `PortGuard-v1.9.6`；新包 SHA256 = **`dcee40cf00b05ccfb402bb9436c01545e2362f90b659b0e711ef05de369394da`**（交付栈重建 exe + 重打 zip 产生，已同步填入 §3.3、§5 与 `verify_expect.txt` 的 `EXPECTED_ZIP_SHA`）。

> 上述两处历史哈希（① ②）是**作废对象的事实依据**，必须留档；**`dcee40cf00b05ccfb402bb9436c01545e2362f90b659b0e711ef05de369394da` 才是新签单的期望值**。两者不得混用：A2 期望值、§5「包 SHA256」格、§3.3「新包 SHA256」一律用本值，**不写 `d27beea6…`**。

### 6.3 签字前 / 签字后

**签字前**：不创建 `PortGuard-v1.9.6` Release、不推 tag、不对外分发任何包；`dist/` 现有包保持不动；§3A.2 的 8 条对外写操作一条都不执行（#6 / #7 需单独书面授权）。

**签字后**

1. **[§3A.2 #1→#2→#4→#5]** 走 README 发版流程，tag / Release name = `PortGuard-v1.9.6`，**资产分两批上传**（解决「签字页要靠 Release 才能拿到锚点、而锚点又要先于验证拿到」的时序鸡生蛋）：**第 1 批（发布时）** = zip + 侧车 `.sha256` 两个资产；**第 2 批（2008R2 30 项全 PASS、已签签字页回收后）** = 补传**已回收的已签**签字页。`verify_expect.txt` **不作为 Release 资产**；其三个值 `EXPECTED_ZIP_SHA` / `EXPECTED_VERSION` / `EXPECTED_SUMS_ENTRIES` 写入 **Release 公告正文 + 已签签字页**，由验证方在 2008R2 干净机上经该独立渠道**人工抄入**、生成自己机器上的 `verify_expect.txt`，并在 §5「`verify_expect.txt` 独立送达渠道与证据」格登记渠道与证据（`A2_EXPECT_PROVENANCE` 恒 `NEEDS-VISUAL`）；
2. **[§3A.2 #4 后、#6 前]** 发布前后抓旧版 Release 快照逐字段比对（发布脚本只 POST、零 DELETE/PATCH；`PATCH /releases/443972998` 改旧 body 属**授权后的一次性独立动作**，不得纳入发布脚本，且 `PATCH` 的 body 是整体替换须先 GET 取回原文）；
3. **[§3A.2 #8]** **同时归档证据包**（报告 + 截图 + 日志 + CSV + 基线文件 + 证据索引），否则签字页的「证据文件」列无法追溯；
4. **[§3A.2 #8]** 把签字页归档到 `_design/ux_review/`；**补传已签签字页作为第 2 批资产（§3A.2 #5 第 2 批，需再次授权）**。

**Release 公告正文模板（中英双版，发布时直接取用，不得临时编造）**

> Release 公告正文是锚点三值的**独立渠道之一**，必须包含下列三值；本 Release **不提供** 任何 `verify_expect.txt` 下载。

```
[中文版]
独立校验锚点（请在干净机上人工抄入以下三值，生成你自己机器上的 verify_expect.txt；
本 Release 不提供任何 expect 文件下载，请勿直接复用他人机器上的副本）：
  EXPECTED_ZIP_SHA      = dcee40cf00b05ccfb402bb9436c01545e2362f90b659b0e711ef05de369394da
  EXPECTED_VERSION      = 1.9.6
  EXPECTED_SUMS_ENTRIES = 174
  A2_EXPECT_PROVENANCE  = NEEDS-VISUAL（须人工确认送达渠道并留证，见已签签字页 §5）

[English]
Independent verification anchor. Copy the three values below BY HAND onto the
clean verification machine and generate your own verify_expect.txt. This
release ships NO expect file for download; do not reuse a copy from another
machine:
  EXPECTED_ZIP_SHA      = dcee40cf00b05ccfb402bb9436c01545e2362f90b659b0e711ef05de369394da
  EXPECTED_VERSION      = 1.9.6
  EXPECTED_SUMS_ENTRIES = 174
  A2_EXPECT_PROVENANCE  = NEEDS-VISUAL (human must confirm the delivery channel
                                           and record evidence on the signed sheet)
```

> 三值必须与包内 `SHA256SUMS.txt`、侧车 `.sha256`、本签单 §3.3 / §5 逐字一致。
> 若 `verify_expect.txt` 缺失 / 字段不全 / 格式错 / 仍是占位 → **A2 硬 FAIL**，不得判 `NEEDS-VISUAL`、不得人肉放行。

**若 C4 失败的回滚代价**（提前说清，避免有人想「现场改个数字就发」）

改列宽 → 重跑 `tests/test_ui_layout.py` + 两栈 `render_shots.py` + 全量门禁 → 用交付栈重建 exe（删 `build/port_guard` + `dist/PortGuard`）→ **PYZ 字节码校验重做** → 重跑 exe 冒烟 → 重打 zip → **新 SHA256（占位值随之更新）** → 本清单重新全跑。这不是「改个常数」，因为包内字节码、清单哈希、侧车哈希、独立锚点全都要跟着变。

---

## 7. 对原评审 §六「不确定项」的更新（v1.9.6 口径）

| 项 | 原状态 | v1.9.6 更新 |
|---|---|---|
| 交付栈（PySide2）实际字体度量 | 未查实 | **已查实（Win10 上的 PySide2 交付栈）**：界面字体 15px、IPv6 最差文本 133px vs 开发栈 118px（+12.7%）、两栈 1360px 体检全绿；**列宽未改，数据沿用**。**2008R2 的字体回退仍待清单 C4** |
| 产物 = 当前源码 | 已核验（v1.9.5） | **已重做**：v1.9.6 用 py3.8 交付栈解释器重读 `PYZ.pyz`，15 项全 OK（`APP_VERSION='1.9.6'` / `__setattr__` co_names / 四张表列宽 / M1/M3/M5 字面量），未沿用旧 PASS |
| 交付包完整性 | 14 份材料 / 175 entries / `d27beea6…` | **已重打并复验**：新包 SHA = `dcee40cf00b05ccfb402bb9436c01545e2362f90b659b0e711ef05de369394da`；55,723,580 B / 175 entries / 14 份材料 / `SHA256SUMS.txt` 174 条哈希行（177 总行）/ `VERSION.txt=PortGuard v1.9.6` / 侧车一致；`EXPECTED_SUMS_ENTRIES=174` |
| 门禁基线 | 1119 passed / 2 skipped；mypy 7 errors | **v1.9.6 已重跑**：ruff 双绿（148 files）、mypy 7 errors / 4 files 基线、pytest 1119 passed / 2 skipped、两栈 selftest 45 项、两栈 `render_shots.py` 体检全绿、PYZ 15 项 PASS、完整启动冒烟 PASS。**唯一开放项**：`tools/stress.py refresh` 两次 FAIL（200 行 115.2/151.9ms、2000 行 1498.6/1491.2ms），但本机 CPU 连续 4 次 96.5~100% 满载且成员进程归零 → 判「**无法判定 / 待 QA 空闲环境复核**」，不判回归、不写 PASS |
| 2008R2 干净机实机验证 | 评审未覆盖 | **仍未覆盖** —— 本签单 30 项待执行，见 §4 / §5 |
| §4 清单判据质量 | 8 处 P0 假绿 / 假红 | **本签单已按 §2 逐字改写 29 项、保留 1 项（D1），见 §4.1 映射表** |
| 线上发布状态 | 写作「尚未发布、闸门关闭」 | **已纠正**：v1.9.5 Release 已发布且已下载 2 次；v1.9.6 tag/Release 只读确认 404；见 §0 / §6 |
| 畸形 `rules.json` / 假拦截 / 并发同 IP / 打包可复现性 | 未查实 | 保持未查实，均非 v1.9.6 上线阻断项 |

---

## 附 A. 本轮未做的事（避免误读）

- **没有**在 2008R2 上跑过任何一条命令；本机是 Win10 18363，全部 30 项仍是待执行签单；
- **没有**执行任何新的发布动作、**没有**改动任何远端状态、**没有**推 `PortGuard-v1.9.6` tag；§3A.2 的 8 条对外写操作一条都未执行；
- **已删除** v1.9.5 原件 §0 与附录里「尚未发布、闸门关闭」的不实表述 —— 线上 v1.9.5 Release 确实存在（id 443972998、2 次下载），改按 §6 三层作废书写；
- **没有**改动任何 v1.9.5 历史文档（不覆盖、不重命名、不删除）；
- **没有**改动产品代码、**没有**写进 `delivery/`、**没有**动 `dist/` 里的现有包（改动前后 `PortGuard-v1.9.5.zip` 哈希恒为 `d27beea6…84`）；
- 取证脚本只在 Win10 上做过结构冒烟（证明能跑完、不报错、报告纯 ASCII），**不是 2008R2 验证证据**；冒烟报告与临时 fixture 已清理。

---

## 附 B. 证据链（三份 v1.9.5 历史文档，不覆盖、不重命名）

| # | 文件 | 在本签单中的作用 |
|---|---|---|
| 1 | `_design/ux_review/RELEASE_VERIFICATION_v1.9.5.md` | 修订基线：§1 能力边界、§4 原 30 项、§5 签字页、§6 闸门。**原件保留不动** |
| 2 | `_design/ux_review/RELEASE_REVIEW_v1.9.5.md` | 评审当时快照：M1~M5、S9、门禁基线、「未查实」项原样留档。**原件保留不动** |
| 3 | `_design/ux_review/DEPRECATION_NOTICE_v1.9.5.md` | 远端只读事实、作废声明草稿、授权状态表（§五）。**原件保留不动**（状态仍为 DRAFT，公开需单独授权）。§3A.2 的 8 条清单来源为安基石发布闸门复核，非本文 |

补充引用（同样保留不动）：
- `_design/ux_review/VERIFY_2008R2_GATE_REVIEW.md` —— §2 逐字修订的**唯一来源**、§4 人工目视清单与证据命名规范；其 §5 对照表为 v1.9.5 口径，已被本签单 §5.4 取代；
- `_design/ux_review/UX_REVIEW_v1.9.5.md` —— UX 评审快照；
- `.github/workflows/ci.yml` —— §3A 发布前闸门复核的只读依据（`:9-13`、`:19-109`）。

---

## 附 C. 取证脚本与独立锚点（v1.9.6 口径）

| 文件 | 说明 |
|---|---|
| `verify_2008r2.bat` | 双击入口；CRLF + 纯 ASCII + 无 BOM；第 4 参可显式指定 zip、第 5 参可显式指定 `verify_expect.txt` |
| `verify_2008r2.ps1` | 取证主体；PowerShell 2.0 语法、纯 ASCII、只读；A2 为**三方比对** |
| `verify_expect.txt` | **外部独立期望锚点**：`EXPECTED_ZIP_SHA` / `EXPECTED_VERSION` / `EXPECTED_SUMS_ENTRIES`；纯 ASCII / CRLF / 无 BOM |

**护栏要点**

1. A2 三方比对 = `certutil` 实测 vs 侧车 `.sha256` vs `verify_expect.txt` 独立锚点。若 zip 与侧车**一起被替换**，两方比对仍会 PASS，第三方锚点才能抓到。
2. `verify_expect.txt` **必须经 Release 公告 / 签字页独立渠道送达，不得与 zip + 侧车同批生成后一起下发**；这条已写进 `.bat` 头部、`.ps1` 头部、报告头部与 `A2_EXPECT_PROVENANCE` 判据。
3. **脚本启动即检查** expect 文件存在且字段齐全；**缺失 / 格式错 / 仍是占位 → `A2_ZIP_SHA256 FAIL`**，不得判 `NEEDS-VISUAL`、不得人肉放行。细分判据：`A2_EXPECT_PRESENT` / `A2_EXPECT_FORMAT` / `A2_ANCHOR_MATCH` / `A2_VERSION_MATCH` / `A2_HASH_MATCH` / `A2_SIDECAR_PRESENT` / `A2_SIDECAR_FORMAT` / `A2_ZIP_SHA256` / `A3_MANIFEST_COUNT`。
4. **脚本正文无任何版本 / 哈希 / 包名字面量**：版本号从 `PortGuard-v*.zip` 文件名解析，期望值全部来自外部文件；报告版本标签同样动态生成，纯 ASCII。
5. 脚本**只读**：不创建/删除防火墙规则、不改数据库、不改产品文件、不重打包、不启动 GUI（只跑 `--diag --quiet`）；所有视觉项恒为 `NEEDS-VISUAL`，脚本不签字、不改 §5。
6. **占位 / 缺失 / 格式错 / 字段不全 → `A2_ZIP_SHA256` 硬 FAIL** 是**设计意图**（防止未填锚点就放行），不是缺陷、不得判 `NEEDS-VISUAL`、不得人肉放行。仓库内 `_design/ux_review/verify_expect.txt` 是**发布方母版**，已填真实值（`EXPECTED_ZIP_SHA=dcee40cf00b05ccfb402bb9436c01545e2362f90b659b0e711ef05de369394da` / `EXPECTED_VERSION=1.9.6` / `EXPECTED_SUMS_ENTRIES=174`），仅用于生成 Release 公告 / 签字页里的数值，**不作为交付件、不作为 Release 资产、不与 zip + 侧车同批下发**；验证方须在干净机上经独立渠道人工抄入三值生成自己机器上的 `verify_expect.txt`，并在 §5 登记渠道与证据。直接复制母版文件 ≠ provenance 闭环。
