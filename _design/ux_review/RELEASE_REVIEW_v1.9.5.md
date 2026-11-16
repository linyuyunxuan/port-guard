# PortGuard v1.9.5 上线前评估报告

评审日期：2026-11-14
评审方式：六专家并行评审（测试质量 / 架构 / UI·UX / 代码质量 / 安全与发布运维 + 交付总监汇编）
仓库根：`D:/WorkBuddy/ip防火墙-2region-3.18.0/port-guard`（内容即仓库根，无内层目录）
评审期间**未修改任何产品代码**（`git diff` 为空）

> **复核补记（2026-11-14，修复后）**：本文是「评审当时」的快照，判定与 §六「未查实」项原样留档，
> 未作改写。M1~M5 已修复、门禁重跑、交付栈 PySide2 字体度量实测、exe 与发布包重建的结果，
> 见同目录 `_design/ux_review/RELEASE_VERIFICATION_v1.9.5.md`；其中 §1 明确写出
> **2008R2 干净机验证尚未执行**、§4 给出可执行的 30 项签单、§6 是发布闸门。
> 注意：本文 §五 的门禁基线（1108 passed）与 §附 的包哈希（`2a322b46…`）已被复核结果替代
> （现为 1119 passed / `d27beea6…`）。**在干净机签字前不得据本文判定「可以发布」。**

---

## 一、结论

**改完 3 项必修即可上线（CONDITIONAL SHIP）。**

判定不是"质量不行"——这个项目的工程底子很扎实：
- 架构分层真实成立（`app/` 零 Qt 依赖、28 个 core 模块在无 Qt 环境全部可导入）
- 安全面经实机变异验证无命令注入漏洞
- 交付包 12 份材料齐全、逐文件哈希自洽、exe 完整启动冒烟通过
- 视觉令牌化做得好，浅色主题 13 项对比度全部达标

阻断原因是**三件具体的事**，每件都有可复现的证据：

| # | 必修项 | 严重度 | 位置 |
|---|--------|--------|------|
| **M1** | 自动封禁写库失败**仍继续建防火墙规则** → 规则永久残留、界面不可见 | **P0** | `core/pipeline.py:231-235` |
| **M2** | 监控页「端口」「协议」列**真实截断**（`180…` / `HT…`），且体检脚本判据本身有误 | P1 | `gui/page_monitor.py:100` + `_design/render_shots.py:183,336` |
| **M3** | 「忽略风险事件」在封禁建议页**无审计留痕**，审计口径随页面而异 | P1 | `gui/page_bans.py:1026-1036` |
| **M4** | 交付包内含 OpenSSL 1.1 二进制，但**缺 OpenSSL 许可与 NOTICE 声明** | P1（发布合规） | `delivery/licenses/`、`delivery/NOTICE.txt` |
| **M5** | 防火墙日志**写入路径与读取路径不一致** → 「已开启」但读不到数据 | P1 | `gui/page_settings.py:766` vs `core/port_watcher.py:143` |

> **为什么是 CONDITIONAL SHIP 而不是 NO-SHIP**：三个必修项都会产生**静默后果**——防火墙多一条规则库里没有记录（界面看不到、巡检永不解封）、表格数值被截断（用户以为端口是 180）、审计缺一条记录（事后无从追溯）。对一个防火墙管控工具，静默后果不可接受，所以必须修完再发；但三者都是**局部、边界清晰、可在半天内改完**的缺陷，不是架构性重做。修完 + 跑通验证清单，即可发布。

### 关于「负数时长 → 永久封禁」这条（曾被提为 P0，经复核降级为 P2）

`core/validators.py:205` 的 `clamp_int` 确实是 `max(low, min(high, v))`，`app/ban_service.py:391`
用 `clamp_int(duration_sec, 0, MAX_BAN_SECONDS, 0)`，负数会被夹成 **0**，而 0 在本系统里
恰好是「永久封禁」的语义。

**但经逐路径核实，当前没有任何入口能传入负数**：
- `gui/page_bans.py:225` `ManualBanDialog` 用 `QSpinBox.setRange(0, 365*24*60)` —— 物理上不可能为负
- `gui/main_window.py:212,285` `duration_sec()` 用 `max(0, ...)`
- `app/blacklist_service.py:83`、`app/list_migration.py:404` 传常量 `PERMANENT = 0`
- 自动封禁路径走 `gui/ban_coordinator.py` 的 `_sec()` 语义（下限钉 1 秒）

**结论**：这是一条**待踩的坑**，不是当前可触发的线上事故。仍建议加固（非法时长一律退回
`DEFAULT_BAN_DURATION_SEC`，永不返回 0），但**不列为上线阻断项**。

---

## 二、必修项详情与最小改法

### M1 · 自动封禁写库失败仍建防火墙规则（P0，唯一真阻断项）

**根因**：`core/pipeline.py:231-235`
```python
ban_id = None
try:
    ban_id = insert_ban(rec_ban)
except Exception:
    log.exception("自动封禁：写入 pending 记录失败 ip=%s", rec.ip)
ok, name, err = block_ip(rec.ip, duration, note=result.reason)   # ← 无条件继续
```
`insert_ban` 失败 → `ban_id` 保持 None，但**仍然建防火墙规则**。
后果：防火墙有规则、数据库无记录 → 该 IP 永不被到期巡检解封，且界面完全看不到这条封禁。

**对照（证明这是遗漏，不是设计）**：手动封禁路径 `app/ban_service.py:489-503` 处理得完全正确 ——
`insert_ban` 抛异常时 `return None, "写入封禁记录失败：{e}"`，**根本不会调 `block_ip`**，
还会补一条 `audit.record(RESULT_FAIL)`。**只有自动封禁路径漏了这道闸。**

**可达性：高**。数据库写失败是常见故障（磁盘满、库被锁、权限不足、并发写冲突），
不是理论边界。

**最小改法**：`core/pipeline.py` 在 `insert_ban` 失败时直接 `return False`（不调 `block_ip`），
并补一条失败审计。可参考 `app/ban_service.py:489-503` 的现成写法。

**护栏测试**：mock `insert_ban` 抛异常 → 断言 `block_ip` **未被调用**。

---

### M2 · 监控页列截断 + 体检脚本判据错误（P1）

**现象**：端口列 `18080` 显示为 `180…`，协议列 `HTTPS` 显示为 `HT…`（真实截断，非理论推断）。

**根因**：`gui/page_monitor.py:100`
```python
COL_WIDTHS = [96, 52, 138, 112, 58, 57, 209, 52, 147, 70, 112]
#                              ↑端口58  ↑协议57
```
而体检脚本 `_design/render_shots.py` 用了**偏乐观**的判据：
- `:183` `ELIDE_PAD = 20`，但真实内缩是 **22px**（`gui/theme.py:518` 的 `padding: 0 9px` 共 18
  + `PM_FocusFrameHMargin` 共 4）
- `:336-346` 的 `need = fm.horizontalAdvance(text)` **没算省略号本身的 10px 宽**，
  而 Qt 的省略号是画在可用宽内的

两处误差叠加，正好把「差 5px」的端口列判成了 OK。**判据本身错了，比没有判据更危险**——
它让人以为已经防住了。

**实测阈值**（8 档列宽并排渲染验证）：端口列需 **≥64**，协议列需 **≥76**。

**最小改法**：
1. `gui/page_monitor.py:100` 端口 58→**64**、协议 57→**76**，请求列 209→**184**
   （仍 >150 下限，不破坏「每页只一列 Stretch」约束）
2. `_design/render_shots.py:183` `ELIDE_PAD` 改 22
3. `_design/render_shots.py:336-346` 的 `need` 加上省略号宽

**交付栈风险**：PySide2 的 YaHei/Consolas 度量比 PySide6 宽 6~20%，协议列当前是「压线通过」，
**在 2008R2 交付栈上 `HTTPS` 会立刻截断**。建议端口列直接给 70、协议列给 82 留出余量。

---

### M3 · 「忽略风险事件」缺审计留痕（P1）

**根因**：`gui/page_bans.py:1026-1036` 的 `_ignore` 路径只有 `try/except + log.exception + refresh`，
**完全没有 `audit.record`**。而同一个动作在事件页（`gui/page_events.py:933-941`、`1119+`）
**有**审计。

后果：同动作两页口径不一；且事件处理状态是**可来回切**的动作，缺少 before 快照就无法事后
判断某条事件是被确认过、还是被忽略过又改回来。

同时这 4 处（`gui/page_bans.py:1031,1033`、`gui/page_events.py:933,1119`）**绕过 app 层直写
数据库**，与 `app/data_service.py:1-27` 文档写明的「gui 再也不直接 import core.database 做
写操作」自相矛盾。

**最小改法**：在 `app/data_service.py` 新增 `set_risk_handled(ids, handled, scope_desc)`
（含 audit + before 快照 + 失败留痕），4 个调用点改为调它。纯搬运，不改业务语义。

**护栏测试**：走封禁建议页 `_ignore` → 断言 `audit.record` 被调用。

---

---

### M4 · 交付包缺 OpenSSL 许可声明（P1，发布合规）

**根因**：交付包内确实随附了 OpenSSL 1.1 二进制：
```
PortGuard/_internal/libcrypto-1_1.dll
PortGuard/_internal/libssl-1_1.dll
PortGuard/_internal/_ssl.pyd
```
但 `delivery/licenses/` 只有三份（`LICENSE-Apache-2.0.txt` / `LICENSE-GPL-3.0.txt` /
`LICENSE-LGPL-3.0.txt`），**没有 OpenSSL 许可**；`delivery/NOTICE.txt` 里也只有 Python 的
版权声明（`Copyright 2001 Gareth Rees` / `Copyright 2004-2026 Ned Batchelder`），
**完全没有 OpenSSL 相关声明**。

**为什么是发布阻断**：OpenSSL 1.1 采用 Apache-2.0 许可，但该许可的 §4(d) 要求
「在 NOTICE 文件中声明」并保留其版权声明。以现状把包发给客户，属于**许可证声明不完整**——
这是发行合规问题，不是代码问题，但同样影响「能不能发出去」。

**最小改法**：
1. `delivery/licenses/` 增加 `LICENSE-OpenSSL.txt`（OpenSSL 1.1 的 Apache-2.0 许可全文）
2. `delivery/NOTICE.txt` 增加 OpenSSL 段：`This product includes software developed by
   the OpenSSL Project (https://www.openssl.org/)` + OpenSSL 版权声明
3. `tools/pack_release.py` 的材料清单与 `tests/test_delivery_compliance_20261110.py` 同步加校验

---

### M5 · 防火墙日志写入路径与读取路径不一致（P1）

**根因**：
- **写入侧**：`gui/page_settings.py:766` 调 `win_fwlog.enable_logging()` **不传 path** →
  `core/win_fwlog.py:418` `target = path or DEFAULT_LOG_PATH` → 写入 `DEFAULT_LOG_PATH`
- **读取侧**：`core/port_watcher.py:143`
  `fwlog_path=cfg.get("watch_fwlog_path", "") or win_fwlog.DEFAULT_LOG_PATH`

**问题**：若用户在设置里改过 `watch_fwlog_path`，读取侧指向用户指定文件，而「开启防火墙日志」
按钮**始终**写到 `DEFAULT_LOG_PATH` → 用户看到提示「已开启，日志路径：xxx」，但监控页的
「防火墙日志」通道**读的是另一个文件、看不到任何数据**，且没有任何报错。

**最小改法**：`gui/page_settings.py:766` 改为
`win_fwlog.enable_logging(cfg.get("watch_fwlog_path", "") or win_fwlog.DEFAULT_LOG_PATH)`，
与读取侧同源；并在开启成功提示里显示**实际写入路径**。

---

### 附：建议一并加固（不阻断上线）
| 项 | 位置 | 说明 |
|---|---|---|
| 负数时长 → 永久封禁 | `core/validators.py:205` + `app/ban_service.py:391` | 当前不可达（见 §1），但**未来新增入口可能踩中**。建议非法时长一律退回 `DEFAULT_BAN_DURATION_SEC`，永不返回 0 |
| 畸形 `rules.json` 崩溃 | `core/rule_engine.py:283,284,352,353` | README **明文支持**用户手改 `data/rules.json`。`status` 为 int / `region_rules` 系数非数字 / `paths` 为字符串 都会让 `_compile()` 抛异常 → 引擎崩溃 → 全链路丢数据。建议 `reload()` 对 `_compile()` 加 try，坏规则跳过而非整体崩 |

---

## 三、可先发布、下一版修（SHOULD FIX）

| # | 项 | 位置 | 影响 |
|---|---|---|---|
| S1 | 打包产物不可复现（4 层根因：zip 条目取源文件 mtime / `writestr` 不传 `date_time` 取当前时间 / PyInstaller PE 时间戳 / `base_library.zip` 内条目 mtime）→ 同源码两次打包出两个哈希 | `tools/pack_release.py:165,169,174` | 影响交付可追溯性，不影响功能。**且 zip 文件名不含构建号 → 重跑会静默覆盖已发布的包** |
| S2 | `core/alerts.py:101` 整个 core 层唯一的 Qt 依赖（函数内懒导入，侥幸成立） | `core/alerts.py:101` | 破坏「core 无界面」硬约定 |
| S3 | `core/pipeline.py:53,84,258-262` 七处 core→app 反向依赖，且同文件 `:47` 注释自称「core→app 的边一条都没有」被自己推翻 | `core/pipeline.py` | 分层说明失效 |
| S4 | `core/rule_engine.py:602` 死条件（`if not any(...allow...)` 恒为 True，因 582-592 已 return），且注释语义与代码实际行为不一致 | `core/rule_engine.py:602` | 注释误导后续维护者 |
| S5 | 畸形 `rules.json`（`status` 为 int / `region_rules` 系数非数字 / `paths` 为字符串）会让规则引擎崩溃。**README 明文支持用户手改 rules.json** | `core/rule_engine.py:283,284,352,353` | 用户手改配置 → 引擎崩溃 → 全链路丢数据 |
| S6 | 运行日志页无空态；跟读异常静默吞掉（用户看不到任何提示） | `gui/page_logs.py:250-254` | 用户无感知 |
| S7 | 面向用户的术语混用（「黑名单」/「封禁」/「拦截」并存）。数据字段名 `blacklist` 与导入导出术语**保留不改** | `gui/page_guard.py:162,166`、`gui/page_settings.py:352` | 心智模型负担 |
| S8 | 41 项生产零引用符号；`gui/page_settings_old.py` 2308 行死文件（已查实**不在**交付包内）；`page_access.py` 与 `page_events.py` 约 90 行逐字重复 | 多处 | 技术债 |
| S9 | IPv6 规则名不可逆 → 2008R2（无 `Get-NetFirewallRule`）上 **IPv6 规则一旦残留无法删除** | `core/firewall.py:511-536` | v1.9.5 无 IPv6 封禁入口承诺，`NEVER_BAN_NETWORKS` 已挡住本地段 → 非本次阻断，**但需排期** |

---

## 四、已核验通过的项（无需处理）

- **命令注入面无漏洞**（实机变异验证）：全仓 `shell=True` / `os.system` **0 命中**；`normalize_ip`
  对 18 个恶意向量全部 REJECT；`ps_quote` 实机 8/8 向量均未被执行；**对照组**（不加 `ps_quote`）
  实测双引号与 `$()` 注入成功
- **提权不静默失败**：每个写防火墙入口都有 admin 前置检查（`core/firewall.py:62` `is_admin()`）+ 明确提示
- **交付包完整**：12 份材料齐全、退出码 0、顶层仅 `PortGuard/`、无目录条目 / STORED、
  `SHA256SUMS.txt` 格式正确（3 行说明 + 路径已带 `PortGuard/` 前缀）、zip 侧车 sha256 与实际一致
  ⚠️ 但**缺 OpenSSL 许可与 NOTICE 声明**（包内确实有 `libcrypto-1_1.dll` / `libssl-1_1.dll`）→ 见 M4
- **exe 冒烟通过**：15s 存活，启动行 `PortGuard 1.9.5 启动：运行方式=打包 exe 管理员=False`，
  日志无「界面启动失败」/ Traceback / CRITICAL
- **产物 = 当前源码**：PYZ 内 62 个项目模块逐个验证，`MISMATCHED: NONE`（无「改了代码没重打包」）
- **版本 6 处联动一致**：`core/config.py` / `selftest.py:46` / `README.md` / `version_info.txt` /
  `pyproject.toml` / `delivery/04_CHANGELOG.txt` 全为 1.9.5
- **门禁基线一致**：pytest **1108 passed / 2 skipped**、mypy **7 errors / 4 files**（开发栈口径）、
  ruff check / ruff format 双绿（148 个文件）
- **视觉体系合格**：全仓仅 5 处硬编码颜色；浅色主题 13 项对比度全部 ≥4.5:1
  （`text_primary` 16.34:1）；7 页空态/加载态/错误态是真实做过的（区分「真没有」与「筛不出来」）；
  危险操作 7 处二次确认且**默认按钮一律 `No`**；未发现错别字
- **CI 配置齐全**：四项门禁 + 「完整版 PySide6 静默多装」防回退卡口 + 离线 IP 库现场拉取

---

## 五、上线前最小验证清单

改完 M1~M5 后，按顺序跑：

```bash
# 1. 静态门禁（开发栈，注意不要用 venv38 —— mypy 基线只认开发栈）
envs/portguard/Scripts/python.exe -m ruff check .
envs/portguard/Scripts/python.exe -m ruff format --check .
envs/portguard/Scripts/python.exe -m mypy .            # 基线 7 errors / 4 files

# 2. 全量测试（--basetemp 每次必须全新目录；不要并行跑两个 pytest）
envs/portguard/Scripts/python.exe -m pytest -q --basetemp=D:/WorkBuddy/_pg_pt_<全新目录>
#    基线 1108 passed / 2 skipped，且新增护栏测试全部通过

# 3. 自检 + 压测（系统空闲时单独跑，别紧跟长串门禁）
QT_QPA_PLATFORM=offscreen envs/portguard/Scripts/python.exe selftest.py    # 44 项
envs/portguard/Scripts/python.exe tools/stress.py                          # 看 RESULT:

# 4. 重建 exe（解释器必须是纯 ASCII 的交付栈；重建前删 build/port_guard + dist/PortGuard）
PYTHONPATH= "C:/Users/Administrator/pg/venv38/Scripts/python.exe" -m PyInstaller \
  --noconfirm --clean port_guard.spec
#    日志须见：[port_guard.spec] 检测到 Qt 绑定：PySide2（目录 C:\Users\Administrator\pg\...）

# 5. 验证包内是新一版
"C:/Users/Administrator/pg/venv38/Scripts/python.exe" tools/peek_packaged_code.py \
  dist/PortGuard/PortGuard.exe "1.9.5" "BanCoordinator" "events_filter_bar" "to_epoch_ms"

# 6. 交付包完整性（--out-dir 指向仓库外目录，避免覆盖已发布包）
envs/portguard/Scripts/python.exe tools/pack_release.py --version 1.9.5 --out-dir <仓库外目录>
#    退出码 0 + 12 份材料齐全
```

**然后必须做的真机验证**（本次评审无法覆盖）：

- 在 **Windows Server 2008 R2 干净机器**上装交付包，验证：exe 启动、监控页端口/协议列**不截断**
  （M3 在 PySide2 上有 6~20% 字体度量差，开发栈绿了不代表交付栈绿）、netsh 回退建规则成功、
  封禁→到期解封闭环
- 验证**普通权限模式**：界面可开、监控/风险/历史/查询全部可用、写防火墙时给出明确提权提示
- 验证**自动封禁路径**：写库失败时**不得**留下孤儿防火墙规则（M1）
- 验证**负数时长**：手动封禁输入负数，必须报「时长非法」而非静默永久封禁（加固项，���验即可）

---

## 六、不确定项

| 项 | 状态 | 说明 |
|----|------|------|
| 交付栈（PySide2）实际字体度量 | **未查实** | 评审在开发栈（PySide6）渲染，交付栈度量差 6~20%，M3 的真实严重度需在 2008R2 上确认 |
| 畸形 `rules.json` 的崩溃后果 | **未查实** | 静态分析指向引擎崩溃 → 全链路丢数据，但未做端到端复现 |
| 「已封禁但规则被人工删除」的假拦截 | **未查实** | `core/models.py:277` 承诺「答『已拦截』就必须真有规则在生效」，但 `existing is not None` 路径未复核规则存在性 |
| 自动封禁与 GUI 手动封禁并发同 IP | **未查实** | 两条 active 记录共用固定规则名，解封会互相干扰；实际并发窗口未测 |
| 打包可复现性 | **未查实** | 4 层根因已定位，但修复方案（`SOURCE_DATE_EPOCH` 式固定时间戳）未实做验证 |
| `tools/peek_packaged_code.py` 跨解释器不可用 | 已定位 | 用 py3.13 解释器读 py3.8 编译的 code object 会报 `bad marshal data`；须用 py3.8 解释器 |

---

## 附：评审过程说明

- 五位成员并行评审，覆盖测试质量 / 架构 / UI·UX / 代码质量 / 安全与发布运维五个独立域；
  架构师在最后阶段出具综合裁决
- **全程未修改任何产品代码**（`git diff` 为空）。评审期间成员用 `core/rule_engine.py:765`
  做变异验证（临时注入 `and False`）与 `_metric_tmp.py` 一次性脚本，两者均已还原/移出；
  已复核交付 exe 的 PYZ **不含**该注入
- 交付物 `dist/PortGuard-v1.9.5.zip`（sha256 `2a322b46…efac84`）与 `delivery/` 全程未被破坏，
  评审结束时侧车哈希仍与实际一致
