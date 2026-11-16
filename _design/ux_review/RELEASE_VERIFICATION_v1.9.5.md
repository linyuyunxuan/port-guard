# PortGuard v1.9.5 · 修复后复核 + 2008R2 干净机验证清单

复核日期：2026-11-14
配套文档：`_design/ux_review/RELEASE_REVIEW_v1.9.5.md`（评审当时快照，判定与「未查实」项原样留档）
仓库根：`D:/WorkBuddy/ip防火墙-2region-3.18.0/port-guard`

---

## 0. 结论（先看这一条）

**5 项必修已全部修复，全量门禁重跑通过，交付栈 PySide2 字体度量专项已实测通过，exe 与发布包已按交付栈重建并校验。但「在 Windows Server 2008 R2 干净机上验证一次」尚未执行。**

当前开发机是 **Windows 10 专业版 10.0.18363**，不是 2008R2（6.1.7601），且本次会话没有可用的干净机。
因此发布包状态是 **「候选包已备好」，不是「已验证可发布」**。

> **发布裁决：CONDITIONAL → 待签字。**
> §4 清单全部 PASS 并回收 §5 签字页之前，不要创建 Release、不要推 `PortGuard-v1.9.5` tag、
> 不要把 `dist/PortGuard-v1.9.5.zip` 交付给最终使用方。

---

## 1. 能力边界（为什么不能拿本机结果代替干净机）

| 维度 | 本机（本轮已验证） | 2008R2 干净机（未验证） |
|---|---|---|
| 操作系统 | Windows 10 专业版 10.0.18363 | Windows Server 2008 R2 SP1 / 6.1.7601 |
| Python / Qt | 交付栈 py3.8.8 + PySide2 5.15.2.1（与产物一致） | 无 Python，只用打包产物 |
| 界面字体 | 有 `Microsoft YaHei UI`（实测解析为 15px） | **没有** `Microsoft YaHei UI`，QSS 回退到 `Microsoft YaHei` |
| 防火墙命令 | netsh 可用（Win10 分支） | netsh 分支 + 无 `Get-NetFirewallRule` |
| 运行库 | VC++ 运行库齐备 | 需现场确认 `MSVCP140*.dll` / `VCRUNTIME140*.dll` |
| 「干净」 | 否：有 venv、源码、旧包、历史数据库 | 是：无 Python、无旧版 PortGuard、无残留规则 |

**已经做到的是「软件栈等价验证」**：同一份 py3.8.8 + PySide2 5.15.2.1、同一份 QSS、真实字体解析
（`QT_QPA_PLATFORM=windows` + 显式加载 `msyh.ttc` / `consola.ttf`）、同一份打包 exe 的完整启动冒烟。
这条恰好覆盖了用户点名的「开发栈绿 ≠ 交付栈绿」。

**没做到的是「OS 层差异」**：
1. `netsh advfirewall` 在 6.1 上的输出格式与回退分支；
2. **字体回退**——`gui/theme.py:134` 写的是
   `font-family: "Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI", sans-serif`，
   2008R2 缺少第一候选，会落到第二候选，水平度量可能变化；
3. 125% DPI / 旧版 DWM 下的取整；
4. 干净机上 VC++ 运行库与 UAC 策略；
5. 「无旧版残留」前提下的首次安装路径。

第 2 条是本次 Win10 交付栈验证**结构上覆盖不到**的一项，已列为清单 C4 的硬检查项。

---

## 2. M1~M5 修复落点（对照原评审）

| # | 缺陷 | 修复落点 | 护栏测试 | 变异验证 |
|---|---|---|---|---|
| **M1** | 自动封禁写库失败仍建防火墙规则 | `core/pipeline.py`：`insert_ban` 异常时写 `ACTION_BAN_AUTO` 失败审计并 `return False`，不再调 `block_ip` | `tests/test_pipeline_auto_ban.py` 新增 2 条（规则未创建 / 失败被审计） | 把 `return False` 改成 `pass` → 2 failed，恢复后转绿 |
| **M2** | 监控/事件/封禁列截断 + 体检判据本身错误 | `gui/page_monitor.py` / `page_events.py` / `page_bans.py` 列宽按两栈取大值重定；`_design/render_shots.py` 改用 `QFontMetrics.elidedText()`、`ELIDE_PAD=22`、补 worst-case、0 行 tooltip 判 FAIL | `tests/test_ui_layout.py` 17 passed；两栈 `render_shots.py` 体检 | 修判据后交付栈暴露 6 项失败 → 逐列加宽至全绿 |
| **M3** | 忽略风险事件审计口径随页面而异 | 新增 `app/data_service.set_risk_handled()`（成功/失败都审计 + before 快照）；4 个 GUI 调用点收口 | `tests/test_audit.py` 新增 3 条；`tests/test_merge_display.py` 打桩点改到真调用点 | `_ignore` 改回直写 `core.database` → 「没有查到审计记录」，恢复后转绿 |
| **M4** | OpenSSL / PSF 许可缺失 | `delivery/licenses/` 新增 2 份上游全文（OpenSSL 1.1.1i 6121B / Python 3.8 PSF 32628B）；`NOTICE`、`02_TERMS.txt`、`00_README.txt`、`04_CHANGELOG.txt`、`README.md`、`tools/pack_release.py` 同步 | `tests/test_delivery_compliance_20261110.py`：`DELIVERY_FILES == 11`、全文关键标记、5 份许可覆盖每个分发二进制 | 注释掉 OpenSSL 条目 → `assert 10 == 11` 转红，恢复后转绿 |
| **M5** | 防火墙日志写入/读取路径不一致 | 新增 `core/win_fwlog.resolve_log_path()` 作唯一真源；`PortWatcher.sync_fwlog_path()` 热更新 tailer；`gui/page_settings._enable_fwlog()` 把同一 `target` 传给 `enable_logging(path=target)` 并回显实际路径 | `tests/test_win_fwlog.py` 新增 3 条（优先级 / watcher 读同路径 / 写读同源） | 改回不传 path → `assert [None] == ['D:\fwlogs\pfirewall.log']` 转红 |

M4 的 OpenSSL 全文取自 `openssl/openssl` tag `OpenSSL_1_1_1i` 的 `LICENSE`（含 OpenSSL License + Original SSLeay License），
PSF 全文取自 Python 3.8.8 官方 Windows 安装目录 `LICENSE.txt`；包内 `libcrypto-1_1.dll` / `libssl-1_1.dll`
版本信息已核对为 `1.1.1i`。

---

## 3. 已完成的验证

### 3.1 全量门禁（本轮重跑）

| 项 | 命令 / 口径 | 结果 |
|---|---|---|
| ruff check | `envs/portguard/Scripts/python.exe -m ruff check .` | `All checks passed!` |
| ruff format | `-m ruff format --check .` | `148 files already formatted` |
| mypy | `-m mypy .`（**只认开发栈**） | 回到基线 `Found 7 errors in 4 files` |
| 全量测试 | `-m pytest -q --basetemp=<仓库外全新目录>` | **1119 passed, 2 skipped**（基线 1108 → +11 条护栏） |
| 自检 | `QT_QPA_PLATFORM=offscreen ... selftest.py`（两栈各一次） | 44 项全部通过 |
| 压测 | `tools/stress.py refresh`（系统空闲单独跑） | `RESULT: PASS` |
| 表格体检 | `_design/render_shots.py`（两栈各一次，1360px） | 两栈均 `1360px 表格体检全部通过`，EXIT=0 |
| 封禁页探针 | `_design/_bans_probe.py`（两栈各一次） | `OK 封禁页批量功能自检通过` |

> mypy 的 7 errors 是既有基线，不是本轮新增；QA 点名的 2 处 `# type: ignore` 在 mypy 2.4.0 下必需，未删。

### 3.2 交付栈 PySide2 字体度量专项（原评审 §六「未查实」项，本轮关闭）

用户判断成立，且实测结果证明**评审里建议的 `64 / 76 / 184` 不能照抄**：

| 最差文本 | 开发栈 PySide6 / py3.13 | 交付栈 PySide2 / py3.8 | 差异 |
|---|---|---|---|
| 界面字体解析 | `Microsoft YaHei UI 14px` | `Microsoft YaHei UI 15px` | 字号 +1px |
| IPv6 `2400:3200:baba::1` | 118px | **133px** | **+12.7%** |
| 「严重」 | 40px | 42px | +5% |
| 评分 `100` | 21px | 24px | +14% |
| 状态「已封禁」 | 42px | 45px | +7% |
| 徽章+规则名整组 | 196px | 198px | +1% |

最终列宽按**两栈取大值**定，不是按开发栈：

```
gui/page_monitor.py  COL_WIDTHS = [96, 52, 160, 98, 64, 76, 209, 52, 130, 70, 96]
gui/page_events.py   COL_WIDTHS = [37, 146, 200, 158, 112, 58, 156, 46, 80, 106]
gui/page_bans.py     BAN_WIDTHS = [33, 158, 240, 116, 56, 46, 88, 132, 132, 96]
gui/page_bans.py     SUG_WIDTHS = [37, 138, 69, 158, 122, 70, 53, 170, 129]
```

交付栈 1360px 监控页逐列余量（真实内缩 22px = QSS padding 18 + FocusFrameHMargin 4）：

| 列 | 可用宽 | 最差文本需 | 余量 |
|---|---|---|---|
| 时间 `23:59:59×27` | 74 | 71 | 3 |
| 来源 IP `2400:3200:baba::1` | 138 | 133 | 5 |
| 端口 `18080` | 42 | 35 | 7 |
| 协议 `HTTPS` | 54 | 37 | 17 |
| 状态 `999` | 30 | 21 | 9 |

事件页 / 封禁建议 / 封禁记录三张表同样全项 OK（`_design/ux_review/` 之外的完整日志留档在
`C:/Users/Administrator/pg/_render_delivery_final.log`）。

**残留**：以上数字是在 Win10 的 `Microsoft YaHei UI` 下测得。2008R2 无该字体，
QSS 回退到 `Microsoft YaHei` 后水平度量需真机确认 → 见 §4 / C4。

### 3.3 产物重建与一致性

- 重建前删 `build/port_guard` + `dist/PortGuard`，用纯 ASCII 交付栈解释器：
  ```
  PYTHONPATH= "C:/Users/Administrator/pg/venv38/Scripts/python.exe" -m PyInstaller --noconfirm --clean port_guard.spec
  ```
  构建日志确认 `[port_guard.spec] 检测到 Qt 绑定：PySide2`。
- 打包目录 `_internal/` 内确认存在 `PySide2/`、`shiboken2/`，**没有** PySide6；
  `libcrypto-1_1.dll` / `libssl-1_1.dll` 在位（M4 对应的二进制确实被分发）。
- `C:/Users/Administrator/pg/_verify_pyz.py` 用交付栈解释器读 `PYZ.pyz`，逐项还原字节码：
  ```
  monitor COL_WIDTHS = [[96, 52, 160, 98, 64, 76, 209, 52, 130, 70, 96]]
  bans BAN_WIDTHS    = [[33, 158, 240, 116, 56, 46, 88, 132, 132, 96]]
  bans SUG_WIDTHS    = [[37, 138, 69, 158, 122, 70, 53, 170, 129]]
  RESULT: PASS
  ```
  同时确认 M1 失败分支、M3 `data_service`、M5 `resolve_log_path` 的新字面量在 PYZ 内。
- `C:/Users/Administrator/pg/_smoke_exe.py`：`PortGuard.exe --diag --quiet` + 无参完整启动 15s，
  启动行 `运行方式=打包 exe`，无「界面启动失败」/ Traceback / CRITICAL，`RESULT: PASS`。
  （xdb 下载源 WinError 10053 是出网限制，不是启动失败。）
- `tools/pack_release.py --version 1.9.5`：`175` entries、`14` 份交付材料（含 `SHA256SUMS.txt`）。
- `C:/Users/Administrator/pg/_verify_zip.py`：`RESULT: PASS`，顶层仅 `PortGuard/`、无目录条目、
  无 STORED、清单 174 行逐项哈希自洽。
- **新包 SHA256**：`d27beea6bdd67685700d2161aa2b86100ba718da9690cdb4d1a28d77cba17684`
  （替代评审时的 `2a322b46…efac84`；旧包留档在
  `C:/Users/Administrator/pg/PortGuard-v1.9.5-pre-fix.zip`）。

---

## 4. 2008R2 干净机验证清单（可执行 / 逐项判定）

### 准备条件

- 一台**干净**的 Windows Server 2008 R2 SP1（内部版本 7601，x64）虚拟机，先做快照便于回滚；
- 机上**没有** Python、没有 venv、没有源码、没有旧版 PortGuard、没有 `PortGuard_Block_*` / `PortGuard_Allow_*` 残留规则；
- 准备一个**管理员**账号与一个**普通用户**账号；
- 把 `PortGuard-v1.9.5.zip` + `PortGuard-v1.9.5.zip.sha256` 拷到本机；
- 解压到**纯 ASCII 路径**（例 `C:\PG\`）。中文路径会让 Qt 的 `QLibraryInfo.PrefixPath` 推导失败，这是构建期已踩过的坑，运行期同样不要冒险；
- 全程保留 `portguard.log*`、自诊断报告与截图作为证据。

### A. 环境与完整性

| # | 操作 | 期望结果 | PASS/FAIL |
|---|---|---|---|
| A1 | `winver` / `systeminfo \| findstr /i "OS"` | `6.1.7601`，Service Pack 1 | ☐ |
| A2 | `certutil -hashfile PortGuard-v1.9.5.zip SHA256` | `d27beea6bdd67685700d2161aa2b86100ba718da9690cdb4d1a28d77cba17684`，与侧车文件一致 | ☐ |
| A3 | 按 `03_INTEGRITY.txt` 校验 `SHA256SUMS.txt` | 逐文件全部 OK、0 mismatch | ☐ |
| A4 | `C:\PG\PortGuard\PortGuard.exe --diag --quiet` | 报告落盘；`Qt 线路 = PySide2`；`版本判定 ✓`（最低 7601 满足）；`MSVCP140.dll` / `MSVCP140_1.dll` / `MSVCP140_2.dll` / `VCRUNTIME140.dll` / `VCRUNTIME140_1.dll` 五项全 ✓；出现「PySide2（Qt5）线路不依赖 icuuc.dll」；**无**「产物内缺少 / 系统也缺失」 | ☐ |
| A5 | 确认 `C:\Windows\Fonts` 下字体清单 | 记录是否存在 `msyhui.ttc`（Microsoft YaHei UI）、`msyh.ttc`（Microsoft YaHei）、`consola.ttf`。**预期无 `msyhui.ttc`** → C4 必须做 | ☐ |

### B. 普通权限启动（观察模式）

| # | 操作 | 期望结果 | PASS/FAIL |
|---|---|---|---|
| B1 | 用**普通用户**双击 `PortGuard.exe`（不提权、不弹 UAC） | 15s 内主窗口出现；日志有 `PortGuard 1.9.5 启动：运行方式=打包 exe 管理员=False`；**无**「界面启动失败」/ `Traceback` / `CRITICAL` | ☐ |
| B2 | 「关于」页 | 版本号 = `VERSION.txt` = 文件名 = `04_CHANGELOG.txt` 顶部 = **1.9.5** | ☐ |
| B3 | 逐页切换 7 个页面 | 监控 / 风险事件 / 访问历史 / 统计 / IP 查询 / 日志 / 设置均可打开，不崩、不白屏 | ☐ |
| B4 | 顶栏「权限」查看 | 明确列出「当前可做什么 / 哪些动作需要管理员」；观察模式下不写防火墙 | ☐ |

### C. 视觉验收 · M2（PySide2 真机，重点）

| # | 操作 | 期望结果 | PASS/FAIL |
|---|---|---|---|
| C1 | 窗口 **1360×860、100% DPI**；监控页造出/灌入含 `18080`、`HTTPS`、`2400:3200:baba::1`、`23:59:59 ×27` 的样本 | 端口列显示完整 `18080`、协议列完整 `HTTPS`、来源 IP 完整、时间完整，**无 `…` 省略**；截图留证 | ☐ |
| C2 | 切到 **125% DPI** 与 **1200×800** 各重试一次 | 同 C1，有界列不得被截断 | ☐ |
| C3 | 事件页 / 封禁建议页 / 封禁记录页同样用最差值（`11-14 11:24:03 ×100`、IPv6、`2099-12-31 23:59`、`[自动] 命中规则：判定风险：1024`） | 有界列（时间 / IP / 端口 / 评分 / 状态 / 两列到期创建）全部完整 | ☐ |
| **C4** | **字体回退专项**：确认 A5 里没有 `Microsoft YaHei UI`，再重做 C1/C3 | QSS 回退到 `Microsoft YaHei` 后，**上述列仍不截断**。这是本机 Win10 覆盖不到的唯一结构差异，**失败则需按两栈取大值再定宽** | ☐ |
| C5 | 悬停长归属地 / 请求 / 进程 / 原因列 | 允许省略，但 tooltip 必须能看全文；不可出现「省略了又没有途径看全文」 | ☐ |

> C1 里的 IPv6 **只作为显示文本**，不要触发 IPv6 封禁：原评审 S9 指出 2008R2 上 IPv6 规则名不可逆，
> 该项不在 v1.9.5 承诺范围内。

### D. 管理员权限 + 防火墙闭环

| # | 操作 | 期望结果 | PASS/FAIL |
|---|---|---|---|
| D1 | 用 `start-as-admin.bat` 启动 | UAC 弹出、确认后进入管理员态；顶栏权限状态变更 | ☐ |
| D2 | 手动封禁一个**测试用 IPv4**，时长设 1 分钟 | 封禁记录页出现一条 `active` 记录，无报错 | ☐ |
| D3 | `netsh advfirewall firewall show rule name=all \| findstr /i PortGuard_Block` | 对应规则存在（2008R2 无 `Get-NetFirewallRule`，**必须走 netsh 回退**） | ☐ |
| D4 | 等待到期（>1 分钟） | 记录变「已解封」，且 D3 中规则**消失**（到期解封闭环） | ☐ |
| D5 | 再建一条封禁，手动点「解封」 | 规则立即消失、记录状态同步 | ☐ |

### E. M1 黑盒回归（无源码注入，靠制造写库失败）

| # | 操作 | 期望结果 | PASS/FAIL |
|---|---|---|---|
| E1 | 记录 D 阶段基线：D3 的规则清单 | — | ☐ |
| E2 | 让数据库不可写（把 `data/portguard.db` 设为只读，或以独占方式锁住）后，触发**一次自动封禁** | 日志出现「自动封禁：写入 pending 记录失败」；审计日志有一条 `自动封禁 … 失败：写入封禁记录失败，未创建防火墙规则`（`RESULT_FAIL`） | ☐ |
| E3 | 再跑一次 D3 的 `netsh` 查询 | **不得新增任何 `PortGuard_Block_*` 规则** —— 这是「无孤儿规则」的唯一判据 | ☐ |
| E4 | 恢复数据库可写，确认界面封禁列表里也没有幽灵记录 | 库与防火墙两侧一致，无残留 | ☐ |

### F. M5 黑盒回归（日志写读同源）

| # | 操作 | 期望结果 | PASS/FAIL |
|---|---|---|---|
| F1 | 设置页把「防火墙日志路径」改为自定义路径（例 `D:\fwlogs\pfirewall.log`），点「开启防火墙日志」 | 提示「已开启」并显示**该自定义路径** | ☐ |
| F2 | `netsh advfirewall show allprofiles logging` | `FileName` 等于 F1 的自定义路径，**不是**系统默认 `pfirewall.log` | ☐ |
| F3 | 造一次被拦截的连接，观察监控页「防火墙日志」通道 | 能读到数据（不再出现「已开启但无数据」的静默失联） | ☐ |
| F4 | 改回默认路径再开启一次 | 写入侧与读取侧同步切回，不需重启程序 | ☐ |

### G. 卸载与残留

| # | 操作 | 期望结果 | PASS/FAIL |
|---|---|---|---|
| G1 | 按 `01_DEPLOY.txt` 卸载步骤处理 | `netsh` 中无 `PortGuard_Block_*` / `PortGuard_Allow_*` 残留 | ☐ |
| G2 | 检查用户数据目录 | 按文档单独处理，不误删无关文件 | ☐ |
| G3 | 回滚到 A 之前的虚拟机快照 | 确认无静默副作用（注册表/服务/开机自启按文档可查） | ☐ |

---

## 5. 签字页

**机器信息**

| 项 | 填写 |
|---|---|
| 机器名 / 是否虚拟机 | |
| OS 全称 + 内部版本 | |
| `winver` 截图编号 | |
| 是否干净机（无 Python / 无旧版 PortGuard） | |
| DPI 设置 | |
| 包 SHA256（须为 `d27beea6…`） | |

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

**最终裁决**（勾选其一）

- ☐ **SHIP**：30 项全 PASS 或 N/A 且有书面理由 → 允许按 §6 发布
- ☐ **NO SHIP**：存在 FAIL → 回到修复流程，重建 exe、重打包、产生新哈希，本清单重新全跑
- ☐ **CONDITIONAL**：仅 C4 失败 → 按「两栈 + 目标机字体」三者取大值重定列宽，重跑 §3 后再来一次

签字：____________  复核：____________  日期：____________

---

## 6. 发布闸门（Gate）

**签字前**（当前状态）

- `dist/PortGuard-v1.9.5.zip` 只作为候选包存在，**不创建 GitHub Release**、**不推 tag**、
  **不把 `04_CHANGELOG.txt` 标为已发布**、不对外分发；
- 若有人已经拿到 `2a322b46…` 的旧包，须明确告知作废，以 `d27beea6…` 为准。

**签字后**

1. 走 README 的发版流程，tag / Release name = `PortGuard-v1.9.5`，附 zip + 侧车 `.sha256` + 本签字页；
2. 发布前后抓旧版 Release 快照逐字段比对（发布脚本只 POST、零 DELETE/PATCH）；
3. 把签字页归档到 `_design/ux_review/`。

**若 C4 失败的回滚代价**（提前说清，避免有人想「现场改个数字就发」）

改列宽 → 重跑 `tests/test_ui_layout.py` + 两栈 `render_shots.py` + 全量门禁 →
用交付栈重建 exe（删 `build/port_guard` + `dist/PortGuard`）→ 用 `peek_packaged_code.py` / PYZ 校验
新字节码 → 重跑 exe 冒烟 → 重打 zip → **新 SHA256** → 本清单重新全跑。
这不是「改个常数」，因为包内字节码、清单哈希、侧车哈希全都要跟着变。

---

## 7. 对原评审 §六「不确定项」的更新

| 项 | 原状态 | 本轮更新 |
|---|---|---|
| 交付栈（PySide2）实际字体度量 | **未查实** | **已查实（Win10 上的 PySide2 交付栈）**：界面字体 15px，IPv6 最差文本 133px vs 开发栈 118px（+12.7%）；两栈 1360px 体检全绿。**2008R2 的字体回退仍待清单 C4** |
| 产物 = 当前源码 | 已核验 | 重新核验：PYZ 内本轮 M1/M2/M3/M5 字面量与三张表列宽全部命中 |
| 交付包完整性 | 12 份材料 | 现为 **14 份**（新增 2 份许可全文），175 entries，新哈希 `d27beea6…` |
| 门禁基线 | 1108 passed / 2 skipped | 现为 **1119 passed / 2 skipped**（+11 条护栏）；mypy 仍 7 errors / 4 files |
| 2008R2 干净机实机验证 | 评审未覆盖 | **仍未覆盖** —— 本清单待执行，见 §0 / §4 |
| 畸形 `rules.json` / 假拦截 / 并发同 IP / 打包可复现性 | 未查实 | 保持未查实，均非 v1.9.5 上线阻断项 |

---

## 附：本轮未做的事（避免误读）

- **没有**在 2008R2 上跑过任何一条命令；本机是 Win10 18363；
- **没有**把 `dist/` 里的包标为已发布，也没有推 GitHub Release / tag；
- **没有**改动原评审报告的判定与「未查实」项，只在文件头加了复核补记指针；
- 本轮产品代码确有改动（`git status` 列出 23 个已跟踪文件修改 + 2 个新许可文件），
  与前序「评审期间零改动」不同 —— 这是用户本轮明确要求的修复。
