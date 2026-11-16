# PortGuard v1.9.5 上线前 UI/UX 与界面状态覆盖审查

审查人：简意白（jian-yi-bai-2）　｜　日期：2026-11-14
审查方式：读代码 + **离屏真实渲染**（`envs/portguard/Scripts/python.exe` + `QT_QPA_PLATFORM=offscreen`，字体走 `addApplicationFont(msyh.ttc/msyhbd.ttc)` 后 `setFont`，**未调 `addApplicationFont` 前的 segfault 陷阱已避开**）
截图目录：`_design/ux_review/`（本目录）
**未修改任何产品代码**，仅新增本目录下的截图与本报告。

---

## 〇、结论

**视觉体系合格，可以上线；有一处真实的显示缺陷建议在上线前修掉。**

本项目在「令牌化」这件事上做得比绝大多数同类项目好：`gui/theme.py` 的 `Color` dataclass 三层结构清晰，颜色几乎全部走 `C.*`，浅色主题下正文对比度全部达标，7 页的空态/加载态/错误态覆盖是**真实做过**的（不是摆设），危险操作全部有二次确认且默认按钮一律是 `No`。

问题集中在**一个地方**：项目的表格列宽体检脚本（`_design/render_shots.py`）用了一个偏乐观的「可用宽度」模型，导致**监控页的「端口」和「协议」两列在实机上真的把数值截断了**，而体检脚本报的是 OK。这是「机器判据本身错了」，比「没做判据」更危险——它让人以为已经防住了。

---

## 一、界面清单与状态覆盖表

| 页面 | 正常态 | 空态 | 加载态 | 错误态 | 超长文本态 | 禁用态 |
|---|---|---|---|---|---|---|
| **总览** `gui/page_overview.py` | ✅ | ⚠️ 覆盖缺口（无独立空态，但 6 卡恒显，设计合理） | ✅「正在刷新…」`page_overview.py:167-172` | ✅ `_fail()` 降级为「—」+ 脚注写原因 `page_overview.py:260-265` | ✅ 脚注 wordWrap | ✅ |
| **实时监控** `gui/page_monitor.py` | ⚠️ **端口/协议列截断（阻断）** | ✅ 双空态 `page_monitor.py:843-850`（区分「没数据」/「筛不出」） | ⚠️ 覆盖缺口（无显式加载态） | ✅ `BAN_STATE_FAIL_TEXT` 横幅 `gui/widgets.py:888-891` | ⚠️ 进程列省略（允许，有 tooltip `page_monitor.py:198`） | ✅ `btn_clear.setEnabled(total>0)` `page_monitor.py:811` |
| **风险事件** `gui/page_events.py` | ✅ | ✅ 双空态 `page_events.py:783-788` | ✅ `RefreshGuard` `page_events.py:448` | ✅ 横幅 + 「重试」`page_events.py:348-350` | ✅ 路径列省略 + tooltip | ✅ 批量按钮 `setEnabled(n>0)` `page_events.py:904` |
| **历史访问** `gui/page_access.py` | ✅ | ✅ 三态（`读取失败`/`无匹配`/`暂无`）`page_access.py:578-642` | ✅ `RefreshGuard` `page_access.py:434` | ✅ `empty.set_state("读取失败", str(e))` `page_access.py:578` | ✅ | ✅ |
| **封禁管理** `gui/page_bans.py` | ✅ | ✅ 双区各一：`sug_empty` `page_bans.py:596` / `empty` `page_bans.py:772` | ✅ `RefreshGuard` `page_bans.py:723` | ✅ 防火墙状态横幅 2 条 `page_bans.py:348-352, 500` | ✅ | ✅ `setEnabled(n>0)` `page_bans.py:1045,1055` |
| **规则配置** `gui/page_rules.py` | ✅ | N/A（表单页，无列表） | N/A | ✅ `QMessageBox.warning` `page_rules.py:406,491` | ✅ | ✅ 递增关闭时置灰 `page_guard.py:291` |
| **IP 查询** `gui/page_iplookup.py` | ✅ | ✅「尚未查询」`page_iplookup.py:176` | N/A | ✅ 行内红字「查询失败：…」`page_iplookup.py:283` | ✅ | N/A |
| **运行日志** `gui/page_logs.py` | ✅ | ❌ **覆盖缺口**（无 `EmptyState`，`grep -c EmptyState` = 0） | ⚠️ 覆盖缺口（无） | ❌ **静默吞异常** `page_logs.py:250-254` | ✅ | ✅ 级别下拉 `setEnabled(idx==SOURCE_APP)` `page_logs.py:357` |
| **设置** `gui/page_settings.py` | ✅ | N/A | ✅「IP 库 正在探测」`gui/main_window.py:496` | ✅ `lbl_db_state` 红/绿 `page_data.py:963,995` | ✅ | ✅ 自启开关 `setEnabled(False)` `page_settings.py:373` |
| **关于** `gui/about_dialog.py` | ✅ | N/A | N/A | ✅ | ✅ | ✅ `AboutDialog(NAV_ITEMS, self)` **传了 parent**，继承 GLOBAL_STYLE ✅ `gui/main_window.py:647` |

### 空态专项（重点核查项）

四个列表页的空态**全部有可用说明文案 + 出路按钮**，不是一片空白表格：

| 场景 | 文案 | 位置 |
|---|---|---|
| 无封禁记录 | `EmptyState("尚无封禁记录", "确认封禁后，记录会出现在这里")` | `gui/page_bans.py:772` |
| 筛「已到期」但没有 | title 改为「没有已到期的封禁」，desc 改为「当前筛选下没有到期时间已过的记录」 | `gui/page_bans.py:1399-1400` |
| 无风险事件 | `EmptyState("暂无风险事件", "当前规则未命中任何访问，这是正常状态")` | `gui/page_events.py:353` |
| 无访问记录 | `EmptyState("暂无访问记录", "还没有收到任何访问上报")` | `gui/page_access.py:288` |
| IP 未查询 | `EmptyState("尚未查询", "输入 IP 后点查询，结果会显示在这里")` | `gui/page_iplookup.py:176` |

而且**区分了「真没有」与「筛不出来」**（`gui/page_monitor.py:843-850`、`gui/page_events.py:783-788`），空态按钮文案分别是「去开启」「重置筛选」。这一条很多同类产品都做错，此处做对了。

### 覆盖缺口汇总（2 处，均为 P2）
1. **运行日志页无空态**（`gui/page_logs.py` 全文无 `EmptyState`）：切到「端口访问日志」且无数据时，用户看到的是一个空白文本框 + 页脚一行「端口访问日志：显示 0 / 缓冲 0 行」，**没有一句「为什么空」和「怎么办」**。
2. **运行日志页跟读失败零提示**：`gui/page_logs.py:250-254`
   ```python
   except Exception:
       log.debug("跟读程序日志失败", exc_info=True)
       return
   ```
   用户看到日志停住不动，界面**没有任何提示**。建议页脚追加「（日志文件读取失败，请检查权限）」并用 `C.danger` 着色。

---

## 二、视觉一致性（硬编码颜色 / 未走 `C` 令牌 / 对比度）

### 2.1 硬编码颜色 —— 全仓库仅 5 处（排除未使用的 `gui/page_settings_old.py`）

| 文件:行号 | 值 | 判定 |
|---|---|---|
| `gui/main_window.py:137` | `QColor("#FFFFFF")` | ✅ 可接受（盾牌对勾描边，语义固定白） |
| `gui/row_action.py:74` | `"#E9B4B2"` | ⚠️ **绕过令牌**：danger 按钮描边色，与 `gui/theme.py:926` 同值但**两处各写一遍** |
| `gui/row_action.py:74` | `"#FFFFFF"` | ⚠️ 应改用 `C.accent_on`（同行 `:75` 已经这么做了，同一行内不一致） |
| `gui/row_action.py:75` | `"#A9DCC5"` | ⚠️ 同上，与 `gui/theme.py:935` 重复 |
| `gui/widgets.py:344`、`gui/widgets.py:426` | `"#FFFFFF"` | ⚠️ 应改用 `C.accent_on` |

**另有 8 个色值写在 QSS 字符串里、不在 `Color` dataclass 里**：
`gui/theme.py:322` `#0E7450`、`:339` `#A92724`、`:355` `#8A5100`、`:358` `#0B5C40`、`:359` `#6E4100`、`:360` `#8E1F1C`、`:926` `#E9B4B2`、`:935` `#A9DCC5`

→ **用户会看到什么现象**：目前无可见症状（值都挑得对）。但**事实上的单一数据源并不存在**——`gui/row_action.py:71-72` 的注释明确写着「自绘和 QSS 必须长得一模一样」，而 `#E9B4B2` 却在 `theme.py:926` 和 `row_action.py:74` 两处手写。将来改危险按钮描边色漏改一处，就会出现「同一张表里两种按钮描边色不一致」。

**改法**：把 `#E9B4B2` / `#A9DCC5` 提升为 `Color` 的新字段（如 `danger_border` / `success_border`），`theme.py` 的 QSS 串与 `row_action.py` 同时引用。纯重构，零视觉变化。

### 2.2 未走 `C` 令牌的地方

**除上表 5 处外，没有发现任何组件绕过 `C` 直接写 hex。** 全仓库 `setStyleSheet` 调用点全部使用 `{C.xxx}` 插值（`gui/components.py`、`gui/main_window.py`、`gui/page_*.py`、`gui/widgets.py` 等）。
这一项是本项目的**强项**，`_design/01_visual_direction.md` 的约束落到了实处。

### 2.3 对比度 —— WCAG 公式实算

| 组合 | 实测 | 判定 |
|---|---|---|
| `text_primary #18202E` on `bg_card #FFFFFF` | **16.34:1** | ✅ AA 远超 |
| `text_primary` on `bg_zebra #F7F9FC` | **15.50:1** | ✅ |
| `text_secondary #46536A` on 表头 `bg_card_alt #F2F5FA` | **7.10:1** | ✅ |
| `text_muted #53627A` on `bg_card` | **6.18:1** | ✅ |
| `text_muted` on `bg_card_alt` | **5.66:1** | ✅ |
| 白字 on `primary #3349B8` | **7.54:1** | ✅ |
| 白字 on `success #0B6B4A` | **6.53:1** | ✅ |
| 白字 on `danger_solid #B02A20` | **6.57:1** | ✅ |
| 白字 on `warning #8A5200` | **6.39:1** | ✅ |
| 徽章 normal `#46536A` on `#E7EEFC` | **6.66:1** | ✅ |
| 徽章 low `#1B4FD1` on `#E6EEFC` | **5.83:1** | ✅ |
| 徽章 medium `#8A5200` on `#FFF3DF` | **5.82:1** | ✅ |
| 徽章 high `#8E1B14` on `#FBE9E7` | **7.73:1** | ✅ |
| 徽章 critical `#FFFFFF` on `#B02A20` | **6.57:1** | ✅ |
| `text_link #2F42BE` / `primary` / `success` / `danger` / `warning` / `critical` / `info` on 全部 13 个浅底 | 全部 ≥4.5 | ✅ |
| `text_disabled #9AA3B2` on `bg_disabled #F0F2F6` | **2.27:1** | ⚠️ 见下 |

**唯一不达标项**：`text_disabled`（`gui/theme.py:70`）在所有背景上都是 2.1~2.5:1。

- **判定：不阻断**。WCAG 1.4.3 明确豁免 "inactive UI components"（禁用控件文本不要求达到对比度要求）。
- **但从可用性看**：用户看不太清「这个按钮为什么是灰的」。
- **重要事实**：所有禁用按钮**都有 tooltip 说明为什么不能点**（如 `gui/components.py:518`「该 IP 已在封禁中，解封请到『封禁管理』页」、`gui/page_monitor.py:698`），**「为什么灰」的信息不在颜色里** —— 这是正确的设计。
- **建议（P2）**：`text_disabled` 从 `#9AA3B2` 压深到约 `#7B8494`，可提升到 ~3.5:1，同时保留「灰」的视觉语义。

---

## 三、信息层级与文案问题

### 3.1 总览页卡片层级 —— 清楚 ✅

`gui/page_overview.py:184-250` 的结构：
`3px 主色顶条` → `8px 圆点 + 13px 卡片标题` → `38px Consolas 主数字` → `13.5px 说明` → `淡底明细块` → `12px 脚注` → `查看 →`

四层字号（38 / 13.5 / 13 / 12）拉开，数字用等宽 Consolas 不跳动，层级一眼可读。
「实时流」卡用 `BarStripWidget`（24 格状态条，`gui/page_overview.py:59-131`）做视觉锚点，且**红格上限 3 个 + 连续 4 格判异常**（`:95-106`）—— 红色作为稀缺资源，这个克制是对的，符合「不玩花哨撞色」的底线。

### 3.2 文案问题（3 项）

#### (1) 术语混用：「黑名单」/「封禁」/「拦截」/「阻断」并存

| 位置 | 原文 | 面向用户？ |
|---|---|---|
| `gui/page_guard.py:162` | 「封禁期间累计被拦下多少次后列入**黑名单**」 | ✅ 是 |
| `gui/page_guard.py:166` | 「惯犯升级**黑名单**」（开关名） | ✅ 是 |
| `gui/page_settings.py:352` | 「启动 1.5 秒内补跑到期巡检与**黑名单补封**」 | ✅ 是 |
| `gui/page_bans.py:752` | 「可直接导入其它防火墙 / **黑名单系统**」 | ✅ 是（但指外部格式） |
| `gui/page_bans.py:1304` | 「文件是纯文本、一行一个、无表头，可直接导入其它防火墙 / **黑名单系统**」 | ✅ 是（但指外部格式） |
| `gui/page_data.py:104` | 「N 条**黑名单**、N 条白名单」 | ✅ 是 |
| `gui/page_rules.py:363` | 注释「**黑名单命中**不再是一张规则卡」 | ❌ 注释 |
| `gui/page_monitor.py:501` | 注释「请求把 IP 加进『拦截』规则（**原黑名单**入口）」 | ❌ 注释 |
| `gui/mixins.py:554,568,570` | 注释「**黑名单补封**」 | ❌ 注释 |
| `gui/main_window.py:294` | 注释「**黑名单** → 防火墙联动」 | ❌ 注释 |

**用户会看到什么现象**：在「规则配置」页读到的是「规则」，在「封禁管理」页读到的是「封禁」，在设置页读到的是「黑名单补封」，在导出提示里读到的是「黑名单系统」。用户要建立「这是同一件事」的心智模型，需要自己推断。

**但**：`blacklist` 是**数据字段名**（`gui/page_data.py:104` `data['blacklist']`），也是**导入/导出的行业通用格式名**，改掉会与外部系统脱节。

**建议（P2）**：
- **不改**数据字段名与导入/导出术语（`page_bans.py:752,1304` 保留「黑名单系统」是对的）
- **改**面向用户的功能名：`gui/page_guard.py:162,166`「惯犯升级黑名单」→「惯犯升级：永久封禁」；`gui/page_settings.py:352`「黑名单补封」→「补封名单项」
- `gui/page_data.py:104` 若是展示内部名单条数，建议「封禁名单 N 条 / 放行名单 N 条」

#### (2) 顶部导航短词与页面标题不统一

- `gui/main_window.py:556` 短词表：`("实时", "风险", "历史", "封禁", "规则", "IP", "日志", "设置", "关于")`
- 但这块**不是侧栏**，是顶部面包屑条（`gui/main_window.py:523` `objectName("breadcrumb")`，高 52）。短词化是刻意的（`gui/main_window.py:554-555` 注释：「短词化后给全名留 tooltip / accessibleName」）。
- **不统一的对应**：
  | 导航短词 | 页面标题 | 位置 |
  |---|---|---|
  | 实时 | 实时监控 | `gui/page_monitor.py:521` |
  | 风险 | 风险事件 | `gui/page_events.py:333` |
  | 历史 | 历史访问 | `gui/page_access.py:261` |
  | 封禁 | 封禁管理 | `gui/page_bans.py:325` |
  | 规则 | 规则配置 | `gui/page_rules.py:278` |
  | **IP** | **IP 查询工具** | `gui/page_iplookup.py:89` |
  | 日志 | 运行日志 | `gui/page_logs.py:124` |
  | 设置 | 设置 | `gui/page_settings.py:147` |

- **判定：P2，不阻断**。这是「面包屑用短词 + 页内用全名」的一致设计，8 个业务页对应关系 1:1，悬停有 tooltip 全名（`gui/main_window.py:565`），不构成理解障碍。
- **唯一建议**：`gui/page_iplookup.py:89` 的「IP 查询**工具**」→ 「IP 查询」，与 `gui/main_window.py:79` 的 `("IP 查询", "查询")` 对齐（「工具」二字在页标题里多余）。

#### (3) 中英混排与错别字 —— 基本达标 ✅

- 「离线 IP 库就绪 2/2 个文件」（`gui/page_overview.py:459`）中英之间有空格 ✅
- 标语统一用「·」分隔（`gui/page_overview.py:152`）✅
- **未发现错别字**。`gui/main_window.py:1166`「已以管理员身份运行」用的是「已经」的「已」+「以」，正确 ✅
- `gui/page_bans.py:145`「重复封禁递增」等短标签无歧义 ✅

---

## 四、可访问性与危险操作安全

### 4.1 危险操作二次确认 —— 全部到位 ✅

| 操作 | 位置 | 确认内容 | 默认按钮 |
|---|---|---|---|
| 安全启用 Windows 防火墙 | `gui/page_bans.py:482-495` | 列出 4 步 + 「放行范围是此刻正在监听的快照」说明 | **No** |
| 批量解封 | `gui/page_bans.py:1144-1151` | 「将删除这 N 条记录对应的防火墙规则，并把记录标记为已解封」 | **No** |
| 批量删除封禁记录 | `gui/page_bans.py:1188-1195` | 「仅从数据库删除选中的 N 条记录，**不会**改动已生效的防火墙规则」 | **No** |
| 单条删除记录 | `gui/page_bans.py:1613-1620` | 「仅从数据库删除封禁记录 #id（IP x）」 | **No** |
| 一键全部解封 | `gui/page_bans.py:1633-1640` | 「将删除所有以 PortGuard_Block_ 开头的防火墙规则」 | **No** |
| 批量确认封禁 | `gui/page_bans.py:1084` | 校验逐条做、确认只弹一次、执行串行在同一后台线程 | — |
| 删除 / 放行规则 | `gui/page_rules.py:491,505` | 「规则未完全生效」有明确文案 | — |

**默认按钮全部是 `QMessageBox.StandardButton.No`** —— 这一点做得非常对，误按回车不会误删。

**可撤销提示**：批量解封/删除**没有撤销入口**，但有审计留档（`gui/page_bans.py:1200` 注释「删除前把关键字段整条留档」）+ 有二次确认。对桌面端防火墙工具，二次确认 + 审计留档已足够，不要求撤销。判定 ✅。

### 4.2 表格列对齐 —— 基本到位，一处不对齐

用 `gui/widgets.py:692-702` 的 `align_headers()` 统一表头对齐方式跟数据一致（数据居中 → 表头也居中）。实测：

- 监控页：`headerData` 对 section 1/4/5/7 返回 `AlignCenter`（`gui/page_monitor.py:166`），与数据的 `TextAlignmentRole`（`gui/page_monitor.py:204`）**同一组列** ✅
- **不对齐项**：事件页/封禁页的「等级 / 命中规则」列由 `RiskBadgeDelegate` 自绘（`gui/widgets.py:401`），**有 note 时走左对齐**（`gui/widgets.py:437`），但表头仍是居中（`gui/page_events.py:564` 设的是 `COL_PATH` 为 Stretch，未改等级列表头）→ **表头居中、徽章组左对齐，横坐标对不齐**。P2。

### 4.3 长 IP / 长路径截断 —— 见 §5 阻断项

---

## 五、★ 阻断项：监控页「端口」与「协议」列数值被截断

### 现象

`_design/ux_review/1_monitor.png`（整页）与 `z_port.png`（4 倍放大）可见：端口列的 `18080` 显示为 **`180…`**，协议列的 `HTTPS` 显示为 **`HT…`**。

`z_https_table.png`（独立 QTableWidget 复现，同一 GLOBAL_STYLE）同样复现。

### 根因（已定位到行）

`gui/page_monitor.py:100`
```python
COL_WIDTHS = [96, 52, 138, 112, 58, 57, 209, 52, 147, 70, 112]
#                              ↑端口58  ↑协议57
```

`gui/page_monitor.py:85-88` 的注释写的是：
> `端口 58（5 位数 18080 需 55）· 状态 52（3 位数需 41）`
> `协议 57（`HTTPS` 实测 37 + padding 20 = 57 —— 52 时渲染成 `HTT…`，这是 2026-10-27 走查抓到的真实截断。这 5px 从命中规则列借的」

**这个 55 和 37 是对的，但 padding 20 是错的。**

Qt 实测（`QStyle.SubElement.SE_ItemViewItemText` 矩形，取自真实监控表）：

| 列 | 列宽 | 文本矩形宽 | 文本宽 | 省略号宽 | 需（含省略号） | 可用 |
|---|---|---|---|---|---|---|
| 端口 | 58 | **40** | `18080` = 35 | 10 | **45** | 40 ❌ |
| 协议 | 57 | **39** | `HTTPS` = 37 | 10 | **47** | 39 ❌ |
| 来源 IP | 138 | 120 | `113.118.113.77` = 111 | 12 | 123 | 120 ⚠️余量 -3 |
| 时间 | 96 | 78 | `08:36:23×4` = 64 | 10 | 74 | 78 ✅ |
| 进程 | 112 | 94 | `nginx.exe` = 70 | 12 | 82 | 94 ✅ |

内缩 = 9（左）+ 9（右）+ 2（`PM_FocusFrameHMargin`）+ 2 = **22px**，不是注释里说的 20。

### 实测阈值（证据图 `z_final.png`）

同一张表 8 档列宽并排渲染：

| 列宽 | 58 | 64 | 70 | 76 | 82 | 88 | 94 | 100 |
|---|---|---|---|---|---|---|---|---|
| `18080` | `180…` | `18080` | `18080` | `18080` | `18080` | `18080` | `18080` | `18080` |
| `HTTPS` | `HT…` | `HT…` | `HT…` | `HTTPS` | `HTTPS` | `HTTPS` | `HTTPS` | `HTTPS` |

**端口列需 ≥64，协议列需 ≥76**（当前 58 / 57，**均不达标**）。

### 为什么体检脚本没抓到

`_design/render_shots.py:183` 定义 `ELIDE_PAD = 20`，注释写「20 = QSS 左右各 8（共 16）+ Qt 渲染实测损耗 4」，并明确「⚠️ 不要按 theme 的 16 改小」。

**但 `gui/theme.py:518` 写的是 `padding: 0 9px`（左右共 18，不是 16）**，加上 `PM_FocusFrameHMargin = 2`（左右共 4），真实内缩是 **22**，不是 20。

更关键的是 `_design/render_shots.py:336-346` 的 `check_elide()`：
```python
need = fm.horizontalAdvance(text)     # ← 纯文本宽，没算省略号本身的 10px
avail = col_w - ELIDE_PAD
ok = need <= avail
```
Qt 的省略号是**画在可用宽内**的，真正的判据应是「文本宽 + 省略号宽 ≤ 可用宽」才能保证不出现省略号。这两个模型误差叠加，正好把「差 5px」的端口列判成了 OK。

**两处缺陷同时存在**：`_design/render_shots.py:183`（ELIDE_PAD）与 `:336-346`（need 计算）。**只改 ELIDE_PAD 到 22 还不够，need 必须加上省略号宽。**

### 附带影响（对 PySide2 交付栈的风险）

`gui/page_monitor.py:86` 自己写着「这是 2026-10-27 走查抓到的真实截断」，而 `_design/render_shots.py:134` 注释自述「PySide2 的 YaHei / Consolas 度量比 PySide6 宽 6~20%」。
协议列当前判据是「`HTTPS` 需 37px、可用 37px」—— **压线通过**。在 PySide2 栈上 Consolas 宽度多 6~20%，`HTTPS` 立刻开始截断。
**这是一个踩过一次但没修干净的坑**，且**开发栈（PySide6）与交付栈（PySide2）的判定结果会不一致**。

### 建议改法（不破坏「每页只一列 Stretch」约束）

监控页固定列合计 = 96+52+138+112+58+57+52+147+70+112 = **894**，请求列（唯一 Stretch，`gui/page_monitor.py:101` `COL_REQUEST = 6`）当前 209。

**改法**：端口 58→64（+6）、协议 57→76（+19），固定列合计 894+25 = **919**，请求列 209→**184**。

- 请求列 184 > 150 下限（`_design/render_shots.py:137` `ELASTIC_MIN["监控"]["请求"] = 150`）✅
- 1200 档视口 1179：919 固定 + 请求 260 ✅（改前 285）
- 1360 档视口 1299：请求列 184，仍能放 `POST /api/v1/orders/search`（约 180px）—— **偏紧，建议同时把请求列下限锁进体检脚本**
- 「每页只一列 Stretch」约束不受影响 ✅

**更稳的替代（不推荐）**：协议列只显示 `HTTP`/`TCP`/`UDP`（去掉 S）省 7px，或端口列用 `number_font(11)`。前者会改语义（用户看不到 HTTPS 是 TLS），后者影响数字扫读性，**均不采用**。

### 同时必须修体检脚本（否则下次还会漏）

`_design/render_shots.py`：
1. `ELIDE_PAD` 20 → **22**，并把注释里的「theme 的 16」改成「theme 的 18（`padding: 0 9px`）+ focus frame 4 = 22」
2. `check_elide()` 的 `need` 改为 `fm.horizontalAdvance(text) + fm.horizontalAdvance("…")`
3. 判据从「`need <= avail`」改成「**文本宽 ≤ avail**」—— 能完整显示就不该有省略号，不要求给省略号预留位置

改完必须重跑 `python _design/render_shots.py --width 1360 --height 860`，它会从「FAIL 1 项」变成「FAIL 2 项（封禁记录横滚 + 监控端口/协议）」，再按上面调列宽直到全绿。

### 关于「封禁记录 横滚=4」这个 FAIL —— 是脚本误报，不是产品缺陷

`_design/render_shots.py:422` 报 `FAIL 1360 封禁记录 横向滚动条=4>0`。

**我复核了**：封禁记录表在 `gui/page_bans.py:351-352` 的 `CapsuleTabs` **第二个 tab** 里，体检脚本在**第一个 tab 可见**时测它的 `viewport().width()`，此时它还没被布局，拿到 627（错误值）。
手动把 tab 切过去后实测（1360 档）：
```
封禁记录(激活后): 视口=1297 合计=1297 差=0 横滚max=0
```
**横滚为 0，产品无缺陷。**

→ **建议**：脚本测「封禁记录」前先 `win.page_bans.tabs.setCurrentIndex(win.page_bans.tabs.indexOf(win.page_bans.ban_panel))`，否则这个 FAIL 会一直挂着，让人以为有横滚问题。

---

## 六、分级清单

### 🔴 阻断上线（建议 v1.9.5 修掉再发）

| # | 问题 | 位置 | 用户会看到什么现象 |
|---|---|---|---|
| 1 | 监控页「端口」列 `18080` → `180…`、「协议」列 `HTTPS` → `HT…` | `gui/page_monitor.py:100`（`COL_WIDTHS` 端口 58 / 协议 57） | 实时监控页最关键的「哪个端口、被什么协议访问」两列数值看不全。攻击者打的是 18080 还是 8080 用户分不出来；HTTPS 与 HTTP 无法区分。端口是判断「哪个服务被盯上」的依据 |
| 2 | 表格体检脚本 `ELIDE_PAD` 与 `need` 计算错误 | `_design/render_shots.py:183`、`:336-346` | 唯一的表格视觉门禁**漏报真实缺陷**（端口/协议），同时**误报**（封禁记录横滚）。改了列宽不修脚本，下次改动会重新引入同类问题 |

### 🟡 建议改进（不阻断，但影响专业度）

| # | 问题 | 位置 | 用户会看到什么现象 |
|---|---|---|---|
| 3 | 总览卡脚注文案过长导致折行、卡底参差 | `gui/page_overview.py:334`（406px）、`:388-391`（549px）、`:414`（418px）、`:436`（391px），卡片可用宽仅 385px | 6 张卡的脚注行高不一致（15px vs 30px），底部参差不齐；「统计口径 / 健康分定义」这类元信息与主数字抢视觉权重 |
| 4 | `danger_border` / `success_border` 未进 `Color`，同一色两处手写 | `gui/theme.py:926`、`:935` + `gui/row_action.py:74`、`:75` | 当前无可见症状；改色时漏改一处就会出现「自绘按钮与 QSS 按钮描边色不一致」 |
| 5 | 运行日志页无空态 | `gui/page_logs.py`（全文无 `EmptyState`） | 切到「端口访问日志」无数据时是空白文本框 + 页脚「显示 0 / 缓冲 0 行」，没有「为什么空 / 怎么办」 |
| 6 | 运行日志页跟读失败被静默吞掉 | `gui/page_logs.py:250-254` | 日志停住不动，界面零提示，用户不知是程序挂了还是没日志了 |
| 7 | 术语混用：「黑名单」/「封禁」/「拦截」/「阻断」 | 面向用户的位置：`gui/page_guard.py:162,166`、`gui/page_settings.py:352`、`gui/page_data.py:104` | 同一部件事在四个页面四种叫法，用户需自己推断是同一件事 |
| 8 | 页标题「IP 查询工具」与导航「IP 查询」不一致 | `gui/page_iplookup.py:89` | 「工具」二字多余，进入页面才知道全名 |
| 9 | `text_disabled` 对比度 2.27:1 | `gui/theme.py:70` | 禁用按钮文字偏淡，看不清「为什么灰」（但 tooltip 有解释，WCAG 也豁免） |
| 10 | 事件页「等级 / 命中规则」列表头居中、徽章组左对齐 | `gui/widgets.py:437` vs `gui/page_events.py:564` | 一列的横坐标对不齐，扫读时徽章串不成竖线 |
| 11 | `row_action.py:74` 的 `"#FFFFFF"` 应为 `C.accent_on` | `gui/row_action.py:74` | 当前视觉无差异；同行 `:75` 已用 `C.accent_on`，同一 dict 内不一致 |

### 🟢 可选 / 记录留档

| # | 事项 | 位置 | 说明 |
|---|---|---|---|
| 12 | 事件页「等级 / 命中规则」列宽 200px，整组需 196px | `gui/page_events.py` 列宽表 / `_design/render_shots.py:211` `BADGE_NOTE_COLUMNS` | 体检报 OK，但**余量只有 4px**，规则名再长一个字就省略。建议提到 210~220 |
| 13 | 访问页「用户代理」列 120px | `gui/page_access.py:686` | `Mozilla/5.0 (Windows NT 10.0)` 需 205px → 省略成 `Mozilla/5.0 (…`，**有 tooltip 兜底**（`tip=ua_text`），符合「允许省略但必须有兜底」原则，不阻断 |
| 14 | 监控页「进程」列 112px | `gui/page_monitor.py:198` | `TermService.exe` 需 105px（可用 94px）→ 省略成 `TermService.…`，**有 tooltip 兜底**，不阻断 |
| 15 | 点击区普遍 < 44×44 | `gui/components.py:393`（DotsButton 22×22）、`gui/theme.py:922`（行内小按钮 26px）、`gui/widgets.py:194`（开关 44×24） | 桌面端密集表格的通行做法，且行内小按钮 tooltip 齐全。**桌面端不按移动端 44px 判**；若要提升，优先提行内「⋯」到 28×28 |

---

## 七、无障碍自查

| 项 | 结论 | 依据 |
|---|---|---|
| 正文对比度 ≥ 4.5:1 | ✅ 全部达标（最低 5.66:1） | §2.3 实算 |
| 大字对比度 ≥ 3:1 | ✅ 全部达标 | §2.3 实算 |
| 徽章对比度 | ✅ 5.82~7.73:1 | `gui/theme.py:104-128` |
| 禁用态对比度 | ⚠️ 2.27:1（WCAG 豁免 inactive 控件；tooltip 有解释原因） | `gui/theme.py:70` |
| 键盘可达 | ✅ | Ctrl+0~8 切页 `gui/main_window.py:603-615`；Ctrl+F 定位搜索框 `:620`；F1 帮助 `:625`；纯图标按钮带 accessibleName `gui/components.py:395` + tooltip `:396` |
| 语义标签 | ✅ | 按钮用 QPushButton；开关用 ToggleSwitch（自绘但有 `toggled` 信号，`gui/widgets.py:190`）；表格有表头语义 |
| 焦点可见 | ✅ | `#btn_primary:focus` 用 `primary_pressed` 深色描边 `gui/theme.py:357`（注释说明「白描边压在浅色底上等于没有」）；`QToolButton:focus` 有 info 描边 `:588`；`QTableView:focus` 有 primary 边框 `:514` |
| 无障碍名称覆盖 | ⚠️ 仅 6 处 `setAccessibleName` | `gui/components.py:371,395` + `gui/main_window.py:549,566,578`。行内「确认封禁」「解封」等**文字按钮本身有文字**，不需要；表格内**纯图标**按钮（若有）应补 |
| 不依赖颜色作为唯一语义通道 | ✅ | 风险等级除颜色外还有**文字徽章** `gui/widgets.py:329-350`；封禁状态有文字；统计卡是「6px 圆点 + 标签」双通道 `gui/widgets.py:285-294`；告警有文字 + 横幅图标 `gui/widgets.py:490-511` |
| 动效 | ✅ | 开关 120ms InOutQuad `gui/widgets.py:200-201`，无炫技动画、无闪烁 |

---

## 八、上线结论

**建议：修掉阻断项 1、2 后即可上线。**

- 视觉体系（令牌化、对比度、层级、间距、空态、危险操作确认、焦点可见）**已达可交付水准**，是**克制、专业、信息优先**的商务风，无渐变糊/霓虹撞色/玻璃拟态，符合用户审美底线
- 唯一真实缺陷（端口/协议截断）**范围小、30 分钟内可修完**，修完顺带清掉「体检脚本自身有 bug」这个长期隐患
- 建议改进项 3~11 可放到 v1.9.6

**特别提醒给主理人**：`_design/render_shots.py` 是这个项目**唯一的表格视觉门禁**，它当前 **既漏报真实缺陷（端口/协议）又误报（封禁记录横滚）**。修了列宽不修脚本，下次改动还会重新引入同类问题 —— 这是本次审查里**最值得投入的改进**。

---

## 附录：本目录（`_design/ux_review/`）内容清单

**9 个主页面整页图**（v1.9.5 当前代码，1360×860 离屏渲染）

| 文件 | 页面 |
|---|---|
| `0_overview.png` | 总览台 |
| `1_monitor.png` | 实时监控（**可见 `180…` / `HT…` 缺陷**） |
| `2_events.png` | 风险事件 |
| `3_access.png` | 历史访问 |
| `4_bans.png` | 封禁管理（待确认建议 tab） |
| `5_rules.png` | 规则配置 |
| `6_iplookup.png` | IP 查询 |
| `7_logs.png` | 运行日志 |
| `8_settings.png` | 设置 |

**缺陷证据图**

| 文件 | 内容 |
|---|---|
| `z_port.png` | 监控页端口+协议列 4 倍放大 —— `180…` / `HT…` 缺陷直接证据 |
| `z_https_table.png` | 独立 QTableWidget + 同一 GLOBAL_STYLE 复现 `18080`→`180…`、`HTTPS`→`HT…` |
| `z_final.png` | **列宽阈值对比图**：58/64/70/76/82/88/94/100 八档并排，证明端口需 ≥64、协议需 ≥76 |
| `z_monitor_table.png` | 监控表整体 3 倍放大 |
| `z_ov_foot2.png` | 总览卡脚注折行证据 |

**状态态图**

| 文件 | 内容 |
|---|---|
| `e_bans_records_empty.png` | 封禁记录 tab 实态（13 条记录，含解封按钮与筛选栏） |
| `e_events.png` | 风险事件页实态 |

**本报告**：`UX_REVIEW_v1.9.5.md`（即本文件）

**未修改任何产品代码。**
