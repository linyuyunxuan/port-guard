# PortGuard 视觉方向 v1.1 ·「石墨哨岗 Graphite Watchtower」

> **一句话**：把界面做成一台**夜里还亮着的机柜面板** —— 石墨灰的静默底，只在「需要动手」和「需要警觉」的地方亮一下。
> **参考坐标**：Grafana 的深底数据密度 × 1Password 8 的分层（几乎不用描边）× Sentry 的用色纪律。不抄它们的蓝，也不做紫粉渐变。
> **为什么适合 7×24 盯屏**：① 底色饱和度 ≤6%，长时注视不产生色疲劳；② 90% 像素是中性灰，剩下 10% 彩色**全部携带语义**，「出现颜色」本身就是告警；③ 层级靠明度差而非描边，10 列高密度表格不会变成格子布；④ 色相分离：主色靛 234° / 危险红 358° / 警告琥珀 38° / 成功绿 152°，互不相邻。
> **v1.1 修订**（已对齐 `02_ux_spec.md`）：① 表格内取消行级风险底色，风险只由徽章表达（§2.1/§5.5）；② 列宽基线改 10 列 + 「严重度永远第 2 列」；③ 监控页统计卡 4→3；④ 补 `:focus` 规则（§7）；⑤ 表内徽章改 `QStyledItemDelegate` 自绘。

## 1. 设计原则

| # | 原则 | 落地判定 |
|---|---|---|
| P1 | **颜色只表示语义，不表示装饰** | 除靛/红/琥珀/绿外不许第 5 个色相；表头、侧栏选中、标题一律不上彩色底 |
| P2 | **先分层，再考虑描边** | 页面→面板明度差 1.14、面板→行 1.05；仅「表头下沿 / 输入框 / 次级按钮」保留 1px |
| P3 | **风险色是稀缺资源** | 高饱和红只出现在：严重徽章实底、确认类按钮、已封禁计数。其余用淡底+亮字 |
| P4 | **数据优先于容器** | 表格/日志区不套卡片边框、不加内边距；容器只定位，不装饰 |
| P5 | **精密的圆角** | 圆角随尺寸递减（8/6/4/2），小元素用 4px 保「刀切感」，不做全站统一 8px |

> Why：运维是「余光扫屏」场景，色彩必须有唯一解释权 —— 一旦主色也能当装饰，用户就无法用「变红」判断出事。

## 2. 色彩令牌（逐字段对应 `gui/theme.py :: Color`；〔新〕= 需新增字段）

| 字段 | HEX | 用途 |
|---|---|---|
| primary / primary_hover | `#6C7CF5` / `#8A98FF` | 主色「哨兵靛」：主动作填充、选中指示条、focus 边框、文字强调 / 主按钮 hover、选项卡选中文字 |
| primary_light / primary_soft | `#2A3157` / `#262E57` | 主色中调：禁用按钮底、图形第二层 / **表格与列表选中行底**、下拉与菜单选中项 |
| success / success_light | `#3FBF7F` / `#16302A` | 正常/成功/在线/服务运行中 / 在线徽章底、成功态淡底 |
| danger / danger_light | `#E5484D` / `#301E24` | 高危语义：高危文字、危险描边按钮、封禁计数 / 高危行底、高危徽章底 |
| warning / warning_light | `#E0A03A` / `#2A2418` | 中风险、权限不足、需注意横幅 / 中风险行底、中风险徽章底 |
| critical / critical_light | `#FF6B6B` / `#3B1F26` | 严重语义的**亮调红**：淡底上的红字、行左 2px 指示 / 严重行底 |
| info / info_light | `#8B9BFF` / `#1E2440` | 低风险、INFO 级日志 / 低风险徽章底、info 横幅底 |
| bg_body / bg_card / bg_card_alt | `#0F1115` / `#1A1F27` / `#232830` | 页面底、**表头带**、工具栏底 / 面板·统计卡·表格容器底 / 抬升面：对话框、菜单、tooltip、卡片 hover |
| bg_sidebar / bg_sidebar_hover / bg_sidebar_active | `#0A0C10` / `#171C24` / `#1B2140` | 侧栏与状态栏（比 body 再暗，形成外框）/ 导航 hover / 导航选中**淡底**（靛感实色，不用主色满填） |
| border / border_light | `#2A303A` / `#1E242C` | 唯一常规描边：表头下沿、输入框、次级按钮 / 分隔线：侧栏右沿、状态栏上沿、面板分组线 |
| text_primary / text_secondary / text_muted | `#E4E8ED` / `#98A2AE` / `#7B8592` | 正文·表格主数据·表单值 / 表头·标签·导航默认 / 说明文字·占位符·页脚·次要列 |
| text_on_dark / text_link | `#F4F7FA` / `#8B9BFF` | 页面与面板标题、统计数字、选中行文字 / 可点击文字（与 info 同族，不多占色相） |
| **`bg_input`**〔新〕 | `#0B0E12` | 输入框/下拉/文本域/日志区底（比卡片更暗 = 内凹） |
| **`bg_zebra`**〔新〕 | `#1E232B` | 表格斑马纹（偶数行） |
| **`bg_hover`**〔新〕 | `#2B313C` | 表格行 / 列表项 hover（必须亮于斑马，否则偶数行 hover 会消失） |
| **`border_strong`**〔新〕 | `#333A45` | 次级按钮、下拉默认描边（比 border 明确一档） |
| **`accent_on`**〔新〕 | `#0B0E13` | **主色/成功/警告实底上的文字色**（近黑，替代白字） |
| **`danger_solid`**〔新〕 | `#D8383F` | 满底危险按钮 / 严重徽章实底（配白字 4.61:1） |

> Why 加 `accent_on`：白字压 `#6C7CF5` 只有 3.60:1、压 `#3FBF7F` 只有 2.34:1（均不合格）；近黑字压主色 5.37:1、压成功绿 8.26:1。深色界面上「亮填充 + 深字」也比白字更聚焦。

### 2.1 风险语义映射（覆盖现有 `LEVEL_COLORS` / `LEVEL_BG`；**表格内不用行底**）

| 等级 | 表格文字 | 行卡片底（非表格） | 徽章底 / 徽章字 | 实测 |
|---|---|---|---|---|
| normal 正常 | text_secondary | 无 | `#242A33` / text_secondary | 5.58:1 |
| low 低 | info | 无 | info_light / info | 5.96:1 |
| medium 中 | warning | warning_light | warning_light / warning | 6.79:1 |
| high 高危 | critical | danger_light | danger_light / critical | 5.66:1 |
| critical 严重 | critical | critical_light | **danger_solid 实底 / `#FFFFFF`** | 4.61:1 |

> Why：表格内风险**只由徽章表达**（事件页 47/53 行是 high/critical，铺行底会让淡底变成默认底色，信号归零）；行卡片（封禁建议、详情）仍可用 `LEVEL_BG`。严重度不换色相而靠**填充重量**（实心 > 淡底 > 无底）分级，红色系始终只有一支。表中 `#242A33` 及后续 `#16191F`/`#232838`/`#10141A` 类灰阶为**一次性写死值**，不进令牌表。

### 2.2 关键对比度实测

| 组合 | 比值 |
|---|---|
| **primary `#6C7CF5` on bg_body `#0F1115`** | **5.25:1**（AA 正文通过；on bg_card 4.60:1） |
| danger / warning / success on bg_body | 4.83 / 8.33 / 8.07 |
| text_primary / secondary / muted on bg_body | 15.36 / 7.30 / 5.05 |
| 层级明度差：body→card / card→zebra / card→hover / card→input / card→border | 1.14 / 1.05 / 1.18 / 1.17 / 1.25 |

> Why 斑马只差 1.05、hover 1.18：10 列 × 50 行时行底强对比会成「条形码」，横向追踪失效。明度阶梯必须满足 **zebra(1.05) < hover(1.18) < selected(1.27)**，否则交互状态互相覆盖。

## 3. 字体与字号阶梯

字体族：`"Microsoft YaHei UI", "Microsoft YaHei", "Segoe UI", sans-serif`（2008 R2 无 YaHei UI 时自动落 YaHei）；**数字一律 `Consolas`**（Vista/2008 起自带、等宽 tabular），禁依赖 Cascadia / JetBrains Mono / 苹方。

| 令牌 | px | 字重 | 场景 | 行高处理 |
|---|---|---|---|---|
| stat | 26 | 700 | 统计卡大数字（Consolas） | `setFixedHeight(32)` + `AlignVCenter` |
| page-title | 20 | 600 | 页面标题（text_on_dark） | 固定 26 |
| section | 14 | 600 | 面板标题、对话框标题 | 20 |
| body | 13 | 400 | 表单标签、按钮、正文 | 20 |
| table | 12 | 400 | 表格单元格、列表项 | 行高 30（`setDefaultSectionSize(30)`） |
| caption | 11 | 400/600 | 表头(600)、徽章(600)、状态栏、辅助说明 | 16 |
| mono | 12 | 400 | IP/端口/时间/路径/评分/ID/时长（Consolas） | 随行 |

> Why 表格 12px：1360 宽放 10 列，13px 时「时间/端口」仍会截断；12px + 等宽数字多容纳约 8% 字符，正文仍 13px 保表单可读。QSS **无 `line-height`、无 `letter-spacing`**：多行文案用 `QTextBlockFormat.setLineHeight(140%)`，中文标题只靠字重与字号做层级。

## 4. 间距与圆角体系

**间距（4pt 基准）**：`2 / 4 / 8 / 12 / 16 / 20 / 24 / 32 / 40`，禁止 6/10/14/18（现状 QSS 大量 6/10/14 正是「到处都是框」的隐性成因）。固定值：页面内边距 `24` · 面板 `16` · 统计卡 `14/16` · 工具条上下 `12` · 区块间距 `16` · 按钮组 gap `8` · 单元格左右 `10`。

| 圆角档 | px | 用在哪 |
|---|---|---|
| 容器 | **8** | 面板、统计卡、表格容器、对话框、下拉弹出层 |
| 控件 | **6** | 按钮、输入框、下拉、搜索框、选项卡 pane |
| 徽章 | **4** | 徽章、表格内小按钮、复选框、菜单项 |
| 胶囊 | **高/2** | 开关轨道、状态点、滚动条 handle |

> Why 不全站 8px：8px 落在 22px 小按钮与 18px 徽章上等于把形状做成胶囊，风险标签会变「可爱」；工具界面要刀切感。反之 8px 以下出现在 400×300 面板上又显油腻。曲率与尺寸成比例才「精密」。

## 5. 组件视觉规范

### 5.1 侧栏 / 导航 / 品牌区

| 项 | 规格 |
|---|---|
| 侧栏 | 宽 `200`，底 `bg_sidebar`，右沿 `1px border_light`，无圆角 |
| 品牌区 | 高 `64`，padding `0 16`；主名 15/700 `text_on_dark`；副名 11/400 `text_muted` |
| 品牌图标 | **自绘盾牌 20×20，填充 primary**（弃 `🛡` emoji：Win10 为彩色字形破坏调性、2008 R2 可能豆腐块） |
| 导航项 | 高 `38`，`border-left: 2px solid transparent`，`border-radius: 0`，padding `0 14`，13/400 `text_secondary`，整行满铺 |
| hover | 底 `bg_sidebar_hover`，字 `text_on_dark` |
| 选中 | 底 `bg_sidebar_active` + 左条 `2px primary` + 字 `text_on_dark` + 600 |
| 分组标题 | 11/600 `text_muted`，高 `28`，padding `0 16` |
| 底部 | 上沿 `1px border_light`；「已封禁 N」= 6px 圆点（有数 `danger` / 无 `success`）+ 12/600 文字；版本 11 `text_muted` |

> Why 选中态不满填主色：整条 `#6C7CF5`（5.25:1）会持续「视觉尖叫」，盯屏时侧栏永远抢注意力；2px 左条 + 淡底足够定位，全屏只付出一处彩色。

### 5.2 页面标题区 + 顶部状态区

- 标题区高 `56`：标题 20/600 `text_on_dark`，说明 12/400 `text_muted` 在其右 `10px`（同基线不换行）；右侧操作按钮高 `32`、gap `8`、右对齐。**顶部状态区**（补现状缺失）独立 `44px` 条，底 `bg_body`、下沿 `1px border_light`；3 组「6×6 状态点胶囊 + 11px 标签」= `接收服务`/`本机观察`/`权限`，运行 `success`、停止 `text_muted`、异常 `danger`、权限不足 `warning`，组间 `1px border_light` 竖线、边距 `10`。
  > Why：三个「是否正在防护」的状态现在被压在 26px 状态栏最右端，等于没有；状态点比文字更快被余光扫到。

### 5.3 统计卡

- **3 张等宽**（356px/张，删「接收服务」卡——它与顶部 44 状态条重复，且 26px 大字写「未启动」不像指标）。高 `76`，radius `8`，底 `bg_card`，**无边框**，padding `14 16`；数字 26/700 Consolas 着语义色（今日访问 `text_on_dark`、今日风险 `warning`、当前封禁 `danger`），标签 11 `text_secondary` 居其下 `2`，标签左侧 6px 语义圆点（QPainter 画）。
- hover 底 `bg_card_alt`；可点击进筛选时（今日风险→事件页）再叠 `1px` 语义色描边（不可点击则无 hover）。
  > Why 去边框：三卡并排时 1px 竖线紧邻会读成「表格的延续」而非「指标」；1.14 明度差 + 更亮的数字已够分组。

### 5.4 面板 / 分组容器（结论：背景差分层，不用边框）

- 面板 = `bg_card` + radius `8` + padding `16`，**不写 border**；标题独立一行 14/600，不画标题栏底、不加分隔条；需分组用 `1px border_light` 横线 + 上下 `16`。嵌套 ≤2 层，第二层用 `bg_card_alt`，不再加边框。可描边例外：输入框、次级按钮、表头下沿、对话框外沿、横幅左条。

> Why：「卡片有边框 + 控件有边框 + 表格有边框」= 三层框嵌套，眼睛判断不出谁是容器；无边框化后只有**可交互对象**带描边，视觉语法立刻清晰。

### 5.5 表格（本产品的主战场）

| 项 | 规格 |
|---|---|
| 容器 | `bg_card` + radius `8`，**无边框**、无内边距，表格紧贴容器边缘 |
| 表头 | 高 `34`，底 `bg_body`（比卡片暗 1.08 = 压住感），下沿 `1px border`，11/600 `text_secondary`，padding `0 10`，左对齐，**无竖线** |
| 行 | 高 `30`（现状 ~26）；`setShowGrid(False)`、`gridline-color: transparent`；斑马 `bg_zebra`（ΔL 1.05） |
| hover / 选中 | hover 底 `bg_hover`（ΔL 1.18，必须亮于斑马）；选中 `primary_soft` + `text_on_dark`（14.6:1），不加左条不加描边 |
| 风险表达 | **只用徽章**（18px，`QStyledItemDelegate` 自绘：`rect.adjusted(6,6,-6,-6)`、半径 4、11/600 居中、漆在行底之上）；行底只有 bg / zebra / hover / selected 四种 |
| 分隔线 | 横竖都不要；列关系靠对齐与表头分组表达 |
| 数字列 | Consolas 12 右对齐（时间/端口/状态/评分/ID/时长/日期），IP 与路径左对齐 |
| 列宽与列序 | **严重度永远第 2 列**。监控 10 列：时间 80·风险 60·IP 126·归属地 128·端口 56·协议 48·请求(stretch,min150)·状态 52·命中规则 132·服务器 96（固定 778）；事件/封禁页列清单见 `02_ux_spec.md` §P0-2 |

> Why 去网格线 & 砍列：13 列 = 12 条竖线与斑马横纹交叉出栅格噪声；砍到 10 列后端口列可给 56（5 位数 18080 完整），时间给 80（8 字符 + 右对齐）才不出现 `18…`、`13:59…`。

### 5.6 工具栏

- 条高 `56`（上下 padding `12`），底 = 页面底，**不画背景、不画下边框**，靠与表格 `12px` 间距分组。搜索框 w`260` h`32`：底 `bg_input`、`1px border`、radius `6`、padding `0 10`、12.5px、占位 `text_muted`；筛选下拉 h`32`、`min-width 96`、箭头区留 `24`。按钮全部 h`32`、与搜索框同基线（禁一高一低），主按钮只 1 个，其余 secondary/ghost，gap `8`；「共 N 条」用 11 `text_muted` 贴表格右上或工具条最右，不单独占行。

### 5.7 输入框 / 下拉（四态）

| 状态 | 规格 |
|---|---|
| 默认 | 底 `bg_input`，`1px border`，radius `6`，h`32`，padding `0 10`，13 `text_primary`，占位 `text_muted` |
| hover | 边框 `border_strong` |
| focus | 边框 `primary`（1px 即够）+ 底 `#10141A` + `selection-background-color: primary`；QSS 无 box-shadow，**不要**用加粗边框伪装光圈 |
| error / disabled | error：边框 `danger` + 下方 11px `danger` 说明（QLabel，不靠控件内图标）；disabled：底 `#16191F`、字 `#6A7381`（3.06:1，刻意偏低表达不可用） |

### 5.8 按钮（四型 + 表格内小按钮）

| 类型 | 默认 | hover | pressed / disabled |
|---|---|---|---|
| primary | 底 `primary`、字 `accent_on` 600 | 底 `primary_hover` | `#5A69E0` / 底 `#232838` 字 `#6A7381` |
| secondary | 底 `bg_card_alt`、`1px border_strong`、字 `text_primary` | 底 `bg_hover`、边框 `#3E4653` | `#1E242C` / 透明边框 `#262C36` 字 `#6A7381` |
| ghost | 透明无边框、字 `text_secondary` | 底 `bg_card_alt`、字 `text_primary` | `#1E242C` / 字 `#6A7381` |
| danger（描边） | 透明、`1px danger`、字 `danger` | 底 `danger_solid`、字 `#FFFFFF` | `#C0303A` / 边框 `#4A2A2E` 字 `#7A5A5E` |
| danger-solid | 底 `danger_solid`、字 `#FFFFFF` 600（仅对话框确认，1 屏 1 个） | 底 `danger` | `#B92F36` / 底 `#3A2426` 字 `#7A5A5E` |
| 表格内小按钮 | h`22`、padding `0 8`、r`4`、11px；危险动作 = 描边 `#8E3338` + 字 `critical`（hover 实底 `danger_solid` 白字）；次要动作 = ghost | — | — |

尺寸统一：页面级 h`32`、padding `0 16`、r`6`、13px/500；工具条内 h`32`；对话框内 h`32`。

> Why 表格内危险动作只描边：一屏 20 行 ×「确认封禁+忽略」= 40 个高饱和块，红色失去稀缺性，用户对「危险」的阈值被拉高 —— 这正是防御工具最不能有的失敏。

### 5.9 其它控件

| 组件 | 规格 |
|---|---|
| 徽章 | **底色式，不用描边式**：h`18`(表内)/`20`(页面)，r`4`，11/600 居中，配色见 §2.1。**表内徽章按列撑满（列宽 − 12）**，4 档同宽、可纵向扫读（比按文字收紧更适合严重度列）；页面级徽章按「文字 + padding 12」收紧。表内徽章由 `QStyledItemDelegate` 自绘：先按行态刷底，再在 `adjusted(6,6,-6,-6)` 内画圆角矩形 + 居中文字，**底必须实色 hex**（alpha 会让斑马纹透色，奇偶行不同色） |
| 开关（自绘） | `36×20`，轨道 r`10`：关 `#333A45`、开 `primary`、禁用 40% 不透明；滑块 `16×16` `#F4F7FA`、内边距 `2`；切换 `120ms InOutQuad`（QSS 做不到，属自绘控件特权） |
| 复选框 | `14×14`、r`3`、`1px border_strong`；checked = 底 `primary` + 白色对勾（随包 `assets/check.svg`，QtSvg 缺失时降级白色实心块） |
| 横幅 info/warning/danger | 左条 `3px` 同档色 + 底 `info_light`/`warning_light`/`danger_light` + 图标 14px 自绘（⚠/ⓘ，不用 emoji）+ 正文 12.5 `text_primary`；radius `6`、padding `10 12`、图标与字 gap `10`、动作按钮右对齐（同档描边、h`26`）。**整条不描边** |
| 选项卡 | **下划线式**：tab 无边框无背景无上圆角，padding `8 2`，gap `24`，12.5/400 `text_secondary`；选中 13/600 `text_on_dark` + `border-bottom: 2px solid primary`；hover `text_primary`；pane 无边框同底 |
| 对话框 | 底 `bg_card_alt`、外沿 `1px border_strong`、r`8`、padding `20`；标题 14/600；表单行距 `12`；按钮区右对齐 gap `8`、距正文 `20`；「取消在左、确认在右」 |
| 状态栏 / 滚动条 | 状态栏高 `26`、底 `bg_sidebar`、上沿 `1px border_light`、11 `text_secondary`，右侧组间 `1px border_light` 竖线、边距 `10`，关键状态前置 6px 圆点；滚动条宽 `10`、轨道透明、handle `rgba(255,255,255,0.10)` r`5` hover `0.18`、无箭头 |

## 6. 反模式清单（这套界面里不要做的事）

| # | 不要做 | 为什么（针对本产品） |
|---|---|---|
| 1 | 给容器加阴影 / 内发光 / 外发光 | QSS 无 `box-shadow`，用 `rgba()` 描边伪装会在斑马纹上露馅；数据面需要绝对锐利边界，发光会让 10 列文字边缘发虚，长时阅读模糊度上升 |
| 2 | 表格行里放满底红按钮 | 见 §5.8：53 行 × 2 个红块后红色不再是「严重」信号；且与风险徽章同色同权重，语义自相冲突 |
| 3 | 用主色做大面积填充（侧栏选中、表头、标题带、图表背景） | 主色 5.25:1 高对比，大面积会持续抢注意力；余光扫屏时真正该变的红/琥珀会被淹没 |
| 4 | 引入第 5 个色相、渐变、霓虹青、彩虹图例、蓝紫双主色 | 四色相已占满语义槽位，第 5 色会被误读成「新的风险等级」；渐变在 2008 R2 的 Qt5 上有 banding，且与「精密仪表」调性冲突 |
| 5 | 用 emoji/彩色字形做图标；写 `border-radius` 四值 | `🛡`/`⚠` 在 Win10 是彩色字形、2008 R2 可能缺字形且无法着色；Qt 仅支持单值 `border-radius`，四值会被静默忽略，导致「有的圆有的方」 |

## 7. Qt 落地约束备忘

- `border-radius` 单值；`border-left: 2px` 可单独用（侧栏指示条唯一用法）。**无 `transition`**：hover/focus 瞬时切换，故状态色差必须够大（正文 hover ≥ΔL 1.15），否则用户以为没反应。行高与列级字体不能由 QSS 指定：行高用 `verticalHeader().setDefaultSectionSize(30)`，数字列在 `make_item()` 内 `QFont("Consolas", 10)`（≈12px）。
- **焦点必须可见**（QSS 无 `outline`，只能靠边框）：所有按钮/输入框默认常驻 `1px solid transparent`（占位，避免聚焦时 1px 位移）；`:focus` 时 `ghost`/`secondary`/`danger` 描边 → `#8B9BFF`，而**填充型（primary/success/danger-solid）必须用暗环 `accent_on`**（`#8B9BFF` 压 `#6C7CF5` 只有 1.35:1，等于没焦点）；`QTableView`/`QTreeView` 默认 `border:1px solid transparent; border-radius:8px`，`:focus` → `1px primary`；`QCheckBox::indicator:focus` → `1px #8B9BFF`。
- 部分原生控件（`QComboBox` 弹出、`QMessageBox`、滚动条）仍读 `QPalette`：`QApplication` 级 `setStyleSheet(GLOBAL_STYLE)` 的同时必须设 `palette` 的 `Window/Base/Text`，否则出现白底白字。
