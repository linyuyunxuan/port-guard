# PortGuard v1.9.5 旧包作废声明（草稿 · 未公开）

> **状态：DRAFT — 尚未对外发布。**
> 本文件是「独立公告」方案的本地草稿，用于替代 `PATCH /releases/443972998` 改 Release body
> 的做法。后者会踩项目自定的「发布脚本只 POST、零 DELETE/PATCH」约定，且 `PATCH` 的 `body`
> 是**整体替换**（只发追加段会抹掉原发布说明）。
> **公开本声明、开 issue、通知已下载对象，均需用户单独书面授权；本轮一条都未执行。**
>
> 起草日期：2026-11-16
> 证据口径：全部来自公开只读 GET 与本地只读命令，无写操作

---

## 一、作废对象与证据

| 项 | 值 |
|---|---|
| Release | `PortGuard-v1.9.5`，id `443972998`，`draft=false` / `prerelease=false` |
| 发布时间 | 2026-11-13T08:14:49Z |
| 主资产 | `PortGuard-v1.9.5.zip`，id `742852300`，55,708,903 bytes |
| 主资产 SHA256 | `2a322b4673a2042d26ea44d1f79230462a3a467d68237169fe6e5af174efac84` |
| 侧车 | `PortGuard-v1.9.5.zip.sha256`，id `742853260` |
| 下载次数 | 主资产 2、侧车 2（**计数会自然增长，此处为起草时快照**） |
| tag 指向 | `PortGuard-v1.9.5` → `a4088580d0a6f0842b2d6ab324f7e356a74a24d8` |
| 本地对照 | `HEAD = ae6d54c7…`（= 远端 main）、`HEAD^ = a4088580…` |

**结论**：该 tag 指向的 commit **不含 M1~M5 修复**（本地 23 个改动文件当时尚未提交），
因此线上 v1.9.5 包是修复前的构建；同一版本号下同时存在线上 `2a322b46…` 与本地候选
`d27beea6bdd67685700d2161aa2b86100ba718da9690cdb4d1a28d77cba17684` 两个不同哈希，
即 README:577-579 所述「验收证据与实际交付物错位」的同一风险形态（该段原文讲的是
「改了产品代码却没重建 exe」，此处是其在发布环节的对应面，不冒充原文）。

旧包未修的 5 项缺陷及实际后果：

| # | 缺陷 | 用户可见后果 |
|---|---|---|
| M1 | 自动封禁写库失败仍创建防火墙规则 | 可能在系统留下库里没有记录、界面看不到、永不到期解封的 `PortGuard_Block_*` 孤儿规则 |
| M2 | 监控 / 事件 / 封禁列截断 | 端口 `18080` 显示成 `180…`、协议 `HTTPS` 显示成 `HT…`、IPv6 显示不全 |
| M3 | 忽略风险事件审计口径随页面而异 | 封禁建议页的忽略动作无审计留痕，事后无从追溯 |
| M4 | 缺 OpenSSL 1.1.1i / Python 3.8 PSF 许可全文 | 包内分发 `libcrypto-1_1.dll` / `libssl-1_1.dll` 与 CPython 运行库，许可声明不完整 |
| M5 | 防火墙日志写入与读取路径不一致 | 提示「已开启」但监控页读的是另一个文件、无数据也无报错 |

此外，该包**未在 Windows Server 2008 R2 干净机上验证**（正式交付目标平台）。

---

## 二、作废声明 · 中文（可直接用于 issue / 公告 / Release body 追加段）

```
## ⚠️ PortGuard v1.9.5 旧包已作废 / DEPRECATED

本 Release 附带的 PortGuard-v1.9.5.zip
（SHA256 2a322b4673a2042d26ea44d1f79230462a3a467d68237169fe6e5af174efac84）
已作废，请勿继续使用或分发。

原因：
- 该包不含 M1~M5 修复（tag 指向的 commit 早于修复提交）；
- 未在 Windows Server 2008 R2 干净机上完成验证；
- 特别是 M1：自动封禁写库失败时仍会创建防火墙规则，可能留下孤儿规则。

请改用 PortGuard-v1.9.6：
https://github.com/linyuyunxuan/port-guard/releases/tag/PortGuard-v1.9.6

已下载本包的用户请删除旧包并重新下载 v1.9.6。
本程序无应用内自动升级、无 Authenticode 签名，旧包不会自动更新，须人工替换。

校验新包：
  sha256sum -c PortGuard-v1.9.6.zip.sha256
或
  certutil -hashfile PortGuard-v1.9.6.zip SHA256
解压到纯 ASCII 路径（例 C:\PG\），中文路径会让 Qt 的 QLibraryInfo.PrefixPath 推导失败。
```

---

## 三、作废声明 · English

```
## ⚠️ DEPRECATED RELEASE — PortGuard v1.9.5

The PortGuard-v1.9.5.zip attached to this release
(SHA256 2a322b4673a2042d26ea44d1f79230462a3a467d68237169fe6e5af174efac84)
is deprecated. Do not use or redistribute it.

Why:
- It does not contain the M1-M5 fixes (the tag points to a commit predating them).
- It was never validated on a clean Windows Server 2008 R2 machine.
- In particular M1: a failed database write during auto-ban still creates a firewall
  rule, which can leave an orphan PortGuard_Block_* rule behind.

Use PortGuard-v1.9.6 instead:
https://github.com/linyuyunxuan/port-guard/releases/tag/PortGuard-v1.9.6

If you already downloaded this package, delete it and download v1.9.6.
There is no in-app auto-update and no Authenticode signature, so old copies will
NOT update themselves - manual replacement is required.

Verify the new package:
  sha256sum -c PortGuard-v1.9.6.zip.sha256
or
  certutil -hashfile PortGuard-v1.9.6.zip SHA256
Extract to a pure-ASCII path (e.g. C:\PG\); non-ASCII paths break Qt's
QLibraryInfo.PrefixPath resolution.
```

---

## 四、若改用「改 Release body」方案（需单独授权，本文件不采用）

- 确切动作：`PATCH https://api.github.com/repos/linyuyunxuan/port-guard/releases/443972998`
- **必须先 `GET /releases/443972998` 取回原 body 全文**，在末尾拼接 §二/§三 的声明后**整体提交**；
  只发追加段会抹掉原发布说明（原 body 写的是 `2a322b46…` 与三项 CI 修复）。
- 与「发布脚本只 POST、零 DELETE/PATCH」冲突 → **不得纳入发布脚本**，作为独立一次性动作单独授权。
- 会改 `body` / `updated_at`，与「发布后既有 3 条 Release 全字段任何 diff 判失败」冲突 →
  **排在发布后快照比对完成之后执行**，或把 v1.9.5 的 body 列入「授权后允许变更」白名单并记录 diff。
- token 从用户 MEMORY.md 文件内正则读取，**绝不进命令行**。

---

## 五、授权状态（截至起草时）

| 动作 | 状态 |
|---|---|
| 本草稿落盘（本地） | 已完成 |
| 公开为 issue / 仓库公告 | **未执行，需授权** |
| `PATCH /releases/443972998` 改 body | **未执行，需单独书面授权** |
| `DELETE /releases/assets/*` 替换资产 | **不做**（用户已选 A：另起 v1.9.6） |
| 通知已下载 2 次的对象 | **未执行，需单独授权** |
| `POST /releases` 建 v1.9.6 / 上传资产 | **未执行**（且按闸门须先有 30 项签单 PASS 与签字页） |
| `git commit` / `git push` | **未执行** |

---

## 六、已确定 / 待确定项

**已确定（2026-11-16，交付栈重建后实测并由 team-lead 独立复验）**

| 项 | 值 |
|---|---|
| `PortGuard-v1.9.6.zip` SHA256 | `dcee40cf00b05ccfb402bb9436c01545e2362f90b659b0e711ef05de369394da` |
| 包大小 / zip 条目 | 55,723,580 B / 175 entries |
| 包内 `VERSION.txt` | `PortGuard v1.9.6` |
| `SHA256SUMS.txt` 哈希行 | 174（177 行总计 − 3 行 `#` 注释；首行带 UTF-8 BOM） |
| 侧车 `.sha256` | 与上表 SHA256 一致，校验口径自洽 |
| 独立锚点 `verify_expect.txt` | 母版已填 `EXPECTED_ZIP_SHA` / `EXPECTED_VERSION=1.9.6` / `EXPECTED_SUMS_ENTRIES=174` |

> 该哈希**不是** `d27beea6…`（未发布的 v1.9.5 候选包），更不是 `2a322b46…`（已发布的作废旧包）。
>
> **锚点送达口径（已裁决，不得弱化）**：仓库内 `_design/ux_review/verify_expect.txt` 是**发布方母版**，不是送达件，
> **永不**作为 Release 资产上传（连副本都不做——一旦可下载就有人直接取用，锚点独立性事实失效）。
> 三个值改由 **Release 公告正文 + 已签签字页** 作为独立渠道公布，验证方在 2008R2 干净机上
> **人工抄入**、生成自己机器上的 `verify_expect.txt`，并在签字页登记渠道与证据。
> 不得与 zip + 侧车同批下发，否则 A2 三方比对退回假绿。

**仍待确定**

- 签字页归档文件名（2008R2 干净机 30 项签单 PASS 后）
- 公告公开渠道与实际发布日期（需单独书面授权）
- 已下载 2 次对象的通知渠道与留痕（需单独书面授权）
