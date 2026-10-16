"""
PortGuard — 离线 IP 库在线同步（ip2region xdb）

背景：ip2region 的 xdb 是离线库，随上游仓库更新（新增/修正 IP 段）。
内置一份能跑，但会随时间过期 —— 本模块负责「实时把离线库同步到线上最新版」。

## 版本比对：不下载也能精确判断
GitHub Contents API 返回的是 **git blob sha1**（`sha1("blob <size>\\0" + content)`），
本地文件可以本地算出来，两者相等即内容完全一致。实测：

    data/ip2region_v6.xdb  -> 15002d535f31336cc556b672a617186c827ea14c  (与上游一致)
    data/ip2region_v4.xdb  -> c3d5915c69816dd3474943f0c826dcc2fd9aa562  (上游 bda1438a…，已过期)

所以「探测更新」只需一次几百字节的 API 请求，**零大文件流量**。

## 更新流程（每一步都可失败回退）
1. 探测：GitHub API 拿 sha/size；API 不可达时退回「范围请求读 Content-Range」只比大小
2. 下载：按源列表顺序尝试（CDN → 官方 → 镜像 → Gitee），任一成功即停，支持断点大小校验
3. 校验：大小 → git blob sha → xdb 结构校验 → 抽样查询冒烟
4. 备份：旧库先复制到 backup/，带时间戳
5. 换库：下载文件 `os.replace` 原子替换（同盘，Windows 下原子）
6. 热加载：`GeoLocator.reload()` 把新库整库读入内存并原子替换 searcher，**不重启进程**
7. 回滚：热加载失败则从备份恢复并重新热加载，回到可用状态

## 安全约束
- 只允许 https，且主机必须在白名单内（防被改成内网地址做 SSRF）
- 单文件体积上限（防被喂超大文件打爆磁盘）
- 校验不过的文件绝不落盘到正式库位置
- 校验通过后仍保留 .bak，可一键回滚
"""
import contextlib
import hashlib
import json
import os
import shutil
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from core import settings as cfg
from core.config import (
    APP_VERSION,
    XDB_ALLOWED_HOSTS,
    XDB_DOWNLOAD_TIMEOUT,
    XDB_MAX_FILE_MB,
    XDB_META_API,
    XDB_SOURCE_TEMPLATES,
    XDB_UPSTREAM,
    backup_dir,
    download_dir,
    xdb_manifest_path,
    xdb_path,
)
from core.logger import get_logger
from core.validators import InvalidURL, safe_https_url

log = get_logger(__name__)

# 单文件下载超时按体积自适应：假定最差 40 KB/s
_MIN_SPEED_BPS = 40_000
_USER_AGENT = f"PortGuard/{APP_VERSION} (+offline-ipdb-sync)"

_lock = threading.RLock()
_in_progress = False

ProgressFn = Optional[Callable[[str, str, int], None]]


# ═══════════════════════════════════════════════════════════
#  结果模型
# ═══════════════════════════════════════════════════════════

@dataclass
class FileStatus:
    name: str
    local_size: int = 0
    local_sha: str = ""
    remote_size: int = 0
    remote_sha: str = ""
    needs_update: bool = False
    reason: str = ""

    @property
    def local_mb(self) -> float:
        return round(self.local_size / 1024 / 1024, 2)

    @property
    def remote_mb(self) -> float:
        return round(self.remote_size / 1024 / 1024, 2)


@dataclass
class CheckResult:
    ok: bool = False
    message: str = ""
    method: str = "none"          # github-api | content-range | none
    files: List[FileStatus] = field(default_factory=list)
    checked_at: int = 0

    @property
    def has_update(self) -> bool:
        return any(f.needs_update for f in self.files)


@dataclass
class UpdateResult:
    ok: bool = False
    updated: bool = False          # 是否真的换了库
    message: str = ""
    files: List[Dict] = field(default_factory=list)
    duration_ms: int = 0
    reloaded: bool = False
    rolled_back: bool = False


# ═══════════════════════════════════════════════════════════
#  指纹
# ═══════════════════════════════════════════════════════════

def git_blob_sha1(path: str) -> str:
    """
    计算文件的 git blob sha1，可直接与 GitHub API 返回的 sha 比对。
    公式：sha1("blob <字节数>\\0" + 文件内容)
    """
    size = os.path.getsize(path)
    h = hashlib.sha1()
    h.update(f"blob {size}\0".encode())
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ═══════════════════════════════════════════════════════════
#  清单（记录上次同步状态，供 UI 展示）
# ═══════════════════════════════════════════════════════════

def get_manifest() -> Dict:
    p = xdb_manifest_path()
    if not os.path.exists(p):
        return {}
    try:
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        log.exception("读取离线库清单失败")
        return {}


def _save_manifest(d: Dict) -> None:
    p = xdb_manifest_path()
    tmp = p + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2)
        os.replace(tmp, p)
    except Exception:
        log.exception("写入离线库清单失败")


# ═══════════════════════════════════════════════════════════
#  网络
# ═══════════════════════════════════════════════════════════

def _opener(direct: bool):
    """direct=True 直连（默认）；False 走系统/环境变量代理"""
    if direct:
        return urllib.request.build_opener(urllib.request.ProxyHandler({}))
    return urllib.request.build_opener(urllib.request.ProxyHandler())


def _proxy_modes() -> List[bool]:
    """
    返回尝试顺序。默认直连（公共 CDN 直连更快更稳）；
    若系统配置了代理，再补一轮走代理的尝试。
    """
    proxy = (cfg.get("xdb_proxy", "") or "").strip()
    if proxy:
        return [True]     # 显式配置了代理，_opener 会用它
    modes = [True]
    try:
        if urllib.request.getproxies():
            modes.append(False)
    except Exception:
        pass
    return modes


def _headers(extra: Optional[Dict] = None) -> Dict[str, str]:
    h = {"User-Agent": _USER_AGENT, "Accept": "*/*"}
    proxy = (cfg.get("xdb_proxy", "") or "").strip()
    if proxy:
        h["X-Proxy-Hint"] = proxy
    if extra:
        h.update(extra)
    return h


def _custom_proxy_handler():
    proxy = (cfg.get("xdb_proxy", "") or "").strip()
    if not proxy:
        return None
    return urllib.request.ProxyHandler({"http": proxy, "https": proxy})


def _open(url: str, timeout: float, direct: bool, extra_headers: Optional[Dict] = None):
    proxy = _custom_proxy_handler()
    op = urllib.request.build_opener(proxy) if proxy is not None else _opener(direct)
    req = urllib.request.Request(url, headers=_headers(extra_headers))
    return op.open(req, timeout=timeout)


def _source_list() -> List[str]:
    """
    组装下载源列表。用户可在设置里用 xdb_source 指定一个自定义模板前缀
    （形如 `https://my-mirror.example.com/ip2region/{path}`），优先尝试。
    """
    tpls: List[str] = []
    custom = (cfg.get("xdb_source", "") or "").strip()
    if custom:
        tpls.append(custom)
    tpls.extend(XDB_SOURCE_TEMPLATES)
    return tpls


def _allowed_hosts() -> List[str]:
    hosts = list(XDB_ALLOWED_HOSTS)
    extra = (cfg.get("xdb_extra_hosts", "") or "").strip()
    if extra:
        hosts.extend(h.strip().lower() for h in extra.split(",") if h.strip())
    return hosts


def _build_urls(name: str) -> List[str]:
    up = XDB_UPSTREAM.get(name)
    if not up:
        return []
    hosts = _allowed_hosts()
    out = []
    for tpl in _source_list():
        url = tpl.replace("{path}", up)
        try:
            out.append(safe_https_url(url, allowed_hosts=hosts))
        except InvalidURL as e:
            log.warning("跳过不合规的下载源：%s", e)
    return out


# ═══════════════════════════════════════════════════════════
#  探测
# ═══════════════════════════════════════════════════════════

def _remote_via_api(name: str, timeout: float) -> Optional[Tuple[str, int]]:
    """GitHub Contents API -> (sha, size)。只需几百字节流量。"""
    up = XDB_UPSTREAM.get(name)
    if not up:
        return None
    url = XDB_META_API.format(path=up)
    for direct in _proxy_modes():
        try:
            with _open(url, timeout, direct,
                       {"Accept": "application/vnd.github+json"}) as r:
                data = json.loads(r.read().decode("utf-8"))
            sha = str(data.get("sha") or "")
            size = int(data.get("size") or 0)
            if sha and size > 0:
                return sha, size
        except Exception as e:
            log.debug("元数据探测失败（%s, direct=%s）：%s", name, direct, e)
    return None


def _remote_via_range(name: str, timeout: float) -> Optional[int]:
    """
    API 不可达时的兜底：对第一个可用源发 `Range: bytes=0-0`，
    从 `Content-Range: bytes 0-0/11122642` 里读出总大小。
    """
    for url in _build_urls(name):
        for direct in _proxy_modes():
            try:
                with _open(url, timeout, direct, {"Range": "bytes=0-0"}) as r:
                    cr = r.headers.get("Content-Range") or ""
                    if "/" in cr:
                        total = int(cr.rsplit("/", 1)[1])
                        if total > 0:
                            return total
            except Exception:
                continue
    return None


def _file_status(name: str, remote: Optional[Tuple[str, int]]) -> FileStatus:
    path = xdb_path(name)
    st = FileStatus(name=name)
    if os.path.exists(path):
        st.local_size = os.path.getsize(path)
        try:
            st.local_sha = git_blob_sha1(path)
        except Exception:
            log.exception("计算本地库指纹失败：%s", path)
    else:
        st.reason = "本地库文件缺失"

    if remote is None:
        st.needs_update = not os.path.exists(path)
        st.reason = st.reason or "无法探测线上版本（网络不可达），跳过"
        return st

    st.remote_sha, st.remote_size = remote

    if not os.path.exists(path):
        st.needs_update = True
        st.reason = "本地库文件缺失，需要下载"
        return st

    if st.remote_sha:
        if st.local_sha and st.local_sha == st.remote_sha:
            st.needs_update = False
            st.reason = "已是最新（内容指纹一致）"
        else:
            st.needs_update = True
            st.reason = "线上内容已更新"
    elif st.remote_size:
        st.needs_update = st.local_size != st.remote_size
        st.reason = ("大小不一致，可能已更新" if st.needs_update
                     else "大小一致（未能取到内容指纹，按大小判定为最新）")
    else:
        st.needs_update = False
        st.reason = "无法判定"
    return st


def check(progress: ProgressFn = None) -> CheckResult:
    """探测线上版本并与本地比对（不下载大文件）"""
    res = CheckResult(checked_at=int(time.time() * 1000))
    try:
        any_api = False
        for i, name in enumerate(XDB_UPSTREAM, start=1):
            if progress:
                progress("check", f"正在探测 {name} …", int(i * 100 / len(XDB_UPSTREAM)))
            remote = _remote_via_api(name, timeout=15)
            if remote:
                any_api = True
            else:
                size = _remote_via_range(name, timeout=15)
                remote = ("", size) if size else None
            res.files.append(_file_status(name, remote))
        res.method = "github-api" if any_api else (
            "content-range" if any(f.remote_size for f in res.files) else "none")
    except Exception as e:
        log.exception("探测线上版本失败")
        res.ok = False
        res.message = f"探测失败：{e}"
        return res

    res.ok = any(f.remote_size or f.remote_sha for f in res.files)
    if not res.ok:
        res.message = "无法连接任何更新源（离线或网络受限），已跳过检查"
    elif res.has_update:
        names = "、".join(f.name for f in res.files if f.needs_update)
        res.message = f"发现新版本：{names}"
    else:
        res.message = "离线库已是最新版本"
    cfg.set("xdb_last_check_at", str(res.checked_at))
    return res


# ═══════════════════════════════════════════════════════════
#  下载与校验
# ═══════════════════════════════════════════════════════════

def _timeout_for(size: int) -> float:
    est = max(XDB_DOWNLOAD_TIMEOUT, int(size / _MIN_SPEED_BPS) + 30)
    return float(min(est, 900))


def _download(name: str, dest: str, expect_size: int = 0,
              progress: ProgressFn = None, budget: str = "download") -> Tuple[bool, str, str]:
    """
    依次尝试各下载源，成功返回 (True, 使用的源, "")。
    下载写入 dest.part，完成后大小校验通过才 rename 成 dest。
    """
    urls = _build_urls(name)
    if not urls:
        return False, "", f"{name} 没有可用的下载源（可能被白名单拦下）"

    max_bytes = XDB_MAX_FILE_MB * 1024 * 1024
    part = dest + ".part"
    errors: List[str] = []

    for idx, url in enumerate(urls, start=1):
        host = url.split("/")[2] if "://" in url else url
        for direct in _proxy_modes():
            try:
                if progress:
                    progress(budget, f"尝试源 {idx}/{len(urls)}：{host}", 5)
                to = _timeout_for(expect_size or max_bytes // 8)
                with _open(url, to, direct) as r, open(part, "wb") as f:
                    total = int(r.headers.get("Content-Length") or expect_size or 0)
                    got = 0
                    last_pct = -1
                    last_emit = 0.0
                    while True:
                        chunk = r.read(1 << 16)
                        if not chunk:
                            break
                        got += len(chunk)
                        if got > max_bytes:
                            raise RuntimeError(
                                f"文件超过 {XDB_MAX_FILE_MB} MB 上限，已中断")
                        f.write(chunk)
                        # 进度节流：百分比变化 且 间隔 >= 400ms 才回调，
                        # 否则 10MB 下载会触发 160 次 UI 刷新
                        if progress and total:
                            pct = min(99, int(got * 100 / total))
                            now = time.monotonic()
                            if pct != last_pct and now - last_emit >= 0.4:
                                last_pct, last_emit = pct, now
                                progress(budget,
                                         f"{os.path.basename(name)} 已下载 "
                                         f"{got / 1048576:.1f}/{total / 1048576:.1f} MB",
                                         pct)
                if expect_size and got != expect_size:
                    raise RuntimeError(f"大小不符：期望 {expect_size} 实得 {got}")
                if got == 0:
                    raise RuntimeError("下载内容为空")
                os.replace(part, dest)
                log.info("离线库 %s 下载完成：%s（%.2f MB，源 %s）",
                         name, dest, got / 1048576, host)
                return True, url, ""
            except Exception as e:
                errors.append(f"{host}: {e}")
                log.warning("下载源失败 %s（direct=%s）：%s", host, direct, e)
                try:
                    if os.path.exists(part):
                        os.remove(part)
                except Exception:
                    pass
    return False, "", "；".join(errors[:6])


def verify_downloaded(path: str, name: str, expect_sha: str = "",
                      expect_size: int = 0) -> Tuple[bool, str]:
    """
    四重校验：大小 → git blob sha → xdb 结构 → 抽样查询冒烟。
    任何一项不过都判定失败，调用方不会把它换进正式库位置。
    """
    try:
        size = os.path.getsize(path)
    except Exception as e:
        return False, f"文件不可读：{e}"
    if size <= 0:
        return False, "文件为空"
    if expect_size and size != expect_size:
        return False, f"大小不符：期望 {expect_size}，实得 {size}"

    if expect_sha:
        try:
            got = git_blob_sha1(path)
        except Exception as e:
            return False, f"指纹计算失败：{e}"
        if got != expect_sha:
            return False, f"内容指纹不符：期望 {expect_sha[:12]}，实得 {got[:12]}"

    # xdb 结构校验 + 抽样查询
    try:
        from ip2region import util as ip2util
        ip2util.verify_from_file(path)
    except Exception as e:
        return False, f"xdb 结构校验失败：{e}"

    try:
        from ip2region import searcher as xdbsearcher
        from ip2region import util as ip2util
        version = ip2util.IPv4 if name.endswith("_v4.xdb") else ip2util.IPv6
        buf = ip2util.load_content_from_file(path)
        s = xdbsearcher.new_with_buffer(version, buf)
        probes = (["1.1.1.1", "8.8.8.8", "223.5.5.5", "114.114.114.114"]
                  if version is ip2util.IPv4
                  else ["2400:3200::1", "2001:4860:4860::8888", "240e:1:1::1"])
        hits = 0
        for ip in probes:
            try:
                if (s.search(ip) or "").strip():
                    hits += 1
            except Exception:
                pass
        if hits == 0:
            return False, "抽样查询全部未命中，疑似文件损坏"
    except Exception as e:
        return False, f"加载冒烟测试失败：{e}"

    return True, ""


# ═══════════════════════════════════════════════════════════
#  备份 / 回滚
# ═══════════════════════════════════════════════════════════

def _backup(name: str) -> Optional[str]:
    src = xdb_path(name)
    if not os.path.exists(src):
        return None
    dst = os.path.join(backup_dir(), f"{name}.{int(time.time())}.bak")
    try:
        shutil.copy2(src, dst)
        log.info("已备份旧库：%s", dst)
        return dst
    except Exception:
        log.exception("备份旧库失败：%s", src)
        return None


def restore_backup(name: str, backup_file: str = "") -> Tuple[bool, str]:
    """从备份恢复指定库并热加载"""
    if not backup_file:
        cands = sorted(
            (f for f in os.listdir(backup_dir()) if f.startswith(name + ".")),
            reverse=True)
        if not cands:
            return False, f"没有 {name} 的可用备份"
        backup_file = os.path.join(backup_dir(), cands[0])
    if not os.path.exists(backup_file):
        return False, f"备份文件不存在：{backup_file}"
    try:
        shutil.copy2(backup_file, xdb_path(name))
    except Exception as e:
        return False, f"恢复失败：{e}"
    ok, err = _reload_locator()
    log.warning("已从备份恢复 %s（%s），热加载 %s", name, backup_file,
                "成功" if ok else f"失败：{err}")
    return ok, err


def list_backups() -> List[Dict]:
    out = []
    try:
        for f in sorted(os.listdir(backup_dir()), reverse=True):
            p = os.path.join(backup_dir(), f)
            if not os.path.isfile(p):
                continue
            out.append({"file": f, "path": p,
                        "size": os.path.getsize(p),
                        "mtime": int(os.path.getmtime(p) * 1000)})
    except Exception:
        pass
    return out


def _reload_locator() -> Tuple[bool, str]:
    try:
        from core.geo_locator import reload_locator
        return reload_locator()
    except Exception as e:
        log.exception("热加载定位库失败")
        return False, str(e)


# ═══════════════════════════════════════════════════════════
#  主流程
# ═══════════════════════════════════════════════════════════

def is_updating() -> bool:
    return _in_progress


def update(force: bool = False, progress: ProgressFn = None,
           names: Optional[List[str]] = None) -> UpdateResult:
    """
    执行同步：探测 → 下载 → 校验 → 备份 → 原子替换 → 热加载。
    force=True 时即使指纹一致也重新下载（用于修复疑似损坏的库）。
    同一时刻只允许一个同步任务。
    """
    global _in_progress
    t0 = time.time()

    with _lock:
        if _in_progress:
            return UpdateResult(ok=False, message="已有同步任务在进行中")
        _in_progress = True

    try:
        return _do_update(force, progress, names, t0)
    finally:
        with _lock:
            _in_progress = False


def _do_update(force: bool, progress: ProgressFn,
               names: Optional[List[str]], t0: float) -> UpdateResult:
    result = UpdateResult()
    targets = names or list(XDB_UPSTREAM.keys())

    def emit(stage: str, message: str, percent: int = 0) -> None:
        if progress:
            progress(stage, message, percent)
        try:
            from core.event_bus import bus
            bus.emit_xdb({"stage": stage, "message": message, "percent": percent})
        except Exception:
            pass

    # 1) 探测
    emit("check", "正在探测线上版本…", 2)
    chk = check(progress=lambda s, m, p: emit(s, m, max(2, p // 3)))
    if not chk.ok:
        result.message = chk.message
        cfg.set("xdb_last_result", chk.message)
        emit("failed", chk.message, 100)
        result.duration_ms = int((time.time() - t0) * 1000)
        return result

    todo = [f for f in chk.files if (f.needs_update or force) and f.name in targets]
    if not todo:
        result.ok = True
        result.updated = False
        result.message = "离线库已是最新版本，无需更新"
        result.files = [asdict(f) for f in chk.files]
        cfg.set("xdb_last_result", result.message)
        emit("uptodate", result.message, 100)
        result.duration_ms = int((time.time() - t0) * 1000)
        return result

    # 2) 下载 + 校验（全部先落到 download/ 目录，任一步失败都不动正式库）
    staged: List[Tuple[str, str, Optional[str], Dict]] = []
    dl_dir = download_dir()
    total = len(todo)
    for i, fs in enumerate(todo, start=1):
        name = fs.name
        stage_file = os.path.join(dl_dir, f"{name}.new")
        base_pct = 5 + int((i - 1) * 70 / total)
        span = int(70 / total)

        emit("download", f"开始下载 {name}（{fs.remote_mb} MB）", base_pct)

        # 进度回调：base_pct / span 显式绑定为默认参数。闭包若直接引用循环变量，
        # 一旦回调被延时调用（未来改成异步下载就会），拿到的会是循环结束后的值，
        # 进度条会跳错区间。
        def _on_progress(s, m, p, _b=base_pct, _s=span):
            emit(s, m, _b + int(p * _s / 100))

        ok, src, err = _download(
            name, stage_file, expect_size=fs.remote_size,
            progress=_on_progress, budget="download")
        if not ok:
            msg = f"{name} 下载失败：{err}"
            log.error(msg)
            _cleanup(staged)
            result.message = msg
            cfg.set("xdb_last_result", msg)
            emit("failed", msg, 100)
            result.duration_ms = int((time.time() - t0) * 1000)
            return result

        emit("verify", f"正在校验 {name}…", base_pct + span)
        ok, err = verify_downloaded(stage_file, name,
                                    expect_sha=fs.remote_sha,
                                    expect_size=fs.remote_size)
        if not ok:
            msg = f"{name} 校验失败：{err}"
            log.error(msg)
            with contextlib.suppress(Exception):
                os.remove(stage_file)
            _cleanup(staged)
            result.message = msg
            cfg.set("xdb_last_result", msg)
            emit("failed", msg, 100)
            result.duration_ms = int((time.time() - t0) * 1000)
            return result

        new_sha = git_blob_sha1(stage_file)
        new_sha256 = sha256_of(stage_file)
        staged.append((name, stage_file, _backup(name), {
            "name": name,
            "size": os.path.getsize(stage_file),
            "sha": new_sha,
            "sha256": new_sha256,
            "old_sha": fs.local_sha,
            "old_sha256": "",
            "source": src,
            "updated_at": int(time.time() * 1000),
        }))
        emit("verify", f"{name} 校验通过", base_pct + span)

    # 3) 原子替换
    emit("apply", "正在替换离线库…", 80)
    applied: List[str] = []
    try:
        for name, stage_file, _bak, _meta in staged:
            os.replace(stage_file, xdb_path(name))
            applied.append(name)
    except Exception as e:
        log.exception("替换离线库失败，开始回滚")
        for name, _sf, bak, _m in staged:
            if bak and name in applied:
                try:
                    shutil.copy2(bak, xdb_path(name))
                except Exception:
                    log.exception("回滚 %s 失败", name)
        result.ok = False
        result.rolled_back = True
        result.message = f"替换失败已回滚：{e}"
        cfg.set("xdb_last_result", result.message)
        emit("failed", result.message, 100)
        result.duration_ms = int((time.time() - t0) * 1000)
        return result

    # 4) 热加载
    emit("reload", "正在热加载新库（无需重启）…", 88)
    ok, err = _reload_locator()
    if not ok:
        log.error("热加载失败，回滚到更新前状态：%s", err)
        for name, _sf, bak, _m in staged:
            if bak:
                try:
                    shutil.copy2(bak, xdb_path(name))
                except Exception:
                    log.exception("回滚 %s 失败", name)
        _reload_locator()
        result.ok = False
        result.rolled_back = True
        result.message = f"新库热加载失败，已回滚：{err}"
        cfg.set("xdb_last_result", result.message)
        emit("failed", result.message, 100)
        result.duration_ms = int((time.time() - t0) * 1000)
        return result

    # 5) 记录清单
    man = get_manifest()
    man["app_version"] = APP_VERSION
    man["updated_at"] = int(time.time() * 1000)
    files = man.setdefault("files", {})
    for _name, _sf, _bak, meta in staged:
        files[meta["name"]] = meta
    _save_manifest(man)

    now_ms = int(time.time() * 1000)
    cfg.set("xdb_last_update_at", str(now_ms))
    msg = "已更新：" + "、".join(f"{n}（{m['size'] / 1048576:.1f} MB）"
                                for n, _s, _b, m in staged)
    cfg.set("xdb_last_result", msg)
    log.info("离线库同步完成：%s", msg)

    result.ok = True
    result.updated = True
    result.reloaded = True
    result.message = msg
    result.files = [m for _n, _s, _b, m in staged]
    result.duration_ms = int((time.time() - t0) * 1000)
    emit("done", msg, 100)
    return result


def _cleanup(staged: List[Tuple[str, str, Optional[str], Dict]]) -> None:
    for _n, sf, _b, _m in staged:
        try:
            if os.path.exists(sf):
                os.remove(sf)
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════
#  状态摘要（UI 用）
# ═══════════════════════════════════════════════════════════

def status_summary() -> Dict:
    """给设置页/IP 查询页展示的一屏摘要"""
    man = get_manifest()
    files = man.get("files", {}) if isinstance(man, dict) else {}
    out: Dict[str, Dict] = {}
    for name in XDB_UPSTREAM:
        p = xdb_path(name)
        local = {"name": name, "exists": os.path.exists(p), "size": 0, "mtime": 0}
        if local["exists"]:
            try:
                st = os.stat(p)
                local["size"] = st.st_size
                local["mtime"] = int(st.st_mtime * 1000)
            except Exception:
                pass
        rec = files.get(name, {})
        local["synced_sha"] = rec.get("sha", "")
        local["synced_at"] = rec.get("updated_at", 0)
        local["source"] = rec.get("source", "")
        out[name] = local
    return {
        "files": out,
        "last_check_at": cfg.get_int("xdb_last_check_at", 0),
        "last_update_at": cfg.get_int("xdb_last_update_at", 0),
        "last_result": cfg.get("xdb_last_result", ""),
        "auto_sync": cfg.get_bool("xdb_auto_sync", True),
        "auto_download": cfg.get_bool("xdb_auto_download", True),
        "interval_hours": cfg.get_int("xdb_sync_interval_hours", 24),
        "updating": _in_progress,
    }
