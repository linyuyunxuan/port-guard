"""IP 归属地定位器与离线库在线同步的测试（全部离线，不访问网络）"""

import json
import os

import pytest

from core import settings as cfg
from core import xdb_updater as U
from core.config import XDB_UPSTREAM, v4_xdb_path, v6_xdb_path, xdb_manifest_path
from core.database import init_db
from core.geo_locator import GeoLocator

# ═══════════════════ 定位器 ═══════════════════


@pytest.fixture
def locator(isolated_env):
    init_db()
    cfg.warm()
    return GeoLocator()


def test_locator_loads(locator):
    assert locator.available
    assert locator.load_error == ""


def test_lookup_v4_china(locator):
    geo = locator.lookup("113.118.113.77")
    assert geo.found
    assert geo.is_china
    assert geo.country == "中国"
    assert geo.province and geo.province != "0"


def test_lookup_v6(locator):
    geo = locator.lookup("2400:3200::1")
    assert geo.found
    assert geo.is_china


def test_lookup_reserved_range_is_not_china(locator):
    """
    127.0.0.1 在 ip2region 中落在 Reserved 段（有结果、但绝不是国内地址）。
    回归点：规则引擎不能把 Reserved 当成有效归属地去打分。
    """
    geo = locator.lookup("127.0.0.1")
    assert geo.is_china is False
    assert geo.country.lower() in ("reserved", "0", "")


def test_lookup_unknown_returns_not_found(locator):
    """解析不出 IP 时必须兜底为未知，而不是抛异常"""
    geo = locator.lookup("not-an-ip")
    assert geo.found is False
    assert geo.display == "未知"


def test_lookup_garbage_does_not_raise(locator):
    """非法 IP 必须兜底为未知，绝不把异常抛给 HTTP 层"""
    for bad in ("", "abc", "1.2.3", "999.1.1.1", "'; DROP TABLE x; --"):
        geo = locator.lookup(bad)
        assert geo.found is False


def test_cache_hit_and_clear(locator):
    locator.lookup("113.118.113.77")
    locator.lookup("113.118.113.77")
    info = locator.cache_info()
    assert info["hit"] >= 1
    assert info["size"] >= 1
    locator.cache_clear()
    assert locator.cache_info()["size"] == 0


def test_hot_reload_swaps_generation(locator):
    """热换库：不重启进程，代数 +1，缓存清空，查询依然正确"""
    locator.lookup("113.118.113.77")
    assert locator.cache_info()["size"] > 0
    ok, err = locator.reload()
    assert ok, err
    assert locator.generation == 1
    assert locator.cache_info()["size"] == 0
    assert locator.lookup("113.118.113.77").found


def test_reload_with_bad_path_keeps_old_library(locator):
    """热换库失败时必须保留旧库继续可用，不能把服务搞挂"""
    ok, err = locator.reload(v4_path="C:/definitely/not/here.xdb")
    assert ok is False and err
    assert locator.available
    assert locator.lookup("113.118.113.77").found


def test_library_info_structure(locator):
    info = locator.library_info()
    assert info["v4"]["exists"] and info["v4"]["size"] > 0
    assert info["v6"]["exists"] and info["v6"]["size"] > 0
    assert "manifest" in info


# ═══════════════════ 版本指纹 ═══════════════════


def test_git_blob_sha1_matches_git_formula(tmp_path):
    """
    git blob sha1 = sha1("blob <size>\\0" + content)
    校验我们的实现与手工计算一致（这是判断线上是否有新版本的唯一依据）。
    """
    import hashlib

    p = tmp_path / "f.bin"
    payload = b"hello portguard"
    p.write_bytes(payload)
    expect = hashlib.sha1(b"blob " + str(len(payload)).encode() + b"\0" + payload).hexdigest()
    assert U.git_blob_sha1(str(p)) == expect


def test_git_blob_sha1_against_real_xdb(isolated_env):
    """
    对真实 xdb 计算指纹，应与上游 GitHub API 返回的 sha 一致（v6 已确认相同）。
    这里只断言「能算出 40 位十六进制且不等于空」，网络比对放在集成测试里。
    """
    sha = U.git_blob_sha1(v6_xdb_path())
    assert len(sha) == 40
    assert all(c in "0123456789abcdef" for c in sha)


# ═══════════════════ 下载校验 ═══════════════════


def test_verify_downloaded_accepts_real_library(isolated_env):
    ok, err = U.verify_downloaded(
        v4_xdb_path(), "ip2region_v4.xdb", expect_sha=U.git_blob_sha1(v4_xdb_path())
    )
    assert ok, err


def test_verify_downloaded_rejects_wrong_sha(isolated_env):
    ok, err = U.verify_downloaded(v4_xdb_path(), "ip2region_v4.xdb", expect_sha="0" * 40)
    assert ok is False
    assert "指纹" in err


def test_verify_downloaded_rejects_wrong_size(isolated_env):
    ok, err = U.verify_downloaded(
        v4_xdb_path(), "ip2region_v4.xdb", expect_size=os.path.getsize(v4_xdb_path()) + 1
    )
    assert ok is False
    assert "大小" in err


def test_verify_downloaded_rejects_garbage(tmp_path):
    """被投毒的垃圾文件绝不能通过校验进入正式库位置"""
    p = tmp_path / "fake.xdb"
    p.write_bytes(b"\x00" * 4096)
    ok, err = U.verify_downloaded(str(p), "ip2region_v4.xdb")
    assert ok is False
    assert err


def test_verify_downloaded_rejects_empty(tmp_path):
    p = tmp_path / "empty.xdb"
    p.write_bytes(b"")
    ok, _err = U.verify_downloaded(str(p), "ip2region_v4.xdb")
    assert ok is False


# ═══════════════════ 下载源白名单 ═══════════════════


def test_build_urls_only_allowlisted_https(isolated_env):
    init_db()
    cfg.warm()
    urls = U._build_urls("ip2region_v4.xdb")
    assert urls, "内置源列表不应为空"
    assert all(u.startswith("https://") for u in urls)
    assert all("{path}" not in u for u in urls)


def test_custom_source_outside_allowlist_is_dropped(isolated_env):
    """自定义源若指向未授权主机（如内网地址）必须被丢弃，防 SSRF"""
    init_db()
    cfg.warm()
    cfg.set("xdb_source", "https://evil.internal.example/{path}")
    urls = U._build_urls("ip2region_v4.xdb")
    assert all("evil.internal.example" not in u for u in urls)


def test_custom_https_source_is_preferred(isolated_env):
    init_db()
    cfg.warm()
    cfg.set("xdb_source", "https://cdn.statically.io/gh/lionsoul2014/ip2region/master/{path}")
    urls = U._build_urls("ip2region_v4.xdb")
    assert urls[0].startswith("https://cdn.statically.io/")


# ═══════════════════ 清单与状态 ═══════════════════


def test_manifest_roundtrip(isolated_env):
    init_db()
    assert U.get_manifest() == {}
    p = xdb_manifest_path()
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"app_version": "test", "files": {"x": {"sha": "abc"}}}, f)
    m = U.get_manifest()
    assert m["app_version"] == "test"
    assert m["files"]["x"]["sha"] == "abc"


def test_manifest_tolerates_corrupt_file(isolated_env):
    init_db()
    with open(xdb_manifest_path(), "w", encoding="utf-8") as f:
        f.write("{ not json")
    assert U.get_manifest() == {}


def test_status_summary_shape(isolated_env):
    init_db()
    cfg.warm()
    s = U.status_summary()
    assert set(s["files"].keys()) == set(XDB_UPSTREAM.keys())
    for d in s["files"].values():
        assert "exists" in d and "size" in d
    assert "auto_sync" in s and "interval_hours" in s


def test_file_status_detects_update(isolated_env):
    init_db()
    path = v4_xdb_path()
    local_sha = U.git_blob_sha1(path)
    st = U._file_status("ip2region_v4.xdb", (local_sha, os.path.getsize(path)))
    assert st.needs_update is False

    st2 = U._file_status("ip2region_v4.xdb", ("deadbeef" * 5, 12345))
    assert st2.needs_update is True


def test_file_status_without_remote_marks_unknown(isolated_env):
    init_db()
    st = U._file_status("ip2region_v4.xdb", None)
    assert st.needs_update is False
    assert "无法探测" in st.reason or "缺失" in st.reason


def test_backup_and_restore(isolated_env):
    """备份与回滚链路：换库失败时能回到可用状态"""
    init_db()
    cfg.warm()
    path = v4_xdb_path()
    original = U.git_blob_sha1(path)
    bak = U._backup("ip2region_v4.xdb")
    assert bak and os.path.exists(bak)

    # 破坏当前库文件，然后从备份恢复
    with open(path, "r+b") as f:
        f.seek(0)
        f.write(b"\x00\x00\x00\x00")
    assert U.git_blob_sha1(path) != original

    loc = GeoLocator()
    loc.reload()
    ok, err = U.restore_backup("ip2region_v4.xdb")
    assert ok, err
    assert U.git_blob_sha1(path) == original
