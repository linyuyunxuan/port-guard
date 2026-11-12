"""v1.9.5 第二批护栏：观察模式 / 降级可验收 / 策略与审计可带出。

守的是三条底线：
  1. 交付 exe 不再强制提权，且「以管理员启动」入口随包可用；
  2. 读取失败绝不能被渲染成「未封禁 / 未知」；
  3. 逐台复制策略与导出审计时，不把运行数据或凭据带出去。

变异验证见 `_verify_tmp/mutation_trust_v195.py`：把实现改回错的，本文件必须变红。
"""

import json
import os
from pathlib import Path
from typing import Any

import pytest

from core import config as cfgmod
from core import database, policy_snapshot
from core import settings as cfg
from core.config import APP_VERSION
from gui import settings_audit
from qtcompat import QApplication, QFont

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def qapp():
    """离屏 QApplication（与 test_about_dialog 同一套口径）"""
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    app = QApplication.instance()
    if app is None:
        app = QApplication([])
    assert isinstance(app, QApplication)
    app.setFont(QFont("Microsoft YaHei UI", 9))
    yield app


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _method(rel: str, name: str, next_name: str) -> str:
    """截取单个方法体，避免「文件别处还有同名字符串」造成误判。"""
    src = _read(rel)
    return src[src.index(f"def {name}") : src.index(f"def {next_name}")]


# ── H5：观察模式 ──


def test_manifest_defaults_to_standard_user():
    manifest = _read("app.manifest")
    assert 'level="asInvoker"' in manifest
    assert "requireAdministrator" not in manifest
    spec = _read("port_guard.spec")
    assert "uac_admin=False," in spec
    assert "uac_admin=True," not in spec


def test_admin_launcher_ships_and_is_cmd_safe():
    raw = (ROOT / "delivery" / "start-as-admin.bat").read_bytes()
    assert all(x < 128 for x in raw), "启动器必须纯 ASCII"
    assert raw.count(b"\r\n") == raw.count(b"\n") > 0, "必须 CRLF"
    assert not raw.startswith(b"\xef\xbb\xbf"), "bat 不能带 BOM"
    assert b"-Verb RunAs" in raw
    assert "start-as-admin.bat" in _read("tools/pack_release.py")


def test_about_dialog_opens_permission_tab(qapp):
    from gui.about_dialog import AboutDialog

    dlg = AboutDialog([], initial_tab=2)
    try:
        assert dlg.tabs.tabText(2) == "权限与能力"
        assert dlg.tabs.currentIndex() == 2
    finally:
        dlg.close()
    assert "_show_permissions" in _read("gui/main_window.py")
    assert "si_admin.clicked.connect" in _read("gui/main_window.py")


def test_startup_geo_failure_never_blocks_unattended():
    body = _method("gui/main_window.py", "_poll_geo", "_reload_geo_now")
    assert "QMessageBox" not in body
    assert "定位库 读取失败" in body
    assert "重新加载定位库" in body
    assert "_set_status" in body


def test_geo_reload_entry_is_wired():
    assert "geo_reload_requested" in _read("gui/page_settings.py")
    assert "geo_reload_requested.connect" in _read("gui/main_window.py")
    # 定位库按钮在「数据与离线库」子页（拆分后归属 page_data）
    assert "重新加载定位库" in _read("gui/page_data.py")
    assert "reload_locator()" in _read("gui/main_window.py")


def test_overview_does_not_score_observe_mode_as_unhealthy():
    src = _read("gui/page_overview.py")
    assert 'num.setText(f"{ok}/2")' in src
    assert "观察模式（只读）" in src
    assert "权限不参与健康分" in src


def test_firewall_banner_visible_in_observe_mode():
    body = _method("gui/page_bans.py", "_refresh_fw_banner", "_render_fw_banner")
    assert "if not firewall.is_admin():" not in body
    assert "self._render_fw_banner()" in body


# ── H6：读取失败 ≠ 无数据 ──


class _BadConn:
    def execute(self, *_args: Any, **_kwargs: Any):
        raise RuntimeError("db boom")

    def close(self) -> None:
        pass


def test_active_ban_map_records_failure_for_gui(fresh_db):
    with pytest.raises(RuntimeError):
        database._active_ban_map(_BadConn())  # type: ignore[arg-type]
    assert "db boom" in database.ban_state_error()
    database.init_db()
    database.active_ban_ip_map()
    assert database.ban_state_error() == ""


def test_ban_state_banner_distinguishes_failure_from_empty():
    from gui.widgets import set_ban_state_banner

    class _Banner:
        def __init__(self) -> None:
            self.text = ""
            self.visible: bool = False

        def set_text(self, text: str) -> None:
            self.text = text

        def setVisible(self, visible: bool) -> None:
            self.visible = visible

    banner = _Banner()
    set_ban_state_banner(None, "boom")  # 最小宿主桩：不能炸
    assert not banner.visible
    set_ban_state_banner(banner, "boom")
    assert banner.visible and "读取失败" in banner.text
    set_ban_state_banner(banner, "")
    assert not banner.visible


def test_three_list_pages_show_ban_state_failure():
    for rel in ("gui/page_access.py", "gui/page_events.py", "gui/page_bans.py"):
        src = _read(rel)
        assert "set_ban_state_banner" in src, rel
        assert "_ban_state_banner" in src, rel
        assert '"重试"' in src, rel


def test_geo_failure_is_not_rendered_as_unknown():
    src = _read("gui/page_bans.py")
    assert "geo_failed" in src
    assert '"读取失败"' in src
    assert "归属地查询失败" in src
    assert "self.sug_empty = EmptyState(" in src
    assert "self.sug_empty = QLabel" not in src


# ── M7：审计可带出、策略可复制 ──


def test_audit_export_row_carries_host_and_version():
    row = settings_audit.audit_csv_row(
        {"ts": 0, "actor": "alice", "action": "settings.save", "result": "ok"},
        host="HOST-A",
        version="1.9.5",
    )
    assert len(row) == len(settings_audit.AUDIT_EXPORT_HEADERS) == 8
    assert row[1] == "alice", "操作者要留原始值，不能被中文别名替换"
    assert row[6] == "HOST-A" and row[7] == "1.9.5"
    assert "主机名" in settings_audit.AUDIT_EXPORT_HEADERS
    assert "程序版本" in settings_audit.AUDIT_EXPORT_HEADERS
    assert "导出 CSV" in _read("gui/settings_audit.py")


def test_policy_snapshot_excludes_sensitive_and_runtime_keys(fresh_db):
    cfg.warm()
    data = policy_snapshot.build_snapshot()
    assert data["schema"] == 1
    assert data["app_version"] == APP_VERSION
    assert isinstance(data["rules"], dict)
    assert isinstance(data["blacklist"], list) and isinstance(data["whitelist"], list)
    assert set(data["settings"]) <= set(policy_snapshot.POLICY_SETTING_KEYS)
    for key in (
        "alert_webhook_url",
        "xdb_proxy",
        "xdb_last_check_at",
        "xdb_sources",
        "autostart_enabled",
        "maintenance_last_date",
        "watch_fwlog_path",
    ):
        assert key not in data["settings"], f"不该跨机器复制：{key}"


def test_policy_snapshot_roundtrip(fresh_db, tmp_path: Path):
    cfg.warm()
    cfg.set("auto_ban_threshold", "77", persist=False)
    path = str(tmp_path / "policy.json")
    exported = policy_snapshot.export_to(path)
    assert exported["settings"]["auto_ban_threshold"] == "77"
    assert json.loads(Path(path).read_text(encoding="utf-8"))["schema"] == 1

    cfg.set("auto_ban_threshold", "10", persist=False)
    res = policy_snapshot.import_from(path)
    assert res["ok"], res["error"]
    assert cfg.get("auto_ban_threshold") == "77"
    assert res["applied"]["settings"] > 0
    assert Path(res["backup_dir"]).is_dir()
    assert (Path(res["backup_dir"]) / "settings.json").is_file()


def test_policy_snapshot_rejects_bad_or_sensitive_payload(fresh_db, tmp_path: Path):
    ok, err = policy_snapshot.validate({"schema": 999})
    assert not ok and "版本不兼容" in err
    base: dict = {
        "schema": policy_snapshot.SCHEMA,
        "rules": {},
        "blacklist": [],
        "whitelist": [],
        "settings": {},
    }
    assert policy_snapshot.validate(base)[0]
    bad = dict(base, settings={"alert_webhook_url": "https://example.invalid"})
    ok2, err2 = policy_snapshot.validate(bad)
    assert not ok2 and "不允许复制" in err2
    assert not policy_snapshot.validate(dict(base, blacklist=[1, 2]))[0]
    assert not policy_snapshot.import_from(str(tmp_path / "missing.json"))["ok"]


def test_policy_import_rolls_back_on_write_failure(fresh_db, tmp_path: Path, monkeypatch: Any):
    """失败必须发生在「设置已写入之后」，且回滚必须真的被调用。"""
    database.init_db()  # fresh_db 删库后未必建表，避免 set_many 落库刷错
    cfg.warm()
    path = str(tmp_path / "policy.json")
    policy_snapshot.export_to(path)  # 快照带的是导出时的阈值（默认 90）
    cfg.set("auto_ban_threshold", "10", persist=False)  # 导入前把现值改掉
    before = cfg.get("auto_ban_threshold")
    snapshot_value = json.loads(Path(path).read_text(encoding="utf-8"))["settings"][
        "auto_ban_threshold"
    ]
    assert snapshot_value != before, "快照值与现值必须不同，否则回滚断言是空转"

    # RuleEngine.__init__ 里就会调 load_lists / reload，直接打桩这两个方法会让
    # 失败发生在任何写入之前 —— 那样「是否回滚」根本验不出来。改成让写入真实
    # 执行完再失败；第二次（回滚里的 set_many）放行，才能验证恢复。
    real_set_many = cfg.set_many
    state = {"n": 0}

    def _write_then_boom(items):
        real_set_many(items)
        state["n"] += 1
        if state["n"] == 1:
            raise RuntimeError("write failed")

    real_restore = policy_snapshot._restore
    restored = []

    def _spy_restore(folder):
        restored.append(folder)
        return real_restore(folder)

    monkeypatch.setattr(cfg, "set_many", _write_then_boom)
    monkeypatch.setattr(policy_snapshot, "_restore", _spy_restore)
    res = policy_snapshot.import_from(path)
    assert not res["ok"]
    assert "回滚" in res["error"]
    assert Path(res["backup_dir"]).is_dir()
    assert (Path(res["backup_dir"]) / "settings.json").is_file()
    assert state["n"] >= 1, "写入必须已发生，否则回滚断言是空转"
    assert restored == [res["backup_dir"]], "导入失败必须真的调用回滚"
    assert cfg.get("auto_ban_threshold") == before, "回滚必须把已写入的设置恢复原值"


def test_policy_snapshot_paths_are_isolated(fresh_db):
    """护栏自身不能写真实 data/：isolated_env 已把 project_dir 指向临时目录。"""
    assert cfgmod.project_dir() != str(ROOT)
    assert str(ROOT / "data") not in cfgmod.rules_path()
