"""交付合规护栏（v1.9.4）：包内材料、对外口径、版本联动。

这些断言守的是「随 zip 以 1:N 复制到客户机器」的东西：
少一份许可全文、把可选 Webhook 写成「绝不外发」、关于页指向包内不存在的文件、
或者版本号漏改一处，都会让每一台客户机器带着同一个缺陷交付出去。

变异验证见提交说明：把实现改回错的，本文件必须成片变红，否则属于空转。
"""

import hashlib
import importlib.util
import re
import zipfile
from pathlib import Path
from typing import Any

from core.config import APP_VERSION

ROOT = Path(__file__).resolve().parents[1]
DELIVERY = ROOT / "delivery"

# tools/ 没有 __init__.py，用 importlib 直接按文件路径加载，免得依赖 pytest 的 sys.path
_spec = importlib.util.spec_from_file_location("pack_release", ROOT / "tools" / "pack_release.py")
assert _spec is not None and _spec.loader is not None
pack_release: Any = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pack_release)


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def _doc(name: str) -> str:
    return (DELIVERY / name).read_text(encoding="utf-8")


# ── 交付材料齐全 ──


def test_delivery_files_exist():
    assert (ROOT / "NOTICE").is_file()
    for rel in pack_release.DELIVERY_FILES:
        assert (DELIVERY / rel).is_file(), f"缺少交付材料：{rel}"
    assert len(pack_release.DELIVERY_FILES) == 9


def test_license_texts_are_official_full_texts():
    lgpl = (DELIVERY / "licenses/LICENSE-LGPL-3.0.txt").read_bytes()
    gpl = (DELIVERY / "licenses/LICENSE-GPL-3.0.txt").read_bytes()
    apache = (DELIVERY / "licenses/LICENSE-Apache-2.0.txt").read_bytes()
    assert b"GNU LESSER GENERAL PUBLIC LICENSE" in lgpl
    assert b"GNU GENERAL PUBLIC LICENSE" in gpl
    assert b"Apache License" in apache and b"Version 2.0, January 2004" in apache
    # 许可全文保持上游原字节，便于与官方 wheel 逐字比对
    assert not lgpl.startswith(b"\xef\xbb\xbf")
    assert not apache.startswith(b"\xef\xbb\xbf")


def test_delivery_docs_contain_required_facts():
    deploy = _doc("01_DEPLOY.txt")
    for fact in (
        "%APPDATA%\\PortGuard\\",
        "PortGuard_Block_",
        "PortGuard_Allow_",
        "KB2999226",
        "--diag --quiet",
        "xdb_auto_sync",
        "立即同步",
        "asInvoker",
        "观察模式",
        "start-as-admin.bat",
        "重新加载定位库",
        "封禁状态读取失败",
        "策略快照",
        "导出 CSV",
    ):
        assert fact in deploy, f"部署说明漏了关键事实：{fact}"

    terms = _doc("02_TERMS.txt")
    for fact in ("LGPL v3", "PySide2", "替换", "Webhook"):
        assert fact in terms

    integrity = _doc("03_INTEGRITY.txt")
    for fact in ("Authenticode", "certutil", "SHA256", "asInvoker", "start-as-admin.bat"):
        assert fact in integrity
    # 不能把「未签名」写成「已签名」，也不能把「全进程提权」写成现状
    assert "**未进行 Authenticode 数字签名**" in integrity
    assert "requireAdministrator（全进程" not in integrity

    changelog = _doc("04_CHANGELOG.txt")
    assert f"v{APP_VERSION} ·" in changelog
    assert "只读 / 观察模式" in changelog
    assert "策略快照" in changelog


# ── 对外口径与实物一致 ──


def test_notice_matches_delivered_stack():
    text = _read("NOTICE")
    assert "PySide2 5.15.2.1" in text
    assert "已随交付 exe 包附带" in text
    assert "licenses/LICENSE-LGPL-3.0.txt" in text
    for gone in ("| FastAPI |", "| Uvicorn |", "| Starlette", "| Pydantic"):
        assert gone not in text, f"NOTICE 仍把已移除的依赖列为运行时依赖：{gone}"
    assert "httpx" not in text


def test_readme_has_no_stale_claims():
    text = _read("README.md")
    for stale in (
        "也不往外部发告警",
        "GUI 使用 PySide6（LGPL v3）",
        "PortGuard_Block_<IP>_<毫秒时间戳>",
        "PortGuard 1.2.0 启动",
        "程序**不开放任何监听端口**，也不往外部发告警",
    ):
        assert stale not in text, f"README 仍有与实物冲突的表述：{stale}"
    for fact in (
        "Webhook",
        "PySide2 5.15.2.1",
        "十四、对外交付包与客户材料",
        "xdb_auto_sync",
        "asInvoker",
        "start-as-admin.bat",
        "观察模式",
    ):
        assert fact in text


def test_about_dialog_points_to_files_that_really_ship():
    text = _read("gui/about_dialog.py")
    assert "NOTICE.txt" in text
    assert "licenses/" in text
    assert "02_TERMS.txt" in text
    assert (ROOT / "NOTICE").is_file()
    assert (DELIVERY / "licenses/LICENSE-LGPL-3.0.txt").is_file()


def test_settings_button_does_not_promise_app_update():
    # 离线库更新按钮文本随「数据与离线库」tab 拆分迁移到 page_data
    text = _read("gui/page_data.py")
    assert "检查离线库更新" in text
    assert "立即检查更新" not in text


def test_history_docs_are_marked_as_snapshots():
    for rel in (
        "docs/功能评估与优化建议-2026-10-20.md",
        "docs/功能评测与上线建议-2026-10-22.md",
        "docs/压测报告-2026-10-22.md",
    ):
        head = "\n".join(_read(rel).splitlines()[:8])
        assert "历史快照，非当前交付基线" in head, f"未标注历史基线：{rel}"


def test_event_bus_and_log_comments_have_no_removed_service():
    assert "HTTP 服务" not in _read("core/event_bus.py")
    assert "不依赖 PyQt" not in _read("core/event_bus.py")
    assert "uvicorn 的日志" not in _read("gui/page_logs.py")
    # 注释不得再宣称「环境变量一键关联网」，代码里并没有读取点
    config = _read("core/config.py")
    assert "当前版本没有读取该环境变量" in config


# ── 版本号联动（漏改任何一处都会让客户拿到对不上的版本） ──


def test_version_sources_match_app_version():
    pyproject = re.search(r'^version\s*=\s*"([^"]+)"', _read("pyproject.toml"), re.M)
    assert pyproject is not None and pyproject.group(1) == APP_VERSION

    readme = re.search(r"\| 程序版本 \| v([\d.]+) \|", _read("README.md"))
    assert readme is not None and readme.group(1) == APP_VERSION

    selftest = re.search(r'APP_VERSION == "([\d.]+)"', _read("selftest.py"))
    assert selftest is not None and selftest.group(1) == APP_VERSION

    version_info = _read("version_info.txt")
    for key in ("FileVersion", "ProductVersion"):
        m = re.search(rf'StringStruct\("{key}", "([\d.]+)"\)', version_info)
        assert m is not None and m.group(1) == APP_VERSION
    parts = [*APP_VERSION.split("."), "0"]
    tuple_text = f"({', '.join(parts)})"
    assert f"filevers={tuple_text}" in version_info
    assert f"prodvers={tuple_text}" in version_info

    assert f"v{APP_VERSION} ·" in _doc("04_CHANGELOG.txt")


# ── 打包产物：交付材料是固定组成 ──


def _fake_src(root: Path) -> Path:
    src = root / "src"
    (src / "_internal" / "data").mkdir(parents=True)
    (src / "PortGuard.exe").write_bytes(b"FAKE_EXE")
    (src / "_internal" / "data" / "ip2region_v4.xdb").write_bytes(b"FAKE_XDB")
    return src


def test_pack_injects_delivery_materials(tmp_path: Path):
    src = _fake_src(tmp_path)
    out_dir = tmp_path / "out"
    assert pack_release.pack(str(src), APP_VERSION, str(out_dir)) == 0
    out = out_dir / f"PortGuard-v{APP_VERSION}.zip"

    required = {
        "PortGuard/PortGuard.exe",
        "PortGuard/NOTICE.txt",
        "PortGuard/VERSION.txt",
        "PortGuard/SHA256SUMS.txt",
        "PortGuard/00_README.txt",
        "PortGuard/01_DEPLOY.txt",
        "PortGuard/02_TERMS.txt",
        "PortGuard/03_INTEGRITY.txt",
        "PortGuard/04_CHANGELOG.txt",
        "PortGuard/start-as-admin.bat",
        "PortGuard/licenses/LICENSE-LGPL-3.0.txt",
        "PortGuard/licenses/LICENSE-GPL-3.0.txt",
        "PortGuard/licenses/LICENSE-Apache-2.0.txt",
    }
    with zipfile.ZipFile(out) as zf:
        names = zf.namelist()
        assert required <= set(names)
        assert all(n.startswith("PortGuard/") for n in names)
        assert not [n for n in names if n.endswith("/")]
        assert all(i.compress_type == zipfile.ZIP_DEFLATED for i in zf.infolist())

        # 中文客户文档用 UTF-8 BOM，许可全文保持上游原字节
        assert zf.read("PortGuard/NOTICE.txt").startswith(b"\xef\xbb\xbf")
        assert b"PySide2 5.15.2.1" in zf.read("PortGuard/NOTICE.txt")
        assert not zf.read("PortGuard/licenses/LICENSE-LGPL-3.0.txt").startswith(b"\xef\xbb\xbf")
        # 启动器必须保持 CRLF + 纯 ASCII + 无 BOM，否则中文系统会整行乱飞
        bat = zf.read("PortGuard/start-as-admin.bat")
        assert b"\r\n" in bat and bat.count(b"\r\n") == bat.count(b"\n")
        assert all(x < 128 for x in bat) and not bat.startswith(b"\xef\xbb\xbf")
        assert (
            zf.read("PortGuard/VERSION.txt").decode("utf-8-sig").strip()
            == f"PortGuard v{APP_VERSION}"
        )

        sums = zf.read("PortGuard/SHA256SUMS.txt").decode("utf-8-sig").splitlines()
        rows = [line.split("  ", 1) for line in sums if line and not line.startswith("#")]
        digests = {name: digest for digest, name in rows}
        assert set(digests) == set(names) - {"PortGuard/SHA256SUMS.txt"}
        for name, digest in digests.items():
            assert hashlib.sha256(zf.read(name)).hexdigest() == digest

    sha = (out_dir / (out.name + ".sha256")).read_text(encoding="utf-8").strip()
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    assert sha == f"{digest}  {out.name}"


def test_pack_refuses_when_delivery_materials_missing(tmp_path: Path, monkeypatch: Any):
    src = _fake_src(tmp_path)
    out_dir = tmp_path / "out_missing"
    monkeypatch.setattr(pack_release, "DELIVERY_DIR", str(tmp_path / "empty_dir"))
    assert pack_release.pack(str(src), APP_VERSION, str(out_dir)) == 3
    assert not (out_dir / f"PortGuard-v{APP_VERSION}.zip").exists()
