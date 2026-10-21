"""设置页「自定义镜像源」下拉：多条地址的增删与落库。

这一块的设计取舍值得钉住：
  · 设置键从单条 `xdb_source` 换成 JSON 数组 `xdb_sources`，
    但**老库里那条单值必须能读出来**（不能一升级就丢用户配置）；
  · 下拉里全部条目都会保存，所以「选中哪一条」不改变结果 →
    不许点亮「未保存」（否则只是点着看看就以为改脏了）。
"""

import json
import os

from core import database
from core import settings as cfg
from core import xdb_updater as U


def _qapp():
    os.environ["QT_QPA_PLATFORM"] = "offscreen"
    from qtcompat import QApplication

    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication([])
    return app


def _db():
    """建库 + 预热设置缓存（必须早于任何 cfg.set，否则没有 settings 表）"""
    database.init_db()
    cfg.warm()


def _page():
    from gui import page_settings

    _qapp()  # 必须持有 QApplication，否则控件无法创建
    _db()
    return page_settings.SettingsPage()


def _preset(**kv):
    """先把设置写进库，再构造页面（模拟「用户上次填过」）"""
    _db()
    for k, v in kv.items():
        cfg.set(k, v)
    cfg.invalidate()


def _saved() -> list:
    raw = cfg.get("xdb_sources", "") or "[]"
    return json.loads(raw)


def test_load_lists_all_saved_sources():
    _preset(
        xdb_sources=json.dumps(["https://a.example.com/{path}"]),
        xdb_source="https://b.example.com/{path}",  # 1.1.0 遗留
    )
    page = _page()
    items = [page.cb_xdb_source.itemText(i) for i in range(page.cb_xdb_source.count())]
    assert items == ["https://a.example.com/{path}", "https://b.example.com/{path}"]


def test_save_writes_json_array_and_clears_legacy_key():
    _preset(xdb_source="https://old.example.com/{path}")
    page = _page()
    # 遗留值已在 load 时并入下拉，保存后应统一落到新键、老键清空
    page.save()
    assert _saved() == ["https://old.example.com/{path}"]
    assert (cfg.get("xdb_source", "") or "") == ""


def test_add_then_save_keeps_both():
    page = _page()
    page.cb_xdb_source.setEditText("https://a.example.com/{path}")
    page.btn_xdb_src_add.click()
    page.cb_xdb_source.setEditText("https://b.example.com/{path}")
    page.btn_xdb_src_add.click()
    page.save()
    assert _saved() == ["https://a.example.com/{path}", "https://b.example.com/{path}"]


def test_add_is_deduped():
    page = _page()
    page.cb_xdb_source.setEditText("https://a.example.com/{path}")
    page.btn_xdb_src_add.click()
    page.btn_xdb_src_add.click()
    assert page.cb_xdb_source.count() == 1


def test_delete_removes_only_the_selected_one():
    _preset(
        xdb_sources=json.dumps(["https://a.example.com/{path}", "https://b.example.com/{path}"])
    )
    page = _page()
    page.cb_xdb_source.setCurrentIndex(0)
    page.btn_xdb_src_del.click()
    page.save()
    assert _saved() == ["https://b.example.com/{path}"]


def test_typed_text_survives_save_without_clicking_add():
    """打了字直接点保存不该丢 —— 宽容一点比「静默丢弃」好"""
    page = _page()
    page.cb_xdb_source.setEditText("https://typed.example.com/{path}")
    page.save()
    assert _saved() == ["https://typed.example.com/{path}"]


def test_saved_count_is_capped():
    page = _page()
    for i in range(U.MAX_CUSTOM_SOURCES + 5):
        page.cb_xdb_source.setEditText(f"https://m{i}.example.com/{{path}}")
        page.btn_xdb_src_add.click()
    page.save()
    assert len(_saved()) == U.MAX_CUSTOM_SOURCES


def test_selecting_an_item_does_not_mark_dirty():
    """选中哪一条不影响保存结果，就不该点亮「未保存」"""
    _preset(
        xdb_sources=json.dumps(["https://a.example.com/{path}", "https://b.example.com/{path}"])
    )
    page = _page()
    assert page._dirty is False
    page.cb_xdb_source.setCurrentIndex(1)
    assert page._dirty is False


def test_typing_marks_dirty():
    """用户真的打字才算改动（走 textEdited；setCurrentIndex 那种不算）"""
    page = _page()
    le = page.cb_xdb_source.lineEdit()
    le.setText("https://typing.example.com/{path}")
    le.textEdited.emit(le.text())
    assert page._dirty is True


def test_add_and_delete_mark_dirty():
    page = _page()
    page.cb_xdb_source.setEditText("https://a.example.com/{path}")
    page.btn_xdb_src_add.click()
    page.save()
    assert page._dirty is False
    page.cb_xdb_source.setCurrentIndex(0)
    page.btn_xdb_src_del.click()
    assert page._dirty is True


def test_hint_reports_count_and_empty_state():
    page = _page()
    assert "内置源" in page.lbl_xdb_src.text()
    page.cb_xdb_source.setEditText("https://a.example.com/{path}")
    page.btn_xdb_src_add.click()
    assert "1 条" in page.lbl_xdb_src.text()
