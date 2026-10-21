"""生成界面用的极小位图资源（可重复执行，输出稳定）。

目前只有一项：`assets/check.png` —— QSS 勾选框的白色对勾。

为什么必须有这个文件：QSS 里 `QCheckBox::indicator:checked` 一旦改背景色，Qt 就
不再画原生对勾，选中态只剩一个纯色方块 —— 在浅色主题下它和「禁用色块」几乎
无法区分。Qt 样式表不支持 SVG data URI，也不能在 QSS 里画折线，唯一稳的办法
是给 `image:` 一个真实图片路径（PySide2 / PySide6 都是这条规则）。

用法：envs\\portguard\\Scripts\\python.exe tools\\gen_ui_assets.py
"""

import os
import sys

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from qtcompat import QApplication, QColor, QPainter, QPen, QPixmap, QPointF, QPolygonF, Qt

#: 勾选框外框 15×15、描边 1px → 内空 13×13，图片按内空画满，
#: Qt 会把 image 居中画在 indicator 里，不需要额外留白。
CHECK_SIZE = 13


def make_check(path: str, size: int = CHECK_SIZE, color: str = "#FFFFFF") -> None:
    # 用 QPixmap 而不是 QImage：qtcompat 只导出前者，且 QPixmap 同样支持
    # ARGB 透明底与 PNG 输出，没必要为一个工具脚本扩兼容层。
    img = QPixmap(size, size)
    img.fill(Qt.GlobalColor.transparent)

    p = QPainter(img)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    # 笔画 2.0：13px 见方下 1.5px 会在 100% 缩放下糊成一条灰线
    pen = QPen(QColor(color))
    pen.setWidthF(2.0)
    pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.setBrush(Qt.BrushStyle.NoBrush)
    p.drawPolyline(
        QPolygonF(
            [
                QPointF(size * 0.20, size * 0.52),
                QPointF(size * 0.42, size * 0.74),
                QPointF(size * 0.82, size * 0.26),
            ]
        )
    )
    p.end()

    out = os.path.join(ROOT, path)
    if not img.save(out, "PNG"):
        raise SystemExit(f"写入失败：{out}")
    print("saved", out, f"{size}x{size}", os.path.getsize(out), "bytes")


def main() -> int:
    app = QApplication.instance()
    if not isinstance(app, QApplication):
        app = QApplication([])
    make_check(os.path.join("assets", "check.png"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
