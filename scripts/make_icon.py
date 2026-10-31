"""生成应用图标（ICO）。"""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QRectF
from PySide6.QtGui import QImage, QPainter
from PySide6.QtWidgets import QApplication

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sssec.ui.icons import paint_brand  # noqa: E402


def main() -> None:
    app = QApplication.instance() or QApplication([])
    assets = ROOT / "sssec" / "assets"
    assets.mkdir(parents=True, exist_ok=True)
    for size in (256, 128, 64, 32):
        image = QImage(size, size, QImage.Format_ARGB32)
        image.fill(0)
        painter = QPainter(image)
        painter.setRenderHint(QPainter.Antialiasing)
        paint_brand(painter, QRectF(0, 0, size, size))
        painter.end()
        if size == 256:
            image.save(str(assets / "sssec.ico"), "ICO")
    print("图标已生成。")
    app.quit()


if __name__ == "__main__":
    main()
