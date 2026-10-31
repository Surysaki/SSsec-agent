"""控件回收工具，确保重建布局时旧控件立即从界面消失。"""

from __future__ import annotations

from PySide6.QtWidgets import QWidget


def dispose_widget(widget: QWidget | None) -> None:
    if widget is None:
        return
    widget.hide()
    widget.setParent(None)
    widget.deleteLater()


__all__ = ["dispose_widget"]
