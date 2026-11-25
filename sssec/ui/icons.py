"""内联 SVG 图标与品牌标识，避免运行时依赖图标主题。

品牌标识使用项目提供的“狼头盾牌”LOGO（``assets/logo_mark.png``）：
黑色盾牌 + 白色狼头，并在透明背景上增加了细微的浅色描边，确保在
浅色与深色主题、Windows 浅色与深色任务栏中都能保持轮廓。
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from PySide6.QtCore import QByteArray, QRectF, Qt
from PySide6.QtGui import (
    QColor,
    QIcon,
    QImage,
    QLinearGradient,
    QPainter,
    QPainterPath,
    QPen,
    QPixmap,
)
from PySide6.QtSvg import QSvgRenderer

from sssec.ui.theme import COLORS

_ASSETS = Path(__file__).resolve().parent.parent / "assets"

_PATHS: dict[str, str] = {
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "chat": '<path d="M21 15a2 2 0 0 1-2 2H8l-5 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>',
    "settings": (
        '<path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3"/>'
        '<path d="M1 14h6M9 8h6M17 16h6"/>'
    ),
    "trash": (
        '<path d="M3 6h18M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2"/>'
        '<path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>'
        '<path d="M10 11v6M14 11v6"/>'
    ),
    "edit": (
        '<path d="M12 20h9"/>'
        '<path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/>'
    ),
    "shield": (
        '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
        '<path d="M9 12l2 2 4-4"/>'
    ),
    "shield_plain": '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
    "target": (
        '<circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3"/>'
        '<path d="M12 2v3M12 19v3M2 12h3M19 12h3"/>'
    ),
    "send": '<path d="M12 19V5M5 12l7-7 7 7"/>',
    "stop": '<rect x="6" y="6" width="12" height="12" rx="2" fill="currentColor" stroke="none"/>',
    "more": '<circle cx="5" cy="12" r="1.5" fill="currentColor"/><circle cx="12" cy="12" r="1.5" fill="currentColor"/><circle cx="19" cy="12" r="1.5" fill="currentColor"/>',
    "x": '<path d="M18 6L6 18M6 6l12 12"/>',
    "check": '<path d="M20 6L9 17l-5-5"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/>',
    "chevron_down": '<path d="M6 9l6 6 6-6"/>',
    "chevron_right": '<path d="M9 18l6-6-6-6"/>',
    "chevron_up": '<path d="M18 15l-6-6-6 6"/>',
    "terminal": '<path d="M4 17l6-5-6-5"/><path d="M12 19h8"/>',
    "folder": (
        '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>'
    ),
    "file": '<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6"/><path d="M8 13h8M8 17h5"/>',
    "alert": '<path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4M12 17h.01"/>',
    "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/>',
    "key": '<circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3L21 2M17 6l3 3M14 9l3 3"/>',
    "copy": '<rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
    "refresh": '<path d="M21 2v6h-6"/><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M3 22v-6h6"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/>',
    "user": '<circle cx="12" cy="8" r="4"/><path d="M4 21a8 8 0 0 1 16 0"/>',
    "spark": '<path d="M12 2l1.8 6.2L20 10l-6.2 1.8L12 18l-1.8-6.2L4 10l6.2-1.8z"/>',
    "lock": '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/>',
    "unlock": '<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 7.5-2"/>',
    "book": '<path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/>',
    "external": '<path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6M10 14L21 3"/>',
    "arrow_up_right": '<path d="M7 17L17 7M7 7h10v10"/>',
    "sun": (
        '<circle cx="12" cy="12" r="4"/>'
        '<path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4'
        'M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>'
    ),
    "moon": '<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>',
    "bolt": '<path d="M13 2L4 14h7l-1 8 9-12h-7z"/>',
    # ---- Linear 风格补充图标 ----
    "command": (
        '<path d="M18 3a3 3 0 0 0-3 3v12a3 3 0 1 0 3-3H6a3 3 0 1 0 3 3V6a3 3 0 1 0-3 3h12a3 3 0 0 0 0-6z"/>'
    ),
    "panel_left": (
        '<rect x="3" y="3" width="18" height="18" rx="3"/>'
        '<path d="M9.5 3v18"/>'
    ),
    "layers": (
        '<path d="M12 2l9 5-9 5-9-5 9-5z"/>'
        '<path d="M3 12l9 5 9-5"/>'
        '<path d="M3 17l9 5 9-5"/>'
    ),
    "inbox": (
        '<path d="M3 13h4l2 3h6l2-3h4"/>'
        '<path d="M5 5h14l2 8v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4z"/>'
    ),
    "message": (
        '<path d="M21 12a8 8 0 0 1-8 8H8l-5 3 1.5-4.5A8 8 0 1 1 21 12z"/>'
    ),
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "filter": '<path d="M3 5h18l-7 8v6l-4 2v-8z"/>',
    "download": (
        '<path d="M12 3v12"/><path d="M7 10l5 5 5-5"/>'
        '<path d="M4 19h16"/>'
    ),
    "upload": (
        '<path d="M12 21V9"/><path d="M7 14l5-5 5 5"/>'
        '<path d="M4 5h16"/>'
    ),
    "plus_square": (
        '<rect x="3" y="3" width="18" height="18" rx="3"/>'
        '<path d="M12 8v8M8 12h8"/>'
    ),
    "arrow_right": '<path d="M4 12h16"/><path d="M14 6l6 6-6 6"/>',
    "sliders": (
        '<path d="M4 6h9M17 6h3M4 12h3M11 12h9M4 18h11M19 18h1"/>'
        '<circle cx="15" cy="6" r="2"/><circle cx="9" cy="12" r="2"/>'
        '<circle cx="17" cy="18" r="2"/>'
    ),
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
    "play": '<path d="M7 4l13 8-13 8z"/>',
    "link": (
        '<path d="M10 13a5 5 0 0 0 7 0l2-2a5 5 0 0 0-7-7l-1 1"/>'
        '<path d="M14 11a5 5 0 0 0-7 0l-2 2a5 5 0 0 0 7 7l1-1"/>'
    ),
    "book_open": (
        '<path d="M12 6.5C10.5 5 8.5 4 5 4v15c3.5 0 5.5 1 7 2.5 1.5-1.5 3.5-2.5 7-2.5V4c-3.5 0-5.5 1-7 2.5z"/>'
        '<path d="M12 6.5v15"/>'
    ),
    "grid": (
        '<rect x="3" y="3" width="7" height="7" rx="1.5"/>'
        '<rect x="14" y="3" width="7" height="7" rx="1.5"/>'
        '<rect x="3" y="14" width="7" height="7" rx="1.5"/>'
        '<rect x="14" y="14" width="7" height="7" rx="1.5"/>'
    ),
}

_SVG_TEMPLATE = (
    '<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" '
    'viewBox="0 0 24 24" fill="none" stroke="{color}" stroke-width="{width}" '
    'stroke-linecap="round" stroke-linejoin="round">{paths}</svg>'
)


def icon(
    name: str,
    color: str | None = None,
    size: int = 20,
    width: float = 1.5,
) -> QIcon:
    """渲染一个内联 SVG 图标。

    这里刻意不缓存 ``QIcon``：QIcon 依赖 QGuiApplication，模块级缓存可能
    在进程退出时晚于 Qt 应用对象析构，导致 Windows 上的退出崩溃。图标本身
    很小，按需渲染的成本可以接受；品牌 LOGO 使用 QImage 缓存，不受影响。
    """
    paths = _PATHS.get(name)
    if paths is None:
        return QIcon()
    resolved = color or COLORS.get("icon", "#788ca0")
    if 'fill="currentColor"' in paths:
        paths = paths.replace("currentColor", resolved)
    svg = _SVG_TEMPLATE.format(color=resolved, width=width, paths=paths)
    renderer = QSvgRenderer(QByteArray(svg.encode("utf-8")))
    pixmap = QPixmap(size * 2, size * 2)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    renderer.render(painter)
    painter.end()
    pixmap.setDevicePixelRatio(2.0)
    return QIcon(pixmap)


@lru_cache(maxsize=1)
def _brand_mark_image() -> QImage:
    """加载品牌 LOGO：设计源图裁剪、透明描边后的 1024×1024 PNG。

    缓存 ``QImage`` 而不是 ``QPixmap``：QImage 不依赖 QGuiApplication，
    可以安全地存活到进程退出，避免 Qt 关闭顺序导致的析构崩溃。
    """
    path = _ASSETS / "logo_mark.png"
    if not path.exists():
        return QImage()
    return QImage(str(path))


def _paint_fallback_brand(painter: QPainter, box: QRectF) -> None:
    """LOGO 资源缺失时的降级盾牌，避免窗口图标变成空白。"""
    size = box.width()
    shield = QPainterPath()
    shield.moveTo(box.center().x(), box.top() + size * 0.05)
    shield.cubicTo(
        box.left() + size * 0.22,
        box.top() + size * 0.14,
        box.left() + size * 0.12,
        box.top() + size * 0.18,
        box.left() + size * 0.12,
        box.top() + size * 0.46,
    )
    shield.cubicTo(
        box.left() + size * 0.12,
        box.top() + size * 0.74,
        box.center().x(),
        box.bottom() - size * 0.02,
        box.center().x(),
        box.bottom() - size * 0.02,
    )
    shield.cubicTo(
        box.center().x(),
        box.bottom() - size * 0.02,
        box.right() - size * 0.12,
        box.top() + size * 0.74,
        box.right() - size * 0.12,
        box.top() + size * 0.46,
    )
    shield.cubicTo(
        box.right() - size * 0.12,
        box.top() + size * 0.18,
        box.right() - size * 0.22,
        box.top() + size * 0.14,
        box.center().x(),
        box.top() + size * 0.05,
    )
    shield.closeSubpath()
    gradient = QLinearGradient(box.topLeft(), box.bottomRight())
    gradient.setColorAt(0.0, QColor("#0b1118"))
    gradient.setColorAt(1.0, QColor("#122430"))
    painter.setPen(
        QPen(QColor("#f7fffd"), max(1.0, size * 0.04), Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin)
    )
    painter.setBrush(gradient)
    painter.drawPath(shield)


def paint_brand(painter: QPainter, rect: QRectF) -> None:
    """绘制 SSsec 品牌图标：狼头盾牌 LOGO。

    LOGO 本身是 1024×1024 的透明 PNG，内部保留约 10% 留白并带有细微
    浅色描边；这里直接等比缩放到目标矩形，16px 任务栏图标也能保持轮廓。
    """
    painter.save()
    painter.setRenderHint(QPainter.Antialiasing, True)
    painter.setRenderHint(QPainter.SmoothPixmapTransform, True)
    size = min(rect.width(), rect.height())
    if size <= 0:
        painter.restore()
        return
    box = QRectF(
        rect.center().x() - size / 2,
        rect.center().y() - size / 2,
        size,
        size,
    )
    mark = _brand_mark_image()
    if not mark.isNull():
        painter.drawImage(box, mark)
    else:
        _paint_fallback_brand(painter, box)
    painter.restore()


def brand_pixmap(size: int = 36) -> QPixmap:
    pixmap = QPixmap(size, size)
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    paint_brand(painter, QRectF(0, 0, size, size))
    painter.end()
    return pixmap


def app_icon() -> QIcon:
    icon_obj = QIcon()
    for size in (16, 20, 24, 32, 48, 64, 128, 256):
        pixmap = QPixmap(size, size)
        pixmap.fill(Qt.transparent)
        painter = QPainter(pixmap)
        paint_brand(painter, QRectF(0, 0, size, size))
        painter.end()
        icon_obj.addPixmap(pixmap)
    return icon_obj


__all__ = ["app_icon", "brand_pixmap", "icon", "paint_brand"]
