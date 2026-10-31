"""可复用的 PySide6 基础组件。"""

from __future__ import annotations

import html
import math
import re
from typing import Callable

import markdown as markdown_lib
from PySide6.QtCore import QPoint, QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import (
    QColor,
    QCursor,
    QFont,
    QMouseEvent,
    QPainter,
    QTextDocument,
    QTextOption,
)
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTextBrowser,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from sssec.ui.icons import icon, paint_brand
from sssec.ui.theme import COLORS

_DANGEROUS_HTML = re.compile(
    r"<(script|style|iframe|object|embed|link|meta|img|form|input|video|audio)\b"
    r"[^>]*>.*?</\1\s*>|<(script|style|iframe|object|embed|link|meta|img|form|input|video|audio)\b[^>]*/?>",
    re.IGNORECASE | re.DOTALL,
)
_EVENT_ATTR = re.compile(r"\s+on[a-zA-Z]+\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I)

_MD_CSS_TEMPLATE = """
body {{ color: {text}; font-family: 'Microsoft YaHei UI', 'Segoe UI'; font-size: 10.5pt; line-height: 1.55; margin: 0; padding: 0; }}
p {{ margin: 0 0 9px 0; }}
h1, h2, h3, h4 {{ color: {heading}; margin: 14px 0 7px 0; font-weight: 700; }}
h1 {{ font-size: 15pt; }} h2 {{ font-size: 13pt; }} h3 {{ font-size: 11.5pt; }} h4 {{ font-size: 10.5pt; }}
a {{ color: {link}; text-decoration: none; }}
strong {{ color: {heading}; font-weight: 700; }}
em {{ color: {text_soft}; }}
ul, ol {{ margin: 5px 0 9px 0; -qt-list-indent: 1; }}
li {{ margin: 3px 0; }}
code {{ font-family: 'Cascadia Code', Consolas, monospace; background-color: {code_inline_bg}; color: {code_inline_text}; font-size: 9pt; }}
pre {{ font-family: 'Cascadia Code', Consolas, monospace; background-color: {code_bg}; color: {code_text}; border: 1px solid {code_border}; padding: 10px; font-size: 8.8pt; white-space: pre-wrap; }}
blockquote {{ color: {muted}; border-left: 3px solid {accent_border_hover}; margin: 8px 0; padding: 2px 0 2px 10px; background-color: {surface_2}; }}
hr {{ border: none; border-top: 1px solid {border}; margin: 12px 0; }}
table {{ border-collapse: collapse; margin: 8px 0; }}
th {{ background-color: {surface_3}; color: {heading}; border: 1px solid {border}; padding: 6px 8px; font-weight: 700; }}
td {{ border: 1px solid {border}; padding: 5px 8px; color: {text_soft}; }}
"""


def _markdown_css() -> str:
    return _MD_CSS_TEMPLATE.format(
        text=COLORS["text"],
        heading=COLORS["heading"],
        text_soft=COLORS["text_soft"],
        muted=COLORS["muted"],
        link=COLORS["blue"],
        code_bg=COLORS["code_bg"],
        code_border=COLORS["code_border"],
        code_text=COLORS["code_text"],
        code_inline_bg=COLORS["code_inline_bg"],
        code_inline_text=COLORS["code_inline_text"],
        surface_2=COLORS["surface_2"],
        surface_3=COLORS["surface_3"],
        accent_border_hover=COLORS["accent_border_hover"],
        border=COLORS["border"],
    )


def _sanitize_html(html_text: str) -> str:
    cleaned = _DANGEROUS_HTML.sub("", html_text)
    cleaned = _EVENT_ATTR.sub("", cleaned)
    return cleaned


def render_markdown(text: str) -> str:
    css = _markdown_css()
    if not text:
        return f"<html><head><style>{css}</style></head><body></body></html>"
    try:
        body = markdown_lib.markdown(
            text,
            extensions=["fenced_code", "tables", "sane_lists"],
            output_format="html5",
        )
    except Exception:
        body = f"<p>{html.escape(text).replace(chr(10), '<br>')}</p>"
    body = _sanitize_html(body)
    return (
        f"<html><head><meta charset='utf-8'><style>{css}</style></head>"
        f"<body>{body}</body></html>"
    )


class MarkdownView(QTextBrowser):
    """按内容自动调整高度、随外层滚动的 Markdown 阅读组件。"""

    def __init__(self, text: str = "", parent: QWidget | None = None):
        super().__init__(parent)
        self._source = ""
        self.setOpenExternalLinks(True)
        self.setFrameShape(QFrame.NoFrame)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setTextInteractionFlags(
            Qt.TextSelectableByMouse | Qt.LinksAccessibleByMouse
        )
        self.setFocusPolicy(Qt.StrongFocus)
        self.setWordWrapMode(QTextOption.WrapAtWordBoundaryOrAnywhere)
        self.document().setDocumentMargin(0)
        self.viewport().setAutoFillBackground(False)
        self.setAttribute(Qt.WA_TranslucentBackground, True)
        self.setStyleSheet("QTextBrowser { background: transparent; border: none; }")
        self._render_timer = QTimer(self)
        self._render_timer.setSingleShot(True)
        self._render_timer.setInterval(30)
        self._render_timer.timeout.connect(self._do_render)
        self.set_markdown(text)

    def set_markdown(self, text: str, debounce: bool = False) -> None:
        self._source = text
        if debounce:
            self._render_timer.start()
        else:
            self._do_render()

    def source(self) -> str:
        return self._source

    def _do_render(self) -> None:
        if self.toPlainText() != self._source:
            self.setHtml(render_markdown(self._source))
        self.document().setTextWidth(max(80, self.viewport().width()))
        self._adjust_height()

    def _adjust_height(self) -> None:
        doc = self.document()
        width = max(80, self.viewport().width())
        doc.setTextWidth(width)
        height = math.ceil(doc.size().height()) + 3
        self.setFixedHeight(max(18, min(height, 4000)))

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._adjust_height()

    def wheelEvent(self, event) -> None:  # noqa: N802
        # 让聊天区滚动而不是本组件内部滚动。
        event.ignore()

    def mousePressEvent(self, event) -> None:  # noqa: N802
        super().mousePressEvent(event)


class ElidedLabel(QLabel):
    def __init__(self, text: str = "", parent: QWidget | None = None):
        super().__init__(parent)
        self._full_text = text
        self.setText(text)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)

    def set_full_text(self, text: str) -> None:
        self._full_text = text
        self.setToolTip(text)
        self._apply_elide()

    def full_text(self) -> str:
        return self._full_text

    def _apply_elide(self) -> None:
        metrics = self.fontMetrics()
        available = max(80, self.width() - 4)
        super().setText(metrics.elidedText(self._full_text, Qt.ElideRight, available))

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._apply_elide()


class BrandMark(QWidget):
    def __init__(self, size: int = 36, parent: QWidget | None = None):
        super().__init__(parent)
        self._size = size
        self.setFixedSize(size, size)

    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(self._size, self._size)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        paint_brand(painter, QRectF(0, 0, self.width(), self.height()))
        painter.end()


class TypingDots(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._phase = 0
        self._timer = QTimer(self)
        self._timer.setInterval(360)
        self._timer.timeout.connect(self._tick)
        self.setFixedSize(34, 18)

    def start(self) -> None:
        self._phase = 0
        self._timer.start()
        self.update()

    def stop(self) -> None:
        self._timer.stop()
        self.update()

    def _tick(self) -> None:
        self._phase = (self._phase + 1) % 3
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        for index in range(3):
            alpha = 255 if index == self._phase else 85
            color = QColor(COLORS["accent"])
            color.setAlpha(alpha)
            painter.setBrush(color)
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(QRectF(5 + index * 9, 7, 4, 4))
        painter.end()


class Toast(QFrame):
    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setObjectName("Toast")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(13, 8, 13, 8)
        self._label = QLabel("")
        self._label.setWordWrap(True)
        layout.addWidget(self._label)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide)
        self.hide()

    def show_message(self, text: str, msec: int = 3600) -> None:
        self._label.setText(text)
        self.adjustSize()
        self.setFixedWidth(min(max(260, self.sizeHint().width()), 560))
        self._reposition()
        self.show()
        self.raise_()
        self._timer.start(msec)

    def _reposition(self) -> None:
        parent = self.parentWidget()
        if not parent:
            return
        # 显示在标题栏下方右侧，避免遮住底部的工具审批条与输入框。
        x = max(12, parent.width() - self.width() - 30)
        y = 88
        self.move(x, y)


class SuggestionCard(QFrame):
    clicked = Signal()

    def __init__(
        self,
        title: str,
        subtitle: str,
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.setObjectName("SuggestionCard")
        self.setCursor(QCursor(Qt.PointingHandCursor))
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 11, 12, 11)
        layout.setSpacing(10)
        text_layout = QVBoxLayout()
        text_layout.setSpacing(3)
        title_label = QLabel(title)
        title_label.setObjectName("SuggestionTitle")
        subtitle_label = QLabel(subtitle)
        subtitle_label.setObjectName("SuggestionSub")
        subtitle_label.setWordWrap(True)
        for label in (title_label, subtitle_label):
            label.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        text_layout.addWidget(title_label)
        text_layout.addWidget(subtitle_label)
        layout.addLayout(text_layout, 1)
        arrow = QLabel()
        arrow.setPixmap(icon("arrow_up_right", COLORS["faint"], 16).pixmap(16, 16))
        arrow.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        layout.addWidget(arrow, 0, Qt.AlignTop)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.LeftButton and self.rect().contains(event.position().toPoint()):
            self.clicked.emit()
        super().mouseReleaseEvent(event)


def icon_button(
    icon_name: str,
    tooltip: str,
    *,
    color: str | None = None,
    size: int = 18,
    icon_size: int = 18,
    object_name: str = "IconButton",
) -> QToolButton:
    button = QToolButton()
    button.setObjectName(object_name)
    button.setIcon(icon(icon_name, color or COLORS["icon"], icon_size))
    button.setIconSize(QSize(icon_size, icon_size))
    button.setToolTip(tooltip)
    button.setCursor(QCursor(Qt.PointingHandCursor))
    button.setFixedSize(size + 14, size + 14)
    return button


def text_button(
    text: str,
    *,
    object_name: str = "Secondary",
    icon_name: str | None = None,
    color: str | None = None,
) -> QPushButton:
    button = QPushButton(text)
    button.setObjectName(object_name)
    button.setCursor(QCursor(Qt.PointingHandCursor))
    if icon_name:
        button.setIcon(icon(icon_name, color or COLORS["text_soft"], 16))
        button.setIconSize(QSize(16, 16))
    return button


def divider() -> QFrame:
    line = QFrame()
    line.setObjectName("Divider")
    line.setFrameShape(QFrame.HLine)
    return line


def set_dynamic_property(widget: QWidget, name: str, value) -> None:
    widget.setProperty(name, value)
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    widget.update()


def apply_mono_font(widget: QWidget, size: int = 9) -> None:
    font = QFont("Cascadia Code", size)
    font.setStyleHint(QFont.Monospace)
    widget.setFont(font)


class ClickFrame(QFrame):
    clicked = Signal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setCursor(QCursor(Qt.PointingHandCursor))

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.LeftButton and self.rect().contains(event.position().toPoint()):
            self.clicked.emit()
        super().mouseReleaseEvent(event)


__all__ = [
    "BrandMark",
    "ClickFrame",
    "ElidedLabel",
    "MarkdownView",
    "SuggestionCard",
    "Toast",
    "TypingDots",
    "apply_mono_font",
    "divider",
    "icon_button",
    "render_markdown",
    "set_dynamic_property",
    "text_button",
]
