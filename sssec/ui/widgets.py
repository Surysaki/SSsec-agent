"""可复用的 PySide6 基础组件（Linear 风格）。"""

from __future__ import annotations

import html
import math
import re

import markdown as markdown_lib
from PySide6.QtCore import QRectF, QSize, Qt, QTimer, Signal
from PySide6.QtGui import (
    QColor,
    QCursor,
    QFont,
    QGuiApplication,
    QMouseEvent,
    QPainter,
    QPixmap,
    QTextCharFormat,
    QTextCursor,
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
from sssec.ui.theme import COLORS, mono_font_family, ui_font_family

_DANGEROUS_HTML = re.compile(
    r"<(script|style|iframe|object|embed|link|meta|img|form|input|video|audio)\b"
    r"[^>]*>.*?</\1\s*>|<(script|style|iframe|object|embed|link|meta|img|form|input|video|audio)\b[^>]*/?>",
    re.IGNORECASE | re.DOTALL,
)
_EVENT_ATTR = re.compile(r"\s+on[a-zA-Z]+\s*=\s*(?:\"[^\"]*\"|'[^']*'|[^\s>]+)", re.I)
_TASK_OPEN = re.compile(r"^(\s*[-*+]\s+)\[ \]\s+", re.MULTILINE)
_TASK_DONE = re.compile(r"^(\s*[-*+]\s+)\[[xX]\]\s+", re.MULTILINE)

_MD_CSS_TEMPLATE = """
body {{
    color: {text};
    font-family: {font_ui};
    font-size: 9.8pt;
    line-height: 1.62;
    margin: 0;
    padding: 0;
}}
p {{ margin: 0 0 10px 0; }}
h1, h2, h3, h4 {{
    color: {heading};
    margin: 16px 0 8px 0;
    font-weight: 600;
    line-height: 1.3;
}}
h1 {{ font-size: 14pt; }} h2 {{ font-size: 12pt; }} h3 {{ font-size: 10.5pt; }} h4 {{ font-size: 9.8pt; }}
a {{ color: {link}; text-decoration: none; }}
strong {{ color: {heading}; font-weight: 600; }}
em {{ color: {text_soft}; }}
ul, ol {{ margin: 5px 0 10px 0; -qt-list-indent: 1; }}
li {{ margin: 3px 0; }}
code {{
    font-family: {font_mono};
    background-color: {code_inline_bg};
    color: {code_inline_text};
    font-size: 8.6pt;
}}
pre {{
    font-family: {font_mono};
    background-color: {code_bg};
    color: {code_text};
    border: 1px solid {code_border};
    padding: 10px;
    font-size: 8.4pt;
    white-space: pre-wrap;
}}
blockquote {{
    color: {muted};
    border-left: 2px solid {accent_border_hover};
    margin: 10px 0;
    padding: 2px 0 2px 11px;
    background-color: transparent;
}}
hr {{ border: none; color: {border}; background-color: {border}; height: 1px; margin: 14px 0; }}
table {{ border-collapse: collapse; margin: 8px 0; }}
th {{
    background-color: {surface_2};
    color: {heading};
    border: 1px solid {border};
    padding: 6px 9px;
    font-weight: 600;
}}
td {{ border: 1px solid {border}; padding: 5px 9px; color: {text_soft}; }}
"""


def _markdown_css() -> str:
    return _MD_CSS_TEMPLATE.format(
        font_ui=f"'{ui_font_family()}', 'Microsoft YaHei', sans-serif",
        font_mono=f"'{mono_font_family()}', 'Microsoft YaHei', monospace",
        text=COLORS["text"],
        heading=COLORS["heading"],
        text_soft=COLORS["text_soft"],
        muted=COLORS["muted"],
        link=COLORS["accent_text"],
        code_bg=COLORS["code_bg"],
        code_border=COLORS["code_border"],
        code_text=COLORS["code_text"],
        code_inline_bg=COLORS["code_inline_bg"],
        code_inline_text=COLORS["code_inline_text"],
        surface_2=COLORS["surface_2"],
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
    # Python-Markdown 没有任务列表扩展；把 GFM 的 "[ ] / [x]" 换成方框字符，
    # 让技能卡里的检查表在界面里读起来更自然。
    text = _TASK_OPEN.sub(r"\1☐ ", text)
    text = _TASK_DONE.sub(r"\1☑ ", text)
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
        # 流式阶段先按纯文本增量插入，避免每个 token 都重排整段 Markdown；
        # 一段回答结束后再一次性渲染 Markdown 格式。
        self._streaming = False
        self._rendered_source: str | None = None
        self._stream_format = QTextCharFormat()
        self._stream_estimated_lines = 0.0
        self._stream_height = 90
        self.set_markdown(text)

    def set_markdown(self, text: str, debounce: bool = False) -> None:
        self._streaming = False
        self._source = text
        if debounce:
            self._render_timer.start()
        else:
            self._do_render()

    def source(self) -> str:
        return self._source

    def is_streaming(self) -> bool:
        return self._streaming

    def begin_stream(self, text: str = "") -> None:
        """进入流式模式：清空文档，之后只做纯文本增量插入。"""
        self._render_timer.stop()
        self._streaming = True
        self._source = ""
        self._rendered_source = None
        self._stream_estimated_lines = 0.0
        self._stream_height = 90
        self.setFixedHeight(self._stream_height)
        self.clear()
        self.document().setDocumentMargin(0)
        font = QFont(ui_font_family())
        font.setPointSizeF(9.8)
        self._stream_format = QTextCharFormat()
        self._stream_format.setFont(font)
        self._stream_format.setForeground(QColor(COLORS["text"]))
        if text:
            self._append_stream_raw(text)

    def set_stream_text(self, text: str) -> None:
        if not self._streaming or not text.startswith(self._source):
            self.begin_stream()
            delta = text
        else:
            delta = text[len(self._source):]
        if delta:
            self._append_stream_raw(delta)

    def append_stream_text(self, text: str) -> None:
        if not text:
            return
        if not self._streaming:
            self.begin_stream()
        self._append_stream_raw(text)

    def _append_stream_raw(self, text: str) -> None:
        self._source += text
        cursor = self.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(text, self._stream_format)
        self.setTextCursor(cursor)
        # 流式阶段把可视高度限制在 520px 内：文本继续在内部滚动，
        # 避免每个 token 都把 4000px 高的 QTextBrowser 重新布局/重绘。
        # 未到上限时用真实文档高度，避免短回答下方出现大片空白；
        # 到达上限后不再调用 document().size()，只做增量插入和滚动。
        self.document().setTextWidth(max(80, self.viewport().width()))
        if self._stream_height < 520:
            target_height = int(
                min(520, max(90, math.ceil(self.document().size().height()) + 6))
            )
            if abs(target_height - self._stream_height) >= 6:
                self._stream_height = target_height
                self.setFixedHeight(target_height)
        self.ensureCursorVisible()

    def finish_stream(self) -> None:
        """一段回答结束，切换到完整 Markdown 渲染。"""
        if not self._streaming:
            return
        self._streaming = False
        self.set_markdown(self._source, debounce=False)

    def _do_render(self) -> None:
        if self._rendered_source != self._source:
            self.setHtml(render_markdown(self._source))
            self._rendered_source = self._source
        self.document().setTextWidth(max(80, self.viewport().width()))
        self._adjust_height()

    def _adjust_height(self) -> None:
        doc = self.document()
        width = max(80, self.viewport().width())
        doc.setTextWidth(width)
        if self._streaming:
            if self._stream_height < 520:
                target_height = int(
                    min(520, max(90, math.ceil(doc.size().height()) + 6))
                )
                if abs(target_height - self._stream_height) >= 6:
                    self._stream_height = target_height
                    self.setFixedHeight(target_height)
            self.ensureCursorVisible()
            return
        height = math.ceil(doc.size().height()) + 3
        self.setFixedHeight(max(18, min(height, 4000)))

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._adjust_height()

    def wheelEvent(self, event) -> None:  # noqa: N802
        # 让聊天区滚动而不是本组件内部滚动。
        event.ignore()


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


def dot_pixmap(color: str, size: int = 8, ring: str | None = None) -> QPixmap:
    """生成状态圆点：Linear 用它替代大面积色块徽标。"""
    scale = 2
    pixmap = QPixmap(size * scale + (2 if ring else 0), size * scale + (2 if ring else 0))
    pixmap.fill(Qt.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    painter.setPen(Qt.NoPen)
    if ring:
        painter.setBrush(QColor(ring))
        painter.drawEllipse(0, 0, pixmap.width(), pixmap.height())
        offset = scale
        inner = pixmap.width() - offset * 2
    else:
        inner = pixmap.width()
        offset = 0
    painter.setBrush(QColor(color))
    painter.drawEllipse(offset, offset, inner, inner)
    painter.end()
    pixmap.setDevicePixelRatio(float(scale))
    return pixmap


def status_dot(color: str, size: int = 8, ring: str | None = None) -> QLabel:
    label = QLabel()
    label.setFixedSize(size + (2 if ring else 0), size + (2 if ring else 0))
    label.setPixmap(dot_pixmap(color, size, ring))
    label.setAttribute(Qt.WA_TransparentForMouseEvents, True)
    return label


# 语义色调：每组返回“浅底 / 前景 / 边框”三个主题色键。
TONE_KEYS: dict[str, tuple[str, str, str]] = {
    "accent": ("accent_soft", "accent", "accent_border"),
    "cyan": ("cyan_soft", "cyan", "cyan_border"),
    "violet": ("violet_soft", "violet", "violet_border"),
    "green": ("green_soft", "green", "green_border"),
    "amber": ("amber_soft", "amber", "amber_border"),
    "blue": ("blue_soft", "blue", "blue_border"),
    "red": ("red_soft", "red", "red_border"),
}


def tone_colors(tone: str) -> tuple[str, str, str]:
    keys = TONE_KEYS.get(tone, TONE_KEYS["accent"])
    return tuple(COLORS[key] for key in keys)  # type: ignore[return-value]


def tone_badge(
    icon_name: str,
    tone: str = "accent",
    *,
    size: int = 28,
    icon_size: int = 15,
) -> QLabel:
    """彩色圆角图标徽标：用于建议卡、设置页标题与工具卡片。"""
    background, foreground, border = tone_colors(tone)
    badge = QLabel()
    badge.setFixedSize(size, size)
    badge.setAlignment(Qt.AlignCenter)
    badge.setPixmap(icon(icon_name, foreground, icon_size).pixmap(icon_size, icon_size))
    badge.setStyleSheet(
        f"background: {background}; border: 1px solid {border};"
        f"border-radius: {max(5, size // 4)}px;"
    )
    badge.setAttribute(Qt.WA_TransparentForMouseEvents, True)
    return badge


class CopyButton(QToolButton):
    """带点击反馈的复制按钮：复制成功显示绿色对勾，空内容给出提示。"""

    def __init__(
        self,
        text: str = "",
        *,
        tooltip: str = "复制",
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        self.setObjectName("Ghost")
        self.setCursor(QCursor(Qt.PointingHandCursor))
        self.setFixedSize(24, 24)
        self._text = text
        self._provider = None
        self._default_tooltip = tooltip
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self._restore)
        self._restore()
        self.clicked.connect(self._copy)

    def set_text(self, text: str) -> None:
        self._text = text or ""

    def set_provider(self, provider) -> None:
        self._provider = provider

    def _payload(self) -> str:
        if self._provider is not None:
            try:
                return str(self._provider() or "")
            except Exception:
                return ""
        return self._text

    def _copy(self) -> None:
        text = self._payload().strip()
        if not text:
            self._flash("暂无可复制内容", "info", COLORS["amber"])
            return
        QGuiApplication.clipboard().setText(text)
        self._flash("已复制", "check", COLORS["green"])

    def _flash(self, tooltip: str, icon_name: str, color: str) -> None:
        self._timer.stop()
        self.setIcon(icon(icon_name, color, 13))
        self.setToolTip(tooltip)
        self._timer.start(1400)

    def _restore(self) -> None:
        self.setIcon(icon("copy", COLORS["muted"], 13))
        self.setToolTip(self._default_tooltip)


class PageHeader(QWidget):
    """设置页标题：彩色图标徽标 + 标题 + 一句说明。"""

    def __init__(
        self,
        icon_name: str,
        title: str,
        subtitle: str = "",
        *,
        tone: str = "accent",
        parent: QWidget | None = None,
    ):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(11)
        layout.addWidget(tone_badge(icon_name, tone, size=32, icon_size=16), 0, Qt.AlignTop)
        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)
        title_label = QLabel(title)
        title_label.setObjectName("SettingsSection")
        text_layout.addWidget(title_label)
        if subtitle:
            subtitle_label = QLabel(subtitle)
            subtitle_label.setObjectName("PageSub")
            subtitle_label.setWordWrap(True)
            text_layout.addWidget(subtitle_label)
        layout.addLayout(text_layout, 1)


def letter_spacing(widget: QWidget, spacing: float = 0.5) -> QWidget:
    font = widget.font()
    font.setLetterSpacing(QFont.AbsoluteSpacing, spacing)
    widget.setFont(font)
    return widget


def caption_label(text: str, *, spacing: float = 0.6) -> QLabel:
    """小号大写分组标题，模拟 Linear 的 sidebar 分组节奏。"""
    label = QLabel(text)
    label.setObjectName("SectionCaption")
    font = label.font()
    font.setLetterSpacing(QFont.AbsoluteSpacing, spacing)
    label.setFont(font)
    return label


def kbd_label(text: str) -> QLabel:
    label = QLabel(text)
    label.setObjectName("KbdHint")
    label.setAlignment(Qt.AlignCenter)
    label.setAttribute(Qt.WA_TransparentForMouseEvents, True)
    return label


def meta_dot() -> QLabel:
    label = QLabel("·")
    label.setObjectName("MetaDot")
    label.setAttribute(Qt.WA_TransparentForMouseEvents, True)
    return label


class TypingDots(QWidget):
    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self._phase = 0
        self._timer = QTimer(self)
        self._timer.setInterval(380)
        self._timer.timeout.connect(self._tick)
        self.setFixedSize(26, 14)

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
            alpha = 230 if index == self._phase else 70
            color = QColor(COLORS["muted"])
            color.setAlpha(alpha)
            painter.setBrush(color)
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(QRectF(3 + index * 7, 5, 3.4, 3.4))
        painter.end()


class Toast(QFrame):
    def __init__(self, parent: QWidget):
        super().__init__(parent)
        self.setObjectName("Toast")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 9, 12, 9)
        layout.setSpacing(8)
        self._dot = status_dot(COLORS["accent"], 6)
        layout.addWidget(self._dot, 0, Qt.AlignVCenter)
        self._label = QLabel("")
        self._label.setWordWrap(True)
        layout.addWidget(self._label, 1)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide)
        self.hide()

    def show_message(self, text: str, msec: int = 3600) -> None:
        self._label.setText(text)
        self.adjustSize()
        self.setFixedWidth(min(max(260, self.sizeHint().width()), 520))
        self._reposition()
        self.show()
        self.raise_()
        self._timer.start(msec)

    def _reposition(self) -> None:
        parent = self.parentWidget()
        if not parent:
            return
        # 显示在标题栏下方右侧，避免遮住底部的工具审批条与输入框。
        x = max(12, parent.width() - self.width() - 28)
        y = 68
        self.move(x, y)


class SuggestionCard(QFrame):
    clicked = Signal()

    def __init__(
        self,
        title: str,
        subtitle: str,
        parent: QWidget | None = None,
        icon_name: str = "arrow_right",
        tone: str = "accent",
    ):
        super().__init__(parent)
        self.setObjectName("SuggestionCard")
        self.setCursor(QCursor(Qt.PointingHandCursor))
        layout = QHBoxLayout(self)
        layout.setContentsMargins(11, 9, 11, 9)
        layout.setSpacing(10)

        layout.addWidget(
            tone_badge(icon_name, tone, size=28, icon_size=15), 0, Qt.AlignVCenter
        )

        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)
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
        arrow.setPixmap(icon("arrow_right", COLORS["faint"], 14).pixmap(14, 14))
        arrow.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        layout.addWidget(arrow, 0, Qt.AlignVCenter)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.LeftButton and self.rect().contains(event.position().toPoint()):
            self.clicked.emit()
        super().mouseReleaseEvent(event)


def icon_button(
    icon_name: str,
    tooltip: str,
    *,
    color: str | None = None,
    size: int = 26,
    icon_size: int = 16,
    object_name: str = "IconButton",
) -> QToolButton:
    button = QToolButton()
    button.setObjectName(object_name)
    button.setIcon(icon(icon_name, color or COLORS["icon"], icon_size))
    button.setIconSize(QSize(icon_size, icon_size))
    button.setToolTip(tooltip)
    button.setCursor(QCursor(Qt.PointingHandCursor))
    button.setFixedSize(size, size)
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
        button.setIcon(icon(icon_name, color or COLORS["text_soft"], 15))
        button.setIconSize(QSize(15, 15))
    return button


def divider() -> QFrame:
    line = QFrame()
    line.setObjectName("Divider")
    line.setFrameShape(QFrame.HLine)
    line.setFixedHeight(1)
    return line


def vertical_rule(height: int = 16) -> QFrame:
    line = QFrame()
    line.setObjectName("VerticalRule")
    line.setFixedSize(1, height)
    return line


def set_dynamic_property(widget: QWidget, name: str, value) -> None:
    widget.setProperty(name, value)
    style = widget.style()
    style.unpolish(widget)
    style.polish(widget)
    widget.update()


def apply_mono_font(widget: QWidget, size: int = 9) -> None:
    font = QFont(mono_font_family(), size)
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
    "CopyButton",
    "ElidedLabel",
    "MarkdownView",
    "PageHeader",
    "SuggestionCard",
    "TONE_KEYS",
    "Toast",
    "TypingDots",
    "apply_mono_font",
    "caption_label",
    "divider",
    "dot_pixmap",
    "icon_button",
    "kbd_label",
    "letter_spacing",
    "meta_dot",
    "render_markdown",
    "set_dynamic_property",
    "status_dot",
    "text_button",
    "tone_badge",
    "tone_colors",
    "ui_font_family",
    "vertical_rule",
]
