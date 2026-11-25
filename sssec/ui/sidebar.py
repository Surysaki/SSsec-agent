"""左侧工作区栏：品牌、会话列表与模型入口（Linear 风格）。"""

from __future__ import annotations

from datetime import datetime
from typing import Iterable

from PySide6.QtCore import QSize, Qt, Signal
from PySide6.QtGui import QAction, QCursor, QMouseEvent
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMenu,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from sssec import __version__
from sssec.models import Conversation, relative_time
from sssec.ui.disposal import dispose_widget
from sssec.ui.icons import icon
from sssec.ui.theme import COLORS, is_dark
from sssec.ui.widgets import (
    BrandMark,
    ClickFrame,
    caption_label,
    set_dynamic_property,
    status_dot,
)


class ConversationRow(QFrame):
    clicked = Signal(str)
    rename_requested = Signal(str)
    delete_requested = Signal(str)

    def __init__(self, conversation: Conversation, *, selected: bool, running: bool):
        super().__init__()
        self.conversation_id = conversation.id
        self.setObjectName("ConversationRow")
        self.setCursor(QCursor(Qt.PointingHandCursor))
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setFixedHeight(44)

        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Linear 的选中态只用 2px 强调条 + 极浅底色，不用整块高亮。
        self.indicator = QFrame()
        self.indicator.setFixedSize(2, 16)
        self.indicator.setStyleSheet(
            f"background: {COLORS['accent']}; border-radius: 1px;"
        )
        self.indicator.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        outer.addWidget(self.indicator, 0, Qt.AlignVCenter)

        layout = QVBoxLayout()
        layout.setContentsMargins(8, 6, 8, 6)
        layout.setSpacing(1)
        outer.addLayout(layout, 1)

        top = QHBoxLayout()
        top.setSpacing(6)
        self.title_label = QLabel()
        self.title_label.setObjectName("ConvoTitle")
        self.title_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        title = conversation.title or "新对话"
        metrics = self.title_label.fontMetrics()
        self.title_label.setText(metrics.elidedText(title, Qt.ElideRight, 150))
        self.title_label.setToolTip(title)
        top.addWidget(self.title_label, 1)

        if running:
            running_label = status_dot(COLORS["accent"], 6)
            running_label.setToolTip("正在生成")
            top.addWidget(running_label, 0, Qt.AlignVCenter)
        self.time_label = QLabel(relative_time(conversation.updated_at))
        self.time_label.setObjectName("ConvoTime")
        top.addWidget(self.time_label, 0, Qt.AlignTop)
        layout.addLayout(top)

        preview = QLabel(conversation.preview())
        preview.setObjectName("ConvoPreview")
        preview.setWordWrap(False)
        metrics = preview.fontMetrics()
        preview.setText(metrics.elidedText(conversation.preview(), Qt.ElideRight, 178))
        layout.addWidget(preview)
        self.set_selected(selected)

    def set_selected(self, selected: bool) -> None:
        set_dynamic_property(self, "selected", "true" if selected else "false")
        set_dynamic_property(
            self.title_label, "selected", "true" if selected else "false"
        )
        self.indicator.setVisible(selected)

    def mouseReleaseEvent(self, event: QMouseEvent) -> None:  # noqa: N802
        if event.button() == Qt.LeftButton:
            self.clicked.emit(self.conversation_id)
        super().mouseReleaseEvent(event)

    def contextMenuEvent(self, event) -> None:  # noqa: N802
        menu = QMenu(self)
        rename = QAction(icon("edit", COLORS["text_soft"], 15), "重命名", menu)
        delete = QAction(icon("trash", COLORS["red"], 15), "删除对话", menu)
        rename.triggered.connect(lambda: self.rename_requested.emit(self.conversation_id))
        delete.triggered.connect(lambda: self.delete_requested.emit(self.conversation_id))
        menu.addAction(rename)
        menu.addSeparator()
        menu.addAction(delete)
        menu.exec(event.globalPos())


class ModelCard(ClickFrame):
    def __init__(self):
        super().__init__()
        self.setObjectName("ModelCard")
        self.setFixedHeight(46)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 6, 7, 6)
        layout.setSpacing(8)
        self.status = status_dot(COLORS["accent"], 6)
        layout.addWidget(self.status, 0, Qt.AlignVCenter)
        text_layout = QVBoxLayout()
        text_layout.setSpacing(1)
        self.name_label = QLabel("模型服务")
        self.name_label.setObjectName("ModelName")
        self.name_label.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.meta_label = QLabel("未配置")
        self.meta_label.setObjectName("ModelMeta")
        self.meta_label.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        text_layout.addWidget(self.name_label)
        text_layout.addWidget(self.meta_label)
        layout.addLayout(text_layout, 1)
        chevron = QLabel()
        chevron.setPixmap(
            icon("chevron_right", COLORS["faint"], 13).pixmap(13, 13)
        )
        chevron.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        layout.addWidget(chevron)

    def set_model(self, name: str, meta: str) -> None:
        metrics = self.name_label.fontMetrics()
        self.name_label.setText(metrics.elidedText(name, Qt.ElideRight, 176))
        self.meta_label.setText(metrics.elidedText(meta, Qt.ElideRight, 188))
        self.setToolTip(f"{name}\n{meta}\n点击配置模型服务")


class Sidebar(QWidget):
    new_conversation_requested = Signal()
    conversation_selected = Signal(str)
    settings_requested = Signal()
    theme_toggle_requested = Signal()
    rename_requested = Signal(str)
    delete_requested = Signal(str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("Sidebar")
        self.setFixedWidth(264)
        self._conversations: list[Conversation] = []
        self._current_id: str | None = None
        self._running_id: str | None = None
        self._query = ""

        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 10)
        root.setSpacing(0)

        brand_row = QHBoxLayout()
        brand_row.setContentsMargins(2, 0, 2, 0)
        brand_row.setSpacing(8)
        brand_row.addWidget(BrandMark(24), 0, Qt.AlignVCenter)
        name = QLabel("SSsec")
        name.setObjectName("BrandName")
        brand_row.addWidget(name, 0, Qt.AlignVCenter)
        brand_row.addStretch(1)
        root.addLayout(brand_row)
        root.addSpacing(12)

        self.new_button = QPushButton("新建对话")
        self.new_button.setObjectName("NewChat")
        self.new_button.setIcon(icon("plus", COLORS["text_soft"], 15))
        self.new_button.setIconSize(QSize(15, 15))
        self.new_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.new_button.setFixedHeight(30)
        self.new_button.clicked.connect(self.new_conversation_requested.emit)
        root.addWidget(self.new_button)
        root.addSpacing(8)

        self.search = QLineEdit()
        self.search.setObjectName("SearchInput")
        self.search.setPlaceholderText("搜索对话…")
        self.search.setClearButtonEnabled(True)
        self.search.addAction(
            icon("search", COLORS["faint"], 14), QLineEdit.LeadingPosition
        )
        self.search.textChanged.connect(self._on_search)
        self.search.setFixedHeight(30)
        root.addWidget(self.search)
        root.addSpacing(14)

        header = QHBoxLayout()
        header.setContentsMargins(4, 0, 4, 0)
        header.setSpacing(6)
        self.section_label = caption_label("对话")
        header.addWidget(self.section_label)
        self.count_label = QLabel("")
        self.count_label.setObjectName("SectionCount")
        header.addWidget(self.count_label)
        header.addStretch(1)
        self.search_hint = QLabel("Ctrl K")
        self.search_hint.setObjectName("KbdHint")
        self.search_hint.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        header.addWidget(self.search_hint)
        root.addLayout(header)
        root.addSpacing(4)

        self.scroll = QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll.setFrameShape(QFrame.NoFrame)
        self.scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.list_host = QWidget()
        self.list_layout = QVBoxLayout(self.list_host)
        self.list_layout.setContentsMargins(0, 0, 2, 8)
        self.list_layout.setSpacing(1)
        self.list_layout.addStretch(1)
        self.scroll.setWidget(self.list_host)
        root.addWidget(self.scroll, 1)

        footer = QFrame()
        footer.setObjectName("SidebarFooter")
        footer_layout = QVBoxLayout(footer)
        footer_layout.setContentsMargins(0, 8, 0, 0)
        footer_layout.setSpacing(2)
        self.model_card = ModelCard()
        self.model_card.clicked.connect(self.settings_requested.emit)
        footer_layout.addWidget(self.model_card)

        bottom_row = QHBoxLayout()
        bottom_row.setContentsMargins(5, 2, 0, 0)
        bottom_row.setSpacing(2)
        self.authorized_hint = QLabel(f"v{__version__} · 仅限授权测试")
        self.authorized_hint.setObjectName("Faint")
        bottom_row.addWidget(self.authorized_hint)
        bottom_row.addStretch(1)
        self.theme_button = QToolButton()
        self.theme_button.setObjectName("IconButton")
        self.theme_button.setIcon(
            icon("moon" if not is_dark() else "sun", COLORS["muted"], 14)
        )
        self.theme_button.setIconSize(QSize(14, 14))
        self.theme_button.setFixedSize(26, 26)
        self.theme_button.setToolTip("切换浅色 / 深色主题")
        self.theme_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.theme_button.clicked.connect(self.theme_toggle_requested.emit)
        bottom_row.addWidget(self.theme_button)
        self.settings_button = QToolButton()
        self.settings_button.setObjectName("IconButton")
        self.settings_button.setIcon(icon("settings", COLORS["muted"], 14))
        self.settings_button.setIconSize(QSize(14, 14))
        self.settings_button.setFixedSize(26, 26)
        self.settings_button.setToolTip("设置与模型服务（Ctrl+,）")
        self.settings_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.settings_button.clicked.connect(self.settings_requested.emit)
        bottom_row.addWidget(self.settings_button)
        footer_layout.addLayout(bottom_row)
        root.addWidget(footer)

    # ------------------------------------------------------------------ public
    def set_model(self, name: str, meta: str) -> None:
        self.model_card.set_model(name, meta)

    def set_conversations(
        self,
        conversations: Iterable[Conversation],
        current_id: str | None,
        running_id: str | None = None,
    ) -> None:
        self._conversations = list(conversations)
        self._current_id = current_id
        self._running_id = running_id
        self._rebuild()

    def select(self, conversation_id: str) -> None:
        self._current_id = conversation_id
        for index in range(self.list_layout.count()):
            widget = self.list_layout.itemAt(index).widget()
            if isinstance(widget, ConversationRow):
                widget.set_selected(widget.conversation_id == conversation_id)

    def focus_search(self) -> None:
        self.search.setFocus()
        self.search.selectAll()

    # ------------------------------------------------------------------ inner
    def _on_search(self, text: str) -> None:
        self._query = text.strip().lower()
        self._rebuild()

    def _matches(self, conversation: Conversation) -> bool:
        if not self._query:
            return True
        haystack = " ".join(
            [
                conversation.title,
                conversation.preview(),
                " ".join(conversation.scope),
            ]
        ).lower()
        return self._query in haystack

    def _rebuild(self) -> None:
        while self.list_layout.count():
            item = self.list_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                dispose_widget(widget)

        filtered = [c for c in self._conversations if self._matches(c)]
        self.count_label.setText(str(len(filtered)) if filtered else "")
        if not filtered:
            empty = QLabel(
                "没有匹配的对话" if self._query else "还没有对话，点击上方新建。"
            )
            empty.setObjectName("Faint")
            empty.setWordWrap(True)
            empty.setContentsMargins(6, 12, 6, 12)
            self.list_layout.addWidget(empty)
            self.list_layout.addStretch(1)
            return

        today = datetime.now().astimezone().date()
        groups: list[tuple[str, list[Conversation]]] = []
        bucket_today: list[Conversation] = []
        bucket_yesterday: list[Conversation] = []
        bucket_earlier: list[Conversation] = []
        for conversation in filtered:
            try:
                date = datetime.fromisoformat(conversation.updated_at).date()
            except Exception:
                date = today
            delta = (today - date).days
            if delta <= 0:
                bucket_today.append(conversation)
            elif delta == 1:
                bucket_yesterday.append(conversation)
            else:
                bucket_earlier.append(conversation)
        if bucket_today:
            groups.append(("今天", bucket_today))
        if bucket_yesterday:
            groups.append(("昨天", bucket_yesterday))
        if bucket_earlier:
            groups.append(("更早", bucket_earlier))

        for group_name, items in groups:
            caption = caption_label(group_name)
            caption.setContentsMargins(8, 10, 4, 3)
            self.list_layout.addWidget(caption)
            for conversation in items:
                row = ConversationRow(
                    conversation,
                    selected=conversation.id == self._current_id,
                    running=conversation.id == self._running_id,
                )
                row.clicked.connect(self.conversation_selected.emit)
                row.rename_requested.connect(self.rename_requested.emit)
                row.delete_requested.connect(self.delete_requested.emit)
                self.list_layout.addWidget(row)
        self.list_layout.addStretch(1)


__all__ = ["Sidebar"]
