"""聊天滚动区。"""

from __future__ import annotations

from PySide6.QtCore import QTimer, Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from sssec.models import Conversation
from sssec.ui.disposal import dispose_widget
from sssec.ui.message_widgets import (
    AssistantMessageWidget,
    EmptyState,
    UserMessageWidget,
)


class ChatView(QScrollArea):
    scope_requested = Signal()
    settings_requested = Signal()
    prompt_selected = Signal(str)

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("ChatScroll")
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self._conversation: Conversation | None = None
        self._demo_mode = False
        self._widgets: dict[str, QWidget] = {}
        self._column: QWidget | None = None
        self._column_layout: QVBoxLayout | None = None
        self._empty: EmptyState | None = None
        self._stick_to_bottom = True
        self._programmatic_scroll = False
        self.verticalScrollBar().valueChanged.connect(self._on_scrolled)
        self.verticalScrollBar().rangeChanged.connect(self._on_range_changed)
        # 合帧滚动：流式 delta 很密集时只保留一个 16ms 回调，避免每个
        # token 都排一次滚动/布局。
        self._scroll_timer = QTimer(self)
        self._scroll_timer.setSingleShot(True)
        self._scroll_timer.setInterval(16)
        self._scroll_timer.timeout.connect(self._scroll_to_bottom)

        host = QWidget()
        host.setObjectName("ChatCanvas")
        outer = QHBoxLayout(host)
        outer.setContentsMargins(32, 0, 32, 0)
        outer.setSpacing(0)
        outer.addStretch(1)
        self._column = QWidget()
        self._column.setObjectName("ChatColumn")
        self._column.setMaximumWidth(784)
        self._column.setMinimumWidth(320)
        self._column.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self._column_layout = QVBoxLayout(self._column)
        self._column_layout.setContentsMargins(0, 24, 0, 22)
        self._column_layout.setSpacing(22)
        self._column_layout.addStretch(1)
        outer.addWidget(self._column, 20)
        outer.addStretch(1)
        self.setWidget(host)

    # ------------------------------------------------------------------ public
    def set_conversation(
        self, conversation: Conversation | None, *, demo_mode: bool = False
    ) -> None:
        self._conversation = conversation
        self._demo_mode = demo_mode
        self._rebuild()

    def update_empty_state(self, demo_mode: bool | None = None) -> None:
        if demo_mode is not None:
            self._demo_mode = demo_mode
        if self._conversation and not self._conversation.messages:
            self._rebuild()

    def append_delta(self, message_id: str, kind: str, text: str) -> None:
        widget = self._widgets.get(message_id)
        if isinstance(widget, AssistantMessageWidget):
            stick = self._stick_to_bottom
            widget.append_delta(kind, text)
            if stick:
                self._request_scroll()

    def append_message(self, message: dict) -> QWidget | None:
        """只追加一条新消息，不重建已有历史。"""
        if self._empty is not None:
            self._clear()
            self._column_layout.addStretch(1)
        widget = self._create_message_widget(message)
        if widget is None:
            return None
        self._widgets[str(message.get("id"))] = widget
        count = self._column_layout.count()
        has_stretch = count > 0 and self._column_layout.itemAt(count - 1).spacerItem() is not None
        if not has_stretch:
            self._column_layout.addStretch(1)
        self._column_layout.insertWidget(self._column_layout.count() - 1, widget)
        if self._stick_to_bottom:
            self._request_scroll()
        return widget

    def refresh_message(self, message: dict) -> None:
        widget = self._widgets.get(str(message.get("id")))
        if isinstance(widget, AssistantMessageWidget):
            stick = self._stick_to_bottom
            widget.sync_from_data(message)
            if stick:
                self._request_scroll()

    def _request_scroll(self) -> None:
        if not self._scroll_timer.isActive():
            self._scroll_timer.start()

    def scroll_to_bottom(self, force: bool = True) -> None:
        if force:
            self._stick_to_bottom = True
        self._scroll_to_bottom()
        QTimer.singleShot(30, self._scroll_to_bottom)
        QTimer.singleShot(140, self._scroll_to_bottom)

    # ------------------------------------------------------------------ inner
    def _clear(self) -> None:
        assert self._column_layout is not None
        while self._column_layout.count():
            item = self._column_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                dispose_widget(widget)
        self._widgets.clear()
        self._empty = None

    def _rebuild(self) -> None:
        self._clear()
        assert self._column_layout is not None
        conversation = self._conversation
        if conversation is None or not conversation.messages:
            self._empty = EmptyState(conversation, self._demo_mode)
            self._empty.scope_requested.connect(self.scope_requested.emit)
            self._empty.settings_requested.connect(self.settings_requested.emit)
            self._empty.prompt_selected.connect(self.prompt_selected.emit)
            self._column_layout.addWidget(self._empty, 0, Qt.AlignHCenter)
            self._column_layout.addStretch(1)
            self.scroll_to_bottom(True)
            return

        for message in conversation.messages:
            widget = self._create_message_widget(message)
            if widget is None:
                continue
            self._widgets[str(message.get("id"))] = widget
            self._column_layout.addWidget(widget)
        self._column_layout.addStretch(1)
        self.scroll_to_bottom(True)

    def _create_message_widget(self, message: dict) -> QWidget | None:
        role = message.get("role")
        if role == "user":
            return UserMessageWidget(message)
        if role == "assistant":
            return AssistantMessageWidget(message)
        return None

    def _on_scrolled(self, value: int) -> None:
        if self._programmatic_scroll:
            return
        bar = self.verticalScrollBar()
        self._stick_to_bottom = bar.maximum() - value <= 90

    def _on_range_changed(self, minimum: int, maximum: int) -> None:
        if self._stick_to_bottom:
            QTimer.singleShot(0, self._auto_scroll_if_sticky)
            QTimer.singleShot(120, self._auto_scroll_if_sticky)

    def _auto_scroll_if_sticky(self) -> None:
        if self._stick_to_bottom:
            self._scroll_to_bottom()

    def _scroll_to_bottom(self) -> None:
        bar = self.verticalScrollBar()
        self._programmatic_scroll = True
        try:
            bar.setValue(bar.maximum())
        finally:
            self._programmatic_scroll = False

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        if self._stick_to_bottom:
            QTimer.singleShot(20, self._scroll_to_bottom)


__all__ = ["ChatView"]
