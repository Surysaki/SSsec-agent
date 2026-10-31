"""底部多行输入框、发送/停止控制与模型/范围状态。"""

from __future__ import annotations

import math

from PySide6.QtCore import QEvent, QSize, Qt, Signal
from PySide6.QtGui import QCursor, QKeyEvent, QTextCursor
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from sssec.ui.icons import icon
from sssec.ui.theme import COLORS
from sssec.ui.widgets import set_dynamic_property


class ChatInput(QPlainTextEdit):
    submit = Signal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("ChatInput")
        self.setPlaceholderText("描述你的测试目标，或询问一个安全问题…")
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setFixedHeight(46)
        self.setTabChangesFocus(True)
        self.textChanged.connect(self._resize)

    def keyPressEvent(self, event: QKeyEvent) -> None:  # noqa: N802
        if event.key() in (Qt.Key_Return, Qt.Key_Enter):
            if event.modifiers() & Qt.ShiftModifier:
                super().keyPressEvent(event)
                return
            self.submit.emit()
            event.accept()
            return
        super().keyPressEvent(event)

    def _resize(self) -> None:
        document = self.document()
        document.setTextWidth(max(120, self.viewport().width()))
        height = math.ceil(document.size().height()) + 16
        self.setFixedHeight(max(46, min(height, 156)))

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._resize()


class Composer(QFrame):
    send_requested = Signal(str)
    stop_requested = Signal()
    scope_requested = Signal()
    settings_requested = Signal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("ComposerArea")
        self._running = False
        self._awaiting = False
        self._busy_elsewhere = False
        self._model_label = ""
        self._scope_text = "未设置目标（不限制）"
        self._scope_ok = False
        self._demo = False
        self._full_access = False

        outer = QVBoxLayout(self)
        outer.setContentsMargins(26, 12, 26, 14)
        outer.setSpacing(0)
        self.card = QFrame()
        self.card.setObjectName("ComposerCard")
        self.card.setMaximumWidth(920)
        outer.addWidget(self.card, 0, Qt.AlignHCenter)
        card_layout = QVBoxLayout(self.card)
        card_layout.setContentsMargins(13, 9, 10, 8)
        card_layout.setSpacing(5)

        self.input = ChatInput()
        self.input.submit.connect(self._submit)
        self.input.installEventFilter(self)
        card_layout.addWidget(self.input)

        bottom = QHBoxLayout()
        bottom.setSpacing(7)
        self.model_label = QLabel("离线演示")
        self.model_label.setObjectName("Faint")
        self.model_label.setToolTip("当前模型服务")
        bottom.addWidget(self.model_label)
        bottom.addSpacing(2)
        self.scope_button = QPushButton("未设置目标（可选）")
        self.scope_button.setObjectName("Chip")
        self.scope_button.setIcon(icon("target", COLORS["muted"], 13))
        self.scope_button.setIconSize(QSize(13, 13))
        self.scope_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.scope_button.setToolTip("设置测试目标提示与范围策略")
        self.scope_button.clicked.connect(self.scope_requested.emit)
        bottom.addWidget(self.scope_button)
        self.access_badge = QLabel("完全权限")
        self.access_badge.setStyleSheet(
            f"color: {COLORS['red']}; background: {COLORS['red_soft']};"
            f"border: 1px solid {COLORS['red_border']}; border-radius: 8px;"
            "padding: 3px 7px; font-size: 8pt; font-weight: 700;"
        )
        self.access_badge.setToolTip("本对话已启用完全权限：工具免确认、范围不拦截")
        self.access_badge.setVisible(False)
        bottom.addWidget(self.access_badge)
        bottom.addStretch(1)

        self.hint = QLabel("Enter 发送 · Shift+Enter 换行")
        self.hint.setObjectName("Faint")
        bottom.addWidget(self.hint)
        bottom.addSpacing(4)

        self.send_button = QPushButton()
        self.send_button.setObjectName("SendButton")
        self.send_button.setFixedSize(36, 36)
        self.send_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.send_button.setToolTip("发送（Enter）")
        self.send_button.clicked.connect(self._on_action)
        self._set_send_icon()
        bottom.addWidget(self.send_button)
        card_layout.addLayout(bottom)

        self.input.textChanged.connect(self._update_send_enabled)

    # ------------------------------------------------------------------ public
    def text(self) -> str:
        return self.input.toPlainText().strip()

    def clear(self) -> None:
        self.input.clear()
        self.input.setFocus()

    def set_text(self, text: str) -> None:
        self.input.setPlainText(text)
        cursor = self.input.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.input.setTextCursor(cursor)
        self.input.setFocus()

    def focus_input(self) -> None:
        self.input.setFocus()

    def set_running(self, running: bool) -> None:
        self._running = running
        if running:
            self._awaiting = False
        self._refresh_controls()

    def set_awaiting_approval(self, awaiting: bool) -> None:
        self._awaiting = awaiting
        self._refresh_controls()

    def set_busy_elsewhere(self, busy: bool) -> None:
        self._busy_elsewhere = busy
        self._refresh_controls()

    def set_context(
        self,
        *,
        model_label: str,
        scope_text: str,
        scope_ok: bool,
        demo: bool,
        full_access: bool = False,
    ) -> None:
        self._model_label = model_label
        self._scope_text = scope_text
        self._scope_ok = scope_ok
        self._demo = demo
        self._full_access = bool(full_access)
        metrics = self.model_label.fontMetrics()
        display_model = model_label
        self.model_label.setText(metrics.elidedText(display_model, Qt.ElideRight, 260))
        self.model_label.setToolTip(model_label + ("（离线演示）" if demo else ""))
        self.scope_button.setText(metrics.elidedText(scope_text, Qt.ElideRight, 210))
        self.scope_button.setToolTip(
            f"测试目标提示：{scope_text}\n点击设置目标与范围策略。"
        )
        set_dynamic_property(self.scope_button, "ok", "true" if scope_ok else "false")
        set_dynamic_property(self.scope_button, "warn", "false")
        self.scope_button.setIcon(
            icon("target", COLORS["accent_text"] if scope_ok else COLORS["muted"], 13)
        )
        self.access_badge.setVisible(self._full_access)
        self._refresh_controls()

    # ------------------------------------------------------------------ inner
    def eventFilter(self, obj, event) -> bool:  # noqa: N802
        if obj is self.input:
            if event.type() == QEvent.FocusIn:
                set_dynamic_property(self.card, "focused", "true")
            elif event.type() == QEvent.FocusOut:
                set_dynamic_property(self.card, "focused", "false")
        return super().eventFilter(obj, event)

    def _on_action(self) -> None:
        if self._running:
            self.stop_requested.emit()
        else:
            self._submit()

    def _submit(self) -> None:
        if self._running or self._awaiting or self._busy_elsewhere:
            return
        text = self.text()
        if not text:
            return
        self.send_requested.emit(text)

    def _set_send_icon(self) -> None:
        color = COLORS["on_accent"]
        if self._running:
            self.send_button.setIcon(icon("stop", color, 17, width=0))
            self.send_button.setToolTip("停止生成")
        else:
            self.send_button.setIcon(icon("send", color, 18))
            self.send_button.setToolTip("发送（Enter）")

    def _update_send_enabled(self) -> None:
        self._refresh_controls()

    def _refresh_controls(self) -> None:
        if self._running:
            self.send_button.setEnabled(True)
            self.send_button.setObjectName("StopButton")
            self.hint.setText("等待上方工具授权…" if self._awaiting else "正在生成…")
            self.input.setPlaceholderText(
                "请先处理上方授权" if self._awaiting else "可以继续输入，发送需等待本轮完成"
            )
            self.send_button.setIcon(icon("stop", COLORS["red"], 16, width=0))
            self.send_button.setToolTip("停止生成")
        else:
            self.send_button.setObjectName("SendButton")
            self._set_send_icon()
            enabled = bool(self.text()) and not self._awaiting and not self._busy_elsewhere
            self.send_button.setEnabled(enabled)
            if self._awaiting:
                self.hint.setText("请先处理上方工具授权")
                self.input.setPlaceholderText("等待工具授权…")
            elif self._busy_elsewhere:
                self.hint.setText("另一会话正在生成")
                self.input.setPlaceholderText("等待当前任务完成…")
            else:
                self.hint.setText("Enter 发送 · Shift+Enter 换行")
                self.input.setPlaceholderText("描述你的测试目标，或询问一个安全问题…")
        style = self.send_button.style()
        style.unpolish(self.send_button)
        style.polish(self.send_button)
        self.send_button.update()


__all__ = ["Composer"]
