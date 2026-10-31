"""编辑对话标题、测试目标范围与完全权限。"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from sssec.models import Conversation
from sssec.security.scope import split_scope_text
from sssec.ui.icons import icon
from sssec.ui.theme import COLORS
from sssec.ui.widgets import BrandMark


class ScopeDialog(QDialog):
    def __init__(self, conversation: Conversation, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("目标范围与执行权限 · SSsec")
        self.setModal(True)
        self.resize(640, 660)
        self.setMinimumSize(560, 580)
        self.conversation = conversation
        self._scope_entries: list[str] = []

        root = QVBoxLayout(self)
        root.setContentsMargins(24, 22, 24, 18)
        root.setSpacing(13)

        header = QHBoxLayout()
        header.setSpacing(12)
        header.addWidget(BrandMark(40), 0, Qt.AlignTop)
        header_text = QVBoxLayout()
        header_text.setSpacing(3)
        title = QLabel("设置测试目标与权限")
        title.setObjectName("PageTitle")
        subtitle = QLabel(
            "目标范围默认只作为提示与审计标记，不再阻断工具；需要时可在设置中开启严格拦截。"
        )
        subtitle.setObjectName("PageSub")
        subtitle.setWordWrap(True)
        header_text.addWidget(title)
        header_text.addWidget(subtitle)
        header.addLayout(header_text, 1)
        root.addLayout(header)
        root.addSpacing(2)

        title_label = QLabel("对话名称")
        title_label.setObjectName("FieldLabel")
        self.title_input = QLineEdit(conversation.title)
        self.title_input.setPlaceholderText("例如：example.com 外部资产测试")
        root.addWidget(title_label)
        root.addWidget(self.title_input)

        scope_label = QLabel("测试目标（可选）")
        scope_label.setObjectName("FieldLabel")
        root.addWidget(scope_label)
        self.scope_input = QPlainTextEdit()
        self.scope_input.setPlaceholderText(
            "每行一个目标，例如：\n"
            "example.com\n"
            "*.lab.example.com\n"
            "10.10.0.0/24\n"
            "https://demo.local:8443"
        )
        self.scope_input.setPlainText("\n".join(conversation.scope))
        self.scope_input.setFixedHeight(128)
        self.scope_input.textChanged.connect(self._update_preview)
        root.addWidget(self.scope_input)

        help_text = QLabel(
            "支持域名、通配子域名、IP、CIDR 与 URL；域名条目同时覆盖其子域名，"
            "URL 仅取主机名。留空表示不限制目标，Agent 仍可执行工具。"
        )
        help_text.setObjectName("HelpText")
        help_text.setWordWrap(True)
        root.addWidget(help_text)

        self.preview_frame = QFrame()
        self.preview_frame.setObjectName("Card")
        preview_layout = QHBoxLayout(self.preview_frame)
        preview_layout.setContentsMargins(12, 8, 12, 8)
        preview_layout.setSpacing(8)
        self.preview_icon = QLabel()
        preview_layout.addWidget(self.preview_icon, 0, Qt.AlignTop)
        self.preview_label = QLabel("")
        self.preview_label.setObjectName("HelpText")
        self.preview_label.setWordWrap(True)
        preview_layout.addWidget(self.preview_label, 1)
        root.addWidget(self.preview_frame)

        access_card = QFrame()
        access_card.setObjectName("Card")
        access_layout = QVBoxLayout(access_card)
        access_layout.setContentsMargins(13, 11, 13, 11)
        access_layout.setSpacing(6)
        access_title_row = QHBoxLayout()
        access_title_row.setSpacing(8)
        bolt = QLabel()
        bolt.setPixmap(icon("bolt", COLORS["red"], 17).pixmap(17, 17))
        access_title_row.addWidget(bolt, 0, Qt.AlignVCenter)
        access_title = QLabel("完全权限")
        access_title.setObjectName("CardTitle")
        access_title_row.addWidget(access_title)
        access_title_row.addStretch(1)
        access_layout.addLayout(access_title_row)
        self.full_checkbox = QCheckBox(
            "本对话启用完全权限：所有工具免确认，且不受目标范围限制"
        )
        self.full_checkbox.setChecked(bool(conversation.full_permission))
        self.full_checkbox.toggled.connect(self._update_preview)
        access_layout.addWidget(self.full_checkbox)
        self.access_warning = QLabel(
            "开启后，命令执行、写请求等操作会直接运行，界面不会弹出确认条。"
            "请只在受控环境或明确授权的测试中使用。"
        )
        self.access_warning.setWordWrap(True)
        self.access_warning.setStyleSheet(
            f"color: {COLORS['amber']}; font-size: 8.5pt;"
        )
        access_layout.addWidget(self.access_warning)
        root.addWidget(access_card)

        warning = QLabel(
            "SSsec 无法替代你的授权审查。目标范围是技术提示，不是法律授权；"
            "请妥善保存授权书、测试窗口与应急联系方式。"
        )
        warning.setObjectName("Faint")
        warning.setWordWrap(True)
        root.addWidget(warning)
        root.addStretch(1)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        cancel = QPushButton("取消")
        cancel.setObjectName("Secondary")
        cancel.clicked.connect(self.reject)
        save = QPushButton("保存")
        save.setObjectName("Primary")
        save.clicked.connect(self._save)
        buttons.addWidget(cancel)
        buttons.addWidget(save)
        root.addLayout(buttons)

        self._update_preview()

    def _update_preview(self) -> None:
        entries = split_scope_text(self.scope_input.toPlainText())
        self._scope_entries = entries
        full_access = self.full_checkbox.isChecked()
        if full_access:
            self.preview_label.setText(
                "完全权限已开启：工具调用不需要人工确认，也不会按目标范围拦截。"
            )
            self.preview_icon.setPixmap(
                icon("bolt", COLORS["red"], 17).pixmap(17, 17)
            )
            self.access_warning.setStyleSheet(
                f"color: {COLORS['red']}; font-size: 8.5pt;"
            )
        elif entries:
            shown = "、".join(f"`{item}`" for item in entries[:5])
            if len(entries) > 5:
                shown += f" 等 {len(entries)} 项"
            self.preview_label.setText(
                f"已记录 {len(entries)} 个目标：{shown}\n"
                "默认不拦截范围外目标；严格模式可在“设置 → Agent 与安全”中开启。"
            )
            self.preview_icon.setPixmap(
                icon("target", COLORS["accent"], 17).pixmap(17, 17)
            )
            self.access_warning.setStyleSheet(
                f"color: {COLORS['amber']}; font-size: 8.5pt;"
            )
        else:
            self.preview_label.setText(
                "未设置目标：Agent 仍可执行网络与命令工具，范围策略默认为“不限制”。"
            )
            self.preview_icon.setPixmap(
                icon("target", COLORS["faint"], 17).pixmap(17, 17)
            )
            self.access_warning.setStyleSheet(
                f"color: {COLORS['amber']}; font-size: 8.5pt;"
            )

    def _save(self) -> None:
        title = self.title_input.text().strip() or "新对话"
        entries = split_scope_text(self.scope_input.toPlainText())
        self.title_input.setText(title)
        self.scope_input.setPlainText("\n".join(entries))
        self.accept()

    @property
    def values(self) -> tuple[str, list[str], bool, bool]:
        title = self.title_input.text().strip() or "新对话"
        entries = split_scope_text(self.scope_input.toPlainText())
        authorized = bool(entries)
        return title, entries, authorized, bool(self.full_checkbox.isChecked())
