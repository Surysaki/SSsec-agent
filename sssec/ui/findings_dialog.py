"""测试发现列表。"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from sssec.models import SEVERITIES, Conversation, format_local_time
from sssec.ui.icons import icon
from sssec.ui.theme import COLORS
from sssec.ui.widgets import MarkdownView

SEVERITY_STYLE = {
    "critical": ("red_soft", "red", "red_border"),
    "high": ("amber_soft", "amber", "amber_border"),
    "medium": ("amber_soft", "amber", "amber_border"),
    "low": ("accent_soft", "accent_text", "accent_border"),
    "info": ("surface_2", "text_soft", "border"),
}


def _severity_colors(severity: str) -> tuple[str, str, str]:
    keys = SEVERITY_STYLE.get(severity, SEVERITY_STYLE["info"])
    return tuple(COLORS[key] for key in keys)  # type: ignore[return-value]


class FindingCard(QFrame):
    def __init__(self, finding: dict):
        super().__init__()
        self.setObjectName("Card")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 12, 14, 12)
        layout.setSpacing(6)
        top = QHBoxLayout()
        top.setSpacing(8)
        severity = str(finding.get("severity") or "info")
        bg, fg, border = _severity_colors(severity)
        badge = QLabel(SEVERITIES.get(severity, severity))
        badge.setAlignment(Qt.AlignCenter)
        badge.setStyleSheet(
            f"background: {bg}; color: {fg}; border: 1px solid {border};"
            "border-radius: 5px; padding: 2px 7px; font-size: 8pt; font-weight: 600;"
        )
        top.addWidget(badge)
        title = QLabel(str(finding.get("title") or "未命名发现"))
        title.setObjectName("CardTitle")
        title.setWordWrap(True)
        top.addWidget(title, 1)
        date = QLabel(format_local_time(str(finding.get("created_at") or "")))
        date.setObjectName("Faint")
        top.addWidget(date)
        layout.addLayout(top)
        if finding.get("target"):
            target = QLabel(f"目标 · {finding['target']}")
            target.setObjectName("Mono")
            target.setStyleSheet(
                f"color: {COLORS['muted']}; font-size: 8.5pt;"
            )
            target.setTextInteractionFlags(Qt.TextSelectableByMouse)
            layout.addWidget(target)
        description = str(finding.get("description") or "")
        if description:
            layout.addWidget(MarkdownView(description))
        evidence = str(finding.get("evidence") or "").strip()
        if evidence:
            caption = QLabel("证据")
            caption.setObjectName("SectionCaption")
            layout.addWidget(caption)
            evidence_label = QLabel(evidence)
            evidence_label.setWordWrap(True)
            evidence_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            evidence_label.setStyleSheet(
                f"background: {COLORS['code_bg']}; border: 1px solid {COLORS['code_border']};"
                f"border-radius: 7px; color: {COLORS['code_text']};"
                "font-family: 'Cascadia Code', Consolas, monospace;"
                "font-size: 8.5pt; padding: 8px;"
            )
            layout.addWidget(evidence_label)


class FindingsDialog(QDialog):
    def __init__(self, conversation: Conversation, parent: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle("测试发现 · SSsec")
        self.resize(760, 640)
        self.setMinimumSize(620, 480)
        self.setModal(True)

        root = QVBoxLayout(self)
        root.setContentsMargins(22, 20, 22, 16)
        root.setSpacing(12)
        header = QHBoxLayout()
        icon_label = QLabel()
        icon_label.setPixmap(icon("file", COLORS["accent"], 22).pixmap(22, 22))
        header.addWidget(icon_label)
        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)
        title = QLabel("测试发现")
        title.setObjectName("PageTitle")
        subtitle = QLabel(
            f"{conversation.title} · 共 {len(conversation.findings)} 条记录"
        )
        subtitle.setObjectName("PageSub")
        title_layout.addWidget(title)
        title_layout.addWidget(subtitle)
        header.addLayout(title_layout, 1)
        close_button = QPushButton("关闭")
        close_button.setObjectName("Secondary")
        close_button.clicked.connect(self.accept)
        header.addWidget(close_button, 0, Qt.AlignTop)
        root.addLayout(header)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        host = QWidget()
        list_layout = QVBoxLayout(host)
        list_layout.setContentsMargins(0, 4, 4, 4)
        list_layout.setSpacing(9)
        if not conversation.findings:
            empty = QLabel(
                "还没有测试发现。\n\n当 Agent 验证并记录问题后，发现会出现在这里。"
            )
            empty.setObjectName("PageSub")
            empty.setAlignment(Qt.AlignCenter)
            empty.setStyleSheet(
                f"color: {COLORS['muted']}; background: {COLORS['surface_2']};"
                f"border: 1px dashed {COLORS['border_strong']};"
                "border-radius: 10px; padding: 48px;"
            )
            list_layout.addWidget(empty)
        else:
            order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
            for finding in sorted(
                conversation.findings,
                key=lambda item: (
                    order.get(str(item.get("severity")), 5),
                    str(item.get("created_at") or ""),
                ),
            ):
                list_layout.addWidget(FindingCard(finding))
        list_layout.addStretch(1)
        scroll.setWidget(host)
        root.addWidget(scroll, 1)
        note = QLabel("发现记录保存在本地会话文件中，不会上传到第三方服务。")
        note.setObjectName("Faint")
        root.addWidget(note)
