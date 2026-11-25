"""测试发现列表（Linear 风格）。"""

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
from sssec.ui.theme import COLORS, mono_font_family
from sssec.ui.widgets import MarkdownView, caption_label, status_dot

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
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(5)
        top = QHBoxLayout()
        top.setSpacing(7)
        severity = str(finding.get("severity") or "info")
        bg, fg, border = _severity_colors(severity)
        top.addWidget(status_dot(fg, 6), 0, Qt.AlignVCenter)
        badge = QLabel(SEVERITIES.get(severity, severity))
        badge.setAlignment(Qt.AlignCenter)
        badge.setStyleSheet(
            f"background: {bg}; color: {fg}; border: 1px solid {border};"
            "border-radius: 4px; padding: 1px 6px; font-size: 7.5pt; font-weight: 600;"
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
            target.setStyleSheet(f"color: {COLORS['muted']}; font-size: 8.2pt;")
            target.setTextInteractionFlags(Qt.TextSelectableByMouse)
            layout.addWidget(target)
        description = str(finding.get("description") or "")
        if description:
            layout.addWidget(MarkdownView(description))
        evidence = str(finding.get("evidence") or "").strip()
        if evidence:
            layout.addWidget(caption_label("证据"))
            evidence_label = QLabel(evidence)
            evidence_label.setWordWrap(True)
            evidence_label.setTextInteractionFlags(Qt.TextSelectableByMouse)
            evidence_label.setStyleSheet(
                f"background: {COLORS['code_bg']}; border: 1px solid {COLORS['code_border']};"
                f"border-radius: 6px; color: {COLORS['code_text']};"
                f"font-family: {mono_font_family()};"
                "font-size: 8.2pt; padding: 7px;"
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
        root.setContentsMargins(24, 20, 24, 14)
        root.setSpacing(10)

        header = QHBoxLayout()
        header.setSpacing(10)
        badge = QLabel()
        badge.setFixedSize(30, 30)
        badge.setAlignment(Qt.AlignCenter)
        badge.setPixmap(icon("file", COLORS["accent"], 16).pixmap(16, 16))
        badge.setStyleSheet(
            f"background: {COLORS['accent_soft']};"
            f"border: 1px solid {COLORS['accent_border']};"
            "border-radius: 7px;"
        )
        header.addWidget(badge, 0, Qt.AlignTop)
        title_layout = QVBoxLayout()
        title_layout.setSpacing(1)
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
        scroll.setObjectName("SettingsScroll")
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        host = QWidget()
        list_layout = QVBoxLayout(host)
        list_layout.setContentsMargins(0, 2, 4, 4)
        list_layout.setSpacing(8)
        if not conversation.findings:
            empty = QLabel(
                "还没有测试发现。\n\n当 Agent 验证并记录问题后，发现会出现在这里。"
            )
            empty.setObjectName("PageSub")
            empty.setAlignment(Qt.AlignCenter)
            empty.setStyleSheet(
                f"color: {COLORS['muted']}; background: transparent;"
                f"border: 1px dashed {COLORS['border_strong']};"
                "border-radius: 8px; padding: 48px;"
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


__all__ = ["FindingsDialog"]
