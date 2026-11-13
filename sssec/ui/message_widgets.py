"""聊天消息、工具调用卡片、审批条与欢迎空状态。"""

from __future__ import annotations

import json
from typing import Any

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtGui import QCursor, QGuiApplication
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from sssec.models import SEVERITIES, assistant_text, format_local_time
from sssec.security.scope import scope_summary
from sssec.ui.disposal import dispose_widget
from sssec.ui.icons import icon
from sssec.ui.theme import COLORS
from sssec.ui.widgets import (
    BrandMark,
    MarkdownView,
    SuggestionCard,
    TypingDots,
    apply_mono_font,
    set_dynamic_property,
)

TOOL_LABELS = {
    "http_request": "HTTP 请求",
    "http_probe": "HTTP 指纹",
    "http_raw": "原始 HTTP",
    "http_upload": "文件上传",
    "dns_lookup": "DNS 查询",
    "dns_zone_transfer": "DNS 区域传送",
    "tcp_probe": "TCP 探测",
    "tcp_exchange": "TCP 交互",
    "port_scan": "端口扫描",
    "subdomain_enum": "子域枚举",
    "dir_scan": "目录发现",
    "web_crawl": "页面爬取",
    "run_command": "命令执行",
    "save_finding": "记录发现",
    "whois_lookup": "WHOIS 查询",
    "tls_certificate": "TLS 证书",
    "security_headers": "安全响应头",
    "param_fuzz": "参数探测",
    "cors_check": "CORS 检查",
    "jwt_analyze": "JWT 分析",
    "waf_detect": "WAF 识别",
    "webshell_client": "Webshell",
    "codec": "编解码",
    "payload_forge": "Payload 生成",
    "binary_info": "二进制分析",
    "crypto_workshop": "Crypto 分析",
    "file_analyze": "文件分析",
    "archive_extract": "解压",
    "artifact_scan": "源码/秘密扫描",
    "flag_hunt": "Flag 提取",
    "workspace_list": "目录浏览",
    "workspace_read": "读取文件",
    "workspace_write": "写入文件",
    "handoff": "交接阶段",
}
TOOL_ICONS = {
    "http_request": "globe",
    "http_probe": "globe",
    "http_raw": "terminal",
    "http_upload": "arrow_up_right",
    "dns_lookup": "search",
    "dns_zone_transfer": "search",
    "tcp_probe": "shield_plain",
    "tcp_exchange": "terminal",
    "port_scan": "shield_plain",
    "subdomain_enum": "search",
    "dir_scan": "folder",
    "web_crawl": "globe",
    "run_command": "terminal",
    "save_finding": "file",
    "whois_lookup": "book",
    "tls_certificate": "lock",
    "security_headers": "shield",
    "param_fuzz": "alert",
    "cors_check": "globe",
    "jwt_analyze": "key",
    "waf_detect": "shield",
    "webshell_client": "terminal",
    "codec": "spark",
    "payload_forge": "spark",
    "binary_info": "file",
    "crypto_workshop": "lock",
    "file_analyze": "file",
    "archive_extract": "folder",
    "artifact_scan": "search",
    "flag_hunt": "target",
    "workspace_list": "folder",
    "workspace_read": "file",
    "workspace_write": "edit",
    "handoff": "arrow_up_right",
}
STATUS_LABELS = {
    "pending": "等待",
    "awaiting_approval": "待授权",
    "running": "执行中",
    "done": "完成",
    "error": "失败",
    "denied": "已拒绝",
    "cancelled": "已取消",
}
STATUS_PROPS = {
    "pending": "awaiting",
    "awaiting_approval": "awaiting",
    "running": "running",
    "done": "done",
    "error": "error",
    "denied": "denied",
    "cancelled": "cancelled",
}
STATUS_COLORS = {
    "awaiting": COLORS["amber"],
    "running": COLORS["blue"],
    "done": COLORS["green"],
    "error": COLORS["red"],
    "denied": COLORS["red"],
    "cancelled": COLORS["faint"],
}


def _preview_args(tool: dict[str, Any]) -> str:
    args = tool.get("args") or {}
    name = tool.get("name")
    try:
        if name == "http_request":
            return f"{args.get('method', 'GET').upper()} {args.get('url', '')}"
        if name == "dns_lookup":
            return f"{args.get('host', '')}  ·  {args.get('record_type', 'A')}"
        if name == "tcp_probe":
            ports = args.get("ports") or []
            port_text = ", ".join(str(p) for p in ports[:10])
            if len(ports) > 10:
                port_text += "…"
            return f"{args.get('host', '')}  ·  {port_text}"
        if name == "run_command":
            command = " ".join(str(args.get("command", "")).split())
            return command[:140] + ("…" if len(command) > 140 else "")
        if name == "save_finding":
            severity = SEVERITIES.get(str(args.get("severity")), args.get("severity", ""))
            return f"{args.get('title', '')}  ·  {severity}"
        if name == "whois_lookup":
            return str(args.get("host", ""))
        if name == "tls_certificate":
            return f"{args.get('host', '')}:{args.get('port', 443)}"
        if name == "security_headers":
            return str(args.get("url", ""))
        if name == "encode_payload":
            return f"{args.get('encoding', 'base64')}  ·  {str(args.get('data', ''))[:80]}"
        if name in ("workspace_list", "workspace_read", "workspace_write"):
            return str(args.get("path", "."))
        if name == "handoff":
            target = args.get("next_agent", "")
            task = " ".join(str(args.get("task", "")).split())
            return f"→ {target}  ·  {task[:100]}"
        if name in ("http_probe", "web_crawl", "dir_scan", "param_fuzz", "cors_check", "waf_detect"):
            return str(args.get("url") or args.get("base_url") or "")
        if name in ("port_scan", "subdomain_enum"):
            return str(args.get("host") or args.get("domain") or "")
        if name == "dns_zone_transfer":
            return str(args.get("domain") or "")
        if name == "tcp_exchange":
            return f"{args.get('host', '')}:{args.get('port', '')}"
        if name == "jwt_analyze":
            return str(args.get("token", ""))[:80]
        if name == "codec":
            return f"{args.get('operation', 'encode')} · {args.get('format', 'base64')}"
        if name == "payload_forge":
            return str(args.get("category", ""))
        if name in ("binary_info", "file_analyze", "archive_extract", "artifact_scan", "flag_hunt"):
            return str(args.get("path", "."))
    except Exception:
        pass
    return json.dumps(args, ensure_ascii=False)[:140]


def _pretty_json(value: Any) -> str:
    try:
        if isinstance(value, str):
            parsed = json.loads(value)
            return json.dumps(parsed, ensure_ascii=False, indent=2)
        return json.dumps(value, ensure_ascii=False, indent=2)
    except Exception:
        return str(value)


class CodeView(QPlainTextEdit):
    def __init__(self, text: str, max_height: int = 190):
        super().__init__()
        self.setObjectName("CodeBlock")
        self.setReadOnly(True)
        self.setPlainText(text)
        self.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setMaximumHeight(max_height)
        self.setMinimumHeight(min(110, max_height))
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)


class ToolCallCard(QFrame):
    def __init__(self, tool: dict[str, Any], parent: QWidget | None = None):
        super().__init__(parent)
        self.tool = tool
        self._expanded = False
        status = str(tool.get("status") or "pending")
        status_prop = STATUS_PROPS.get(status, "awaiting")
        self.setObjectName("ToolCard")
        set_dynamic_property(self, "status", status_prop)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(11, 8, 11, 8)
        self._layout.setSpacing(3)

        header = QHBoxLayout()
        header.setSpacing(7)
        icon_color = STATUS_COLORS.get(status_prop, COLORS["muted"])
        icon_label = QLabel()
        icon_label.setPixmap(
            icon(TOOL_ICONS.get(str(tool.get("name")), "terminal"), icon_color, 15).pixmap(
                15, 15
            )
        )
        header.addWidget(icon_label, 0, Qt.AlignVCenter)

        name_label = QLabel(TOOL_LABELS.get(str(tool.get("name")), str(tool.get("name"))))
        name_label.setObjectName("ToolName")
        header.addWidget(name_label)
        mono = QLabel(str(tool.get("name") or ""))
        mono.setObjectName("ToolMono")
        header.addWidget(mono)
        header.addStretch(1)

        status_label = QLabel(STATUS_LABELS.get(status, status))
        status_label.setObjectName("ToolStatus")
        set_dynamic_property(status_label, "status", status_prop)
        header.addWidget(status_label)

        self._expand_button = QToolButton()
        self._expand_button.setIcon(icon("chevron_right", COLORS["faint"], 14))
        self._expand_button.setIconSize(self._expand_button.iconSize())
        self._expand_button.setCursor(QCursor(Qt.PointingHandCursor))
        self._expand_button.setToolTip("查看参数与结果")
        self._expand_button.clicked.connect(self._toggle)
        header.addWidget(self._expand_button)
        self._layout.addLayout(header)

        summary = QLabel(_preview_args(tool))
        summary.setObjectName("ToolSummary")
        summary.setWordWrap(True)
        summary.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._layout.addWidget(summary)

        duration = tool.get("duration_ms")
        if status in ("done", "error", "denied") and duration is not None:
            info = QLabel(f"耗时 {duration} ms")
            info.setObjectName("ToolMeta")
            self._layout.addWidget(info)

        self._details = QWidget()
        details_layout = QVBoxLayout(self._details)
        details_layout.setContentsMargins(0, 6, 0, 1)
        details_layout.setSpacing(5)
        caption_args = QLabel("参数")
        caption_args.setObjectName("SectionCaption")
        details_layout.addWidget(caption_args)
        details_layout.addWidget(CodeView(_pretty_json(tool.get("args") or {}), 150))
        result = tool.get("result") or tool.get("error") or ""
        if result:
            caption_result = QLabel("结果")
            caption_result.setObjectName("SectionCaption")
            details_layout.addWidget(caption_result)
            details_layout.addWidget(CodeView(_pretty_json(result), 230))
        self._details.setVisible(False)
        self._layout.addWidget(self._details)

    def _toggle(self) -> None:
        self._expanded = not self._expanded
        self._details.setVisible(self._expanded)
        self._expand_button.setIcon(
            icon(
                "chevron_down" if self._expanded else "chevron_right",
                COLORS["muted"],
                14,
            )
        )


class ReasoningBlock(QFrame):
    def __init__(self, text: str):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(3)
        self._button = QToolButton()
        self._button.setObjectName("ReasoningToggle")
        self._button.setText("思考过程")
        self._button.setIcon(icon("chevron_right", COLORS["muted"], 14))
        self._button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self._button.setCursor(QCursor(Qt.PointingHandCursor))
        self._button.clicked.connect(self._toggle)
        layout.addWidget(self._button, 0, Qt.AlignLeft)
        self._label = QLabel(text)
        self._label.setObjectName("ReasoningText")
        self._label.setWordWrap(True)
        self._label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._label.setVisible(False)
        layout.addWidget(self._label)
        self._expanded = False

    def _toggle(self) -> None:
        self._expanded = not self._expanded
        self._label.setVisible(self._expanded)
        self._button.setIcon(
            icon(
                "chevron_down" if self._expanded else "chevron_right",
                COLORS["muted"],
                14,
            )
        )


class UserMessageWidget(QWidget):
    def __init__(self, message: dict[str, Any]):
        super().__init__()
        self.message = message
        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(9)
        outer.addStretch(1)
        bubble = QFrame()
        bubble.setObjectName("UserBubble")
        bubble.setMaximumWidth(670)
        layout = QVBoxLayout(bubble)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(0)
        label = QLabel(str(message.get("content") or ""))
        label.setObjectName("UserText")
        label.setWordWrap(True)
        label.setTextFormat(Qt.PlainText)
        label.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(label)
        outer.addWidget(bubble)
        avatar = QLabel("你")
        avatar.setObjectName("UserAvatar")
        avatar.setFixedSize(28, 28)
        avatar.setAlignment(Qt.AlignCenter)
        outer.addWidget(avatar, 0, Qt.AlignTop)


class AssistantMessageWidget(QWidget):
    def __init__(self, message: dict[str, Any]):
        super().__init__()
        self.message = message
        self._last_text_view: MarkdownView | None = None
        self._last_text_index: int = -1
        self._typing: TypingDots | None = None
        self._body_host = QWidget()
        self._body_layout = QVBoxLayout(self._body_host)
        self._body_layout.setContentsMargins(0, 0, 0, 0)
        self._body_layout.setSpacing(8)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(7)

        header = QHBoxLayout()
        header.setSpacing(8)
        header.addWidget(BrandMark(22), 0, Qt.AlignVCenter)
        name = QLabel("SSsec")
        name.setObjectName("AssistantName")
        header.addWidget(name)
        meta_text = str(message.get("model") or "SSsec Agent")
        meta = QLabel(meta_text)
        meta.setObjectName("AssistantMeta")
        header.addWidget(meta)
        header.addStretch(1)
        time_label = QLabel(format_local_time(str(message.get("created_at") or ""), "%H:%M"))
        time_label.setObjectName("AssistantMeta")
        header.addWidget(time_label)
        self.copy_button = QToolButton()
        self.copy_button.setIcon(icon("copy", COLORS["faint"], 14))
        self.copy_button.setToolTip("复制回答")
        self.copy_button.setCursor(QCursor(Qt.PointingHandCursor))
        self.copy_button.clicked.connect(self._copy)
        header.addWidget(self.copy_button)
        root.addLayout(header)

        indented = QHBoxLayout()
        indented.setContentsMargins(30, 0, 0, 0)
        indented.addWidget(self._body_host, 1)
        root.addLayout(indented)

        self.footer_host = QWidget()
        self.footer_layout = QHBoxLayout(self.footer_host)
        self.footer_layout.setContentsMargins(30, 0, 0, 0)
        self.footer_layout.setSpacing(7)
        root.addWidget(self.footer_host)

        self.sync_from_data(message)

    def _copy(self) -> None:
        QGuiApplication.clipboard().setText(assistant_text(self.message))

    def append_delta(self, kind: str, text: str) -> None:
        segments = self.message.get("segments") or []
        latest_index = len(segments) - 1
        if (
            kind == "text"
            and self._last_text_view is not None
            and latest_index == self._last_text_index
        ):
            current = self._last_text_view.source()
            self._last_text_view.set_markdown(current + text, debounce=True)
        else:
            # 工具执行后的新一轮文本会形成新的 text segment，必须重绘，
            # 不能把内容追加到工具调用之前的 Markdown 视图。
            self.sync_from_data(self.message)
        self._ensure_typing(False)

    def _clear_body(self) -> None:
        while self._body_layout.count():
            item = self._body_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                dispose_widget(widget)
        while self.footer_layout.count():
            item = self.footer_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                dispose_widget(widget)
        self._last_text_view = None
        self._last_text_index = -1
        self._typing = None

    def sync_from_data(self, message: dict[str, Any]) -> None:
        self.message = message
        self._clear_body()
        segments = message.get("segments") or []
        has_text = False
        for index, segment in enumerate(segments):
            seg_type = segment.get("type")
            if seg_type == "text":
                text = str(segment.get("text") or "")
                if not text:
                    continue
                view = MarkdownView(text)
                self._body_layout.addWidget(view)
                self._last_text_view = view
                self._last_text_index = index
                has_text = True
            elif seg_type == "reasoning":
                text = str(segment.get("text") or "").strip()
                if text:
                    self._body_layout.addWidget(ReasoningBlock(text))
            elif seg_type == "tool":
                tool = segment.get("tool") or {}
                self._body_layout.addWidget(ToolCallCard(tool))

        status = str(message.get("status") or "complete")
        if not segments and status == "streaming":
            typing_host = QWidget()
            typing_layout = QHBoxLayout(typing_host)
            typing_layout.setContentsMargins(0, 0, 0, 0)
            typing_layout.setSpacing(7)
            self._typing = TypingDots()
            self._typing.start()
            typing_layout.addWidget(self._typing)
            hint = QLabel("正在思考…")
            hint.setObjectName("StreamingHint")
            typing_layout.addWidget(hint)
            typing_layout.addStretch(1)
            self._body_layout.addWidget(typing_host)
        elif status == "streaming" and not has_text:
            typing_host = QWidget()
            typing_layout = QHBoxLayout(typing_host)
            typing_layout.setContentsMargins(0, 0, 0, 0)
            typing_layout.setSpacing(7)
            self._typing = TypingDots()
            self._typing.start()
            typing_layout.addWidget(self._typing)
            hint = QLabel("正在使用工具…")
            hint.setObjectName("StreamingHint")
            typing_layout.addWidget(hint)
            typing_layout.addStretch(1)
            self._body_layout.addWidget(typing_host)

        if status == "error" and message.get("error"):
            error_card = QFrame()
            error_card.setObjectName("ErrorCard")
            error_layout = QHBoxLayout(error_card)
            error_layout.setContentsMargins(10, 8, 10, 8)
            error_layout.setSpacing(7)
            err_icon = QLabel()
            err_icon.setPixmap(icon("alert", COLORS["red"], 15).pixmap(15, 15))
            error_layout.addWidget(err_icon, 0, Qt.AlignTop)
            error_text = QLabel(str(message.get("error")))
            error_text.setObjectName("ErrorText")
            error_text.setWordWrap(True)
            error_text.setTextInteractionFlags(Qt.TextSelectableByMouse)
            error_layout.addWidget(error_text, 1)
            self._body_layout.addWidget(error_card)

        if status == "streaming":
            hint = QLabel("正在生成")
            hint.setObjectName("StreamingHint")
            self.footer_layout.addWidget(hint)
            self.footer_layout.addStretch(1)
        elif status == "awaiting_approval":
            hint = QLabel("等待你确认工具调用")
            hint.setObjectName("StreamingHint")
            hint.setStyleSheet(f"color: {COLORS['amber']}; font-size: 8.5pt;")
            self.footer_layout.addWidget(hint)
            self.footer_layout.addStretch(1)
        elif status == "cancelled":
            hint = QLabel("已停止生成")
            hint.setObjectName("StreamingHint")
            self.footer_layout.addWidget(hint)
            self.footer_layout.addStretch(1)
        elif status == "complete" and not has_text and not segments:
            hint = QLabel("本轮没有可显示的文字回复。")
            hint.setObjectName("StreamingHint")
            self.footer_layout.addWidget(hint)
            self.footer_layout.addStretch(1)
        self.footer_host.setVisible(self.footer_layout.count() > 0)

    def _ensure_typing(self, visible: bool) -> None:
        if self._typing is not None and visible:
            self._typing.start()
        elif self._typing is not None and not visible:
            self._typing.stop()


class ApprovalBar(QFrame):
    approved = Signal()
    denied = Signal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("ApprovalBar")
        self._calls: list[dict] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 11, 14, 11)
        layout.setSpacing(7)

        top = QHBoxLayout()
        top.setSpacing(8)
        alert_icon = QLabel()
        alert_icon.setPixmap(icon("alert", COLORS["amber"], 17).pixmap(17, 17))
        top.addWidget(alert_icon, 0, Qt.AlignTop)
        self.title = QLabel("需要你的确认")
        self.title.setObjectName("ApprovalTitle")
        top.addWidget(self.title)
        top.addStretch(1)
        self.count_label = QLabel("")
        self.count_label.setObjectName("ApprovalBody")
        top.addWidget(self.count_label)
        layout.addLayout(top)

        self.detail = QLabel("")
        self.detail.setObjectName("ApprovalBody")
        self.detail.setWordWrap(True)
        self.detail.setTextInteractionFlags(Qt.TextSelectableByMouse)
        layout.addWidget(self.detail)

        self.command_preview = QPlainTextEdit()
        self.command_preview.setObjectName("CodeBlock")
        self.command_preview.setReadOnly(True)
        self.command_preview.setMaximumHeight(96)
        self.command_preview.setMinimumHeight(58)
        self.command_preview.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self.command_preview.setVisible(False)
        layout.addWidget(self.command_preview)

        self.warning = QLabel("")
        self.warning.setObjectName("ApprovalBody")
        self.warning.setStyleSheet(f"color: {COLORS['amber']}; font-size: 8.5pt;")
        self.warning.setWordWrap(True)
        self.warning.setVisible(False)
        layout.addWidget(self.warning)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.deny_button = QPushButton("拒绝")
        self.deny_button.setObjectName("Secondary")
        self.deny_button.clicked.connect(self._deny)
        self.approve_button = QPushButton("允许并执行")
        self.approve_button.setObjectName("Primary")
        self.approve_button.clicked.connect(self._approve)
        buttons.addWidget(self.deny_button)
        buttons.addWidget(self.approve_button)
        layout.addLayout(buttons)
        self.hide()

    def set_payload(self, payload: dict) -> None:
        calls = payload.get("calls") or []
        self._calls = calls
        worker_label = str(payload.get("worker_label") or "").strip()
        self.title.setText(
            f"需要你的确认 · {worker_label}" if worker_label else "需要你的确认"
        )
        self.count_label.setText(f"{len(calls)} 项工具调用")
        lines: list[str] = []
        for call in calls[:4]:
            label = TOOL_LABELS.get(str(call.get("name")), str(call.get("name")))
            preview = _preview_args(call)
            if len(preview) > 155:
                preview = preview[:155] + "…"
            lines.append(f"•  {label}：{preview}")
        if len(calls) > 4:
            lines.append(f"•  以及另外 {len(calls) - 4} 项调用")
        self.detail.setText("\n".join(lines) or "工具调用等待确认。")
        has_command = any(call.get("name") == "run_command" for call in calls)
        commands = [
            str((call.get("args") or {}).get("command") or "")
            for call in calls
            if call.get("name") == "run_command"
        ]
        self.command_preview.setVisible(has_command)
        if has_command:
            self.command_preview.setPlainText(
                "\n\n".join(f"$ {command}" for command in commands)
            )
        else:
            self.command_preview.clear()
        has_write_http = any(
            call.get("name") == "http_request"
            and str((call.get("args") or {}).get("method") or "GET").upper()
            not in ("GET", "HEAD", "OPTIONS")
            for call in calls
        )
        self.warning.setVisible(has_command or has_write_http)
        if has_command:
            self.warning.setText(
                "包含命令执行：命令将在当前会话的独立工作目录中由 PowerShell 运行，"
                "请仔细核对参数与影响。"
            )
        elif has_write_http:
            self.warning.setText(
                "包含非只读 HTTP 方法：请求可能改变目标状态，请确认方法、路径与请求体。"
            )
        self.set_busy(False)
        self.show()

    def set_busy(self, busy: bool) -> None:
        self.approve_button.setEnabled(not busy)
        self.deny_button.setEnabled(not busy)
        if busy:
            self.approve_button.setText("正在提交…")
        else:
            self.approve_button.setText("允许并执行")

    def _approve(self) -> None:
        self.set_busy(True)
        self.approved.emit()

    def _deny(self) -> None:
        self.set_busy(True)
        self.denied.emit()


class EmptyState(QWidget):
    scope_requested = Signal()
    settings_requested = Signal()
    prompt_selected = Signal(str)

    def __init__(self, conversation, demo_mode: bool = False):
        super().__init__()
        self._conversation = conversation
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 40, 0, 20)
        layout.setSpacing(0)
        layout.setAlignment(Qt.AlignHCenter | Qt.AlignTop)

        mark = BrandMark(64)
        layout.addWidget(mark, 0, Qt.AlignHCenter)
        layout.addSpacing(20)
        heading = QLabel("开始一次安全测试")
        heading.setObjectName("EmptyHeading")
        heading.setAlignment(Qt.AlignCenter)
        layout.addWidget(heading)
        layout.addSpacing(8)
        sub = QLabel(
            "设置目标提示，或直接为当前对话开启完全权限，让 SSsec 完成信息收集、验证与记录。"
        )
        sub.setObjectName("PageSub")
        sub.setAlignment(Qt.AlignCenter)
        sub.setWordWrap(True)
        layout.addWidget(sub)
        layout.addSpacing(22)

        scope_card = QFrame()
        scope_card.setObjectName("Card")
        scope_layout = QHBoxLayout(scope_card)
        scope_layout.setContentsMargins(14, 11, 14, 11)
        scope_layout.setSpacing(10)
        authorized = bool(conversation and conversation.scope)
        full_access = bool(conversation and conversation.full_permission)
        icon_label = QLabel()
        icon_label.setPixmap(
            icon(
                "shield" if authorized else "target",
                COLORS["green"] if authorized else COLORS["accent"],
                20,
            ).pixmap(20, 20)
        )
        scope_layout.addWidget(icon_label, 0, Qt.AlignVCenter)
        text_layout = QVBoxLayout()
        text_layout.setSpacing(2)
        if full_access:
            scope_title_text = "完全权限已开启"
            scope_detail = "所有工具调用免人工确认，且不按目标范围拦截。"
        elif authorized:
            scope_title_text = "已设置测试目标"
            scope_detail = (
                f"{scope_summary(conversation.scope, conversation.authorized)}"
                " · 目标范围作为提示与审计标记"
            )
        else:
            scope_title_text = "测试目标（可选）"
            scope_detail = "未设置目标也会执行工具；目标列表仅用于提示与审计。"
        scope_title = QLabel(scope_title_text)
        scope_title.setObjectName("CardTitle")
        scope_text = QLabel(scope_detail)
        scope_text.setObjectName("HelpText")
        scope_text.setWordWrap(True)
        text_layout.addWidget(scope_title)
        text_layout.addWidget(scope_text)
        scope_layout.addLayout(text_layout, 1)
        scope_button = QPushButton("编辑范围与权限" if (authorized or full_access) else "设置范围 / 完全权限")
        scope_button.setObjectName("Secondary")
        scope_button.clicked.connect(self.scope_requested.emit)
        scope_layout.addWidget(scope_button)
        layout.addWidget(scope_card)
        layout.addSpacing(18)

        caption = QLabel("可以这样开始")
        caption.setObjectName("SectionCaption")
        layout.addWidget(caption)
        layout.addSpacing(7)
        suggestions = [
            ("梳理测试计划", "根据测试目标制定低影响、可回滚的测试步骤"),
            ("只读信息收集", "查询 DNS、HTTP 与常见端口连通性"),
            ("检查 HTTP 安全响应头", "识别缺失的安全头并给出修复建议"),
        ]
        for title, subtitle in suggestions:
            card = SuggestionCard(title, subtitle)
            card.clicked.connect(
                lambda _checked=False, text=f"{title}：{subtitle}": self.prompt_selected.emit(
                    text
                )
            )
            layout.addWidget(card)
            layout.addSpacing(7)

        layout.addSpacing(12)
        if demo_mode:
            demo_row = QHBoxLayout()
            demo_row.addStretch(1)
            demo_note = QLabel("当前使用离线演示模型，不会执行真实工具")
            demo_note.setObjectName("HelpText")
            demo_row.addWidget(demo_note)
            config_button = QPushButton("配置模型")
            config_button.setObjectName("Chip")
            config_button.clicked.connect(self.settings_requested.emit)
            demo_row.addWidget(config_button)
            demo_row.addStretch(1)
            layout.addLayout(demo_row)
        layout.addSpacing(8)
        disclaimer = QLabel(
            "SSsec 仅用于已获得明确授权的安全测试。开启完全权限前请确认测试活动合法且范围可控。"
        )
        disclaimer.setObjectName("EmptyDisclaimer")
        disclaimer.setAlignment(Qt.AlignCenter)
        disclaimer.setWordWrap(True)
        layout.addWidget(disclaimer)
        layout.addStretch(1)
        self.setMinimumWidth(560)
        self.setMaximumWidth(700)
