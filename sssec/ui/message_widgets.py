"""聊天消息、工具调用卡片、审批条与欢迎空状态（Linear 风格）。"""

from __future__ import annotations

import json
from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QCursor
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
    CopyButton,
    MarkdownView,
    SuggestionCard,
    TypingDots,
    caption_label,
    dot_pixmap,
    meta_dot,
    set_dynamic_property,
    status_dot,
    tone_badge,
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
_STATUS_COLOR_KEYS = {
    "awaiting": "amber",
    "running": "blue",
    "done": "green",
    "error": "red",
    "denied": "red",
    "cancelled": "faint",
}

# 工具卡片的彩色图标徽标：按工具语义分组，保持整体克制。
_BLUE_TOOLS = {
    "http_probe",
    "dns_lookup",
    "dns_zone_transfer",
    "whois_lookup",
    "port_scan",
    "subdomain_enum",
    "dir_scan",
    "web_crawl",
    "tls_certificate",
    "api_discover",
}
_VIOLET_TOOLS = {
    "codec",
    "payload_forge",
    "binary_info",
    "disassemble",
    "crypto_workshop",
    "file_analyze",
    "archive_extract",
    "artifact_scan",
    "tcp_exchange",
}
_CYAN_TOOLS = {"workspace_list", "workspace_read", "workspace_write"}
_AMBER_TOOLS = {"run_command", "http_upload", "webshell_client"}
_GREEN_TOOLS = {"save_finding", "flag_hunt"}


def _tool_tone(name: str) -> str:
    name = str(name or "")
    if name in _GREEN_TOOLS:
        return "green"
    if name in _AMBER_TOOLS:
        return "amber"
    if name in _VIOLET_TOOLS:
        return "violet"
    if name in _BLUE_TOOLS:
        return "blue"
    if name in _CYAN_TOOLS:
        return "cyan"
    return "accent"


def _status_color(status_prop: str) -> str:
    return COLORS[_STATUS_COLOR_KEYS.get(status_prop, "muted")]


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
        # 按内容行数取高，避免两三行 JSON 撑出一大片空白。
        visual_lines = sum(
            max(1, (len(line) // 74) + 1) for line in text.splitlines() or [""]
        )
        height = min(max_height, max(46, visual_lines * 15 + 22))
        self.setFixedHeight(height)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)


class ToolCallCard(QFrame):
    def __init__(self, tool: dict[str, Any], parent: QWidget | None = None):
        super().__init__(parent)
        self.tool = tool
        self._expanded = False
        # 参数/结果编辑器在首次展开时才创建；折叠状态不解析大 JSON，
        # 避免长任务里每次刷新都重建几十个隐藏 QPlainTextEdit。
        self._details: QWidget | None = None
        self._args_view: CodeView | None = None
        self._result_view: CodeView | None = None

        status = str(tool.get("status") or "pending")
        status_prop = STATUS_PROPS.get(status, "awaiting")
        self.setObjectName("ToolCard")
        set_dynamic_property(self, "status", status_prop)
        self._layout = QVBoxLayout(self)
        self._layout.setContentsMargins(10, 8, 10, 8)
        self._layout.setSpacing(2)

        header = QHBoxLayout()
        header.setSpacing(7)
        self._status_dot = status_dot(_status_color(status_prop), 6)
        header.addWidget(self._status_dot, 0, Qt.AlignVCenter)

        tool_name = str(tool.get("name"))
        header.addWidget(
            tone_badge(
                TOOL_ICONS.get(tool_name, "terminal"),
                _tool_tone(tool_name),
                size=22,
                icon_size=12,
            ),
            0,
            Qt.AlignVCenter,
        )

        name_label = QLabel(TOOL_LABELS.get(tool_name, tool_name))
        name_label.setObjectName("ToolName")
        header.addWidget(name_label)
        mono = QLabel(tool_name)
        mono.setObjectName("ToolMono")
        header.addWidget(mono)
        header.addStretch(1)

        self._duration_label = QLabel("")
        self._duration_label.setObjectName("ToolMeta")
        header.addWidget(self._duration_label)

        self._status_label = QLabel(STATUS_LABELS.get(status, status))
        self._status_label.setObjectName("ToolStatus")
        set_dynamic_property(self._status_label, "status", status_prop)
        header.addWidget(self._status_label)

        self._expand_button = QToolButton()
        self._expand_button.setObjectName("Ghost")
        self._expand_button.setIcon(icon("chevron_right", COLORS["faint"], 12))
        self._expand_button.setIconSize(self._expand_button.iconSize())
        self._expand_button.setCursor(QCursor(Qt.PointingHandCursor))
        self._expand_button.setToolTip("查看参数与结果")
        self._expand_button.setFixedSize(22, 22)
        self._expand_button.clicked.connect(self._toggle)
        header.addWidget(self._expand_button)
        self._layout.addLayout(header)

        self._summary = QLabel("")
        self._summary.setObjectName("ToolSummary")
        self._summary.setWordWrap(True)
        self._summary.setContentsMargins(33, 0, 0, 0)
        self._summary.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self._layout.addWidget(self._summary)

        self.update_tool(tool)

    def update_tool(self, tool: dict[str, Any]) -> None:
        """就地更新状态/摘要，不重建整张卡片。"""
        self.tool = tool
        status = str(tool.get("status") or "pending")
        status_prop = STATUS_PROPS.get(status, "awaiting")
        set_dynamic_property(self, "status", status_prop)
        self._status_dot.setPixmap(dot_pixmap(_status_color(status_prop), 6))
        self._status_label.setText(STATUS_LABELS.get(status, status))
        set_dynamic_property(self._status_label, "status", status_prop)
        self._summary.setText(_preview_args(tool))
        duration = tool.get("duration_ms")
        if duration is not None:
            self._duration_label.setText(f"{duration} ms")
            self._duration_label.setVisible(True)
        else:
            self._duration_label.setVisible(False)
        if self._details is not None and self._expanded:
            self._build_details()

    def _clear_details(self) -> None:
        if self._details is None:
            return
        while self._details.layout() and self._details.layout().count():
            item = self._details.layout().takeAt(0)
            widget = item.widget()
            if widget is not None:
                dispose_widget(widget)
        self._details.hide()
        self._details.setParent(None)
        self._details.deleteLater()
        self._details = None
        self._args_view = None
        self._result_view = None

    def _build_details(self) -> None:
        self._clear_details()
        details = QWidget()
        details_layout = QVBoxLayout(details)
        details_layout.setContentsMargins(33, 6, 0, 1)
        details_layout.setSpacing(5)
        details_layout.addWidget(caption_label("参数"))
        self._args_view = CodeView(_pretty_json(self.tool.get("args") or {}), 150)
        details_layout.addWidget(self._args_view)
        result = self.tool.get("result") or self.tool.get("error") or ""
        if result:
            details_layout.addWidget(caption_label("结果"))
            self._result_view = CodeView(_pretty_json(result), 230)
            details_layout.addWidget(self._result_view)
        self._details = details
        self._layout.addWidget(details)
        details.setVisible(self._expanded)

    def _toggle(self) -> None:
        self._expanded = not self._expanded
        if self._expanded and self._details is None:
            self._build_details()
        if self._details is not None:
            self._details.setVisible(self._expanded)
        self._expand_button.setIcon(
            icon(
                "chevron_down" if self._expanded else "chevron_right",
                COLORS["muted"],
                12,
            )
        )


class ReasoningBlock(QFrame):
    def __init__(self, text: str):
        super().__init__()
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        self._button = QToolButton()
        self._button.setObjectName("ReasoningToggle")
        self._button.setText("思考过程")
        self._button.setIcon(icon("chevron_right", COLORS["muted"], 12))
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

    def set_text(self, text: str) -> None:
        if self._label.text() != text:
            self._label.setText(text)

    def _toggle(self) -> None:
        self._expanded = not self._expanded
        self._label.setVisible(self._expanded)
        self._button.setIcon(
            icon(
                "chevron_down" if self._expanded else "chevron_right",
                COLORS["muted"],
                12,
            )
        )


class UserMessageWidget(QWidget):
    def __init__(self, message: dict[str, Any]):
        super().__init__()
        self.message = message
        outer = QHBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(6)
        outer.addStretch(1)
        # 发送者的复制按钮紧贴气泡左侧，复制的是发送者写的那段话。
        self.copy_button = CopyButton(tooltip="复制发送内容")
        self.copy_button.set_provider(lambda: str(self.message.get("content") or ""))
        outer.addWidget(self.copy_button, 0, Qt.AlignVCenter)
        bubble = QFrame()
        bubble.setObjectName("UserBubble")
        bubble.setMaximumWidth(600)
        layout = QVBoxLayout(bubble)
        layout.setContentsMargins(12, 8, 12, 8)
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
        avatar.setFixedSize(22, 22)
        avatar.setAlignment(Qt.AlignCenter)
        outer.addWidget(avatar, 0, Qt.AlignTop)


class AssistantMessageWidget(QWidget):
    def __init__(self, message: dict[str, Any]):
        super().__init__()
        self.message = message
        self._last_text_view: MarkdownView | None = None
        self._last_text_index: int = -1
        self._typing: TypingDots | None = None
        self._typing_host: QWidget | None = None
        self._typing_label: QLabel | None = None
        self._segment_widgets: list[QWidget | None] = []
        self._text_views: dict[int, MarkdownView] = {}
        self._tool_cards: dict[int, ToolCallCard] = {}
        self._reasoning_blocks: dict[int, ReasoningBlock] = {}
        self._error_card: QFrame | None = None
        self._footer_key: tuple | None = None
        self._body_host = QWidget()
        self._body_layout = QVBoxLayout(self._body_host)
        self._body_layout.setContentsMargins(0, 0, 0, 0)
        self._body_layout.setSpacing(8)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(6)

        header = QHBoxLayout()
        header.setSpacing(7)
        header.addWidget(BrandMark(17), 0, Qt.AlignVCenter)
        name = QLabel("SSsec")
        name.setObjectName("AssistantName")
        header.addWidget(name)
        meta = QLabel(str(message.get("model") or "SSsec Agent"))
        meta.setObjectName("AssistantMeta")
        header.addWidget(meta)
        header.addWidget(meta_dot())
        time_label = QLabel(format_local_time(str(message.get("created_at") or ""), "%H:%M"))
        time_label.setObjectName("AssistantMeta")
        header.addWidget(time_label)
        self.copy_button = CopyButton(tooltip="复制回答")
        self.copy_button.set_provider(lambda: assistant_text(self.message))
        header.addWidget(self.copy_button, 0, Qt.AlignVCenter)
        header.addStretch(1)
        root.addLayout(header)

        indented = QHBoxLayout()
        indented.setContentsMargins(24, 0, 0, 0)
        indented.addWidget(self._body_host, 1)
        root.addLayout(indented)

        self.footer_host = QWidget()
        self.footer_layout = QHBoxLayout(self.footer_host)
        self.footer_layout.setContentsMargins(24, 0, 0, 0)
        self.footer_layout.setSpacing(7)
        root.addWidget(self.footer_host)

        self.sync_from_data(message)

    def append_delta(self, kind: str, text: str) -> None:
        if kind != "text" or not text:
            return
        segments = self.message.get("segments") or []
        if not segments:
            return
        latest_index = len(segments) - 1
        segment = segments[latest_index]
        if segment.get("type") != "text":
            return
        if latest_index >= len(self._segment_widgets):
            self.sync_from_data(self.message)
            return
        view = self._text_views.get(latest_index)
        if view is None:
            self.sync_from_data(self.message)
            view = self._text_views.get(latest_index)
        if view is None:
            return
        target = str(segment.get("text") or "")
        if not view.is_streaming():
            if target != view.source():
                view.set_stream_text(target)
        elif target.startswith(view.source()):
            delta = target[len(view.source()):]
            if delta:
                view.append_stream_text(delta)
        elif target != view.source():
            view.set_stream_text(target)
        self._refresh_typing()

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
        self._segment_widgets = []
        self._text_views = {}
        self._tool_cards = {}
        self._reasoning_blocks = {}
        self._typing_host = None
        self._typing_label = None
        self._typing = None
        self._error_card = None
        self._footer_key = None
        self._last_text_view = None
        self._last_text_index = -1

    def _insert_segment_widget(self, index: int, widget: QWidget) -> None:
        position = sum(
            1 for item in self._segment_widgets[:index] if item is not None
        )
        self._body_layout.insertWidget(position, widget)

    def _build_segment(self, index: int, segment: dict[str, Any], status: str) -> None:
        seg_type = segment.get("type")
        if seg_type == "text":
            text = str(segment.get("text") or "")
            if not text:
                self._segment_widgets.append(None)
                return
            view = MarkdownView()
            is_last = index == len(self.message.get("segments") or []) - 1
            if status == "streaming" and is_last:
                view.set_stream_text(text)
            else:
                view.set_markdown(text)
            self._body_layout.addWidget(view)
            self._segment_widgets.append(view)
            self._text_views[index] = view
            self._last_text_view = view
            self._last_text_index = index
        elif seg_type == "reasoning":
            text = str(segment.get("text") or "").strip()
            block = ReasoningBlock(text)
            self._body_layout.addWidget(block)
            self._segment_widgets.append(block)
            self._reasoning_blocks[index] = block
        elif seg_type == "tool":
            tool = segment.get("tool") or {}
            card = ToolCallCard(tool)
            self._body_layout.addWidget(card)
            self._segment_widgets.append(card)
            self._tool_cards[index] = card
        else:
            self._segment_widgets.append(None)

    def _needs_rebuild(self, segments: list[dict[str, Any]]) -> bool:
        if len(segments) < len(self._segment_widgets):
            return True
        for index, segment in enumerate(segments[: len(self._segment_widgets)]):
            widget = self._segment_widgets[index]
            seg_type = segment.get("type")
            if seg_type == "text":
                if widget is None:
                    continue
                if not isinstance(widget, MarkdownView):
                    return True
            elif seg_type == "reasoning":
                if not isinstance(widget, ReasoningBlock):
                    return True
            elif seg_type == "tool":
                if not isinstance(widget, ToolCallCard):
                    return True
        return False

    def _rebuild_body(self) -> None:
        self._clear_body()
        segments = self.message.get("segments") or []
        status = str(self.message.get("status") or "complete")
        for index, segment in enumerate(segments):
            self._build_segment(index, segment, status)
        self._refresh_typing()
        self._refresh_error()
        self._refresh_footer()

    def _refresh_typing(self) -> None:
        segments = self.message.get("segments") or []
        status = str(self.message.get("status") or "complete")
        has_text = any(
            segment.get("type") == "text" and str(segment.get("text") or "").strip()
            for segment in segments
        )
        if status == "streaming" and not has_text:
            hint = "正在思考…" if not segments else "正在使用工具…"
            if self._typing_host is None:
                host = QWidget()
                layout = QHBoxLayout(host)
                layout.setContentsMargins(0, 0, 0, 0)
                layout.setSpacing(6)
                self._typing = TypingDots()
                self._typing.start()
                layout.addWidget(self._typing, 0, Qt.AlignVCenter)
                self._typing_label = QLabel(hint)
                self._typing_label.setObjectName("StreamingHint")
                layout.addWidget(self._typing_label, 0, Qt.AlignVCenter)
                layout.addStretch(1)
                self._body_layout.addWidget(host)
                self._typing_host = host
            elif self._typing_label is not None and self._typing_label.text() != hint:
                self._typing_label.setText(hint)
            if self._typing is not None:
                self._typing.start()
        elif self._typing_host is not None:
            self._typing_host.hide()
            self._typing_host.setParent(None)
            self._typing_host.deleteLater()
            self._typing_host = None
            self._typing_label = None
            self._typing = None

    def _refresh_error(self) -> None:
        status = str(self.message.get("status") or "complete")
        error = str(self.message.get("error") or "") if status == "error" else ""
        if not error:
            if self._error_card is not None:
                self._error_card.hide()
                self._error_card.setParent(None)
                self._error_card.deleteLater()
                self._error_card = None
            return
        if self._error_card is None:
            card = QFrame()
            card.setObjectName("ErrorCard")
            layout = QHBoxLayout(card)
            layout.setContentsMargins(10, 8, 10, 8)
            layout.setSpacing(7)
            err_icon = QLabel()
            err_icon.setPixmap(icon("alert", COLORS["red"], 14).pixmap(14, 14))
            layout.addWidget(err_icon, 0, Qt.AlignTop)
            text = QLabel(error)
            text.setObjectName("ErrorText")
            text.setWordWrap(True)
            text.setTextInteractionFlags(Qt.TextSelectableByMouse)
            layout.addWidget(text, 1)
            self._body_layout.addWidget(card)
            self._error_card = card
        else:
            labels = self._error_card.findChildren(QLabel, "ErrorText")
            if labels and labels[0].text() != error:
                labels[0].setText(error)

    def _refresh_footer(self) -> None:
        segments = self.message.get("segments") or []
        status = str(self.message.get("status") or "complete")
        has_text = any(
            segment.get("type") == "text" and str(segment.get("text") or "").strip()
            for segment in segments
        )
        key = (status, has_text, len(segments))
        if key == self._footer_key:
            self.footer_host.setVisible(self.footer_layout.count() > 0)
            return
        self._footer_key = key
        while self.footer_layout.count():
            item = self.footer_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                dispose_widget(widget)
        if status == "streaming":
            self.footer_layout.addWidget(status_dot(COLORS["accent"], 5))
            hint = QLabel("正在生成")
            hint.setObjectName("StreamingHint")
            self.footer_layout.addWidget(hint)
            self.footer_layout.addStretch(1)
        elif status == "awaiting_approval":
            self.footer_layout.addWidget(status_dot(COLORS["amber"], 5))
            hint = QLabel("等待你确认工具调用")
            hint.setObjectName("StreamingHint")
            hint.setStyleSheet(f"color: {COLORS['amber']}; font-size: 8.3pt;")
            self.footer_layout.addWidget(hint)
            self.footer_layout.addStretch(1)
        elif status == "cancelled":
            self.footer_layout.addWidget(status_dot(COLORS["faint"], 5))
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

    def sync_from_data(self, message: dict[str, Any]) -> None:
        self.message = message
        segments = message.get("segments") or []
        status = str(message.get("status") or "complete")
        if self._needs_rebuild(segments):
            self._rebuild_body()
            return

        # 新增 segment 时先移除 typing 行，保证它始终在末尾。
        if self._typing_host is not None:
            self._typing_host.hide()
            self._typing_host.setParent(None)
            self._typing_host.deleteLater()
            self._typing_host = None
            self._typing_label = None
            self._typing = None
        for index in range(len(self._segment_widgets), len(segments)):
            self._build_segment(index, segments[index], status)

        last_index = len(segments) - 1
        for index, segment in enumerate(segments):
            widget = (
                self._segment_widgets[index]
                if index < len(self._segment_widgets)
                else None
            )
            seg_type = segment.get("type")
            if seg_type == "text":
                text = str(segment.get("text") or "")
                if not text:
                    continue
                if widget is None:
                    widget = MarkdownView()
                    self._insert_segment_widget(index, widget)
                    self._segment_widgets[index] = widget
                    self._text_views[index] = widget
                view = widget
                if not isinstance(view, MarkdownView):
                    continue
                if view.source() != text:
                    if status == "streaming" and index == last_index:
                        view.set_stream_text(text)
                    else:
                        if view.is_streaming():
                            view.finish_stream()
                        view.set_markdown(text)
                if status == "streaming" and index == last_index and not view.is_streaming():
                    view.set_stream_text(text)
            elif seg_type == "reasoning":
                text = str(segment.get("text") or "").strip()
                if widget is None:
                    block = ReasoningBlock(text)
                    self._insert_segment_widget(index, block)
                    self._segment_widgets[index] = block
                    self._reasoning_blocks[index] = block
                elif isinstance(widget, ReasoningBlock):
                    widget.set_text(text)
            elif seg_type == "tool":
                tool = segment.get("tool") or {}
                if widget is None:
                    card = ToolCallCard(tool)
                    self._insert_segment_widget(index, card)
                    self._segment_widgets[index] = card
                    self._tool_cards[index] = card
                elif isinstance(widget, ToolCallCard):
                    widget.update_tool(tool)

        # 跨过工具/推理的文本段已经结束，立即渲染它的 Markdown；
        # 最后一个文本段如果仍在流式输出，继续保留纯文本增量模式。
        for index, view in list(self._text_views.items()):
            if status != "streaming" or index != last_index:
                view.finish_stream()

        self._refresh_typing()
        self._refresh_error()
        self._refresh_footer()


class ApprovalBar(QFrame):
    approved = Signal()
    denied = Signal()

    def __init__(self, parent: QWidget | None = None):
        super().__init__(parent)
        self.setObjectName("ApprovalBar")
        self._calls: list[dict] = []
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)

        top = QHBoxLayout()
        top.setSpacing(7)
        alert_icon = QLabel()
        alert_icon.setPixmap(icon("alert", COLORS["amber"], 15).pixmap(15, 15))
        top.addWidget(alert_icon, 0, Qt.AlignVCenter)
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
        self.command_preview.setMaximumHeight(88)
        self.command_preview.setMinimumHeight(54)
        self.command_preview.setLineWrapMode(QPlainTextEdit.WidgetWidth)
        self.command_preview.setVisible(False)
        layout.addWidget(self.command_preview)

        self.warning = QLabel("")
        self.warning.setObjectName("ApprovalBody")
        self.warning.setStyleSheet(f"color: {COLORS['amber']}; font-size: 8.2pt;")
        self.warning.setWordWrap(True)
        self.warning.setVisible(False)
        layout.addWidget(self.warning)

        buttons = QHBoxLayout()
        buttons.setSpacing(6)
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
            f"需要确认 · {worker_label}" if worker_label else "需要你的确认"
        )
        self.count_label.setText(f"{len(calls)} 项工具调用")
        lines: list[str] = []
        for call in calls[:4]:
            label = TOOL_LABELS.get(str(call.get("name")), str(call.get("name")))
            preview = _preview_args(call)
            if len(preview) > 155:
                preview = preview[:155] + "…"
            lines.append(f"·  {label}：{preview}")
        if len(calls) > 4:
            lines.append(f"·  以及另外 {len(calls) - 4} 项调用")
        self.detail.setText("\n".join(lines) or "工具调用等待确认。")
        has_command = any(call.get("name") == "run_command" for call in calls)
        commands = [
            str((call.get("args") or {}).get("command") or "")
            for call in calls
            if call.get("name") == "run_command"
        ]
        self.command_preview.setVisible(has_command)
        if has_command:
            command_text = "\n\n".join(f"$ {command}" for command in commands)
            self.command_preview.setPlainText(command_text)
            lines = max(1, command_text.count("\n") + 1)
            self.command_preview.setFixedHeight(min(96, max(42, lines * 15 + 18)))
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
        layout.setContentsMargins(0, 34, 0, 16)
        layout.setSpacing(0)
        layout.setAlignment(Qt.AlignHCenter | Qt.AlignTop)

        mark = BrandMark(52)
        layout.addWidget(mark, 0, Qt.AlignHCenter)
        layout.addSpacing(16)
        heading = QLabel("开始一次安全测试")
        heading.setObjectName("EmptyHeading")
        heading.setAlignment(Qt.AlignCenter)
        layout.addWidget(heading)
        layout.addSpacing(6)
        sub = QLabel(
            "设置目标提示，或直接为当前对话开启完全权限，让 SSsec 完成信息收集、验证与记录。"
        )
        sub.setObjectName("PageSub")
        sub.setAlignment(Qt.AlignCenter)
        sub.setWordWrap(True)
        layout.addWidget(sub)
        layout.addSpacing(20)

        scope_card = QFrame()
        scope_card.setObjectName("Card")
        scope_layout = QHBoxLayout(scope_card)
        scope_layout.setContentsMargins(12, 10, 12, 10)
        scope_layout.setSpacing(10)
        authorized = bool(conversation and conversation.scope)
        full_access = bool(conversation and conversation.full_permission)

        badge = tone_badge(
            "bolt" if full_access else ("shield" if authorized else "target"),
            "red" if full_access else ("green" if authorized else "accent"),
            size=28,
            icon_size=16,
        )
        scope_layout.addWidget(badge, 0, Qt.AlignVCenter)
        text_layout = QVBoxLayout()
        text_layout.setSpacing(1)
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
        scope_button = QPushButton("编辑" if (authorized or full_access) else "设置")
        scope_button.setObjectName("Secondary")
        scope_button.clicked.connect(self.scope_requested.emit)
        scope_layout.addWidget(scope_button)
        layout.addWidget(scope_card)
        layout.addSpacing(18)

        caption = caption_label("可以这样开始")
        layout.addWidget(caption)
        layout.addSpacing(6)
        suggestions = [
            ("梳理测试计划", "根据测试目标制定低影响、可回滚的测试步骤", "layers", "accent"),
            ("只读信息收集", "查询 DNS、HTTP 与常见端口连通性", "globe", "cyan"),
            ("检查 HTTP 安全响应头", "识别缺失的安全头并给出修复建议", "shield", "green"),
        ]
        for title, subtitle, icon_name, tone in suggestions:
            card = SuggestionCard(title, subtitle, icon_name=icon_name, tone=tone)
            card.clicked.connect(
                lambda _checked=False, text=f"{title}：{subtitle}": self.prompt_selected.emit(
                    text
                )
            )
            layout.addWidget(card)
            layout.addSpacing(6)

        layout.addSpacing(12)
        if demo_mode:
            demo_row = QHBoxLayout()
            demo_row.setSpacing(6)
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
        self.setMinimumWidth(600)
        self.setMaximumWidth(680)


__all__ = [
    "ApprovalBar",
    "AssistantMessageWidget",
    "EmptyState",
    "ToolCallCard",
    "UserMessageWidget",
]
