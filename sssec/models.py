"""会话、消息与测试发现的本地数据模型。"""

from __future__ import annotations

import copy
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

DEFAULT_TITLE = "新对话"
TOOL_PENDING_STATUSES = {"pending", "awaiting_approval", "running"}
TOOL_FINAL_STATUSES = {"done", "error", "denied", "cancelled"}
SEVERITIES = {
    "critical": "严重",
    "high": "高危",
    "medium": "中危",
    "low": "低危",
    "info": "信息",
}


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def new_id() -> str:
    return uuid.uuid4().hex


def format_local_time(value: str, fmt: str = "%m-%d %H:%M") -> str:
    try:
        return datetime.fromisoformat(value).strftime(fmt)
    except Exception:
        return ""


def relative_time(value: str) -> str:
    try:
        dt = datetime.fromisoformat(value)
        if dt.tzinfo is None:
            dt = dt.astimezone()
        now = datetime.now().astimezone()
        seconds = max(0, int((now - dt).total_seconds()))
        if seconds < 60:
            return "刚刚"
        if seconds < 3600:
            return f"{seconds // 60} 分钟前"
        if seconds < 86400 and dt.date() == now.date():
            return f"{seconds // 3600} 小时前"
        if dt.date() == now.date():
            return dt.strftime("%H:%M")
        if (now.date() - dt.date()).days == 1:
            return "昨天"
        if dt.year == now.year:
            return dt.strftime("%m-%d")
        return dt.strftime("%Y-%m-%d")
    except Exception:
        return ""


def title_from_text(text: str) -> str:
    cleaned = re.sub(r"[#>*_`~\[\]()]", "", text or "")
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    if not cleaned:
        return DEFAULT_TITLE
    if len(cleaned) > 34:
        cleaned = cleaned[:34].rstrip() + "…"
    return cleaned


def new_user_message(content: str) -> dict[str, Any]:
    return {
        "id": new_id(),
        "role": "user",
        "content": content,
        "created_at": now_iso(),
        "segments": [],
        "status": "complete",
        "error": None,
    }


def new_assistant_message(model_label: str) -> dict[str, Any]:
    return {
        "id": new_id(),
        "role": "assistant",
        "content": "",
        "created_at": now_iso(),
        "segments": [],
        "status": "streaming",
        "error": None,
        "model": model_label,
    }


def new_tool_segment(
    call_id: str,
    name: str,
    args: dict[str, Any] | None = None,
    requires_approval: bool = False,
    status: str = "pending",
) -> dict[str, Any]:
    return {
        "type": "tool",
        "tool": {
            "id": call_id,
            "name": name,
            "args": args or {},
            "status": status,
            "result": "",
            "error": None,
            "requires_approval": requires_approval,
            "started_at": None,
            "finished_at": None,
            "duration_ms": None,
        },
    }


def message_text(message: dict[str, Any]) -> str:
    if message.get("role") == "user":
        return str(message.get("content") or "")
    parts: list[str] = []
    for segment in message.get("segments") or []:
        if segment.get("type") == "text":
            parts.append(str(segment.get("text") or ""))
    if not parts:
        return str(message.get("content") or "")
    return "".join(parts).strip()


def assistant_text(message: dict[str, Any]) -> str:
    return message_text(message)


def append_text(
    message: dict[str, Any],
    text: str,
    kind: str = "text",
    *,
    commander: bool = False,
) -> None:
    if not text:
        return
    seg_type = "reasoning" if kind == "reasoning" else "text"
    is_commander = bool(commander and seg_type == "reasoning")
    segments = message.setdefault("segments", [])
    if (
        segments
        and segments[-1].get("type") == seg_type
        and bool(segments[-1].get("commander")) == is_commander
    ):
        segments[-1]["text"] = str(segments[-1].get("text") or "") + text
    else:
        segment: dict[str, Any] = {"type": seg_type, "text": text}
        if is_commander:
            segment["commander"] = True
        segments.append(segment)
    if seg_type == "text":
        message["content"] = assistant_text(message)


def find_tool(message: dict[str, Any], call_id: str) -> dict[str, Any] | None:
    for segment in message.get("segments") or []:
        if segment.get("type") == "tool" and segment.get("tool", {}).get("id") == call_id:
            return segment["tool"]
    return None


def ensure_tool(
    message: dict[str, Any],
    call_id: str,
    name: str,
    args: dict[str, Any] | None = None,
    requires_approval: bool = False,
    status: str = "pending",
) -> dict[str, Any]:
    existing = find_tool(message, call_id)
    if existing:
        if args and not existing.get("args"):
            existing["args"] = args
        return existing
    segment = new_tool_segment(call_id, name, args, requires_approval, status)
    message.setdefault("segments", []).append(segment)
    return segment["tool"]


def add_finding(conversation: "Conversation", data: dict[str, Any]) -> dict[str, Any]:
    severity = str(data.get("severity") or "info").lower()
    if severity not in SEVERITIES:
        severity = "info"
    finding = {
        "id": data.get("id") or new_id(),
        "title": str(data.get("title") or "未命名发现"),
        "severity": severity,
        "target": str(data.get("target") or ""),
        "description": str(data.get("description") or ""),
        "evidence": str(data.get("evidence") or ""),
        "created_at": data.get("created_at") or now_iso(),
    }
    existing_ids = {item.get("id") for item in conversation.findings}
    if finding["id"] not in existing_ids:
        conversation.findings.append(finding)
    conversation.updated_at = now_iso()
    return finding


@dataclass
class Conversation:
    id: str
    title: str = DEFAULT_TITLE
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)
    scope: list[str] = field(default_factory=list)
    authorized: bool = False
    full_permission: bool = False
    messages: list[dict[str, Any]] = field(default_factory=list)
    findings: list[dict[str, Any]] = field(default_factory=list)

    def touch(self) -> None:
        self.updated_at = now_iso()

    def add_user(self, content: str) -> dict[str, Any]:
        message = new_user_message(content)
        self.messages.append(message)
        if self.title == DEFAULT_TITLE:
            self.title = title_from_text(content)
        self.touch()
        return message

    def add_assistant(self, model_label: str) -> dict[str, Any]:
        message = new_assistant_message(model_label)
        self.messages.append(message)
        self.touch()
        return message

    def message_by_id(self, message_id: str) -> dict[str, Any] | None:
        return next((m for m in self.messages if m.get("id") == message_id), None)

    def last_assistant(self) -> dict[str, Any] | None:
        for message in reversed(self.messages):
            if message.get("role") == "assistant":
                return message
        return None

    def preview(self) -> str:
        for message in reversed(self.messages):
            text = message_text(message)
            if text:
                text = re.sub(r"^#{1,6}\s*", "", text, flags=re.MULTILINE)
                text = re.sub(r"^\s*[-+*]\s+", "", text, flags=re.MULTILINE)
                text = re.sub(r"[*_`~]{1,3}", "", text)
                text = re.sub(r"\s+", " ", text).strip()
                return text[:60] + ("…" if len(text) > 60 else "")
        if self.findings:
            return f"{len(self.findings)} 条测试发现"
        return "空白对话"

    def has_active_approval(self) -> bool:
        for message in self.messages:
            for segment in message.get("segments") or []:
                if (
                    segment.get("type") == "tool"
                    and segment.get("tool", {}).get("status") == "awaiting_approval"
                ):
                    return True
        return False

    def clone(self) -> "Conversation":
        return Conversation.from_dict(copy.deepcopy(self.to_dict()))

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
            "id": self.id,
            "title": self.title,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "scope": list(self.scope),
            "authorized": self.authorized,
            "full_permission": self.full_permission,
            "messages": copy.deepcopy(self.messages),
            "findings": copy.deepcopy(self.findings),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Conversation":
        scope = [str(x) for x in (data.get("scope") or []) if str(x).strip()]
        messages = [m for m in (data.get("messages") or []) if isinstance(m, dict)]
        for message in messages:
            message.setdefault("segments", [])
            message.setdefault("content", "")
            message.setdefault("status", "complete")
            message.setdefault("error", None)
        conversation = cls(
            id=str(data.get("id") or new_id()),
            title=str(data.get("title") or DEFAULT_TITLE),
            created_at=str(data.get("created_at") or now_iso()),
            updated_at=str(data.get("updated_at") or now_iso()),
            scope=scope[:200],
            authorized=bool(data.get("authorized")),
            full_permission=bool(data.get("full_permission")),
            messages=messages,
            findings=[f for f in (data.get("findings") or []) if isinstance(f, dict)],
        )
        if not conversation.authorized or not conversation.scope:
            conversation.authorized = bool(
                conversation.authorized and conversation.scope
            )
        return conversation

    @classmethod
    def create(cls, title: str = DEFAULT_TITLE) -> "Conversation":
        return cls(id=new_id(), title=title or DEFAULT_TITLE)


def repair_interrupted_messages(conversation: Conversation) -> bool:
    """应用异常退出后，把半成品消息标记为中断，避免 UI 永远显示运行中。"""
    changed = False
    for message in conversation.messages:
        if message.get("role") != "assistant":
            continue
        if message.get("status") in ("streaming", "awaiting_approval"):
            message["status"] = "error"
            message["error"] = "应用退出，本次生成已中断。"
            changed = True
        for segment in message.get("segments") or []:
            if segment.get("type") != "tool":
                continue
            tool = segment.get("tool") or {}
            if tool.get("status") in TOOL_PENDING_STATUSES:
                tool["status"] = "cancelled"
                tool["finished_at"] = tool.get("finished_at") or now_iso()
                changed = True
    return changed


__all__ = [
    "DEFAULT_TITLE",
    "SEVERITIES",
    "Conversation",
    "add_finding",
    "append_text",
    "assistant_text",
    "ensure_tool",
    "find_tool",
    "format_local_time",
    "message_text",
    "new_assistant_message",
    "new_tool_segment",
    "new_user_message",
    "relative_time",
    "repair_interrupted_messages",
    "title_from_text",
]
