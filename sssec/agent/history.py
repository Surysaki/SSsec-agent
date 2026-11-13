"""把 SSsec 的会话数据还原成 LangChain 消息，用于下一轮上下文。"""

from __future__ import annotations

import uuid

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolMessage

from sssec.models import Conversation, message_text

_MAX_TOOL_RESULT_CHARS = 6000


def conversation_to_messages(
    conversation: Conversation, max_messages: int = 40
) -> list[BaseMessage]:
    selected = conversation.messages[-max(1, max_messages) :]
    # 历史从用户消息开始，避免首条是孤立的工具结果。
    while selected and selected[0].get("role") != "user":
        selected = selected[1:]

    result: list[BaseMessage] = []
    for message in selected:
        role = message.get("role")
        if role == "user":
            text = str(message.get("content") or "").strip()
            if text:
                message_id = str(message.get("id") or "").strip()
                result.append(
                    HumanMessage(
                        content=text,
                        **({"id": message_id} if message_id else {}),
                    )
                )
            continue
        if role != "assistant":
            continue
        result.extend(_assistant_to_messages(message))
    return result


def _assistant_to_messages(message: dict) -> list[BaseMessage]:
    segments = message.get("segments") or []
    message_id = str(message.get("id") or "").strip() or f"assistant_{uuid.uuid4().hex}"
    if not segments:
        text = message_text(message).strip()
        return (
            [AIMessage(content=text, id=f"{message_id}:text")]
            if text
            else []
        )

    messages: list[BaseMessage] = []
    pending_text: list[str] = []
    pending_reasoning: list[str] = []
    index = 0
    total = len(segments)

    while index < total:
        segment = segments[index]
        seg_type = segment.get("type")
        if seg_type == "text":
            pending_text.append(str(segment.get("text") or ""))
            index += 1
            continue
        if seg_type == "reasoning":
            # 指挥官决策不是模型返回的 reasoning_content，不能回传给 API。
            if not segment.get("commander"):
                pending_reasoning.append(str(segment.get("text") or ""))
            index += 1
            continue
        if seg_type != "tool":
            index += 1
            continue

        group: list[dict] = []
        cursor = index
        while cursor < total and segments[cursor].get("type") == "tool":
            tool = segments[cursor].get("tool") or {}
            if tool.get("status") in ("done", "error", "denied") and tool.get("id"):
                group.append(tool)
            cursor += 1

        if not group:
            index = cursor
            continue

        unique_group: list[dict] = []
        seen_ids: set[str] = set()
        for tool in group:
            tool_id = str(tool.get("id") or "")
            if not tool_id or tool_id in seen_ids:
                continue
            seen_ids.add(tool_id)
            unique_group.append(tool)
        group = unique_group
        if not group:
            index = cursor
            continue

        tool_calls = []
        for tool in group:
            tool_calls.append(
                {
                    "name": str(tool.get("name") or "unknown_tool"),
                    "args": tool.get("args") or {},
                    "id": str(tool.get("id")),
                    "type": "tool_call",
                }
            )
        text = "".join(pending_text).strip()
        reasoning = "".join(pending_reasoning).strip()
        extra = {"reasoning_content": reasoning} if reasoning else None
        messages.append(
            AIMessage(
                content=text,
                tool_calls=tool_calls,
                id=f"{message_id}:ai:{index}",
                additional_kwargs=extra or {},
            )
        )
        pending_text = []
        pending_reasoning = []
        for tool in group:
            content = str(tool.get("result") or tool.get("error") or "")
            if len(content) > _MAX_TOOL_RESULT_CHARS:
                content = content[:_MAX_TOOL_RESULT_CHARS] + "\n…（结果已截断）"
            messages.append(
                ToolMessage(
                    content=content,
                    tool_call_id=str(tool.get("id")),
                    name=str(tool.get("name") or "unknown_tool"),
                    status="error" if tool.get("status") in ("error", "denied") else "success",
                    id=f"{message_id}:tool:{tool.get('id')}",
                )
            )
        index = cursor

    if pending_text or pending_reasoning:
        text = "".join(pending_text).strip()
        reasoning = "".join(pending_reasoning).strip()
        if text or reasoning:
            messages.append(
                AIMessage(
                    content=text,
                    id=f"{message_id}:tail",
                    additional_kwargs=(
                        {"reasoning_content": reasoning} if reasoning else {}
                    ),
                )
            )
    return messages


__all__ = ["conversation_to_messages"]
