"""模型流式输出到 UI 的公共逻辑。

指挥官、阶段子图与离线演示图都需要把模型的增量文本/推理发送给界面，
这里只保留一份实现，避免三处重复。
"""

from __future__ import annotations

import json
import uuid

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    ToolMessage,
    message_chunk_to_message,
)

from sssec.agent.llm import extract_reasoning, extract_text
from sssec.agent.runtime import AgentContext


def ensure_call_ids(message: AIMessage) -> None:
    """为缺失或重复 ID 的 tool_call 补一个稳定 ID，便于 UI 与 ToolMessage 对应。"""
    seen: set[str] = set()
    for index, call in enumerate(message.tool_calls or []):
        call_id = str(call.get("id") or "").strip()
        if not call_id or call_id in seen:
            call_id = f"call_{uuid.uuid4().hex[:16]}_{index}"
            call["id"] = call_id
        seen.add(call_id)


async def stream_reply(
    model: BaseChatModel,
    messages: list[BaseMessage],
    ctx: AgentContext,
) -> AIMessage:
    """流式调用模型，把增量转发给 UI，并返回聚合后的 AIMessage。"""
    aggregate = None
    reasoning_parts: list[str] = []
    async for chunk in model.astream(messages):
        if aggregate is None:
            aggregate = chunk
        else:
            aggregate = aggregate + chunk
        text = extract_text(getattr(chunk, "content", ""))
        if text:
            ctx.emit_text(text)
        reasoning = extract_reasoning(chunk)
        if reasoning:
            reasoning_parts.append(reasoning)
            ctx.emit_reasoning(reasoning)

    if aggregate is None:
        raise RuntimeError("模型没有返回任何内容")

    message = message_chunk_to_message(aggregate)
    if not isinstance(message, AIMessage):
        message = AIMessage(content=extract_text(getattr(message, "content", "")))
    if not message.id:
        message.id = f"ai_{uuid.uuid4().hex}"
    if reasoning_parts:
        # DeepSeek 等 thinking 模型要求下一轮把 reasoning_content 原样带回；
        # 单独聚合，避免 chunk 合并时丢失或重复。
        message.additional_kwargs["reasoning_content"] = "".join(reasoning_parts)
    ensure_call_ids(message)
    return message


def sanitize_messages(messages: list[BaseMessage]) -> list[BaseMessage]:
    """修复不完整的 tool-call 历史。

    OpenAI/DeepSeek 要求一条带 ``tool_calls`` 的 assistant 消息后面紧跟
    每个 ``tool_call_id`` 对应的 tool 消息。以下情况会破坏这个约束：

    * 子 Agent 达到轮次上限，模型返回的 tool_calls 没有执行；
    * 用户取消/审批中断，部分工具没有结果；
    * 历史窗口裁剪后只剩部分 ToolMessage。

    这里为缺失的调用补一条“未执行”的 ToolMessage，并丢弃孤立的 ToolMessage，
    避免下一轮模型请求直接 400。
    """
    result: list[BaseMessage] = []
    index = 0
    total = len(messages)
    while index < total:
        message = messages[index]
        if isinstance(message, ToolMessage):
            # 孤立的 tool 结果（前面没有对应 assistant tool_calls）不能发给模型。
            index += 1
            continue
        result.append(message)
        if not isinstance(message, AIMessage) or not message.tool_calls:
            index += 1
            continue

        expected: list[str] = []
        names: dict[str, str] = {}
        for call_index, call in enumerate(message.tool_calls):
            call_id = str(call.get("id") or "").strip()
            if not call_id:
                call_id = f"call_{uuid.uuid4().hex[:16]}_{call_index}"
                call["id"] = call_id
            if not call_id or call_id in expected:
                continue
            expected.append(call_id)
            names[call_id] = str(call.get("name") or "unknown_tool")

        found: dict[str, ToolMessage] = {}
        cursor = index + 1
        while cursor < total and isinstance(messages[cursor], ToolMessage):
            tool_message = messages[cursor]
            tool_id = str(getattr(tool_message, "tool_call_id", "") or "")
            if tool_id in expected and tool_id not in found:
                found[tool_id] = tool_message
            cursor += 1

        for call_id in expected:
            if call_id in found:
                result.append(found[call_id])
                continue
            result.append(
                ToolMessage(
                    content=json.dumps(
                        {
                            "ok": False,
                            "error": "该工具调用未执行（达到阶段轮次上限、审批中断或运行被取消）。",
                        },
                        ensure_ascii=False,
                    ),
                    tool_call_id=call_id,
                    name=names.get(call_id, "unknown_tool"),
                    status="error",
                    id=f"tool_{uuid.uuid4().hex}",
                )
            )
        index = cursor
    return result


__all__ = ["ensure_call_ids", "sanitize_messages", "stream_reply"]
