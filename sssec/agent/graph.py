"""LangGraph Agent：流式模型节点、工具节点与人工审批中断。"""

from __future__ import annotations

import json
import time
import uuid
from typing import Annotated, Any, TypedDict

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    AnyMessage,
    BaseMessage,
    SystemMessage,
    ToolMessage,
)
from langchain_core.messages import message_chunk_to_message
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.types import interrupt

from sssec.agent.llm import (
    build_chat_model,
    extract_reasoning,
    extract_text,
)
from sssec.agent.runtime import AgentContext
from sssec.agent.tools import _result_ok, build_tools, truncate_middle


class AgentState(TypedDict, total=False):
    messages: Annotated[list[AnyMessage], add_messages]
    approval: dict[str, Any] | None


APPROVAL_REASON = {
    "run_command": "命令执行需要在操作员确认后运行",
    "http_request": "网络探测请求需要操作员确认",
    "dns_lookup": "DNS 查询需要操作员确认",
    "tcp_probe": "端口探测需要操作员确认",
    "save_finding": "写入测试发现需要操作员确认",
}


def _json_safe(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, default=str))
    except Exception:
        return str(value)


def _tool_call_payload(call: dict[str, Any], requires_approval: bool) -> dict[str, Any]:
    return {
        "id": str(call.get("id") or uuid.uuid4().hex),
        "name": str(call.get("name") or "unknown_tool"),
        "args": _json_safe(call.get("args") or {}),
        "requires_approval": requires_approval,
    }


def _ensure_call_ids(message: AIMessage) -> None:
    for index, call in enumerate(message.tool_calls or []):
        if not call.get("id"):
            call["id"] = f"call_{uuid.uuid4().hex[:16]}_{index}"


def compile_agent(
    ctx: AgentContext,
    *,
    model: BaseChatModel | None = None,
    checkpointer: BaseCheckpointSaver | None = None,
):
    tools = build_tools(ctx)
    tool_by_name = {item.name: item for item in tools}
    base_model = model or build_chat_model(
        ctx.provider, ctx.settings.safety, streaming=True
    )
    # 记录到上下文，Worker 在事件循环关闭前会显式关闭底层 HTTP 客户端。
    ctx.model = base_model
    bound_model = base_model.bind_tools(tools)

    async def agent_node(state: AgentState) -> dict[str, Any]:
        messages: list[BaseMessage] = [
            SystemMessage(content=ctx.system_prompt),
            *state["messages"],
        ]
        aggregate = None
        try:
            async for chunk in bound_model.astream(messages):
                if aggregate is None:
                    aggregate = chunk
                else:
                    aggregate = aggregate + chunk
                text = extract_text(getattr(chunk, "content", ""))
                if text:
                    ctx.emit_text(text)
                reasoning = extract_reasoning(chunk)
                if reasoning:
                    ctx.emit_reasoning(reasoning)
        except Exception:
            raise
        if aggregate is None:
            raise RuntimeError("模型没有返回任何内容")
        message = message_chunk_to_message(aggregate)
        if not isinstance(message, AIMessage):
            message = AIMessage(content=extract_text(getattr(message, "content", "")))
        _ensure_call_ids(message)
        return {"messages": [message]}

    def route_after_agent(state: AgentState) -> str:
        last = state["messages"][-1] if state.get("messages") else None
        if not isinstance(last, AIMessage) or not last.tool_calls:
            return END
        if any(
            ctx.requires_approval(
                str(call.get("name") or ""),
                call.get("args") if isinstance(call.get("args"), dict) else {},
            )
            for call in last.tool_calls
        ):
            return "approval"
        return "tools"

    def approval_node(state: AgentState) -> dict[str, Any]:
        last = state["messages"][-1]
        calls = [
            _tool_call_payload(
                call,
                ctx.requires_approval(
                    str(call.get("name") or ""),
                    call.get("args") if isinstance(call.get("args"), dict) else {},
                ),
            )
            for call in (last.tool_calls or [])
        ]
        payload = {
            "type": "approval_required",
            "calls": calls,
            "reason": "本轮工具调用包含敏感操作，请核对后决定是否执行。",
        }
        decision = interrupt(payload)
        if not isinstance(decision, dict):
            decision = {"approved": bool(decision)}
        return {"approval": decision}

    async def tools_node(state: AgentState) -> dict[str, Any]:
        last = state["messages"][-1]
        approval = state.get("approval") or {}
        approved = bool(approval.get("approved"))
        calls = list(last.tool_calls or [])
        gate_needed = any(
            ctx.requires_approval(
                str(call.get("name") or ""),
                call.get("args") if isinstance(call.get("args"), dict) else {},
            )
            for call in calls
        )
        if gate_needed:
            ctx.audit.write(
                "approval_decision",
                approved=approved,
                calls=[
                    {
                        "name": call.get("name"),
                        "args": call.get("args"),
                        "id": call.get("id"),
                    }
                    for call in calls
                ],
            )
        deny_all = gate_needed and not approved
        tool_messages: list[ToolMessage] = []
        for call in calls:
            call_id = str(call.get("id") or uuid.uuid4().hex)
            name = str(call.get("name") or "unknown_tool")
            args = call.get("args") if isinstance(call.get("args"), dict) else {}
            requires = ctx.requires_approval(name, args)
            started = time.perf_counter()
            if deny_all:
                denied = json.dumps(
                    {
                        "ok": False,
                        "error": "操作员拒绝了本轮工具调用。请停止该操作，并向用户说明。",
                        "denied": True,
                    },
                    ensure_ascii=False,
                )
                ctx.emit_tool_finished(call_id, name, "denied", denied, 0)
                ctx.audit.write(
                    "tool_denied",
                    tool=name,
                    args=args,
                    call_id=call_id,
                )
                tool_messages.append(
                    ToolMessage(
                        content=denied,
                        tool_call_id=call_id,
                        name=name,
                        status="error",
                    )
                )
                continue

            ctx.emit_tool_started(call_id, name, args, requires)
            ctx.audit.write("tool_call", tool=name, args=args, call_id=call_id)
            target_tool = tool_by_name.get(name)
            if target_tool is None:
                error = json.dumps(
                    {"ok": False, "error": f"工具不可用或不存在：{name}"},
                    ensure_ascii=False,
                )
                duration = int((time.perf_counter() - started) * 1000)
                ctx.emit_tool_finished(call_id, name, "error", error, duration)
                ctx.audit.write(
                    "tool_result",
                    tool=name,
                    status="error",
                    duration_ms=duration,
                )
                tool_messages.append(
                    ToolMessage(
                        content=error,
                        tool_call_id=call_id,
                        name=name,
                        status="error",
                    )
                )
                continue

            ctx.command_approved = approved or not requires
            try:
                raw_result = await target_tool.ainvoke(args)
                result = (
                    raw_result
                    if isinstance(raw_result, str)
                    else json.dumps(raw_result, ensure_ascii=False, default=str)
                )
                result = truncate_middle(result)
                status = "done" if _result_ok(result) else "error"
            except Exception as exc:
                result = json.dumps(
                    {
                        "ok": False,
                        "error": f"{type(exc).__name__}: {str(exc)[:800]}",
                    },
                    ensure_ascii=False,
                )
                status = "error"
            finally:
                ctx.command_approved = False
            duration = int((time.perf_counter() - started) * 1000)
            ctx.emit_tool_finished(call_id, name, status, result, duration)
            ctx.audit.write(
                "tool_result",
                tool=name,
                call_id=call_id,
                status=status,
                duration_ms=duration,
                result_preview=result[:1500],
            )
            tool_messages.append(
                ToolMessage(
                    content=result,
                    tool_call_id=call_id,
                    name=name,
                    status="success" if status == "done" else "error",
                )
            )
        return {"messages": tool_messages, "approval": None}

    builder = StateGraph(AgentState)
    builder.add_node("agent", agent_node)
    builder.add_node("approval", approval_node)
    builder.add_node("tools", tools_node)
    builder.add_edge(START, "agent")
    builder.add_conditional_edges(
        "agent",
        route_after_agent,
        {"approval": "approval", "tools": "tools", END: END},
    )
    builder.add_edge("approval", "tools")
    builder.add_edge("tools", "agent")
    return builder.compile(checkpointer=checkpointer or InMemorySaver())


__all__ = ["AgentState", "compile_agent"]
