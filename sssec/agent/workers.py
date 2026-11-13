"""渗透测试阶段子图（Subgraph）。

每个阶段都是一个独立的 LangGraph 子图：

    START → agent → (approval?) → tools → agent → … → END

子图通过 ``handoff`` 工具把控制权交回指挥官；由于使用与父图相同的
``PentestState``，子图的 ``interrupt()`` 会自然冒泡到父图，由
``AgentWorker`` 统一处理审批。
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)
from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from sssec.agent.prompts import (
    build_final_solver_prompt,
    build_single_continue_prompt,
    build_single_prompt,
    build_worker_prompt,
)
from sssec.agent.runtime import AgentContext
from sssec.agent.state import (
    HANDOFF_TARGETS,
    WORKER_LABELS,
    PentestState,
)
from sssec.agent.stream import sanitize_messages, stream_reply
from sssec.agent.toolkit import extract_flags
from sssec.agent.tools import _result_ok, build_tools, build_worker_tools, truncate_middle


# 单 Agent 第一次尝试中，模型提前收尾时最多强制补做几轮深挖。
# 只作用于 single 图，不影响 team/final 的调度。
MAX_SINGLE_CONTINUATIONS = 2


@dataclass(frozen=True)
class WorkerSpec:
    name: str
    label: str
    tool_names: tuple[str, ...]
    max_rounds: int = 6


def worker_round_budget(spec_max: int, bonus: int, configured: int) -> int:
    """阶段轮次 = min(阶段基础值 + 重试加成, 全局配置)，至少 1。"""
    return max(1, min(max(1, spec_max) + max(0, bonus), max(1, configured)))


WORKER_SPECS: dict[str, WorkerSpec] = {
    "recon": WorkerSpec(
        name="recon",
        label=WORKER_LABELS["recon"],
        tool_names=(
            "http_probe",
            "http_request",
            "dns_lookup",
            "dns_zone_transfer",
            "port_scan",
            "subdomain_enum",
            "dir_scan",
            "web_crawl",
            "whois_lookup",
            "tls_certificate",
            "api_discover",
            "workspace_list",
            "workspace_read",
            "flag_hunt",
            "save_finding",
        ),
    ),
    "vuln_analysis": WorkerSpec(
        name="vuln_analysis",
        label=WORKER_LABELS["vuln_analysis"],
        tool_names=(
            "http_request",
            "http_raw",
            "http_upload",
            "security_headers",
            "param_fuzz",
            "lfi_probe",
            "ssrf_probe",
            "api_discover",
            "cors_check",
            "jwt_analyze",
            "waf_detect",
            "artifact_scan",
            "codec",
            "crypto_workshop",
            "binary_info",
            "disassemble",
            "file_analyze",
            "run_command",
            "workspace_list",
            "workspace_read",
            "workspace_write",
            "flag_hunt",
            "save_finding",
        ),
    ),
    "exploit": WorkerSpec(
        name="exploit",
        label=WORKER_LABELS["exploit"],
        tool_names=(
            "http_request",
            "http_raw",
            "http_upload",
            "security_headers",
            "param_fuzz",
            "lfi_probe",
            "ssrf_probe",
            "api_discover",
            "payload_forge",
            "codec",
            "tcp_exchange",
            "binary_info",
            "disassemble",
            "run_command",
            "workspace_list",
            "workspace_read",
            "workspace_write",
            "flag_hunt",
            "save_finding",
        ),
        max_rounds=8,
    ),
    "post_exploit": WorkerSpec(
        name="post_exploit",
        label=WORKER_LABELS["post_exploit"],
        tool_names=(
            "run_command",
            "webshell_client",
            "archive_extract",
            "artifact_scan",
            "file_analyze",
            "disassemble",
            "http_request",
            "http_raw",
            "workspace_list",
            "workspace_read",
            "workspace_write",
            "flag_hunt",
            "save_finding",
        ),
        max_rounds=6,
    ),
    "reverse": WorkerSpec(
        name="reverse",
        label=WORKER_LABELS["reverse"],
        tool_names=(
            "binary_info",
            "disassemble",
            "file_analyze",
            "crypto_workshop",
            "codec",
            "run_command",
            "tcp_exchange",
            "archive_extract",
            "artifact_scan",
            "workspace_list",
            "workspace_read",
            "workspace_write",
            "flag_hunt",
            "save_finding",
        ),
        max_rounds=8,
    ),
}


def _recent_messages(messages: list[BaseMessage], limit: int) -> list[BaseMessage]:
    """截取最近一段合法的消息窗口，并修复不完整的 tool-call 历史。"""
    selected = list(messages[-max(4, int(limit or 40)) :])
    while selected and isinstance(selected[0], ToolMessage):
        selected.pop(0)
    return sanitize_messages(selected)


def _tool_call_payload(call: dict[str, Any], requires_approval: bool) -> dict[str, Any]:
    return {
        "id": str(call.get("id") or uuid.uuid4().hex),
        "name": str(call.get("name") or "unknown_tool"),
        "args": _json_safe(call.get("args") or {}),
        "requires_approval": requires_approval,
    }


def _json_safe(value: Any) -> Any:
    try:
        return json.loads(json.dumps(value, ensure_ascii=False, default=str))
    except Exception:
        return str(value)


def _handoff_from_args(args: dict[str, Any]) -> dict[str, Any] | None:
    target = str(args.get("next_agent") or "").strip()
    if target not in HANDOFF_TARGETS:
        return None
    task = str(args.get("task") or "").strip()
    if target != "finish" and not task:
        return None
    return {
        "next_agent": target,
        "task": task[:4000],
        "reason": str(args.get("reason") or "").strip()[:1000],
        "summary": str(args.get("summary") or "").strip()[:4000],
    }


def _count_flags(messages: list[BaseMessage]) -> int:
    """统计当前上下文里已经出现的不同 flag，用于决定是否继续深挖。"""
    seen: set[str] = set()
    for message in messages:
        if not isinstance(message, (AIMessage, ToolMessage)):
            continue
        content = getattr(message, "content", "")
        if isinstance(content, list):
            content = " ".join(str(item) for item in content)
        for flag in extract_flags(str(content)):
            seen.add(flag.lower())
    return len(seen)


def compile_worker(
    ctx: AgentContext,
    spec: WorkerSpec,
    base_model: BaseChatModel,
    *,
    include_handoff: bool = True,
    checkpointer: Any = None,
):
    """编译一个阶段子图。"""
    tools = (
        build_worker_tools(ctx, spec.tool_names)
        if include_handoff
        else build_tools(ctx, spec.tool_names)
    )
    tool_by_name = {item.name: item for item in tools}
    tool_names = [item.name for item in tools]
    bound_model = base_model.bind_tools(tools)
    bonus = max(0, int(getattr(ctx, "round_bonus", 0) or 0))
    configured_rounds = int(
        ctx.settings.safety.max_tool_rounds or (spec.max_rounds + bonus)
    )
    if spec.name == "final":
        configured_rounds = max(configured_rounds, spec.max_rounds)
    max_rounds = worker_round_budget(spec.max_rounds, bonus, configured_rounds)
    # 单 Agent / 最终突破就是任务级预算；多 Agent 的阶段预算在多次指挥官派发之间
    # 仍保留一个累计上限，避免每次派发都把 worker_rounds 重置成满额。
    total_cap = (
        max_rounds
        if spec.name in {"single", "final"}
        else max(max_rounds, min(16, max_rounds * 2))
    )

    async def agent_node(state: PentestState) -> dict[str, Any]:
        if spec.name == "single":
            system = build_single_prompt(
                ctx.system_prompt,
                task=str(state.get("task") or ""),
                tool_names=tool_names,
                flag_count=max(1, int(getattr(ctx, "target_flags", 1) or 1)),
            )
        elif spec.name == "final":
            system = build_final_solver_prompt(
                ctx.system_prompt,
                task=str(state.get("task") or ""),
                tool_names=tool_names,
            )
        else:
            system = build_worker_prompt(
                ctx.system_prompt,
                worker=spec.name,
                task=str(state.get("task") or ""),
                tool_names=tool_names,
                reports=state.get("worker_reports") or [],
            )
        recent = _recent_messages(
            state.get("messages") or [],
            ctx.settings.safety.max_history_messages,
        )
        message = await stream_reply(
            bound_model,
            [SystemMessage(content=system), *recent],
            ctx,
        )
        totals = dict(state.get("worker_rounds_total") or {})
        totals[spec.name] = int(totals.get(spec.name, 0)) + 1
        return {
            "messages": [message],
            "worker_rounds": int(state.get("worker_rounds") or 0) + 1,
            "worker_rounds_total": totals,
        }

    def route_after_agent(state: PentestState) -> str:
        rounds = int(state.get("worker_rounds") or 0)
        total = int((state.get("worker_rounds_total") or {}).get(spec.name, 0))
        last = (state.get("messages") or [None])[-1]
        if total > total_cap or rounds > max_rounds:
            # 达到轮次上限时如果模型仍返回 tool_calls，必须为每个调用补一条
            # ToolMessage，否则下一轮模型请求会因 tool_calls 没有响应而 400。
            return "close" if isinstance(last, AIMessage) and last.tool_calls else END
        if not isinstance(last, AIMessage) or not last.tool_calls:
            # 单 Agent 第一次尝试：模型提前收尾但还没拿全 flag 时，
            # 不关闭靶场，补一轮“继续深挖”的指令，最多 MAX_SINGLE_CONTINUATIONS 次。
            if spec.name == "single" and rounds < max_rounds:
                found = _count_flags(state.get("messages") or [])
                target = max(1, int(getattr(ctx, "target_flags", 1) or 1))
                if (
                    found < target
                    and int(state.get("single_continue") or 0)
                    < MAX_SINGLE_CONTINUATIONS
                ):
                    return "deepen"
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

    def close_tools_node(state: PentestState) -> dict[str, Any]:
        last = (state.get("messages") or [None])[-1]
        calls = list(getattr(last, "tool_calls", None) or [])
        messages = []
        for call in calls:
            call_id = str(call.get("id") or f"call_{uuid.uuid4().hex[:16]}")
            call["id"] = call_id
            messages.append(
                ToolMessage(
                    id=f"tool_{uuid.uuid4().hex}",
                    content=json.dumps(
                        {
                            "ok": False,
                            "error": f"达到 {spec.label} 的工具轮次上限，该调用未执行。",
                        },
                        ensure_ascii=False,
                    ),
                    tool_call_id=call_id,
                    name=str(call.get("name") or "unknown_tool"),
                    status="error",
                )
            )
        ctx.audit.write(
            "worker_round_limit",
            worker=spec.name,
            calls=[call.get("name") for call in calls],
        )
        return {"messages": messages, "approval": None, "handoff": None}

    def deepen_node(state: PentestState) -> dict[str, Any]:
        """单 Agent 提前收尾但没拿全 flag：不关闭靶场，追加一轮继续深挖。"""
        found = _count_flags(state.get("messages") or [])
        target = max(1, int(getattr(ctx, "target_flags", 1) or 1))
        count = int(state.get("single_continue") or 0) + 1
        text = build_single_continue_prompt(
            task=str(state.get("task") or ""),
            tool_names=tool_names,
            flag_count=target,
            found_flags=found,
            continuation=count,
        )
        ctx.audit.write(
            "single_continue",
            continuation=count,
            found_flags=found,
            target_flags=target,
            max_rounds=max_rounds,
        )
        return {
            "messages": [
                HumanMessage(
                    content=text,
                    id=f"human_continue_{uuid.uuid4().hex}",
                )
            ],
            "single_continue": count,
        }

    def approval_node(state: PentestState) -> dict[str, Any]:
        last = (state.get("messages") or [None])[-1]
        calls = [
            _tool_call_payload(
                call,
                ctx.requires_approval(
                    str(call.get("name") or ""),
                    call.get("args") if isinstance(call.get("args"), dict) else {},
                ),
            )
            for call in (getattr(last, "tool_calls", None) or [])
        ]
        payload = {
            "type": "approval_required",
            "worker": spec.name,
            "worker_label": spec.label,
            "calls": calls,
            "reason": f"{spec.label} 的本轮工具调用需要操作员确认。",
        }
        decision = interrupt(payload)
        if not isinstance(decision, dict):
            decision = {"approved": bool(decision)}
        return {"approval": decision}

    async def tools_node(state: PentestState) -> dict[str, Any]:
        last = (state.get("messages") or [None])[-1]
        approval = state.get("approval") or {}
        approved = bool(approval.get("approved"))
        calls = list(getattr(last, "tool_calls", None) or [])
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
                worker=spec.name,
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
        handoff_payload: dict[str, Any] | None = None

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
                    worker=spec.name,
                    tool=name,
                    args=args,
                    call_id=call_id,
                )
                tool_messages.append(
                    ToolMessage(
                        id=f"tool_{uuid.uuid4().hex}",
                        content=denied,
                        tool_call_id=call_id,
                        name=name,
                        status="error",
                    )
                )
                continue

            ctx.emit_tool_started(call_id, name, args, requires)
            ctx.audit.write(
                "tool_call",
                worker=spec.name,
                tool=name,
                args=args,
                call_id=call_id,
            )

            # handoff 不真正执行外部操作，只记录交接请求并结束当前子图。
            if name == "handoff":
                payload = _handoff_from_args(args)
                if payload is None:
                    result = json.dumps(
                        {
                            "ok": False,
                            "error": "handoff 参数无效：next_agent 必须是 "
                            "recon/vuln_analysis/exploit/post_exploit/finish，"
                            "且非 finish 时 task 不能为空。",
                        },
                        ensure_ascii=False,
                    )
                    status = "error"
                else:
                    handoff_payload = payload
                    result = json.dumps(
                        {"ok": True, "handoff": payload},
                        ensure_ascii=False,
                    )
                    status = "done"
                    ctx.audit.write("handoff", worker=spec.name, **payload)
                duration = int((time.perf_counter() - started) * 1000)
                ctx.emit_tool_finished(call_id, name, status, result, duration)
                ctx.audit.write(
                    "tool_result",
                    worker=spec.name,
                    tool=name,
                    call_id=call_id,
                    status=status,
                    duration_ms=duration,
                    result_preview=result[:1500],
                )
                tool_messages.append(
                    ToolMessage(
                        id=f"tool_{uuid.uuid4().hex}",
                        content=result,
                        tool_call_id=call_id,
                        name=name,
                        status="success" if status == "done" else "error",
                    )
                )
                continue

            target_tool = tool_by_name.get(name)
            if target_tool is None:
                error = json.dumps(
                    {"ok": False, "error": f"当前阶段不可用或不存在该工具：{name}"},
                    ensure_ascii=False,
                )
                duration = int((time.perf_counter() - started) * 1000)
                ctx.emit_tool_finished(call_id, name, "error", error, duration)
                ctx.audit.write(
                    "tool_result",
                    worker=spec.name,
                    tool=name,
                    call_id=call_id,
                    status="error",
                    duration_ms=duration,
                )
                tool_messages.append(
                    ToolMessage(
                        id=f"tool_{uuid.uuid4().hex}",
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
                worker=spec.name,
                tool=name,
                call_id=call_id,
                status=status,
                duration_ms=duration,
                result_preview=result[:1500],
            )
            tool_messages.append(
                ToolMessage(
                    id=f"tool_{uuid.uuid4().hex}",
                    content=result,
                    tool_call_id=call_id,
                    name=name,
                    status="success" if status == "done" else "error",
                )
            )

        return {
            "messages": tool_messages,
            "approval": None,
            "handoff": handoff_payload,
        }

    def route_after_tools(state: PentestState) -> str:
        return END if state.get("handoff") else "agent"

    builder = StateGraph(PentestState)
    builder.add_node("agent", agent_node)
    builder.add_node("deepen", deepen_node)
    builder.add_node("approval", approval_node)
    builder.add_node("tools", tools_node)
    builder.add_node("close", close_tools_node)
    builder.add_edge(START, "agent")
    builder.add_conditional_edges(
        "agent",
        route_after_agent,
        {
            "approval": "approval",
            "tools": "tools",
            "close": "close",
            "deepen": "deepen",
            END: END,
        },
    )
    builder.add_edge("deepen", "agent")
    builder.add_edge("approval", "tools")
    builder.add_conditional_edges(
        "tools",
        route_after_tools,
        {"agent": "agent", END: END},
    )
    builder.add_edge("close", END)
    return builder.compile(name=spec.name, checkpointer=checkpointer)


__all__ = [
    "WORKER_SPECS",
    "WorkerSpec",
    "compile_worker",
]
