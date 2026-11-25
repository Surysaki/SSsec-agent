"""渗透测试阶段子图（Subgraph）。

每个阶段都是一个独立的 LangGraph 子图：

    START → agent → (approval?) → tools → agent → … → END

子图通过 ``handoff`` 工具把控制权交回指挥官；由于使用与父图相同的
``PentestState``，子图的 ``interrupt()`` 会自然冒泡到父图，由
``AgentWorker`` 统一处理审批。
"""

from __future__ import annotations

import hashlib
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

from sssec.agent.llm import extract_text
from sssec.agent.prompts import (
    build_final_solver_prompt,
    build_single_continue_prompt,
    build_single_prompt,
    build_worker_continue_prompt,
    build_worker_prompt,
)
from sssec.agent.runtime import AgentContext
from sssec.agent.state import (
    HANDOFF_TARGETS,
    MAX_LOOP_HINTS,
    MAX_WORKER_CONTINUATIONS,
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


def _evidence_ledger(messages: list[BaseMessage], max_items: int = 60) -> str:
    """把较早的消息压成确定性的“证据账本”，避免放开轮次后撑爆上下文。"""
    lines: list[str] = []
    for message in messages:
        if isinstance(message, ToolMessage):
            content = extract_text(getattr(message, "content", ""))
            content = " ".join(content.split())[:180]
            lines.append(
                f"- {message.name or 'tool'}[{message.status or '?'}]: {content}"
            )
        elif isinstance(message, AIMessage) and message.tool_calls:
            names = ",".join(str(call.get("name") or "?") for call in message.tool_calls)
            lines.append(f"- 调用: {names}")
    if not lines:
        return ""
    lines = lines[-max_items:]
    text = "\n".join(lines)
    if len(text) > 6000:
        text = "…（更早的记录已省略）\n" + text[-6000:]
    return text


def _model_messages(
    messages: list[BaseMessage],
    limit: int,
) -> list[BaseMessage]:
    """给模型的输入：最近原文 + 更早内容的证据账本，保持 tool-call 配对合法。"""
    limit = max(6, int(limit or 80))
    if len(messages) <= limit:
        return _recent_messages(messages, limit)

    recent = list(messages[-limit:])
    while recent and isinstance(recent[0], ToolMessage):
        recent.pop(0)
    older = messages[: len(messages) - len(recent)]
    ledger = _evidence_ledger(older, max_items=80)
    if not ledger:
        return _recent_messages(recent, limit)
    summary = HumanMessage(
        content=(
            "## 更早的操作记录（压缩后的证据账本，仅供回忆，不要当作当前结论）\n"
            + ledger
        ),
        id=f"ledger_{uuid.uuid4().hex[:12]}",
    )
    return sanitize_messages([summary, *recent])


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


def _round_signature(
    calls: list[dict[str, Any]],
    tool_messages: list[ToolMessage],
) -> str:
    """一轮工具调用的指纹：工具名 + 参数 + 结果状态。

    刻意不包含结果正文：``run_command`` 之类的结果里有耗时、时间戳等
    每次都变的字段，带上正文会让“同一个动作反复执行”永远检测不出来。
    """
    args_by_id = {
        str(call.get("id") or ""): call.get("args") or {} for call in calls
    }
    parts: list[str] = []
    for message in tool_messages:
        args = args_by_id.get(str(message.tool_call_id), {})
        try:
            args_text = json.dumps(args, ensure_ascii=False, sort_keys=True)
        except Exception:
            args_text = str(args)
        parts.append(
            "|".join(
                [
                    str(message.name or ""),
                    args_text[:500],
                    str(message.status or ""),
                ]
            )
        )
    if not parts:
        return ""
    return hashlib.sha1("\n".join(parts).encode("utf-8")).hexdigest()


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
    configured_soft = int(ctx.settings.safety.max_tool_rounds or 0)
    # 软预算：只用于提示与进度，不截断阶段。
    soft_rounds = (
        max(spec.max_rounds, configured_soft + bonus)
        if configured_soft
        else spec.max_rounds
    )
    if spec.name in {"single", "final"}:
        soft_rounds = max(soft_rounds, spec.max_rounds + bonus)
    # 安全熔断：真正的兜底，正常任务不应触达。
    hard_stop = int(ctx.settings.safety.hard_stop_rounds or 0)
    loop_guard = max(1, int(ctx.settings.safety.loop_guard or 3))

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
                skills_available=bool(ctx.settings.safety.skills_enabled),
            )
        if soft_rounds and int(state.get("worker_rounds") or 0) >= soft_rounds:
            system += (
                f"\n\n## 进度提示\n本阶段已执行 {int(state.get('worker_rounds') or 0)} 轮，"
                f"超过软预算 {soft_rounds} 轮。不会强制结束，但请优先收敛："
                "换策略、换入口或 handoff，不要重复已经失败的调用。"
            )
        recent = _model_messages(
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
        last = (state.get("messages") or [None])[-1]
        if hard_stop and rounds >= hard_stop:
            # 安全熔断：只有模型持续空转才会触达，属于兜底而非预算。
            ctx.audit.write(
                "worker_brake",
                worker=spec.name,
                rounds=rounds,
                limit=hard_stop,
            )
            return "close" if isinstance(last, AIMessage) and last.tool_calls else END
        if not isinstance(last, AIMessage) or not last.tool_calls:
            # 单 Agent / 最终突破：模型提前收尾但还没拿全 flag 时，补一轮继续深挖。
            if spec.name in {"single", "final"}:
                if rounds < soft_rounds:
                    found = _count_flags(state.get("messages") or [])
                    target = max(1, int(getattr(ctx, "target_flags", 1) or 1))
                    if (
                        found < target
                        and int(state.get("single_continue") or 0)
                        < MAX_SINGLE_CONTINUATIONS
                    ):
                        return "deepen"
                return END
            # 多 Agent：整个派发一次工具都没调用就写总结，视为“空转阶段”，
            # 给它一次明确继续的机会，而不是把这段文本当成阶段完成。
            if (
                int(state.get("worker_tool_calls") or 0) == 0
                and int(state.get("deepen_count") or 0) < MAX_WORKER_CONTINUATIONS
                and not state.get("handoff")
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
                            "error": (
                                f"{spec.label} 已触发安全熔断（{hard_stop} 轮），"
                                "该调用未执行。请收尾并说明当前进展。"
                            ),
                        },
                        ensure_ascii=False,
                    ),
                    tool_call_id=call_id,
                    name=str(call.get("name") or "unknown_tool"),
                    status="error",
                )
            )
        ctx.audit.write(
            "worker_brake_round_limit",
            worker=spec.name,
            calls=[call.get("name") for call in calls],
        )
        return {"messages": messages, "approval": None, "handoff": None, "stalled": True}

    def loop_node(state: PentestState) -> dict[str, Any]:
        """检测到重复调用：注入一次“换策略”指令，而不是直接结束。"""
        streak = int(state.get("loop_streak") or 0)
        hints = int(state.get("loop_hint") or 0) + 1
        ctx.audit.write(
            "worker_loop",
            worker=spec.name,
            streak=streak,
            hint=hints,
        )
        text = (
            f"停一下：你刚才连续 {streak} 次执行了完全相同的操作，结果也相同，"
            "这说明当前路线已经走不通。\n\n"
            "接下来不要重复这个调用，改为：\n"
            "1. 换一个入口/参数/编码/身份/协议，或换一个工具；\n"
            "2. 如果确认这条路线已穷尽，调用 `handoff` 说明卡点与新假设；\n"
            "3. 直接给出下一步的具体工具调用，不要只写总结。"
        )
        return {
            "messages": [
                HumanMessage(content=text, id=f"human_loop_{uuid.uuid4().hex[:12]}")
            ],
            "loop_hint": hints,
            "loop_streak": 0,
        }

    def stalled_node(state: PentestState) -> dict[str, Any]:
        """重复调用且换策略无效：中止当前阶段，把结论交回指挥官。"""
        streak = int(state.get("loop_streak") or 0)
        ctx.audit.write("worker_stalled", worker=spec.name, streak=streak)
        text = (
            f"本阶段已自动中止：检测到连续 {streak} 次重复调用且没有新证据，"
            "换策略提示后仍未改善。已保留现有证据，请指挥官换阶段或换路线。"
        )
        return {
            "messages": [AIMessage(content=text, id=f"ai_{uuid.uuid4().hex}")],
            "stalled": True,
        }

    def deepen_node(state: PentestState) -> dict[str, Any]:
        """模型提前收尾但阶段目标未达成：追加一轮继续指令，不关闭阶段。"""
        if spec.name in {"single", "final"}:
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
                soft_rounds=soft_rounds,
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

        count = int(state.get("deepen_count") or 0) + 1
        text = build_worker_continue_prompt(
            worker=spec.name,
            task=str(state.get("task") or ""),
            tool_names=tool_names,
            reason="本轮没有调用任何工具就准备结束",
        )
        ctx.audit.write(
            "worker_continue",
            worker=spec.name,
            continuation=count,
            rounds=int(state.get("worker_rounds") or 0),
        )
        return {
            "messages": [
                HumanMessage(
                    content=text,
                    id=f"human_worker_continue_{uuid.uuid4().hex}",
                )
            ],
            "deepen_count": count,
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
        loaded_skills = list(state.get("loaded_skills") or [])

        for call in calls:
            call_id = str(call.get("id") or uuid.uuid4().hex)
            name = str(call.get("name") or "unknown_tool")
            args = call.get("args") if isinstance(call.get("args"), dict) else {}
            requires = ctx.requires_approval(name, args)
            started = time.perf_counter()

            if name == "skill_load":
                requested = str(args.get("skill_id") or "").strip()
                max_loaded = max(1, int(ctx.settings.safety.skill_max_loaded or 1))
                if requested and requested not in loaded_skills and len(loaded_skills) >= max_loaded:
                    blocked = json.dumps(
                        {
                            "ok": False,
                            "error": (
                                f"本阶段已加载 {len(loaded_skills)} 张技能卡（{', '.join(loaded_skills)}），"
                                "达到上限。可先 skill_unload(<id>) 释放名额，再加载新的卡。"
                            ),
                            "loaded": loaded_skills,
                            "available": [item.id for item in ctx.skill_store().list()],
                        },
                        ensure_ascii=False,
                    )
                    ctx.emit_tool_finished(call_id, name, "error", blocked, 0)
                    ctx.audit.write(
                        "skill_blocked",
                        worker=spec.name,
                        skill=requested,
                        loaded=loaded_skills,
                    )
                    tool_messages.append(
                        ToolMessage(
                            id=f"tool_{uuid.uuid4().hex}",
                            content=blocked,
                            tool_call_id=call_id,
                            name=name,
                            status="error",
                        )
                    )
                    continue

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
            if name == "skill_load" and status == "done":
                requested = str(args.get("skill_id") or "").strip()
                if requested and requested not in loaded_skills:
                    loaded_skills.append(requested)
                    ctx.audit.write(
                        "skill_loaded",
                        worker=spec.name,
                        skill=requested,
                        chars=len(result),
                    )
            if name == "skill_unload" and status == "done":
                requested = str(args.get("skill_id") or "").strip()
                if requested in loaded_skills:
                    loaded_skills.remove(requested)
                    ctx.audit.write(
                        "skill_unloaded",
                        worker=spec.name,
                        skill=requested,
                    )
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

        history = list(state.get("action_history") or [])
        signature = _round_signature(calls, tool_messages)
        if signature:
            history.append(signature)
        streak = 1
        for previous in reversed(history[:-1]):
            if previous == signature:
                streak += 1
            else:
                break
        return {
            "messages": tool_messages,
            "approval": None,
            "handoff": handoff_payload,
            "action_history": history[-60:],
            "loop_streak": streak if signature else 0,
            "worker_tool_calls": int(state.get("worker_tool_calls") or 0)
            + len(tool_messages),
            "loaded_skills": loaded_skills,
        }

    def route_after_tools(state: PentestState) -> str:
        if state.get("handoff"):
            return END
        streak = int(state.get("loop_streak") or 0)
        hints = int(state.get("loop_hint") or 0)
        if streak >= loop_guard and hints >= MAX_LOOP_HINTS:
            return "stalled"
        if streak >= loop_guard:
            return "loop"
        return "agent"

    builder = StateGraph(PentestState)
    builder.add_node("agent", agent_node)
    builder.add_node("deepen", deepen_node)
    builder.add_node("approval", approval_node)
    builder.add_node("tools", tools_node)
    builder.add_node("close", close_tools_node)
    builder.add_node("loop", loop_node)
    builder.add_node("stalled", stalled_node)
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
        {"agent": "agent", "loop": "loop", "stalled": "stalled", END: END},
    )
    builder.add_edge("loop", "agent")
    builder.add_edge("stalled", END)
    builder.add_edge("close", END)
    return builder.compile(name=spec.name, checkpointer=checkpointer)


__all__ = [
    "WORKER_SPECS",
    "WorkerSpec",
    "compile_worker",
]
