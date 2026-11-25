"""多 Agent 编排：指挥官 Supervisor + 四个渗透阶段子图。

整体结构：

    START → commander ──决定──→ recon / vuln_analysis / exploit / post_exploit
                 ▲                              │
                 └──────────── report ◄─────────┘
                 │
                 └── finish → finalize → END

* 指挥官只做路由，不持有工具；
* 每个阶段是一个独立编译的子图，拥有自己的工具集与提示词；
* 子图的 ``interrupt()`` 会冒泡到父图，由 ``AgentWorker`` 统一向 UI 请求审批；
* 子图结束后由父图 ``report`` 节点生成阶段报告，再交给指挥官决定下一步。
"""

from __future__ import annotations

import hashlib
import json
import uuid
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, SystemMessage, ToolMessage
from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph

from sssec.agent.commander import commander_node
from sssec.agent.llm import DemoChatModel, build_chat_model, extract_text
from sssec.agent.prompts import build_system_prompt
from sssec.agent.runtime import AgentContext
from sssec.agent.state import PentestState, WORKER_LABELS
from sssec.agent.stream import sanitize_messages, stream_reply
from sssec.agent.tools import build_tools
from sssec.agent.workers import WORKER_SPECS, WorkerSpec, compile_worker
from sssec.models import now_iso

# 兼容旧导入名。
AgentState = PentestState


def _ensure_system_prompt(ctx: AgentContext) -> None:
    if (ctx.system_prompt or "").strip():
        return
    ctx.system_prompt = build_system_prompt(
        scope=ctx.scope,
        authorized=ctx.authorized,
        settings=ctx.settings,
        provider=ctx.provider,
        findings=ctx.findings,
        workspace=str(ctx.workspace),
        full_permission=ctx.full_permission,
    )


def _last_ai_text(messages: list[Any]) -> str:
    for message in reversed(messages):
        if isinstance(message, AIMessage) and not message.tool_calls:
            text = extract_text(message.content).strip()
            if text:
                return text
    for message in reversed(messages):
        if isinstance(message, AIMessage):
            text = extract_text(message.content).strip()
            if text:
                return text
    return ""


def _compile_demo(
    ctx: AgentContext,
    model: BaseChatModel,
    checkpointer: BaseCheckpointSaver,
):
    """离线演示模型：保持单节点体验，不进入多 Agent 空转。"""

    async def agent_node(state: PentestState) -> dict[str, Any]:
        message = await stream_reply(
            model,
            [
                SystemMessage(content=ctx.system_prompt),
                *sanitize_messages(state.get("messages") or []),
            ],
            ctx,
        )
        return {"messages": [message]}

    builder = StateGraph(PentestState)
    builder.add_node("demo_agent", agent_node)
    builder.add_edge(START, "demo_agent")
    builder.add_edge("demo_agent", END)
    return builder.compile(checkpointer=checkpointer)


def _compile_solver(
    ctx: AgentContext,
    base_model: BaseChatModel,
    checkpointer: BaseCheckpointSaver,
    *,
    final: bool = False,
):
    """单 Agent / 最终突破图：全部工具 + 任务级轮次，没有指挥官开销。"""
    tool_names = tuple(tool.name for tool in build_tools(ctx))
    configured = max(1, int(ctx.settings.safety.max_tool_rounds or 16))
    max_rounds = max(configured, 20) if final else configured
    name = "final" if final else "single"
    spec = WorkerSpec(
        name=name,
        label=WORKER_LABELS.get(name, name),
        tool_names=tool_names,
        max_rounds=max_rounds,
    )
    ctx.audit.write(
        "final_start" if final else "single_start",
        tools=list(tool_names),
        max_tool_rounds=max_rounds,
    )
    return compile_worker(
        ctx,
        spec,
        base_model,
        include_handoff=False,
        checkpointer=checkpointer,
    )


def _compile_single(
    ctx: AgentContext,
    base_model: BaseChatModel,
    checkpointer: BaseCheckpointSaver,
):
    return _compile_solver(ctx, base_model, checkpointer, final=False)


def _compile_team(
    ctx: AgentContext,
    base_model: BaseChatModel,
    checkpointer: BaseCheckpointSaver,
):
    worker_graphs = {
        name: compile_worker(ctx, WORKER_SPECS[name], base_model)
        for name in WORKER_SPECS
    }
    # v0.2.1：把“最终突破”接进调度图。前面阶段反复卡住时，指挥官可以直接
    # 升级到拥有全部工具的 final Agent，而不是收尾。
    final_spec = WorkerSpec(
        name="final",
        label=WORKER_LABELS["final"],
        tool_names=tuple(tool.name for tool in build_tools(ctx)),
        max_rounds=20,
    )
    worker_graphs["final"] = compile_worker(ctx, final_spec, base_model)

    async def commander(state: PentestState) -> dict[str, Any]:
        return await commander_node(ctx, base_model, state)

    def report(state: PentestState) -> dict[str, Any]:
        worker = str(state.get("next_agent") or "unknown")
        label = WORKER_LABELS.get(worker, worker)
        messages = state.get("messages") or []
        # v0.2.1：只统计本次派发新增的消息，避免阶段被中止时把上一阶段的
        # 收尾文本误当成这一阶段的报告（这正是 v0.2.0 “假无进展”的根因）。
        cursor = max(0, int(state.get("report_cursor") or 0))
        if cursor > len(messages):
            cursor = 0
        fresh = messages[cursor:]
        summary = _last_ai_text(fresh)
        recent = [
            {
                "type": getattr(item, "type", type(item).__name__),
                "content": extract_text(getattr(item, "content", ""))[:400],
            }
            for item in fresh[-6:]
        ]
        evidence = [
            {
                "tool": str(getattr(item, "name", "tool") or "tool"),
                "status": str(getattr(item, "status", "") or ""),
                "content": extract_text(getattr(item, "content", ""))[:600],
            }
            for item in fresh
            if isinstance(item, ToolMessage)
        ][-8:]
        if evidence:
            fingerprint = hashlib.sha1(
                json.dumps(evidence, ensure_ascii=False, sort_keys=True).encode("utf-8")
            ).hexdigest()
        elif summary.strip():
            fingerprint = hashlib.sha1(summary.encode("utf-8")).hexdigest()
        else:
            fingerprint = ""
        entry = {
            "worker": worker,
            "label": label,
            "task": str(state.get("task") or ""),
            "summary": summary[-4000:],
            "handoff": state.get("handoff"),
            "recent": recent,
            "evidence": evidence,
            "progress_key": fingerprint,
            # 没有文本、没有工具证据，说明这个阶段被中止或模型空转；
            # 这类报告不能拿来判定“没有新进展”。
            "truncated": not summary.strip() and not evidence,
            "stalled": bool(state.get("stalled")),
            "skills": list(state.get("loaded_skills") or []),
            "rounds": int((state.get("worker_rounds_total") or {}).get(worker, 0)),
            "created_at": now_iso(),
        }
        ctx.audit.write(
            "worker_report",
            worker=worker,
            task=entry["task"][:1500],
            summary=entry["summary"][:2000],
            handoff=entry["handoff"],
            evidence_count=len(evidence),
            progress_key=fingerprint,
            truncated=entry["truncated"],
            stalled=entry["stalled"],
            skills=entry["skills"],
        )
        return {
            "worker_reports": [*(state.get("worker_reports") or []), entry],
            "report_cursor": len(messages),
        }

    def finalize(state: PentestState) -> dict[str, Any]:
        summary = str(state.get("finish_summary") or "").strip()
        if not summary:
            summary = "已完成当前可执行的阶段，按现有证据收尾。"
        text = f"\n\n---\n\n**指挥官收尾**：{summary}"
        ctx.emit_text(text)
        ctx.audit.write(
            "team_finished",
            steps=int(state.get("step") or 0),
            summary=summary[:2000],
            workers=[
                str(item.get("worker") or "")
                for item in (state.get("worker_reports") or [])
            ],
        )
        return {
            "messages": [AIMessage(content=text, id=f"ai_{uuid.uuid4().hex}")],
            "finished": True,
        }

    def route_commander(state: PentestState) -> str:
        target = str(state.get("next_agent") or "")
        return target if target in worker_graphs else "finalize"

    builder = StateGraph(PentestState)
    builder.add_node("commander", commander)
    for name, graph in worker_graphs.items():
        builder.add_node(name, graph)
    builder.add_node("report", report)
    builder.add_node("finalize", finalize)

    builder.add_edge(START, "commander")
    builder.add_conditional_edges(
        "commander",
        route_commander,
        {
            **{name: name for name in worker_graphs},
            "finalize": "finalize",
        },
    )
    for name in worker_graphs:
        builder.add_edge(name, "report")
    builder.add_edge("report", "commander")
    builder.add_edge("finalize", END)

    ctx.audit.write(
        "team_start",
        workers=list(worker_graphs),
        max_tool_rounds=ctx.settings.safety.max_tool_rounds,
        approval_mode=ctx.settings.safety.approval_mode,
    )
    return builder.compile(checkpointer=checkpointer)


def compile_agent(
    ctx: AgentContext,
    *,
    model: BaseChatModel | None = None,
    checkpointer: BaseCheckpointSaver | None = None,
    single: bool = False,
    final: bool = False,
):
    """编译 SSsec Agent 图。

    ``single=True`` 时走单 Agent 快速解题图（全部工具，任务级轮次）；
    ``final=True`` 时走最终汇总突破图（全部工具、更高轮次、证据只作参考）；
    默认仍走“指挥官 + 阶段子图”的多 Agent 图。
    ``model`` 主要用于测试注入；生产路径使用当前 Provider 构建模型。
    离线演示模型仍走单节点图，避免无工具能力的模型在四个阶段间空转。
    """
    _ensure_system_prompt(ctx)
    base_model = model or build_chat_model(
        ctx.provider, ctx.settings.safety, streaming=True
    )
    # 记录到上下文，Worker 在事件循环关闭前会显式关闭底层 HTTP 客户端。
    ctx.model = base_model
    saver = checkpointer or InMemorySaver()
    if isinstance(base_model, DemoChatModel):
        return _compile_demo(ctx, base_model, saver)
    if final:
        return _compile_solver(ctx, base_model, saver, final=True)
    if single:
        return _compile_single(ctx, base_model, saver)
    return _compile_team(ctx, base_model, saver)


__all__ = ["AgentState", "compile_agent"]
