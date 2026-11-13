"""指挥官（Supervisor）节点：只做路由，不执行任何工具。"""

from __future__ import annotations

import difflib
import json
import logging
import re
from typing import Any

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import HumanMessage, SystemMessage

from sssec.agent.llm import DemoChatModel, extract_text
from sssec.agent.prompts import build_commander_prompt
from sssec.agent.runtime import AgentContext
from sssec.agent.state import (
    HANDOFF_TARGETS,
    MAX_TEAM_STEPS,
    WORKER_LABELS,
    WORKER_ORDER,
    PentestState,
)

logger = logging.getLogger("sssec.agent")

_TARGET_ALIASES = {
    "recon": "recon",
    "侦察": "recon",
    "信息收集": "recon",
    "vuln": "vuln_analysis",
    "vuln_analysis": "vuln_analysis",
    "漏洞分析": "vuln_analysis",
    "exploit": "exploit",
    "漏洞利用": "exploit",
    "利用": "exploit",
    "post": "post_exploit",
    "post_exploit": "post_exploit",
    "后渗透": "post_exploit",
    "reverse": "reverse",
    "逆向": "reverse",
    "逆向分析": "reverse",
    "二进制": "reverse",
    "固件": "reverse",
    "finish": "finish",
    "done": "finish",
    "收尾": "finish",
    "完成": "finish",
    "结束": "finish",
}


def _normalize_target(value: Any) -> str:
    text = str(value or "").strip().strip("`'\" ").lower()
    return _TARGET_ALIASES.get(text, "")


def last_user_text(state: PentestState) -> str:
    for message in reversed(state.get("messages") or []):
        if isinstance(message, HumanMessage):
            text = extract_text(message.content).strip()
            if text:
                return text
    return "未提供明确目标"


def _clip(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    return text[:limit]


def parse_decision(text: str) -> dict[str, Any] | None:
    """从模型输出中解析指挥官 JSON 决策。"""
    cleaned = (text or "").strip()
    if not cleaned:
        return None
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```[a-zA-Z0-9_-]*\s*", "", cleaned)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    decoder = json.JSONDecoder()
    data: dict[str, Any] | None = None
    for match in re.finditer(r"\{", cleaned):
        try:
            candidate, _end = decoder.raw_decode(cleaned[match.start() :])
        except Exception:
            continue
        if not isinstance(candidate, dict):
            continue
        if _normalize_target(candidate.get("next") or candidate.get("next_agent")):
            data = candidate
            break
    if data is None:
        return None
    target = _normalize_target(data.get("next") or data.get("next_agent"))
    if target not in HANDOFF_TARGETS:
        return None
    task = _clip(data.get("task"), 4000)
    if target != "finish" and not task:
        return None
    return {
        "next": target,
        "task": task,
        "reason": _clip(data.get("reason"), 1000),
        "summary": _clip(data.get("summary"), 4000),
    }


def fallback_decision(state: PentestState) -> dict[str, Any]:
    """模型输出不可解析时的确定性回退：优先采纳 handoff，否则按阶段推进。"""
    handoff = state.get("handoff") or {}
    target = _normalize_target(handoff.get("next_agent"))
    if target in HANDOFF_TARGETS:
        return {
            "next": target,
            "task": _clip(handoff.get("task"), 4000),
            "reason": _clip(handoff.get("reason"), 1000)
            or "采纳上一阶段子 Agent 的交接建议",
            "summary": _clip(handoff.get("summary"), 4000),
        }

    reports = state.get("worker_reports") or []
    completed = {str(item.get("worker") or "") for item in reports}
    for name in WORKER_ORDER:
        if name not in completed:
            return {
                "next": name,
                "task": _default_task(name),
                "reason": "按渗透测试默认阶段顺序推进（指挥官模型未返回可解析决策）",
                "summary": "",
            }
    return {
        "next": "finish",
        "task": "",
        "reason": "所有阶段均已完成，按默认策略收尾",
        "summary": "已完成当前可执行的阶段，按现有证据收尾。",
    }


def _default_task(name: str) -> str:
    return {
        "recon": "对当前目标做低影响信息收集：确认可达性、DNS/端口/HTTP/TLS 指纹，输出候选入口。",
        "vuln_analysis": "基于已有证据做漏洞假设与配置检查，按严重程度排序，给出需要验证的入口。",
        "exploit": "对高优先级候选入口做最小化验证，证明影响后立即停止，并记录证据。",
        "post_exploit": "评估当前访问级别与影响范围，整理证据与修复建议，准备收尾。",
        "reverse": "对工作区中的 ELF/PE/固件做逆向：先 binary_info/disassemble，定位校验入口与关键比较，给出求解思路与密钥。",
    }.get(name, "按当前阶段职责推进任务。")


async def decide(
    ctx: AgentContext,
    model: BaseChatModel,
    state: PentestState,
) -> tuple[dict[str, Any], str]:
    """让指挥官模型做决策；失败时返回确定性回退。"""
    step = int(state.get("step") or 0) + 1
    # 后期重试时除了工具轮次，也给指挥官更多调度轮次。
    bonus = max(0, int(getattr(ctx, "round_bonus", 0) or 0))
    max_steps = MAX_TEAM_STEPS + min(16, bonus * 2)
    if step > max_steps:
        return (
            {
                "next": "finish",
                "task": "",
                "reason": f"已达到最大调度轮次 {max_steps}",
                "summary": "达到最大调度轮次，按当前证据收尾。",
            },
            "limit",
        )

    if isinstance(model, DemoChatModel):
        return fallback_decision(state), "demo-fallback"

    prompt = build_commander_prompt(
        ctx.system_prompt,
        objective=last_user_text(state),
        reports=state.get("worker_reports") or [],
        step=step,
        max_steps=max_steps,
        handoff=state.get("handoff"),
    )
    try:
        reply = await model.ainvoke(
            [
                SystemMessage(content=prompt),
                HumanMessage(content="请给出下一步调度 JSON。"),
            ]
        )
        text = extract_text(getattr(reply, "content", ""))
        decision = parse_decision(text)
        if decision is not None:
            return decision, "model"
        logger.info("指挥官输出无法解析，使用回退调度: %s", text[:300])
        ctx.audit.write("commander_parse_error", text=text[:1500])
    except Exception as exc:
        logger.warning("指挥官模型调用失败，使用回退调度", exc_info=True)
        ctx.audit.write(
            "commander_error",
            error=type(exc).__name__,
            message=str(exc)[:1000],
        )
    return fallback_decision(state), "fallback"


def _no_progress(state: PentestState, target: str) -> bool:
    reports = state.get("worker_reports") or []
    if len(reports) < 2:
        return False
    last, previous = reports[-1], reports[-2]
    if str(last.get("worker") or "") != target:
        return False
    if str(previous.get("worker") or "") != target:
        return False
    if last.get("progress_key") and last.get("progress_key") == previous.get("progress_key"):
        return True
    last_evidence = json.dumps(last.get("evidence") or [], ensure_ascii=False).lower()
    previous_evidence = json.dumps(
        previous.get("evidence") or [], ensure_ascii=False
    ).lower()
    # 本轮新拿到 flag 时不要因为摘要相似而提前收尾。
    if "flag{" in last_evidence and "flag{" not in previous_evidence:
        return False
    last_summary = str(last.get("summary") or "").strip()
    previous_summary = str(previous.get("summary") or "").strip()
    if len(last_summary) < 80 or len(previous_summary) < 80:
        return False
    ratio = difflib.SequenceMatcher(
        None,
        previous_summary[:2000],
        last_summary[:2000],
    ).ratio()
    return ratio >= 0.92


async def commander_node(
    ctx: AgentContext,
    model: BaseChatModel,
    state: PentestState,
) -> dict[str, Any]:
    """指挥官节点：输出下一阶段、任务简报与调度日志。"""
    step = int(state.get("step") or 0) + 1
    decision, source = await decide(ctx, model, state)
    target = decision["next"]
    # 连续两次同一阶段、证据指纹和摘要都高度相似，说明没有新进展；
    # 继续派发只会重复消耗时间，直接收尾并保留现有证据。
    if target != "finish" and _no_progress(state, target):
        ctx.audit.write(
            "commander_no_progress",
            worker=target,
            step=step,
            previous_step=max(1, step - 1),
        )
        decision = {
            "next": "finish",
            "task": "",
            "reason": f"连续两次 {target} 阶段没有产生新证据，停止重复派发",
            "summary": "连续阶段无新证据，已保留现有发现并收尾。",
        }
        target = "finish"
        source = "no-progress"
    label = WORKER_LABELS.get(target, "收尾")
    reason = decision.get("reason") or "按当前证据推进"
    task = decision.get("task") or ""

    ctx.emit_commander(f"\n指挥官决策：{label} · {reason}\n")
    ctx.audit.write(
        "commander_decision",
        step=step,
        next=target,
        task=task[:2000],
        reason=reason[:1000],
        source=source,
    )

    entry = {
        "step": step,
        "next": target,
        "task": task,
        "reason": reason,
        "source": source,
    }
    return {
        "next_agent": target,
        "task": task,
        "reason": reason,
        "finish_summary": decision.get("summary") or ("任务已完成。" if target == "finish" else ""),
        "handoff": None,
        "step": step,
        "worker_rounds": 0,
        "commander_log": [*(state.get("commander_log") or []), entry],
    }


__all__ = [
    "commander_node",
    "decide",
    "fallback_decision",
    "last_user_text",
    "parse_decision",
]
