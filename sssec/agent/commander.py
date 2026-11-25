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
    MAX_TEAM_STEPS_HARD,
    WORKER_LABELS,
    WORKER_ORDER,
    PentestState,
)
from sssec.agent.toolkit import extract_flags

logger = logging.getLogger("sssec.agent")

# 连续“没有新证据”时允许升级几次（换阶段 / 升级 final），超过后才允许 blocked 收尾。
MAX_ESCALATIONS = 2
_FLAG_MISSION_RE = re.compile(r"flag|ctf|夺旗|靶场", re.IGNORECASE)

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
    "final": "final",
    "最终突破": "final",
    "最终汇总": "final",
    "汇总突破": "final",
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


def mission_objective(state: PentestState) -> str:
    """任务目标：优先用运行开始时记录的 mission，避免“继续”覆盖掉原始目标。"""
    stored = str(state.get("mission_objective") or "").strip()
    return stored or last_user_text(state)


def is_flag_mission(state: PentestState) -> bool:
    return bool(_FLAG_MISSION_RE.search(mission_objective(state)))


def has_flag(state: PentestState) -> bool:
    for message in state.get("messages") or []:
        content = extract_text(getattr(message, "content", ""))
        if content and extract_flags(content):
            return True
    return False


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
    soft_steps = MAX_TEAM_STEPS + min(16, bonus * 2)
    hard_steps = MAX_TEAM_STEPS_HARD + bonus * 4
    if step > hard_steps:
        return (
            {
                "next": "finish",
                "task": "",
                "reason": f"已达到调度硬熔断 {hard_steps} 步",
                "summary": "调度步数达到安全熔断上限，按当前证据收尾。",
            },
            "hard-limit",
        )

    if isinstance(model, DemoChatModel):
        return fallback_decision(state), "demo-fallback"

    prompt = build_commander_prompt(
        ctx.system_prompt,
        objective=mission_objective(state),
        reports=state.get("worker_reports") or [],
        step=step,
        max_steps=soft_steps,
        handoff=state.get("handoff"),
        skills_index=(
            ctx.skill_store().index_text()
            if getattr(ctx.settings.safety, "skills_enabled", True)
            else ""
        ),
    )
    if step > soft_steps:
        prompt += (
            f"\n\n## 策略复盘\n调度序号 {step} 已超过软预算 {soft_steps}。"
            "不要因此收尾：检查是否在重复同一条路线，换阶段、换思路或升级到 `final`。"
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
    """指挥官节点：输出下一阶段、任务简报与调度日志。

    v0.2.1 起采用“目标驱动收尾”：轮次只做提示，不再因为预算耗尽而收尾。
    没有新证据时优先升级（换阶段 / 升级 final），只有确认 blocked 才允许结束。
    """
    step = int(state.get("step") or 0) + 1
    decision, source = await decide(ctx, model, state)
    target = decision["next"]
    escalations = int(state.get("escalations") or 0)
    goal_done = has_flag(state) or not is_flag_mission(state)

    def _escalate(reason: str) -> dict[str, Any]:
        """换一条路线继续，而不是结束任务。"""
        previous = str((state.get("worker_reports") or [{}])[-1].get("worker") or "")
        candidates = ["final", "post_exploit", "exploit", "recon", "vuln_analysis"]
        alt = next((name for name in candidates if name != previous), "final")
        return {
            "next": alt,
            "task": (
                f"上一轮 {previous or '上一阶段'} 没有产生新证据（{reason}）。"
                "不要再重复相同动作：换一个入口/参数/协议，或改用另一种验证方式；"
                "先说明当前卡点，再给出具体工具调用。"
            ),
            "reason": f"无进展升级（第 {escalations + 1} 次）：{reason}",
            "summary": "",
        }

    # 1) 同一阶段连续两次没有新证据：升级路线，而不是收尾。
    if target != "finish" and _no_progress(state, target):
        ctx.audit.write(
            "commander_no_progress",
            worker=target,
            step=step,
            escalations=escalations,
        )
        if escalations < MAX_ESCALATIONS:
            decision = _escalate(f"连续两次 {target} 阶段没有产生新证据")
            target = decision["next"]
            source = "escalate"
        else:
            decision = {
                "next": "finish",
                "task": "",
                "reason": f"已连续 {escalations} 次换路线仍无新证据，按 blocked 收尾",
                "summary": "多次换路线后仍没有新证据，已保留现有发现并结束。",
            }
            target = "finish"
            source = "blocked"

    # 2) 因为软预算/步数想收尾：只要还没升级够，就不允许结束；硬熔断除外。
    if (
        target == "finish"
        and source in {"no-progress", "limit"}
        and escalations < MAX_ESCALATIONS
    ):
        decision = _escalate(decision.get("reason") or "预算或调度步数触顶")
        target = decision["next"]
        source = "escalate"

    # 3) flag 类任务在没拿到 flag 时，模型主动收尾也要先升级一次。
    if (
        target == "finish"
        and source == "model"
        and is_flag_mission(state)
        and not has_flag(state)
        and escalations < MAX_ESCALATIONS
        and state.get("worker_reports")
    ):
        decision = _escalate("目标要求 flag，但还没有任何 flag 证据")
        target = decision["next"]
        source = "escalate"

    if source == "escalate":
        escalations += 1
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
        escalations=escalations,
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
        "worker_tool_calls": 0,
        "deepen_count": 0,
        "loop_streak": 0,
        "loop_hint": 0,
        "stalled": False,
        "escalations": escalations,
        "loaded_skills": [],
        "skill_conflicts": [],
        "commander_log": [*(state.get("commander_log") or []), entry],
    }


__all__ = [
    "MAX_ESCALATIONS",
    "commander_node",
    "decide",
    "fallback_decision",
    "has_flag",
    "is_flag_mission",
    "last_user_text",
    "mission_objective",
    "parse_decision",
]
