"""多 Agent 协作共享的状态、阶段常量与交接目标。

SSsec 采用「指挥官（supervisor）+ 阶段子图（subgraph）」结构：

* 指挥官只做路由，不执行工具；
* 四个阶段子图各自拥有独立的工具集与系统提示；
* 子图完成自己的任务后，通过 ``handoff`` 工具或普通结束消息把控制权交回指挥官；
* 指挥官根据阶段报告决定下一步，直到 ``finish``。
"""

from __future__ import annotations

from typing import Annotated, Any, TypedDict

from langchain_core.messages import AnyMessage
from langgraph.graph.message import add_messages

# 渗透测试主流程中的子 Agent。顺序同时作为“默认推进顺序”使用。
WORKER_ORDER: tuple[str, ...] = (
    "recon",
    "vuln_analysis",
    "exploit",
    "post_exploit",
)

WORKER_LABELS: dict[str, str] = {
    "recon": "信息收集 Agent",
    "vuln_analysis": "漏洞分析 Agent",
    "exploit": "漏洞利用 Agent",
    "post_exploit": "后渗透 Agent",
    "reverse": "逆向分析 Agent",
    "single": "单 Agent 解题",
    "final": "最终汇总突破 Agent",
}

WORKER_DESCRIPTIONS: dict[str, str] = {
    "recon": "HTTP 指纹、端口扫描、子域枚举、目录发现、爬虫、WHOIS/TLS 与 DNS 区域传送",
    "vuln_analysis": "参数/CORS/JWT/WAF/SSRF/LFI/API 文档探测、源码秘密扫描、Crypto/二进制分析",
    "exploit": "HTTP/原始请求/上传、Payload 生成、TCP 交互、命令执行与二进制利用",
    "post_exploit": "Webshell 命令、证据整理、flag 提取、压缩包分析、源码秘密扫描",
    "reverse": "ELF/PE/固件逆向、静态反汇编、校验逻辑与授权算法分析",
    "final": "汇总前面所有证据、重新建模并做最后突破的全工具 Agent",
}

# 允许 handoff 的目标：四个阶段 + 逆向专项 + 最终突破 + 收尾。
HANDOFF_TARGETS: tuple[str, ...] = (*WORKER_ORDER, "reverse", "final", "finish")

# 指挥官调度软预算：超过后进入“策略复盘”，但不再强制收尾。
MAX_TEAM_STEPS = 16
# 指挥官调度硬熔断：只在模型持续空转时兜底，正常任务不应触达。
MAX_TEAM_STEPS_HARD = 200

# 单个阶段一次派发内允许的“空转续跑”次数（模型没调用任何工具就想收尾）。
MAX_WORKER_CONTINUATIONS = 1
# 循环检测触发后，最多提示几次换策略；超过后中止该阶段。
MAX_LOOP_HINTS = 1


class PentestState(TypedDict, total=False):
    """父子图共享状态。

    父图使用全部字段；子图只读写 ``messages`` / ``approval`` / ``task`` /
    ``handoff`` / ``worker_rounds``。使用同一份 schema 可以让子图直接作为
    父图节点运行，并让 LangGraph 正确传播 ``interrupt()``。
    """

    messages: Annotated[list[AnyMessage], add_messages]
    approval: dict[str, Any] | None

    # 指挥官写给下一个子 Agent 的任务简报。
    next_agent: str
    task: str
    reason: str

    # 子 Agent 的交接请求（由 handoff 工具产生）。
    handoff: dict[str, Any] | None

    # 父图维护的阶段报告与调度日志。
    worker_reports: list[dict[str, Any]]
    commander_log: list[dict[str, Any]]

    step: int
    worker_rounds: int
    worker_rounds_total: dict[str, int]
    # 单 Agent 首次尝试中，模型提前收尾后被强制继续深挖的次数。
    single_continue: int
    finished: bool
    finish_summary: str

    # --- v0.2.1：目标驱动调度 -------------------------------------------------
    # 本次阶段派发内已经发生的工具调用数（用于识别“零工具空转阶段”）。
    worker_tool_calls: int
    # 本阶段“空转续跑”次数。
    deepen_count: int
    # 最近若干轮的调用签名，用于循环检测。
    action_history: list[str]
    # 连续相同签名的次数。
    loop_streak: int
    # 已发出的“换策略”提示次数。
    loop_hint: int
    # 阶段被循环检测/熔断中止。
    stalled: bool
    # 阶段报告读取消息的游标，保证 report 只统计本轮新增消息。
    report_cursor: int
    # 无进展升级次数（换阶段/换路线），超过阈值才允许 blocked 收尾。
    escalations: int
    # 任务目标快照（跨轮恢复时使用）。
    mission_objective: str
    # 自动续跑次数。
    auto_continue: int
    # 本阶段已加载的技能卡 id（每阶段重置）与证据冲突记录。
    loaded_skills: list[str]
    skill_conflicts: list[dict[str, Any]]


__all__ = [
    "HANDOFF_TARGETS",
    "MAX_LOOP_HINTS",
    "MAX_TEAM_STEPS",
    "MAX_TEAM_STEPS_HARD",
    "MAX_WORKER_CONTINUATIONS",
    "PentestState",
    "WORKER_DESCRIPTIONS",
    "WORKER_LABELS",
    "WORKER_ORDER",
]
