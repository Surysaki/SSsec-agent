"""Agent 单次运行上下文与事件出口。"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from sssec.config import AppSettings, ProviderConfig
from sssec.security.audit import AuditLog
from sssec.security.scope import ScopeDecision, check_host, check_url


@dataclass
class AgentEvents:
    text_delta: Callable[[str], None] = lambda _text: None
    reasoning_delta: Callable[[str], None] = lambda _text: None
    tool_started: Callable[[dict], None] = lambda _data: None
    tool_finished: Callable[[dict], None] = lambda _data: None
    finding_saved: Callable[[dict], None] = lambda _data: None


@dataclass
class AgentContext:
    conversation_id: str
    scope: list[str]
    authorized: bool
    settings: AppSettings
    provider: ProviderConfig
    data_dir: Path
    workspace: Path
    system_prompt: str
    audit: AuditLog
    events: AgentEvents = field(default_factory=AgentEvents)
    findings: list[dict] = field(default_factory=list)
    command_approved: bool = False
    full_permission: bool = False
    model: Any = None

    def emit_text(self, text: str) -> None:
        if text:
            self.events.text_delta(text)

    def emit_reasoning(self, text: str) -> None:
        if text:
            self.events.reasoning_delta(text)

    def emit_tool_started(
        self,
        call_id: str,
        name: str,
        args: dict,
        requires_approval: bool,
    ) -> None:
        self.events.tool_started(
            {
                "id": call_id,
                "name": name,
                "args": args,
                "requires_approval": requires_approval,
            }
        )

    def emit_tool_finished(
        self,
        call_id: str,
        name: str,
        status: str,
        result: str,
        duration_ms: int | None = None,
    ) -> None:
        self.events.tool_finished(
            {
                "id": call_id,
                "name": name,
                "status": status,
                "result": result,
                "duration_ms": duration_ms,
            }
        )

    def emit_finding(self, finding: dict) -> None:
        self.events.finding_saved(finding)

    def requires_approval(self, tool_name: str, args: dict | None = None) -> bool:
        if self.full_permission:
            return False
        mode = self.settings.safety.approval_mode
        if mode in ("off", "full"):
            return False
        if mode == "all":
            return True
        if tool_name == "run_command":
            return True
        if tool_name == "http_request":
            # GET/HEAD/OPTIONS 视为只读；其他方法可能改变目标状态，需确认。
            method = str((args or {}).get("method") or "GET").upper().strip()
            return method not in {"GET", "HEAD", "OPTIONS"}
        return False

    @property
    def scope_mode(self) -> str:
        """当前生效的范围策略；完全权限或全局完全权限模式会强制关闭拦截。"""
        if self.full_permission or self.settings.safety.approval_mode == "full":
            return "off"
        mode = self.settings.safety.scope_mode
        return mode if mode in ("off", "warn", "strict") else "off"

    def check_host(self, host: str) -> ScopeDecision:
        return check_host(host, self.scope, self.authorized, self.scope_mode)

    def check_url(self, url: str) -> ScopeDecision:
        return check_url(url, self.scope, self.authorized, self.scope_mode)

    def can_execute_shell(self) -> bool:
        return bool(self.settings.safety.enable_shell)


__all__ = ["AgentContext", "AgentEvents"]
