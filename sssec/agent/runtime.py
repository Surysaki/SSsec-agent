"""Agent 单次运行上下文与事件出口。"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from sssec.config import AppSettings, ProviderConfig
from sssec.security.audit import AuditLog
from sssec.security.scope import ScopeDecision, check_host, check_url

# 宽松审批模式下仍需人工确认的高风险命令特征。
# 这里只做“明显不可逆/破坏性/提权持久化”的粗筛，不能替代操作员判断。
_HIGH_RISK_COMMAND_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE)
    for pattern in (
        r"\brm\s+(-[a-z]*r[a-z]*f|-[a-z]*f[a-z]*r)\b",
        r"\bdel\s+/[fsq]\b",
        r"\bformat(\.com)?\b",
        r"\bmkfs(\.\w+)?\b",
        r"\bdd\s+if=",
        r"\bshutdown\b",
        r"\breboot\b",
        r"\bpoweroff\b",
        r"\bhalt\b",
        r"\breg\s+delete\b",
        r"\bremove-item\b[^\n]*-recurse",
        r"\bstop-computer\b",
        r"\bclear-disk\b",
        r"\binitialize-disk\b",
        r"\bformat-volume\b",
        r"\biex\b",
        r"\binvoke-expression\b",
        r"\bcurl\b[^\n]*\|\s*(ba)?sh\b",
        r"\bwget\b[^\n]*\|\s*(ba)?sh\b",
        r"\bnet\s+user\b[^\n]*/add\b",
        r"\buseradd\b",
        r"\bchmod\s+777\b",
        r":\(\)\s*\{",
    )
)

# 只读、低影响的工具；宽松模式下直接执行。
_RELAXED_SAFE_TOOLS = {
    "http_request",
    "http_probe",
    "http_raw",
    "http_upload",
    "dns_lookup",
    "dns_zone_transfer",
    "tcp_probe",
    "tcp_exchange",
    "port_scan",
    "subdomain_enum",
    "dir_scan",
    "web_crawl",
    "whois_lookup",
    "tls_certificate",
    "security_headers",
    "param_fuzz",
    "cors_check",
    "jwt_analyze",
    "waf_detect",
    "codec",
    "payload_forge",
    "binary_info",
    "crypto_workshop",
    "file_analyze",
    "archive_extract",
    "artifact_scan",
    "flag_hunt",
    "workspace_list",
    "workspace_read",
    "workspace_write",
    "webshell_client",
    "save_finding",
    "handoff",
}


def is_high_risk_command(command: str) -> bool:
    """判断命令是否命中明显高风险特征。"""
    text = str(command or "")
    if not text.strip():
        return False
    return any(pattern.search(text) for pattern in _HIGH_RISK_COMMAND_PATTERNS)


@dataclass
class AgentEvents:
    text_delta: Callable[[str], None] = lambda _text: None
    reasoning_delta: Callable[[str], None] = lambda _text: None
    commander_delta: Callable[[str], None] = lambda _text: None
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
    round_bonus: int = 0
    # 本题需要找的 flag 总数；单 Agent 用它判断是否继续深挖。
    target_flags: int = 1
    model: Any = None
    _skill_store: Any = None

    def skill_store(self):
        """技能库（惰性创建，测试与 UI 共用同一数据目录）。"""
        if self._skill_store is None:
            from sssec.skills import SkillStore

            self._skill_store = SkillStore(self.data_dir)
        return self._skill_store

    def emit_text(self, text: str) -> None:
        if text:
            self.events.text_delta(text)

    def emit_reasoning(self, text: str) -> None:
        if text:
            self.events.reasoning_delta(text)

    def emit_commander(self, text: str) -> None:
        if text:
            self.events.commander_delta(text)

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
        """按当前审批策略判断某个工具调用是否需要人工确认。

        ``relaxed`` 是 SSsec 多 Agent 模式的默认策略：

        * 只读网络/分析/工作区读取工具直接执行；
        * ``run_command`` 只在命中高风险特征时需要确认；
        * ``workspace_write`` 直接执行（工作区仍限制在会话目录内）。

        ``sensitive`` 保留原来的保守策略：命令与非只读 HTTP 方法需要确认。
        """
        if self.full_permission:
            return False
        mode = self.settings.safety.approval_mode
        if mode in ("off", "full"):
            return False
        if mode == "all":
            return True
        if mode == "relaxed":
            if tool_name == "run_command":
                command = str((args or {}).get("command") or "")
                return is_high_risk_command(command)
            return tool_name not in _RELAXED_SAFE_TOOLS
        if tool_name in {
            "run_command",
            "workspace_write",
            "archive_extract",
            "http_raw",
            "http_upload",
            "webshell_client",
            "tcp_exchange",
        }:
            return True
        if tool_name == "http_request":
            # GET/HEAD/OPTIONS 视为只读；其他方法可能改变目标状态，需确认。
            method = str((args or {}).get("method") or "GET").upper().strip()
            return method not in {"GET", "HEAD", "OPTIONS"}
        if tool_name == "param_fuzz":
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


__all__ = ["AgentContext", "AgentEvents", "is_high_risk_command"]
