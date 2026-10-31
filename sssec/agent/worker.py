"""在 QThread 中运行 LangGraph，并用 Qt 信号把流式事件送回界面。"""

from __future__ import annotations

import asyncio
import copy
import logging
import threading
from pathlib import Path
from typing import Any

from langchain_core.messages import BaseMessage, HumanMessage
from langgraph.types import Command
from PySide6.QtCore import QThread, Signal

from sssec.agent.graph import compile_agent
from sssec.agent.llm import aclose_model, friendly_error
from sssec.agent.prompts import build_system_prompt
from sssec.agent.runtime import AgentContext, AgentEvents
from sssec.config import AppSettings, ProviderConfig
from sssec.security.audit import AuditLog

logger = logging.getLogger("sssec.agent")


class AgentWorker(QThread):
    text_delta = Signal(str)
    reasoning_delta = Signal(str)
    tool_started = Signal(dict)
    tool_finished = Signal(dict)
    approval_required = Signal(dict)
    finding_saved = Signal(dict)
    run_finished = Signal(str, str)  # status: complete / cancelled / error, message

    def __init__(
        self,
        *,
        conversation_id: str,
        history: list[BaseMessage],
        user_input: str,
        scope: list[str],
        authorized: bool,
        findings: list[dict],
        settings: AppSettings,
        provider: ProviderConfig,
        data_dir: Path,
        workspace: Path,
        full_permission: bool = False,
        parent: Any = None,
    ):
        super().__init__(parent)
        self.conversation_id = conversation_id
        self.history = copy.deepcopy(history)
        self.user_input = user_input
        self.scope = list(scope)
        self.authorized = authorized
        self.full_permission = bool(full_permission)
        self.findings = copy.deepcopy(findings)
        self.settings = settings.clone()
        self.provider = provider.clone()
        self.data_dir = data_dir
        self.workspace = workspace

        self._loop: asyncio.AbstractEventLoop | None = None
        self._task: asyncio.Task | None = None
        self._approval_future: asyncio.Future | None = None
        self._model: Any = None
        self._cancel_requested = threading.Event()
        self._approval_lock = threading.Lock()
        self._finished_emitted = False

    # ------------------------------------------------------------------ public
    def provide_approval(self, approved: bool, note: str = "") -> None:
        decision = {"approved": bool(approved), "note": note}
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        loop.call_soon_threadsafe(self._resolve_approval, decision)

    def cancel(self) -> None:
        self._cancel_requested.set()
        loop = self._loop
        if loop is None or loop.is_closed():
            return
        try:
            loop.call_soon_threadsafe(self._cancel_in_loop)
        except RuntimeError:
            pass

    # ------------------------------------------------------------------- inner
    def _resolve_approval(self, decision: dict[str, Any]) -> None:
        future = self._approval_future
        if future is not None and not future.done():
            future.set_result(decision)

    def _cancel_in_loop(self) -> None:
        if self._task is not None and not self._task.done():
            self._task.cancel()

    def _emit_finished(self, status: str, message: str = "") -> None:
        if not self._finished_emitted:
            self._finished_emitted = True
            self.run_finished.emit(status, message)

    def run(self) -> None:  # noqa: D401 - QThread entry point
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        audit = AuditLog(self.data_dir, self.conversation_id)
        status = "complete"
        message = ""
        try:
            loop.run_until_complete(self._run_async(audit))
        except asyncio.CancelledError:
            status = "cancelled"
            audit.write("run_finished", status=status)
        except Exception as exc:
            logger.exception("Agent run failed")
            status = "error"
            message = friendly_error(exc, self.provider)
            audit.write("run_error", error=type(exc).__name__, message=message[:1000])
        finally:
            self._approval_future = None
            if self._model is not None:
                try:
                    # 必须在 loop 关闭前清理模型连接，否则 httpx 的连接池
                    # 可能在下一个 loop 中尝试关闭旧 transport，触发
                    # “RuntimeError: Event loop is closed”。
                    loop.run_until_complete(
                        asyncio.wait_for(aclose_model(self._model), timeout=5)
                    )
                except Exception:
                    logger.debug("关闭模型 HTTP 客户端失败", exc_info=True)
                self._model = None
            try:
                pending = [task for task in asyncio.all_tasks(loop) if not task.done()]
                for task in pending:
                    task.cancel()
                if pending:
                    loop.run_until_complete(
                        asyncio.gather(*pending, return_exceptions=True)
                    )
                loop.run_until_complete(loop.shutdown_asyncgens())
            except Exception:
                logger.debug("清理事件循环时出现问题", exc_info=True)
            try:
                loop.close()
            except Exception:
                pass
            asyncio.set_event_loop(None)
            self._loop = None
            self._emit_finished(status, message)

    async def _run_async(self, audit: AuditLog) -> None:
        self._task = asyncio.current_task()
        if self._cancel_requested.is_set():
            raise asyncio.CancelledError()
        ctx = AgentContext(
            conversation_id=self.conversation_id,
            scope=self.scope,
            authorized=self.authorized,
            settings=self.settings,
            provider=self.provider,
            data_dir=self.data_dir,
            workspace=self.workspace,
            system_prompt="",
            audit=audit,
            events=AgentEvents(
                text_delta=self.text_delta.emit,
                reasoning_delta=self.reasoning_delta.emit,
                tool_started=self.tool_started.emit,
                tool_finished=self.tool_finished.emit,
                finding_saved=self.finding_saved.emit,
            ),
            findings=self.findings,
            full_permission=self.full_permission,
        )
        ctx.system_prompt = build_system_prompt(
            scope=self.scope,
            authorized=self.authorized,
            settings=self.settings,
            provider=self.provider,
            findings=self.findings,
            workspace=str(self.workspace),
            full_permission=self.full_permission,
        )
        audit.write(
            "run_start",
            provider=self.provider.name,
            model=self.provider.model,
            scope=self.scope,
            authorized=self.authorized,
            approval_mode=self.settings.safety.approval_mode,
            scope_mode=self.settings.safety.scope_mode,
            full_permission=self.full_permission,
        )
        try:
            try:
                graph = compile_agent(ctx)
            finally:
                self._model = ctx.model
            config = {
                "configurable": {"thread_id": f"run-{self.conversation_id}-{id(self)}"},
                "recursion_limit": max(10, self.settings.safety.max_tool_rounds * 3 + 4),
            }
            next_input: Any = {
                "messages": [*self.history, HumanMessage(content=self.user_input)]
            }
            while True:
                interrupted = False
                async for update in graph.astream(
                    next_input, config=config, stream_mode="updates"
                ):
                    if self._cancel_requested.is_set():
                        raise asyncio.CancelledError()
                    if isinstance(update, dict) and "__interrupt__" in update:
                        interrupts = update["__interrupt__"]
                        payload: dict[str, Any] = {}
                        if interrupts:
                            value = getattr(interrupts[0], "value", None)
                            if isinstance(value, dict):
                                payload = dict(value)
                        self._approval_future = self._loop.create_future()
                        audit.write(
                            "approval_requested",
                            calls=payload.get("calls"),
                            reason=payload.get("reason"),
                        )
                        self.approval_required.emit(payload)
                        decision = await self._approval_future
                        if decision is None:
                            raise asyncio.CancelledError()
                        audit.write(
                            "approval_received",
                            approved=bool(decision.get("approved")),
                        )
                        next_input = Command(resume=decision)
                        interrupted = True
                        break
                if not interrupted:
                    break
            audit.write("run_finished", status="complete")
        finally:
            self._approval_future = None


__all__ = ["AgentWorker"]
