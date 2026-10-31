"""模型服务适配：OpenAI 兼容协议、Anthropic 与离线演示模型。"""

from __future__ import annotations

import asyncio
import inspect
import ipaddress
import re
import time
from typing import Any, AsyncIterator
from urllib.parse import urlsplit

import httpx
from langchain_anthropic import ChatAnthropic
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import (
    AIMessage,
    AIMessageChunk,
    BaseMessage,
    HumanMessage,
    SystemMessage,
)
from langchain_core.outputs import ChatGeneration, ChatGenerationChunk, ChatResult
from langchain_openai import ChatOpenAI

from sssec.config import ProviderConfig, SafetySettings


class ModelConfigError(RuntimeError):
    pass


def _is_local_base(base_url: str) -> bool:
    try:
        host = urlsplit(base_url).hostname or ""
    except ValueError:
        return False
    if host in {"localhost", "0.0.0.0", "::1"} or host.endswith(".local"):
        return True
    try:
        address = ipaddress.ip_address(host)
        return address.is_private or address.is_loopback
    except ValueError:
        return False


def validate_provider(provider: ProviderConfig) -> None:
    if provider.type == "demo":
        return
    if provider.type not in {"openai", "anthropic"}:
        raise ModelConfigError(f"不支持的模型服务类型：{provider.type}")
    if not provider.model.strip():
        raise ModelConfigError("尚未填写模型 ID")
    base = provider.base_url.strip()
    if base and not base.startswith(("http://", "https://")):
        raise ModelConfigError("Base URL 必须以 http:// 或 https:// 开头")
    if provider.type == "openai" and not provider.api_key.strip():
        if not (base and _is_local_base(base)):
            raise ModelConfigError(
                "尚未填写 API Key。若使用 Ollama / LM Studio 等本地服务，"
                "请把 Base URL 指向本机地址。"
            )
    if provider.type == "anthropic" and not provider.api_key.strip():
        raise ModelConfigError("Anthropic 服务需要 API Key")


def build_chat_model(
    provider: ProviderConfig,
    safety: SafetySettings,
    *,
    streaming: bool = True,
) -> BaseChatModel:
    validate_provider(provider)
    if provider.type == "demo":
        return DemoChatModel(
            model_name=provider.model or "demo-agent",
            temperature=provider.temperature,
        )

    base_url = provider.base_url.strip().rstrip("/") or None
    api_key = provider.api_key.strip()
    timeout_seconds = max(5, int(safety.network_timeout))

    if provider.type == "openai":
        key = api_key or "not-needed"
        kwargs: dict[str, Any] = {
            "model": provider.model.strip(),
            "api_key": key,
            "temperature": max(0.0, min(2.0, float(provider.temperature))),
            # 必须传 httpx.Timeout 而不是 int/float：
            # langchain_openai 会对可哈希的 timeout 使用模块级 lru_cache 的
            # 全局 httpx.AsyncClient。SSsec 每轮对话都在新的 asyncio loop 中
            # 运行，复用上一个 loop 的连接池会触发
            # “RuntimeError: Event loop is closed”。httpx.Timeout 不可哈希，
            # 会迫使 LangChain 为每个模型实例创建独立的 AsyncClient。
            "timeout": httpx.Timeout(timeout_seconds),
            "max_retries": 2,
            "streaming": streaming,
        }
        if base_url:
            kwargs["base_url"] = base_url
        if provider.max_tokens > 0:
            kwargs["max_tokens"] = provider.max_tokens
        return ChatOpenAI(**kwargs)

    kwargs = {
        "model": provider.model.strip(),
        "api_key": api_key,
        "temperature": max(0.0, min(1.0, float(provider.temperature))),
        "timeout": timeout_seconds,
        "max_retries": 2,
        "streaming": streaming,
        "max_tokens": provider.max_tokens if provider.max_tokens > 0 else 4096,
    }
    if base_url:
        kwargs["base_url"] = base_url
    return ChatAnthropic(**kwargs)


def extract_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, str):
                parts.append(block)
            elif isinstance(block, dict):
                block_type = block.get("type")
                if block_type in (None, "text", "output_text"):
                    text = block.get("text")
                    if isinstance(text, str):
                        parts.append(text)
        return "".join(parts)
    return ""


def _extract_reasoning(additional_kwargs: dict[str, Any] | None) -> str:
    if not additional_kwargs:
        return ""
    for key in ("reasoning_content", "reasoning", "thinking"):
        value = additional_kwargs.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


async def aclose_model(model: BaseChatModel | None) -> None:
    """在当前事件循环仍打开时关闭模型底层的异步 HTTP 客户端。

    ChatOpenAI 的 ``root_async_client`` 是 openai.AsyncOpenAI，它的
    ``close()`` 是协程。必须在 Worker 的 asyncio loop 关闭前调用，
    否则连接池可能持有已关闭 loop 上的 transport。
    """
    if model is None:
        return
    client = getattr(model, "root_async_client", None)
    if client is None:
        return
    for name in ("aclose", "close"):
        closer = getattr(client, name, None)
        if closer is None:
            continue
        try:
            result = closer()
            if inspect.isawaitable(result):
                await result
        except Exception:
            pass
        return


def friendly_error(exc: Exception, provider: ProviderConfig | None = None) -> str:
    text = str(exc) or type(exc).__name__
    if provider and provider.api_key:
        text = text.replace(provider.api_key, "***")
    lower = text.lower()
    name = type(exc).__name__
    if any(token in lower for token in ("401", "invalid api key", "unauthorized")):
        return "认证失败：请检查 API Key 是否正确、是否已过期。"
    if any(token in lower for token in ("403", "permission")):
        return "服务拒绝访问（403）：请检查 Key 的权限或模型访问资格。"
    if any(token in lower for token in ("404", "not found")):
        return "服务返回 404：请检查 Base URL 与模型 ID 是否正确。"
    if any(token in lower for token in ("429", "rate limit", "quota")):
        return "请求频率或额度受限（429）：请稍后重试，或检查账户余额。"
    if any(
        token in lower
        for token in (
            "connection",
            "connect",
            "timeout",
            "timed out",
            "network",
            "dns",
            "ssl",
        )
    ):
        return f"无法连接模型服务：{text[:300]}"
    if "tool" in lower and any(
        token in lower for token in ("support", "not supported", "invalid")
    ):
        return f"当前模型可能不支持工具调用：{text[:300]}"
    text = re.sub(r"\s+", " ", text).strip()
    return f"{name}：{text[:600]}"


def _demo_scope_hint(messages: list[BaseMessage]) -> str:
    for message in messages:
        if isinstance(message, SystemMessage):
            content = extract_text(message.content)
            match = re.search(r"当前记录的目标范围:\s*(.+)", content)
            if match:
                return match.group(1).strip()
            match = re.search(r"当前授权目标（硬边界）:\s*(.+)", content)
            if match:
                return match.group(1).strip()
    return "未设置"


def _demo_full_permission(messages: list[BaseMessage]) -> bool:
    for message in messages:
        if isinstance(message, SystemMessage):
            content = extract_text(message.content)
            if "完全权限" in content and "本对话所有工具调用均无需人工确认" in content:
                return True
            if "当前为全局完全权限模式" in content:
                return True
    return False


class DemoChatModel(BaseChatModel):
    """无需网络、用于首次启动体验的离线模型。

    它不发起任何真实工具调用，所有回答都由本地模板生成。
    """

    model_name: str = "demo-agent"
    temperature: float = 0.2

    @property
    def _llm_type(self) -> str:
        return "sssec-demo"

    def bind_tools(self, tools: Any, **kwargs: Any) -> "DemoChatModel":
        return self

    def _build_reply(self, messages: list[BaseMessage]) -> str:
        last_human = ""
        for message in reversed(messages):
            if isinstance(message, HumanMessage):
                last_human = extract_text(message.content)
                break
        scope = _demo_scope_hint(messages)
        full_access = _demo_full_permission(messages)
        asked = last_human.strip().replace("\n", " ")
        if len(asked) > 60:
            asked = asked[:60] + "…"
        if full_access:
            scope_line = (
                "当前对话已开启 **完全权限**：工具调用不再请求确认，也不按目标范围拦截。"
                "接入真实模型后，命令会直接执行，请在受控环境中使用。"
            )
        elif scope not in ("未设置", "未授权", "", "未设置（不限制目标）"):
            scope_line = (
                f"当前会话测试目标：`{scope}`。范围默认仅作为提示与审计记录；"
                "可在设置中开启严格拦截，或为对话开启完全权限。"
            )
        else:
            scope_line = (
                "当前会话**未设置目标提示**：默认不限制目标，工具仍可执行。"
                "你可以点击右上角的目标按钮添加提示范围，或在设置中开启严格拦截。"
            )
        return f"""### 离线演示模式

你好，我是 **SSsec**。你刚才的问题是：「{asked or "（空消息）"}」

我目前运行在本地离线演示模型上：不会连接任何外部 API，也不会真的扫描或执行命令。你可以先用我体验流式对话、明暗主题、多会话、工具审批、完全权限和测试发现界面。

{scope_line}

接入真实模型后，我可以调用以下工具：

| 工具 | 用途 | 审批 |
| --- | --- | --- |
| `http_request` | 发起 HTTP 探测 | 标准模式自动执行（写请求需确认） |
| `dns_lookup` | 查询 A / AAAA / MX / TXT 等记录 | 自动执行 |
| `tcp_probe` | 对目标做有限 TCP 连通性检查 | 自动执行 |
| `run_command` | 在会话工作目录执行 PowerShell | 标准模式逐条批准；完全权限直接执行 |
| `save_finding` | 记录漏洞发现与证据 | 自动记录 |

**下一步**：点击左下角「设置」→「模型服务」，填入 OpenAI 兼容或 Anthropic 模型服务的信息，然后保存并设为当前模型即可。需要减少确认步骤时，可在对话顶部开启「完全权限」。

> SSsec 仅应用于已获得明确授权的安全测试。请始终确认你的测试活动符合授权范围与当地法律。"""

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> ChatResult:
        return ChatResult(
            generations=[
                ChatGeneration(message=AIMessage(content=self._build_reply(messages)))
            ]
        )

    async def _astream(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: Any = None,
        **kwargs: Any,
    ) -> AsyncIterator[ChatGenerationChunk]:
        text = self._build_reply(messages)
        # 按 2~4 个字符切片，模拟自然流式输出，同时避免逐字 sleep 过慢。
        index = 0
        while index < len(text):
            step = 3 if index % 7 else 4
            piece = text[index : index + step]
            index += step
            if run_manager is not None:
                await run_manager.on_llm_new_token(piece)
            yield ChatGenerationChunk(message=AIMessageChunk(content=piece))
            await asyncio.sleep(0.006)


async def test_provider(provider: ProviderConfig, safety: SafetySettings) -> dict[str, Any]:
    """用一次最小请求验证服务是否可用。"""
    started = time.perf_counter()
    model: BaseChatModel | None = None
    try:
        model = build_chat_model(provider, safety, streaming=False)
        reply = await asyncio.wait_for(
            model.ainvoke(
                [
                    SystemMessage(content="你是连接测试助手。"),
                    HumanMessage(content="只回复：SSsec 连接正常"),
                ]
            ),
            timeout=max(20, safety.network_timeout + 10),
        )
        latency = int((time.perf_counter() - started) * 1000)
        text = extract_text(reply.content).strip() or "（服务返回了空内容）"
        return {
            "ok": True,
            "message": f"连接成功（{latency} ms）：{text[:160]}",
            "latency_ms": latency,
        }
    except Exception as exc:
        return {"ok": False, "message": friendly_error(exc, provider), "latency_ms": 0}
    finally:
        await aclose_model(model)


__all__ = [
    "DemoChatModel",
    "ModelConfigError",
    "aclose_model",
    "build_chat_model",
    "extract_text",
    "extract_reasoning",
    "friendly_error",
    "test_provider",
    "validate_provider",
]


def extract_reasoning(chunk: Any) -> str:
    additional = getattr(chunk, "additional_kwargs", None) or {}
    return _extract_reasoning(additional)
