"""SSsec 的测试工具集。

网络工具会在调用前记录目标与当前范围策略；范围默认不拦截，可在设置中
切换为“仅提示”或“严格拦截”。命令执行在标准模式下仍需要操作员批准，
“完全权限”对话或关闭审批后会直接执行。工具输出统一为 JSON 字符串，
方便模型读取，也方便 UI 展示与审计。
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import dns.exception
import dns.resolver
import httpx
from langchain_core.tools import BaseTool, tool

from sssec.agent.runtime import AgentContext
from sssec.models import SEVERITIES, new_id, now_iso

MAX_TOOL_OUTPUT = 16000
MAX_HTTP_BODY_BYTES = 262144
MAX_HTTP_BODY_CHARS = 12000
ALLOWED_HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
ALLOWED_DNS_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "PTR"}


def _json(data: Any) -> str:
    text = json.dumps(data, ensure_ascii=False, default=str)
    return truncate_middle(text, MAX_TOOL_OUTPUT)


def _ok(data: dict[str, Any]) -> str:
    return _json({"ok": True, "data": data})


def _err(message: str, **extra: Any) -> str:
    return _json({"ok": False, "error": message, **extra})


def truncate_middle(text: str, limit: int = MAX_TOOL_OUTPUT) -> str:
    if len(text) <= limit:
        return text
    head = int(limit * 0.62)
    tail = limit - head - 24
    return text[:head] + "\n…（输出过长，中间已截断）…\n" + text[-tail:]


def _result_ok(text: str) -> bool:
    try:
        parsed = json.loads(text)
        return bool(parsed.get("ok", True)) if isinstance(parsed, dict) else True
    except Exception:
        return True


async def _read_limited(stream: asyncio.StreamReader, limit: int) -> tuple[bytes, bool]:
    """持续排空子进程输出，但只在内存中保留最多 limit 字节。"""
    chunks: list[bytes] = []
    kept = 0
    truncated = False
    while True:
        chunk = await stream.read(8192)
        if not chunk:
            break
        if kept < limit:
            take = min(len(chunk), limit - kept)
            chunks.append(chunk[:take])
            kept += take
        if kept >= limit:
            truncated = True
    return b"".join(chunks), truncated


async def _http_request(
    ctx: AgentContext,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
) -> str:
    method = (method or "GET").upper().strip()
    if method not in ALLOWED_HTTP_METHODS:
        return _err(f"不支持的 HTTP 方法：{method}")
    decision = ctx.check_url(url)
    if not decision.allowed:
        return _err(f"目标范围拒绝：{decision.reason}")
    if headers is not None and not isinstance(headers, dict):
        return _err("headers 必须是字符串键值对象")

    request_headers = {
        "User-Agent": "SSsec/0.2 (authorized security testing)",
        "Accept": "*/*",
    }
    for key, value in (headers or {}).items():
        if isinstance(key, str) and isinstance(value, (str, int, float)):
            request_headers[key] = str(value)

    # 自定义 Host 头可能把请求导向同一 IP 上的未授权虚拟主机，必须单独校验。
    for key, value in list(request_headers.items()):
        if key.lower() != "host":
            continue
        try:
            header_host = urlsplit("//" + value).hostname or ""
        except ValueError:
            return _err("Host 头格式无效")
        host_decision = ctx.check_host(header_host)
        if not host_decision.allowed:
            return _err(f"Host 头超出目标范围：{host_decision.reason}")
        break

    timeout = max(3, int(ctx.settings.safety.network_timeout))
    redirects: list[str] = []
    current_url = url
    current_method = method
    current_body = body.encode("utf-8") if body is not None else None
    if current_method in ("GET", "HEAD"):
        current_body = None

    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout),
            follow_redirects=False,
            verify=True,
        ) as client:
            for _hop in range(6):
                async with client.stream(
                    current_method,
                    current_url,
                    headers=request_headers,
                    content=current_body,
                ) as response:
                    status_code = response.status_code
                    location = response.headers.get("location")
                    if status_code in (301, 302, 303, 307, 308) and location:
                        next_url = urljoin(current_url, location)
                        next_decision = ctx.check_url(next_url)
                        if not next_decision.allowed:
                            return _err(
                                f"重定向目标超出目标范围：{next_decision.reason}",
                                redirects=redirects + [next_url],
                            )
                        redirects.append(current_url)
                        previous_host = (urlsplit(current_url).hostname or "").lower()
                        next_host = (urlsplit(next_url).hostname or "").lower()
                        current_url = next_url
                        if previous_host != next_host:
                            # 跨主机跳转时移除凭据与 Host 覆盖，避免泄露给另一个目标。
                            for header_name in list(request_headers):
                                if header_name.lower() in (
                                    "authorization",
                                    "cookie",
                                    "proxy-authorization",
                                    "host",
                                ):
                                    request_headers.pop(header_name, None)
                        if status_code == 303 or (
                            status_code in (301, 302) and current_method == "POST"
                        ):
                            current_method = "GET"
                            current_body = None
                        continue

                    raw = bytearray()
                    truncated_body = False
                    async for chunk in response.aiter_bytes():
                        remaining = MAX_HTTP_BODY_BYTES - len(raw)
                        if remaining <= 0:
                            truncated_body = True
                            break
                        raw.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            truncated_body = True
                            break
                    encoding = response.encoding or "utf-8"
                    try:
                        decoded = bytes(raw).decode(encoding, errors="replace")
                    except (LookupError, TypeError):
                        decoded = bytes(raw).decode("utf-8", errors="replace")
                    if len(decoded) > MAX_HTTP_BODY_CHARS:
                        decoded = decoded[:MAX_HTTP_BODY_CHARS]
                        truncated_body = True
                    response_headers = {
                        key: value
                        for key, value in response.headers.items()
                        if len(value) <= 2000
                    }
                    return _ok(
                        {
                            "url": current_url,
                            "method": current_method,
                            "status_code": status_code,
                            "reason": response.reason_phrase,
                            "headers": response_headers,
                            "body": decoded,
                            "body_truncated": truncated_body,
                            "redirects": redirects,
                            "scope_matched": decision.matched,
                            "scope_mode": decision.mode,
                            "scope_warning": decision.warning,
                        }
                    )
            return _err("重定向次数超过 5 次，已停止", redirects=redirects)
    except httpx.TimeoutException:
        return _err(f"HTTP 请求超时（{timeout}s）")
    except httpx.InvalidURL:
        return _err("URL 格式无效")
    except httpx.HTTPError as exc:
        return _err(f"HTTP 请求失败：{type(exc).__name__}: {truncate_middle(str(exc), 500)}")
    except Exception as exc:
        return _err(f"HTTP 请求异常：{type(exc).__name__}: {truncate_middle(str(exc), 500)}")


def _dns_lookup_sync(host: str, record_type: str, timeout: int) -> str:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = min(timeout, 10)
    resolver.lifetime = min(timeout + 3, 15)
    answer = resolver.resolve(host, record_type, lifetime=min(timeout + 3, 15))
    values: list[str] = []
    for record in answer:
        try:
            values.append(record.to_text())
        except Exception:
            values.append(str(record))
    return json.dumps(
        {
            "host": host,
            "record_type": record_type,
            "answers": values[:50],
            "truncated": len(values) > 50,
        },
        ensure_ascii=False,
    )


async def _dns_lookup(ctx: AgentContext, host: str, record_type: str = "A") -> str:
    host = (host or "").strip().rstrip(".")
    record_type = (record_type or "A").upper().strip()
    if record_type not in ALLOWED_DNS_TYPES:
        return _err(f"不支持的记录类型：{record_type}")
    decision = ctx.check_host(host)
    if not decision.allowed:
        return _err(f"目标范围拒绝：{decision.reason}")
    if not host or len(host) > 253:
        return _err("主机名无效")
    try:
        payload = await asyncio.wait_for(
            asyncio.to_thread(
                _dns_lookup_sync,
                host,
                record_type,
                int(ctx.settings.safety.network_timeout),
            ),
            timeout=max(10, ctx.settings.safety.network_timeout + 5),
        )
        data = json.loads(payload)
        data["scope_matched"] = decision.matched
        data["scope_mode"] = decision.mode
        data["scope_warning"] = decision.warning
        return _ok(data)
    except dns.resolver.NXDOMAIN:
        return _err(f"域名不存在（NXDOMAIN）：{host}")
    except dns.resolver.NoAnswer:
        return _err(f"没有 {record_type} 记录：{host}")
    except dns.resolver.NoNameservers:
        return _err("DNS 服务器未返回有效应答")
    except (dns.exception.Timeout, asyncio.TimeoutError):
        return _err("DNS 查询超时")
    except Exception as exc:
        return _err(f"DNS 查询失败：{type(exc).__name__}: {truncate_middle(str(exc), 300)}")


async def _tcp_probe(
    ctx: AgentContext,
    host: str,
    ports: list[int],
    timeout_ms: int = 1200,
) -> str:
    host = (host or "").strip()
    decision = ctx.check_host(host)
    if not decision.allowed:
        return _err(f"目标范围拒绝：{decision.reason}")
    if not isinstance(ports, list) or not ports:
        return _err("ports 必须是非空端口数组")
    cleaned: list[int] = []
    for port in ports:
        try:
            number = int(port)
        except (TypeError, ValueError):
            return _err(f"无效端口：{port}")
        if not 1 <= number <= 65535:
            return _err(f"端口超出范围：{number}")
        if number not in cleaned:
            cleaned.append(number)
    if len(cleaned) > 20:
        return _err("单次最多探测 20 个端口，请分批进行")
    timeout = max(200, min(10000, int(timeout_ms))) / 1000.0
    semaphore = asyncio.Semaphore(8)

    async def probe(port: int) -> dict[str, Any]:
        started = time.perf_counter()
        async with semaphore:
            writer = None
            try:
                _reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=timeout
                )
                return {
                    "port": port,
                    "state": "open",
                    "latency_ms": int((time.perf_counter() - started) * 1000),
                }
            except asyncio.TimeoutError:
                return {"port": port, "state": "timeout"}
            except (ConnectionRefusedError, ConnectionResetError):
                return {"port": port, "state": "closed"}
            except socket.gaierror:
                return {"port": port, "state": "dns_error"}
            except OSError as exc:
                return {
                    "port": port,
                    "state": "error",
                    "error": truncate_middle(str(exc), 160),
                }
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

    started_all = time.perf_counter()
    results = await asyncio.gather(*(probe(port) for port in cleaned))
    return _ok(
        {
            "host": host,
            "scope_matched": decision.matched,
            "scope_mode": decision.mode,
            "scope_warning": decision.warning,
            "results": results,
            "open_ports": [item["port"] for item in results if item["state"] == "open"],
            "elapsed_ms": int((time.perf_counter() - started_all) * 1000),
        }
    )


async def _run_command(ctx: AgentContext, command: str) -> str:
    command = (command or "").strip()
    if not command:
        return _err("命令为空")
    if len(command) > 4000:
        return _err("命令过长（上限 4000 字符）")
    if not ctx.can_execute_shell():
        return _err("当前设置已禁用命令执行工具")
    if not ctx.command_approved:
        return _err("命令未经操作员批准，已拒绝执行")

    timeout = max(5, int(ctx.settings.safety.command_timeout))
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["SSSEC_CONVERSATION_ID"] = ctx.conversation_id
    creationflags = 0
    if sys.platform == "win32":
        shell = shutil.which("powershell.exe") or shutil.which("pwsh.exe") or "powershell.exe"
        prefix = (
            "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new(); "
            "$OutputEncoding = [Console]::OutputEncoding; "
            "$ProgressPreference = 'SilentlyContinue'; "
        )
        args = [
            shell,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            prefix + command,
        ]
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    else:
        args = ["/bin/bash", "-lc", command]

    started = time.perf_counter()
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            cwd=str(ctx.workspace),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
            creationflags=creationflags,
        )
        assert proc.stdout is not None and proc.stderr is not None
        stdout_task = asyncio.create_task(_read_limited(proc.stdout, 300_000))
        stderr_task = asyncio.create_task(_read_limited(proc.stderr, 300_000))
        timed_out = False
        try:
            exit_code = await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            timed_out = True
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=5)
            except asyncio.TimeoutError:
                pass
            exit_code = -1
        stdout_bytes, out_truncated = await stdout_task
        stderr_bytes, err_truncated = await stderr_task
        stdout = stdout_bytes.decode("utf-8", errors="replace")
        stderr = stderr_bytes.decode("utf-8", errors="replace")
        duration = int((time.perf_counter() - started) * 1000)
        if not timed_out and exit_code == 0:
            return _ok(
                {
                    "command": command,
                    "cwd": str(ctx.workspace),
                    "exit_code": exit_code,
                    "stdout": truncate_middle(stdout, 10000),
                    "stderr": truncate_middle(stderr, 5000),
                    "duration_ms": duration,
                    "truncated": out_truncated or err_truncated,
                }
            )
        return _err(
            "命令执行超时，进程已被终止" if timed_out else f"命令退出码 {exit_code}",
            command=command,
            exit_code=exit_code,
            timed_out=timed_out,
            cwd=str(ctx.workspace),
            stdout=truncate_middle(stdout, 10000),
            stderr=truncate_middle(stderr, 5000),
            duration_ms=duration,
            truncated=out_truncated or err_truncated,
        )
    except FileNotFoundError:
        return _err("找不到可用的命令解释器（PowerShell / bash）")
    except Exception as exc:
        return _err(f"命令启动失败：{type(exc).__name__}: {truncate_middle(str(exc), 400)}")
    finally:
        if proc is not None and proc.returncode is None:
            try:
                proc.kill()
            except Exception:
                pass


def _save_finding(
    ctx: AgentContext,
    title: str,
    severity: str,
    description: str,
    target: str = "",
    evidence: str = "",
) -> str:
    severity = (severity or "info").lower().strip()
    if severity not in SEVERITIES:
        return _err(f"严重级别必须是：{', '.join(SEVERITIES)}")
    if not title.strip():
        return _err("标题不能为空")
    finding = {
        "id": new_id(),
        "title": title.strip()[:200],
        "severity": severity,
        "target": (target or "").strip()[:300],
        "description": description.strip()[:4000],
        "evidence": evidence.strip()[:8000],
        "created_at": now_iso(),
    }
    ctx.findings.append(finding)
    ctx.emit_finding(finding)
    return _ok({"finding": finding, "total_findings": len(ctx.findings)})


def _command_summary(command: str) -> str:
    one_line = " ".join(command.split())
    return one_line[:120] + ("…" if len(one_line) > 120 else "")


def build_tools(ctx: AgentContext) -> list[BaseTool]:
    """构建绑定到本次运行上下文的 LangChain 工具。"""

    @tool("http_request")
    async def http_request(
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | None = None,
    ) -> str:
        """对目标发起一次 HTTP 请求并返回状态码、响应头（截断）和响应体（截断）。

        仅允许 http/https；当前范围策略会记录在结果中，严格模式下会拦截范围外目标。
        """
        return await _http_request(ctx, url, method, headers, body)

    @tool("dns_lookup")
    async def dns_lookup(host: str, record_type: str = "A") -> str:
        """查询主机的 DNS 记录。record_type 可选 A、AAAA、CNAME、MX、TXT、NS、SOA、CAA、PTR。"""
        return await _dns_lookup(ctx, host, record_type)

    @tool("tcp_probe")
    async def tcp_probe(host: str, ports: list[int], timeout_ms: int = 1200) -> str:
        """对主机做 TCP 连接探测（不发送应用层数据）。单次最多 20 个端口，返回 open/closed/timeout 状态。"""
        return await _tcp_probe(ctx, host, ports, timeout_ms)

    @tool("run_command")
    async def run_command(command: str) -> str:
        """在会话专属工作目录中执行 PowerShell（Windows）或 bash 命令。

        标准模式下该工具需要操作员批准；开启“完全权限”后直接执行。输出会截断，
        不要执行破坏性、持久化或明显超出测试目的的命令。
        """
        return await _run_command(ctx, command)

    @tool("save_finding")
    def save_finding(
        title: str,
        severity: str,
        description: str,
        target: str = "",
        evidence: str = "",
    ) -> str:
        """把一条已经验证的测试发现记录到当前会话。severity 必须是 critical、high、medium、low、info 之一。"""
        return _save_finding(ctx, title, severity, description, target, evidence)

    tools: list[BaseTool] = [http_request, dns_lookup, tcp_probe]
    if ctx.settings.safety.enable_shell:
        tools.append(run_command)
    tools.append(save_finding)
    return tools


__all__ = [
    "ALLOWED_DNS_TYPES",
    "ALLOWED_HTTP_METHODS",
    "MAX_TOOL_OUTPUT",
    "build_tools",
    "truncate_middle",
]
