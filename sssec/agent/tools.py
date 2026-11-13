"""SSsec 的测试工具集。

网络工具会在调用前记录目标与当前范围策略；范围默认不拦截，可在设置中
切换为“仅提示”或“严格拦截”。命令执行在默认宽松模式下只对高风险命令
请求确认，保守模式逐条批准，“完全权限”对话会直接执行。工具输出统一为
JSON 字符串，方便模型读取，也方便 UI 展示与审计。
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import dns.exception
import dns.resolver
import httpx
from langchain_core.tools import BaseTool, tool

from sssec import __version__
from sssec.agent.runtime import AgentContext
from sssec.agent.state import HANDOFF_TARGETS
from sssec.agent.toolkit import (
    MAX_TOOL_OUTPUT,
    err as _err,
    normalize_host as _normalize_host,
    ok as _ok,
    read_limited as _read_limited,
    result_ok as _result_ok,
    safe_workspace_path,
    truncate_middle,
)
from sssec.agent.tools_ctf import build_ctf_tools
from sssec.agent.tools_recon import build_recon_tools
from sssec.agent.tools_web import build_web_tools
from sssec.models import SEVERITIES, new_id, now_iso

MAX_HTTP_BODY_BYTES = 262144
MAX_HTTP_BODY_CHARS = 12000
ALLOWED_HTTP_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
ALLOWED_DNS_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "PTR"}


def _safe_workspace_path(ctx: AgentContext, raw_path: str) -> Path:
    return safe_workspace_path(ctx.workspace, raw_path)


async def _whois_lookup(ctx: AgentContext, host: str) -> str:
    host = _normalize_host(host)
    if not host:
        return _err("主机名无效")
    decision = ctx.check_host(host)
    if not decision.allowed:
        return _err(f"目标范围拒绝：{decision.reason}")

    timeout = max(5, int(ctx.settings.safety.network_timeout))

    async def query(server: str, payload: str) -> str:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(server, 43), timeout=timeout
        )
        try:
            writer.write(payload.encode("utf-8", errors="ignore"))
            await writer.drain()
            data, _truncated = await _read_limited(reader, 24_000)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        return data.decode("utf-8", errors="replace")

    try:
        first = await asyncio.wait_for(query("whois.iana.org", host + "\r\n"), timeout=timeout + 3)
    except (OSError, asyncio.TimeoutError) as exc:
        return _err(f"WHOIS 查询失败：{type(exc).__name__}: {truncate_middle(str(exc), 300)}")

    referral = None
    for line in first.splitlines():
        if line.lower().startswith("refer:"):
            referral = line.split(":", 1)[1].strip()
            break

    response = first
    used_server = "whois.iana.org"
    if referral and referral != used_server and len(referral) <= 253:
        try:
            response = await asyncio.wait_for(
                query(referral, host + "\r\n"), timeout=timeout + 3
            )
            used_server = referral
        except (OSError, asyncio.TimeoutError):
            # 转介服务器失败时保留 IANA 的返回。
            pass

    return _ok(
        {
            "host": host,
            "server": used_server,
            "response": truncate_middle(response, 12000),
            "scope_matched": decision.matched,
            "scope_mode": decision.mode,
            "scope_warning": decision.warning,
        }
    )


def _name_to_dict(name: Any) -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        for item in name or ():
            for key, value in item:
                result[str(key)] = str(value)
    except Exception:
        pass
    return result


async def _tls_certificate(ctx: AgentContext, host: str, port: int = 443) -> str:
    host = _normalize_host(host)
    if not host:
        return _err("主机名无效")
    try:
        port = int(port)
    except (TypeError, ValueError):
        return _err("端口无效")
    if not 1 <= port <= 65535:
        return _err("端口超出范围")
    decision = ctx.check_host(host)
    if not decision.allowed:
        return _err(f"目标范围拒绝：{decision.reason}")

    timeout = max(5, int(ctx.settings.safety.network_timeout))
    context = ssl.create_default_context()
    writer = None
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=context, server_hostname=host),
            timeout=timeout,
        )
        ssl_object = writer.get_extra_info("ssl_object")
        if ssl_object is None:
            return _err("未能建立 TLS 会话")
        cert = ssl_object.getpeercert() or {}
        cipher = ssl_object.cipher() or ("", "", 0)
        version = ssl_object.version() or ""
        expires_at = cert.get("notAfter", "")
        days_remaining = None
        try:
            expires_at = ssl.cert_time_to_seconds(expires_at)
            days_remaining = int((expires_at - time.time()) // 86400)
            expires_at = datetime.fromtimestamp(expires_at).astimezone().isoformat(
                timespec="seconds"
            )
        except Exception:
            pass
        return _ok(
            {
                "host": host,
                "port": port,
                "tls_version": version,
                "cipher": {"name": cipher[0], "protocol": cipher[1], "bits": cipher[2]},
                "subject": _name_to_dict(cert.get("subject")),
                "issuer": _name_to_dict(cert.get("issuer")),
                "serial_number": cert.get("serialNumber", ""),
                "not_before": cert.get("notBefore", ""),
                "not_after": expires_at,
                "days_remaining": days_remaining,
                "subject_alt_names": [
                    value for kind, value in (cert.get("subjectAltName") or ()) if kind == "DNS"
                ][:50],
                "scope_matched": decision.matched,
                "scope_mode": decision.mode,
                "scope_warning": decision.warning,
            }
        )
    except ssl.SSLError as exc:
        return _err(f"TLS 握手失败：{truncate_middle(str(exc), 400)}")
    except (OSError, asyncio.TimeoutError) as exc:
        return _err(f"TLS 连接失败：{type(exc).__name__}: {truncate_middle(str(exc), 300)}")
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def _workspace_list(ctx: AgentContext, path: str = ".") -> str:
    try:
        target = _safe_workspace_path(ctx, path)
    except ValueError as exc:
        return _err(str(exc))
    if not target.exists():
        return _err(f"路径不存在：{target.relative_to(Path(ctx.workspace).resolve())}")
    if target.is_file():
        stat = target.stat()
        return _ok(
            {
                "path": str(target.relative_to(Path(ctx.workspace).resolve())),
                "type": "file",
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime)
                .astimezone()
                .isoformat(timespec="seconds"),
            }
        )
    entries = []
    for child in sorted(target.iterdir(), key=lambda item: (item.is_file(), item.name.lower())):
        try:
            stat = child.stat()
            entries.append(
                {
                    "name": child.name,
                    "type": "dir" if child.is_dir() else "file",
                    "size": 0 if child.is_dir() else stat.st_size,
                    "modified": datetime.fromtimestamp(stat.st_mtime)
                    .astimezone()
                    .isoformat(timespec="seconds"),
                }
            )
        except OSError:
            continue
        if len(entries) >= 200:
            break
    return _ok(
        {
            "path": str(target.relative_to(Path(ctx.workspace).resolve())),
            "entries": entries,
            "truncated": len(entries) >= 200,
        }
    )


def _workspace_read(ctx: AgentContext, path: str, max_bytes: int = 20000) -> str:
    try:
        target = _safe_workspace_path(ctx, path)
    except ValueError as exc:
        return _err(str(exc))
    if not target.exists() or not target.is_file():
        return _err("文件不存在")
    try:
        limit = max(1, min(200000, int(max_bytes)))
    except (TypeError, ValueError):
        limit = 20000
    try:
        with target.open("rb") as handle:
            data = handle.read(limit + 1)
    except OSError as exc:
        return _err(f"读取失败：{exc}")
    truncated = len(data) > limit
    data = data[:limit]
    text = data.decode("utf-8", errors="replace")
    return _ok(
        {
            "path": str(target.relative_to(Path(ctx.workspace).resolve())),
            "size": target.stat().st_size,
            "truncated": truncated,
            "content": text,
        }
    )


def _workspace_write(
    ctx: AgentContext,
    path: str,
    content: str,
    append: bool = False,
) -> str:
    try:
        target = _safe_workspace_path(ctx, path)
    except ValueError as exc:
        return _err(str(exc))
    text = str(content or "")
    if len(text) > 200000:
        return _err("内容过长（上限 200000 字符）")
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        if append and target.exists():
            with target.open("a", encoding="utf-8") as handle:
                handle.write(text)
        else:
            target.write_text(text, encoding="utf-8")
    except OSError as exc:
        return _err(f"写入失败：{exc}")
    return _ok(
        {
            "path": str(target.relative_to(Path(ctx.workspace).resolve())),
            "size": target.stat().st_size,
            "append": bool(append),
        }
    )


async def _http_request(
    ctx: AgentContext,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
    insecure: bool = False,
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
        "User-Agent": f"SSsec/{__version__} (authorized security testing)",
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
            verify=not insecure,
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


async def _security_headers(ctx: AgentContext, url: str, insecure: bool = False) -> str:
    """拉取一次响应并做常见安全响应头/信息泄露检查。"""
    raw = await _http_request(ctx, url, "GET", insecure=insecure)
    try:
        parsed = json.loads(raw)
    except Exception:
        return raw if isinstance(raw, str) else _err("响应解析失败")
    if not isinstance(parsed, dict) or not parsed.get("ok"):
        return _err(
            "HTTP 请求失败，无法分析响应头",
            detail=str(parsed.get("error") if isinstance(parsed, dict) else parsed)[:500],
        )
    data = parsed.get("data") or {}
    headers = {
        str(key).lower(): str(value)
        for key, value in (data.get("headers") or {}).items()
    }

    checks = {
        "content-security-policy": "限制脚本/资源来源，降低 XSS 影响",
        "strict-transport-security": "强制 HTTPS，降低降级与中间人风险",
        "x-frame-options": "限制页面被第三方框架嵌入",
        "x-content-type-options": "阻止 MIME 类型嗅探",
        "referrer-policy": "限制 Referer 中的敏感信息",
        "permissions-policy": "限制浏览器特性权限",
        "cross-origin-opener-policy": "隔离跨源窗口",
        "cross-origin-resource-policy": "限制跨源资源读取",
    }
    missing = [
        {"header": header, "recommendation": reason}
        for header, reason in checks.items()
        if header not in headers
    ]
    present = [
        {"header": header, "value": headers.get(header, "")[:500]}
        for header in checks
        if header in headers
    ]

    disclosure = []
    for header in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        if header in headers:
            disclosure.append({"header": header, "value": headers[header][:300]})

    cookie_issues: list[dict[str, str]] = []
    for key, value in (data.get("headers") or {}).items():
        if str(key).lower() != "set-cookie":
            continue
        lowered = str(value).lower()
        issues = []
        if "secure" not in lowered:
            issues.append("缺少 Secure")
        if "httponly" not in lowered:
            issues.append("缺少 HttpOnly")
        if "samesite" not in lowered:
            issues.append("缺少 SameSite")
        if issues:
            cookie_issues.append(
                {"cookie": str(value).split(";", 1)[0][:200], "issues": issues}
            )

    recommendations = [item["recommendation"] for item in missing]
    if disclosure:
        recommendations.append("收敛 Server / X-Powered-By 等版本与框架信息")
    if cookie_issues:
        recommendations.append("为 Cookie 增加 Secure / HttpOnly / SameSite 属性")

    return _ok(
        {
            "url": data.get("url") or url,
            "status_code": data.get("status_code"),
            "present_headers": present,
            "missing_headers": missing,
            "cookie_issues": cookie_issues,
            "information_disclosure": disclosure,
            "recommendations": recommendations,
            "scope_matched": data.get("scope_matched"),
            "scope_mode": data.get("scope_mode"),
            "scope_warning": data.get("scope_warning"),
        }
    )


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


def _build_tool_definitions(
    ctx: AgentContext,
    names: list[str] | tuple[str, ...] | None = None,
) -> list[BaseTool]:
    """构建绑定到本次运行上下文的 LangChain 工具。"""

    @tool("http_request")
    async def http_request(
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: str | None = None,
        insecure: bool = False,
    ) -> str:
        """对目标发起一次 HTTP 请求并返回状态码、响应头（截断）和响应体（截断）。

        仅允许 http/https；当前范围策略会记录在结果中，严格模式下会拦截范围外目标。
        ``insecure=True`` 可跳过 TLS 证书校验，仅用于 CTF/自签名靶场。
        """
        return await _http_request(ctx, url, method, headers, body, insecure)

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

        默认宽松模式下只有明显高风险命令需要操作员确认；保守模式逐条批准；
        完全权限直接执行。输出会截断，不要执行破坏性、持久化或明显超出
        测试目的的命令。
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

    @tool("whois_lookup")
    async def whois_lookup(host: str) -> str:
        """查询域名或 IP 的 WHOIS 注册信息（先查 IANA，再自动跟随 refer 转介）。"""
        return await _whois_lookup(ctx, host)

    @tool("tls_certificate")
    async def tls_certificate(host: str, port: int = 443) -> str:
        """读取目标 TLS 证书的颁发者、有效期、SAN、协议版本与加密套件。"""
        return await _tls_certificate(ctx, host, port)

    @tool("security_headers")
    async def security_headers(url: str, insecure: bool = False) -> str:
        """检查目标 HTTP 安全响应头、Cookie 属性与 Server/X-Powered-By 信息泄露。"""
        return await _security_headers(ctx, url, insecure)

    @tool("workspace_list")
    def workspace_list(path: str = ".") -> str:
        """列出会话工作目录中的文件与子目录（限制在工作目录内）。"""
        return _workspace_list(ctx, path)

    @tool("workspace_read")
    def workspace_read(path: str, max_bytes: int = 20000) -> str:
        """读取会话工作目录中的文本文件（限制在工作目录内，最多 200000 字节）。"""
        return _workspace_read(ctx, path, max_bytes)

    @tool("workspace_write")
    def workspace_write(path: str, content: str, append: bool = False) -> str:
        """把文本写入会话工作目录（限制在工作目录内）。用于保存证据、脚本和中间结果。"""
        return _workspace_write(ctx, path, content, append)

    mapping: dict[str, BaseTool] = {
        "http_request": http_request,
        "dns_lookup": dns_lookup,
        "tcp_probe": tcp_probe,
        "save_finding": save_finding,
        "whois_lookup": whois_lookup,
        "tls_certificate": tls_certificate,
        "security_headers": security_headers,
        "workspace_list": workspace_list,
        "workspace_read": workspace_read,
        "workspace_write": workspace_write,
    }
    mapping.update(build_recon_tools(ctx))
    mapping.update(build_web_tools(ctx))
    mapping.update(build_ctf_tools(ctx))
    if ctx.settings.safety.enable_shell:
        mapping["run_command"] = run_command
    if names is None:
        return list(mapping.values())
    return [mapping[name] for name in names if name in mapping]


@tool("handoff")
def handoff(
    next_agent: str,
    task: str,
    reason: str = "",
    summary: str = "",
) -> str:
    """当你完成当前阶段、确认可以把任务交给下一个阶段时调用。

    next_agent 必须是 recon、vuln_analysis、exploit、post_exploit 或 finish。
    调用后当前子 Agent 会结束，由指挥官决定是否采纳这次交接。
    """
    target = str(next_agent or "").strip()
    if target not in HANDOFF_TARGETS:
        return _err(
            "next_agent 必须是 recon、vuln_analysis、exploit、post_exploit 或 finish",
            allowed=list(HANDOFF_TARGETS),
        )
    brief = str(task or "").strip()
    if target != "finish" and not brief:
        return _err("交接给下一个 Agent 时 task 不能为空")
    return _ok(
        {
            "next_agent": target,
            "task": brief[:4000],
            "reason": str(reason or "").strip()[:1000],
            "summary": str(summary or "").strip()[:4000],
        }
    )


def build_tools(
    ctx: AgentContext,
    names: list[str] | tuple[str, ...] | None = None,
) -> list[BaseTool]:
    """构建工具列表。

    ``names`` 为空时返回全部可用工具；子 Agent 传入自己的工具名即可获得
    专属工具集，实现“每个阶段各自丰富工具”。
    """
    return _build_tool_definitions(ctx, names)


def build_worker_tools(
    ctx: AgentContext,
    names: list[str] | tuple[str, ...],
) -> list[BaseTool]:
    """子 Agent 工具集：专属工具 + 交接工具。"""
    tools = _build_tool_definitions(ctx, names)
    tools.append(handoff)
    return tools


__all__ = [
    "ALLOWED_DNS_TYPES",
    "ALLOWED_HTTP_METHODS",
    "MAX_TOOL_OUTPUT",
    "build_tools",
    "build_worker_tools",
    "handoff",
    "truncate_middle",
]
