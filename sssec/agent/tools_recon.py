"""信息收集工具：HTTP 指纹、端口扫描、子域枚举、目录发现、爬虫与 DNS 区域传送。"""

from __future__ import annotations

import asyncio
import json
import re
import socket
import uuid
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

import dns.asyncresolver
import dns.query
import dns.resolver
import dns.zone
import httpx
from langchain_core.tools import BaseTool, tool

from sssec.agent.runtime import AgentContext
from sssec.agent.toolkit import err, normalize_host, ok, parse_ports, truncate_middle

COMMON_PORTS = [
    21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139, 143,
    161, 389, 443, 445, 465, 500, 514, 515, 548, 587, 631, 636, 873, 990, 993,
    995, 1080, 1099, 1433, 1521, 1723, 1883, 2049, 2181, 2375, 2376, 3000, 3306,
    3389, 3690, 4369, 5000, 5432, 5601, 5672, 5900, 5984, 6379, 7001, 8000, 8008,
    8080, 8081, 8088, 8443, 8888, 9000, 9090, 9200, 9300, 11211, 15672, 27017,
]

SERVICE_HINTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    161: "snmp", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    514: "syslog", 587: "smtp-submission", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    11211: "memcached", 27017: "mongodb",
}

SUBDOMAIN_WORDS = [
    "www", "api", "admin", "administrator", "app", "apps", "auth", "beta",
    "blog", "cdn", "cloud", "cms", "console", "dashboard", "demo", "dev",
    "developer", "docs", "download", "ftp", "git", "gitlab", "grafana", "help",
    "internal", "intranet", "jenkins", "jira", "kibana", "lab", "login", "mail",
    "manage", "m", "mobile", "monitor", "nas", "oa", "ops", "panel", "pay",
    "portal", "pre", "prod", "proxy", "qa", "remote", "s3", "sandbox", "shop",
    "stage", "staging", "static", "status", "support", "test", "testing", "vpn",
    "web", "wiki", "work", "www2", "zabbix",
]

DIR_WORDS = [
    ".git/config", ".env", ".svn/entries", "admin", "api", "api/docs",
    "api/swagger.json", "swagger", "swagger-ui", "actuator", "actuator/env",
    "backup", "backup.zip", "backups", "config", "config.php", "console",
    "dashboard", "db.sql", "debug", "docs", "download", "file", "files",
    "graphql", "health", "index.php", "info.php", "login", "log", "logs",
    "manage", "metrics", "old", "phpinfo.php", "robots.txt", "server-status",
    "sitemap.xml", "source", "src", "static", "test", "tmp", "upload", "uploads",
    "user", "users", "web.config", "wp-admin", "wp-config.php", "wp-login.php",
]

_TECH_SIGNATURES = {
    "wordpress": ("wp-content", "wp-includes", "wordpress"),
    "drupal": ("drupal", "sites/default/files"),
    "joomla": ("joomla", "/components/com_"),
    "nginx": ("nginx",),
    "apache": ("apache",),
    "iis": ("microsoft-iis",),
    "php": ("php", "x-powered-by: php"),
    "aspnet": ("asp.net", "x-aspnet-version"),
    "react": ("react", "_next/static", "data-reactroot"),
    "vue": ("vue.js", "vue.min.js", "__vue__"),
    "nextjs": ("__next_data__", "_next/static"),
    "nuxt": ("__nuxt__",),
    "jquery": ("jquery",),
    "bootstrap": ("bootstrap",),
    "cloudflare": ("cloudflare", "cf-ray"),
    "spring": ("whitelabel error page", "spring"),
    "tomcat": ("tomcat",),
    "jenkins": ("jenkins",),
    "gitlab": ("gitlab",),
    "grafana": ("grafana",),
    "kibana": ("kibana",),
    "elasticsearch": ("elasticsearch", "you know, for search"),
}


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.scripts: list[str] = []
        self.forms: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): (value or "") for key, value in attrs}
        if tag in ("a", "link") and values.get("href"):
            self.links.append(values["href"])
        if tag == "script" and values.get("src"):
            self.scripts.append(values["src"])
        if tag == "form" and values.get("action"):
            self.forms.append(values["action"])


def _title(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.I | re.S)
    if not match:
        return ""
    return re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", match.group(1))).strip()[:200]


def _technologies(headers: dict[str, str], body: str) -> list[str]:
    haystack = (" ".join(f"{k}: {v}" for k, v in headers.items()) + " " + body).lower()
    found = []
    for name, signatures in _TECH_SIGNATURES.items():
        if any(signature in haystack for signature in signatures):
            found.append(name)
    return sorted(set(found))


async def _fetch(
    client: httpx.AsyncClient,
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    content: bytes | None = None,
    max_body: int = 200_000,
) -> dict[str, Any]:
    response = await client.request(
        method, url, headers=headers, content=content, follow_redirects=False
    )
    raw = await response.aread()
    text = raw[:max_body].decode(response.encoding or "utf-8", errors="replace")
    return {
        "status_code": response.status_code,
        "reason": response.reason_phrase,
        "headers": {k: v for k, v in response.headers.items() if len(v) <= 2000},
        "body": text,
        "truncated": len(raw) > max_body,
        "url": str(response.url),
    }


async def _http_probe(ctx: AgentContext, url: str, insecure: bool = False) -> str:
    decision = ctx.check_url(url)
    if not decision.allowed:
        return err(f"目标范围拒绝：{decision.reason}")
    timeout = max(5, int(ctx.settings.safety.network_timeout))
    redirects: list[str] = []
    current = url
    try:
        async with httpx.AsyncClient(
            timeout=httpx.Timeout(timeout), follow_redirects=False, verify=not insecure
        ) as client:
            data: dict[str, Any] = {}
            for _hop in range(6):
                data = await _fetch(client, current, max_body=120_000)
                location = data["headers"].get("location") or data["headers"].get("Location")
                if data["status_code"] in (301, 302, 303, 307, 308) and location:
                    next_url = urljoin(current, location)
                    next_decision = ctx.check_url(next_url)
                    if not next_decision.allowed:
                        return err(
                            f"重定向目标超出目标范围：{next_decision.reason}",
                            redirects=redirects + [next_url],
                        )
                    redirects.append(current)
                    current = next_url
                    continue
                break
            headers = data.get("headers") or {}
            body = data.get("body") or ""
            cookies = []
            for key, value in headers.items():
                if key.lower() != "set-cookie":
                    continue
                lowered = value.lower()
                cookies.append(
                    {
                        "cookie": value.split(";", 1)[0][:200],
                        "secure": "secure" in lowered,
                        "httponly": "httponly" in lowered,
                        "samesite": "samesite" in lowered,
                    }
                )
            return ok(
                {
                    "url": data.get("url") or current,
                    "status_code": data.get("status_code"),
                    "reason": data.get("reason"),
                    "title": _title(body),
                    "technologies": _technologies(headers, body),
                    "server": headers.get("server") or headers.get("Server", ""),
                    "powered_by": headers.get("x-powered-by")
                    or headers.get("X-Powered-By", ""),
                    "content_type": headers.get("content-type")
                    or headers.get("Content-Type", ""),
                    "cookies": cookies[:30],
                    "redirects": redirects,
                    "body_preview": truncate_middle(body, 1200),
                    "scope_matched": decision.matched,
                    "scope_mode": decision.mode,
                    "scope_warning": decision.warning,
                }
            )
    except httpx.TimeoutException:
        return err(f"HTTP 探测超时（{timeout}s）")
    except httpx.HTTPError as exc:
        return err(f"HTTP 探测失败：{type(exc).__name__}: {truncate_middle(str(exc), 300)}")
    except Exception as exc:
        return err(f"HTTP 探测异常：{type(exc).__name__}: {truncate_middle(str(exc), 300)}")


async def _port_scan(
    ctx: AgentContext,
    host: str,
    ports: Any = None,
    timeout_ms: int = 800,
    banner: bool = False,
) -> str:
    host = normalize_host(host)
    if not host:
        return err("主机名无效")
    decision = ctx.check_host(host)
    if not decision.allowed:
        return err(f"目标范围拒绝：{decision.reason}")
    selected = parse_ports(ports, COMMON_PORTS)
    if not selected:
        return err("未提供有效端口")
    if len(selected) > 500:
        return err("单次最多扫描 500 个端口，请分批进行")
    timeout = max(0.2, min(10.0, int(timeout_ms) / 1000.0))
    semaphore = asyncio.Semaphore(64)

    async def probe(port: int) -> dict[str, Any]:
        async with semaphore:
            started = asyncio.get_running_loop().time()
            writer = None
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=timeout
                )
                result: dict[str, Any] = {
                    "port": port,
                    "state": "open",
                    "service": SERVICE_HINTS.get(port, ""),
                    "latency_ms": int(
                        (asyncio.get_running_loop().time() - started) * 1000
                    ),
                }
                if banner:
                    try:
                        raw = await asyncio.wait_for(reader.read(256), timeout=0.4)
                        if raw:
                            result["banner"] = raw.decode("utf-8", errors="replace")[:300]
                    except (asyncio.TimeoutError, OSError):
                        pass
                return result
            except asyncio.TimeoutError:
                return {"port": port, "state": "timeout", "service": SERVICE_HINTS.get(port, "")}
            except (ConnectionRefusedError, ConnectionResetError):
                return {"port": port, "state": "closed", "service": SERVICE_HINTS.get(port, "")}
            except socket.gaierror:
                return {"port": port, "state": "dns_error"}
            except OSError as exc:
                return {"port": port, "state": "error", "error": str(exc)[:200]}
            finally:
                if writer is not None:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

    started_all = asyncio.get_running_loop().time()
    results = await asyncio.gather(*(probe(port) for port in selected))
    open_ports = [item for item in results if item.get("state") == "open"]
    return ok(
        {
            "host": host,
            "scanned": len(selected),
            "open_ports": open_ports,
            "results": results,
            "elapsed_ms": int((asyncio.get_running_loop().time() - started_all) * 1000),
            "scope_matched": decision.matched,
            "scope_mode": decision.mode,
            "scope_warning": decision.warning,
        }
    )


async def _subdomain_enum(
    ctx: AgentContext,
    domain: str,
    wordlist: Any = None,
    limit: int = 100,
) -> str:
    domain = normalize_host(domain)
    if not domain:
        return err("域名无效")
    decision = ctx.check_host(domain)
    if not decision.allowed:
        return err(f"目标范围拒绝：{decision.reason}")
    words = SUBDOMAIN_WORDS
    if wordlist:
        if isinstance(wordlist, str):
            words = [item.strip() for item in re.split(r"[\s,;]+", wordlist) if item.strip()]
        elif isinstance(wordlist, (list, tuple)):
            words = [str(item).strip() for item in wordlist if str(item).strip()]
    words = words[: max(1, min(500, int(limit)))]
    resolver = dns.asyncresolver.Resolver(configure=True)
    resolver.timeout = max(1, int(ctx.settings.safety.network_timeout) / 2)
    resolver.lifetime = max(2, int(ctx.settings.safety.network_timeout))
    semaphore = asyncio.Semaphore(20)
    wildcard_ips: set[str] = set()
    try:
        random_label = f"sssec-{uuid.uuid4().hex[:10]}"
        wildcard = await resolver.resolve(random_label + "." + domain, "A")
        wildcard_ips = {str(item) for item in wildcard}
    except Exception:
        wildcard_ips = set()

    async def check(label: str) -> dict[str, Any] | None:
        host = f"{label}.{domain}"
        child_decision = ctx.check_host(host)
        if not child_decision.allowed:
            return None
        async with semaphore:
            try:
                answer = await resolver.resolve(host, "A")
                ips = [str(item) for item in answer]
                if wildcard_ips and set(ips) <= wildcard_ips:
                    return None
                return {"host": host, "ips": ips}
            except Exception:
                return None

    results = await asyncio.gather(*(check(label) for label in words))
    found = [item for item in results if item]
    return ok(
        {
            "domain": domain,
            "found": found,
            "count": len(found),
            "wildcard_detected": bool(wildcard_ips),
            "wildcard_ips": sorted(wildcard_ips)[:20],
            "tested": len(words),
            "scope_matched": decision.matched,
            "scope_mode": decision.mode,
            "scope_warning": decision.warning,
        }
    )


async def _dir_scan(
    ctx: AgentContext,
    base_url: str,
    wordlist: Any = None,
    extensions: Any = None,
    limit: int = 80,
    insecure: bool = False,
) -> str:
    decision = ctx.check_url(base_url)
    if not decision.allowed:
        return err(f"目标范围拒绝：{decision.reason}")
    words = DIR_WORDS
    if wordlist:
        if isinstance(wordlist, str):
            words = [item.strip() for item in re.split(r"[\s,;]+", wordlist) if item.strip()]
        elif isinstance(wordlist, (list, tuple)):
            words = [str(item).strip() for item in wordlist if str(item).strip()]
    suffix = ""
    if extensions:
        if isinstance(extensions, str):
            suffix = extensions
        elif isinstance(extensions, (list, tuple)):
            suffix = ",".join(str(item) for item in extensions)
    words = words[: max(1, min(300, int(limit)))]
    timeout = max(3, int(ctx.settings.safety.network_timeout))
    semaphore = asyncio.Semaphore(10)
    base = base_url.rstrip("/") + "/"

    async def check(word: str) -> dict[str, Any] | None:
        target = urljoin(base, word.lstrip("/"))
        if suffix and not any(target.endswith(f".{item.strip('.').lower()}") for item in suffix.split(",")):
            if not target.endswith("/") and "." not in word.rsplit("/", 1)[-1]:
                target = target + "." + suffix.split(",")[0].strip().lstrip(".")
        target_decision = ctx.check_url(target)
        if not target_decision.allowed:
            return None
        async with semaphore:
            try:
                response = await client.get(target)
                if response.status_code in (200, 204, 301, 302, 307, 308, 401, 403, 405, 500):
                    return {
                        "url": str(response.url),
                        "status_code": response.status_code,
                        "length": len(await response.aread()),
                        "location": response.headers.get("location", ""),
                    }
            except Exception:
                return None
        return None

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout), follow_redirects=False, verify=not insecure
    ) as client:
        results = await asyncio.gather(*(check(word) for word in words))
    found = [item for item in results if item]
    return ok(
        {
            "base_url": base_url,
            "found": found,
            "count": len(found),
            "tested": len(words),
            "scope_matched": decision.matched,
            "scope_mode": decision.mode,
            "scope_warning": decision.warning,
        }
    )


async def _web_crawl(
    ctx: AgentContext,
    url: str,
    max_pages: int = 5,
    max_scripts: int = 8,
    insecure: bool = False,
) -> str:
    decision = ctx.check_url(url)
    if not decision.allowed:
        return err(f"目标范围拒绝：{decision.reason}")
    timeout = max(5, int(ctx.settings.safety.network_timeout))
    pages: list[str] = []
    links: list[str] = []
    forms: list[str] = []
    scripts: list[str] = []
    endpoints: list[str] = []
    origin = f"{urlsplit(url).scheme}://{urlsplit(url).netloc}"
    queue = [url]
    seen: set[str] = set()
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout), follow_redirects=False, verify=not insecure
    ) as client:
        while queue and len(pages) < max(1, min(20, int(max_pages))):
            current = queue.pop(0)
            if current in seen:
                continue
            seen.add(current)
            current_decision = ctx.check_url(current)
            if not current_decision.allowed:
                continue
            try:
                response = await client.get(current)
                if response.status_code in (301, 302, 303, 307, 308):
                    location = response.headers.get("location")
                    if location:
                        redirected = urljoin(current, location)
                        if (
                            ctx.check_url(redirected).allowed
                            and redirected not in seen
                            and len(queue) < 40
                        ):
                            queue.append(redirected)
                    continue
                final_url = str(response.url)
                if not ctx.check_url(final_url).allowed:
                    continue
                text = (await response.aread())[:300_000].decode(
                    response.encoding or "utf-8", errors="replace"
                )
            except Exception:
                continue
            pages.append(final_url)
            parser = _LinkParser()
            try:
                parser.feed(text)
            except Exception:
                pass
            for link in parser.links:
                absolute = urljoin(str(response.url), link)
                if absolute not in links:
                    links.append(absolute)
                parsed = urlsplit(absolute)
                if parsed.netloc == urlsplit(url).netloc and parsed.path not in ("", "/"):
                    if absolute not in queue and absolute not in seen and len(queue) < 40:
                        queue.append(absolute)
            for form in parser.forms:
                absolute = urljoin(str(response.url), form)
                if absolute not in forms:
                    forms.append(absolute)
            for script in parser.scripts:
                absolute = urljoin(str(response.url), script)
                if absolute not in scripts:
                    scripts.append(absolute)
            for match in re.finditer(
                r"""["'](/(?:api|v\d+|graphql|rest|admin|internal|debug|upload|auth)[^"'\s<>]{0,120})["']""",
                text,
                re.I,
            ):
                value = match.group(1)
                if value not in endpoints:
                    endpoints.append(value)
        for script in scripts[: max(0, min(20, int(max_scripts)))]:
            script_decision = ctx.check_url(script)
            if not script_decision.allowed:
                continue
            try:
                response = await client.get(script)
                if not ctx.check_url(str(response.url)).allowed:
                    continue
                text = (await response.aread())[:200_000].decode(
                    response.encoding or "utf-8", errors="replace"
                )
            except Exception:
                continue
            for match in re.finditer(
                r"""["'](/(?:api|v\d+|graphql|rest|admin|internal|debug|upload|auth)[^"'\s<>]{0,120})["']""",
                text,
                re.I,
            ):
                value = match.group(1)
                if value not in endpoints:
                    endpoints.append(value)
    return ok(
        {
            "start_url": url,
            "pages": pages,
            "links": links[:200],
            "forms": forms[:50],
            "scripts": scripts[:50],
            "endpoints": endpoints[:200],
            "scope_matched": decision.matched,
            "scope_mode": decision.mode,
            "scope_warning": decision.warning,
        }
    )


def _zone_transfer_sync(domain: str, nameserver: str, timeout: int) -> str:
    from dns.zone import from_xfr

    transfer = dns.query.xfr(nameserver, domain, timeout=timeout, lifetime=timeout + 5)
    zone = from_xfr(transfer)
    records: list[dict[str, str]] = []
    for name, node in zone.nodes.items():
        for rdataset in node.rdatasets:
            for rdata in rdataset:
                records.append(
                    {
                        "name": str(name),
                        "type": str(rdataset.rdtype),
                        "value": rdata.to_text()[:500],
                    }
                )
                if len(records) >= 300:
                    return json.dumps(records, ensure_ascii=False)
    return json.dumps(records, ensure_ascii=False)


async def _dns_zone_transfer(ctx: AgentContext, domain: str, nameserver: str = "") -> str:
    domain = normalize_host(domain)
    if not domain:
        return err("域名无效")
    decision = ctx.check_host(domain)
    if not decision.allowed:
        return err(f"目标范围拒绝：{decision.reason}")
    timeout = max(5, int(ctx.settings.safety.network_timeout))
    servers: list[str] = []
    if nameserver:
        server_host = normalize_host(nameserver)
        server_decision = ctx.check_host(server_host)
        if not server_host or not server_decision.allowed:
            return err("nameserver 不在目标范围内")
        servers = [server_host]
    else:
        try:
            resolver = dns.resolver.Resolver(configure=True)
            answer = await asyncio.to_thread(resolver.resolve, domain, "NS")
            servers = [str(item).rstrip(".") for item in answer]
        except Exception as exc:
            return err(f"无法获取 NS 记录：{type(exc).__name__}: {truncate_middle(str(exc), 300)}")
    if not servers:
        return err("没有可用的 NS 记录")
    attempts = []
    for server in servers[:4]:
        try:
            raw = await asyncio.to_thread(_zone_transfer_sync, domain, server, timeout)
            records = json.loads(raw)
            attempts.append({"nameserver": server, "records": records, "ok": True})
            if records:
                return ok(
                    {
                        "domain": domain,
                        "nameserver": server,
                        "records": records,
                        "count": len(records),
                        "attempts": attempts,
                    }
                )
        except Exception as exc:
            attempts.append(
                {
                    "nameserver": server,
                    "ok": False,
                    "error": f"{type(exc).__name__}: {truncate_middle(str(exc), 300)}",
                }
            )
    return ok(
        {
            "domain": domain,
            "records": [],
            "count": 0,
            "attempts": attempts,
            "message": "未发现允许 AXFR 的名称服务器",
        }
    )


def build_recon_tools(ctx: AgentContext) -> dict[str, BaseTool]:
    @tool("http_probe")
    async def http_probe(url: str, insecure: bool = False) -> str:
        """对 URL 做一次指纹探测：状态码、标题、技术栈、Server、Cookie 属性与重定向链。"""
        return await _http_probe(ctx, url, insecure)

    @tool("port_scan")
    async def port_scan(
        host: str,
        ports: Any = None,
        timeout_ms: int = 800,
        banner: bool = False,
    ) -> str:
        """对主机做 TCP 端口扫描（默认常见端口），可返回端口对应的服务猜测与 banner。"""
        return await _port_scan(ctx, host, ports, timeout_ms, banner)

    @tool("subdomain_enum")
    async def subdomain_enum(
        domain: str,
        wordlist: Any = None,
        limit: int = 100,
    ) -> str:
        """用内置/自定义字典枚举子域名，自动检测泛解析并过滤通配结果。"""
        return await _subdomain_enum(ctx, domain, wordlist, limit)

    @tool("dir_scan")
    async def dir_scan(
        base_url: str,
        wordlist: Any = None,
        extensions: Any = None,
        limit: int = 80,
        insecure: bool = False,
    ) -> str:
        """对 Web 根路径做常见目录/文件发现（.git、.env、admin、swagger、backup 等）。"""
        return await _dir_scan(ctx, base_url, wordlist, extensions, limit, insecure)

    @tool("web_crawl")
    async def web_crawl(
        url: str,
        max_pages: int = 5,
        max_scripts: int = 8,
        insecure: bool = False,
    ) -> str:
        """抓取页面链接、表单、脚本，并从 JS 中提取 API/端点线索。"""
        return await _web_crawl(ctx, url, max_pages, max_scripts, insecure)

    @tool("dns_zone_transfer")
    async def dns_zone_transfer(domain: str, nameserver: str = "") -> str:
        """尝试对目标域名的 NS 做 AXFR 区域传送，返回可读的 DNS 记录。"""
        return await _dns_zone_transfer(ctx, domain, nameserver)

    return {
        "http_probe": http_probe,
        "port_scan": port_scan,
        "subdomain_enum": subdomain_enum,
        "dir_scan": dir_scan,
        "web_crawl": web_crawl,
        "dns_zone_transfer": dns_zone_transfer,
    }


__all__ = ["build_recon_tools"]
