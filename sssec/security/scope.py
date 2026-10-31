"""测试目标范围（scope）解析与可配置的拦截策略。

范围支持以下写法（每行一个，也接受逗号分隔）：

- example.com            精确域名及其子域名
- *.example.com          仅子域名
- 10.10.0.0/24           IPv4 / IPv6 CIDR
- 192.168.1.10           单个 IP
- https://lab.example.com:8443/path   URL（只取主机名）
- *                      任意目标

范围默认只作为**提示与审计标记**，不阻断工具调用；
可以在设置中切换为 ``warn``（仅提示）或 ``strict``（严格拦截）。
对话开启“完全权限”时始终使用 ``off``。
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_MAX_SCOPE_ENTRIES = 200
SCOPE_MODES = ("off", "warn", "strict")


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    matched: str | None = None
    warning: str | None = None
    mode: str = "strict"


def split_scope_text(text: str) -> list[str]:
    raw: list[str] = []
    for line in (text or "").replace("\r", "\n").split("\n"):
        raw.extend(part for part in re.split(r"[,，;；]", line) if part.strip())
    return normalize_scope_entries(raw)


def _strip_entry(entry: str) -> str:
    value = entry.strip().strip("\"'").strip()
    if not value:
        return ""
    if "://" in value:
        try:
            value = urlsplit(value).hostname or ""
        except ValueError:
            return ""
    # 去掉路径 / 查询串，但保留 CIDR 中的 "/"。
    if any(ch in value for ch in ("/", "?", "#")):
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    value = value.strip().rstrip(".").lower()
    if not value:
        return ""
    if value.startswith("[") and "]" in value:
        value = value[1 : value.index("]")]
    # host:port（IPv6 裸地址不在此处理）
    if value.count(":") == 1 and not value.replace(":", "").isdigit():
        host_part, port_part = value.rsplit(":", 1)
        if port_part.isdigit():
            value = host_part
    # 域名统一转成 IDNA ASCII，避免中文域名与解析结果不一致。
    if value != "*":
        try:
            if value.startswith("*."):
                value = "*." + value[2:].encode("idna").decode("ascii")
            else:
                try:
                    ipaddress.ip_network(value, strict=False)
                except ValueError:
                    value = value.encode("idna").decode("ascii")
        except UnicodeError:
            return ""
    return value


def normalize_scope_entries(entries: list[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        value = _strip_entry(entry)
        if not value:
            continue
        if value != "*":
            try:
                if "/" in value:
                    value = str(ipaddress.ip_network(value, strict=False)).lower()
                else:
                    value = str(ipaddress.ip_address(value)).lower()
            except ValueError:
                # 域名 / 通配符域名
                if value.startswith("*.") and len(value) > 2:
                    value = "*." + value[2:].strip(".")
                elif "*" in value:
                    # 只支持前置通配符，避免误导性的部分通配
                    continue
        if value not in seen:
            seen.add(value)
            result.append(value)
        if len(result) >= _MAX_SCOPE_ENTRIES:
            break
    return result


def _host_kind(host: str) -> tuple[str, object]:
    value = host.strip().strip("[]").rstrip(".").lower()
    try:
        return "ip", ipaddress.ip_address(value)
    except ValueError:
        try:
            return "domain", value.encode("idna").decode("ascii")
        except UnicodeError:
            return "domain", value


def _match_host(host: str, normalized: list[str]) -> tuple[str | None, str]:
    host_kind, host_value = _host_kind(host or "")
    for entry in normalized:
        if entry == "*":
            return entry, "命中全局目标"
        try:
            if host_kind == "ip":
                if "/" in entry:
                    if host_value in ipaddress.ip_network(entry, strict=False):
                        return entry, f"命中网段 {entry}"
                elif host_value == ipaddress.ip_address(entry):
                    return entry, f"命中 IP {entry}"
            else:
                if entry.startswith("*."):
                    suffix = entry[2:]
                    if host_value.endswith("." + suffix):
                        return entry, f"命中通配域名 {entry}"
                elif "/" not in entry:
                    # 域名条目同时覆盖其子域名
                    if host_value == entry or host_value.endswith("." + entry):
                        return entry, f"命中域名 {entry}"
        except ValueError:
            continue
    return None, f"{host} 不在当前提示范围内"


def check_host(
    host: str,
    scope: list[str],
    authorized: bool,
    mode: str = "strict",
) -> ScopeDecision:
    """检查主机是否命中范围。

    ``mode``：
    - ``off``：不拦截，直接放行；
    - ``warn``：放行，但范围外会附带 warning；
    - ``strict``：范围外拒绝。
    """
    mode = mode if mode in SCOPE_MODES else "strict"
    if mode == "off":
        return ScopeDecision(
            True,
            "当前未启用目标范围拦截",
            None,
            None,
            mode,
        )
    if not host:
        return ScopeDecision(False, "目标主机为空", None, None, mode)

    normalized = normalize_scope_entries(scope)
    if not normalized:
        reason = "该对话尚未设置测试目标范围"
        if mode == "warn":
            return ScopeDecision(True, "未设置目标范围，已按提示模式放行", None, reason, mode)
        return ScopeDecision(False, reason, None, None, mode)
    if mode == "strict" and not authorized:
        return ScopeDecision(False, "该对话尚未完成授权确认", None, None, mode)

    matched, reason = _match_host(host, normalized)
    if matched is not None:
        return ScopeDecision(True, reason, matched, None, mode)
    if mode == "warn":
        return ScopeDecision(True, "目标不在提示范围内，已放行", None, reason, mode)
    return ScopeDecision(False, f"{host} 不在当前目标范围内", None, None, mode)


def check_url(
    url: str,
    scope: list[str],
    authorized: bool,
    mode: str = "strict",
) -> ScopeDecision:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return ScopeDecision(False, "URL 格式无法解析", None, None, mode)
    if parsed.scheme.lower() not in ("http", "https"):
        return ScopeDecision(False, "仅支持 http / https 协议", None, None, mode)
    if not parsed.hostname:
        return ScopeDecision(False, "URL 缺少主机名", None, None, mode)
    return check_host(parsed.hostname, scope, authorized, mode)


def scope_summary(scope: list[str], authorized: bool = True) -> str:
    """范围的人类可读摘要。

    ``authorized`` 参数保留用于统一调用签名，不影响展示；范围默认只是提示。
    """
    if not scope:
        return "未设置目标（不限制）"
    if scope == ["*"]:
        return "全部目标（不限制）"
    if len(scope) == 1:
        return scope[0]
    return f"{scope[0]} 等 {len(scope)} 个目标"
