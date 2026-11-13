"""工具层公共辅助：JSON 输出、截断、工作区路径、端口解析与 flag 提取。"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

MAX_TOOL_OUTPUT = 16000

_FLAG_RE = re.compile(
    r"\b(?:flag|ctf|FLAG|CTF|DASCTF|HFCTF|NSSCTF|moectf|hgame|SCTF|"
    r"BJDCTF|GKCTF|SUCTF|XCTF|TCTF)\{[^}\r\n]{1,200}\}",
    re.IGNORECASE,
)

# 这些是模型/示例里常见的占位符，不是真实 flag。
_FLAG_PLACEHOLDERS = {
    "flag{...}",
    "flag{xxx}",
    "flag{xxx...}",
    "flag{example}",
    "flag{your_flag_here}",
    "flag{flag}",
}

# 截断、省略、模板残留；出现任意一个都视为不完整。
_FLAG_REJECT_MARKERS = ("...", "…", "***", "xxx", "todo", "your_flag")


def json_text(data: Any, limit: int = MAX_TOOL_OUTPUT) -> str:
    text = json.dumps(data, ensure_ascii=False, default=str)
    return truncate_middle(text, limit)


def ok(data: dict[str, Any]) -> str:
    return json_text({"ok": True, "data": data})


def err(message: str, **extra: Any) -> str:
    return json_text({"ok": False, "error": message, **extra})


def result_ok(text: str) -> bool:
    try:
        parsed = json.loads(text)
        return bool(parsed.get("ok", True)) if isinstance(parsed, dict) else True
    except Exception:
        return True


def truncate_middle(text: str, limit: int = MAX_TOOL_OUTPUT) -> str:
    if len(text) <= limit:
        return text
    head = int(limit * 0.62)
    tail = max(0, limit - head - 24)
    omitted = text[head : len(text) - tail] if tail else text[head:]
    # 截断区里可能正好有 flag；保留下来，避免模型只看到半截字符串后瞎猜。
    flags = extract_flags(omitted)
    tail_text = text[-tail:] if tail else ""
    extra = ""
    if flags:
        extra = "\n[截断区发现的完整 flag：" + "、".join(flags[:10]) + "]"
    return text[:head] + "\n…（输出过长，中间已截断）…\n" + tail_text + extra


async def read_limited(stream: Any, limit: int) -> tuple[bytes, bool]:
    """持续排空子进程/网络流，但只在内存中保留最多 limit 字节。"""
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


def normalize_host(value: str) -> str:
    """把 URL / host:port / 裸主机统一成 host。"""
    from urllib.parse import urlsplit

    text = str(value or "").strip()
    if not text:
        return ""
    if "://" in text:
        try:
            text = urlsplit(text).hostname or ""
        except ValueError:
            return ""
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    if text.count(":") == 1 and text.rsplit(":", 1)[1].isdigit():
        text = text.rsplit(":", 1)[0]
    return text.strip().rstrip(".").lower()


def safe_workspace_path(workspace: Path, raw_path: str) -> Path:
    """把用户路径限制在会话工作目录内，拒绝目录穿越。"""
    base = Path(workspace).resolve()
    value = str(raw_path or ".").strip() or "."
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = base / candidate
    target = candidate.resolve()
    if not target.is_relative_to(base):
        raise ValueError("路径超出会话工作目录")
    return target


def parse_ports(value: Any, default: list[int] | None = None) -> list[int]:
    """解析端口列表/范围字符串，去重并限制在 1-65535。"""
    if value is None or value == "":
        return list(default or [])
    raw: list[str] = []
    if isinstance(value, str):
        raw = re.split(r"[\s,;]+", value.strip())
    elif isinstance(value, (list, tuple, set)):
        raw = [str(item) for item in value]
    else:
        raw = [str(value)]
    result: list[int] = []
    for item in raw:
        item = item.strip()
        if not item:
            continue
        if "-" in item and item.count("-") == 1:
            start, end = item.split("-", 1)
            try:
                start_i, end_i = int(start), int(end)
            except ValueError:
                continue
            if start_i > end_i:
                start_i, end_i = end_i, start_i
            for port in range(start_i, end_i + 1):
                if 1 <= port <= 65535 and port not in result:
                    result.append(port)
                if len(result) >= 500:
                    return result
            continue
        try:
            port = int(item)
        except ValueError:
            continue
        if 1 <= port <= 65535 and port not in result:
            result.append(port)
        if len(result) >= 500:
            break
    return result


def _clean_flag(value: str) -> str:
    """去掉 JSON/字符串转义残留，避免把 ``flag{...\\"}`` 当成完整 flag。"""
    flag = (value or "").strip()
    flag = re.sub(r'\\+"\}', "}", flag)
    flag = re.sub(r"\\+\}$", "}", flag)
    return flag


def extract_flags(text: str) -> list[str]:
    seen: set[str] = set()
    flags: list[str] = []
    for match in _FLAG_RE.finditer(text or ""):
        value = _clean_flag(match.group(0))
        key = value.lower()
        if not value or key in _FLAG_PLACEHOLDERS or key in seen:
            continue
        inner = value[value.find("{") + 1 : value.rfind("}")]
        # 截断/占位/模板残留
        if any(marker in inner.lower() for marker in _FLAG_REJECT_MARKERS):
            continue
        # 真正的 flag 通常不含空白、引号或反斜杠；命令片段/JSON 残片会被这里挡掉。
        if re.search(r"\s", inner):
            continue
        if any(ch in inner for ch in ('"', "'", "\\")):
            continue
        seen.add(key)
        flags.append(value)
    return flags


def printable_strings(data: bytes, minimum: int = 4, limit: int = 120) -> list[str]:
    values: list[str] = []
    current: list[str] = []
    for byte in data:
        char = chr(byte)
        if 32 <= byte < 127:
            current.append(char)
        else:
            if len(current) >= minimum:
                values.append("".join(current))
            current = []
    if len(current) >= minimum:
        values.append("".join(current))
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
        if len(result) >= limit:
            break
    return result


__all__ = [
    "MAX_TOOL_OUTPUT",
    "err",
    "extract_flags",
    "json_text",
    "normalize_host",
    "ok",
    "parse_ports",
    "printable_strings",
    "read_limited",
    "result_ok",
    "safe_workspace_path",
    "truncate_middle",
]
