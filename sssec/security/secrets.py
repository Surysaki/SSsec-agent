"""跨平台的本地密钥保护。

Windows 上使用 DPAPI（与当前 Windows 用户绑定）。其他平台在没有系统钥匙串
集成时退化为 Base64 编码，并在界面上明确标注，避免造成"已强加密"的误解。
"""

from __future__ import annotations

import base64
import ctypes
import os
import sys
from ctypes import wintypes

_DPAPI_PREFIX = "dpapi:"
_B64_PREFIX = "b64:"


def encryption_label() -> str:
    if sys.platform == "win32":
        return "Windows DPAPI（绑定当前用户）"
    return "Base64 本地编码（当前平台无 DPAPI）"


def is_strong_encryption() -> bool:
    return sys.platform == "win32"


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def _dpapi(data: bytes, protect: bool) -> bytes:
    if sys.platform != "win32":
        raise OSError("DPAPI 仅在 Windows 上可用")

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    buffer = ctypes.create_string_buffer(data)
    blob_in = _DataBlob(
        len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))
    )
    blob_out = _DataBlob()
    description = wintypes.LPCWSTR("SSsec local secret")

    if protect:
        fn = crypt32.CryptProtectData
        fn.argtypes = [
            ctypes.POINTER(_DataBlob),
            wintypes.LPCWSTR,
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        ]
        fn.restype = wintypes.BOOL
        ok = fn(
            ctypes.byref(blob_in),
            description,
            None,
            None,
            None,
            0,
            ctypes.byref(blob_out),
        )
    else:
        fn = crypt32.CryptUnprotectData
        fn.argtypes = [
            ctypes.POINTER(_DataBlob),
            ctypes.POINTER(wintypes.LPWSTR),
            ctypes.POINTER(_DataBlob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(_DataBlob),
        ]
        fn.restype = wintypes.BOOL
        ok = fn(
            ctypes.byref(blob_in),
            None,
            None,
            None,
            None,
            0,
            ctypes.byref(blob_out),
        )

    if not ok:
        raise OSError(
            f"DPAPI 调用失败（错误码 {ctypes.get_last_error()}）"
        )
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def protect_secret(value: str) -> str:
    """把明文密钥转换成可安全写入配置文件的字符串。"""
    if not value:
        return ""
    raw = value.encode("utf-8")
    if sys.platform == "win32":
        return _DPAPI_PREFIX + base64.b64encode(_dpapi(raw, protect=True)).decode("ascii")
    return _B64_PREFIX + base64.b64encode(raw).decode("ascii")


def unprotect_secret(value: str) -> str:
    if not value:
        return ""
    try:
        if value.startswith(_DPAPI_PREFIX):
            encrypted = base64.b64decode(value[len(_DPAPI_PREFIX) :])
            return _dpapi(encrypted, protect=False).decode("utf-8")
        if value.startswith(_B64_PREFIX):
            return base64.b64decode(value[len(_B64_PREFIX) :]).decode("utf-8")
    except Exception:
        # 配置损坏时不要阻塞应用启动；用户可以在设置中重新填写。
        return ""
    # 兼容手工写入的旧配置。
    return value


def data_dir_hint() -> str:
    if sys.platform == "win32":
        root = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(root, "SSsec")
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/SSsec")
    return os.path.expanduser("~/.local/share/sssec")
