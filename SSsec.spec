# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置。运行 scripts/build.ps1 生成 dist/SSsec/。"""

from pathlib import Path

from PyInstaller.utils.hooks import (
    collect_data_files,
    collect_submodules,
    copy_metadata,
)

ROOT = Path(SPECPATH)
datas = [(str(ROOT / "sssec" / "assets"), "sssec/assets")]
hiddenimports = []

for package in (
    "langchain_core",
    "langchain_openai",
    "langchain_anthropic",
    "langgraph",
    "langgraph_sdk",
    "langsmith",
    "openai",
    "anthropic",
    "httpx",
    "dns",
    "markdown",
    "tiktoken_ext",
    "capstone",
    "pefile",
    "elftools",
):
    try:
        hiddenimports += collect_submodules(package)
    except Exception:
        pass

for package in ("certifi", "tiktoken"):
    try:
        datas += collect_data_files(package)
    except Exception:
        pass

for package in (
    "langchain-core",
    "langchain-openai",
    "langchain-anthropic",
    "langgraph",
    "langsmith",
    "openai",
    "anthropic",
    "httpx",
    "pydantic",
    "tiktoken",
    "PySide6",
):
    try:
        datas += copy_metadata(package)
    except Exception:
        pass

a = Analysis(
    [str(ROOT / "main.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=sorted(set(hiddenimports)),
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "tkinter",
        "pytest",
        "IPython",
        "PySide6.QtWebEngineCore",
        "PySide6.QtWebEngineWidgets",
        "PySide6.QtQml",
        "PySide6.QtQuick",
        "PySide6.Qt3DCore",
    ],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SSsec",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / "sssec" / "assets" / "sssec.ico"),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="SSsec",
)
