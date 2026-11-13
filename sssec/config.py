"""应用配置、模型服务档案和本地数据路径。"""

from __future__ import annotations

import copy
import json
import os
import sys
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from sssec.security.secrets import (
    encryption_label,
    is_strong_encryption,
    protect_secret,
    unprotect_secret,
)

APP_VERSION = "0.2.0"
CONFIG_SCHEMA = 2

PROVIDER_TYPES = {
    "openai": "OpenAI 兼容",
    "anthropic": "Anthropic",
    "demo": "离线演示",
}

APPROVAL_MODES = {
    "relaxed": "宽松（仅高风险命令需确认，默认）",
    "sensitive": "仅敏感工具需审批",
    "all": "所有工具均需审批",
    "off": "关闭审批（所有工具直接执行）",
    "full": "完全权限（免确认 + 取消范围拦截）",
}

SCOPE_MODES = {
    "off": "不限制目标（默认）",
    "warn": "仅提示、不拦截",
    "strict": "严格拦截范围外目标",
}

THEMES = {
    "light": "浅色（白色主题）",
    "dark": "深色（安全测试工作台）",
}
DEFAULT_THEME = "light"


def get_data_dir() -> Path:
    override = os.environ.get("SSSEC_HOME", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
        return Path(base) / "SSsec"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "SSsec"
    return Path.home() / ".local" / "share" / "sssec"


@dataclass
class ProviderConfig:
    id: str
    name: str
    type: str = "openai"
    model: str = ""
    base_url: str = ""
    api_key: str = ""
    temperature: float = 0.2
    max_tokens: int = 0

    @property
    def is_demo(self) -> bool:
        return self.type == "demo"

    @property
    def type_label(self) -> str:
        return PROVIDER_TYPES.get(self.type, self.type)

    @property
    def label(self) -> str:
        if self.is_demo:
            return f"{self.name} · 离线"
        return f"{self.name} · {self.model or '未填写模型'}"

    def clone(self) -> "ProviderConfig":
        return ProviderConfig(**copy.deepcopy(asdict(self)))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProviderConfig":
        return cls(
            id=str(data.get("id") or uuid.uuid4().hex),
            name=str(data.get("name") or "未命名服务"),
            type=str(data.get("type") or "openai"),
            model=str(data.get("model") or ""),
            base_url=str(data.get("base_url") or ""),
            api_key=unprotect_secret(str(data.get("api_key") or "")),
            temperature=float(data.get("temperature", 0.2)),
            max_tokens=int(data.get("max_tokens", 0) or 0),
        )

    def to_storage_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["api_key"] = protect_secret(self.api_key)
        return data


def default_providers() -> list[ProviderConfig]:
    return [
        ProviderConfig(
            id="builtin-demo",
            name="离线演示",
            type="demo",
            model="demo-agent",
            temperature=0.2,
        ),
        ProviderConfig(
            id="builtin-deepseek",
            name="DeepSeek",
            type="openai",
            model="deepseek-chat",
            base_url="https://api.deepseek.com/v1",
            temperature=0.2,
        ),
        ProviderConfig(
            id="builtin-openai",
            name="OpenAI",
            type="openai",
            model="gpt-4.1-mini",
            base_url="https://api.openai.com/v1",
            temperature=0.2,
        ),
        ProviderConfig(
            id="builtin-anthropic",
            name="Anthropic",
            type="anthropic",
            model="claude-sonnet-4-5",
            base_url="https://api.anthropic.com",
            temperature=0.2,
        ),
        ProviderConfig(
            id="builtin-ollama",
            name="Ollama / 本地模型",
            type="openai",
            model="qwen2.5:7b",
            base_url="http://127.0.0.1:11434/v1",
            temperature=0.2,
        ),
    ]


@dataclass
class SafetySettings:
    approval_mode: str = "relaxed"
    scope_mode: str = "off"
    enable_shell: bool = True
    max_tool_rounds: int = 12
    command_timeout: int = 60
    network_timeout: int = 20
    max_history_messages: int = 60

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any] | None) -> "SafetySettings":
        data = data or {}
        approval_mode = str(data.get("approval_mode", "relaxed"))
        if approval_mode not in APPROVAL_MODES:
            approval_mode = "relaxed"
        scope_mode = str(data.get("scope_mode", "off"))
        if scope_mode not in SCOPE_MODES:
            scope_mode = "off"
        return cls(
            approval_mode=approval_mode,
            scope_mode=scope_mode,
            enable_shell=bool(data.get("enable_shell", True)),
            max_tool_rounds=max(1, min(20, int(data.get("max_tool_rounds", 12) or 12))),
            command_timeout=max(5, min(600, int(data.get("command_timeout", 60) or 60))),
            network_timeout=max(3, min(120, int(data.get("network_timeout", 20) or 20))),
            max_history_messages=max(
                4, min(120, int(data.get("max_history_messages", 60) or 60))
            ),
        )


@dataclass
class AppSettings:
    active_provider_id: str = "builtin-demo"
    providers: list[ProviderConfig] = field(default_factory=default_providers)
    safety: SafetySettings = field(default_factory=SafetySettings)
    theme: str = DEFAULT_THEME
    schema_version: int = CONFIG_SCHEMA

    def active_provider(self) -> ProviderConfig:
        for provider in self.providers:
            if provider.id == self.active_provider_id:
                return provider
        if self.providers:
            self.active_provider_id = self.providers[0].id
            return self.providers[0]
        provider = default_providers()[0]
        self.providers = [provider]
        self.active_provider_id = provider.id
        return provider

    def provider_by_id(self, provider_id: str) -> ProviderConfig | None:
        return next((p for p in self.providers if p.id == provider_id), None)

    def clone(self) -> "AppSettings":
        return AppSettings(
            active_provider_id=self.active_provider_id,
            providers=[p.clone() for p in self.providers],
            safety=SafetySettings(**self.safety.to_dict()),
            theme=self.theme,
            schema_version=self.schema_version,
        )

    def to_storage_dict(self) -> dict[str, Any]:
        return {
            "schema_version": CONFIG_SCHEMA,
            "active_provider_id": self.active_provider_id,
            "providers": [p.to_storage_dict() for p in self.providers],
            "safety": self.safety.to_dict(),
            "theme": self.theme,
        }

    @classmethod
    def from_storage_dict(cls, data: dict[str, Any]) -> "AppSettings":
        providers = [
            ProviderConfig.from_dict(item)
            for item in (data.get("providers") or [])
            if isinstance(item, dict)
        ]
        if not providers:
            providers = default_providers()
        active = str(data.get("active_provider_id") or providers[0].id)
        if active not in {p.id for p in providers}:
            active = providers[0].id
        theme = str(data.get("theme") or DEFAULT_THEME).lower()
        if theme not in THEMES:
            theme = DEFAULT_THEME
        return cls(
            active_provider_id=active,
            providers=providers,
            safety=SafetySettings.from_dict(data.get("safety")),
            theme=theme,
        )


class SettingsStore:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.path = data_dir / "config.json"

    def load(self) -> AppSettings:
        if not self.path.exists():
            settings = AppSettings()
            self.save(settings)
            return settings
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except Exception:
            backup = self.path.with_suffix(".invalid.json")
            try:
                self.path.replace(backup)
            except OSError:
                pass
            settings = AppSettings()
            self.save(settings)
            return settings
        if not isinstance(raw, dict):
            return AppSettings()
        return AppSettings.from_storage_dict(raw)

    def save(self, settings: AppSettings) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            settings.to_storage_dict(), ensure_ascii=False, indent=2
        )
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, self.path)


def ensure_data_dirs(data_dir: Path) -> None:
    for name in ("conversations", "workspaces", "audit", "logs", "exports"):
        (data_dir / name).mkdir(parents=True, exist_ok=True)


def load_ui_state(data_dir: Path) -> dict[str, Any]:
    path = data_dir / "ui_state.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_ui_state(data_dir: Path, state: dict[str, Any]) -> None:
    path = data_dir / "ui_state.json"
    tmp = path.with_suffix(".tmp")
    try:
        tmp.write_text(
            json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        os.replace(tmp, path)
    except OSError:
        pass


__all__ = [
    "APP_VERSION",
    "APPROVAL_MODES",
    "AppSettings",
    "DEFAULT_THEME",
    "ProviderConfig",
    "SCOPE_MODES",
    "SafetySettings",
    "SettingsStore",
    "THEMES",
    "ensure_data_dirs",
    "encryption_label",
    "get_data_dir",
    "is_strong_encryption",
    "load_ui_state",
    "save_ui_state",
]
