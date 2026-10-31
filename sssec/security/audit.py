"""追加式审计日志：记录工具调用、审批和关键运行事件。"""

from __future__ import annotations

import json
import threading
from datetime import datetime
from pathlib import Path
from typing import Any

_SENSITIVE_KEYS = {"authorization", "cookie", "set-cookie", "x-api-key", "api-key"}


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for key, item in value.items():
            if str(key).lower() in _SENSITIVE_KEYS:
                out[key] = "***"
            else:
                out[key] = _redact(item)
        return out
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


class AuditLog:
    def __init__(self, data_dir: Path, conversation_id: str):
        self.path = data_dir / "audit" / f"{conversation_id}.jsonl"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, event: str, **fields: Any) -> None:
        record = {
            "ts": datetime.now().astimezone().isoformat(timespec="milliseconds"),
            "event": event,
            **_redact(fields),
        }
        try:
            with self._lock, self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError:
            # 审计写失败不应让 Agent 崩溃；运行时仍会向用户返回结果。
            pass


__all__ = ["AuditLog"]
