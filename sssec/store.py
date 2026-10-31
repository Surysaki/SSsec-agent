"""会话文件持久化。

每个会话保存为独立 JSON，使用临时文件 + os.replace 原子替换，降低崩溃时
损坏数据的概率。目录由 SSsec 独占，文件名只使用服务端生成的十六进制 ID。
"""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

from sssec.models import Conversation, repair_interrupted_messages

_ID_RE = re.compile(r"^[0-9a-f]{32}$")


class ConversationStore:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.dir = data_dir / "conversations"
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, conversation_id: str) -> Path:
        if not _ID_RE.match(conversation_id or ""):
            raise ValueError("非法的会话 ID")
        return self.dir / f"{conversation_id}.json"

    def exists(self, conversation_id: str) -> bool:
        try:
            return self._path(conversation_id).exists()
        except ValueError:
            return False

    def load(self, conversation_id: str) -> Conversation | None:
        path = self._path(conversation_id)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
        if not isinstance(data, dict):
            return None
        conversation = Conversation.from_dict(data)
        if repair_interrupted_messages(conversation):
            self.save(conversation)
        return conversation

    def save(self, conversation: Conversation) -> None:
        path = self._path(conversation.id)
        tmp = path.with_suffix(".tmp")
        payload = json.dumps(conversation.to_dict(), ensure_ascii=False, indent=2)
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, path)

    def delete(self, conversation_id: str) -> None:
        path = self._path(conversation_id)
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        audit = self.data_dir / "audit" / f"{conversation_id}.jsonl"
        try:
            audit.unlink(missing_ok=True)
        except OSError:
            pass

    def list_all(self) -> list[Conversation]:
        conversations: list[Conversation] = []
        for path in self.dir.glob("*.json"):
            if not _ID_RE.match(path.stem):
                continue
            conversation = self.load(path.stem)
            if conversation:
                conversations.append(conversation)
        conversations.sort(key=lambda c: c.updated_at, reverse=True)
        return conversations

    def workspace(self, conversation_id: str) -> Path:
        if not _ID_RE.match(conversation_id or ""):
            raise ValueError("非法的会话 ID")
        path = self.data_dir / "workspaces" / conversation_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def export_copy(self, conversation_id: str, destination_dir: Path) -> Path:
        source = self._path(conversation_id)
        destination_dir.mkdir(parents=True, exist_ok=True)
        target = destination_dir / source.name
        shutil.copy2(source, target)
        return target


__all__ = ["ConversationStore"]
