"""技能库：内置技能卡 + 用户自定义技能，按需加载。"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SKILL_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,48}$")
MAX_BODY_CHARS = 8000
MAX_INJECT_CHARS = 6000
STAGES = (
    "recon",
    "vuln_analysis",
    "exploit",
    "post_exploit",
    "reverse",
    "final",
    "commander",
    "any",
)

BUILTIN_SKILLS_DIR = Path(__file__).resolve().parent / "assets" / "skills"


@dataclass
class Skill:
    """一张技能参考卡。"""

    id: str
    name: str
    when: str
    body: str = ""
    stages: list[str] = field(default_factory=list)
    category: str = ""
    version: str = "1.0.0"
    source: str = ""
    license: str = ""
    builtin: bool = False
    enabled: bool = True
    path: Path | None = None

    @property
    def stage_text(self) -> str:
        return "、".join(self.stages) if self.stages else "any"

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "when": self.when,
            "category": self.category,
            "stages": list(self.stages),
            "builtin": self.builtin,
            "enabled": self.enabled,
            "version": self.version,
            "source": self.source,
            "license": self.license,
        }


def _strip_quotes(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _parse_list(value: str) -> list[str]:
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    items = [item.strip().strip("\"'") for item in value.split(",")]
    return [item for item in items if item]


def parse_skill(
    text: str,
    *,
    builtin: bool = False,
    path: Path | None = None,
) -> Skill:
    """解析 front-matter + 正文；不依赖 PyYAML。"""
    raw = str(text or "").replace("\r\n", "\n")
    if not raw.startswith("---"):
        raise ValueError("技能文件缺少 front-matter（以 --- 开头）")
    parts = raw.split("\n---", 1)
    if len(parts) != 2:
        raise ValueError("技能文件缺少结束分隔符 ---")
    head = parts[0][3:]
    body = parts[1].lstrip("\n")
    data: dict[str, str] = {}
    for line in head.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip().lower()] = value.strip()
    skill_id = _strip_quotes(data.get("id", ""))
    name = _strip_quotes(data.get("name", ""))
    when = _strip_quotes(data.get("when", ""))
    if not skill_id or not SKILL_ID_RE.match(skill_id):
        raise ValueError("技能 id 必须是 2-49 位小写字母/数字/短横线")
    if not name:
        raise ValueError("技能缺少 name")
    if not when:
        raise ValueError("技能缺少 when（触发条件）")
    stages = _parse_list(data.get("stages", "any")) or ["any"]
    unknown = [item for item in stages if item not in STAGES]
    if unknown:
        raise ValueError(f"未知阶段：{', '.join(unknown)}")
    if len(body) > MAX_BODY_CHARS:
        raise ValueError(f"技能正文过长（上限 {MAX_BODY_CHARS} 字符）")
    enabled = str(data.get("enabled", "true")).strip().lower() not in {
        "false",
        "0",
        "no",
    }
    return Skill(
        id=skill_id,
        name=name,
        when=when,
        body=body.strip(),
        stages=stages,
        category=_strip_quotes(data.get("category", "")) or "其他",
        version=_strip_quotes(data.get("version", "1.0.0")) or "1.0.0",
        source=_strip_quotes(data.get("source", "")),
        license=_strip_quotes(data.get("license", "")),
        builtin=builtin,
        enabled=enabled,
        path=path,
    )


def render_skill(skill: Skill) -> str:
    """把技能对象写回 markdown。"""
    lines = [
        "---",
        f"id: {skill.id}",
        f"name: {skill.name}",
        f"when: {skill.when}",
        f"category: {skill.category or '其他'}",
        f"stages: [{', '.join(skill.stages)}]",
        f"version: {skill.version}",
    ]
    if skill.source:
        lines.append(f"source: {skill.source}")
    if skill.license:
        lines.append(f"license: {skill.license}")
    lines.append("---")
    lines.append("")
    lines.append(skill.body.strip())
    lines.append("")
    return "\n".join(lines)


class SkillStore:
    """内置技能（随安装包）+ 用户技能（数据目录）。"""

    def __init__(self, data_dir: Path, builtin_dir: Path | None = None):
        self.data_dir = Path(data_dir)
        self.builtin_dir = Path(builtin_dir) if builtin_dir else BUILTIN_SKILLS_DIR
        self.user_dir = self.data_dir / "skills"
        self._skills: dict[str, Skill] = {}
        self._disabled: set[str] = set()
        self.reload()

    # ------------------------------------------------------------------ load
    def reload(self) -> None:
        self._skills = {}
        self._disabled = self._load_disabled()
        for directory, builtin in ((self.builtin_dir, True), (self.user_dir, False)):
            if not directory.exists():
                continue
            for path in sorted(directory.glob("*.md")):
                try:
                    skill = parse_skill(
                        path.read_text(encoding="utf-8"),
                        builtin=builtin,
                        path=path,
                    )
                except Exception:
                    continue
                # 用户同名技能覆盖内置（但内置仍保留只读身份）。
                if skill.id in self._skills and builtin:
                    continue
                self._skills[skill.id] = skill
        for skill_id in self._disabled:
            if skill_id in self._skills:
                self._skills[skill_id].enabled = False

    def _overrides_path(self) -> Path:
        return self.user_dir / "overrides.json"

    def _load_disabled(self) -> set[str]:
        path = self._overrides_path()
        if not path.exists():
            return set()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return {str(item) for item in data.get("disabled") or []}
        except Exception:
            return set()

    def _save_disabled(self) -> None:
        self.user_dir.mkdir(parents=True, exist_ok=True)
        path = self._overrides_path()
        path.write_text(
            json.dumps({"disabled": sorted(self._disabled)}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    # ----------------------------------------------------------------- query
    def list(self, *, include_disabled: bool = False) -> list[Skill]:
        items = [item for item in self._skills.values() if item.enabled or include_disabled]
        return sorted(items, key=lambda item: (not item.builtin, item.id))

    def get(self, skill_id: str) -> Skill | None:
        return self._skills.get(str(skill_id or "").strip())

    def index_text(self, limit: int = 60) -> str:
        """给指挥官的紧凑索引：按分类列出 id，细节交给 skill_list。"""
        skills = self.list()[: max(1, int(limit))]
        if not skills:
            return "- 暂无可用技能"
        groups: dict[str, list[str]] = {}
        for skill in skills:
            groups.setdefault(skill.category or "其他", []).append(skill.id)
        lines = [
            f"- {category}（{len(items)}）: " + "、".join(f"`{item}`" for item in items)
            for category, items in sorted(groups.items())
        ]
        return "\n".join(lines)

    def categories(self) -> list[str]:
        return sorted({item.category or "其他" for item in self._skills.values()})

    def body_for(self, skill_id: str, max_chars: int = MAX_INJECT_CHARS) -> str:
        skill = self.get(skill_id)
        if skill is None:
            return ""
        body = skill.body.strip()
        if len(body) > max_chars:
            body = body[:max_chars] + "\n…（正文已截断，完整内容见技能库）"
        return body

    # ----------------------------------------------------------------- write
    def save_user(self, skill: Skill) -> Skill:
        if skill.builtin:
            raise ValueError("内置技能只读，请复制为我的技能后再修改")
        if not SKILL_ID_RE.match(skill.id):
            raise ValueError("技能 id 必须是 2-49 位小写字母/数字/短横线")
        if not skill.name.strip():
            raise ValueError("技能缺少 name")
        if not skill.when.strip():
            raise ValueError("技能缺少 when（触发条件）")
        if len(skill.body) > MAX_BODY_CHARS:
            raise ValueError(f"技能正文过长（上限 {MAX_BODY_CHARS} 字符）")
        existing = self.get(skill.id)
        if existing is not None and existing.builtin:
            raise ValueError("内置技能 id 不可覆盖，请换一个 id")
        self.user_dir.mkdir(parents=True, exist_ok=True)
        path = self.user_dir / f"{skill.id}.md"
        skill.builtin = False
        skill.path = path
        path.write_text(render_skill(skill), encoding="utf-8")
        self._skills[skill.id] = skill
        if not skill.enabled and skill.id not in self._disabled:
            self._disabled.add(skill.id)
            self._save_disabled()
        return skill

    def delete_user(self, skill_id: str) -> bool:
        skill = self.get(skill_id)
        if skill is None or skill.builtin or skill.path is None:
            return False
        try:
            skill.path.unlink(missing_ok=True)
        except OSError:
            return False
        self._skills.pop(skill_id, None)
        if skill_id in self._disabled:
            self._disabled.discard(skill_id)
            self._save_disabled()
        return True

    def set_enabled(self, skill_id: str, enabled: bool) -> bool:
        skill = self.get(skill_id)
        if skill is None:
            return False
        skill.enabled = bool(enabled)
        if enabled:
            self._disabled.discard(skill_id)
        else:
            self._disabled.add(skill_id)
        self._save_disabled()
        return True

    def import_markdown(self, text: str, *, overwrite: bool = False) -> Skill:
        skill = parse_skill(text, builtin=False)
        existing = self.get(skill.id)
        if existing is not None:
            if existing.builtin:
                raise ValueError(f"与内置技能 {skill.id} 同名，请先修改 id")
            if not overwrite:
                raise ValueError(f"技能 {skill.id} 已存在")
        return self.save_user(skill)

    def export_markdown(self, skill_id: str) -> str:
        skill = self.get(skill_id)
        if skill is None:
            raise ValueError("技能不存在")
        return render_skill(skill)

    def copy_as_user(self, skill_id: str, new_id: str | None = None) -> Skill:
        """把内置技能复制成可编辑的用户技能。"""
        skill = self.get(skill_id)
        if skill is None:
            raise ValueError("技能不存在")
        target_id = new_id or f"{skill.id}-copy"
        if target_id in self._skills:
            raise ValueError(f"技能 {target_id} 已存在")
        copy = Skill(
            id=target_id,
            name=f"{skill.name}（副本）",
            when=skill.when,
            body=skill.body,
            stages=list(skill.stages),
            category=skill.category,
            version=skill.version,
            source=skill.source,
            license=skill.license,
            builtin=False,
            enabled=True,
        )
        return self.save_user(copy)


__all__ = [
    "BUILTIN_SKILLS_DIR",
    "MAX_BODY_CHARS",
    "MAX_INJECT_CHARS",
    "SKILL_ID_RE",
    "STAGES",
    "Skill",
    "SkillStore",
    "parse_skill",
    "render_skill",
]
