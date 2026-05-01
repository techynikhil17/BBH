"""Read skill files and their adjacent ``patterns.json``.

The skill library (PROMPT 03 output) stores skills at
``skills/{vuln_class}/{slug}/skill.md`` plus ``patterns.json``. This module
resolves the path from a skill identifier and returns both pieces.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from ..config import SKILLS_DIR


@dataclass
class SkillBundle:
    skill_id: str          # the canonical "{vuln_class}/{slug}" form
    skill_path: Path
    patterns_path: Optional[Path]
    skill_md: str
    patterns: list[dict[str, Any]]


class SkillNotFoundError(FileNotFoundError):
    """Raised when the requested skill identifier doesn't resolve to a file."""


def _split_skill_id(skill_id: str) -> tuple[str, str]:
    """Split ``ssrf/cloud-metadata`` (or ``ssrf:cloud-metadata``) into parts."""
    skill_id = (skill_id or "").strip().strip("/")
    if not skill_id:
        raise ValueError("empty skill_id")
    sep = "/" if "/" in skill_id else (":" if ":" in skill_id else "/")
    parts = [p for p in skill_id.replace(":", "/").split("/") if p]
    if len(parts) != 2:
        raise ValueError(f"skill_id must be 'vuln_class/slug', got {skill_id!r}")
    return parts[0].lower(), parts[1].lower()


def resolve_skill_path(skill_id: str, skills_dir: Path = SKILLS_DIR) -> Path:
    """Return the on-disk path to ``skill.md`` for the given identifier."""
    vuln_class, slug = _split_skill_id(skill_id)
    return skills_dir / vuln_class / slug / "skill.md"


def read_skill(skill_id: str, skills_dir: Path = SKILLS_DIR) -> SkillBundle:
    """Load skill.md and patterns.json for ``skill_id``."""
    skill_path = resolve_skill_path(skill_id, skills_dir)
    if not skill_path.exists():
        raise SkillNotFoundError(f"skill not found: {skill_path}")

    skill_md = skill_path.read_text(encoding="utf-8")
    patterns_path = skill_path.parent / "patterns.json"
    patterns: list[dict[str, Any]] = []
    if patterns_path.exists():
        try:
            data = json.loads(patterns_path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                patterns = data
        except json.JSONDecodeError:
            pass

    vuln_class, slug = _split_skill_id(skill_id)
    canonical = f"{vuln_class}/{slug}"
    return SkillBundle(
        skill_id=canonical,
        skill_path=skill_path,
        patterns_path=patterns_path if patterns_path.exists() else None,
        skill_md=skill_md,
        patterns=patterns,
    )


def list_available_skills(skills_dir: Path = SKILLS_DIR) -> list[str]:
    """Enumerate every ``vuln_class/slug`` pair on disk (skipping ``_templates``)."""
    if not skills_dir.exists():
        return []
    out: list[str] = []
    for path in sorted(skills_dir.rglob("skill.md")):
        if "_templates" in path.parts:
            continue
        try:
            slug = path.parent.name
            vuln_class = path.parent.parent.name
            out.append(f"{vuln_class}/{slug}")
        except Exception:
            continue
    return out
