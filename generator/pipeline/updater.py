"""Update existing skill files with newly observed patterns.

For each ``PatternGroup``:
1. Locate the corresponding skill at ``skills/{vuln_class}/{slug}/``.
2. If the skill doesn't exist yet → fall through to normal generation.
3. If it does → load existing ``skill.md`` + ``patterns.json``, identify
   patterns whose ``source_url`` is not yet recorded, and produce a
   ``GenerationTask`` whose ``existing_skill`` field is populated. Claude
   Code's instruction tells it to extend rather than rewrite.

The version-bump rule (patch for log additions, minor for new patterns in
main body) is enforced by Claude Code per the instruction text — there's
no programmatic way to detect "log additions only" before generation.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ..config import SKILLS_DIR
from ..models import GenerationTask, PatternGroup
from .task_writer import build_task

logger = logging.getLogger(__name__)


@dataclass
class ExistingSkill:
    skill_md: str
    patterns: list[dict]
    skill_path: Path
    patterns_path: Path


def find_existing_skill(group: PatternGroup, skills_dir: Path = SKILLS_DIR) -> Optional[ExistingSkill]:
    """Return the on-disk skill for ``group`` if one exists, else ``None``."""
    skill_dir = skills_dir / group.vuln_class / group.slug
    skill_path = skill_dir / "skill.md"
    patterns_path = skill_dir / "patterns.json"
    if not skill_path.exists():
        return None

    try:
        skill_md = skill_path.read_text(encoding="utf-8")
    except OSError as exc:
        logger.warning("could not read %s: %s", skill_path, exc)
        return None

    patterns: list[dict] = []
    if patterns_path.exists():
        try:
            patterns = json.loads(patterns_path.read_text(encoding="utf-8"))
            if not isinstance(patterns, list):
                patterns = []
        except json.JSONDecodeError as exc:
            logger.warning("malformed patterns.json at %s: %s", patterns_path, exc)
            patterns = []

    return ExistingSkill(
        skill_md=skill_md,
        patterns=patterns,
        skill_path=skill_path,
        patterns_path=patterns_path,
    )


def diff_new_patterns(
    incoming: list[dict],
    existing: list[dict],
) -> tuple[list[dict], list[str]]:
    """Return ``(new_patterns, new_urls)``.

    Patterns are considered "the same" if they share ``source_url``; we
    only carry source_url forward as the dedup key because it's the
    authoritative provenance field.
    """
    existing_urls = {p.get("source_url") for p in existing if p.get("source_url")}
    new_patterns = [p for p in incoming if p.get("source_url") and p["source_url"] not in existing_urls]
    new_urls = [p["source_url"] for p in new_patterns]
    return new_patterns, new_urls


def build_update_task(
    group: PatternGroup,
    existing: ExistingSkill,
) -> Optional[GenerationTask]:
    """Build a task to update ``existing`` with the new patterns in ``group``.

    Returns ``None`` if there are no genuinely new patterns — nothing to do.
    """
    new_patterns, new_urls = diff_new_patterns(group.patterns, existing.patterns)
    if not new_patterns:
        return None

    # Pass the FULL incoming pattern list; Claude Code uses ``new_pattern_urls``
    # to know which ones are new, but it benefits from seeing the full set to
    # validate frequency counts against the existing skill's claims.
    return build_task(
        group,
        existing_skill=existing.skill_md,
        existing_patterns=existing.patterns,
        new_pattern_urls=new_urls,
    )
