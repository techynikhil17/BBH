"""Read completed task JSONs and assemble skill files on disk.

Skill layout (per group):
    skills/{vuln_class}/{slug}/
        ├── skill.md         # the markdown returned by Claude Code
        └── patterns.json    # the cleaned patterns list returned by Claude Code

The assembler is intentionally thin — it trusts Claude Code's
``skill_md_content`` verbatim. The validator (separate module) is what
guarantees structural correctness; the assembler is just I/O.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from pydantic import ValidationError

from ..config import COMPLETED_DIR, PENDING_DIR, SKILLS_DIR, TASK_ID_PREFIX
from ..models import GenerationCompletion

logger = logging.getLogger(__name__)


@dataclass
class AssemblyResult:
    task_id: str
    vuln_class: str
    vuln_subtype: str
    skill_path: Path
    patterns_path: Path
    pattern_count: int


class AssemblerError(Exception):
    """Couldn't assemble the skill (bad completion JSON, missing fields, etc.)."""


def _load_pending_task(task_id: str, pending_dir: Path) -> dict:
    path = pending_dir / f"{task_id}.json"
    if not path.exists():
        raise AssemblerError(f"pending task file missing for {task_id}: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _load_completion(task_id: str, completed_dir: Path) -> GenerationCompletion:
    path = completed_dir / f"{task_id}.json"
    if not path.exists():
        raise AssemblerError(f"completion file missing for {task_id}: {path}")
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise AssemblerError(f"completion file for {task_id} is not valid JSON: {exc}") from exc
    try:
        return GenerationCompletion(**raw)
    except ValidationError as exc:
        raise AssemblerError(f"completion file for {task_id} doesn't match expected shape: {exc}") from exc


def assemble_skill(
    task_id: str,
    *,
    pending_dir: Path = PENDING_DIR,
    completed_dir: Path = COMPLETED_DIR,
    skills_dir: Path = SKILLS_DIR,
    cleanup: bool = True,
) -> AssemblyResult:
    """Read the pending+completed pair for one task and write the skill on disk.

    On success removes both the pending and completed files (so a re-run
    doesn't duplicate work). On failure leaves them alone for debugging.
    """
    if not task_id.startswith(f"{TASK_ID_PREFIX}_"):
        raise AssemblerError(f"task_id {task_id} doesn't have the {TASK_ID_PREFIX}_ prefix")

    task_data = _load_pending_task(task_id, pending_dir)
    completion = _load_completion(task_id, completed_dir)

    vuln_class = task_data.get("vuln_class") or ""
    vuln_subtype = task_data.get("vuln_subtype") or "general"
    if not vuln_class:
        raise AssemblerError(f"pending task {task_id} missing vuln_class")

    slug = (vuln_subtype or "general").replace("/", "_").replace(" ", "-").lower()
    skill_dir = skills_dir / vuln_class / slug
    skill_dir.mkdir(parents=True, exist_ok=True)

    skill_path = skill_dir / "skill.md"
    patterns_path = skill_dir / "patterns.json"

    skill_md = completion.skill_md_content or ""
    if not skill_md.lstrip().startswith("# SKILL:"):
        raise AssemblerError(
            f"completion for {task_id} doesn't start with '# SKILL:' header"
        )

    skill_path.write_text(skill_md, encoding="utf-8")
    patterns_path.write_text(
        json.dumps(completion.patterns_json, indent=2) + "\n", encoding="utf-8"
    )

    if cleanup:
        for d in (pending_dir, completed_dir):
            p = d / f"{task_id}.json"
            try:
                p.unlink()
            except FileNotFoundError:
                pass

    return AssemblyResult(
        task_id=task_id,
        vuln_class=vuln_class,
        vuln_subtype=vuln_subtype,
        skill_path=skill_path,
        patterns_path=patterns_path,
        pattern_count=len(completion.patterns_json),
    )


def assemble_all(
    *,
    pending_dir: Path = PENDING_DIR,
    completed_dir: Path = COMPLETED_DIR,
    skills_dir: Path = SKILLS_DIR,
    cleanup: bool = True,
) -> tuple[list[AssemblyResult], list[tuple[str, str]]]:
    """Assemble every completion that has a matching pending task.

    Returns ``(results, errors)`` where ``errors`` is a list of
    ``(task_id, reason)`` tuples for completions that couldn't be assembled.
    """
    if not completed_dir.exists():
        return [], []

    results: list[AssemblyResult] = []
    errors: list[tuple[str, str]] = []

    for path in sorted(completed_dir.glob(f"{TASK_ID_PREFIX}_*.json")):
        task_id = path.stem
        try:
            results.append(
                assemble_skill(
                    task_id,
                    pending_dir=pending_dir,
                    completed_dir=completed_dir,
                    skills_dir=skills_dir,
                    cleanup=cleanup,
                )
            )
        except AssemblerError as exc:
            errors.append((task_id, str(exc)))
            logger.warning("assembly failed for %s: %s", task_id, exc)

    return results, errors
