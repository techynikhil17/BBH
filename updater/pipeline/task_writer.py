"""Write Claude Code synthesis tasks for the updater.

Most updater work is deterministic and Python handles it directly. We only
hand off to Claude Code when something requires reasoning:
- a promotable pattern needs a well-formed COMMON PATTERNS table row,
- structural_hints suggest new preconditions / assumptions,
- DETECTION SIGNALS likely needs a refresh.

Otherwise ``build_task`` returns ``None`` and the caller skips the handoff.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from researcher.session.models import SessionResult

from ..config import COMPLETED_DIR, PENDING_DIR, TASK_ID_PREFIX
from .diff_analyzer import DiffResult


_INSTRUCTION = """You are updating a bug bounty skill file after a research session.
Read the current skill content and session summary carefully.

Your job is to determine and write ONLY these updates and return them as JSON.

ETHICAL CONSTRAINTS — non-negotiable:
- Do NOT include exploitation code, payload strings, or weaponized techniques.
- Do NOT reproduce report content verbatim. Paraphrase at a methodology level.
- If unsure, leave the field as null and let the human reviewer decide.

OUTPUT FIELDS:

1. promoted_pattern_rows: []
   For each entry in `session_summary.promotable_patterns`, write a new
   markdown table row for COMMON PATTERNS FROM REAL REPORTS using the
   exact column shape of the existing rows in the current_skill_content.
   Append "(confirmed {N} sessions)" to the Pattern column where N is the
   pattern's session_count. Skip patterns that already appear in the table.

2. new_preconditions: []
   If structural_hints reveal preconditions not already listed in the
   skill's PRECONDITIONS section, write each as a fresh checkbox item
   (e.g. "- [ ] User session must hold an OAuth refresh token").
   Otherwise return an empty list.

3. new_assumptions: []
   If structural_hints suggest unchecked developer assumptions not already
   in ASSUMPTIONS TO CHALLENGE, write fresh checkbox items.

4. updated_detection_signals: null
   Return the full replacement body for the DETECTION SIGNALS section
   (without the `## DETECTION SIGNALS` header) only if the session reveals
   genuinely new positive / negative / escalation signals worth folding
   into the canonical lists. Return null otherwise.

5. chain_entries: {}
   For each confirmed chain in session_summary.confirmed_chains, write the
   entry from EACH involved skill's perspective. Key = skill_path
   (e.g. "ssrf/cloud-metadata"), value = the markdown block to append to
   ATTACK CHAINS DISCOVERED in that skill. Do not duplicate entries the
   skill already documents. Return {} if no chain documentation is needed.

RULES:
- Never remove existing content.
- Never rewrite sections that aren't in your output.
- Keep formatting (table columns, checkbox style) identical to the
  existing skill body.
- If a field needs no update, return null (or [] / {} for collection types).

Return JSON shape:
{
  "promoted_pattern_rows": ["...", "..."],
  "new_preconditions": ["- [ ] ...", "..."],
  "new_assumptions": ["- [ ] ...", "..."],
  "updated_detection_signals": null,
  "chain_entries": {
    "ssrf/cloud-metadata": "### Chain: ...",
    "rce/deserialization/java": "### Chain: ..."
  }
}
"""


def make_task_id(session_id: str, skill_path: str) -> str:
    """Build the deterministic, filesystem-safe task id used everywhere."""
    safe_skill = skill_path.replace("/", "_").replace(" ", "-")
    return f"{TASK_ID_PREFIX}_{session_id}_{safe_skill}"


def needs_claude_code(diff: DiffResult) -> bool:
    """``True`` when the diff has work that requires reasoning."""
    return bool(diff.promotable_patterns) or diff.needs_structural_update


def build_task(
    session: SessionResult,
    diff: DiffResult,
    *,
    completed_dir: Path = COMPLETED_DIR,
) -> Optional[dict[str, Any]]:
    """Compose the JSON payload for a single updater task. ``None`` if not needed."""
    if not needs_claude_code(diff):
        return None

    skill_path = Path(diff.skill_path)
    skill_id = "/".join(skill_path.parent.parts[-2:]) if "skill.md" in skill_path.name else str(skill_path)
    current_content = skill_path.read_text(encoding="utf-8") if skill_path.exists() else ""

    task_id = make_task_id(session.session_id, skill_id)
    expected_output = completed_dir / f"{task_id}.json"
    return {
        "task_id": task_id,
        "task_type": "skill_update",
        "skill_path": skill_id,
        "session_id": session.session_id,
        "current_skill_content": current_content,
        "session_summary": {
            "novel_observations": diff.novel_observations,
            "confirmed_chains": diff.confirmed_chains,
            "promotable_patterns": diff.promotable_patterns,
            "structural_hints": diff.structural_hints,
            "failed_approaches": diff.failed_approaches,
        },
        "instruction": _INSTRUCTION,
        "expected_output_path": str(expected_output),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def write_task(task: dict[str, Any], *, pending_dir: Path = PENDING_DIR) -> Path:
    """Atomically write ``task`` to ``pending_dir/<task_id>.json``."""
    pending_dir.mkdir(parents=True, exist_ok=True)
    out = pending_dir / f"{task['task_id']}.json"
    tmp = out.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(task, indent=2, default=str), encoding="utf-8")
    tmp.replace(out)
    return out
