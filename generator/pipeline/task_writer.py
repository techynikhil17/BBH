"""Write generation task files for Claude Code to pick up.

For each ``PatternGroup``, we drop a JSON file at
``data/claude_tasks/pending/{task_id}.json`` containing:
- the patterns to reason over,
- the existing skill content (when updating),
- a fully-substituted schema template (Jinja2-rendered),
- a natural-language instruction telling Claude Code exactly what to return.

Claude Code reads this file, generates the skill markdown using its own
reasoning, and writes a completion JSON to ``COMPLETED_DIR``.
"""

from __future__ import annotations

import json
import logging
from datetime import date
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, StrictUndefined, select_autoescape

from ..config import (
    COMPLETED_DIR,
    PENDING_DIR,
    SKILL_TEMPLATE_NAME,
    TEMPLATE_DIR,
)
from ..models import GenerationTask, PatternGroup

logger = logging.getLogger(__name__)


_INSTRUCTION_TEMPLATE = """Generate a complete skill.md for {vuln_class} / {vuln_subtype} using the
patterns provided in this task file. Follow the EXACT schema in
`schema_template` — every section header must appear, in the order shown,
with the same wording. Derive content directly from the patterns; do NOT
fall back on generic knowledge about this vulnerability class.

ETHICAL CONSTRAINTS — non-negotiable:
- Do NOT include exploitation code, payload strings, or weaponized techniques.
- Do NOT reproduce report content verbatim. Paraphrase at a methodology level.
- Focus on detection methodology, behavioral signals, and root-cause patterns.

DERIVE CONTENT FROM THE PATTERNS:
- OVERVIEW: synthesize across the `root_cause_pattern` fields. 3-4 sentences.
- PRECONDITIONS: deduplicate the entries from `preconditions` arrays;
  3-8 items total. Each must be observable on a target.
- DETECTION METHODOLOGY: derive Phase 1 from `affected_feature_type` and
  `affected_stack_hints`; Phase 2 from `detection_approach` and
  `oob_required`; Phase 3 from `behavioral_signal` plus your judgment about
  false-positive distinguishers.
- TESTING WORKFLOW: 5-10 ASCII steps connected with `→` arrows.
- COMMON PATTERNS table: one row per distinct pattern. Compute frequency by
  counting patterns that share the same `root_cause_pattern` shape (case-
  insensitive substring overlap is fine). Sort by frequency descending.
- DETECTION SIGNALS: positive signals from `behavioral_signal` fields;
  negative signals are inferred — what looks similar but isn't this vuln;
  escalation signals come from `chain_targets` + `chain_reasoning`.
- CHAIN OPPORTUNITIES table: derive from `chain_targets`. Confidence:
  `high` if a target appears in > 2 patterns in this group, `medium` if
  1-2 patterns, `low` if only inferred from chain_reasoning narrative.
- ASSUMPTIONS TO CHALLENGE: minimum 3, derived from `root_cause_pattern`.
  State the developer's wrong assumption that the patterns prove false.
- REPORTING TEMPLATE HINTS: derive each subsection from the patterns
  (severity range for impact, common pattern shape for CVSS hint,
  root_cause_pattern for remediation, detection_approach for PoC format).

UPDATE MODE:
{update_block}

OUTPUT:
Return ONLY a JSON object with these keys:
{{
  "skill_md_content": "<the complete markdown string, starting with '# SKILL: ...'>",
  "patterns_json": [<the same patterns array, deduplicated by source_url, with
                    LLM-irrelevant fields trimmed if you wish>],
  "metadata": {{
    "pattern_count": <int>,
    "severity_range": "<e.g., 'medium-critical'>",
    "payout_range": "<e.g., '$500-$5,000' or 'unknown' if no payouts present>",
    "chain_skills": [<list of canonical vuln_class strings most likely to chain>]
  }}
}}

Write that JSON to `{expected_output_path}`. No prose outside the JSON.
"""

_INSTRUCTION_UPDATE_BLOCK_NEW = (
    "This is a NEW skill. There is no `existing_skill` content to merge."
)

_INSTRUCTION_UPDATE_BLOCK_UPDATE = """This is an UPDATE to an existing skill. The current skill.md content is in
`existing_skill`. The URLs in `new_pattern_urls` are patterns that have not
yet been incorporated. Strategy:
- Preserve unchanged sections verbatim.
- Add rows to the COMMON PATTERNS table for new behavioral shapes.
- Extend DETECTION SIGNALS lists with any new signals from the new patterns.
- Update CHAIN OPPORTUNITIES if the new patterns reveal new chain targets.
- Bump version: patch (z) for log-only additions; minor (y) for new
  patterns affecting the main body. Update Last Updated to today.
- Do NOT remove existing rows — only append / refine.
"""


def _render_schema_template(group: PatternGroup) -> str:
    """Pre-fill the static placeholders so Claude Code sees a concrete schema.

    Dynamic counts (severity_range, payout, etc.) are left as instruction
    text rather than rendered placeholders — Claude Code computes those from
    the patterns and substitutes them in its output.
    """
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(disabled_extensions=("md",), default=False),
        undefined=StrictUndefined,
    )
    tmpl = env.get_template(SKILL_TEMPLATE_NAME)
    skill_name = f"{group.vuln_class.upper()} — {group.vuln_subtype.replace('_', ' ').title()}"
    return tmpl.render(
        skill_name=skill_name,
        vuln_class=group.vuln_class,
        vuln_subtype=group.vuln_subtype,
        # The fields below are placeholders Claude Code overwrites in its output.
        severity_range="<derived from severity fields in patterns>",
        typical_payout="<derived from payout_usd fields in patterns>",
        pattern_count=len(group.patterns),
        last_updated=date.today().isoformat(),
        version="1.0.0",
    )


def build_instruction(
    group: PatternGroup,
    expected_output_path: Path,
    *,
    is_update: bool,
) -> str:
    """Compose the natural-language instruction embedded in the task file."""
    update_block = _INSTRUCTION_UPDATE_BLOCK_UPDATE if is_update else _INSTRUCTION_UPDATE_BLOCK_NEW
    return _INSTRUCTION_TEMPLATE.format(
        vuln_class=group.vuln_class,
        vuln_subtype=group.vuln_subtype,
        expected_output_path=str(expected_output_path),
        update_block=update_block,
    )


def build_task(
    group: PatternGroup,
    *,
    completed_dir: Path = COMPLETED_DIR,
    existing_skill: Optional[str] = None,
    existing_patterns: Optional[list[dict]] = None,
    new_pattern_urls: Optional[list[str]] = None,
) -> GenerationTask:
    """Build a typed ``GenerationTask`` for ``group`` ready to be serialized."""
    is_update = existing_skill is not None
    expected_output = completed_dir / f"{group.task_id}.json"
    instruction = build_instruction(group, expected_output, is_update=is_update)
    schema = _render_schema_template(group)
    return GenerationTask(
        task_id=group.task_id,
        vuln_class=group.vuln_class,
        vuln_subtype=group.vuln_subtype,
        patterns=group.patterns,
        existing_skill=existing_skill,
        existing_patterns=existing_patterns,
        new_pattern_urls=new_pattern_urls,
        is_update=is_update,
        instruction=instruction,
        schema_template=schema,
        expected_output_path=str(expected_output),
    )


def write_task(
    task: GenerationTask,
    *,
    pending_dir: Path = PENDING_DIR,
) -> Path:
    """Atomically write ``task`` to ``pending_dir/<task_id>.json``."""
    pending_dir.mkdir(parents=True, exist_ok=True)
    path = pending_dir / f"{task.task_id}.json"
    tmp = path.with_suffix(".json.tmp")
    payload = task.model_dump(mode="json")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    tmp.replace(path)
    return path


def write_tasks(
    tasks: list[GenerationTask],
    *,
    pending_dir: Path = PENDING_DIR,
) -> list[Path]:
    """Write every task; return the list of files created."""
    return [write_task(t, pending_dir=pending_dir) for t in tasks]
