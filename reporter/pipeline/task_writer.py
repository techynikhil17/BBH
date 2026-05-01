"""Write report-generation tasks for Claude Code to read.

One pending task per finding. Each task contains the finding, its CVSS, any
chain escalation, the platform, and the canonical instruction text. Claude
Code reads the instruction, writes the narrative sections, drops a
completion JSON; the assembler then renders the final markdown report.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from ..config import COMPLETED_DIR, PENDING_DIR, TASK_ID_PREFIX
from ..models import CVSSResult, EscalationResult, Finding


_INSTRUCTION = """You are writing a professional bug bounty vulnerability report for submission
to a bug bounty program. The researcher has confirmed this finding on an
authorized, in-scope target.

Read the finding, CVSS score, and any chain escalation in this task file.
Return a JSON object with the seven keys below — and ONLY those keys.
Be specific: reference the actual target, feature, and observation data.
Generic, vague, or padded prose is rejected by the validator.

ETHICAL CONSTRAINTS — non-negotiable:
- Do NOT include working exploit code or copy-paste payloads.
- Do NOT use sensational language ("zero-day", "hack", "exploit", "0day",
  "critical bug", "hacked").
- Do reference HTTP request shape (method, endpoint, parameter name)
  without full attack payloads.
- Steps must be reproducible by a competent triage engineer.

OUTPUT JSON — keys MUST match exactly:

{
  "title":
    "string — '[VulnType] in [Feature] allows [Impact]'.
     Max 80 chars. Factual.",

  "summary":
    "string — 2-3 sentences. Impact first, then cause.
     References the actual target and feature.",

  "vulnerability_details":
    "string — markdown.
     Root cause: what assumption did the developer make that's wrong?
     Why is this feature vulnerable in particular?
     Technical but accessible to triage. NO exploit code.",

  "impact_analysis":
    "string — markdown.
     Primary impact: what the attacker gains directly.
     Secondary impact: what they do with that.
     Affected scope: which users / data / systems are exposed.
     Be SPECIFIC ('attacker reads all user PII'), not vague ('data could be exposed').
     Must be at least 100 characters.",

  "steps_to_reproduce":
    "string — numbered markdown list, minimum 3 steps.
     Triage must be able to follow without guessing.
     For each step include the observation that confirms the issue.
     Reference HTTP method + endpoint + parameter shape; no full payload strings.",

  "proof_of_concept":
    "string — markdown.
     Describe the evidence captured (screenshots, requests, OOB callbacks).
     For chain findings: walk through each component's demonstration in order.
     No working exploit code.",

  "remediation":
    "string — markdown.
     Specific fix that addresses the root cause from `vulnerability_details`.
     Generic 'validate input' is rejected by the validator.
     Include hardening recommendations beyond the minimum fix.
     Reference the correct implementation pattern.
     Must be at least 100 characters."
}

If `chain_escalation.applied` is true in the task, the report should
present this finding as a chain: incorporate the chain reasoning into
`impact_analysis` and reference the matched escalation rule.
"""


def make_task_id(finding: Finding) -> str:
    safe_id = finding.finding_id.replace("/", "_").replace(" ", "-")
    return f"{TASK_ID_PREFIX}_{safe_id}"


def build_task(
    finding: Finding,
    cvss: CVSSResult,
    *,
    platform: str,
    chain_escalation: Optional[EscalationResult] = None,
    completed_dir: Path = COMPLETED_DIR,
) -> dict:
    """Build the JSON payload for one report-generation task."""
    task_id = make_task_id(finding)
    expected_output = completed_dir / f"{task_id}.json"
    return {
        "task_id": task_id,
        "task_type": "report_generation",
        "platform": platform,
        "finding": finding.model_dump(mode="json"),
        "cvss": cvss.model_dump(mode="json"),
        "chain_escalation": (
            chain_escalation.model_dump(mode="json") if chain_escalation else None
        ),
        "instruction": _INSTRUCTION,
        "expected_output_path": str(expected_output),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }


def write_task(task: dict, *, pending_dir: Path = PENDING_DIR) -> Path:
    """Atomically write ``task`` to ``pending_dir/<task_id>.json``."""
    pending_dir.mkdir(parents=True, exist_ok=True)
    out = pending_dir / f"{task['task_id']}.json"
    tmp = out.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(task, indent=2, default=str), encoding="utf-8")
    tmp.replace(out)
    return out


def write_tasks(
    tasks: list[dict],
    *,
    pending_dir: Path = PENDING_DIR,
) -> list[Path]:
    return [write_task(t, pending_dir=pending_dir) for t in tasks]
