"""Generate the research brief Claude Code reads at every turn.

Pure function: takes structured state, returns markdown. Stays free of
side effects so it's trivial to test and to regenerate after every
observation update.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from ..session.models import Observation, SessionResult


# Sections we lift into the brief from the source skill.md
_PRECONDITIONS_HEADER = "## PRECONDITIONS"
_ASSUMPTIONS_HEADER = "## ASSUMPTIONS TO CHALLENGE"
_FAILED_HEADER = "## FAILED APPROACHES"


def _extract_section(skill_md: str, header: str) -> str:
    """Return the body of ``## {header}`` in ``skill_md``, or empty string."""
    pattern = re.compile(
        rf"^{re.escape(header)}\s*\n(?P<body>(?:.|\n)*?)(?=^##\s|\Z)",
        re.MULTILINE,
    )
    match = pattern.search(skill_md)
    return match.group("body").strip() if match else ""


def _bulleted_lines(text: str, max_items: int = 12) -> list[str]:
    items = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("- ", "* ", "+ ")) or re.match(r"^- \[\s*[xX ]?\s*\]", stripped):
            items.append(stripped)
        if len(items) >= max_items:
            break
    return items


def _render_observations(observations: list[Observation]) -> str:
    if not observations:
        return "_(no observations logged yet — first probe pending)_"
    lines = [
        "| # | Type | Skill | Description | Probe |",
        "|---|------|-------|-------------|-------|",
    ]
    for i, obs in enumerate(observations, start=1):
        lines.append(
            f"| {i} | {obs.observation_type.value} | "
            f"{obs.related_skill} | "
            f"{_one_line(obs.description, 70)} | "
            f"{_one_line(obs.probe_description, 60)} |"
        )
    return "\n".join(lines)


def _render_chain_suggestions(chains: list[dict[str, Any]]) -> str:
    if not chains:
        return "_(no chain suggestions in the knowledge graph for this skill yet)_"
    lines = [
        "| Rank | From → To | Frequency | Confidence | Trigger |",
        "|------|-----------|----------:|------------|---------|",
    ]
    for i, c in enumerate(chains, start=1):
        lines.append(
            f"| {i} | {c.get('from_skill', '-')} → {c.get('to_skill', '-')} | "
            f"{c.get('frequency', 0)} | {c.get('confidence', '-')} | "
            f"{_one_line(c.get('trigger', '-'), 60)} |"
        )
    return "\n".join(lines)


def _render_failed_approaches(skill_md: str, session: SessionResult) -> str:
    """Combine failures from skill file + this session so Claude Code doesn't repeat them."""
    lines: list[str] = []
    body = _extract_section(skill_md, _FAILED_HEADER)
    if body:
        lines.append("**From skill file:**")
        lines.append(body)
    if session.failed_approaches:
        lines.append("\n**This session:**")
        for fa in session.failed_approaches:
            lines.append(f"- `{fa.approach}` → {fa.reason}")
    if not lines:
        return "_(none recorded — fresh territory)_"
    return "\n".join(lines)


def _one_line(text: str, max_chars: int) -> str:
    text = re.sub(r"\s+", " ", (text or "").strip())
    if len(text) > max_chars:
        text = text[: max_chars - 1].rstrip() + "…"
    # escape pipes so the row stays valid markdown
    return text.replace("|", r"\|")


def _render_recon(recon: dict[str, Any]) -> str:
    if not recon:
        return "_(no recon supplied — pass `--recon path/to.json` to enrich the brief)_"
    lines = []
    for key, value in recon.items():
        if isinstance(value, (list, tuple)):
            value_str = ", ".join(str(v) for v in value)
        elif isinstance(value, dict):
            value_str = ", ".join(f"{k}={v}" for k, v in value.items())
        else:
            value_str = str(value)
        lines.append(f"- **{key}:** {_one_line(value_str, 200)}")
    return "\n".join(lines)


def generate_session_brief(
    *,
    skill_content: str,
    session: SessionResult,
    recon_data: dict[str, Any],
    chain_suggestions: list[dict[str, Any]],
    observations_so_far: list[Observation],
    scope_summary: str = "",
) -> str:
    """Render the full markdown brief Claude Code reads."""
    preconditions = _extract_section(skill_content, _PRECONDITIONS_HEADER) or "_(skill file has no PRECONDITIONS section)_"
    assumptions = _extract_section(skill_content, _ASSUMPTIONS_HEADER) or "_(no assumptions listed in the skill file)_"

    parts = [
        f"# RESEARCH BRIEF — {session.session_id}",
        f"**Target:** {session.target}  **Program:** {session.program}  "
        f"**Skill:** {session.skill_used}  "
        f"**Started:** {session.started_at.isoformat() if isinstance(session.started_at, datetime) else session.started_at}",
        "",
        "## SCOPE CONFIRMATION",
        scope_summary or "_(scope summary not provided)_",
        "",
        "## TECH STACK (from recon)",
        _render_recon(recon_data),
        "",
        "## SKILL SUMMARY",
        "**Preconditions** (verify each on the target before probing):",
        preconditions,
        "",
        "**Assumptions to challenge:**",
        assumptions,
        "",
        "## CHAIN OPPORTUNITIES (from knowledge graph)",
        _render_chain_suggestions(chain_suggestions),
        "",
        "## SESSION OBSERVATIONS SO FAR",
        _render_observations(observations_so_far),
        "",
        "## FAILED APPROACHES (DO NOT REPEAT)",
        _render_failed_approaches(skill_content, session),
        "",
        "## YOUR TASK",
        "Based on the above:",
        "1. Identify 3 gaps the skill file doesn't cover for THIS specific target.",
        "2. Generate 5 ranked test hypotheses (skill-based + novel).",
        "3. Propose the single best next probe to execute.",
        "4. After the next observation is logged, perform chain analysis and "
        "propose either the next probe in the same line of attack or a pivot.",
        "",
        "Think like a senior researcher, not a scanner. What assumption did the "
        "developer make that might be wrong? Where does the published "
        "methodology have blind spots for this specific target?",
        "",
        "ETHICAL CONSTRAINTS:",
        "- Stay within the scope shown above. Out-of-scope tests must be refused.",
        "- Do NOT propose payload strings, exploit code, or weaponized techniques. "
        "Describe probes at the methodology level.",
        "- Stop and recommend triage if a probe could destabilize the target or "
        "exfiltrate live user data.",
    ]
    return "\n".join(parts)
