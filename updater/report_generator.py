"""Generate the post-update markdown summary report.

Written to ``data/sessions/{session_id}/update_report.md`` after every
successful ``update`` run. Keeps a human-readable trail of what changed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

from researcher.session.models import SessionResult

from .pipeline.chain_propagator import PropagationResult
from .pipeline.diff_analyzer import DiffResult
from .pipeline.skill_writer import WriteResult


@dataclass
class SkillUpdateRecord:
    """One row of "what happened to a single skill"."""

    skill_id: str
    skill_path: str
    sections_changed: list[str] = field(default_factory=list)
    promoted_pattern_count: int = 0
    bump_kind: str = "none"
    old_version: str = ""
    new_version: str = ""
    backup_path: Optional[str] = None
    success: bool = True
    errors: list[str] = field(default_factory=list)

    @classmethod
    def from_write_result(
        cls,
        skill_id: str,
        skill_path: str,
        write: WriteResult,
        promoted_pattern_count: int,
    ) -> "SkillUpdateRecord":
        return cls(
            skill_id=skill_id,
            skill_path=skill_path,
            sections_changed=list(write.sections_changed),
            promoted_pattern_count=promoted_pattern_count,
            bump_kind=write.bump.bump_kind if write.bump else "none",
            old_version=write.bump.old_version if write.bump else "",
            new_version=write.bump.new_version if write.bump else "",
            backup_path=str(write.backup_path) if write.backup_path else None,
            success=write.success,
            errors=list(write.errors),
        )


@dataclass
class ReportInputs:
    session: SessionResult
    skill_records: list[SkillUpdateRecord] = field(default_factory=list)
    propagation: Optional[PropagationResult] = None
    pending_promotions: list[dict] = field(default_factory=list)
    nothing_to_update_skills: list[str] = field(default_factory=list)
    diffs: list[DiffResult] = field(default_factory=list)
    timestamp: Optional[datetime] = None


def render_report(inputs: ReportInputs) -> str:
    """Return the report markdown — pure function, easy to unit-test."""
    s = inputs.session
    ts = inputs.timestamp or datetime.now()

    lines: list[str] = [
        f"# Skill Update Report — {s.session_id}",
        f"**Generated:** {ts.isoformat(timespec='seconds')}",
        f"**Session:** {s.program} / {s.target} / {s.skill_used}",
        "",
        "## Summary",
    ]

    sections_changed = sorted({sec for r in inputs.skill_records for sec in r.sections_changed})
    promoted_total = sum(r.promoted_pattern_count for r in inputs.skill_records)
    chain_count = inputs.propagation.chains_propagated if inputs.propagation else 0
    chain_skills = (
        len(inputs.propagation.skills_updated) if inputs.propagation else 0
    )

    bumps = ", ".join(
        f"{r.skill_id} → {r.old_version}→{r.new_version}"
        for r in inputs.skill_records
        if r.bump_kind != "none" and r.old_version
    ) or "(none)"

    lines.extend(
        [
            f"- Skills updated: {sum(1 for r in inputs.skill_records if r.success and r.sections_changed)}",
            f"- Sections changed: {', '.join(sections_changed) if sections_changed else '(none)'}",
            f"- Patterns promoted: {promoted_total}",
            f"- Chains propagated: {chain_count} (across {chain_skills} skill(s))",
            f"- Version bumps: {bumps}",
            "",
            "## Changes Per Skill",
        ]
    )

    if not inputs.skill_records:
        lines.append("_(no skills changed)_")
    for r in inputs.skill_records:
        lines.append(f"### {r.skill_id}")
        lines.append(f"- Path: `{r.skill_path}`")
        lines.append(
            f"- Version: {r.old_version or '-'} → {r.new_version or '-'} "
            f"({r.bump_kind})"
        )
        lines.append(
            f"- Sections updated: "
            f"{', '.join(r.sections_changed) if r.sections_changed else '(none)'}"
        )
        lines.append(f"- Promoted patterns: {r.promoted_pattern_count}")
        if r.backup_path:
            lines.append(f"- Backup: `{r.backup_path}`")
        if r.errors:
            lines.append("- Errors:")
            lines.extend(f"  - {e}" for e in r.errors)
        lines.append("")

    lines.append("## Confirmed Chains Propagated")
    chains = [c for c in s.chains if c.status.value == "confirmed"]
    if chains:
        lines.append("| Chain | From | To | Combined Impact |")
        lines.append("|-------|------|----|------------------|")
        for c in chains:
            lines.append(
                f"| {c.chain_name} | {c.from_skill} | {c.to_skill} | "
                f"{(c.combined_impact or '-')[:80]} |"
            )
    else:
        lines.append("_(no confirmed chains)_")
    lines.append("")

    lines.append("## Pending Promotion (Need More Sessions)")
    if inputs.pending_promotions:
        lines.append("| Pattern | Sessions Seen | Skill |")
        lines.append("|---------|--------------:|-------|")
        for p in inputs.pending_promotions:
            lines.append(
                f"| {p.get('description', '-')[:80]} | "
                f"{p.get('session_count', 0)} | "
                f"{p.get('related_skill', '-')} |"
            )
    else:
        lines.append("_(none)_")
    lines.append("")

    lines.append("## Nothing To Update")
    if inputs.nothing_to_update_skills:
        for skill in inputs.nothing_to_update_skills:
            lines.append(f"- {skill}")
    else:
        lines.append("_(every relevant skill had at least one change)_")
    lines.append("")

    return "\n".join(lines)


def write_report(
    inputs: ReportInputs,
    *,
    sessions_dir: Path,
) -> Path:
    """Render and write the report to ``sessions_dir/{session_id}/update_report.md``."""
    out_dir = Path(sessions_dir) / inputs.session.session_id
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "update_report.md"
    report_path.write_text(render_report(inputs), encoding="utf-8")
    return report_path
