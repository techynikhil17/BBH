from datetime import datetime
from pathlib import Path

import pytest

from researcher.session.models import (
    ChainHypothesis,
    ChainStatus,
    SessionResult,
)
from updater.pipeline.chain_propagator import PropagationResult
from updater.pipeline.skill_writer import WriteResult
from updater.pipeline.version_manager import BumpResult
from updater.report_generator import (
    ReportInputs,
    SkillUpdateRecord,
    render_report,
    write_report,
)


def _session(with_chain=False):
    chains = []
    if with_chain:
        chains.append(
            ChainHypothesis(
                chain_id="c1",
                session_id="sess-1",
                chain_name="SSRF → JWT",
                from_skill="ssrf/cloud-metadata",
                to_skill="auth/jwt-bypass",
                trigger="t",
                pivot="p",
                combined_impact="ato",
                status=ChainStatus.CONFIRMED,
            )
        )
    return SessionResult(
        session_id="sess-1",
        program="shopify",
        target="api.shopify.com",
        skill_used="ssrf/cloud-metadata",
        scope_file="/scope.json",
        started_at=datetime(2026, 5, 1),
        chains=chains,
    )


def _record():
    write = WriteResult(
        success=True,
        sections_changed=["COMMON_PATTERNS", "PRECONDITIONS"],
        bump=BumpResult(old_version="1.0.0", new_version="1.1.0", bump_kind="minor"),
        backup_path=Path("/tmp/skill.md.20260501_120000.bak"),
    )
    return SkillUpdateRecord.from_write_result(
        skill_id="ssrf/cloud-metadata",
        skill_path="/skills/ssrf/cloud-metadata/skill.md",
        write=write,
        promoted_pattern_count=2,
    )


def test_report_contains_all_required_sections():
    inputs = ReportInputs(
        session=_session(with_chain=True),
        skill_records=[_record()],
        propagation=PropagationResult(chains_propagated=1, skills_updated=["a", "b"]),
        pending_promotions=[
            {"description": "Pending one", "session_count": 1, "related_skill": "ssrf/cloud-metadata"}
        ],
        nothing_to_update_skills=[],
    )
    text = render_report(inputs)
    for header in (
        "# Skill Update Report",
        "## Summary",
        "## Changes Per Skill",
        "## Confirmed Chains Propagated",
        "## Pending Promotion (Need More Sessions)",
        "## Nothing To Update",
    ):
        assert header in text, f"missing: {header}"


def test_report_summary_counts():
    inputs = ReportInputs(
        session=_session(),
        skill_records=[_record()],
        propagation=PropagationResult(chains_propagated=2, skills_updated=["a", "b"]),
        pending_promotions=[],
        nothing_to_update_skills=[],
    )
    text = render_report(inputs)
    assert "Skills updated: 1" in text
    assert "Patterns promoted: 2" in text
    assert "Chains propagated: 2" in text


def test_report_lists_version_bump():
    inputs = ReportInputs(
        session=_session(),
        skill_records=[_record()],
    )
    text = render_report(inputs)
    assert "1.0.0→1.1.0" in text


def test_report_when_nothing_changes():
    inputs = ReportInputs(
        session=_session(),
        skill_records=[],
        nothing_to_update_skills=["ssrf/cloud-metadata"],
    )
    text = render_report(inputs)
    assert "(no skills changed)" in text
    assert "ssrf/cloud-metadata" in text


def test_write_report_emits_file(tmp_path):
    inputs = ReportInputs(
        session=_session(with_chain=True),
        skill_records=[_record()],
    )
    path = write_report(inputs, sessions_dir=tmp_path)
    assert path.exists()
    assert path.name == "update_report.md"
    assert path.parent.name == "sess-1"
    text = path.read_text(encoding="utf-8")
    assert "sess-1" in text
