import json

import pytest

from generator.models import PatternGroup
from generator.pipeline.skill_assembler import (
    AssemblerError,
    assemble_all,
    assemble_skill,
)
from generator.pipeline.task_writer import build_task, write_task


_VALID_SKILL_MD = """# SKILL: SSRF — Cloud Metadata
**Category:** ssrf > cloud-metadata
**Severity Range:** high
**Typical Payout:** $1500
**Pattern Count:** 2
**Last Updated:** 2026-05-01
**Version:** 1.0.0

---

## OVERVIEW
x

## REPORTING TEMPLATE HINTS
- **Impact statement:** y
"""


def _setup_dirs(tmp_path):
    pending = tmp_path / "pending"
    completed = tmp_path / "completed"
    skills = tmp_path / "skills"
    pending.mkdir()
    completed.mkdir()
    skills.mkdir()
    return pending, completed, skills


def _pattern(url, vc="ssrf", vs="cloud-metadata"):
    return {
        "source_url": url,
        "vuln_class": vc,
        "vuln_subtype": vs,
        "preconditions": ["x"],
        "behavioral_signal": "y",
        "detection_approach": "z",
        "root_cause_pattern": "rcp",
        "skipped": False,
    }


def _write_pending_completion(pending, completed, group, skill_md=_VALID_SKILL_MD, patterns=None):
    """Helper: write a paired pending+completed pair for the given group."""
    task = build_task(group, completed_dir=completed)
    write_task(task, pending_dir=pending)
    completion = {
        "skill_md_content": skill_md,
        "patterns_json": patterns if patterns is not None else group.patterns,
        "metadata": {"pattern_count": len(group.patterns)},
    }
    (completed / f"{task.task_id}.json").write_text(json.dumps(completion), encoding="utf-8")
    return task.task_id


def test_assemble_writes_skill_and_patterns(tmp_path):
    pending, completed, skills = _setup_dirs(tmp_path)
    group = PatternGroup(
        vuln_class="ssrf",
        vuln_subtype="cloud-metadata",
        patterns=[_pattern("u1"), _pattern("u2")],
    )

    task_id = _write_pending_completion(pending, completed, group)
    result = assemble_skill(
        task_id,
        pending_dir=pending,
        completed_dir=completed,
        skills_dir=skills,
    )

    assert result.skill_path.exists()
    assert result.patterns_path.exists()
    assert result.skill_path.read_text(encoding="utf-8").startswith("# SKILL:")
    saved_patterns = json.loads(result.patterns_path.read_text(encoding="utf-8"))
    assert len(saved_patterns) == 2
    # Cleanup happened
    assert not (pending / f"{task_id}.json").exists()
    assert not (completed / f"{task_id}.json").exists()


def test_assemble_raises_on_missing_completion(tmp_path):
    pending, completed, skills = _setup_dirs(tmp_path)
    with pytest.raises(AssemblerError):
        assemble_skill(
            "skillgen_ssrf_nope",
            pending_dir=pending,
            completed_dir=completed,
            skills_dir=skills,
        )


def test_assemble_raises_on_malformed_completion(tmp_path):
    pending, completed, skills = _setup_dirs(tmp_path)
    group = PatternGroup(
        vuln_class="ssrf",
        vuln_subtype="cloud-metadata",
        patterns=[_pattern("u1"), _pattern("u2")],
    )
    task = build_task(group, completed_dir=completed)
    write_task(task, pending_dir=pending)
    (completed / f"{task.task_id}.json").write_text("{bad json", encoding="utf-8")

    with pytest.raises(AssemblerError):
        assemble_skill(
            task.task_id,
            pending_dir=pending,
            completed_dir=completed,
            skills_dir=skills,
        )


def test_assemble_raises_when_skill_missing_header(tmp_path):
    pending, completed, skills = _setup_dirs(tmp_path)
    group = PatternGroup(
        vuln_class="ssrf",
        vuln_subtype="cloud-metadata",
        patterns=[_pattern("u1"), _pattern("u2")],
    )
    _write_pending_completion(pending, completed, group, skill_md="No proper header here")

    with pytest.raises(AssemblerError):
        assemble_skill(
            group.task_id,
            pending_dir=pending,
            completed_dir=completed,
            skills_dir=skills,
        )


def test_assemble_rejects_wrong_task_id_prefix(tmp_path):
    pending, completed, skills = _setup_dirs(tmp_path)
    with pytest.raises(AssemblerError):
        assemble_skill(
            "extract_something",  # wrong prefix
            pending_dir=pending,
            completed_dir=completed,
            skills_dir=skills,
        )


def test_assemble_all_partial_success(tmp_path):
    pending, completed, skills = _setup_dirs(tmp_path)
    group_a = PatternGroup(
        vuln_class="ssrf",
        vuln_subtype="cloud-metadata",
        patterns=[_pattern("u1"), _pattern("u2")],
    )
    group_b = PatternGroup(
        vuln_class="rce",
        vuln_subtype="ssti",
        patterns=[_pattern("u3", "rce", "ssti"), _pattern("u4", "rce", "ssti")],
    )

    # group_a has a valid completion
    _write_pending_completion(pending, completed, group_a)
    # group_b's completion is broken
    task_b = build_task(group_b, completed_dir=completed)
    write_task(task_b, pending_dir=pending)
    (completed / f"{task_b.task_id}.json").write_text("not json", encoding="utf-8")

    results, errors = assemble_all(
        pending_dir=pending,
        completed_dir=completed,
        skills_dir=skills,
    )
    assert len(results) == 1
    assert len(errors) == 1
    assert results[0].vuln_class == "ssrf"
    assert errors[0][0] == task_b.task_id
