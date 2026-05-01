from datetime import datetime
from pathlib import Path

import pytest

from researcher.session.models import ChainHypothesis, ChainStatus
from researcher.tools.skill_patcher import (
    APPENDABLE_SECTIONS,
    SkillPatcher,
    SkillPatcherError,
)


_BASE_SKILL = """# SKILL: SSRF — Cloud Metadata
**Category:** ssrf > cloud-metadata
**Severity Range:** high

---

## OVERVIEW
Lots of body content stays exactly as-is.

## ASSUMPTIONS TO CHALLENGE
- [ ] Initial assumption

## NOVEL DISCOVERIES LOG
| Date | Session ID | Discovery | Chain Potential | Incorporated |
|------|------------|-----------|-----------------|--------------|

## ATTACK CHAINS DISCOVERED


## FAILED APPROACHES
| Approach | Why It Failed | Date | Session |
|----------|---------------|------|---------|

## REPORTING TEMPLATE HINTS
y
"""


def _write_skill(tmp_path) -> Path:
    p = tmp_path / "skill.md"
    p.write_text(_BASE_SKILL, encoding="utf-8")
    return p


def test_appendable_sections_constant():
    # Sanity — the public list is locked to these 4
    assert "## NOVEL DISCOVERIES LOG" in APPENDABLE_SECTIONS
    assert "## ATTACK CHAINS DISCOVERED" in APPENDABLE_SECTIONS
    assert "## FAILED APPROACHES" in APPENDABLE_SECTIONS
    assert "## ASSUMPTIONS TO CHALLENGE" in APPENDABLE_SECTIONS
    assert len(APPENDABLE_SECTIONS) == 4


def test_append_novel_discovery(tmp_path):
    path = _write_skill(tmp_path)
    p = SkillPatcher()
    assert p.append_novel_discovery(
        path, session_id="sess1", discovery="Header X reflects user input", chain_potential="xss"
    )
    text = path.read_text(encoding="utf-8")
    assert "sess1" in text
    assert "Header X reflects user input" in text
    # The OVERVIEW body must remain intact
    assert "Lots of body content stays exactly as-is." in text
    # The downstream sections must remain intact
    assert "## REPORTING TEMPLATE HINTS" in text


def test_append_failed_approach(tmp_path):
    path = _write_skill(tmp_path)
    p = SkillPatcher()
    assert p.append_failed_approach(
        path, approach="Tested Host header bypass", reason="Server normalizes Host", session_id="sess2"
    )
    text = path.read_text(encoding="utf-8")
    assert "Tested Host header bypass" in text
    assert "Server normalizes Host" in text


def test_append_chain(tmp_path):
    path = _write_skill(tmp_path)
    chain = ChainHypothesis(
        chain_id="c1",
        session_id="sess3",
        chain_name="SSRF → IAM creds",
        from_skill="ssrf/cloud-metadata",
        to_skill="auth/jwt-bypass",
        trigger="metadata reachable",
        pivot="harvest IAM keys",
        combined_impact="full account takeover",
        status=ChainStatus.HYPOTHETICAL,
    )
    p = SkillPatcher()
    assert p.append_chain(path, chain)
    text = path.read_text(encoding="utf-8")
    assert "SSRF → IAM creds" in text
    assert "**Trigger:** metadata reachable" in text
    assert "**Pivot:** harvest IAM keys" in text
    assert "## REPORTING TEMPLATE HINTS" in text  # not clobbered


def test_append_assumption(tmp_path):
    path = _write_skill(tmp_path)
    p = SkillPatcher()
    assert p.append_assumption(path, "Assumes the URL is data, not a target")
    text = path.read_text(encoding="utf-8")
    assert "Assumes the URL is data, not a target" in text
    # Original assumption preserved
    assert "Initial assumption" in text


def test_append_to_missing_section_raises(tmp_path):
    skill_md = "# SKILL: x\n\n## OVERVIEW\nbody\n"
    path = tmp_path / "skill.md"
    path.write_text(skill_md, encoding="utf-8")
    p = SkillPatcher()
    with pytest.raises(SkillPatcherError):
        p.append_novel_discovery(path, session_id="s", discovery="x")


def test_append_to_missing_file_raises(tmp_path):
    p = SkillPatcher()
    with pytest.raises(SkillPatcherError):
        p.append_failed_approach(tmp_path / "no.md", approach="x", reason="y", session_id="s")


def test_pipe_in_field_is_escaped(tmp_path):
    """A user-supplied pipe character must not break table layout."""
    path = _write_skill(tmp_path)
    p = SkillPatcher()
    assert p.append_novel_discovery(
        path,
        session_id="sess",
        discovery="Saw weird response | with pipes | in body",
        chain_potential="-",
    )
    text = path.read_text(encoding="utf-8")
    # Escaped backslash-pipe should appear; raw `|` mid-cell would have broken the row
    assert r"\|" in text


def test_no_full_rewrite_preserves_byte_content(tmp_path):
    """Patching is append-only — content outside the target section must be byte-stable."""
    path = _write_skill(tmp_path)
    before = path.read_text(encoding="utf-8")
    overview_body = before.split("## ASSUMPTIONS")[0]

    p = SkillPatcher()
    p.append_novel_discovery(path, session_id="s", discovery="X")

    after = path.read_text(encoding="utf-8")
    after_overview = after.split("## ASSUMPTIONS")[0]
    assert overview_body == after_overview, "overview section was modified by patcher"
    # And the REPORTING TEMPLATE HINTS section should still be exact
    assert after.endswith("## REPORTING TEMPLATE HINTS\ny\n")
