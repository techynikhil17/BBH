import pytest

from updater.pipeline.version_manager import (
    apply_bump,
    bump_version_string,
    decide_bump,
    parse_current_version,
)


_SKILL_HEADER = """# SKILL: SSRF
**Category:** ssrf > cloud-metadata
**Severity Range:** high
**Typical Payout:** $1500
**Pattern Count:** 3
**Last Updated:** 2026-04-01
**Version:** 1.2.3

---

## OVERVIEW
body
"""


def test_decide_bump_patch_only():
    assert decide_bump({"NOVEL_DISCOVERIES_LOG"}) == "patch"
    assert decide_bump({"FAILED_APPROACHES"}) == "patch"
    assert decide_bump({"NOVEL_DISCOVERIES_LOG", "ATTACK_CHAINS_DISCOVERED"}) == "patch"


def test_decide_bump_minor_wins_when_present():
    """Mixed minor + patch → minor."""
    assert decide_bump({"COMMON_PATTERNS", "NOVEL_DISCOVERIES_LOG"}) == "minor"
    assert decide_bump({"PRECONDITIONS"}) == "minor"
    assert decide_bump({"DETECTION_SIGNALS"}) == "minor"
    assert decide_bump({"ASSUMPTIONS"}) == "minor"


def test_decide_bump_none_for_unknown_sections():
    assert decide_bump(set()) == "none"
    assert decide_bump({"REPORTING_TEMPLATE_HINTS"}) == "none"


def test_bump_version_string():
    assert bump_version_string("1.2.3", "patch") == "1.2.4"
    assert bump_version_string("1.2.3", "minor") == "1.3.0"
    assert bump_version_string("1.2.3", "major") == "2.0.0"
    assert bump_version_string("1.2.3", "none") == "1.2.3"


def test_parse_current_version_default_when_missing():
    assert parse_current_version("# SKILL: nope\n") == "1.0.0"


def test_parse_current_version_present():
    assert parse_current_version(_SKILL_HEADER) == "1.2.3"


def test_apply_bump_minor():
    new_text, result = apply_bump(_SKILL_HEADER, ["COMMON_PATTERNS"])
    assert result.bump_kind == "minor"
    assert result.old_version == "1.2.3"
    assert result.new_version == "1.3.0"
    assert "**Version:** 1.3.0" in new_text
    # Last Updated should also have been refreshed
    assert "**Last Updated:** 2026-04-01" not in new_text


def test_apply_bump_patch():
    new_text, result = apply_bump(_SKILL_HEADER, ["FAILED_APPROACHES"])
    assert result.bump_kind == "patch"
    assert result.new_version == "1.2.4"


def test_apply_bump_none_leaves_text_unchanged():
    new_text, result = apply_bump(_SKILL_HEADER, [])
    assert new_text == _SKILL_HEADER
    assert result.bump_kind == "none"


def test_apply_bump_injects_header_when_missing():
    skill_no_version = "# SKILL: no version yet\n\n## OVERVIEW\nbody\n"
    new_text, result = apply_bump(skill_no_version, ["COMMON_PATTERNS"])
    assert "**Version:**" in new_text
    assert result.new_version  # default bumped from 1.0.0 → 1.1.0
    assert result.new_version == "1.1.0"
