from pathlib import Path

import pytest

from updater.pipeline.skill_writer import SkillWriter


_VALID_SKILL = """# SKILL: SSRF
**Category:** ssrf > cloud-metadata
**Severity Range:** high
**Typical Payout:** $1500
**Pattern Count:** 3
**Last Updated:** 2026-05-01
**Version:** 1.0.0

---

## OVERVIEW
Server-side request forgery in features that fetch user-controlled URLs
allows attackers to reach internal services, including cloud metadata
endpoints. Developers commonly miss this because the URL is treated as
data, not as a target whose host must be validated against an allow-list.

## PRECONDITIONS
- [ ] Endpoint accepts a user-supplied URL parameter
- [ ] Server fetches the URL during normal operation
- [ ] No DNS resolution validation against private ranges

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Look for webhook, integration callback, and URL-import endpoints.

### Phase 2: Active Probing (Authorized Scope Only)
Send the endpoint a URL that resolves to a controlled host; observe
whether the request originates server-side via OOB collaborator.

### Phase 3: Confirmation
Confirm the server resolves DNS and follows redirects without host
validation.

## TESTING WORKFLOW
```
Step 1: x
   →
Step 2: y
```

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Webhook fetch | 2 | webhook | Outbound from server IP | aws |

## DETECTION SIGNALS
**Positive signals:**
- Outbound HTTP request originates from application server

**Negative signals (likely false positive):**
- Request originates from client browser

**Escalation signals:**
- Response includes credentials

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| info_disclosure | IAM credential leak | metadata reachable | high |

## ASSUMPTIONS TO CHALLENGE
- [ ] The URL is data, not a target

## SCOPE CHECKLIST
- [ ] Target confirmed in-scope per program policy
- [ ] Staging/test environment identified if available
- [ ] Rate limiting considered — no DoS risk
- [ ] OOB infrastructure ready if oob_required
- [ ] No production data manipulation planned

## NOVEL DISCOVERIES LOG
| Date | Session ID | Discovery | Chain Potential | Incorporated |
|------|------------|-----------|-----------------|--------------|

## ATTACK CHAINS DISCOVERED


## FAILED APPROACHES
| Approach | Why It Failed | Date | Session |
|----------|---------------|------|---------|

## REPORTING TEMPLATE HINTS
- **Impact statement:** Internal services reachable via SSRF.
- **CVSS hint:** AV:N/AC:L/PR:N/UI:N/S:C
- **Remediation:** Add host allow-list and validate resolved DNS.
- **PoC format:** Screenshot of outbound from server IP to sentinel host.
"""


def _write_skill(tmp_path) -> Path:
    p = tmp_path / "skill.md"
    p.write_text(_VALID_SKILL, encoding="utf-8")
    return p


def test_apply_promoted_pattern_appends_row_and_bumps_minor(tmp_path):
    path = _write_skill(tmp_path)
    writer = SkillWriter()
    result = writer.apply_update(
        path,
        {"promoted_pattern_rows": ["| New flow | 3 (confirmed 3 sessions) | api_endpoint | weird signal | rails |"]},
    )
    assert result.success
    assert "COMMON_PATTERNS" in result.sections_changed
    assert result.bump.bump_kind == "minor"
    text = path.read_text(encoding="utf-8")
    assert "New flow" in text
    # Existing row preserved
    assert "Webhook fetch" in text
    # Backup file created next to skill
    assert any(p.name.endswith(".bak") for p in tmp_path.iterdir())


def test_apply_new_preconditions_appends_and_minor_bump(tmp_path):
    path = _write_skill(tmp_path)
    writer = SkillWriter()
    result = writer.apply_update(
        path,
        {"new_preconditions": ["- [ ] Brand new precondition derived from session"]},
    )
    assert result.success
    assert "PRECONDITIONS" in result.sections_changed
    assert result.bump.bump_kind == "minor"
    text = path.read_text(encoding="utf-8")
    assert "Brand new precondition" in text
    assert "Endpoint accepts a user-supplied URL parameter" in text  # original kept


def test_apply_new_assumptions_appends(tmp_path):
    path = _write_skill(tmp_path)
    writer = SkillWriter()
    result = writer.apply_update(
        path, {"new_assumptions": ["- [ ] Different new assumption"]}
    )
    assert result.success
    assert "ASSUMPTIONS" in result.sections_changed
    text = path.read_text(encoding="utf-8")
    assert "Different new assumption" in text


def test_apply_replaces_detection_signals_section(tmp_path):
    path = _write_skill(tmp_path)
    writer = SkillWriter()
    new_body = (
        "**Positive signals:**\n"
        "- Brand new positive signal observed in session\n\n"
        "**Negative signals (likely false positive):**\n"
        "- Brand new negative signal\n\n"
        "**Escalation signals:**\n"
        "- Brand new escalation signal\n"
    )
    result = writer.apply_update(path, {"updated_detection_signals": new_body})
    assert result.success
    assert "DETECTION_SIGNALS" in result.sections_changed
    text = path.read_text(encoding="utf-8")
    assert "Brand new positive signal" in text
    # Old positive signal should have been REPLACED, not appended
    assert "Outbound HTTP request originates" not in text


def test_dry_run_does_not_modify_file(tmp_path):
    path = _write_skill(tmp_path)
    before = path.read_text(encoding="utf-8")
    writer = SkillWriter()
    result = writer.apply_update(
        path,
        {"new_preconditions": ["- [ ] dry-run only"]},
        dry_run=True,
    )
    assert result.success
    assert "PRECONDITIONS" in result.sections_changed
    after = path.read_text(encoding="utf-8")
    assert before == after  # untouched
    # No backup either in dry-run
    assert not any(p.name.endswith(".bak") for p in tmp_path.iterdir())


def test_rollback_when_validation_fails(tmp_path):
    """Detection signals replacement that produces an invalid skill must roll back."""
    path = _write_skill(tmp_path)
    before = path.read_text(encoding="utf-8")
    writer = SkillWriter()

    # An update that breaks PRECONDITIONS by replacing detection signals with content
    # that includes a prohibited payload (validator catches it)
    bad_body = "**Positive signals:**\n- Try 169.254.169.254 to fetch IAM creds\n\n**Negative signals (likely false positive):**\n-\n\n**Escalation signals:**\n-\n"

    result = writer.apply_update(path, {"updated_detection_signals": bad_body})
    assert not result.success
    assert any("validation" in e.lower() or "prohibited" in e.lower() for e in result.errors)
    # File untouched
    assert path.read_text(encoding="utf-8") == before


def test_no_changes_in_input_returns_nothing_to_apply(tmp_path):
    path = _write_skill(tmp_path)
    writer = SkillWriter()
    result = writer.apply_update(path, {})
    assert result.success  # not an error
    assert result.sections_changed == []


def test_missing_file_returns_failure(tmp_path):
    writer = SkillWriter()
    result = writer.apply_update(
        tmp_path / "nope.md",
        {"new_preconditions": ["- [ ] x"]},
    )
    assert not result.success
    assert any("not found" in e for e in result.errors)
