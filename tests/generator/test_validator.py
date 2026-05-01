from pathlib import Path

import pytest

from generator.validator import (
    REQUIRED_SECTIONS,
    validate_skill_file,
    validate_skill_text,
)


_VALID_SKILL = """# SKILL: SSRF — Cloud Metadata
**Category:** ssrf > cloud-metadata
**Severity Range:** high-critical
**Typical Payout:** $1,500-$5,000
**Pattern Count:** 3
**Last Updated:** 2026-05-01
**Version:** 1.0.0

---

## OVERVIEW
Server-side request forgery in features that fetch user-controlled URLs
allows attackers to reach internal services, including cloud metadata
endpoints. Developers commonly miss this because the URL is treated as
data, not as a target whose host must be validated against an allow-list.

---

## PRECONDITIONS
- [ ] Endpoint accepts a user-supplied URL parameter
- [ ] Server fetches the URL during normal operation
- [ ] No DNS resolution validation against private ranges

---

## DETECTION METHODOLOGY

### Phase 1: Surface Discovery
Look for webhook, integration callback, and URL-import endpoints.

### Phase 2: Active Probing (Authorized Scope Only)
Send the endpoint a URL that resolves to a controlled host; observe
whether the request originates server-side via OOB collaborator.

### Phase 3: Confirmation
Confirm the server resolves DNS and follows redirects without host
validation. Negative test: ensure the same flow with an explicitly
blocked host fails.

---

## TESTING WORKFLOW
```
Step 1: Identify URL-accepting endpoints
   →
Step 2: Configure with sentinel host
   →
Step 3: Observe outbound from server IP
   →
Step 4: Try internal target with private IP
```

---

## COMMON PATTERNS FROM REAL REPORTS
| Pattern | Frequency | Feature Type | Behavioral Signal | Stack Hints |
|---------|-----------|--------------|-------------------|-------------|
| Webhook fetch | 2 | webhook | Outbound from server IP | aws |

---

## DETECTION SIGNALS
**Positive signals:**
- Outbound HTTP request originates from application server

**Negative signals (likely false positive):**
- Request originates from client browser

**Escalation signals:**
- Response includes credentials

---

## CHAIN OPPORTUNITIES
| Chain To | Combined Impact | Trigger Condition | Confidence |
|----------|-----------------|-------------------|------------|
| info_disclosure | IAM credential leak | metadata reachable | high |

---

## ASSUMPTIONS TO CHALLENGE
- [ ] The URL is data, not a target
- [ ] Internal hosts are unreachable from outside
- [ ] DNS resolution validation isn't needed

---

## SCOPE CHECKLIST
- [ ] Target confirmed in-scope per program policy
- [ ] Staging/test environment identified if available
- [ ] Rate limiting considered — no DoS risk
- [ ] OOB infrastructure ready if oob_required
- [ ] No production data manipulation planned

---

## NOVEL DISCOVERIES LOG
| Date | Session ID | Discovery | Chain Potential | Incorporated |
|------|------------|-----------|-----------------|--------------|

---

## ATTACK CHAINS DISCOVERED


---

## FAILED APPROACHES
| Approach | Why It Failed | Date | Session |
|----------|---------------|------|---------|

---

## REPORTING TEMPLATE HINTS
- **Impact statement:** Internal services reachable via SSRF.
- **CVSS hint:** AV:N/AC:L/PR:N/UI:N/S:C
- **Remediation:** Add host allow-list and validate resolved DNS.
- **PoC format:** Screenshot of outbound from server IP to sentinel host.
"""


def test_required_sections_constant():
    assert "OVERVIEW" in REQUIRED_SECTIONS
    assert "REPORTING TEMPLATE HINTS" in REQUIRED_SECTIONS
    assert len(REQUIRED_SECTIONS) == 13


def test_valid_skill_passes():
    report = validate_skill_text(_VALID_SKILL)
    assert report.ok is True, report.errors
    assert report.errors == []


def test_missing_section_fails():
    bad = _VALID_SKILL.replace("## REPORTING TEMPLATE HINTS", "## DUMMY")
    report = validate_skill_text(bad)
    assert not report.ok
    assert any("REPORTING TEMPLATE HINTS" in e for e in report.errors)


def test_missing_top_header_fails():
    bad = _VALID_SKILL.replace("# SKILL: SSRF", "# Some Other Header")
    report = validate_skill_text(bad)
    assert not report.ok
    assert any("# SKILL:" in e for e in report.errors)


def test_short_overview_fails():
    bad = _VALID_SKILL.replace(
        "Server-side request forgery in features that fetch user-controlled URLs\n"
        "allows attackers to reach internal services, including cloud metadata\n"
        "endpoints. Developers commonly miss this because the URL is treated as\n"
        "data, not as a target whose host must be validated against an allow-list.",
        "Short.",
    )
    report = validate_skill_text(bad)
    assert not report.ok
    assert any("OVERVIEW" in e for e in report.errors)


def test_too_few_preconditions_fails():
    bad = _VALID_SKILL.replace(
        "- [ ] Endpoint accepts a user-supplied URL parameter\n"
        "- [ ] Server fetches the URL during normal operation\n"
        "- [ ] No DNS resolution validation against private ranges",
        "- [ ] Only one precondition",
    )
    report = validate_skill_text(bad)
    assert not report.ok
    assert any("PRECONDITIONS" in e for e in report.errors)


def test_workflow_without_arrow_fails():
    bad = _VALID_SKILL.replace("→\n", "\n")
    report = validate_skill_text(bad)
    assert not report.ok
    assert any("→" in e or "TESTING WORKFLOW" in e for e in report.errors)


def test_empty_common_patterns_table_fails():
    bad = _VALID_SKILL.replace(
        "| Webhook fetch | 2 | webhook | Outbound from server IP | aws |\n",
        "",
    )
    report = validate_skill_text(bad)
    assert not report.ok
    assert any("COMMON PATTERNS" in e for e in report.errors)


def test_prohibited_payload_blocked():
    bad = _VALID_SKILL + "\n\nPayload: 169.254.169.254 — try fetching this.\n"
    report = validate_skill_text(bad)
    assert not report.ok
    assert any("prohibited" in e.lower() for e in report.errors)


def test_validate_skill_file(tmp_path):
    path = tmp_path / "skill.md"
    path.write_text(_VALID_SKILL, encoding="utf-8")
    report = validate_skill_file(path)
    assert report.ok


def test_validate_skill_file_missing(tmp_path):
    report = validate_skill_file(tmp_path / "nope.md")
    assert not report.ok
