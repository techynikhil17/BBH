from datetime import datetime

import pytest

from reporter.models import CVSSResult, ReportDraft
from reporter.validator import validate


_VALID_TITLE = "SSRF in Webhook Delivery Allows Internal Service Access"

_VALID_IMPACT = (
    "An authenticated attacker can force the application server to fetch arbitrary "
    "internal URLs. They can read AWS instance metadata to extract IAM role "
    "credentials granting access to S3 buckets containing customer PII."
)

_VALID_REMEDIATION = (
    "Add a host allow-list to the webhook URL fetcher and reject any URL whose "
    "resolved host is in a private or link-local IP range. Validate the URL after "
    "DNS resolution rather than at submission to prevent DNS rebinding. Disable "
    "redirects unless explicitly required, and if so re-validate the redirect target."
)

_VALID_STEPS = (
    "1. Authenticate to the application as a low-privilege user.\n"
    "2. Configure a webhook with a URL pointing at a sentinel host you control.\n"
    "3. Trigger the webhook and observe an inbound request from the application's server IP.\n"
    "4. Replace the URL with one resolving to 169.254.169.254 and re-trigger.\n"  # this WILL trip the prohibited regex; that's the point of the negative test below
)

_CLEAN_STEPS = (
    "1. Authenticate to the application as a low-privilege user.\n"
    "2. Configure a webhook with a URL pointing at a sentinel host you control.\n"
    "3. Trigger the webhook and observe an inbound request from the application's server IP.\n"
    "4. Document the source IP of the inbound request.\n"
)


def _draft(**overrides) -> ReportDraft:
    base = dict(
        finding_id="F001",
        session_id="s1",
        platform="hackerone",
        title=_VALID_TITLE,
        summary="SSRF allows internal access via webhook delivery.",
        vulnerability_details="Body.",
        impact_analysis=_VALID_IMPACT,
        steps_to_reproduce=_CLEAN_STEPS,
        proof_of_concept="Screenshot of inbound request from server IP.",
        cvss=CVSSResult(
            vector_string="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N",
            base_score=8.5,
            severity_label="High",
        ),
        remediation=_VALID_REMEDIATION,
        rendered_markdown="",
        word_count=100,
        generated_at=datetime.now(),
    )
    base.update(overrides)
    return ReportDraft(**base)


def test_valid_draft_passes():
    result = validate(_draft())
    assert result.passed, result.flags


def test_prohibited_title_words_flagged():
    for word in ("zero-day", "0day", "hack", "hacked", "exploit", "critical bug", "pwn"):
        d = _draft(title=f"Found a {word} in webhook delivery")
        result = validate(d)
        assert any(word in f.lower() or word.replace("-", "") in f.lower() for f in result.flags), (
            f"expected a flag for {word!r}, got {result.flags}"
        )


def test_title_length():
    long_title = "x" * 100
    result = validate(_draft(title=long_title))
    assert any("80" in f for f in result.flags)


def test_empty_title():
    result = validate(_draft(title=""))
    assert any("empty" in f for f in result.flags)


def test_too_few_steps():
    short = "1. Auth.\n2. Try once.\n"
    result = validate(_draft(steps_to_reproduce=short))
    assert any("steps_to_reproduce" in f for f in result.flags)


def test_vague_impact_phrase_flagged():
    d = _draft(impact_analysis="Data may be exposed to attackers under some circumstances.")
    result = validate(d)
    assert any("may be exposed" in f.lower() for f in result.flags)


def test_short_remediation_flagged():
    d = _draft(remediation="Validate input.")
    result = validate(d)
    assert any("remediation is too short" in f.lower() for f in result.flags)


def test_generic_remediation_flagged():
    d = _draft(remediation="Validate input. " + "Generic boilerplate. " * 6)
    result = validate(d)
    assert any("validate input" in f.lower() for f in result.flags)


def test_prohibited_payload_in_steps_flagged():
    """The literal AWS metadata IP in steps_to_reproduce trips the regex."""
    d = _draft(steps_to_reproduce=_VALID_STEPS)  # contains 169.254.169.254
    result = validate(d)
    assert any("prohibited content" in f.lower() for f in result.flags)


def test_short_impact_flagged():
    d = _draft(impact_analysis="Bad.")
    result = validate(d)
    assert any("impact_analysis" in f and "short" in f.lower() for f in result.flags)
