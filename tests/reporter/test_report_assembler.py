import pytest

from reporter.models import CVSSResult, Finding
from reporter.pipeline.cvss_calculator import calculate
from reporter.pipeline.report_assembler import (
    CWE_MAP,
    OWASP_MAP,
    REQUIRED_KEYS,
    assemble_chain_report,
    assemble_report,
)


def _finding(**kwargs) -> Finding:
    base = dict(
        finding_id="F001_sess1",
        session_id="sess1",
        vuln_class="ssrf",
        vuln_subtype="cloud-metadata",
        target="api.shopify.com",
        affected_feature="ssrf/cloud-metadata",
        severity="high",
        confirmed=True,
        evidence_description="webhook outbound from server IP",
    )
    base.update(kwargs)
    return Finding(**base)


def _full_task_output(**overrides) -> dict:
    base = {
        "title": "SSRF in webhook delivery enables internal access",
        "summary": "Authenticated SSRF reaches AWS metadata; IAM creds exposed.",
        "vulnerability_details": "Webhook URL fetcher does not validate host.",
        "impact_analysis": (
            "An authenticated attacker can extract IAM credentials granting access "
            "to S3 buckets containing customer PII. Lateral movement into internal "
            "services is feasible from this position."
        ),
        "steps_to_reproduce": (
            "1. Authenticate as a low-priv user.\n"
            "2. Configure a webhook with a sentinel URL.\n"
            "3. Trigger the webhook and confirm inbound from server IP.\n"
        ),
        "proof_of_concept": "Screenshot showing inbound HTTP from server IP to sentinel.",
        "remediation": (
            "Reject any URL whose resolved host is in a private / link-local range. "
            "Validate the URL after DNS resolution to prevent rebinding. Disable "
            "redirects in the fetcher unless explicitly required."
        ),
    }
    base.update(overrides)
    return base


@pytest.mark.parametrize("platform", ["hackerone", "bugcrowd", "generic"])
def test_assemble_for_each_platform(platform):
    finding = _finding()
    cvss = calculate(finding)
    output = _full_task_output()
    draft = assemble_report(output, finding, cvss, platform=platform)
    assert draft.platform == platform
    assert draft.cvss.base_score > 0
    assert draft.rendered_markdown.startswith("#")
    # All platforms must surface the title, the CVSS vector, and the remediation
    assert output["title"] in draft.rendered_markdown
    assert draft.cvss.vector_string in draft.rendered_markdown
    assert "Reject any URL" in draft.rendered_markdown


def test_generic_template_includes_target_table():
    """The generic template alone surfaces target/feature in a metadata table."""
    finding = _finding()
    cvss = calculate(finding)
    draft = assemble_report(_full_task_output(), finding, cvss, platform="generic")
    assert finding.target in draft.rendered_markdown
    assert finding.affected_feature in draft.rendered_markdown
    assert finding.finding_id in draft.rendered_markdown


def test_references_use_cwe_and_owasp_maps():
    finding = _finding(vuln_class="ssrf")
    cvss = calculate(finding)
    draft = assemble_report(_full_task_output(), finding, cvss, platform="hackerone")
    assert draft.references["cwe"] == CWE_MAP["ssrf"]
    assert draft.references["owasp"] == OWASP_MAP["ssrf"]
    assert CWE_MAP["ssrf"] in draft.rendered_markdown
    assert OWASP_MAP["ssrf"] in draft.rendered_markdown


def test_missing_required_section_raises():
    finding = _finding()
    cvss = calculate(finding)
    output = _full_task_output(remediation="")
    with pytest.raises(ValueError) as exc:
        assemble_report(output, finding, cvss, platform="hackerone")
    assert "remediation" in str(exc.value)


def test_required_keys_constant():
    expected = {
        "title", "summary", "vulnerability_details", "impact_analysis",
        "steps_to_reproduce", "proof_of_concept", "remediation",
    }
    assert set(REQUIRED_KEYS) == expected


def test_human_review_notes_default_present():
    draft = assemble_report(_full_task_output(), _finding(), calculate(_finding()), platform="hackerone")
    assert draft.requires_human_review
    assert any("Steps to Reproduce" in note for note in draft.requires_human_review)
    assert any("CVSS" in note for note in draft.requires_human_review)


def test_chain_report_template_renders():
    chain_finding = _finding(
        finding_id="F001_chain_sess1",
        is_chain=True,
        chain_id="c1",
        chain_name="SSRF → JWT bypass",
        notes="auth/jwt-bypass",
    )
    cvss = calculate(chain_finding)
    component = _finding(finding_id="F002_sess1", evidence_description="component")
    draft = assemble_chain_report(
        _full_task_output(),
        chain_finding=chain_finding,
        component_findings=[component],
        cvss=cvss,
        escalation=None,
    )
    assert draft.platform == "chain"
    assert "Chain Vulnerability Report" in draft.rendered_markdown
    assert chain_finding.target in draft.rendered_markdown
