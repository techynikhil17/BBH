import pytest

from extractor.models import (
    ChainPotential,
    ExtractedPattern,
    Severity,
    extracted_pattern_json_schema,
)


def _valid_payload(**overrides):
    base = {
        "source_url": "https://hackerone.com/reports/1",
        "source_platform": "hackerone",
        "vuln_class": "ssrf",
        "vuln_subtype": "cloud-metadata",
        "cwe_id": "CWE-918",
        "affected_feature_type": "webhook",
        "affected_stack_hints": ["aws"],
        "behavioral_signal": "Server-side request observed against internal address.",
        "detection_approach": "Identify endpoints accepting URLs as input and check whether outbound requests originate server-side without host validation.",
        "oob_required": False,
        "preconditions": ["User-controlled URL", "No host allow-list"],
        "root_cause_pattern": "Missing host allow-list on user-supplied URLs",
        "chain_potential": "high",
        "chain_targets": ["info_disclosure"],
        "chain_reasoning": "Metadata endpoint may yield IAM credentials.",
        "severity": "high",
        "payout_usd": 2500,
        "is_novel": False,
        "novel_description": None,
        "extraction_confidence": 0.85,
        "skipped": False,
        "skip_reason": None,
    }
    base.update(overrides)
    return base


def test_minimal_valid():
    p = ExtractedPattern(**_valid_payload())
    assert p.severity == Severity.HIGH
    assert p.chain_potential == ChainPotential.HIGH


def test_cwe_format_normalization():
    p = ExtractedPattern(**_valid_payload(cwe_id="918"))
    assert p.cwe_id == "CWE-918"
    p2 = ExtractedPattern(**_valid_payload(cwe_id="cwe-918"))
    assert p2.cwe_id == "CWE-918"


def test_confidence_bounds():
    with pytest.raises(Exception):
        ExtractedPattern(**_valid_payload(extraction_confidence=1.5))
    with pytest.raises(Exception):
        ExtractedPattern(**_valid_payload(extraction_confidence=-0.1))


def test_payout_non_negative():
    with pytest.raises(Exception):
        ExtractedPattern(**_valid_payload(payout_usd=-1))


def test_skipped_pattern():
    p = ExtractedPattern(**_valid_payload(skipped=True, skip_reason="Title only, no detail"))
    assert p.skipped
    assert p.skip_reason == "Title only, no detail"


def test_json_schema_is_buildable():
    schema = extracted_pattern_json_schema()
    assert schema["additionalProperties"] is False
    # Must be flat — no $defs after inlining
    assert "$defs" not in schema
    # Required fields present
    assert "source_url" in schema["properties"]
    assert "vuln_class" in schema["properties"]
    # Severity enum is inlined (was a $ref)
    severity = schema["properties"]["severity"]
    assert "enum" in severity
    assert "critical" in severity["enum"]


def test_round_trip_json():
    p = ExtractedPattern(**_valid_payload())
    raw = p.model_dump_json()
    p2 = ExtractedPattern.model_validate_json(raw)
    assert p == p2
