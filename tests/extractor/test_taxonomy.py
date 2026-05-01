from extractor.taxonomy import (
    FEATURE_TYPES,
    VULN_CLASSES,
    is_known_feature_type,
    is_known_vuln_class,
    normalize_feature_type,
    normalize_vuln_class,
    taxonomy_summary,
)


def test_canonical_classes_present():
    for c in ("ssrf", "rce", "idor", "sqli", "xss"):
        assert c in VULN_CLASSES
        assert is_known_vuln_class(c)


def test_canonical_feature_types_present():
    for f in ("webhook", "pdf_export", "file_upload", "api_endpoint"):
        assert f in FEATURE_TYPES
        assert is_known_feature_type(f)


def test_alias_normalization_vuln():
    assert normalize_vuln_class("Server-Side Request Forgery") == "ssrf"
    assert normalize_vuln_class("server-side request forgery") == "ssrf"
    assert normalize_vuln_class("REMOTE CODE EXECUTION") == "rce"
    assert normalize_vuln_class("Insecure Direct Object Reference") == "idor"
    assert normalize_vuln_class("BOLA") == "idor"
    assert normalize_vuln_class("SQL Injection") == "sqli"
    assert normalize_vuln_class("Cross-Site Scripting") == "xss"


def test_alias_normalization_feature():
    assert normalize_feature_type("Webhook Handler") == "webhook"
    assert normalize_feature_type("PDF Generator") == "pdf_export"
    assert normalize_feature_type("Avatar Upload") == "file_upload"
    assert normalize_feature_type("OAuth Callback") == "oauth_flow"


def test_unknown_passthrough():
    # Unknown values pass through lower-cased — caller flags as novel
    assert normalize_vuln_class("totally_made_up") == "totally_made_up"
    assert not is_known_vuln_class("totally_made_up")


def test_empty_input():
    assert normalize_vuln_class("") == ""
    assert normalize_vuln_class(None) == ""
    assert normalize_feature_type("") == ""
    assert normalize_feature_type(None) == ""


def test_taxonomy_summary_is_deterministic():
    """Critical for prompt caching — every byte must be stable across calls."""
    a = taxonomy_summary()
    b = taxonomy_summary()
    assert a == b
    assert "VULNERABILITY CLASSES" in a
    assert "FEATURE TYPES" in a
    # Confirm sorted order is preserved
    vuln_block = a.split("FEATURE TYPES")[0]
    vuln_lines = [line.lstrip("- ").strip() for line in vuln_block.splitlines() if line.startswith("- ")]
    assert vuln_lines == sorted(vuln_lines)
