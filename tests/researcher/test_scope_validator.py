import json

import pytest

from researcher.tools.scope_validator import (
    OutOfScopeError,
    ScopeValidator,
)


def _scope_file(tmp_path, **overrides):
    data = {
        "program": "shopify",
        "platform": "hackerone",
        "in_scope": [
            {"asset": "*.shopify.com", "type": "URL"},
            {"asset": "*.myshopify.com", "type": "URL"},
            {"asset": "10.0.0.0/24", "type": "IP_RANGE"},
        ],
        "out_of_scope": ["help.shopify.com"],
        "rules": ["No automated scanning"],
    }
    data.update(overrides)
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(data))
    return path


def test_subdomain_wildcard_match(tmp_path):
    sv = ScopeValidator.load(_scope_file(tmp_path))
    result = sv.validate_target("api.shopify.com")
    assert result.in_scope
    assert "shopify.com" in result.matched_rule


def test_url_collapses_to_host(tmp_path):
    sv = ScopeValidator.load(_scope_file(tmp_path))
    result = sv.validate_target("https://api.shopify.com/admin")
    assert result.in_scope


def test_explicit_exclusion_wins(tmp_path):
    sv = ScopeValidator.load(_scope_file(tmp_path))
    result = sv.validate_target("help.shopify.com")
    assert not result.in_scope
    assert "out-of-scope" in result.reason.lower()


def test_unrelated_domain_fails(tmp_path):
    sv = ScopeValidator.load(_scope_file(tmp_path))
    result = sv.validate_target("evilcorp.com")
    assert not result.in_scope
    assert "no matching" in result.reason.lower()


def test_assert_in_scope_raises(tmp_path):
    sv = ScopeValidator.load(_scope_file(tmp_path))
    with pytest.raises(OutOfScopeError):
        sv.assert_in_scope("evilcorp.com")


def test_cidr_match(tmp_path):
    sv = ScopeValidator.load(_scope_file(tmp_path))
    assert sv.validate_target("10.0.0.5").in_scope
    assert not sv.validate_target("11.0.0.5").in_scope


def test_empty_target(tmp_path):
    sv = ScopeValidator.load(_scope_file(tmp_path))
    result = sv.validate_target("")
    assert not result.in_scope


def test_subdomain_wildcard_does_not_match_apex_only(tmp_path):
    """`*.shopify.com` should match subdomains, not the bare apex."""
    sv = ScopeValidator.load(_scope_file(tmp_path))
    # api.shopify.com matches; bare "shopify.com" should NOT (no leading subdomain)
    assert sv.validate_target("api.shopify.com").in_scope
    assert not sv.validate_target("shopify.com").in_scope


def test_string_in_scope_entries_accepted(tmp_path):
    """Old shorthand: in_scope as plain strings."""
    path = _scope_file(tmp_path, in_scope=["*.example.com"])
    sv = ScopeValidator.load(path)
    assert sv.validate_target("foo.example.com").in_scope


def test_missing_scope_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        ScopeValidator.load(tmp_path / "no.json")


def test_invalid_json_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not valid")
    with pytest.raises(ValueError):
        ScopeValidator.load(path)
