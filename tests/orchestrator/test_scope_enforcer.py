import json

import pytest

from orchestrator.scope_enforcer import ScopeEnforcer
from researcher.tools.scope_validator import OutOfScopeError


def _scope_json(in_scope, out_of_scope=None, rules=None, program="shopify"):
    return {
        "program": program,
        "platform": "hackerone",
        "in_scope": [{"asset": p, "type": "URL"} for p in in_scope],
        "out_of_scope": list(out_of_scope or []),
        "rules": list(rules or []),
    }


def _write_scope(tmp_path, **kwargs):
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(_scope_json(**kwargs)))
    return path


def test_unloaded_returns_not_loaded(tmp_path):
    enforcer = ScopeEnforcer(active_scope_path=tmp_path / "active.json")
    assert enforcer.is_loaded() is False
    assert enforcer.scope is None


def test_load_persists_active_scope_to_disk(tmp_path):
    scope_file = _write_scope(tmp_path, in_scope=["*.example.com"])
    active = tmp_path / "active.json"
    enforcer = ScopeEnforcer(active_scope_path=active)
    enforcer.load("example", scope_file)
    assert enforcer.is_loaded()
    assert active.exists()


def test_validate_target_wildcard_match(tmp_path):
    scope_file = _write_scope(tmp_path, in_scope=["*.shopify.com"])
    enforcer = ScopeEnforcer(active_scope_path=tmp_path / "active.json")
    enforcer.load("shopify", scope_file)
    result = enforcer.validate_target("api.shopify.com")
    assert result.in_scope


def test_validate_target_explicit_exclusion(tmp_path):
    scope_file = _write_scope(
        tmp_path, in_scope=["*.shopify.com"], out_of_scope=["help.shopify.com"]
    )
    enforcer = ScopeEnforcer(active_scope_path=tmp_path / "active.json")
    enforcer.load("shopify", scope_file)
    result = enforcer.validate_target("help.shopify.com")
    assert not result.in_scope
    assert "out-of-scope" in result.reason.lower()


def test_validate_target_unrelated_domain(tmp_path):
    scope_file = _write_scope(tmp_path, in_scope=["*.shopify.com"])
    enforcer = ScopeEnforcer(active_scope_path=tmp_path / "active.json")
    enforcer.load("shopify", scope_file)
    result = enforcer.validate_target("evilcorp.com")
    assert not result.in_scope


def test_assert_in_scope_raises_on_miss(tmp_path):
    scope_file = _write_scope(tmp_path, in_scope=["*.shopify.com"])
    enforcer = ScopeEnforcer(active_scope_path=tmp_path / "active.json")
    enforcer.load("shopify", scope_file)
    with pytest.raises(OutOfScopeError):
        enforcer.assert_in_scope("evilcorp.com")


def test_unloaded_scope_blocks_validate(tmp_path):
    enforcer = ScopeEnforcer(active_scope_path=tmp_path / "active.json")
    result = enforcer.validate_target("anything.com")
    assert not result.in_scope
    assert "no active scope" in result.reason.lower()


def test_action_dos_test_always_blocked(tmp_path):
    scope_file = _write_scope(tmp_path, in_scope=["*.shopify.com"])
    enforcer = ScopeEnforcer(active_scope_path=tmp_path / "active.json")
    enforcer.load("shopify", scope_file)
    result = enforcer.validate_action("dos_test")
    assert not result.allowed
    assert "permanently" in result.reason.lower()


def test_action_production_data_access_always_blocked(tmp_path):
    scope_file = _write_scope(tmp_path, in_scope=["*.shopify.com"])
    enforcer = ScopeEnforcer(active_scope_path=tmp_path / "active.json")
    enforcer.load("shopify", scope_file)
    assert enforcer.validate_action("production_data_access").allowed is False


def test_action_automated_scan_blocked_by_program_rule(tmp_path):
    scope_file = _write_scope(
        tmp_path,
        in_scope=["*.shopify.com"],
        rules=["No automated scanning permitted"],
    )
    enforcer = ScopeEnforcer(active_scope_path=tmp_path / "active.json")
    enforcer.load("shopify", scope_file)
    result = enforcer.validate_action("automated_scan")
    assert not result.allowed
    assert "automated" in result.reason.lower()


def test_action_automated_scan_allowed_when_no_rule(tmp_path):
    scope_file = _write_scope(tmp_path, in_scope=["*.shopify.com"], rules=["Be respectful"])
    enforcer = ScopeEnforcer(active_scope_path=tmp_path / "active.json")
    enforcer.load("shopify", scope_file)
    assert enforcer.validate_action("automated_scan").allowed is True


def test_action_blocked_when_no_scope_loaded(tmp_path):
    enforcer = ScopeEnforcer(active_scope_path=tmp_path / "active.json")
    result = enforcer.validate_action("automated_scan")
    assert not result.allowed
    assert "load-scope" in result.reason.lower()


def test_unload_removes_active_scope(tmp_path):
    scope_file = _write_scope(tmp_path, in_scope=["*.shopify.com"])
    active = tmp_path / "active.json"
    enforcer = ScopeEnforcer(active_scope_path=active)
    enforcer.load("shopify", scope_file)
    assert active.exists()
    enforcer.unload()
    assert not active.exists()
    assert not enforcer.is_loaded()


def test_auto_loads_existing_active_scope(tmp_path):
    """A new instance should pick up an already-persisted active scope."""
    scope_file = _write_scope(tmp_path, in_scope=["*.shopify.com"])
    active = tmp_path / "active.json"
    first = ScopeEnforcer(active_scope_path=active)
    first.load("shopify", scope_file)
    # Build a fresh enforcer pointing at the same file
    second = ScopeEnforcer(active_scope_path=active)
    assert second.is_loaded()
    assert second.validate_target("api.shopify.com").in_scope
