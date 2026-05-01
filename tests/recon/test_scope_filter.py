import json

import pytest

from recon.scope_filter import filter_hosts


def _scope(tmp_path, in_scope, out_of_scope=None):
    data = {
        "program": "shopify",
        "in_scope": [{"asset": p, "type": "URL"} for p in in_scope],
        "out_of_scope": list(out_of_scope or []),
    }
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(data))
    return path


def test_filter_partitions_in_and_out_of_scope(tmp_path):
    scope = _scope(tmp_path, ["*.example.com"], ["help.example.com"])
    hosts = ["api.example.com", "admin.example.com", "help.example.com", "evilcorp.com"]
    result = filter_hosts(hosts, scope_file=scope)
    assert "api.example.com" in result.in_scope
    assert "admin.example.com" in result.in_scope
    assert "help.example.com" in result.out_of_scope
    assert "evilcorp.com" in result.out_of_scope


def test_filter_no_scope_passes_everything_through():
    """Without scope.json, the caller is on their own — everything is 'in scope'."""
    hosts = ["a.com", "b.com"]
    result = filter_hosts(hosts)
    assert result.in_scope == ["a.com", "b.com"]
    assert result.out_of_scope == []


def test_filter_dedups_and_normalizes(tmp_path):
    scope = _scope(tmp_path, ["*.example.com"])
    hosts = ["API.example.com", "api.example.com", " api.example.com ", "API.EXAMPLE.COM"]
    result = filter_hosts(hosts, scope_file=scope)
    assert result.in_scope == ["api.example.com"]


def test_filter_drops_empty_strings(tmp_path):
    scope = _scope(tmp_path, ["*.example.com"])
    result = filter_hosts(["", "  ", "api.example.com"], scope_file=scope)
    assert "api.example.com" in result.in_scope
    assert "" not in result.in_scope
