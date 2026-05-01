import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from recon.assembler import ReconAssembler
from recon.models import HttpService, NucleiFinding
from recon.runners import RunnerOutput


def _scope_file(tmp_path, in_scope, out_of_scope=None) -> Path:
    data = {
        "program": "demo",
        "in_scope": [{"asset": p, "type": "URL"} for p in in_scope],
        "out_of_scope": list(out_of_scope or []),
    }
    path = tmp_path / "scope.json"
    path.write_text(json.dumps(data))
    return path


def _mock_runner(name, *, items, ok=True, skipped=False, error=None):
    runner = MagicMock()
    runner.binary = name
    runner.is_available.return_value = not skipped
    runner.run.return_value = RunnerOutput(
        tool=name, ok=ok, items=list(items), skipped=skipped, error=error,
    )
    runner.probe = runner.run  # httpx uses probe()
    return runner


def test_runs_all_runners_and_merges(tmp_path):
    """Happy path: every runner returns data, scope filters cleanly, result is assembled."""
    sub = _mock_runner("subfinder", items=["api.example.com", "admin.example.com"])
    asset = _mock_runner("assetfinder", items=["staging.example.com", "api.example.com"])
    httpx = _mock_runner(
        "httpx",
        items=[
            HttpService(url="https://api.example.com", status_code=200, tech=["rails", "nginx"], server="nginx"),
            HttpService(url="https://staging.example.com", status_code=200, tech=["rails"]),
        ],
    )
    nuclei = _mock_runner(
        "nuclei",
        items=[NucleiFinding(template_id="http-detect", name="Rails", severity="info")],
    )
    gau = _mock_runner("gau", items=["https://api.example.com/v1/users"])
    wayback = _mock_runner("waybackurls", items=["https://api.example.com/old"])

    asm = ReconAssembler(
        subfinder=sub, assetfinder=asset, httpx=httpx,
        nuclei=nuclei, gau=gau, waybackurls=wayback,
    )

    scope = _scope_file(tmp_path, ["*.example.com"])
    result = asm.run("example.com", scope_file=scope, scope_program="demo")

    assert "api.example.com" in result.in_scope_subdomains
    assert len(result.live_services) == 2
    assert "rails" in result.tech_stack
    assert "nginx" in result.tech_stack
    assert len(result.nuclei_findings) == 1
    assert "https://api.example.com/v1/users" in result.historical_urls
    assert "subfinder" in result.tools_run
    assert "httpx" in result.tools_run
    assert result.errors == []


def test_target_always_appears_in_subdomains():
    """Even when subdomain enumeration is skipped, the bare target stays in the list."""
    sub = _mock_runner("subfinder", items=[], skipped=True, error="not installed")
    asset = _mock_runner("assetfinder", items=[], skipped=True, error="not installed")
    httpx = _mock_runner("httpx", items=[])
    asm = ReconAssembler(
        subfinder=sub, assetfinder=asset, httpx=httpx,
        nuclei=_mock_runner("nuclei", items=[], skipped=True),
        gau=_mock_runner("gau", items=[], skipped=True),
        waybackurls=_mock_runner("waybackurls", items=[], skipped=True),
    )
    result = asm.run("example.com", with_nuclei=False, with_history=False)
    assert "example.com" in result.subdomains
    assert "subfinder" in result.tools_skipped
    assert "assetfinder" in result.tools_skipped


def test_skipped_tool_does_not_kill_pipeline():
    sub = _mock_runner("subfinder", items=["api.example.com"])
    asset = _mock_runner("assetfinder", items=[], skipped=True, error="not installed")
    httpx = _mock_runner("httpx", items=[HttpService(url="https://api.example.com", status_code=200)])
    asm = ReconAssembler(
        subfinder=sub, assetfinder=asset, httpx=httpx,
        nuclei=_mock_runner("nuclei", items=[]),
        gau=_mock_runner("gau", items=[]),
        waybackurls=_mock_runner("waybackurls", items=[]),
    )
    result = asm.run("example.com")
    assert "subfinder" in result.tools_run
    assert "assetfinder" in result.tools_skipped
    assert len(result.live_services) == 1


def test_failing_tool_records_error_but_continues():
    sub = _mock_runner("subfinder", items=[], ok=False, error="boom")
    asset = _mock_runner("assetfinder", items=["a.example.com"])
    httpx = _mock_runner("httpx", items=[])
    asm = ReconAssembler(
        subfinder=sub, assetfinder=asset, httpx=httpx,
        nuclei=_mock_runner("nuclei", items=[]),
        gau=_mock_runner("gau", items=[]),
        waybackurls=_mock_runner("waybackurls", items=[]),
    )
    result = asm.run("example.com")
    assert any("subfinder" in e for e in result.errors)
    # Asset still ran and contributed
    assert "a.example.com" in result.subdomains


def test_out_of_scope_subdomains_are_not_probed(tmp_path):
    """Hosts filtered as out-of-scope must never reach the httpx call."""
    sub = _mock_runner("subfinder", items=["api.example.com", "evilcorp.com"])
    asset = _mock_runner("assetfinder", items=[])
    httpx = _mock_runner("httpx", items=[])
    asm = ReconAssembler(
        subfinder=sub, assetfinder=asset, httpx=httpx,
        nuclei=_mock_runner("nuclei", items=[]),
        gau=_mock_runner("gau", items=[]),
        waybackurls=_mock_runner("waybackurls", items=[]),
    )

    scope = _scope_file(tmp_path, ["*.example.com"])
    result = asm.run("example.com", scope_file=scope)

    # httpx should have been called with in-scope hosts only
    args, kwargs = httpx.run.call_args
    probed = list(args[0]) if args else list(kwargs.get("hosts", []))
    assert "evilcorp.com" not in probed
    assert "api.example.com" in probed
    assert "evilcorp.com" in result.out_of_scope_subdomains


def test_with_nuclei_false_skips_scan():
    sub = _mock_runner("subfinder", items=["a.example.com"])
    asset = _mock_runner("assetfinder", items=[])
    httpx = _mock_runner("httpx", items=[HttpService(url="https://a.example.com", status_code=200)])
    nuclei = _mock_runner("nuclei", items=[NucleiFinding(template_id="x")])
    asm = ReconAssembler(
        subfinder=sub, assetfinder=asset, httpx=httpx,
        nuclei=nuclei,
        gau=_mock_runner("gau", items=[]),
        waybackurls=_mock_runner("waybackurls", items=[]),
    )
    result = asm.run("example.com", with_nuclei=False, with_history=False)
    assert nuclei.run.call_count == 0
    assert result.nuclei_findings == []


def test_invalid_scope_file_records_error(tmp_path):
    sub = _mock_runner("subfinder", items=["a.example.com"])
    asset = _mock_runner("assetfinder", items=[])
    httpx = _mock_runner("httpx", items=[])
    asm = ReconAssembler(
        subfinder=sub, assetfinder=asset, httpx=httpx,
        nuclei=_mock_runner("nuclei", items=[]),
        gau=_mock_runner("gau", items=[]),
        waybackurls=_mock_runner("waybackurls", items=[]),
    )
    bad_scope = tmp_path / "nope.json"
    result = asm.run("example.com", scope_file=bad_scope)
    assert any("scope" in e for e in result.errors)


def test_to_brief_dict_shape():
    """The shape must be a flat dict the researcher's brief renderer can consume."""
    sub = _mock_runner("subfinder", items=["api.example.com"])
    asset = _mock_runner("assetfinder", items=[])
    httpx = _mock_runner(
        "httpx",
        items=[HttpService(url="https://api.example.com", status_code=200, tech=["rails"])],
    )
    asm = ReconAssembler(
        subfinder=sub, assetfinder=asset, httpx=httpx,
        nuclei=_mock_runner("nuclei", items=[]),
        gau=_mock_runner("gau", items=[]),
        waybackurls=_mock_runner("waybackurls", items=[]),
    )
    result = asm.run("example.com", with_nuclei=False, with_history=False)
    brief = result.to_brief_dict()
    assert "target" in brief
    assert "stack" in brief
    assert "rails" in brief["stack"]
    assert "interesting_endpoints" in brief
    # All values must be JSON-serializable
    json.dumps(brief)
