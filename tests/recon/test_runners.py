import json
from unittest.mock import patch

import pytest

from recon.models import HttpService, NucleiFinding
from recon.runners import (
    AssetfinderRunner,
    GauRunner,
    HttpxRunner,
    NucleiRunner,
    SubfinderRunner,
    WaybackurlsRunner,
)


# ---------- subdomain enumeration ----------


def test_subfinder_skipped_when_binary_missing():
    with patch("recon.runners._which", return_value=None):
        out = SubfinderRunner().run("example.com")
    assert out.skipped is True
    assert out.ok is False
    assert out.error == "not installed"


def test_subfinder_parses_stdout():
    fake_stdout = "api.example.com\nadmin.example.com\nstaging.example.com\n"
    with (
        patch("recon.runners._which", return_value="/fake/bin/subfinder"),
        patch("recon.runners._run_capture", return_value=(0, fake_stdout, "")),
    ):
        out = SubfinderRunner().run("example.com")
    assert out.ok is True
    assert out.items == ["api.example.com", "admin.example.com", "staging.example.com"]


def test_subfinder_truncates_to_max():
    """MAX_SUBDOMAINS bound is enforced even if the tool is excited."""
    fake_stdout = "\n".join(f"sub{i}.example.com" for i in range(10000))
    with (
        patch("recon.runners._which", return_value="/fake/bin/subfinder"),
        patch("recon.runners._run_capture", return_value=(0, fake_stdout, "")),
        patch("recon.runners.MAX_SUBDOMAINS", 50),
    ):
        out = SubfinderRunner().run("example.com")
    assert len(out.items) == 50


def test_subfinder_records_error_on_failure():
    with (
        patch("recon.runners._which", return_value="/fake/bin/subfinder"),
        patch("recon.runners._run_capture", return_value=(1, "", "DNS resolution failed")),
    ):
        out = SubfinderRunner().run("example.com")
    assert out.ok is False
    assert "DNS resolution failed" in (out.error or "")


def test_assetfinder_parses_stdout():
    fake_stdout = "a.example.com\nb.example.com\n"
    with (
        patch("recon.runners._which", return_value="/fake/bin/assetfinder"),
        patch("recon.runners._run_capture", return_value=(0, fake_stdout, "")),
    ):
        out = AssetfinderRunner().run("example.com")
    assert out.ok is True
    assert "a.example.com" in out.items


# ---------- httpx ----------


def test_httpx_empty_input_no_subprocess_call():
    """Empty host list should short-circuit before calling the binary."""
    with patch("recon.runners._run_capture") as mock_run:
        out = HttpxRunner().probe([])
    assert out.ok is True
    assert out.items == []
    mock_run.assert_not_called()


def test_httpx_skipped_when_missing():
    with patch("recon.runners._which", return_value=None):
        out = HttpxRunner().probe(["example.com"])
    assert out.skipped is True


def test_httpx_parses_jsonl_output():
    payloads = [
        {
            "url": "https://api.example.com",
            "status_code": 200,
            "title": "API",
            "tech": ["nginx", "rails"],
            "webserver": "nginx",
            "content_length": 1024,
        },
        {
            "url": "https://admin.example.com",
            "status_code": 403,
            "tech": ["cloudflare"],
        },
    ]
    fake_stdout = "\n".join(json.dumps(p) for p in payloads)
    with (
        patch("recon.runners._which", return_value="/fake/bin/httpx"),
        patch("recon.runners._run_capture", return_value=(0, fake_stdout, "")),
    ):
        out = HttpxRunner().probe(["api.example.com", "admin.example.com"])
    assert out.ok is True
    assert len(out.items) == 2
    api: HttpService = out.items[0]
    assert api.status_code == 200
    assert "rails" in api.tech
    assert api.server == "nginx"


def test_httpx_handles_alternative_field_names():
    """httpx releases vary — runner should accept a few key aliases."""
    payload = {"input": "https://example.com", "status-code": 301, "technologies": "nginx,php"}
    with (
        patch("recon.runners._which", return_value="/fake/bin/httpx"),
        patch("recon.runners._run_capture", return_value=(0, json.dumps(payload), "")),
    ):
        out = HttpxRunner().probe(["example.com"])
    assert out.ok is True
    s = out.items[0]
    assert s.url == "https://example.com"
    assert s.status_code == 301
    assert "nginx" in s.tech and "php" in s.tech


def test_httpx_skips_malformed_lines():
    fake_stdout = (
        json.dumps({"url": "https://a", "status_code": 200}) + "\n"
        "not valid json\n"
        + json.dumps({"url": "https://b", "status_code": 200}) + "\n"
    )
    with (
        patch("recon.runners._which", return_value="/fake/bin/httpx"),
        patch("recon.runners._run_capture", return_value=(0, fake_stdout, "")),
    ):
        out = HttpxRunner().probe(["a", "b"])
    assert len(out.items) == 2


# ---------- nuclei ----------


def test_nuclei_skipped_when_missing():
    with patch("recon.runners._which", return_value=None):
        out = NucleiRunner().run(["https://example.com"])
    assert out.skipped is True


def test_nuclei_empty_targets_short_circuits():
    out = NucleiRunner().run([])
    assert out.ok is True
    assert out.items == []


def test_nuclei_parses_jsonl():
    payload = {
        "template-id": "http-tech-detect",
        "info": {"name": "Nginx Detection", "severity": "info", "tags": "tech,nginx"},
        "matched-at": "https://example.com",
    }
    with (
        patch("recon.runners._which", return_value="/fake/bin/nuclei"),
        patch("recon.runners._run_capture", return_value=(0, json.dumps(payload), "")),
    ):
        out = NucleiRunner().run(["https://example.com"])
    assert out.ok is True
    assert len(out.items) == 1
    finding: NucleiFinding = out.items[0]
    assert finding.template_id == "http-tech-detect"
    assert finding.name == "Nginx Detection"
    assert "nginx" in finding.tags


# ---------- gau / waybackurls ----------


def test_gau_skipped_when_missing():
    with patch("recon.runners._which", return_value=None):
        out = GauRunner().run("example.com")
    assert out.skipped is True


def test_gau_caps_url_count():
    fake_stdout = "\n".join(f"https://example.com/path/{i}" for i in range(50000))
    with (
        patch("recon.runners._which", return_value="/fake/bin/gau"),
        patch("recon.runners._run_capture", return_value=(0, fake_stdout, "")),
        patch("recon.runners.MAX_HISTORICAL_URLS", 100),
    ):
        out = GauRunner().run("example.com")
    assert len(out.items) == 100


def test_waybackurls_basic():
    fake_stdout = "https://example.com/a\nhttps://example.com/b\n"
    with (
        patch("recon.runners._which", return_value="/fake/bin/waybackurls"),
        patch("recon.runners._run_capture", return_value=(0, fake_stdout, "")),
    ):
        out = WaybackurlsRunner().run("example.com")
    assert out.ok is True
    assert len(out.items) == 2
