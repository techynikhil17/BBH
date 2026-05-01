from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

from collector.sources.hackerone import HackerOneCollector, _parse_edges
from collector.dedup import url_hash

SAMPLE_EDGES = [
    {
        "node": {
            "id": "1234567",
            "title": "SSRF via webhook callback",
            "severity_rating": "high",
            "total_awarded_amount": "2500",
            "currency": "USD",
            "disclosed_at": "2024-11-01T00:00:00Z",
            "report": {"id": "1234567", "url": "https://hackerone.com/reports/1234567"},
            "team": {"name": "Acme Corp"},
            "weakness": {"name": "Server-Side Request Forgery (SSRF)"},
        },
        "cursor": "abc123",
    },
    {
        "node": {
            "id": "9999999",
            "title": "XSS in search results",
            "severity_rating": "medium",
            "total_awarded_amount": None,
            "currency": "USD",
            "disclosed_at": "2024-10-15T00:00:00Z",
            "report": {"id": "9999999", "url": "https://hackerone.com/reports/9999999"},
            "team": {"name": "Beta Inc"},
            "weakness": {"name": "Cross-Site Scripting (XSS)"},
        },
        "cursor": "def456",
    },
]

SAMPLE_GQL_RESPONSE = {
    "data": {
        "hacktivity_items": {
            "edges": SAMPLE_EDGES,
            "pageInfo": {"hasNextPage": False, "endCursor": "def456"},
        }
    }
}


def test_parse_edges_extracts_fields():
    reports = list(_parse_edges(SAMPLE_EDGES))
    assert len(reports) == 2

    r = reports[0]
    assert r.source == "hackerone"
    assert r.title == "SSRF via webhook callback"
    assert r.url == "https://hackerone.com/reports/1234567"
    assert r.severity == "high"
    assert r.program == "Acme Corp"
    assert r.bounty_usd == 2500.0
    assert "server-side request forgery (ssrf)" in r.vuln_type_tags
    assert r.content_hash == url_hash("https://hackerone.com/reports/1234567")


def test_parse_edges_null_bounty():
    reports = list(_parse_edges(SAMPLE_EDGES))
    assert reports[1].bounty_usd is None


def test_parse_edges_non_usd_bounty():
    edges = [
        {
            "node": {
                "id": "111",
                "title": "RCE",
                "severity_rating": "critical",
                "total_awarded_amount": "5000",
                "currency": "EUR",
                "disclosed_at": "2024-01-01T00:00:00Z",
                "report": {"url": "https://hackerone.com/reports/111"},
                "team": {"name": "EuroApp"},
                "weakness": None,
            }
        }
    ]
    reports = list(_parse_edges(edges))
    assert reports[0].bounty_usd is None
    assert reports[0].source_metadata["bounty_currency"] == "EUR"
    assert reports[0].source_metadata["bounty_original"] == 5000.0


def test_parse_edges_builds_url_from_id_when_no_report():
    edges = [
        {
            "node": {
                "id": "777",
                "title": "Bug",
                "severity_rating": "low",
                "total_awarded_amount": None,
                "currency": "USD",
                "disclosed_at": "2024-01-01T00:00:00Z",
                "report": None,
                "team": {"name": "Corp"},
                "weakness": None,
            }
        }
    ]
    reports = list(_parse_edges(edges))
    assert reports[0].url == "https://hackerone.com/reports/777"
