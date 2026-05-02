"""Tests for the HackerOne collector against the post-2026-05 schema.

The new ``HacktivitySearchQuery`` returns a list of ``HacktivityDocument``
nodes (not edges). ``_parse_edges`` retains its name for backward
compatibility but now operates on the flat node list.
"""

from collector.dedup import url_hash
from collector.sources.hackerone import HackerOneCollector, _parse_edges

# Real-world shape from a captured HacktivitySearchQuery response.
SAMPLE_NODES = [
    {
        "__typename": "HacktivityDocument",
        "_id": "1234567",
        "id": "Z2lkOi8vMTIzNDU2Nw==",
        "cwe": "Server-Side Request Forgery (SSRF)",
        "severity_rating": "high",
        "total_awarded_amount": 2500,
        "report": {
            "id": "Z2lkOi8vUmVwb3J0LzEyMzQ1Njc=",
            "databaseId": "1234567",
            "title": "SSRF via webhook callback",
            "url": "https://hackerone.com/reports/1234567",
            "disclosed_at": "2026-04-15T00:00:00Z",
            "report_generated_content": {
                "hacktivity_summary": (
                    "An SSRF vulnerability was identified in the webhook callback "
                    "endpoint. The application fetched user-supplied URLs server-side "
                    "without validating the resolved host."
                ),
            },
        },
        "team": {"name": "Acme Corp", "currency": "usd"},
    },
    {
        "__typename": "HacktivityDocument",
        "_id": "9999999",
        "id": "Z2lkOi8vOTk5OTk5OQ==",
        "cwe": "Cross-Site Scripting (XSS)",
        "severity_rating": "medium",
        "total_awarded_amount": None,
        "report": {
            "id": "Z2lkOi8vUmVwb3J0Lzk5OTk5OTk=",
            "databaseId": "9999999",
            "title": "XSS in search results",
            "url": "https://hackerone.com/reports/9999999",
            "disclosed_at": "2026-04-10T00:00:00Z",
            "report_generated_content": None,
        },
        "team": {"name": "Beta Inc", "currency": "usd"},
    },
]


def test_parse_edges_extracts_fields():
    reports = list(_parse_edges(SAMPLE_NODES))
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
    # The hacktivity_summary should populate raw_content_preview
    assert r.raw_content_preview is not None
    assert "SSRF vulnerability" in r.raw_content_preview


def test_parse_edges_null_bounty():
    reports = list(_parse_edges(SAMPLE_NODES))
    assert reports[1].bounty_usd is None


def test_parse_edges_non_usd_bounty():
    """Non-USD currencies should be tracked separately and bounty_usd nulled."""
    nodes = [
        {
            "__typename": "HacktivityDocument",
            "_id": "111",
            "cwe": None,
            "severity_rating": "critical",
            "total_awarded_amount": 5000,
            "report": {
                "databaseId": "111",
                "title": "RCE",
                "url": "https://hackerone.com/reports/111",
                "disclosed_at": "2026-04-01T00:00:00Z",
            },
            "team": {"name": "EuroApp", "currency": "eur"},
        }
    ]
    reports = list(_parse_edges(nodes))
    assert reports[0].bounty_usd is None
    assert reports[0].source_metadata["bounty_currency"] == "EUR"
    assert reports[0].source_metadata["bounty_original"] == 5000.0


def test_parse_edges_builds_url_from_id_when_url_missing():
    """When report.url is missing but the node has _id, we synthesize the URL."""
    nodes = [
        {
            "__typename": "HacktivityDocument",
            "_id": "777",
            "id": "Z2lkOi8vNzc3",
            "cwe": None,
            "severity_rating": "low",
            "total_awarded_amount": None,
            # report is present (so we get a title) but url is missing
            "report": {"databaseId": "777", "title": "Sample title"},
            "team": {"name": "Corp"},
        }
    ]
    reports = list(_parse_edges(nodes))
    assert len(reports) == 1
    assert reports[0].url == "https://hackerone.com/reports/777"


def test_parse_edges_handles_legacy_weakness_field():
    """Backward-compat: nodes shaped with legacy ``weakness.name`` still parse."""
    nodes = [
        {
            "_id": "1",
            "report": {
                "url": "https://hackerone.com/reports/1",
                "title": "T",
                "disclosed_at": "2026-01-01T00:00:00Z",
            },
            "team": {"name": "X"},
            "weakness": {"name": "SQL Injection"},
            "severity_rating": "high",
        }
    ]
    reports = list(_parse_edges(nodes))
    assert "sql injection" in reports[0].vuln_type_tags


def test_parse_edges_skips_empty_and_titleless_nodes():
    """Empty nodes AND nodes with no report.title (bounty announcements
    for content-private reports) should be silently skipped — they have
    nothing for the extractor to learn from.
    """
    nodes = [
        {},
        None,
        {"_id": "x"},  # no title → skip
        {"_id": "y", "report": {"url": "https://hackerone.com/reports/y"}},  # no title → skip
    ]
    reports = list(_parse_edges(nodes))
    assert reports == []


def test_parse_edges_keeps_titled_nodes():
    """A node with a real report.title should still produce a RawReport."""
    nodes = [
        {
            "_id": "1",
            "severity_rating": "high",
            "report": {
                "url": "https://hackerone.com/reports/1",
                "title": "Real vulnerability disclosure",
                "disclosed_at": "2026-01-01T00:00:00Z",
            },
            "team": {"name": "X"},
        }
    ]
    reports = list(_parse_edges(nodes))
    assert len(reports) == 1
    assert reports[0].title == "Real vulnerability disclosure"
