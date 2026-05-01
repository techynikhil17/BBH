from datetime import timezone

from collector.sources.bugcrowd import BugcrowdCollector, _parse_activities
from collector.dedup import url_hash

SAMPLE_ACTIVITIES = [
    {
        "title": "SQL Injection in login endpoint",
        "priority": "p1",
        "url": "/submissions/abc123",
        "target": {"name": "Acme Corp"},
        "submitted_at": "2024-11-01T12:00:00Z",
        "point_value": 500,
    },
    {
        "title": "Reflected XSS",
        "priority": "p3",
        "url": "https://bugcrowd.com/submissions/def456",
        "target": {"name": "Beta Co"},
        "submitted_at": "2024-10-20T09:00:00Z",
        "point_value": 150,
    },
]


def test_parse_activities_extracts_fields():
    reports = list(_parse_activities(SAMPLE_ACTIVITIES))
    assert len(reports) == 2

    r = reports[0]
    assert r.source == "bugcrowd"
    assert r.title == "SQL Injection in login endpoint"
    assert r.url == "https://bugcrowd.com/submissions/abc123"
    assert r.severity == "critical"
    assert r.program == "Acme Corp"
    assert r.source_metadata["point_value"] == 500
    assert r.content_hash == url_hash("https://bugcrowd.com/submissions/abc123")


def test_parse_activities_full_url_unchanged():
    reports = list(_parse_activities(SAMPLE_ACTIVITIES))
    assert reports[1].url == "https://bugcrowd.com/submissions/def456"


def test_parse_activities_severity_mapping():
    activities = [
        {"title": "T", "priority": p, "url": f"/s/{p}",
         "target": {"name": "C"}, "submitted_at": "2024-01-01T00:00:00Z", "point_value": 0}
        for p in ["p1", "p2", "p3", "p4", "p5"]
    ]
    reports = list(_parse_activities(activities))
    severities = [r.severity for r in reports]
    assert severities == ["critical", "high", "medium", "low", "low"]


def test_parse_activities_skips_no_url():
    activities = [
        {"title": "No URL", "priority": "p2", "url": "",
         "target": {"name": "C"}, "submitted_at": "2024-01-01T00:00:00Z", "point_value": 0},
        {"title": "Has URL", "priority": "p2", "url": "/s/valid",
         "target": {"name": "C"}, "submitted_at": "2024-01-01T00:00:00Z", "point_value": 0},
    ]
    reports = list(_parse_activities(activities))
    assert len(reports) == 1
    assert reports[0].title == "Has URL"


def test_parse_activities_disclosed_at_timezone():
    reports = list(_parse_activities(SAMPLE_ACTIVITIES))
    assert reports[0].disclosed_at.tzinfo == timezone.utc
