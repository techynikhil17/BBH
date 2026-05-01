import pytest
from datetime import datetime, timezone
from collector.models import (
    RawReport,
    truncate_to_sentence,
    normalize_severity,
)
from collector.dedup import url_hash


# --- truncate_to_sentence ---

def test_truncate_short_text_unchanged():
    text = "Hello world."
    assert truncate_to_sentence(text, 2000) == text


def test_truncate_at_sentence_boundary():
    short = "First sentence."
    text = short + " " + "x" * 2000
    result = truncate_to_sentence(text, 2000)
    assert result == short


def test_truncate_at_whitespace_when_no_boundary():
    text = "a" * 1990 + " " + "b" * 100
    result = truncate_to_sentence(text, 2000)
    assert len(result) <= 2000
    assert not result.endswith("b")


def test_truncate_hard_cut_when_no_whitespace():
    text = "x" * 2100
    result = truncate_to_sentence(text, 2000)
    assert len(result) == 2000


def test_truncate_exclamation_and_question():
    assert truncate_to_sentence("Found it! " + "x" * 2000, 2000) == "Found it!"
    assert truncate_to_sentence("Really? " + "x" * 2000, 2000) == "Really?"


# --- normalize_severity ---

def test_normalize_hackerone_labels():
    assert normalize_severity("critical") == "critical"
    assert normalize_severity("high") == "high"
    assert normalize_severity("medium") == "medium"
    assert normalize_severity("low") == "low"


def test_normalize_bugcrowd_priorities():
    assert normalize_severity("p1") == "critical"
    assert normalize_severity("p2") == "high"
    assert normalize_severity("p3") == "medium"
    assert normalize_severity("p4") == "low"
    assert normalize_severity("p5") == "low"


def test_normalize_unknown_returns_unknown():
    assert normalize_severity("bogus") == "unknown"


def test_normalize_none_returns_none():
    assert normalize_severity(None) is None


def test_normalize_case_insensitive():
    assert normalize_severity("CRITICAL") == "critical"
    assert normalize_severity("P1") == "critical"


# --- RawReport ---

def test_raw_report_minimal_valid():
    url = "https://hackerone.com/reports/1"
    report = RawReport(
        source="hackerone",
        title="XSS in search",
        url=url,
        content_hash=url_hash(url),
        collected_at=datetime.now(timezone.utc),
    )
    assert report.source == "hackerone"
    assert report.severity is None
    assert report.vuln_type_tags == []
    assert report.source_metadata == {}


def test_raw_report_invalid_source():
    with pytest.raises(Exception):
        RawReport(
            source="unknown_source",
            title="test",
            url="https://example.com",
            content_hash=url_hash("https://example.com"),
            collected_at=datetime.now(timezone.utc),
        )


def test_raw_report_content_hash_matches_url():
    url = "https://hackerone.com/reports/999"
    report = RawReport(
        source="hackerone",
        title="Test",
        url=url,
        content_hash=url_hash(url),
        collected_at=datetime.now(timezone.utc),
    )
    assert report.content_hash == url_hash(url)
