import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from collector.dedup import url_hash
from collector.models import RawReport
from collector.storage import Storage


def make_report(url: str, source: str = "hackerone", severity: str | None = None) -> RawReport:
    return RawReport(
        source=source,
        title=f"Report {url}",
        url=url,
        severity=severity,
        content_hash=url_hash(url),
        collected_at=datetime.now(timezone.utc),
    )


async def test_save_new_report_returns_true(tmp_db):
    async with Storage(tmp_db) as s:
        assert await s.save_report(make_report("https://hackerone.com/reports/1")) is True


async def test_save_duplicate_returns_false(tmp_db):
    async with Storage(tmp_db) as s:
        r = make_report("https://hackerone.com/reports/1")
        await s.save_report(r)
        assert await s.save_report(r) is False


async def test_get_stats_per_source(tmp_db):
    async with Storage(tmp_db) as s:
        await s.save_report(make_report("https://hackerone.com/reports/1", "hackerone"))
        await s.save_report(make_report("https://hackerone.com/reports/2", "hackerone"))
        await s.save_report(make_report("https://bugcrowd.com/reports/1", "bugcrowd"))
        stats = await s.get_stats()
    assert stats["hackerone"] == 2
    assert stats["bugcrowd"] == 1
    assert stats["total"] == 3


async def test_get_reports_by_severity(tmp_db):
    async with Storage(tmp_db) as s:
        await s.save_report(make_report("https://h1.com/1", severity="high"))
        await s.save_report(make_report("https://h1.com/2", severity="low"))
        results = await s.get_reports_by_severity("high")
    assert len(results) == 1
    assert results[0].severity == "high"


async def test_export_to_jsonl(tmp_db, tmp_path):
    out = str(tmp_path / "out.jsonl")
    async with Storage(tmp_db) as s:
        await s.save_report(make_report("https://h1.com/1"))
        await s.save_report(make_report("https://h1.com/2"))
        count = await s.export_to_jsonl(out)
    assert count == 2
    lines = Path(out).read_text().strip().splitlines()
    assert len(lines) == 2
    parsed = json.loads(lines[0])
    assert parsed["source"] == "hackerone"


async def test_get_uncollected_count(tmp_db):
    async with Storage(tmp_db) as s:
        await s.save_report(make_report("https://h1.com/1"))
        await s.save_report(make_report("https://h1.com/2"))
        count = await s.get_uncollected_count()
    assert count == 2
