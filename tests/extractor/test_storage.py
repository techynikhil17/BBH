import json

import pytest

from extractor.models import ChainPotential, ExtractedPattern, Severity, SkippedReport
from extractor.storage import PatternStorage


def _pattern(url: str, vuln_class: str = "ssrf", is_novel: bool = False) -> ExtractedPattern:
    return ExtractedPattern(
        source_url=url,
        source_platform="hackerone",
        vuln_class=vuln_class,
        vuln_subtype="cloud-metadata",
        cwe_id="CWE-918",
        affected_feature_type="webhook",
        affected_stack_hints=["aws"],
        behavioral_signal="Outbound request from server to internal IP observed.",
        detection_approach=(
            "Identify endpoints accepting user URLs and check whether outbound "
            "fetches happen server-side without host validation."
        ),
        oob_required=False,
        preconditions=["User-controlled URL"],
        root_cause_pattern="Missing host validation",
        chain_potential=ChainPotential.LOW,
        chain_targets=[],
        chain_reasoning="",
        severity=Severity.HIGH,
        payout_usd=1500.0,
        is_novel=is_novel,
        novel_description="net-new mechanism" if is_novel else None,
        extraction_confidence=0.8,
    )


@pytest.fixture
def storage_paths(tmp_path):
    return {
        "db": tmp_path / "patterns.db",
        "jsonl": tmp_path / "patterns.jsonl",
        "novel": tmp_path / "novel.jsonl",
        "skipped": tmp_path / "skipped.jsonl",
    }


async def test_save_and_stats(storage_paths):
    async with PatternStorage(
        storage_paths["db"],
        storage_paths["jsonl"],
        storage_paths["novel"],
        storage_paths["skipped"],
    ) as s:
        await s.save_pattern(_pattern("https://h1.com/r/1"))
        await s.save_pattern(_pattern("https://h1.com/r/2", vuln_class="rce"))
        stats = await s.stats()

    assert stats["total_patterns"] == 2
    by_class = {row["vuln_class"]: row["n"] for row in stats["by_class"]}
    assert by_class["ssrf"] == 1
    assert by_class["rce"] == 1


async def test_save_dedup_returns_none(storage_paths):
    async with PatternStorage(
        storage_paths["db"],
        storage_paths["jsonl"],
        storage_paths["novel"],
        storage_paths["skipped"],
    ) as s:
        first = await s.save_pattern(_pattern("https://h1.com/r/1"))
        dup = await s.save_pattern(_pattern("https://h1.com/r/1"))
    assert first is not None
    assert dup is None


async def test_novel_writes_to_novel_jsonl(storage_paths):
    async with PatternStorage(
        storage_paths["db"],
        storage_paths["jsonl"],
        storage_paths["novel"],
        storage_paths["skipped"],
    ) as s:
        await s.save_pattern(_pattern("https://h1.com/r/1", is_novel=True))

    novel_lines = storage_paths["novel"].read_text().strip().splitlines()
    assert len(novel_lines) == 1
    record = json.loads(novel_lines[0])
    assert record["is_novel"] is True


async def test_save_skipped(storage_paths):
    async with PatternStorage(
        storage_paths["db"],
        storage_paths["jsonl"],
        storage_paths["novel"],
        storage_paths["skipped"],
    ) as s:
        await s.save_skipped(
            SkippedReport(
                source_url="https://h1.com/r/3",
                source_platform="hackerone",
                skip_reason="title only",
                raw_title="vague",
            )
        )
        stats = await s.stats()

    assert stats["skipped_reports"] == 1
    skipped_lines = storage_paths["skipped"].read_text().strip().splitlines()
    assert len(skipped_lines) == 1


async def test_already_processed(storage_paths):
    async with PatternStorage(
        storage_paths["db"],
        storage_paths["jsonl"],
        storage_paths["novel"],
        storage_paths["skipped"],
    ) as s:
        assert not await s.already_processed("https://h1.com/r/1")
        await s.save_pattern(_pattern("https://h1.com/r/1"))
        assert await s.already_processed("https://h1.com/r/1")


async def test_find_similar_patterns(storage_paths):
    async with PatternStorage(
        storage_paths["db"],
        storage_paths["jsonl"],
        storage_paths["novel"],
        storage_paths["skipped"],
    ) as s:
        await s.save_pattern(_pattern("https://h1.com/r/1", vuln_class="ssrf"))
        await s.save_pattern(_pattern("https://h1.com/r/2", vuln_class="ssrf"))
        await s.save_pattern(_pattern("https://h1.com/r/3", vuln_class="rce"))

        similar = await s.find_similar_patterns(vuln_class="ssrf", feature_type="webhook")
    # All 3 share feature_type=webhook; both ssrf entries also match vuln_class
    assert len(similar) == 3


async def test_update_novelty_flag(storage_paths):
    async with PatternStorage(
        storage_paths["db"],
        storage_paths["jsonl"],
        storage_paths["novel"],
        storage_paths["skipped"],
    ) as s:
        row_id = await s.save_pattern(_pattern("https://h1.com/r/1", is_novel=True))
        assert row_id is not None
        await s.update_novelty_flag(row_id, is_novel=False)
        # Read back via the storage's connection
        cursor = await s._conn.execute("SELECT is_novel FROM patterns WHERE id = ?", (row_id,))
        row = await cursor.fetchone()
        assert row["is_novel"] == 0
