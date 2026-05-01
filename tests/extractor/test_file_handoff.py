"""Tests for the file-based extraction handoff.

These cover the core contract:
1. PatternExtractor.extract() writes a properly-shaped pending task file,
   waits for a completion file, and parses it back into an ExtractedPattern.
2. extract() raises TaskTimeoutError when no completion appears in time.
3. The process-tasks CLI lists pending tasks and polls until completions arrive.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from extractor.main import cli
from extractor.models import ExtractedPattern
from extractor.pipeline.extractor import (
    ExtractionError,
    PatternExtractor,
    TaskTimeoutError,
)


def _sample_report() -> dict:
    return {
        "source": "hackerone",
        "url": "https://hackerone.com/reports/9999",
        "title": "SSRF in webhook delivery",
        "severity": "high",
        "program": "Acme",
        "bounty_usd": 1500,
        "raw_content_preview": "User-supplied URL fetched server-side...",
        "vuln_type_tags": ["ssrf"],
    }


def _completion_payload() -> dict:
    return {
        "source_url": "https://hackerone.com/reports/9999",
        "source_platform": "hackerone",
        "vuln_class": "ssrf",
        "vuln_subtype": "cloud-metadata",
        "cwe_id": "CWE-918",
        "affected_feature_type": "webhook",
        "affected_stack_hints": ["aws"],
        "behavioral_signal": "Outbound request originates from the application server when triggered by a user-supplied URL.",
        "detection_approach": (
            "Identify endpoints that accept URLs as part of user-driven configuration "
            "and verify whether the application initiates an outbound request from a "
            "server-side IP without any host validation."
        ),
        "oob_required": True,
        "preconditions": ["User-controlled URL", "No host allow-list"],
        "root_cause_pattern": "User-supplied URL fetched without validation that the resolved host is in an allowed scope.",
        "chain_potential": "high",
        "chain_targets": ["info_disclosure"],
        "chain_reasoning": "Cloud metadata endpoints can leak credentials.",
        "severity": "high",
        "payout_usd": 1500.0,
        "is_novel": False,
        "novel_description": None,
        "extraction_confidence": 0.95,
        "skipped": False,
        "skip_reason": None,
    }


async def _populate_completion(extractor: PatternExtractor, payload: dict, delay: float = 0.05) -> None:
    """Background helper: wait briefly then write the completion file matching the latest pending task."""
    await asyncio.sleep(delay)
    pending_files = list(extractor.pending_dir.glob("*.json"))
    assert len(pending_files) == 1, "expected exactly one pending task at write-time"
    task_id = pending_files[0].stem
    (extractor.completed_dir / f"{task_id}.json").write_text(json.dumps(payload), encoding="utf-8")


async def test_extract_writes_pending_and_reads_completed(tmp_path):
    """extract() should write a structured pending file, wait, then return the parsed pattern."""
    pending = tmp_path / "pending"
    completed = tmp_path / "completed"
    extractor = PatternExtractor(
        pending_dir=pending,
        completed_dir=completed,
        poll_interval=0.05,
        timeout=5.0,
    )

    report = _sample_report()
    payload = _completion_payload()

    # Schedule the completion to land just after extract() starts polling
    asyncio.create_task(_populate_completion(extractor, payload, delay=0.05))

    pattern, usage = await extractor.extract(report)

    assert isinstance(pattern, ExtractedPattern)
    assert pattern.vuln_class == "ssrf"
    assert pattern.affected_feature_type == "webhook"
    # Source identity comes from the input report, not the LLM payload
    assert pattern.source_url == report["url"]
    assert pattern.source_platform == report["source"]
    # Usage is zeroed in file-handoff mode
    assert usage == {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_creation_input_tokens": 0,
        "cache_read_input_tokens": 0,
    }
    # Cleanup happens on success — both files are gone
    assert not list(pending.glob("*.json"))
    assert not list(completed.glob("*.json"))


async def test_extract_pending_file_shape(tmp_path):
    """The pending file should contain the report, system prompt, user message, and metadata."""
    pending = tmp_path / "pending"
    completed = tmp_path / "completed"
    extractor = PatternExtractor(
        pending_dir=pending,
        completed_dir=completed,
        poll_interval=0.05,
        timeout=2.0,
    )

    report = _sample_report()

    # Capture the pending file before any completion is written
    async def capture_then_complete():
        await asyncio.sleep(0.05)
        pending_files = list(pending.glob("*.json"))
        assert len(pending_files) == 1
        captured.update(json.loads(pending_files[0].read_text(encoding="utf-8")))
        task_id = pending_files[0].stem
        (completed / f"{task_id}.json").write_text(json.dumps(_completion_payload()), encoding="utf-8")

    captured: dict = {}
    asyncio.create_task(capture_then_complete())
    await extractor.extract(report)

    assert captured["status"] == "pending"
    assert "task_id" in captured
    assert "created_at" in captured
    assert captured["report"]["url"] == report["url"]
    assert "system_prompt" in captured and len(captured["system_prompt"]) > 1000
    assert "user_message" in captured and report["title"] in captured["user_message"]
    assert captured["expected_output_path"].endswith(f"{captured['task_id']}.json")


async def test_extract_timeout_raises(tmp_path):
    """No completion → TaskTimeoutError; pending file is left in place for debugging."""
    pending = tmp_path / "pending"
    completed = tmp_path / "completed"
    extractor = PatternExtractor(
        pending_dir=pending,
        completed_dir=completed,
        poll_interval=0.02,
        timeout=0.15,
    )

    with pytest.raises(TaskTimeoutError):
        await extractor.extract(_sample_report())

    # Pending file should remain so the operator can inspect / retry
    assert len(list(pending.glob("*.json"))) == 1


async def test_extract_invalid_completion_raises_extraction_error(tmp_path):
    """A completed file that's not valid JSON should surface as ExtractionError."""
    pending = tmp_path / "pending"
    completed = tmp_path / "completed"
    extractor = PatternExtractor(
        pending_dir=pending,
        completed_dir=completed,
        poll_interval=0.02,
        timeout=2.0,
    )

    async def write_garbage():
        await asyncio.sleep(0.03)
        pending_files = list(pending.glob("*.json"))
        task_id = pending_files[0].stem
        (completed / f"{task_id}.json").write_text("{not valid json", encoding="utf-8")

    asyncio.create_task(write_garbage())

    with pytest.raises(ExtractionError):
        await extractor.extract(_sample_report())


def test_process_tasks_no_pending(tmp_path):
    """process-tasks gracefully reports when there are no pending tasks."""
    pending = tmp_path / "pending"
    completed = tmp_path / "completed"
    pending.mkdir()
    completed.mkdir()

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "process-tasks",
            "--pending-dir", str(pending),
            "--completed-dir", str(completed),
            "--timeout", "1",
            "--poll-interval", "0.05",
        ],
    )
    assert result.exit_code == 0
    assert "No pending tasks" in result.output


def test_process_tasks_lists_pending_with_no_wait(tmp_path):
    """With --no-wait, process-tasks prints all pending tasks and exits without polling."""
    pending = tmp_path / "pending"
    completed = tmp_path / "completed"
    pending.mkdir()
    completed.mkdir()

    # Drop a synthetic pending task in
    task_id = "abc123"
    payload = {
        "task_id": task_id,
        "status": "pending",
        "created_at": "2026-05-01T00:00:00+00:00",
        "max_tokens": 2000,
        "expected_output_path": str(completed / f"{task_id}.json"),
        "report": {"source": "hackerone", "url": "https://h1.com/reports/1"},
        "system_prompt": "<short>",
        "user_message": "Extract the pattern from this report.",
    }
    (pending / f"{task_id}.json").write_text(json.dumps(payload), encoding="utf-8")

    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "process-tasks",
            "--pending-dir", str(pending),
            "--completed-dir", str(completed),
            "--no-wait",
        ],
    )
    assert result.exit_code == 0
    assert task_id in result.output
    assert "Extract the pattern from this report" in result.output
    assert "Expected output" in result.output
