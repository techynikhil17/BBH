"""Core extraction logic — file-based handoff to Claude Code.

Each `extract()` invocation:
1. Writes a pending task file at `data/claude_tasks/pending/{task_id}.json`
   containing the raw report, system prompt, and user message.
2. Polls `data/claude_tasks/completed/{task_id}.json` every `poll_interval`
   seconds for up to `timeout` seconds.
3. Reads the completed file (which Claude Code wrote with its own reasoning),
   parses it as JSON matching the ExtractedPattern shape.
4. Cleans up both the pending and completed files on success.

The public interface (`PatternExtractor.extract(report) -> (pattern, usage)`)
is preserved so `BatchProcessor` and the validator/storage flow remain
unchanged. `usage` is returned with zeroed token counts since there's no API
call to attribute tokens against.
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from pydantic import ValidationError

from ..config import (
    COMPLETED_DIR,
    EXTRACTOR_MAX_TOKENS,
    EXTRACTOR_RETRIES,
    PENDING_DIR,
    TASK_POLL_INTERVAL,
    TASK_TIMEOUT_SECONDS,
)
from ..models import ExtractedPattern
from ..prompts.extraction import build_system_prompt, build_user_message
from ..taxonomy import normalize_feature_type, normalize_vuln_class

logger = logging.getLogger(__name__)


class ExtractionError(Exception):
    """Non-retryable extraction failure (parse, validation, or timeout)."""


class TaskTimeoutError(ExtractionError):
    """The completed task file did not appear within the configured timeout."""


class PatternExtractor:
    """File-based extraction handoff.

    Public surface preserved: ``extract(report)`` returns a
    ``(ExtractedPattern, usage_dict)`` tuple just like the previous
    API-backed version. Only the internal implementation differs.
    """

    def __init__(
        self,
        pending_dir: Path = PENDING_DIR,
        completed_dir: Path = COMPLETED_DIR,
        max_tokens: int = EXTRACTOR_MAX_TOKENS,
        retries: int = EXTRACTOR_RETRIES,
        poll_interval: float = TASK_POLL_INTERVAL,
        timeout: float = TASK_TIMEOUT_SECONDS,
        # Compatibility kwargs — accepted but ignored. Old callers may still
        # pass `client` / `model`; we ignore them rather than raising so the
        # CLI and any external integrations don't break.
        client: Any = None,
        model: Optional[str] = None,
    ) -> None:
        self._pending_dir = Path(pending_dir)
        self._completed_dir = Path(completed_dir)
        self._pending_dir.mkdir(parents=True, exist_ok=True)
        self._completed_dir.mkdir(parents=True, exist_ok=True)
        self._max_tokens = max_tokens
        self._retries = max(1, retries)
        self._poll_interval = max(0.01, float(poll_interval))
        self._timeout = max(self._poll_interval, float(timeout))
        self._system_prompt = build_system_prompt()

    @property
    def pending_dir(self) -> Path:
        return self._pending_dir

    @property
    def completed_dir(self) -> Path:
        return self._completed_dir

    async def extract(self, report: dict[str, Any]) -> tuple[ExtractedPattern, dict[str, int]]:
        """Drop a task file for Claude Code, wait for the completion, parse it.

        Raises ``TaskTimeoutError`` if no completion appears in time, and
        ``ExtractionError`` on JSON / schema failures. On error we leave the
        pending file in place so the operator can debug; only successful
        extractions clean up.
        """
        task_id = uuid.uuid4().hex
        user_msg = build_user_message(report)
        await self._write_pending(task_id, report, user_msg)

        response_text = await self._wait_for_completion(task_id)

        try:
            data = json.loads(response_text)
        except json.JSONDecodeError as exc:
            raise ExtractionError(
                f"completed file for task {task_id} is not valid JSON: {exc}"
            ) from exc

        try:
            pattern = self._build_pattern(data, report)
        except (ValidationError, KeyError, TypeError) as exc:
            raise ExtractionError(
                f"failed to build ExtractedPattern from task {task_id}: {exc}"
            ) from exc

        # Only clean up after a successful round-trip. On failure we leave
        # the artifacts on disk for inspection.
        self._cleanup_task(task_id)

        usage = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
        }
        return pattern, usage

    async def _write_pending(
        self,
        task_id: str,
        report: dict[str, Any],
        user_message: str,
    ) -> None:
        """Write the task file atomically (tmp + rename) so Claude Code never
        sees a partially-written pending file.
        """
        path = self._pending_dir / f"{task_id}.json"
        payload = {
            "task_id": task_id,
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "max_tokens": self._max_tokens,
            "expected_output_path": str(self._completed_dir / f"{task_id}.json"),
            "report": report,
            "system_prompt": self._system_prompt,
            "user_message": user_message,
        }
        tmp_path = path.with_suffix(".json.tmp")
        await asyncio.to_thread(_write_json_atomic, tmp_path, path, payload)

    async def _wait_for_completion(self, task_id: str) -> str:
        """Poll the completed dir for ``task_id``.json until it exists or we time out."""
        completed_path = self._completed_dir / f"{task_id}.json"
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self._timeout

        while True:
            if completed_path.exists():
                try:
                    return await asyncio.to_thread(completed_path.read_text, encoding="utf-8")
                except FileNotFoundError:
                    # Race with deletion — treat as still pending and keep polling
                    pass

            if loop.time() >= deadline:
                raise TaskTimeoutError(
                    f"task {task_id} did not complete within {self._timeout:.1f}s "
                    f"(expected file: {completed_path})"
                )
            await asyncio.sleep(self._poll_interval)

    def _build_pattern(
        self,
        data: dict[str, Any],
        source_report: dict[str, Any],
    ) -> ExtractedPattern:
        # Backfill source identity from the input report — the LLM's source_url
        # / source_platform fields can drift; the report values are authoritative.
        data["source_url"] = source_report.get("url") or data.get("source_url", "")
        data["source_platform"] = (
            source_report.get("source") or data.get("source_platform", "")
        )

        if data.get("vuln_class"):
            data["vuln_class"] = normalize_vuln_class(data["vuln_class"])
        if data.get("affected_feature_type"):
            data["affected_feature_type"] = normalize_feature_type(
                data["affected_feature_type"]
            )

        if data.get("payout_usd") is None and source_report.get("bounty_usd") is not None:
            data["payout_usd"] = source_report["bounty_usd"]

        return ExtractedPattern(**data)

    def _cleanup_task(self, task_id: str) -> None:
        for d in (self._pending_dir, self._completed_dir):
            p = d / f"{task_id}.json"
            try:
                p.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                logger.warning("failed to remove %s: %s", p, exc)


def _write_json_atomic(tmp_path: Path, final_path: Path, data: dict[str, Any]) -> None:
    """Write JSON to ``tmp_path`` then rename to ``final_path``.

    Runs synchronously inside ``asyncio.to_thread`` so the event loop isn't
    blocked on disk I/O for big system prompts.
    """
    tmp_path.parent.mkdir(parents=True, exist_ok=True)
    with open(tmp_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
    tmp_path.replace(final_path)
