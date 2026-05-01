"""Async batch processor — drives the extractor across many reports.

Concurrency model (file-handoff build):
- Reports streamed in (already filtered for resume / dedup by caller)
- Each report becomes a task; ``asyncio.Semaphore`` caps in-flight file ops
- Each ``extract()`` call writes a pending task file and polls for the
  matching completion. Failed extractions are recorded to
  validation_failures.jsonl
- Rich progress bar updates as tasks complete
- Before polling begins we print a clear instruction telling the operator
  (or Claude Code) to run ``process-tasks`` to fill in the completion files.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any, AsyncIterator, Iterable, Optional

import aiofiles
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from ..config import (
    EXTRACTOR_BATCH_SIZE,
    EXTRACTOR_MAX_CONCURRENCY,
    LOG_DIR,
)
from ..models import ExtractedPattern, ExtractionStats, SkippedReport
from ..storage import PatternStorage
from ..validator import validate_pattern
from .extractor import ExtractionError, PatternExtractor, TaskTimeoutError

logger = logging.getLogger(__name__)


class BatchProcessor:
    """Concurrent driver for `PatternExtractor` with rate limiting + progress."""

    def __init__(
        self,
        extractor: PatternExtractor,
        storage: PatternStorage,
        max_concurrency: int = EXTRACTOR_MAX_CONCURRENCY,
        batch_size: int = EXTRACTOR_BATCH_SIZE,
        console: Optional[Console] = None,
    ) -> None:
        self._extractor = extractor
        self._storage = storage
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._batch_size = max(1, batch_size)
        self._console = console or Console()
        self._stats = ExtractionStats()
        self._cumulative_usage: dict[str, int] = {
            "input_tokens": 0,
            "output_tokens": 0,
            "cache_creation_input_tokens": 0,
            "cache_read_input_tokens": 0,
        }
        self._validation_failures_path = LOG_DIR / "validation_failures.jsonl"
        self._validation_failures_path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def stats(self) -> ExtractionStats:
        return self._stats

    @property
    def usage(self) -> dict[str, int]:
        return dict(self._cumulative_usage)

    async def run(self, reports: Iterable[dict[str, Any]]) -> ExtractionStats:
        """Process all reports with bounded concurrency.

        Materializes the iterable to get a stable total for the progress bar.
        For very large inputs callers can pre-chunk and call run() per chunk.
        """
        report_list = list(reports)
        total = len(report_list)
        if total == 0:
            return self._stats

        # Print operator instruction up front. Each ``extract()`` call below
        # writes a pending task file and then polls for its completion. The
        # operator (or Claude Code, in another shell or session) needs to run
        # ``process-tasks`` to fill in the completions.
        pending_dir = self._extractor.pending_dir
        completed_dir = self._extractor.completed_dir
        self._console.print(
            f"\n[bold yellow]Claude Code task files will be written to[/bold yellow] "
            f"[cyan]{pending_dir}[/cyan]"
        )
        self._console.print(
            f"[bold yellow]Run:[/bold yellow] "
            f"[cyan]python -m extractor.main process-tasks[/cyan]"
        )
        self._console.print(
            "Claude Code will read each pending task and write its extraction JSON to "
            f"[cyan]{completed_dir}[/cyan].\n"
        )

        with Progress(
            TextColumn("[bold blue]Extracting"),
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("•"),
            TimeElapsedColumn(),
            TextColumn("•"),
            TimeRemainingColumn(),
            TextColumn("• ok={task.fields[ok]} skip={task.fields[skip]} err={task.fields[err]}"),
            console=self._console,
            transient=False,
        ) as progress:
            task_id = progress.add_task(
                "extract", total=total, ok=0, skip=0, err=0
            )

            async def run_one(report: dict[str, Any]) -> None:
                async with self._semaphore:
                    await self._process_report(report)
                progress.update(
                    task_id,
                    advance=1,
                    ok=self._stats.succeeded,
                    skip=self._stats.skipped,
                    err=self._stats.errored,
                )

            # Process in batches to bound peak memory on huge inputs
            for start in range(0, total, self._batch_size):
                batch = report_list[start : start + self._batch_size]
                await asyncio.gather(
                    *[run_one(r) for r in batch], return_exceptions=False
                )

        return self._stats

    async def _process_report(self, report: dict[str, Any]) -> None:
        """Extract one report end-to-end: API call → validate → persist."""
        self._stats.processed += 1
        url = report.get("url", "")

        # Skip already-processed URLs (resume support)
        if await self._storage.already_processed(url):
            self._stats.skipped += 1
            return

        try:
            pattern, usage = await self._extractor.extract(report)
            self._add_usage(usage)
        except TaskTimeoutError as exc:
            logger.error("task timed out for %s: %s", url, exc)
            self._stats.errored += 1
            await self._log_failure(url, "task_timeout", str(exc), report)
            return
        except ExtractionError as exc:
            logger.warning("extraction failed for %s: %s", url, exc)
            self._stats.errored += 1
            await self._log_failure(url, "extraction_error", str(exc), report)
            return
        except Exception as exc:  # last-resort safety net so one bad report doesn't kill the run
            logger.exception("unexpected error processing %s", url)
            self._stats.errored += 1
            await self._log_failure(url, "unexpected", str(exc), report)
            return

        if pattern.skipped:
            self._stats.skipped += 1
            await self._storage.save_skipped(
                SkippedReport(
                    source_url=pattern.source_url,
                    source_platform=pattern.source_platform,
                    skip_reason=pattern.skip_reason or "model returned skipped=true with no reason",
                    raw_title=report.get("title"),
                )
            )
            return

        # Validate
        result = validate_pattern(pattern)
        if not result.ok:
            logger.info("validation failed for %s: %s", url, result.reason)
            self._stats.validation_failed += 1
            await self._log_failure(url, "validation_failed", result.reason or "", report, pattern)
            return

        if result.novel_flag_should_set and not pattern.is_novel:
            # Pattern's vuln_class or feature_type wasn't in the canonical taxonomy.
            # Mark it as novel so the novelty detector picks it up downstream.
            pattern = pattern.model_copy(
                update={
                    "is_novel": True,
                    "novel_description": pattern.novel_description
                    or "Auto-flagged: vuln_class or feature_type not in canonical taxonomy",
                }
            )

        await self._storage.save_pattern(pattern)
        self._stats.succeeded += 1
        if pattern.is_novel:
            self._stats.novel_flagged += 1

    def _add_usage(self, usage: dict[str, int]) -> None:
        for k, v in usage.items():
            self._cumulative_usage[k] = self._cumulative_usage.get(k, 0) + (v or 0)

    async def _log_failure(
        self,
        source_url: str,
        category: str,
        reason: str,
        report: dict[str, Any],
        pattern: Optional[ExtractedPattern] = None,
    ) -> None:
        record = {
            "source_url": source_url,
            "category": category,
            "reason": reason,
            "report_title": report.get("title"),
            "pattern": pattern.model_dump(mode="json") if pattern else None,
        }
        try:
            async with aiofiles.open(self._validation_failures_path, "a") as fh:
                await fh.write(json.dumps(record, default=str) + "\n")
        except OSError:
            logger.exception("failed to write validation_failures.jsonl entry")


async def iter_reports_jsonl(path: Path) -> AsyncIterator[dict[str, Any]]:
    """Stream reports from a JSONL file, yielding one parsed dict per line."""
    async with aiofiles.open(path, "r") as fh:
        async for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError as exc:
                logger.warning("skipping malformed JSONL line: %s", exc)
