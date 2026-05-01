"""Click CLI for the pattern extraction pipeline.

Subcommands:
  extract        Extract patterns from a JSONL of raw reports
  process-tasks  Display pending tasks and poll for completions (run by Claude Code)
  stats          Show extraction statistics
  review-novel   Re-evaluate is_novel=True patterns against the library
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from .config import (
    COMPLETED_DIR,
    EXTRACTOR_BATCH_SIZE,
    EXTRACTOR_MAX_CONCURRENCY,
    LOG_DIR,
    NOVEL_PATTERNS_JSONL,
    PATTERNS_DB,
    PATTERNS_JSONL,
    PENDING_DIR,
    RAW_REPORTS_INPUT,
    SKIPPED_JSONL,
    TASK_POLL_INTERVAL,
    TASK_TIMEOUT_SECONDS,
)
from .pipeline.batch_processor import BatchProcessor, iter_reports_jsonl
from .pipeline.extractor import PatternExtractor
from .pipeline.novelty_detector import NoveltyDetector
from .storage import PatternStorage

console = Console()


def _setup_logging(ts: str) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    fmt = '{"ts":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","msg":"%(message)s"}'
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.FileHandler(LOG_DIR / f"extraction_{ts}.log"),
            logging.StreamHandler(sys.stderr),
        ],
        force=True,
    )


@click.group()
def cli() -> None:
    """Bug bounty report → vulnerability pattern extraction pipeline."""


@cli.command()
@click.option(
    "--input",
    "-i",
    "input_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=str(RAW_REPORTS_INPUT),
    show_default=True,
    help="JSONL file of raw reports (output of PROMPT 01)",
)
@click.option(
    "--output",
    "-o",
    "output_dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=None,
    help="Override the patterns output directory (otherwise uses config)",
)
@click.option(
    "--limit",
    "-l",
    type=int,
    default=None,
    help="Process at most N reports (after severity filter)",
)
@click.option(
    "--severity",
    multiple=True,
    type=click.Choice(["critical", "high", "medium", "low", "unknown"]),
    help="Filter to reports with the listed severities (repeatable)",
)
@click.option(
    "--source",
    multiple=True,
    help="Filter to reports from the listed source platforms (repeatable)",
)
@click.option(
    "--max-concurrency",
    type=int,
    default=EXTRACTOR_MAX_CONCURRENCY,
    show_default=True,
    help="Max concurrent in-flight extractions",
)
@click.option(
    "--batch-size",
    type=int,
    default=EXTRACTOR_BATCH_SIZE,
    show_default=True,
    help="Reports per batch",
)
@click.option(
    "--review-novel/--no-review-novel",
    default=True,
    show_default=True,
    help="After extraction, run novelty review pass to demote false-positive novel flags",
)
def extract(
    input_path: Path,
    output_dir: Optional[Path],
    limit: Optional[int],
    severity: tuple[str, ...],
    source: tuple[str, ...],
    max_concurrency: int,
    batch_size: int,
    review_novel: bool,
) -> None:
    """Extract structured patterns from a JSONL of raw bug bounty reports."""
    if not input_path.exists():
        console.print(f"[red]Input file not found:[/red] {input_path}")
        sys.exit(1)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    _setup_logging(ts)

    db_path = PATTERNS_DB if output_dir is None else (output_dir / "patterns.db")
    jsonl_path = PATTERNS_JSONL if output_dir is None else (output_dir / "patterns.jsonl")
    novel_path = NOVEL_PATTERNS_JSONL if output_dir is None else (output_dir / "novel_patterns.jsonl")
    skipped_path = SKIPPED_JSONL if output_dir is None else (output_dir / "skipped.jsonl")

    asyncio.run(
        _run_extract(
            input_path=input_path,
            db_path=db_path,
            jsonl_path=jsonl_path,
            novel_path=novel_path,
            skipped_path=skipped_path,
            limit=limit,
            severity_filter=set(severity),
            source_filter=set(source),
            max_concurrency=max_concurrency,
            batch_size=batch_size,
            review_novel=review_novel,
        )
    )


async def _run_extract(
    input_path: Path,
    db_path: Path,
    jsonl_path: Path,
    novel_path: Path,
    skipped_path: Path,
    limit: Optional[int],
    severity_filter: set[str],
    source_filter: set[str],
    max_concurrency: int,
    batch_size: int,
    review_novel: bool,
) -> None:
    reports: list[dict] = []
    async for report in iter_reports_jsonl(input_path):
        if severity_filter and (report.get("severity") not in severity_filter):
            continue
        if source_filter and (report.get("source") not in source_filter):
            continue
        reports.append(report)
        if limit is not None and len(reports) >= limit:
            break

    console.print(f"[cyan]Loaded {len(reports)} reports for extraction.[/cyan]")
    if not reports:
        console.print("[yellow]No reports matched filters — nothing to do.[/yellow]")
        return

    extractor = PatternExtractor()

    async with PatternStorage(db_path, jsonl_path, novel_path, skipped_path) as storage:
        processor = BatchProcessor(
            extractor=extractor,
            storage=storage,
            max_concurrency=max_concurrency,
            batch_size=batch_size,
            console=console,
        )
        await processor.run(reports)

        _print_run_summary(processor)

        if review_novel:
            console.print("\n[cyan]Running novelty review pass (local similarity)...[/cyan]")
            detector = NoveltyDetector(storage=storage)
            review_stats = await detector.review_all_novel()
            console.print(
                f"  reviewed: {review_stats['reviewed']}  "
                f"confirmed novel: {review_stats['confirmed_novel']}  "
                f"demoted: {review_stats['demoted']}  "
                f"errors: {review_stats['errors']}"
            )

    console.print(f"\n[green]Patterns:[/green] {jsonl_path}")
    console.print(f"[green]Novel patterns:[/green] {novel_path}")
    console.print(f"[green]Skipped:[/green] {skipped_path}")


def _print_run_summary(processor: BatchProcessor) -> None:
    s = processor.stats

    table = Table(title="Extraction Summary", show_header=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    table.add_row("Processed", str(s.processed))
    table.add_row("Succeeded", f"[green]{s.succeeded}[/green]")
    table.add_row("Skipped (vague / dup)", f"[yellow]{s.skipped}[/yellow]")
    table.add_row("Errored", f"[red]{s.errored}[/red]")
    table.add_row("Validation failed", f"[red]{s.validation_failed}[/red]")
    table.add_row("Novel-flagged", str(s.novel_flagged))
    console.print()
    console.print(table)


@cli.command("process-tasks")
@click.option(
    "--pending-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(PENDING_DIR),
    show_default=True,
    help="Directory holding pending task files",
)
@click.option(
    "--completed-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(COMPLETED_DIR),
    show_default=True,
    help="Directory where Claude Code writes completion JSONs",
)
@click.option(
    "--timeout",
    type=float,
    default=TASK_TIMEOUT_SECONDS,
    show_default=True,
    help="Seconds to wait for all completions",
)
@click.option(
    "--poll-interval",
    type=float,
    default=TASK_POLL_INTERVAL,
    show_default=True,
    help="Seconds between completion-dir polls",
)
@click.option(
    "--no-wait",
    is_flag=True,
    default=False,
    help="Print pending tasks and exit immediately without polling for completions",
)
def process_tasks(
    pending_dir: Path,
    completed_dir: Path,
    timeout: float,
    poll_interval: float,
    no_wait: bool,
) -> None:
    """Print pending extraction tasks and poll for completions.

    Run by Claude Code: prints each pending task as a structured block, then
    polls the completed directory until every task has a corresponding
    completion file. Claude Code reads the printed prompts, performs the
    extraction reasoning, and uses its Write tool to create completion files
    while this command polls.
    """
    asyncio.run(
        _run_process_tasks(pending_dir, completed_dir, timeout, poll_interval, no_wait)
    )


async def _run_process_tasks(
    pending_dir: Path,
    completed_dir: Path,
    timeout: float,
    poll_interval: float,
    no_wait: bool,
) -> None:
    pending_dir.mkdir(parents=True, exist_ok=True)
    completed_dir.mkdir(parents=True, exist_ok=True)

    pending_files = sorted(pending_dir.glob("*.json"))
    if not pending_files:
        console.print("[yellow]No pending tasks.[/yellow]")
        return

    console.print(f"[cyan]Found {len(pending_files)} pending task(s).[/cyan]\n")

    pending_ids: list[str] = []
    for path in pending_files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            console.print(f"[red]Skipping malformed task {path.name}:[/red] {exc}")
            continue

        task_id = data.get("task_id", path.stem)
        pending_ids.append(task_id)
        expected_output = data.get(
            "expected_output_path", str(completed_dir / f"{task_id}.json")
        )
        report = data.get("report", {}) or {}
        user_message = data.get("user_message", "")

        console.print(f"[bold magenta]===== TASK {task_id} =====[/bold magenta]")
        console.print(f"Expected output: [cyan]{expected_output}[/cyan]")
        console.print(
            f"Source: [cyan]{report.get('source', '?')}[/cyan]  "
            f"URL: [cyan]{report.get('url', '?')}[/cyan]"
        )
        console.print()
        console.print("[bold]USER MESSAGE:[/bold]")
        console.print(user_message)
        console.print(f"[bold magenta]===== END TASK {task_id} =====[/bold magenta]\n")

    console.print(
        "[bold]Write each task's extraction JSON to its expected output path.[/bold]"
    )
    console.print(
        "Each completion file should contain ONLY the ExtractedPattern JSON object — "
        "no markdown, no commentary."
    )

    if no_wait:
        console.print("[yellow]--no-wait set; exiting without polling.[/yellow]")
        return

    console.print(
        f"\nPolling [cyan]{completed_dir}[/cyan] every {poll_interval}s "
        f"(timeout {timeout}s)...\n"
    )

    pending_set = set(pending_ids)
    completed: set[str] = set()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout

    with Progress(
        TextColumn("[bold blue]Awaiting completions"),
        BarColumn(),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        TextColumn("•"),
        TimeRemainingColumn(),
        console=console,
        transient=False,
    ) as progress:
        task_pid = progress.add_task("complete", total=len(pending_set))
        while completed != pending_set:
            for tid in pending_set - completed:
                if (completed_dir / f"{tid}.json").exists():
                    completed.add(tid)
                    progress.update(task_pid, advance=1)
            if completed == pending_set:
                break
            if loop.time() >= deadline:
                missing = pending_set - completed
                console.print(
                    f"\n[red]Timed out.[/red] {len(missing)} task(s) still pending: "
                    + ", ".join(sorted(missing))
                )
                sys.exit(2)
            await asyncio.sleep(poll_interval)

    console.print(f"\n[green]All {len(pending_set)} task(s) completed.[/green]")


@cli.command()
@click.option(
    "--input",
    "-i",
    "input_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=str(PATTERNS_JSONL),
    show_default=True,
    help="patterns.jsonl path (or any compatible JSONL)",
)
def stats(input_path: Path) -> None:
    """Show statistics about extracted patterns."""
    asyncio.run(_run_stats(input_path))


async def _run_stats(input_path: Path) -> None:
    db_path = input_path.parent / "patterns.db"
    if not db_path.exists():
        console.print(f"[red]No SQLite database at {db_path}[/red]")
        console.print("Run `extract` first, or pass --input pointing at a populated patterns dir.")
        sys.exit(1)

    async with PatternStorage(
        db_path,
        input_path,
        input_path.parent / "novel_patterns.jsonl",
        input_path.parent / "skipped.jsonl",
    ) as storage:
        s = await storage.stats()

    table = Table(title="Pattern Library Stats", show_header=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    table.add_row("Total patterns", str(s["total_patterns"]))
    table.add_row("Novel patterns", f"[magenta]{s['novel_patterns']}[/magenta]")
    table.add_row("Skipped reports", f"[yellow]{s['skipped_reports']}[/yellow]")
    console.print(table)

    if s["by_class"]:
        cls_table = Table(title="By Vulnerability Class")
        cls_table.add_column("Class", style="cyan")
        cls_table.add_column("Count", justify="right")
        for row in s["by_class"][:15]:
            cls_table.add_row(row["vuln_class"], str(row["n"]))
        console.print(cls_table)

    if s["by_severity"]:
        sev_table = Table(title="By Severity")
        sev_table.add_column("Severity", style="cyan")
        sev_table.add_column("Count", justify="right")
        for row in s["by_severity"]:
            sev_table.add_row(row["severity"], str(row["n"]))
        console.print(sev_table)


@cli.command("review-novel")
@click.option(
    "--input",
    "-i",
    "input_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=str(NOVEL_PATTERNS_JSONL),
    show_default=True,
    help="novel_patterns.jsonl path (used to locate the patterns DB)",
)
def review_novel(input_path: Path) -> None:
    """Re-evaluate is_novel=True patterns against the library; demote false positives."""
    db_path = input_path.parent / "patterns.db"
    if not db_path.exists():
        console.print(f"[red]No SQLite database at {db_path}[/red]")
        sys.exit(1)
    asyncio.run(_run_review(input_path, db_path))


async def _run_review(input_path: Path, db_path: Path) -> None:
    async with PatternStorage(
        db_path,
        input_path.parent / "patterns.jsonl",
        input_path,
        input_path.parent / "skipped.jsonl",
    ) as storage:
        detector = NoveltyDetector(storage=storage)
        result = await detector.review_all_novel()

    table = Table(title="Novelty Review Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    table.add_row("Reviewed", str(result["reviewed"]))
    table.add_row("Confirmed novel", f"[magenta]{result['confirmed_novel']}[/magenta]")
    table.add_row("Demoted (not novel)", f"[yellow]{result['demoted']}[/yellow]")
    table.add_row("Errors", f"[red]{result['errors']}[/red]")
    console.print(table)


if __name__ == "__main__":
    cli()
