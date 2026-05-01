"""Click CLI for the skill generator.

Subcommands:
  generate       Group patterns and write generation tasks for Claude Code
  process-tasks  Print pending generator tasks; poll for completions (run by Claude Code)
  update         Re-run generation only for groups that have new patterns
  validate       Validate every skill.md under skills/
  index          Regenerate skills/README.md
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
    INSUFFICIENT_PATTERNS_JSONL,
    LOG_DIR,
    PATTERNS_JSONL,
    PENDING_DIR,
    SKILLS_DIR,
    TASK_ID_PREFIX,
    TASK_POLL_INTERVAL,
    TASK_TIMEOUT_SECONDS,
)
from .models import GenerationStats
from .pipeline import grouper, index_builder, skill_assembler, task_writer, updater
from .validator import validate_skills_dir

console = Console()
logger = logging.getLogger(__name__)


def _setup_logging(ts: str) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    fmt = '{"ts":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","msg":"%(message)s"}'
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.FileHandler(LOG_DIR / f"generator_{ts}.log"),
            logging.StreamHandler(sys.stderr),
        ],
        force=True,
    )


@click.group()
def cli() -> None:
    """Bug bounty skill file generator (Claude Code native)."""


# ---------- generate ----------

@cli.command()
@click.option(
    "--input",
    "-i",
    "input_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=str(PATTERNS_JSONL),
    show_default=True,
    help="patterns.jsonl from PROMPT 02",
)
@click.option(
    "--output",
    "-o",
    "skills_dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(SKILLS_DIR),
    show_default=True,
    help="Skills output root",
)
@click.option(
    "--limit",
    "-l",
    type=int,
    default=None,
    help="Process at most N pattern groups (after sort)",
)
@click.option(
    "--no-wait",
    is_flag=True,
    default=False,
    help="Write task files and exit immediately, do not poll for completions",
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
def generate(
    input_path: Path,
    skills_dir: Path,
    limit: Optional[int],
    no_wait: bool,
    timeout: float,
    poll_interval: float,
) -> None:
    """Group patterns, write generation tasks, then poll for completions."""
    if not input_path.exists():
        console.print(f"[red]Input file not found:[/red] {input_path}")
        sys.exit(1)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    _setup_logging(ts)

    asyncio.run(
        _run_generate(
            input_path=input_path,
            skills_dir=skills_dir,
            limit=limit,
            no_wait=no_wait,
            timeout=timeout,
            poll_interval=poll_interval,
        )
    )


async def _run_generate(
    *,
    input_path: Path,
    skills_dir: Path,
    limit: Optional[int],
    no_wait: bool,
    timeout: float,
    poll_interval: float,
) -> None:
    stats = GenerationStats()

    patterns = grouper.load_patterns(input_path)
    if not patterns:
        console.print("[yellow]No patterns to process — nothing to do.[/yellow]")
        return

    eligible, insufficient = grouper.group_patterns(patterns)
    stats.insufficient_groups = len(insufficient)
    written_count = grouper.write_insufficient_patterns(insufficient, INSUFFICIENT_PATTERNS_JSONL)
    if written_count:
        console.print(
            f"[yellow]{written_count} pattern(s) in groups below threshold "
            f"→ {INSUFFICIENT_PATTERNS_JSONL}[/yellow]"
        )

    if limit is not None:
        eligible = eligible[:limit]

    stats.total_groups = len(eligible)
    if not eligible:
        console.print("[yellow]No groups meet the minimum-pattern threshold.[/yellow]")
        return

    # Build tasks; if a skill already exists for the group, fall through to
    # the updater so we generate an update task instead of a fresh-write one.
    tasks_built = []
    for group in eligible:
        existing = updater.find_existing_skill(group, skills_dir=skills_dir)
        if existing is None:
            tasks_built.append(task_writer.build_task(group))
        else:
            update_task = updater.build_update_task(group, existing)
            if update_task is None:
                # Skill already covers all incoming patterns
                logger.info("skipping %s — no new patterns", group.task_id)
                continue
            tasks_built.append(update_task)

    if not tasks_built:
        console.print("[yellow]All groups already up-to-date — no tasks written.[/yellow]")
        return

    paths = task_writer.write_tasks(tasks_built)
    stats.tasks_written = len(paths)

    console.print(
        f"\n[bold yellow]Wrote {len(paths)} task file(s) to[/bold yellow] [cyan]{PENDING_DIR}[/cyan]"
    )
    console.print(
        "[bold yellow]Run:[/bold yellow] "
        "[cyan]python -m generator.main process-tasks[/cyan]"
    )
    console.print(
        "Claude Code will read each pending task and write its skill JSON to "
        f"[cyan]{COMPLETED_DIR}[/cyan].\n"
    )

    if no_wait:
        console.print("[yellow]--no-wait set; exiting without polling.[/yellow]")
        _print_generate_summary(stats)
        return

    expected_ids = {t.task_id for t in tasks_built}
    completed_ids = await _poll_completions(
        expected_ids=expected_ids,
        completed_dir=COMPLETED_DIR,
        timeout=timeout,
        poll_interval=poll_interval,
    )
    stats.completions_received = len(completed_ids)
    stats.timed_out = len(expected_ids - completed_ids)

    # Assemble whatever did complete
    results, errors = skill_assembler.assemble_all(skills_dir=skills_dir)
    stats.skills_assembled = len(results)
    if errors:
        console.print(f"[red]{len(errors)} assembly error(s):[/red]")
        for tid, reason in errors:
            console.print(f"  - {tid}: {reason}")

    # Validate the new on-disk skills
    reports = [validate_skills_dir(skills_dir)]
    flat = [r for batch in reports for r in batch]
    stats.skills_validated = sum(1 for r in flat if r.ok)
    stats.validation_failures = sum(1 for r in flat if not r.ok)
    if stats.validation_failures:
        console.print(f"[red]{stats.validation_failures} skill(s) failed validation:[/red]")
        for r in flat:
            if not r.ok:
                console.print(f"  - {r.path}")
                for err in r.errors:
                    console.print(f"      • {err}")

    # Refresh the index
    index_path = index_builder.write_index(skills_dir=skills_dir)
    console.print(f"\n[green]Index regenerated:[/green] {index_path}")

    _print_generate_summary(stats)


async def _poll_completions(
    *,
    expected_ids: set[str],
    completed_dir: Path,
    timeout: float,
    poll_interval: float,
) -> set[str]:
    """Poll until every ``task_id`` in ``expected_ids`` has a completion file."""
    completed_dir.mkdir(parents=True, exist_ok=True)
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    completed: set[str] = set()

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
        task_pid = progress.add_task("complete", total=len(expected_ids))
        while completed != expected_ids:
            for tid in expected_ids - completed:
                if (completed_dir / f"{tid}.json").exists():
                    completed.add(tid)
                    progress.update(task_pid, advance=1)
            if completed == expected_ids:
                break
            if loop.time() >= deadline:
                missing = expected_ids - completed
                console.print(
                    f"\n[red]Timed out.[/red] {len(missing)} task(s) still pending: "
                    + ", ".join(sorted(missing))
                )
                break
            await asyncio.sleep(poll_interval)

    return completed


def _print_generate_summary(stats: GenerationStats) -> None:
    table = Table(title="Generation Summary", show_header=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", justify="right")
    table.add_row("Eligible groups", str(stats.total_groups))
    table.add_row("Groups below threshold", str(stats.insufficient_groups))
    table.add_row("Task files written", str(stats.tasks_written))
    table.add_row("Completions received", f"[green]{stats.completions_received}[/green]")
    table.add_row("Skills assembled", f"[green]{stats.skills_assembled}[/green]")
    table.add_row("Skills validated", f"[green]{stats.skills_validated}[/green]")
    table.add_row("Validation failures", f"[red]{stats.validation_failures}[/red]")
    table.add_row("Timed out", f"[red]{stats.timed_out}[/red]")
    console.print()
    console.print(table)


# ---------- process-tasks ----------

@cli.command("process-tasks")
@click.option(
    "--pending-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(PENDING_DIR),
    show_default=True,
)
@click.option(
    "--completed-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(COMPLETED_DIR),
    show_default=True,
)
@click.option(
    "--timeout",
    type=float,
    default=TASK_TIMEOUT_SECONDS,
    show_default=True,
)
@click.option(
    "--poll-interval",
    type=float,
    default=TASK_POLL_INTERVAL,
    show_default=True,
)
@click.option(
    "--no-wait",
    is_flag=True,
    default=False,
    help="Print pending tasks and exit without polling",
)
def process_tasks(
    pending_dir: Path,
    completed_dir: Path,
    timeout: float,
    poll_interval: float,
    no_wait: bool,
) -> None:
    """Print pending generator tasks; poll for their completion files.

    Designed to be run BY Claude Code — Claude Code reads each pending task,
    generates the skill markdown using its own reasoning, and writes the
    completion JSON to the expected output path. This command provides the
    progress display and exits when every pending task has a completion.
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

    pending_files = sorted(pending_dir.glob(f"{TASK_ID_PREFIX}_*.json"))
    if not pending_files:
        console.print("[yellow]No pending generator tasks.[/yellow]")
        return

    console.print(f"[cyan]Found {len(pending_files)} pending generator task(s).[/cyan]\n")

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
        is_update = data.get("is_update", False)

        console.print(f"[bold magenta]===== TASK {task_id} =====[/bold magenta]")
        console.print(
            f"vuln_class: [cyan]{data.get('vuln_class', '?')}[/cyan]  "
            f"vuln_subtype: [cyan]{data.get('vuln_subtype', '?')}[/cyan]  "
            f"patterns: [cyan]{len(data.get('patterns', []))}[/cyan]  "
            f"update: [cyan]{is_update}[/cyan]"
        )
        console.print(f"Expected output: [cyan]{expected_output}[/cyan]")
        console.print()
        console.print("[bold]INSTRUCTION:[/bold]")
        console.print(data.get("instruction", ""))
        console.print(f"[bold magenta]===== END TASK {task_id} =====[/bold magenta]\n")

    console.print(
        "[bold]Write each task's skill JSON to its expected output path.[/bold]"
    )
    console.print(
        'Each completion file must contain the exact shape: '
        '{"skill_md_content": "...", "patterns_json": [...], "metadata": {...}}'
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


# ---------- update ----------

@cli.command()
@click.option(
    "--input",
    "-i",
    "input_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=str(PATTERNS_JSONL),
    show_default=True,
    help="patterns.jsonl with new patterns",
)
@click.option(
    "--skills-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(SKILLS_DIR),
    show_default=True,
)
@click.option(
    "--no-wait",
    is_flag=True,
    default=False,
)
@click.option(
    "--timeout",
    type=float,
    default=TASK_TIMEOUT_SECONDS,
    show_default=True,
)
@click.option(
    "--poll-interval",
    type=float,
    default=TASK_POLL_INTERVAL,
    show_default=True,
)
def update(
    input_path: Path,
    skills_dir: Path,
    no_wait: bool,
    timeout: float,
    poll_interval: float,
) -> None:
    """Re-run generation only for groups that have new patterns."""
    if not input_path.exists():
        console.print(f"[red]Input file not found:[/red] {input_path}")
        sys.exit(1)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    _setup_logging(ts)

    asyncio.run(
        _run_update(
            input_path=input_path,
            skills_dir=skills_dir,
            no_wait=no_wait,
            timeout=timeout,
            poll_interval=poll_interval,
        )
    )


async def _run_update(
    *,
    input_path: Path,
    skills_dir: Path,
    no_wait: bool,
    timeout: float,
    poll_interval: float,
) -> None:
    patterns = grouper.load_patterns(input_path)
    eligible, _ = grouper.group_patterns(patterns)

    update_tasks = []
    skipped_no_change = 0
    skipped_no_skill = 0
    for group in eligible:
        existing = updater.find_existing_skill(group, skills_dir=skills_dir)
        if existing is None:
            skipped_no_skill += 1
            continue
        task = updater.build_update_task(group, existing)
        if task is None:
            skipped_no_change += 1
            continue
        update_tasks.append(task)

    console.print(
        f"[cyan]{len(update_tasks)} update task(s);"
        f" {skipped_no_change} group(s) already current;"
        f" {skipped_no_skill} group(s) have no existing skill.[/cyan]"
    )

    if not update_tasks:
        return

    paths = task_writer.write_tasks(update_tasks)
    console.print(f"\n[bold yellow]Wrote {len(paths)} update task file(s) to[/bold yellow] [cyan]{PENDING_DIR}[/cyan]")
    console.print("[bold yellow]Run:[/bold yellow] [cyan]python -m generator.main process-tasks[/cyan]\n")

    if no_wait:
        return

    expected = {t.task_id for t in update_tasks}
    await _poll_completions(
        expected_ids=expected,
        completed_dir=COMPLETED_DIR,
        timeout=timeout,
        poll_interval=poll_interval,
    )

    results, errors = skill_assembler.assemble_all(skills_dir=skills_dir)
    console.print(f"\n[green]Assembled {len(results)} update(s); {len(errors)} error(s).[/green]")
    index_builder.write_index(skills_dir=skills_dir)


# ---------- validate ----------

@cli.command()
@click.option(
    "--skills-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(SKILLS_DIR),
    show_default=True,
)
def validate(skills_dir: Path) -> None:
    """Validate every skill.md under skills/."""
    reports = validate_skills_dir(skills_dir)
    if not reports:
        console.print(f"[yellow]No skills found under {skills_dir}.[/yellow]")
        return

    table = Table(title="Validation Report")
    table.add_column("Skill", style="cyan")
    table.add_column("Status")
    table.add_column("Errors", justify="right")
    for r in reports:
        rel = r.path
        try:
            rel = r.path.relative_to(skills_dir)
        except ValueError:
            pass
        status = "[green]✓[/green]" if r.ok else "[red]✗[/red]"
        table.add_row(str(rel), status, str(len(r.errors)))
    console.print(table)

    failed = [r for r in reports if not r.ok]
    for r in failed:
        console.print(f"\n[red]{r.path}[/red]")
        for err in r.errors:
            console.print(f"  • {err}")

    sys.exit(0 if not failed else 1)


# ---------- index ----------

@cli.command()
@click.option(
    "--skills-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(SKILLS_DIR),
    show_default=True,
)
def index(skills_dir: Path) -> None:
    """Regenerate skills/README.md."""
    path = index_builder.write_index(skills_dir=skills_dir)
    console.print(f"[green]Wrote[/green] {path}")


if __name__ == "__main__":
    cli()
