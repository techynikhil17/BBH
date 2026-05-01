"""Click CLI for the post-session skill updater.

Subcommands:
  update             Run the full post-session synthesis (Claude Code reasoning if needed)
  process-tasks      Print pending updater tasks for Claude Code; poll for completions
  promote            Manually promote a single pattern by id
  restore            Restore a skill from a backup
  history            Show backup history for a skill
  pending-promotion  List patterns that have been seen once and need 1 more session
  report             Print the most recent update report for a session
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

from researcher.session.models import ChainHypothesis, ChainStatus

from .backup.manager import BackupManager
from .config import (
    COMPLETED_DIR,
    LOG_DIR,
    PENDING_DIR,
    SESSIONS_DIR,
    SKILLS_DIR,
    TASK_ID_PREFIX,
    TASK_POLL_INTERVAL,
    TASK_TIMEOUT_SECONDS,
)
from .pipeline.chain_propagator import ChainPropagator
from .pipeline.diff_analyzer import DiffAnalyzer, DiffResult
from .pipeline.pattern_promoter import PatternPromoter
from .pipeline.session_reader import (
    InvalidSessionError,
    read_session,
)
from .pipeline.skill_writer import SkillWriter, WriteResult
from .pipeline.task_writer import build_task, needs_claude_code, write_task
from .report_generator import (
    ReportInputs,
    SkillUpdateRecord,
    render_report,
    write_report,
)


console = Console()
logger = logging.getLogger(__name__)


def _setup_logging(ts: str) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    fmt = '{"ts":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","msg":"%(message)s"}'
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.FileHandler(LOG_DIR / f"updater_{ts}.log"),
            logging.StreamHandler(sys.stderr),
        ],
        force=True,
    )


def _skill_md_path(skill_id: str, skills_dir: Path) -> Path:
    parts = [p for p in skill_id.split("/") if p]
    return skills_dir.joinpath(*parts, "skill.md")


@click.group()
def cli() -> None:
    """Post-session skill file updater."""


# ---------- update ----------

@cli.command()
@click.option(
    "--session",
    "session_path",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
)
@click.option(
    "--skills-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(SKILLS_DIR),
    show_default=True,
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Compute the diff and (Claude Code) tasks without writing files",
)
@click.option(
    "--no-wait",
    is_flag=True,
    default=False,
    help="Write tasks and exit without polling for completions",
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
    session_path: Path,
    skills_dir: Path,
    dry_run: bool,
    no_wait: bool,
    timeout: float,
    poll_interval: float,
) -> None:
    """Run the full post-session update for one session result."""
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    _setup_logging(ts)
    asyncio.run(
        _run_update(
            session_path=session_path,
            skills_dir=skills_dir,
            dry_run=dry_run,
            no_wait=no_wait,
            timeout=timeout,
            poll_interval=poll_interval,
        )
    )


async def _run_update(
    *,
    session_path: Path,
    skills_dir: Path,
    dry_run: bool,
    no_wait: bool,
    timeout: float,
    poll_interval: float,
) -> None:
    try:
        session = read_session(session_path)
    except (FileNotFoundError, InvalidSessionError) as exc:
        console.print(f"[red]Session error:[/red] {exc}")
        sys.exit(1)

    console.print(
        f"[cyan]Session:[/cyan] {session.session_id}  "
        f"[cyan]Skill:[/cyan] {session.skill_used}  "
        f"[cyan]Target:[/cyan] {session.target}"
    )

    skill_path = _skill_md_path(session.skill_used, skills_dir)
    if not skill_path.exists():
        console.print(f"[red]Skill file not found:[/red] {skill_path}")
        sys.exit(1)

    analyzer = DiffAnalyzer()
    diff = analyzer.analyze(session, skill_path)

    if diff.nothing_to_update:
        console.print("[yellow]Nothing to update — session confirmed existing patterns.[/yellow]")
        _emit_report(
            session=session,
            skill_records=[],
            propagation=None,
            pending_promotions=[],
            nothing_to_update_skills=[session.skill_used],
            diffs=[diff],
        )
        return

    _print_diff_summary(diff)

    # Hand off reasoning to Claude Code if needed.
    task = build_task(session, diff)
    task_output: Optional[dict] = None
    if task is not None:
        path = write_task(task)
        console.print(
            f"\n[bold yellow]Wrote updater task:[/bold yellow] [cyan]{path}[/cyan]"
        )
        console.print(
            "[bold yellow]Run:[/bold yellow] "
            "[cyan]python -m updater.main process-tasks[/cyan]"
        )

        if no_wait:
            console.print("[yellow]--no-wait set; exiting without polling.[/yellow]")
            return

        completed_path = await _poll_one_completion(
            task["task_id"], timeout=timeout, poll_interval=poll_interval
        )
        if completed_path is None:
            console.print("[red]Timed out waiting for Claude Code completion.[/red]")
            sys.exit(2)
        try:
            task_output = json.loads(completed_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            console.print(f"[red]Completion file not valid JSON:[/red] {exc}")
            sys.exit(2)
        # Cleanup task pair on success
        try:
            (PENDING_DIR / f"{task['task_id']}.json").unlink(missing_ok=True)
            completed_path.unlink(missing_ok=True)
        except OSError:
            pass

    # Apply Claude-Code-driven section updates (rows / lists / replace), if any.
    skill_records: list[SkillUpdateRecord] = []
    writer = SkillWriter()
    if task_output:
        write_result = writer.apply_update(skill_path, task_output, dry_run=dry_run)
        skill_records.append(
            SkillUpdateRecord.from_write_result(
                skill_id=session.skill_used,
                skill_path=str(skill_path),
                write=write_result,
                promoted_pattern_count=len(task_output.get("promoted_pattern_rows", []) or []),
            )
        )

        # Apply chain_entries from task output (per-skill markdown blocks)
        chain_entries: dict = task_output.get("chain_entries") or {}
        for target_skill, entry in chain_entries.items():
            target_path = _skill_md_path(target_skill, skills_dir)
            if not target_path.exists() or not entry:
                continue
            if dry_run:
                continue
            try:
                # Reuse the same primitive used by the writer
                content = target_path.read_text(encoding="utf-8")
                new_content = SkillWriter._replace_section(  # type: ignore[attr-defined]
                    content, "## ATTACK CHAINS DISCOVERED", entry.strip()
                )
                if new_content and new_content != content:
                    BackupManager().create(target_path)
                    target_path.write_text(new_content, encoding="utf-8")
            except Exception as exc:
                console.print(f"[yellow]Chain entry for {target_skill} failed:[/yellow] {exc}")

    # Propagate confirmed chains via the patcher (parallel mechanism — different sections).
    propagation = ChainPropagator(skills_dir=skills_dir).propagate(
        [c for c in session.chains if c.status == ChainStatus.CONFIRMED]
    ) if not dry_run else None

    # Collect pending promotions for the report
    promoter = PatternPromoter()
    status = promoter.status_for_skill(session.skill_used)
    pending = [
        {
            "description": p.representative_description,
            "session_count": p.session_count,
            "related_skill": p.related_skill,
        }
        for p in status.pending
    ]

    _emit_report(
        session=session,
        skill_records=skill_records,
        propagation=propagation,
        pending_promotions=pending,
        nothing_to_update_skills=[],
        diffs=[diff],
    )

    console.print(
        f"\n[green]Update complete.[/green] "
        f"Sections changed: {sum(len(r.sections_changed) for r in skill_records)}  "
        f"Chains propagated: {propagation.chains_propagated if propagation else 0}"
    )


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
)
def process_tasks(
    pending_dir: Path,
    completed_dir: Path,
    timeout: float,
    poll_interval: float,
    no_wait: bool,
) -> None:
    """Print pending updater tasks; poll for completions."""
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
        console.print("[yellow]No pending updater tasks.[/yellow]")
        return

    console.print(f"[cyan]Found {len(pending_files)} pending updater task(s).[/cyan]\n")

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

        console.print(f"[bold magenta]===== TASK {task_id} =====[/bold magenta]")
        console.print(f"skill_path: [cyan]{data.get('skill_path', '?')}[/cyan]")
        console.print(f"session_id: [cyan]{data.get('session_id', '?')}[/cyan]")
        console.print(f"Expected output: [cyan]{expected_output}[/cyan]\n")
        console.print("[bold]INSTRUCTION:[/bold]")
        console.print(data.get("instruction", ""))
        console.print(f"[bold magenta]===== END TASK {task_id} =====[/bold magenta]\n")

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
    ) as progress:
        pid = progress.add_task("complete", total=len(pending_set))
        while completed != pending_set:
            for tid in pending_set - completed:
                if (completed_dir / f"{tid}.json").exists():
                    completed.add(tid)
                    progress.update(pid, advance=1)
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


async def _poll_one_completion(
    task_id: str,
    *,
    timeout: float,
    poll_interval: float,
    completed_dir: Path = COMPLETED_DIR,
) -> Optional[Path]:
    completed_dir.mkdir(parents=True, exist_ok=True)
    expected = completed_dir / f"{task_id}.json"
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while True:
        if expected.exists():
            return expected
        if loop.time() >= deadline:
            return None
        await asyncio.sleep(poll_interval)


# ---------- promote ----------

@cli.command()
@click.option("--pattern-id", required=True, help="Identifier echoed back from `pending-promotion`")
@click.option("--skill", required=True, help="Skill identifier, e.g. ssrf/cloud-metadata")
@click.option(
    "--skills-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(SKILLS_DIR),
    show_default=True,
)
def promote(pattern_id: str, skill: str, skills_dir: Path) -> None:
    """Manually promote a single pending pattern.

    Lists matching patterns from ``pending-promotion``; the operator copies the
    pattern_id (here we use the normalized description prefix). Skipping the
    promotion threshold is intentional and audit-logged.
    """
    promoter = PatternPromoter()
    status = promoter.status_for_skill(skill)
    candidates = status.pending + status.promotable
    match = next(
        (
            p for p in candidates
            if p.normalized_description.startswith(pattern_id)
            or p.representative_description.startswith(pattern_id)
        ),
        None,
    )
    if match is None:
        console.print(f"[red]No pattern matching id {pattern_id!r} for skill {skill}.[/red]")
        sys.exit(1)

    skill_path = _skill_md_path(skill, skills_dir)
    if not skill_path.exists():
        console.print(f"[red]Skill not found:[/red] {skill_path}")
        sys.exit(1)

    row = (
        f"| {match.representative_description} (manually promoted) | "
        f"{match.session_count} | - | "
        f"{', '.join(match.probe_examples[:1]) if match.probe_examples else '-'} | "
        f"- |"
    )
    writer = SkillWriter()
    result: WriteResult = writer.apply_update(
        skill_path,
        {"promoted_pattern_rows": [row]},
        dry_run=False,
    )
    if not result.success:
        console.print(f"[red]Promotion failed:[/red] {result.errors}")
        sys.exit(1)
    console.print(
        f"[green]Promoted.[/green] {skill}: {result.bump.old_version} → {result.bump.new_version}"
        if result.bump else "[green]Promoted.[/green]"
    )


# ---------- restore ----------

@cli.command()
@click.option("--skill", required=True)
@click.option("--timestamp", required=True, help="Backup timestamp YYYYMMDD_HHMMSS")
@click.option(
    "--skills-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(SKILLS_DIR),
    show_default=True,
)
def restore(skill: str, timestamp: str, skills_dir: Path) -> None:
    """Restore a skill from a specific backup timestamp."""
    skill_path = _skill_md_path(skill, skills_dir)
    if not skill_path.exists():
        console.print(f"[red]Skill not found:[/red] {skill_path}")
        sys.exit(1)
    backups = BackupManager()
    try:
        backup_path = backups.find_backup(skill_path, timestamp)
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)
    backups.restore(skill_path, backup_path)
    console.print(f"[green]Restored {skill} from {backup_path.name}[/green]")


# ---------- history ----------

@cli.command()
@click.option("--skill", required=True)
@click.option(
    "--skills-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(SKILLS_DIR),
    show_default=True,
)
def history(skill: str, skills_dir: Path) -> None:
    """Show backup timestamps for a skill."""
    skill_path = _skill_md_path(skill, skills_dir)
    if not skill_path.exists():
        console.print(f"[red]Skill not found:[/red] {skill_path}")
        sys.exit(1)
    backups = BackupManager().list_backups(skill_path)
    if not backups:
        console.print(f"[yellow]No backups for {skill}.[/yellow]")
        return
    table = Table(title=f"Backups for {skill}")
    table.add_column("Timestamp")
    table.add_column("Path")
    for b in backups:
        table.add_row(b.timestamp.isoformat(timespec="seconds"), str(b.backup_path))
    console.print(table)


# ---------- pending-promotion ----------

@cli.command("pending-promotion")
@click.option("--skill", default=None, help="Filter to one skill")
def pending_promotion(skill: Optional[str]) -> None:
    """List patterns that have been seen once and need 1 more session."""
    promoter = PatternPromoter()
    status_map = promoter.all_status() if skill is None else {skill: promoter.status_for_skill(skill)}

    rows: list[tuple[str, int, str]] = []
    for skill_id, status in status_map.items():
        for p in status.pending:
            rows.append((p.representative_description, p.session_count, skill_id))

    if not rows:
        console.print("[yellow]No patterns pending promotion.[/yellow]")
        return

    table = Table(title="Pending promotion")
    table.add_column("Pattern", style="cyan")
    table.add_column("Sessions", justify="right")
    table.add_column("Skill")
    for pattern, count, sk in rows:
        table.add_row(pattern[:80], str(count), sk)
    console.print(table)


# ---------- report ----------

@cli.command()
@click.option("--session-id", required=True)
def report(session_id: str) -> None:
    """Print the most recent update report for a session."""
    path = SESSIONS_DIR / session_id / "update_report.md"
    if not path.exists():
        console.print(f"[red]No update report at {path}.[/red] Run `update` first.")
        sys.exit(1)
    console.print(path.read_text(encoding="utf-8"))


# ---------- helpers ----------

def _print_diff_summary(diff: DiffResult) -> None:
    table = Table(title="Diff summary")
    table.add_column("Bucket", style="cyan")
    table.add_column("Count", justify="right")
    table.add_row("Novel observations not yet logged", str(len(diff.novel_observations)))
    table.add_row("Confirmed chains not yet logged", str(len(diff.confirmed_chains)))
    table.add_row("Failed approaches not yet logged", str(len(diff.failed_approaches)))
    table.add_row("Promotable patterns", str(len(diff.promotable_patterns)))
    table.add_row("Pending patterns", str(len(diff.pending_patterns)))
    table.add_row("Needs structural update", "yes" if diff.needs_structural_update else "no")
    console.print(table)


def _emit_report(
    *,
    session,
    skill_records,
    propagation,
    pending_promotions,
    nothing_to_update_skills,
    diffs,
) -> None:
    inputs = ReportInputs(
        session=session,
        skill_records=skill_records,
        propagation=propagation,
        pending_promotions=pending_promotions,
        nothing_to_update_skills=nothing_to_update_skills,
        diffs=diffs,
        timestamp=datetime.now(timezone.utc),
    )
    path = write_report(inputs, sessions_dir=SESSIONS_DIR)
    console.print(f"[green]Report:[/green] {path}")


if __name__ == "__main__":
    cli()
