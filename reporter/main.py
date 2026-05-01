"""Click CLI for the bug bounty report generator.

Subcommands:
  generate         Generate a report for one finding
  generate-all     Generate reports for every confirmed finding in a session
  generate-chain   Render the chain template for one chain finding
  process-tasks    Print pending report tasks; poll for completions (run BY Claude Code)
  review           Print a saved report and re-run quality checks
  list             List reports already produced for a session
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
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from researcher.session.models import ChainHypothesis, ChainStatus, SessionResult

from .config import (
    COMPLETED_DIR,
    DEFAULT_PLATFORM,
    LOG_DIR,
    PENDING_DIR,
    REPORTS_DIR,
    SUPPORTED_PLATFORMS,
    TASK_ID_PREFIX,
    TASK_POLL_INTERVAL,
    TASK_TIMEOUT_SECONDS,
)
from .models import EscalationResult, Finding, ReportDraft
from .pipeline.chain_escalator import escalate
from .pipeline.cvss_calculator import calculate
from .pipeline.finding_loader import filter_findings, load_findings
from .pipeline.report_assembler import (
    assemble_chain_report,
    assemble_report,
)
from .pipeline.task_writer import build_task, make_task_id, write_task
from .validator import validate as run_validator

console = Console()
logger = logging.getLogger(__name__)


def _setup_logging(ts: str) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    fmt = '{"ts":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","msg":"%(message)s"}'
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.FileHandler(LOG_DIR / f"reporter_{ts}.log"),
            logging.StreamHandler(sys.stderr),
        ],
        force=True,
    )


def _load_session(path: Path) -> SessionResult:
    raw = json.loads(path.read_text(encoding="utf-8"))
    return SessionResult(**raw)


def _platform_check(platform: str) -> None:
    if platform not in SUPPORTED_PLATFORMS:
        console.print(
            f"[red]Unsupported platform:[/red] {platform}. "
            f"Supported: {', '.join(SUPPORTED_PLATFORMS)}"
        )
        sys.exit(2)


@click.group()
def cli() -> None:
    """Bug bounty report generator."""


# ---------- generate ----------

@cli.command()
@click.option(
    "--session",
    "session_path",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
)
@click.option("--finding", "finding_id", required=True, help="Finding id (e.g. F001_<session>)")
@click.option("--platform", default=DEFAULT_PLATFORM, show_default=True)
@click.option(
    "--output",
    "output_dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(REPORTS_DIR),
    show_default=True,
)
@click.option(
    "--no-wait",
    is_flag=True,
    default=False,
    help="Write the task and exit; do not poll for the completion",
)
@click.option("--timeout", type=float, default=TASK_TIMEOUT_SECONDS, show_default=True)
@click.option("--poll-interval", type=float, default=TASK_POLL_INTERVAL, show_default=True)
def generate(
    session_path: Path,
    finding_id: str,
    platform: str,
    output_dir: Path,
    no_wait: bool,
    timeout: float,
    poll_interval: float,
) -> None:
    """Generate a report for a single finding."""
    _platform_check(platform)
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    _setup_logging(ts)
    asyncio.run(
        _run_generate_one(
            session_path=session_path,
            finding_id=finding_id,
            platform=platform,
            output_dir=output_dir,
            no_wait=no_wait,
            timeout=timeout,
            poll_interval=poll_interval,
        )
    )


async def _run_generate_one(
    *,
    session_path: Path,
    finding_id: str,
    platform: str,
    output_dir: Path,
    no_wait: bool,
    timeout: float,
    poll_interval: float,
) -> None:
    session = _load_session(session_path)
    findings = filter_findings(load_findings(session), finding_id=finding_id)
    if not findings:
        console.print(f"[red]No finding {finding_id!r} in session {session.session_id}.[/red]")
        sys.exit(1)
    finding = findings[0]
    cvss = calculate(finding)
    finding.severity = cvss.severity_label.lower()
    escalation = _maybe_escalate(session, finding)

    task = build_task(finding, cvss, platform=platform, chain_escalation=escalation)
    write_task(task)
    console.print(f"\n[bold yellow]Wrote report task:[/bold yellow] [cyan]{PENDING_DIR / (task['task_id'] + '.json')}[/cyan]")
    console.print("[bold yellow]Run:[/bold yellow] [cyan]python -m reporter.main process-tasks[/cyan]")

    if no_wait:
        console.print("[yellow]--no-wait set; exiting without polling.[/yellow]")
        return

    completed_path = await _poll_one(task["task_id"], timeout=timeout, poll_interval=poll_interval)
    if completed_path is None:
        console.print("[red]Timed out waiting for Claude Code completion.[/red]")
        sys.exit(2)

    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        completion = json.loads(completed_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        console.print(f"[red]Completion file is not valid JSON:[/red] {exc}")
        sys.exit(2)

    try:
        draft = assemble_report(
            completion,
            finding,
            cvss,
            platform=platform,
            chain_escalation=escalation,
        )
    except ValueError as exc:
        console.print(f"[red]Failed to assemble report:[/red] {exc}")
        sys.exit(1)

    validation = run_validator(draft)
    draft.quality_flags = list(validation.flags)

    out_path = output_dir / f"{finding.finding_id}_{platform}.md"
    out_path.write_text(draft.rendered_markdown, encoding="utf-8")
    _print_report_panel(draft, out_path)

    # cleanup task pair on success
    try:
        completed_path.unlink(missing_ok=True)
        (PENDING_DIR / f"{task['task_id']}.json").unlink(missing_ok=True)
    except OSError:
        pass


# ---------- generate-all ----------

@cli.command("generate-all")
@click.option(
    "--session",
    "session_path",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
)
@click.option("--platform", default=DEFAULT_PLATFORM, show_default=True)
@click.option(
    "--output",
    "output_dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(REPORTS_DIR),
    show_default=True,
)
@click.option("--no-wait", is_flag=True, default=False)
@click.option("--timeout", type=float, default=TASK_TIMEOUT_SECONDS, show_default=True)
@click.option("--poll-interval", type=float, default=TASK_POLL_INTERVAL, show_default=True)
def generate_all(
    session_path: Path,
    platform: str,
    output_dir: Path,
    no_wait: bool,
    timeout: float,
    poll_interval: float,
) -> None:
    """Generate a report for every confirmed finding in a session."""
    _platform_check(platform)
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    _setup_logging(ts)
    asyncio.run(
        _run_generate_all(
            session_path=session_path,
            platform=platform,
            output_dir=output_dir,
            no_wait=no_wait,
            timeout=timeout,
            poll_interval=poll_interval,
        )
    )


async def _run_generate_all(
    *,
    session_path: Path,
    platform: str,
    output_dir: Path,
    no_wait: bool,
    timeout: float,
    poll_interval: float,
) -> None:
    session = _load_session(session_path)
    findings = filter_findings(load_findings(session))
    if not findings:
        console.print("[yellow]No confirmed findings in session.[/yellow]")
        return

    tasks_meta: list[tuple[Finding, dict, Optional[EscalationResult]]] = []
    for finding in findings:
        cvss = calculate(finding)
        finding.severity = cvss.severity_label.lower()
        escalation = _maybe_escalate(session, finding)
        task = build_task(finding, cvss, platform=platform, chain_escalation=escalation)
        write_task(task)
        tasks_meta.append((finding, task, escalation))

    console.print(
        f"\n[bold yellow]Wrote {len(tasks_meta)} task file(s).[/bold yellow] "
        "Run: [cyan]python -m reporter.main process-tasks[/cyan]"
    )

    if no_wait:
        return

    expected = {t["task_id"] for _, t, _ in tasks_meta}
    completed_ids = await _poll_many(expected, timeout=timeout, poll_interval=poll_interval)

    output_dir.mkdir(parents=True, exist_ok=True)
    succeeded = 0
    for finding, task, escalation in tasks_meta:
        if task["task_id"] not in completed_ids:
            continue
        completed_path = COMPLETED_DIR / f"{task['task_id']}.json"
        try:
            completion = json.loads(completed_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            continue
        cvss = calculate(finding)
        try:
            draft = assemble_report(
                completion, finding, cvss,
                platform=platform, chain_escalation=escalation,
            )
        except ValueError as exc:
            console.print(f"[red]{finding.finding_id}: {exc}[/red]")
            continue
        validation = run_validator(draft)
        draft.quality_flags = list(validation.flags)
        out_path = output_dir / f"{finding.finding_id}_{platform}.md"
        out_path.write_text(draft.rendered_markdown, encoding="utf-8")
        _print_report_panel(draft, out_path)
        try:
            completed_path.unlink(missing_ok=True)
            (PENDING_DIR / f"{task['task_id']}.json").unlink(missing_ok=True)
        except OSError:
            pass
        succeeded += 1

    console.print(f"\n[green]Generated {succeeded} report(s).[/green]")


# ---------- generate-chain ----------

@cli.command("generate-chain")
@click.option(
    "--session",
    "session_path",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
)
@click.option("--chain-id", required=True)
@click.option("--platform", default=DEFAULT_PLATFORM, show_default=True)
@click.option(
    "--output",
    "output_dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(REPORTS_DIR),
    show_default=True,
)
@click.option("--no-wait", is_flag=True, default=False)
@click.option("--timeout", type=float, default=TASK_TIMEOUT_SECONDS, show_default=True)
@click.option("--poll-interval", type=float, default=TASK_POLL_INTERVAL, show_default=True)
def generate_chain(
    session_path: Path,
    chain_id: str,
    platform: str,
    output_dir: Path,
    no_wait: bool,
    timeout: float,
    poll_interval: float,
) -> None:
    """Render the chain template for a single confirmed chain."""
    _platform_check(platform)
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    _setup_logging(ts)
    asyncio.run(
        _run_generate_chain(
            session_path=session_path,
            chain_id=chain_id,
            platform=platform,
            output_dir=output_dir,
            no_wait=no_wait,
            timeout=timeout,
            poll_interval=poll_interval,
        )
    )


async def _run_generate_chain(
    *,
    session_path: Path,
    chain_id: str,
    platform: str,
    output_dir: Path,
    no_wait: bool,
    timeout: float,
    poll_interval: float,
) -> None:
    session = _load_session(session_path)
    chain = next((c for c in session.chains if c.chain_id == chain_id), None)
    if chain is None or chain.status != ChainStatus.CONFIRMED:
        console.print(f"[red]No confirmed chain {chain_id!r} in session.[/red]")
        sys.exit(1)

    all_findings = load_findings(session)
    chain_findings = [f for f in all_findings if f.chain_id == chain_id and f.is_chain]
    if not chain_findings:
        # Build one on the fly from the chain object
        from .pipeline.finding_loader import _from_chain  # type: ignore[attr-defined]
        chain_findings = [_from_chain(session, chain, 1)]

    chain_finding = chain_findings[0]
    cvss = calculate(chain_finding)
    escalation = escalate(chain, base_severity=cvss.severity_label.lower())
    task = build_task(chain_finding, cvss, platform=platform, chain_escalation=escalation)
    write_task(task)
    console.print(f"\n[bold yellow]Wrote chain task:[/bold yellow] {task['task_id']}")
    console.print("[bold yellow]Run:[/bold yellow] [cyan]python -m reporter.main process-tasks[/cyan]")

    if no_wait:
        return

    completed_path = await _poll_one(task["task_id"], timeout=timeout, poll_interval=poll_interval)
    if completed_path is None:
        console.print("[red]Timed out.[/red]")
        sys.exit(2)
    completion = json.loads(completed_path.read_text(encoding="utf-8"))

    component_findings = [f for f in all_findings if not f.is_chain]
    try:
        draft = assemble_chain_report(
            completion,
            chain_finding=chain_finding,
            component_findings=component_findings,
            cvss=cvss,
            escalation=escalation,
        )
    except ValueError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)

    validation = run_validator(draft)
    draft.quality_flags = list(validation.flags)
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / f"{chain_finding.finding_id}_chain.md"
    out_path.write_text(draft.rendered_markdown, encoding="utf-8")
    _print_report_panel(draft, out_path, chain=True, escalation=escalation)


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
@click.option("--timeout", type=float, default=TASK_TIMEOUT_SECONDS, show_default=True)
@click.option("--poll-interval", type=float, default=TASK_POLL_INTERVAL, show_default=True)
@click.option("--no-wait", is_flag=True, default=False)
def process_tasks(
    pending_dir: Path,
    completed_dir: Path,
    timeout: float,
    poll_interval: float,
    no_wait: bool,
) -> None:
    """Print pending report-generation tasks; poll for completions."""
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
        console.print("[yellow]No pending report tasks.[/yellow]")
        return

    console.print(f"[cyan]Found {len(pending_files)} pending report task(s).[/cyan]\n")
    pending_ids: list[str] = []
    for path in pending_files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            console.print(f"[red]Skipping malformed task {path.name}:[/red] {exc}")
            continue
        task_id = data.get("task_id", path.stem)
        pending_ids.append(task_id)
        console.print(f"[bold magenta]===== TASK {task_id} =====[/bold magenta]")
        console.print(f"platform: [cyan]{data.get('platform', '?')}[/cyan]")
        console.print(f"finding: [cyan]{data.get('finding', {}).get('finding_id', '?')}[/cyan]")
        console.print(f"vuln_class: [cyan]{data.get('finding', {}).get('vuln_class', '?')}[/cyan]")
        console.print(f"target: [cyan]{data.get('finding', {}).get('target', '?')}[/cyan]")
        console.print(f"cvss: [cyan]{data.get('cvss', {}).get('base_score', '?')} {data.get('cvss', {}).get('severity_label', '?')}[/cyan]")
        if data.get("chain_escalation") and data["chain_escalation"].get("applied"):
            console.print(f"[bold]chain escalation:[/bold] {data['chain_escalation'].get('escalated_severity', '')}")
        console.print(f"Expected output: [cyan]{data.get('expected_output_path', '?')}[/cyan]\n")
        console.print("[bold]INSTRUCTION:[/bold]")
        console.print(data.get("instruction", ""))
        console.print(f"[bold magenta]===== END TASK {task_id} =====[/bold magenta]\n")

    if no_wait:
        console.print("[yellow]--no-wait set; exiting without polling.[/yellow]")
        return

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


# ---------- review ----------

@cli.command()
@click.option(
    "--report",
    "report_path",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
)
def review(report_path: Path) -> None:
    """Print a saved report and re-run the validator on its content."""
    text = report_path.read_text(encoding="utf-8")
    console.print(Panel(text, title=str(report_path), border_style="cyan"))
    # We can only validate a structural draft; for free-text re-validate the body
    # by treating it as the rendered_markdown of a synthetic draft.
    from .models import CVSSResult, ReportDraft
    draft = ReportDraft(
        finding_id="",
        session_id="",
        platform="generic",
        title="",
        summary="",
        vulnerability_details="",
        impact_analysis="",
        steps_to_reproduce="",
        proof_of_concept="",
        cvss=CVSSResult(vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", base_score=0.0, severity_label="None"),
        remediation="",
        rendered_markdown=text,
    )
    flags = run_validator(draft).flags
    if not flags:
        console.print("[green]No prohibited content detected in body.[/green]")
    else:
        console.print("[red]Body issues:[/red]")
        for f in flags:
            console.print(f"  - {f}")


# ---------- list ----------

@cli.command("list")
@click.option("--session-id", required=True)
@click.option(
    "--reports-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(REPORTS_DIR),
    show_default=True,
)
def list_reports(session_id: str, reports_dir: Path) -> None:
    """List reports already generated for ``session_id``."""
    if not reports_dir.exists():
        console.print("[yellow]No reports directory.[/yellow]")
        return
    matches = sorted(reports_dir.glob(f"*_{session_id}_*.md"))
    matches.extend(sorted(reports_dir.glob(f"*_chain.md")))
    if not matches:
        console.print(f"[yellow]No reports for {session_id}.[/yellow]")
        return
    table = Table(title=f"Reports for {session_id}")
    table.add_column("Filename", style="cyan")
    table.add_column("Size", justify="right")
    for p in matches:
        size = p.stat().st_size if p.exists() else 0
        table.add_row(p.name, f"{size}B")
    console.print(table)


# ---------- helpers ----------

def _maybe_escalate(session: SessionResult, finding: Finding) -> Optional[EscalationResult]:
    if not finding.is_chain or not finding.chain_id:
        return None
    chain = next((c for c in session.chains if c.chain_id == finding.chain_id), None)
    if chain is None or chain.status != ChainStatus.CONFIRMED:
        return None
    return escalate(chain, base_severity=finding.severity)


async def _poll_one(
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


async def _poll_many(
    expected_ids: set[str],
    *,
    timeout: float,
    poll_interval: float,
    completed_dir: Path = COMPLETED_DIR,
) -> set[str]:
    completed_dir.mkdir(parents=True, exist_ok=True)
    completed: set[str] = set()
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while completed != expected_ids:
        for tid in expected_ids - completed:
            if (completed_dir / f"{tid}.json").exists():
                completed.add(tid)
        if completed == expected_ids:
            break
        if loop.time() >= deadline:
            return completed
        await asyncio.sleep(poll_interval)
    return completed


def _print_report_panel(
    draft: ReportDraft,
    out_path: Path,
    *,
    chain: bool = False,
    escalation: Optional[EscalationResult] = None,
) -> None:
    label = f"Chain Report" if chain else "Report"
    body_lines = [
        f"[bold]Title:[/bold] {draft.title}",
        f"[bold]CVSS:[/bold] {draft.cvss.base_score:.1f} {draft.cvss.severity_label}    "
        f"[bold]Vector:[/bold] {draft.cvss.vector_string}",
        f"[bold]Platform:[/bold] {draft.platform}",
        f"[bold]Word count:[/bold] {draft.word_count}",
    ]
    if escalation and escalation.applied:
        body_lines.append(
            f"[bold magenta]Chain escalation:[/bold magenta] "
            f"{escalation.matched_rule} → {escalation.escalated_severity} "
            f"({escalation.reasoning})"
        )
    if draft.quality_flags:
        body_lines.append("\n[red]Quality flags:[/red]")
        body_lines.extend(f"  - {f}" for f in draft.quality_flags)
    else:
        body_lines.append("\n[green]No quality flags.[/green]")
    body_lines.append("\n[bold]Sections requiring human review (always):[/bold]")
    body_lines.extend(f"  - {note}" for note in draft.requires_human_review)
    body_lines.append(f"\n[green]Saved:[/green] {out_path}")
    console.print(Panel("\n".join(body_lines), title=label, border_style="cyan"))


if __name__ == "__main__":
    cli()
