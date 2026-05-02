"""Click CLI for the master orchestrator.

Subcommands:
  load-scope        Load and persist a scope.json (mandatory before any testing)
  recon             Run recon on a target (delegates to recon/main.py)
  select-skill      Print a structured brief Claude Code reads to recommend skills
  collect           Pass-through to collector (raw report scraping)
  extract           Pass-through to extractor (writes Claude Code tasks)
  generate-skills   Pass-through to generator (writes Claude Code tasks)
  tasks             Show all pending Claude Code tasks grouped by component
  status            Show the live system dashboard
  chains            Show the chain knowledge graph
  sessions          List sessions
  full-pipeline     Run every stage end-to-end with confirmation prompts
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from researcher.tools.scope_validator import OutOfScopeError

from .config import (
    ACTIVE_SCOPE,
    LOGS_DIR,
    RECON_DIR,
    SESSIONS_DIR,
    SKILLS_DIR,
    STATE_DB,
)
from .dashboard import print_dashboard
from .pipeline_manager import PipelineManager
from .scope_enforcer import ScopeEnforcer
from .state_manager import StateManager
from .task_router import TaskRouter

console = Console()
logger = logging.getLogger(__name__)


def _setup_logging(ts: str) -> None:
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        handlers=[
            logging.FileHandler(LOGS_DIR / f"orchestrator_{ts}.log"),
            logging.StreamHandler(sys.stderr),
        ],
        force=True,
    )


@click.group()
def cli() -> None:
    """Bug Bounty Skill System — Master Orchestrator."""


# ---------- Scope ----------


@cli.command("load-scope")
@click.option("--program", required=True, help="Program name (e.g. shopify)")
@click.option(
    "--file",
    "scope_file",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    help="Path to scope.json",
)
def load_scope(program: str, scope_file: Path) -> None:
    """Load and validate program scope. Required before any testing."""
    enforcer = ScopeEnforcer()
    try:
        scope = enforcer.load(program, scope_file)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Failed to load scope:[/red] {exc}")
        sys.exit(1)
    console.print(
        Panel(
            enforcer.get_scope_summary(),
            title=f"[green]Scope loaded for {scope.program}[/green]",
            border_style="green",
        )
    )
    console.print(f"[dim]Persisted to {ACTIVE_SCOPE}[/dim]")


@cli.command("scope")
def show_scope() -> None:
    """Show the active scope (or warn that none is loaded)."""
    enforcer = ScopeEnforcer()
    if not enforcer.is_loaded():
        console.print("[yellow]No active scope loaded.[/yellow]")
        console.print(
            "Run: [magenta]python -m orchestrator.main load-scope --program X --file scope.json[/magenta]"
        )
        sys.exit(1)
    console.print(Panel(enforcer.get_scope_summary(), title="Active scope"))


# ---------- Recon ----------


@cli.command()
@click.option("--target", required=True, help="Apex domain (e.g. shopify.com)")
@click.option(
    "--output",
    "output_dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(RECON_DIR),
    show_default=True,
)
@click.option("--quick", is_flag=True, default=False)
def recon(target: str, output_dir: Path, quick: bool) -> None:
    """Run recon on a target. Validates scope first; delegates to recon/main.py."""
    enforcer = ScopeEnforcer()
    if not enforcer.is_loaded():
        console.print("[red]No active scope loaded.[/red] Run load-scope first.")
        sys.exit(1)
    try:
        enforcer.assert_in_scope(target)
    except OutOfScopeError as exc:
        console.print(f"[red]ABORT:[/red] {exc}")
        sys.exit(2)

    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"{target.lower()}.json"

    cmd = [
        sys.executable, "-m", "recon.main", "run",
        "--target", target,
        "--scope", str(ACTIVE_SCOPE),
        "--output", str(output_path),
    ]
    if quick:
        cmd.append("--quick")
    rc = subprocess.run(cmd).returncode
    sys.exit(rc)


@cli.command("select-skill")
@click.option(
    "--recon",
    "recon_path",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
)
@click.option(
    "--skills-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(SKILLS_DIR),
    show_default=True,
)
def select_skill(recon_path: Path, skills_dir: Path) -> None:
    """Print a structured brief that Claude Code reads to recommend skills.

    The brief includes the recon snapshot, the available skill identifiers,
    and the top chain opportunities. Claude Code reads it and replies with
    a ranked list of skills to prioritize for this target.
    """
    try:
        recon_data = json.loads(recon_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        console.print(f"[red]Recon file unreadable:[/red] {exc}")
        sys.exit(1)

    available_skills: list[str] = []
    if skills_dir.exists():
        for path in sorted(skills_dir.rglob("skill.md")):
            if "_templates" in path.parts:
                continue
            try:
                slug = path.parent.name
                vuln_class = path.parent.parent.name
                available_skills.append(f"{vuln_class}/{slug}")
            except Exception:
                continue

    skill_lines = (
        [f"  • {s}" for s in available_skills]
        if available_skills
        else ["  (none — generate skills first)"]
    )
    body_lines = [
        "[bold]TARGET:[/bold]   " + recon_data.get("target", "-"),
        "[bold]SUBDOMAINS in scope:[/bold] "
        + str(len(recon_data.get("in_scope_subdomains", [])))
        + "    [bold]Live services:[/bold] "
        + str(len(recon_data.get("live_services", []))),
        "[bold]TECH STACK:[/bold] "
        + ", ".join(recon_data.get("tech_stack", []) or ["unknown"]),
        "",
        "[bold]AVAILABLE SKILLS:[/bold]",
        *skill_lines,
        "",
        "[bold]YOUR TASK:[/bold]",
        "Read the recon snapshot above and the chain knowledge graph "
        "(`orchestrator chains`). Recommend a ranked list of 3-5 "
        "skills to prioritize for this target. Justify each pick "
        "with one line referencing recon evidence.",
    ]
    console.print(
        Panel(
            "\n".join(body_lines),
            title="Skill Selection Brief (Claude Code: read this)",
            border_style="magenta",
        )
    )


# ---------- pipeline pass-throughs ----------


@cli.command()
@click.option("--sources", default="all", show_default=True)
@click.option("--limit", default=500, type=int, show_default=True)
def collect(sources: str, limit: int) -> None:
    """Run the report collector."""
    cmd = [sys.executable, "-m", "collector.main", "collect", "--limit", str(limit)]
    if sources != "all":
        for s in sources.split(","):
            cmd.extend(["--sources", s.strip()])
    sys.exit(subprocess.run(cmd).returncode)


@cli.command()
@click.option("--input", "input_path", required=True, type=click.Path(path_type=Path))
def extract(input_path: Path) -> None:
    """Run pattern extraction. Writes tasks for Claude Code."""
    cmd = [sys.executable, "-m", "extractor.main", "extract", "--input", str(input_path)]
    sys.exit(subprocess.run(cmd).returncode)


@cli.command("generate-skills")
@click.option("--input", "input_path", required=True, type=click.Path(path_type=Path))
@click.option("--output", default=str(SKILLS_DIR), show_default=True)
def generate_skills(input_path: Path, output: str) -> None:
    """Generate skill files. Writes tasks for Claude Code."""
    cmd = [
        sys.executable, "-m", "generator.main", "generate",
        "--input", str(input_path),
        "--output", output,
        "--no-wait",
    ]
    sys.exit(subprocess.run(cmd).returncode)


# ---------- tasks ----------


@cli.command()
def tasks() -> None:
    """Show all pending Claude Code tasks grouped by type with run commands."""
    TaskRouter().print_task_summary(console)


# ---------- status / monitoring ----------


@cli.command()
def status() -> None:
    """Show the live system dashboard."""
    asyncio.run(_run_status())


async def _run_status() -> None:
    enforcer = ScopeEnforcer()
    router = TaskRouter()
    async with StateManager(STATE_DB) as state:
        await print_dashboard(console, scope=enforcer, state=state, router=router)


@cli.command()
@click.option("--skill", default=None)
@click.option("--top", default=15, type=int, show_default=True)
def chains(skill: Optional[str], top: int) -> None:
    """Show the chain knowledge graph (filterable by skill)."""
    sys.exit(
        subprocess.run(
            [
                sys.executable, "-m", "researcher.main", "graph",
                *(["--skill", skill] if skill else []),
                "--top", str(top),
            ]
        ).returncode
    )


@cli.command()
def sessions() -> None:
    """List recent sessions."""
    asyncio.run(_run_sessions())


async def _run_sessions() -> None:
    async with StateManager(STATE_DB) as state:
        rows = await state.get_all_sessions(limit=50)

    if not rows:
        # Fall back to discovering sessions on disk if state DB is empty
        if SESSIONS_DIR.exists():
            for path in sorted(SESSIONS_DIR.glob("*/result.json")):
                rows.append(
                    {
                        "session_id": path.parent.name,
                        "program": "?",
                        "target": "?",
                        "skill": "?",
                        "status": "?",
                        "started_at": datetime.fromtimestamp(path.stat().st_mtime).isoformat(),
                    }
                )

    if not rows:
        console.print("[yellow]No sessions recorded yet.[/yellow]")
        return

    table = Table(title="Sessions")
    table.add_column("Session", style="cyan")
    table.add_column("Program")
    table.add_column("Target")
    table.add_column("Skill")
    table.add_column("Status")
    table.add_column("Started")
    for r in rows:
        table.add_row(
            r.get("session_id", "-"),
            r.get("program", "-"),
            r.get("target", "-"),
            r.get("skill", "-"),
            r.get("status", "-"),
            (r.get("started_at") or "-")[:19],
        )
    console.print(table)


# ---------- full pipeline ----------


@cli.command("full-pipeline")
@click.option("--program", required=True)
@click.option(
    "--scope",
    "scope_file",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
)
@click.option("--limit", default=50, type=int, show_default=True)
@click.option("--no-confirm", is_flag=True, default=False, help="Skip prompts between stages")
def full_pipeline(program: str, scope_file: Path, limit: int, no_confirm: bool) -> None:
    """Run all stages in sequence with confirmation prompts."""
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    _setup_logging(ts)
    pm = PipelineManager(console=console)
    results = pm.run_full_pipeline(
        program=program,
        scope_file=scope_file,
        limit=limit,
        confirm=not no_confirm,
    )
    table = Table(title="Pipeline Result")
    table.add_column("Stage", style="cyan")
    table.add_column("OK")
    table.add_column("Message")
    for r in results:
        table.add_row(r.stage, "[green]✓[/green]" if r.ok else "[red]✗[/red]", r.message[:60])
    console.print(table)


if __name__ == "__main__":
    cli()
