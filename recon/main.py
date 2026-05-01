"""Click CLI for the recon stage.

Subcommands:
  run    Run the full recon pipeline against a target
  show   Print a previously-generated recon.json
  list   List recon files on disk
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from .assembler import ReconAssembler
from .config import LOG_DIR, RECON_DIR
from .models import ReconResult
from .runners import (
    AssetfinderRunner,
    GauRunner,
    HttpxRunner,
    NucleiRunner,
    SubfinderRunner,
    WaybackurlsRunner,
)


console = Console()
logger = logging.getLogger(__name__)


def _setup_logging(ts: str) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s %(levelname)s %(name)s: %(message)s',
        handlers=[
            logging.FileHandler(LOG_DIR / f"recon_{ts}.log"),
            logging.StreamHandler(sys.stderr),
        ],
        force=True,
    )


@click.group()
def cli() -> None:
    """Recon automation — produces ``data/recon/<target>.json`` for the researcher."""


@cli.command()
@click.option("--target", required=True, help="Apex domain (e.g. shopify.com)")
@click.option(
    "--scope",
    "scope_file",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="scope.json — when provided, hosts outside scope are recorded but never probed",
)
@click.option("--program", default=None, help="Program name (recorded on the result)")
@click.option(
    "--output",
    "output_path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="Output path; defaults to data/recon/<target>.json",
)
@click.option(
    "--quick",
    is_flag=True,
    default=False,
    help="Skip nuclei + historical URL harvest (faster, lighter)",
)
@click.option("--no-nuclei", is_flag=True, default=False)
@click.option("--no-history", is_flag=True, default=False)
def run(
    target: str,
    scope_file: Optional[Path],
    program: Optional[str],
    output_path: Optional[Path],
    quick: bool,
    no_nuclei: bool,
    no_history: bool,
) -> None:
    """Run the full recon pipeline against ``target`` and write the result."""
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    _setup_logging(ts)

    if quick:
        no_nuclei = True
        no_history = True

    if scope_file and not scope_file.exists():
        console.print(f"[red]Scope file not found:[/red] {scope_file}")
        sys.exit(1)

    output_path = output_path or (RECON_DIR / f"{target.strip().lower()}.json")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    _print_tool_inventory()

    assembler = ReconAssembler()
    console.print(f"\n[cyan]Running recon on[/cyan] [bold]{target}[/bold]...")
    result = assembler.run(
        target,
        scope_file=scope_file,
        scope_program=program,
        with_nuclei=not no_nuclei,
        with_history=not no_history,
    )

    output_path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
    _print_result_summary(result, output_path)


@cli.command()
@click.option(
    "--input",
    "path",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
)
def show(path: Path) -> None:
    """Print a saved recon.json as a summary."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    result = ReconResult(**raw)
    _print_result_summary(result, path)


@cli.command("list")
@click.option(
    "--recon-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(RECON_DIR),
    show_default=True,
)
def list_recon(recon_dir: Path) -> None:
    """List recon files already on disk."""
    if not recon_dir.exists():
        console.print(f"[yellow]No recon directory at {recon_dir}.[/yellow]")
        return
    files = sorted(recon_dir.glob("*.json"))
    if not files:
        console.print("[yellow]No recon files yet.[/yellow]")
        return
    table = Table(title=f"Recon files in {recon_dir}")
    table.add_column("File", style="cyan")
    table.add_column("Size", justify="right")
    for f in files:
        table.add_row(f.name, f"{f.stat().st_size}B")
    console.print(table)


# ---------- helpers ----------

def _print_tool_inventory() -> None:
    """Show which recon tools are installed before kicking off."""
    runners = [
        SubfinderRunner(),
        AssetfinderRunner(),
        HttpxRunner(),
        NucleiRunner(),
        GauRunner(),
        WaybackurlsRunner(),
    ]
    table = Table(title="Tool inventory")
    table.add_column("Tool", style="cyan")
    table.add_column("Available")
    any_missing = False
    for r in runners:
        present = r.is_available()
        any_missing = any_missing or not present
        table.add_row(r.binary, "[green]✓[/green]" if present else "[red]✗[/red]")
    console.print(table)
    if any_missing:
        console.print(
            "[yellow]Some tools are missing. Run setup_env.sh or `go install` them.[/yellow]\n"
        )


def _print_result_summary(result: ReconResult, path: Path) -> None:
    body = [
        f"[bold]Target:[/bold] {result.target}",
        f"[bold]Subdomains:[/bold] {len(result.subdomains)} discovered "
        f"({len(result.in_scope_subdomains)} in-scope, "
        f"{len(result.out_of_scope_subdomains)} out-of-scope)",
        f"[bold]Live services:[/bold] {len(result.live_services)}",
        f"[bold]Tech stack:[/bold] {', '.join(result.tech_stack[:10]) or '-'}",
        f"[bold]Historical URLs:[/bold] {len(result.historical_urls)}",
        f"[bold]Fingerprint hits:[/bold] {len(result.nuclei_findings)}",
        f"[bold]Tools run:[/bold] {', '.join(result.tools_run) or '-'}",
        f"[bold]Tools skipped:[/bold] {', '.join(result.tools_skipped) or '-'}",
    ]
    if result.errors:
        body.append("[red]Errors:[/red]")
        body.extend(f"  - {e}" for e in result.errors)
    body.append(f"\n[green]Saved:[/green] {path}")
    console.print(Panel("\n".join(body), title="Recon Result", border_style="cyan"))

    if result.live_services:
        live_table = Table(title="Live services (top 15)")
        live_table.add_column("URL", style="cyan")
        live_table.add_column("Status", justify="right")
        live_table.add_column("Title")
        live_table.add_column("Tech")
        for s in result.live_services[:15]:
            live_table.add_row(
                s.url,
                str(s.status_code or "-"),
                (s.title or "-")[:40],
                ", ".join(s.tech[:5]),
            )
        console.print(live_table)


if __name__ == "__main__":
    cli()
