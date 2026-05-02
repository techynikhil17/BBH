from __future__ import annotations

import asyncio
import logging
import sys
from datetime import datetime, timezone
from typing import Optional

import click
from rich.console import Console
from rich.live import Live
from rich.table import Table

from .config import ALL_SOURCES, DB_PATH, JSONL_OUTPUT, LOG_DIR
from .sources.github_writeups import GitHubWriteupsCollector
from .sources.hackerone import HackerOneCollector
from .sources.medium_rss import MediumRSSCollector
from .storage import Storage

console = Console()

# Active collectors only. The Bugcrowd and Pentesterland modules still live
# under ``collector/sources/`` (and their unit tests still pass) but they're
# not invokable from the CLI — see ``DEPRECATED_SOURCES`` in config.py for
# the rationale (Bugcrowd: no public title/description content;
# Pentesterland: site dormant since 2022).
_COLLECTORS = {
    "hackerone": HackerOneCollector,
    "github": GitHubWriteupsCollector,
    "medium": MediumRSSCollector,
}


def get_collector(name: str):
    if name not in _COLLECTORS:
        raise click.BadParameter(f"Unknown source '{name}'. Choose from: {', '.join(ALL_SOURCES)}")
    return _COLLECTORS[name]()


def _setup_logging(ts: str) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    fmt = '{"ts":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","msg":"%(message)s"}'
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.FileHandler(LOG_DIR / f"collection_{ts}.log"),
            logging.FileHandler(LOG_DIR / "collection_errors.log"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def _progress_table(stats: dict[str, dict]) -> Table:
    table = Table(title="Collection Progress", show_lines=False)
    table.add_column("Source", style="cyan", width=18)
    table.add_column("Status", width=10)
    table.add_column("New", justify="right", style="green", width=6)
    table.add_column("Dups", justify="right", style="yellow", width=6)

    total_new = total_dups = 0
    status_styles = {
        "running": "[blue]running[/]",
        "done": "[green]done[/]",
        "error": "[red]error[/]",
        "pending": "[dim]pending[/]",
    }
    for src, s in stats.items():
        table.add_row(src, status_styles.get(s["status"], s["status"]), str(s["new"]), str(s["dups"]))
        total_new += s["new"]
        total_dups += s["dups"]

    table.caption = f"Total new: {total_new}  |  Dups skipped: {total_dups}"
    return table


@click.group()
def cli() -> None:
    pass


@cli.command()
@click.option("--sources", "-s", multiple=True, default=("all",),
              help="Source names (repeat flag) or 'all'. E.g. --sources hackerone --sources bugcrowd")
@click.option("--limit", "-l", default=500, show_default=True, help="Max reports per source")
@click.option("--output", "-o", default=None, help="JSONL output path")
def collect(sources: tuple[str, ...], limit: int, output: Optional[str]) -> None:
    """Collect bug bounty reports from public sources."""
    source_names = ALL_SOURCES if "all" in sources else list(sources)
    for name in source_names:
        if name not in _COLLECTORS:
            raise click.BadParameter(f"Unknown source: '{name}'")
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    _setup_logging(ts)
    out = output or str(JSONL_OUTPUT)
    asyncio.run(_collect(source_names, limit, out))


async def _collect(names: list[str], limit: int, out: str) -> None:
    stats = {n: {"status": "pending", "new": 0, "dups": 0} for n in names}

    async with Storage(str(DB_PATH)) as storage:
        with Live(_progress_table(stats), refresh_per_second=4, console=console) as live:

            async def run_one(name: str) -> None:
                stats[name]["status"] = "running"
                live.update(_progress_table(stats))
                try:
                    async for report in get_collector(name).collect(limit):
                        is_new = await storage.save_report(report)
                        key = "new" if is_new else "dups"
                        stats[name][key] += 1
                        live.update(_progress_table(stats))
                    stats[name]["status"] = "done"
                except Exception as exc:
                    logging.getLogger(__name__).error("Source %s failed: %s", name, exc, exc_info=True)
                    stats[name]["status"] = "error"
                live.update(_progress_table(stats))

            await asyncio.gather(*[run_one(n) for n in names], return_exceptions=True)

        count = await storage.export_to_jsonl(out)
        console.print(f"\n[green]Exported {count} reports → {out}[/green]")


@cli.command()
@click.option("--format", "fmt", default="jsonl", type=click.Choice(["jsonl"]), show_default=True)
@click.option("--output", "-o", default=None, help="Output path")
def export(fmt: str, output: Optional[str]) -> None:
    """Export stored reports to JSONL."""
    out = output or str(JSONL_OUTPUT)
    asyncio.run(_export(out))


async def _export(out: str) -> None:
    async with Storage(str(DB_PATH)) as storage:
        count = await storage.export_to_jsonl(out)
    console.print(f"Exported {count} reports → {out}")


@cli.command()
def stats() -> None:
    """Show collection statistics."""
    asyncio.run(_stats())


async def _stats() -> None:
    async with Storage(str(DB_PATH)) as storage:
        s = await storage.get_stats()
    table = Table(title="Collection Stats")
    table.add_column("Source")
    table.add_column("Count", justify="right")
    for k, v in s.items():
        table.add_row(k, str(v))
    console.print(table)


if __name__ == "__main__":
    cli()
