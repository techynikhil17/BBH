"""Rich-based dashboard panel for the live research session."""

from __future__ import annotations

from typing import Optional

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..session.models import SessionResult


def render_dashboard(
    *,
    session: SessionResult,
    scope_validated: bool,
    top_chain: Optional[dict] = None,
) -> Panel:
    """Render the live status panel.

    The panel summarizes session identity, counters, and the top chain
    opportunity — meant to be redrawn after every observation.
    """
    header = Table.grid(padding=(0, 2))
    header.add_column(justify="left")
    header.add_column(justify="right")
    header.add_row(
        Text("Bug Bounty Researcher", style="bold cyan"),
        Text(f"Session: {session.session_id}", style="bold"),
    )
    header.add_row(
        Text(f"Program: {session.program}    Target: {session.target}"),
        Text(),
    )
    header.add_row(
        Text(f"Skill: {session.skill_used}"),
        Text(
            "Scope: ✅ Validated" if scope_validated else "Scope: ❌ Not validated",
            style="green" if scope_validated else "red",
        ),
    )

    counters = Table.grid(padding=(0, 4))
    counters.add_column(justify="left")
    counters.add_column(justify="left")
    counters.add_column(justify="left")
    counters.add_column(justify="left")
    counters.add_column(justify="left")
    counters.add_row(
        Text(f"Observations: {len(session.observations)}", style="cyan"),
        Text(f"Novel: {sum(1 for o in session.observations if o.observation_type == 'novel')}", style="magenta"),
        Text(f"Chains: {len(session.chains)}", style="yellow"),
        Text(f"Failed: {len(session.failed_approaches)}", style="red"),
        Text(
            f"Skill updates: {len(session.skill_files_updated)}",
            style="green",
        ),
    )

    if top_chain:
        chain_line = Text(
            f"{top_chain.get('from_skill', '?')} → {top_chain.get('to_skill', '?')}    "
            f"freq:{top_chain.get('frequency', 0)}    "
            f"{top_chain.get('confidence', '-')}",
            style="bold yellow",
        )
    else:
        chain_line = Text("(no chain suggestions yet)", style="dim")

    chain_block = Group(
        Text("Top Chain Opportunity:", style="bold"),
        chain_line,
    )

    return Panel(
        Group(header, Text(""), counters, Text(""), chain_block),
        title="[bold]Researcher Dashboard[/]",
        border_style="cyan",
    )


def print_dashboard(
    console: Console,
    *,
    session: SessionResult,
    scope_validated: bool,
    top_chain: Optional[dict] = None,
) -> None:
    console.print(render_dashboard(
        session=session,
        scope_validated=scope_validated,
        top_chain=top_chain,
    ))


def print_brief(console: Console, brief: str) -> None:
    """Print the research brief in a panel so Claude Code can lift it from output."""
    console.print(
        Panel(
            brief,
            title="[bold]RESEARCH BRIEF (Claude Code: read this and propose the next probe)[/]",
            border_style="magenta",
        )
    )
