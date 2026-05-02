"""Rich-rendered system dashboard for ``orchestrator status``.

Pure presentation — pulls data from the state manager + scope enforcer +
task router and arranges it into a multi-panel layout. Renders gracefully
when the system is fresh (empty DB, no scope, no skills).
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from rich.columns import Columns
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .config import VERSION
from .scope_enforcer import ScopeEnforcer
from .state_manager import StateManager
from .task_router import TASK_TYPE_MAP, TaskRouter


async def render_dashboard(
    *,
    scope: Optional[ScopeEnforcer] = None,
    state: Optional[StateManager] = None,
    router: Optional[TaskRouter] = None,
) -> Group:
    """Build the dashboard panel group. Async because state queries are."""
    scope = scope or ScopeEnforcer()
    router = router or TaskRouter()

    summary: dict = {}
    history: list[dict] = []
    skill_stats: list[dict] = []
    chains: list[dict] = []
    if state is not None:
        summary = await state.get_system_summary()
        history = await state.get_pipeline_history(limit=5)
        skill_stats = await state.get_skill_stats()
        chains = await state.get_chain_stats(top_n=5)

    return Group(
        _header_panel(),
        Columns(
            [
                _scope_panel(scope),
                _pipeline_panel(summary, history),
            ],
            equal=True,
            expand=True,
        ),
        Columns(
            [
                _active_session_panel(summary),
                _pending_tasks_panel(router),
            ],
            equal=True,
            expand=True,
        ),
        _chain_panel(chains),
        _skill_library_panel(skill_stats, summary),
    )


async def print_dashboard(
    console: Console,
    *,
    scope: Optional[ScopeEnforcer] = None,
    state: Optional[StateManager] = None,
    router: Optional[TaskRouter] = None,
) -> None:
    group = await render_dashboard(scope=scope, state=state, router=router)
    console.print(group)


# ---------- panels ----------


def _header_panel() -> Panel:
    body = Text.from_markup(
        f"[bold cyan]Bug Bounty Skill System[/bold cyan]"
        f"                                                    v{VERSION}"
    )
    return Panel(body, border_style="cyan")


def _scope_panel(scope: ScopeEnforcer) -> Panel:
    if not scope.is_loaded() or scope.scope is None:
        body = Text.from_markup(
            "[red]Status: ✗ no active scope[/red]\n"
            "[dim]Run:[/dim] [magenta]python -m orchestrator.main load-scope --program X --file scope.json[/magenta]"
        )
        return Panel(body, title="[bold]SCOPE[/bold]", border_style="red")

    s = scope.scope
    in_scope_count = len(s.in_scope)
    out_scope_count = len(s.out_of_scope)
    body_lines = [
        f"[bold]Program:[/bold] {s.program}",
        f"[bold]Platform:[/bold] {s.platform or '-'}",
        f"[bold]Assets:[/bold] {in_scope_count} in-scope, {out_scope_count} excluded",
        f"[bold]Status:[/bold] [green]✓ Loaded[/green]",
    ]
    return Panel("\n".join(body_lines), title="[bold]SCOPE[/bold]", border_style="green")


def _pipeline_panel(summary: dict, history: list[dict]) -> Panel:
    stages = summary.get("stage_counts", {})

    def _stage_line(name: str, label: str) -> str:
        counts = stages.get(name, {})
        completed = counts.get("completed", 0)
        running = counts.get("running", 0)
        failed = counts.get("failed", 0)
        if completed and not running and not failed:
            return f"[green]✓[/green] {label}: {completed} runs"
        if running:
            return f"[yellow]→[/yellow] {label}: {running} in-flight, {completed} done"
        if failed:
            return f"[red]✗[/red] {label}: {failed} failed, {completed} done"
        return f"[dim]·[/dim] {label}: not yet run"

    rows = [
        _stage_line("collection", "Collection"),
        _stage_line("extraction", "Extraction"),
        _stage_line("skill_generation", "Skills"),
        _stage_line("session", "Sessions"),
        _stage_line("skill_update", "Updates"),
        _stage_line("report_generation", "Reports"),
    ]
    body = "\n".join(rows)
    return Panel(body, title="[bold]PIPELINE STATE[/bold]", border_style="cyan")


def _active_session_panel(summary: dict) -> Panel:
    sessions = summary.get("active_sessions", [])
    if not sessions:
        body = Text.from_markup("[dim]No active sessions.[/dim]")
        return Panel(body, title="[bold]ACTIVE SESSION[/bold]", border_style="cyan")

    s = sessions[0]
    body_lines = [
        f"[bold]ID:[/bold] {s.get('session_id', '-')}",
        f"[bold]Target:[/bold] {s.get('target', '-')}",
        f"[bold]Skill:[/bold] {s.get('skill', '-')}",
        f"[bold]Started:[/bold] {s.get('started_at', '-')}",
    ]
    if len(sessions) > 1:
        body_lines.append(f"[dim]+ {len(sessions) - 1} more active session(s)[/dim]")
    return Panel("\n".join(body_lines), title="[bold]ACTIVE SESSION[/bold]", border_style="cyan")


def _pending_tasks_panel(router: TaskRouter) -> Panel:
    groups = router.get_pending_tasks()
    if not groups:
        body = Text.from_markup("[green]No pending tasks.[/green]")
        return Panel(body, title="[bold]PENDING TASKS[/bold]", border_style="green")

    lines = []
    for task_type in ("extraction", "skill_generation", "skill_update", "report_generation"):
        count = len(groups.get(task_type, []))
        meta = TASK_TYPE_MAP.get(task_type, {})
        if count == 0:
            lines.append(f"[dim]{task_type}: 0[/dim]")
        else:
            lines.append(
                f"[yellow]{task_type}: {count}[/yellow] [dim]→[/dim] "
                f"{meta.get('command', '?')}"
            )
    # Any unknown task types
    for task_type, tasks in groups.items():
        if task_type in {"extraction", "skill_generation", "skill_update", "report_generation"}:
            continue
        lines.append(f"[red]{task_type}: {len(tasks)} (unknown)[/red]")

    return Panel("\n".join(lines), title="[bold]PENDING TASKS[/bold]", border_style="yellow")


def _chain_panel(chains: list[dict]) -> Panel:
    if not chains:
        body = Text.from_markup("[dim]Chain knowledge graph is empty.[/dim]")
        return Panel(
            body,
            title="[bold]TOP CHAIN OPPORTUNITIES[/bold]",
            border_style="cyan",
        )

    table = Table(show_header=True, header_style="bold")
    table.add_column("From")
    table.add_column("To")
    table.add_column("Freq", justify="right")
    table.add_column("Last Confirmed")
    table.add_column("Combined Impact")
    for c in chains[:5]:
        table.add_row(
            c.get("from_skill", "-"),
            c.get("to_skill", "-"),
            str(c.get("frequency", 0)),
            c.get("last_confirmed", "-") or "-",
            (c.get("combined_impact") or "-")[:50],
        )
    return Panel(
        table, title="[bold]TOP CHAIN OPPORTUNITIES[/bold]", border_style="cyan"
    )


def _skill_library_panel(skill_stats: list[dict], summary: dict) -> Panel:
    skill_count = summary.get("skill_count", 0)
    pattern_count = summary.get("pattern_count", 0)
    if not skill_stats:
        body = Text.from_markup(
            f"[dim]{skill_count} skills, {pattern_count} patterns recorded.[/dim]\n"
            "[dim]Last updated: -[/dim]"
        )
        return Panel(body, title="[bold]SKILL LIBRARY[/bold]", border_style="cyan")

    top = skill_stats[0]
    body_lines = [
        f"[bold]{skill_count} skills[/bold] · {pattern_count} patterns recorded",
        f"[dim]Most-recently updated:[/dim] {top.get('skill_path', '-')} "
        f"(v{top.get('version', '-')}) — {top.get('last_updated', '-')}",
    ]
    return Panel("\n".join(body_lines), title="[bold]SKILL LIBRARY[/bold]", border_style="cyan")
