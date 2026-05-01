"""Click CLI for the researcher agent.

Subcommands:
  start    Begin a new research session (scope-validated)
  resume   Continue an existing session
  end      Mark a session completed and write its result JSON
  graph    Show / inspect the chain knowledge graph
  summary  Show a single session's findings
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import click
from rich.console import Console
from rich.table import Table

from .config import (
    CHAIN_GRAPH_PATH,
    LOG_DIR,
    SESSIONS_DB,
    SESSIONS_DIR,
    SKILLS_DIR,
)
from .interface.display import print_brief, print_dashboard
from .interface.input_handler import collect_observation
from .knowledge.graph_manager import ChainGraph
from .prompts.session_brief import generate_session_brief
from .session.manager import (
    SessionExistsError,
    SessionManager,
    SessionNotFoundError,
)
from .session.models import (
    ChainStatus,
    ObservationType,
    SessionResult,
)
from .tools.scope_validator import OutOfScopeError, ScopeValidator
from .tools.session_logger import SessionLogger
from .tools.skill_patcher import SkillPatcher
from .tools.skill_reader import SkillNotFoundError, read_skill

console = Console()
logger = logging.getLogger(__name__)


def _setup_logging(ts: str) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    fmt = '{"ts":"%(asctime)s","level":"%(levelname)s","name":"%(name)s","msg":"%(message)s"}'
    logging.basicConfig(
        level=logging.INFO,
        format=fmt,
        handlers=[
            logging.FileHandler(LOG_DIR / f"researcher_{ts}.log"),
            logging.StreamHandler(sys.stderr),
        ],
        force=True,
    )


def _make_session_id(program: str) -> str:
    today = datetime.now().strftime("%Y%m%d")
    return f"{program.lower()}_{today}_{uuid.uuid4().hex[:6]}"


def _load_recon(path: Optional[Path]) -> dict[str, Any]:
    if path is None:
        return {}
    if not path.exists():
        console.print(f"[yellow]Recon file not found:[/yellow] {path}")
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        console.print(f"[red]Recon file is not valid JSON:[/red] {exc}")
        return {}


@click.group()
def cli() -> None:
    """Bug bounty researcher agent (Claude Code native)."""


# ---------- start ----------

@cli.command()
@click.option("--program", required=True, help="Program name (e.g., 'shopify')")
@click.option("--target", required=True, help="Target host or URL")
@click.option(
    "--scope",
    "scope_file",
    required=True,
    type=click.Path(path_type=Path, dir_okay=False),
    help="Path to scope.json",
)
@click.option("--skill", required=True, help="Skill identifier, e.g. 'ssrf/cloud-metadata'")
@click.option(
    "--recon",
    "recon_file",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="Path to recon JSON for this target",
)
@click.option(
    "--session-id",
    default=None,
    help="Override the auto-generated session id",
)
@click.option(
    "--skills-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(SKILLS_DIR),
    show_default=True,
)
@click.option(
    "--non-interactive",
    is_flag=True,
    default=False,
    help="Print the brief and exit (no observation prompt loop). Useful for scripted setup.",
)
def start(
    program: str,
    target: str,
    scope_file: Path,
    skill: str,
    recon_file: Optional[Path],
    session_id: Optional[str],
    skills_dir: Path,
    non_interactive: bool,
) -> None:
    """Begin a new research session against a single target."""
    ts = datetime.now().strftime("%Y%m%dT%H%M%S")
    _setup_logging(ts)
    asyncio.run(
        _run_start(
            program=program,
            target=target,
            scope_file=scope_file,
            skill_id=skill,
            recon_file=recon_file,
            session_id=session_id,
            skills_dir=skills_dir,
            non_interactive=non_interactive,
        )
    )


async def _run_start(
    *,
    program: str,
    target: str,
    scope_file: Path,
    skill_id: str,
    recon_file: Optional[Path],
    session_id: Optional[str],
    skills_dir: Path,
    non_interactive: bool,
) -> None:
    # ----- Hard scope gate. Cannot be bypassed. -----
    if not scope_file.exists():
        console.print(f"[red]Scope file not found:[/red] {scope_file}")
        sys.exit(1)
    try:
        validator = ScopeValidator.load(scope_file)
    except (FileNotFoundError, ValueError) as exc:
        console.print(f"[red]Invalid scope file:[/red] {exc}")
        sys.exit(1)
    try:
        validator.assert_in_scope(target)
    except OutOfScopeError as exc:
        console.print(f"[red]ABORT:[/red] {exc}")
        sys.exit(2)

    # ----- Load the skill -----
    try:
        bundle = read_skill(skill_id, skills_dir=skills_dir)
    except (SkillNotFoundError, ValueError) as exc:
        console.print(f"[red]Skill error:[/red] {exc}")
        sys.exit(1)

    sid = session_id or _make_session_id(program)
    session = SessionResult(
        session_id=sid,
        program=program,
        target=target,
        skill_used=bundle.skill_id,
        scope_file=str(scope_file),
        started_at=datetime.now(),
    )

    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    async with SessionManager(SESSIONS_DB) as manager:
        try:
            await manager.create_session(session)
        except SessionExistsError:
            console.print(
                f"[red]Session id already exists:[/red] {sid}. "
                "Use `resume` to continue it or pass a different --session-id."
            )
            sys.exit(1)

        recon = _load_recon(recon_file)
        graph = ChainGraph(CHAIN_GRAPH_PATH)
        suggestions = graph.get_chain_suggestions(bundle.skill_id, top_n=5)

        console.print(
            f"\n[green]Session created:[/green] {sid}  "
            f"[green]Scope:[/green] ✅  [green]Skill:[/green] {bundle.skill_id}\n"
        )

        await _show_state_and_brief(
            console=console,
            session=session,
            bundle=bundle,
            recon=recon,
            chain_suggestions=suggestions,
            scope_summary=validator.render_summary(),
            scope_validated=True,
        )

        if non_interactive:
            return

        await _interactive_loop(
            manager=manager,
            session_id=sid,
            skill_id=bundle.skill_id,
            skill_path=bundle.skill_path,
            scope_summary=validator.render_summary(),
            recon=recon,
            graph=graph,
        )


# ---------- resume ----------

@cli.command()
@click.option("--session-id", required=True)
@click.option(
    "--skills-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=str(SKILLS_DIR),
    show_default=True,
)
def resume(session_id: str, skills_dir: Path) -> None:
    """Resume an existing session — re-validates scope before continuing."""
    asyncio.run(_run_resume(session_id=session_id, skills_dir=skills_dir))


async def _run_resume(*, session_id: str, skills_dir: Path) -> None:
    async with SessionManager(SESSIONS_DB) as manager:
        try:
            session = await manager.get_session(session_id)
        except SessionNotFoundError:
            console.print(f"[red]Session not found:[/red] {session_id}")
            sys.exit(1)

        if session.status != "active":
            console.print(
                f"[yellow]Session {session_id} is {session.status!r}. "
                "Resuming will mark it active again.[/yellow]"
            )

        # Re-validate scope on resume — scope.json may have changed
        try:
            validator = ScopeValidator.load(session.scope_file)
            validator.assert_in_scope(session.target)
        except (FileNotFoundError, ValueError, OutOfScopeError) as exc:
            console.print(f"[red]Cannot resume — scope check failed:[/red] {exc}")
            sys.exit(2)

        try:
            bundle = read_skill(session.skill_used, skills_dir=skills_dir)
        except SkillNotFoundError as exc:
            console.print(f"[red]Skill no longer present:[/red] {exc}")
            sys.exit(1)

        graph = ChainGraph(CHAIN_GRAPH_PATH)
        suggestions = graph.get_chain_suggestions(session.skill_used, top_n=5)

        await _show_state_and_brief(
            console=console,
            session=session,
            bundle=bundle,
            recon={},
            chain_suggestions=suggestions,
            scope_summary=validator.render_summary(),
            scope_validated=True,
        )

        await _interactive_loop(
            manager=manager,
            session_id=session.session_id,
            skill_id=bundle.skill_id,
            skill_path=bundle.skill_path,
            scope_summary=validator.render_summary(),
            recon={},
            graph=graph,
        )


# ---------- end ----------

@cli.command()
@click.option("--session-id", required=True)
def end(session_id: str) -> None:
    """Mark the session completed; write data/sessions/<id>/result.json."""
    asyncio.run(_run_end(session_id=session_id))


async def _run_end(*, session_id: str) -> None:
    async with SessionManager(SESSIONS_DB) as manager:
        try:
            session = await manager.get_session(session_id)
        except SessionNotFoundError:
            console.print(f"[red]Session not found:[/red] {session_id}")
            sys.exit(1)

        await manager.end_session(session_id)
        session.status = "completed"
        session.ended_at = datetime.now()

        out_dir = SESSIONS_DIR / session_id
        out_dir.mkdir(parents=True, exist_ok=True)
        result_path = out_dir / "result.json"
        result_path.write_text(session.model_dump_json(indent=2), encoding="utf-8")

        console.print(f"[green]Session ended.[/green] Result written: {result_path}")
        console.print(
            f"\nNext: run the updater on this session — "
            f"[cyan]python -m updater.main update --session {result_path}[/cyan]"
        )


# ---------- graph ----------

@cli.command()
@click.option("--skill", default=None, help="Filter to chains involving this skill")
@click.option("--top", default=15, show_default=True, help="Top N chains to show")
def graph(skill: Optional[str], top: int) -> None:
    """Show the chain knowledge graph."""
    g = ChainGraph(CHAIN_GRAPH_PATH)
    rows = g.get_chain_suggestions(skill, top_n=top) if skill else g.get_top_chains(top_n=top)

    table = Table(title=f"Chain Graph ({'all' if not skill else skill})")
    table.add_column("From", style="cyan")
    table.add_column("To", style="cyan")
    table.add_column("Frequency", justify="right")
    table.add_column("Confidence")
    table.add_column("Last Seen")
    table.add_column("Combined Impact")
    if not rows:
        console.print("[yellow]Chain graph is empty.[/yellow]")
        return
    for r in rows:
        table.add_row(
            r.get("from_skill", "-"),
            r.get("to_skill", "-"),
            str(r.get("frequency", 0)),
            r.get("confidence", "-"),
            r.get("last_seen", "-"),
            (r.get("combined_impact") or "-")[:60],
        )
    console.print(table)


# ---------- summary ----------

@cli.command()
@click.option("--session-id", required=True)
def summary(session_id: str) -> None:
    """Print a session's observations, chains, and failed approaches."""
    asyncio.run(_run_summary(session_id))


async def _run_summary(session_id: str) -> None:
    async with SessionManager(SESSIONS_DB) as manager:
        try:
            session = await manager.get_session(session_id)
        except SessionNotFoundError:
            console.print(f"[red]Session not found:[/red] {session_id}")
            sys.exit(1)

    print_dashboard(console, session=session, scope_validated=True)

    if session.observations:
        t = Table(title="Observations")
        t.add_column("#", justify="right")
        t.add_column("Type")
        t.add_column("Skill")
        t.add_column("Description")
        for i, o in enumerate(session.observations, start=1):
            t.add_row(str(i), o.observation_type.value, o.related_skill, o.description[:80])
        console.print(t)

    if session.chains:
        t = Table(title="Chains")
        t.add_column("From → To")
        t.add_column("Status")
        t.add_column("Trigger")
        for c in session.chains:
            t.add_row(f"{c.from_skill} → {c.to_skill}", c.status.value, c.trigger[:60])
        console.print(t)

    if session.failed_approaches:
        t = Table(title="Failed approaches")
        t.add_column("Approach")
        t.add_column("Reason")
        for fa in session.failed_approaches:
            t.add_row(fa.approach[:60], fa.reason[:60])
        console.print(t)


# ---------- shared helpers ----------

async def _show_state_and_brief(
    *,
    console: Console,
    session: SessionResult,
    bundle: Any,
    recon: dict[str, Any],
    chain_suggestions: list[dict[str, Any]],
    scope_summary: str,
    scope_validated: bool,
) -> None:
    top_chain = chain_suggestions[0] if chain_suggestions else None
    print_dashboard(console, session=session, scope_validated=scope_validated, top_chain=top_chain)
    brief = generate_session_brief(
        skill_content=bundle.skill_md,
        session=session,
        recon_data=recon,
        chain_suggestions=chain_suggestions,
        observations_so_far=session.observations,
        scope_summary=scope_summary,
    )
    print_brief(console, brief)


async def _interactive_loop(
    *,
    manager: SessionManager,
    session_id: str,
    skill_id: str,
    skill_path: Path,
    scope_summary: str,
    recon: dict[str, Any],
    graph: ChainGraph,
) -> None:
    """Drive the structured observation REPL until the user quits."""
    sl = SessionLogger(manager)
    patcher = SkillPatcher()

    while True:
        observation_input = await collect_observation(console)
        if observation_input is None:
            console.print("[cyan]Exiting interactive loop. Run `end` when done.[/cyan]")
            return

        if observation_input.record_failed:
            await sl.log_failed_approach(
                session_id=session_id,
                approach=observation_input.description,
                reason=observation_input.failed_reason,
                skill=skill_id,
            )
            try:
                if patcher.append_failed_approach(
                    skill_path,
                    approach=observation_input.description,
                    reason=observation_input.failed_reason,
                    session_id=session_id,
                ):
                    await manager.append_skill_file_updated(session_id, str(skill_path))
            except Exception as exc:
                console.print(f"[yellow]Skill patch failed (non-fatal):[/yellow] {exc}")
        else:
            obs = await sl.log_observation(
                session_id=session_id,
                observation_type=observation_input.observation_type,
                description=observation_input.description,
                related_skill=skill_id,
                probe_description=observation_input.probe_description,
                chain_potential=observation_input.chain_potential,
            )

            # If novel, auto-patch the skill's NOVEL DISCOVERIES LOG
            if obs.observation_type == ObservationType.NOVEL:
                try:
                    if patcher.append_novel_discovery(
                        skill_path,
                        session_id=session_id,
                        discovery=obs.description,
                        chain_potential=obs.chain_potential or "-",
                    ):
                        await manager.append_skill_file_updated(session_id, str(skill_path))
                except Exception as exc:
                    console.print(f"[yellow]Skill patch failed (non-fatal):[/yellow] {exc}")

            # Chain observations get logged as a hypothetical ChainHypothesis
            if obs.observation_type == ObservationType.CHAIN and obs.chain_potential:
                chain = await sl.log_chain(
                    session_id=session_id,
                    chain_name=f"{skill_id} → {obs.chain_potential}",
                    from_skill=skill_id,
                    to_skill=obs.chain_potential,
                    trigger=obs.probe_description,
                    pivot=obs.description,
                    combined_impact="(to be determined)",
                    status=ChainStatus.HYPOTHETICAL,
                    evidence_observation_ids=[obs.observation_id],
                )
                graph.add_confirmed_chain(chain, session_id=session_id)
                try:
                    if patcher.append_chain(skill_path, chain):
                        await manager.append_skill_file_updated(session_id, str(skill_path))
                except Exception as exc:
                    console.print(f"[yellow]Skill patch failed (non-fatal):[/yellow] {exc}")

        # Refresh state and reprint the dashboard + brief
        session = await manager.get_session(session_id)
        try:
            bundle = read_skill(skill_id)
        except SkillNotFoundError:
            console.print("[red]Skill file vanished mid-session.[/red] Aborting loop.")
            return

        suggestions = graph.get_chain_suggestions(skill_id, top_n=5)
        await _show_state_and_brief(
            console=console,
            session=session,
            bundle=bundle,
            recon=recon,
            chain_suggestions=suggestions,
            scope_summary=scope_summary,
            scope_validated=True,
        )


if __name__ == "__main__":
    cli()
