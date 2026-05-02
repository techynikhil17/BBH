"""Coordinate stage transitions across the pipeline.

The manager doesn't *call* the components directly — it shells out to their
already-built CLIs (``python -m extractor.main extract``, etc.). That keeps
each component independently runnable and avoids cross-imports producing
fragile coupling.

Design notes:
- Every method records a row in the orchestrator state DB so the dashboard
  can show per-stage status.
- Stages that hand off to Claude Code (extract / generate-skills / update /
  report) print clear "run process-tasks now" instructions and then return
  — they don't poll. The operator runs the next command interactively.
- The full-pipeline runner stops between stages and waits for confirmation,
  preventing accidental fan-out.
"""

from __future__ import annotations

import logging
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from rich.console import Console
from rich.prompt import Confirm

from .config import (
    PATTERNS_DIR,
    RAW_DIR,
    REPORTS_DIR,
    SESSIONS_DIR,
    SKILLS_DIR,
)
from .scope_enforcer import ScopeEnforcer
from .state_manager import StateManager

logger = logging.getLogger(__name__)


@dataclass
class StageResult:
    stage: str
    ok: bool
    message: str = ""
    artifacts: list[str] = field(default_factory=list)
    requires_claude_code: bool = False  # True when next step is process-tasks
    next_command: str = ""


class PipelineManager:
    """Drives stage-by-stage execution with operator-facing prompts."""

    def __init__(
        self,
        *,
        scope: Optional[ScopeEnforcer] = None,
        state: Optional[StateManager] = None,
        console: Optional[Console] = None,
    ) -> None:
        self._scope = scope or ScopeEnforcer()
        self._state = state  # may be None when caller doesn't want persistence
        self._console = console or Console()

    # ---------- per-stage helpers ----------

    def run_collection(
        self,
        sources: Iterable[str] = ("all",),
        limit: int = 500,
        no_review: bool = True,
    ) -> StageResult:
        """Pure-Python stage — invoke the collector CLI."""
        cmd = [sys.executable, "-m", "collector.main", "collect", "--limit", str(limit)]
        for src in sources:
            cmd.extend(["--sources", src])
        rc, out, err = _run(cmd)
        ok = rc == 0
        return StageResult(
            stage="collection",
            ok=ok,
            message=err if not ok else f"collected to {RAW_DIR / 'reports.jsonl'}",
            artifacts=[str(RAW_DIR / "reports.jsonl")] if ok else [],
        )

    def run_extraction(self, input_path: Path) -> StageResult:
        """Writes extraction tasks; operator runs ``process-tasks`` next."""
        cmd = [
            sys.executable, "-m", "extractor.main", "extract",
            "--input", str(input_path),
            "--no-review-novel", "--no-wait" if False else "--review-novel",
        ]
        # The extractor doesn't have an explicit --no-wait flag for `extract`;
        # it always polls. We surface that to the operator.
        self._console.print(
            "[cyan]The extractor will write tasks and wait for completions.[/cyan]\n"
            "[cyan]Run in another shell:[/cyan] [magenta]python -m extractor.main process-tasks[/magenta]"
        )
        rc, _, err = _run(cmd)
        return StageResult(
            stage="extraction",
            ok=rc == 0,
            message=err if rc != 0 else "extraction complete",
            artifacts=[str(PATTERNS_DIR / "patterns.jsonl")] if rc == 0 else [],
            requires_claude_code=True,
            next_command="python -m extractor.main process-tasks",
        )

    def run_skill_generation(
        self,
        input_path: Path = PATTERNS_DIR / "patterns.jsonl",
        skills_dir: Path = SKILLS_DIR,
    ) -> StageResult:
        cmd = [
            sys.executable, "-m", "generator.main", "generate",
            "--input", str(input_path),
            "--output", str(skills_dir),
            "--no-wait",
        ]
        rc, _, err = _run(cmd)
        return StageResult(
            stage="skill_generation",
            ok=rc == 0,
            message=err if rc != 0 else "tasks written; run process-tasks",
            artifacts=[str(skills_dir)] if rc == 0 else [],
            requires_claude_code=True,
            next_command="python -m generator.main process-tasks",
        )

    def run_session(self, *, args: list[str]) -> StageResult:
        """Pass-through to ``researcher.main start ...``.

        ``args`` is the literal argv tail (so callers compose the right
        ``--program`` / ``--target`` / etc.). Scope is re-validated by the
        researcher; we add an early gate here for clearer errors.
        """
        if not self._scope.is_loaded():
            return StageResult(
                stage="session",
                ok=False,
                message="no active scope — run `orchestrator.main load-scope` first",
            )
        cmd = [sys.executable, "-m", "researcher.main", "start", *args]
        rc, _, err = _run(cmd)
        return StageResult(
            stage="session",
            ok=rc == 0,
            message=err if rc != 0 else "session started",
        )

    def run_update(
        self,
        session_result: Path,
        *,
        skills_dir: Path = SKILLS_DIR,
        no_wait: bool = True,
    ) -> StageResult:
        cmd = [
            sys.executable, "-m", "updater.main", "update",
            "--session", str(session_result),
            "--skills-dir", str(skills_dir),
        ]
        if no_wait:
            cmd.append("--no-wait")
        rc, _, err = _run(cmd)
        return StageResult(
            stage="skill_update",
            ok=rc == 0,
            message=err if rc != 0 else "update tasks (if any) written",
            requires_claude_code=True,
            next_command="python -m updater.main process-tasks",
        )

    def run_report_generation(
        self,
        session_result: Path,
        *,
        platform: str = "hackerone",
        output_dir: Path = REPORTS_DIR,
        no_wait: bool = True,
    ) -> StageResult:
        cmd = [
            sys.executable, "-m", "reporter.main", "generate-all",
            "--session", str(session_result),
            "--platform", platform,
            "--output", str(output_dir),
        ]
        if no_wait:
            cmd.append("--no-wait")
        rc, _, err = _run(cmd)
        return StageResult(
            stage="report_generation",
            ok=rc == 0,
            message=err if rc != 0 else "report tasks written",
            requires_claude_code=True,
            next_command="python -m reporter.main process-tasks",
        )

    # ---------- full pipeline ----------

    def run_full_pipeline(
        self,
        *,
        program: str,
        scope_file: Path,
        sources: Iterable[str] = ("pentesterland", "medium"),
        limit: int = 50,
        confirm: bool = True,
    ) -> list[StageResult]:
        """Run every stage end-to-end with confirmation prompts between them.

        Stops at the scope gate when no scope is loaded. Each AI stage prints
        a ``process-tasks`` instruction; the operator runs that and confirms
        before the next stage proceeds.
        """
        results: list[StageResult] = []

        # Stage 0: scope
        if not self._scope.is_loaded():
            try:
                self._scope.load(program, scope_file)
                self._console.print(f"[green]Loaded scope for {program}.[/green]")
            except (FileNotFoundError, ValueError) as exc:
                results.append(StageResult("scope", ok=False, message=str(exc)))
                return results

        if confirm and not Confirm.ask("Proceed with collection?", default=True):
            return results
        results.append(self.run_collection(sources=sources, limit=limit))
        if not results[-1].ok:
            return results

        if confirm and not Confirm.ask(
            "Collection done. Run extraction (you will need to run process-tasks)?",
            default=True,
        ):
            return results
        results.append(self.run_extraction(RAW_DIR / "reports.jsonl"))

        if confirm and not Confirm.ask(
            "Did you run `python -m extractor.main process-tasks`? Continue with skill generation?",
            default=False,
        ):
            return results
        results.append(self.run_skill_generation())

        self._console.print(
            "\n[bold green]Full pipeline orchestration complete.[/bold green]"
        )
        self._console.print(
            "[cyan]Next: run a session via [/cyan]"
            "[magenta]python -m researcher.main start --program ... --target ... --scope ... --skill ...[/magenta]"
        )
        return results


def _run(cmd: list[str]) -> tuple[int, str, str]:
    """Subprocess helper. Inherits stdin/stdout/stderr so the operator sees
    the components' Rich panels and prompts directly."""
    try:
        completed = subprocess.run(cmd, check=False)
        return completed.returncode, "", ""
    except FileNotFoundError as exc:
        return 127, "", str(exc)
