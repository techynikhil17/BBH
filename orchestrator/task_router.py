"""Group pending Claude Code tasks by component and print run instructions.

Tasks land in ``data/claude_tasks/pending/``. Each component (extractor,
generator, updater, reporter) has its own ``process-tasks`` command. The
router scans the directory, classifies each pending task, and prints a
grouped summary so the operator knows which commands to run next.

Classification:
- Modern tasks tag themselves with ``task_type`` in the JSON body
  (skill_generation, skill_update, report_generation).
- The extractor predates that field — its tasks are detected via the
  ``task_id`` prefix used at write time (see component task_writers).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.table import Table

from .config import COMPLETED_DIR, PENDING_DIR

logger = logging.getLogger(__name__)


# Canonical task_type → component metadata
TASK_TYPE_MAP: dict[str, dict[str, str]] = {
    "extraction": {
        "component": "extractor",
        "command": "python -m extractor.main process-tasks",
    },
    "skill_generation": {
        "component": "generator",
        "command": "python -m generator.main process-tasks",
    },
    "skill_update": {
        "component": "updater",
        "command": "python -m updater.main process-tasks",
    },
    "report_generation": {
        "component": "reporter",
        "command": "python -m reporter.main process-tasks",
    },
}

# Fallback when the task body lacks a ``task_type`` — match on filename prefix.
_PREFIX_TO_TYPE: dict[str, str] = {
    "skillgen_": "skill_generation",
    "update_": "skill_update",
    "report_": "report_generation",
    # Extractor tasks have UUID-only filenames with no prefix; we treat any
    # otherwise-unclassified task as extraction so they get routed correctly.
}


@dataclass
class PendingTask:
    path: Path
    task_id: str
    task_type: str


class TaskRouter:
    """Classifies and reports pending Claude Code tasks."""

    def __init__(
        self,
        pending_dir: Path = PENDING_DIR,
        completed_dir: Path = COMPLETED_DIR,
    ) -> None:
        self._pending_dir = Path(pending_dir)
        self._completed_dir = Path(completed_dir)

    # ---------- classification ----------

    def classify(self, path: Path) -> Optional[PendingTask]:
        """Return a typed task descriptor or ``None`` if the file is unreadable."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("skipping unreadable task %s: %s", path, exc)
            return None

        task_id = str(data.get("task_id") or path.stem)
        task_type = str(data.get("task_type") or "").strip()

        if not task_type:
            task_type = _classify_by_prefix(path.stem)

        if not task_type:
            return None

        return PendingTask(path=path, task_id=task_id, task_type=task_type)

    def get_pending_tasks(self) -> dict[str, list[PendingTask]]:
        """Group all pending tasks by ``task_type``."""
        if not self._pending_dir.exists():
            return {}
        groups: dict[str, list[PendingTask]] = {}
        for path in sorted(self._pending_dir.glob("*.json")):
            task = self.classify(path)
            if task is None:
                continue
            groups.setdefault(task.task_type, []).append(task)
        return groups

    # ---------- presentation ----------

    def print_task_summary(self, console: Optional[Console] = None) -> None:
        """Render the grouped table the CLI shows for ``orchestrator tasks``."""
        console = console or Console()
        groups = self.get_pending_tasks()

        if not groups:
            console.print("[yellow]No pending tasks.[/yellow]")
            return

        table = Table(title="Pending Claude Code tasks")
        table.add_column("Task type", style="cyan")
        table.add_column("Count", justify="right")
        table.add_column("Component", style="magenta")
        table.add_column("Run command")

        for task_type, tasks in sorted(groups.items()):
            meta = TASK_TYPE_MAP.get(task_type, {})
            table.add_row(
                task_type,
                str(len(tasks)),
                meta.get("component", "?"),
                meta.get("command", "(unknown)"),
            )
        console.print(table)

    def route_all(self, console: Optional[Console] = None) -> dict[str, list[PendingTask]]:
        """Print the summary and return the grouping (handy for tests)."""
        self.print_task_summary(console)
        return self.get_pending_tasks()


def _classify_by_prefix(stem: str) -> str:
    for prefix, task_type in _PREFIX_TO_TYPE.items():
        if stem.startswith(prefix):
            return task_type
    # Anything without a known prefix: treat as extraction
    return "extraction"
