"""Updater config — paths, thresholds, version-bump rules."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

_BASE = Path(__file__).parent.parent

DATA_DIR: Path = Path(os.getenv("DATA_DIR", _BASE / "data"))
SESSIONS_DIR: Path = Path(os.getenv("SESSIONS_DIR", DATA_DIR / "sessions"))
SKILLS_DIR: Path = Path(os.getenv("SKILLS_DIR", _BASE / "skills"))
LOG_DIR: Path = Path(os.getenv("LOG_DIR", DATA_DIR / "logs"))

# Claude Code task handoff (shared with PROMPTs 02-04)
CLAUDE_TASKS_DIR: Path = Path(os.getenv("CLAUDE_TASKS_DIR", DATA_DIR / "claude_tasks"))
PENDING_DIR: Path = Path(os.getenv("PENDING_DIR", CLAUDE_TASKS_DIR / "pending"))
COMPLETED_DIR: Path = Path(os.getenv("COMPLETED_DIR", CLAUDE_TASKS_DIR / "completed"))

# Knowledge graph (researcher-side; updater appends here too)
CHAIN_GRAPH_PATH: Path = Path(
    os.getenv("CHAIN_GRAPH_PATH", _BASE / "researcher" / "knowledge" / "chain_graph.json")
)

# Promotion threshold: a novel pattern needs this many distinct sessions to graduate.
MIN_PROMOTION_SESSIONS: int = int(os.getenv("MIN_PROMOTION_SESSIONS", "2"))

# Backups
MAX_BACKUPS_PER_SKILL: int = int(os.getenv("MAX_BACKUPS_PER_SKILL", "10"))

# Polling for the Claude Code synthesis task handoff
TASK_POLL_INTERVAL: float = float(os.getenv("TASK_POLL_INTERVAL", "2.0"))
TASK_TIMEOUT_SECONDS: float = float(os.getenv("TASK_TIMEOUT_SECONDS", "600.0"))

TASK_ID_PREFIX: str = "update"

# Section change → bump category
PATCH_SECTIONS: frozenset[str] = frozenset({
    "NOVEL_DISCOVERIES_LOG",
    "FAILED_APPROACHES",
    "ATTACK_CHAINS_DISCOVERED",
})
MINOR_SECTIONS: frozenset[str] = frozenset({
    "COMMON_PATTERNS",
    "PRECONDITIONS",
    "ASSUMPTIONS",
    "DETECTION_SIGNALS",
})
