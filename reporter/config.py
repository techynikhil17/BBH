"""Reporter config — paths, output settings, polling defaults.

No model / API key. Claude Code IS the writer; reasoning hand-off uses the
same task-file pattern as PROMPTs 02-05.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

_BASE = Path(__file__).parent.parent

DATA_DIR: Path = Path(os.getenv("DATA_DIR", _BASE / "data"))
SESSIONS_DIR: Path = Path(os.getenv("SESSIONS_DIR", DATA_DIR / "sessions"))
REPORTS_DIR: Path = Path(os.getenv("REPORTS_DIR", DATA_DIR / "reports"))
LOG_DIR: Path = Path(os.getenv("LOG_DIR", DATA_DIR / "logs"))

# Claude Code task handoff (shared with the rest of the pipeline)
CLAUDE_TASKS_DIR: Path = Path(os.getenv("CLAUDE_TASKS_DIR", DATA_DIR / "claude_tasks"))
PENDING_DIR: Path = Path(os.getenv("PENDING_DIR", CLAUDE_TASKS_DIR / "pending"))
COMPLETED_DIR: Path = Path(os.getenv("COMPLETED_DIR", CLAUDE_TASKS_DIR / "completed"))

TEMPLATE_DIR: Path = Path(__file__).parent / "templates"

TASK_POLL_INTERVAL: float = float(os.getenv("TASK_POLL_INTERVAL", "2.0"))
TASK_TIMEOUT_SECONDS: float = float(os.getenv("TASK_TIMEOUT_SECONDS", "600.0"))

TASK_ID_PREFIX: str = "report"

SUPPORTED_PLATFORMS: tuple[str, ...] = ("hackerone", "bugcrowd", "generic")
DEFAULT_PLATFORM: str = "hackerone"
