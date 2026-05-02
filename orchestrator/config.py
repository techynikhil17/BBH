"""Master orchestrator configuration.

Single source of truth for paths and pipeline thresholds. Component-level
configs (extractor/config.py, etc.) read their own env vars; the
orchestrator never overrides those — it just provides the canonical view
of where everything lives.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR: Path = Path(__file__).parent.parent

# Layout
DATA_DIR: Path = Path(os.getenv("DATA_DIR", BASE_DIR / "data"))
RAW_DIR: Path = DATA_DIR / "raw"
PATTERNS_DIR: Path = DATA_DIR / "patterns"
SESSIONS_DIR: Path = DATA_DIR / "sessions"
REPORTS_DIR: Path = DATA_DIR / "reports"
RECON_DIR: Path = DATA_DIR / "recon"
LOGS_DIR: Path = DATA_DIR / "logs"
CLAUDE_TASKS_DIR: Path = Path(os.getenv("CLAUDE_TASKS_DIR", DATA_DIR / "claude_tasks"))
PENDING_DIR: Path = Path(os.getenv("PENDING_DIR", CLAUDE_TASKS_DIR / "pending"))
COMPLETED_DIR: Path = Path(os.getenv("COMPLETED_DIR", CLAUDE_TASKS_DIR / "completed"))
SKILLS_DIR: Path = Path(os.getenv("SKILLS_DIR", BASE_DIR / "skills"))
KNOWLEDGE_DIR: Path = BASE_DIR / "knowledge"

# Cross-component state
STATE_DB: Path = Path(os.getenv("ORCHESTRATOR_STATE_DB", DATA_DIR / "orchestrator_state.db"))
ACTIVE_SCOPE: Path = SESSIONS_DIR / "active_scope.json"

# Pipeline thresholds (mirrors per-component configs for the dashboard)
MIN_PATTERNS_FOR_SKILL: int = int(os.getenv("MIN_PATTERNS_FOR_SKILL", "2"))
PATTERN_PROMOTION_THRESHOLD: int = int(os.getenv("PATTERN_PROMOTION_THRESHOLD", "2"))
MAX_SKILL_BACKUPS: int = int(os.getenv("MAX_SKILL_BACKUPS", "10"))
TASK_POLL_INTERVAL_SECS: float = float(os.getenv("TASK_POLL_INTERVAL_SECS", "2"))
TASK_TIMEOUT_SECS: float = float(os.getenv("TASK_TIMEOUT_SECS", "300"))

# Recon helper command map (for the dashboard / docs only — actual recon lives
# in the recon/ package)
RECON_TOOLS: dict[str, str] = {
    "subfinder": "subfinder -d {domain} -silent",
    "httpx": "httpx -l {input} -silent -json",
    "katana": "katana -u {url} -silent",
    "gau": "gau {domain}",
}

# Version (shown on the dashboard header)
VERSION: str = "1.0.0"
