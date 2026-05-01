"""Runtime configuration for the skill generator.

File-based handoff to Claude Code (no API). Settings come from env vars via
python-dotenv with sensible defaults for the project layout.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

_BASE = Path(__file__).parent.parent

# Project data root
DATA_DIR: Path = Path(os.getenv("DATA_DIR", _BASE / "data"))

# Inputs
PATTERNS_JSONL: Path = Path(os.getenv("PATTERNS_JSONL", DATA_DIR / "patterns" / "patterns.jsonl"))

# Skill output root
SKILLS_DIR: Path = Path(os.getenv("SKILLS_DIR", _BASE / "skills"))
SKILLS_TEMPLATES_DIR: Path = SKILLS_DIR / "_templates"

# Claude Code task handoff (shared with PROMPT 02; namespacing via task_id prefix)
CLAUDE_TASKS_DIR: Path = Path(os.getenv("CLAUDE_TASKS_DIR", DATA_DIR / "claude_tasks"))
PENDING_DIR: Path = Path(os.getenv("PENDING_DIR", CLAUDE_TASKS_DIR / "pending"))
COMPLETED_DIR: Path = Path(os.getenv("COMPLETED_DIR", CLAUDE_TASKS_DIR / "completed"))

# Skip / overflow files
INSUFFICIENT_PATTERNS_JSONL: Path = Path(
    os.getenv("INSUFFICIENT_PATTERNS_JSONL", DATA_DIR / "insufficient_patterns.jsonl")
)
LOG_DIR: Path = Path(os.getenv("LOG_DIR", DATA_DIR / "logs"))

# Generator behavior
MIN_PATTERNS_PER_GROUP: int = int(os.getenv("MIN_PATTERNS_PER_GROUP", "2"))

# Polling
TASK_POLL_INTERVAL: float = float(os.getenv("TASK_POLL_INTERVAL", "2.0"))
TASK_TIMEOUT_SECONDS: float = float(os.getenv("TASK_TIMEOUT_SECONDS", "600.0"))

# Templates
TEMPLATE_DIR: Path = Path(__file__).parent / "templates"
SKILL_TEMPLATE_NAME: str = "skill_template.md"

# Validation thresholds
MIN_OVERVIEW_CHARS: int = 100
MIN_PRECONDITION_ITEMS: int = 3
MAX_PRECONDITION_ITEMS: int = 8

# Task ID prefix so generator tasks can be filtered from extractor tasks
TASK_ID_PREFIX: str = "skillgen"
