"""Runtime configuration sourced from environment variables.

Read once at import time via `python-dotenv`. Modules import these constants
directly — no global mutable config object.

Note: this build uses a file-based handoff to Claude Code. There is no API
key or model setting — extraction prompts are dropped into PENDING_DIR for
Claude Code to pick up and complete.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

_BASE = Path(__file__).parent.parent

# Project data root
DATA_DIR: Path = Path(os.getenv("DATA_DIR", _BASE / "data"))

# File-based handoff dirs (replace direct API calls)
CLAUDE_TASKS_DIR: Path = Path(os.getenv("CLAUDE_TASKS_DIR", DATA_DIR / "claude_tasks"))
PENDING_DIR: Path = Path(os.getenv("PENDING_DIR", CLAUDE_TASKS_DIR / "pending"))
COMPLETED_DIR: Path = Path(os.getenv("COMPLETED_DIR", CLAUDE_TASKS_DIR / "completed"))

# Output paths
PATTERNS_DIR: Path = Path(os.getenv("PATTERNS_DIR", DATA_DIR / "patterns"))
PATTERNS_DB: Path = Path(os.getenv("PATTERNS_DB", PATTERNS_DIR / "patterns.db"))
PATTERNS_JSONL: Path = Path(os.getenv("PATTERNS_JSONL", PATTERNS_DIR / "patterns.jsonl"))
NOVEL_PATTERNS_JSONL: Path = Path(os.getenv("NOVEL_PATTERNS_JSONL", PATTERNS_DIR / "novel_patterns.jsonl"))
SKIPPED_JSONL: Path = Path(os.getenv("SKIPPED_JSONL", PATTERNS_DIR / "skipped.jsonl"))
LOG_DIR: Path = Path(os.getenv("LOG_DIR", DATA_DIR / "logs"))

# Concurrency / batching (file I/O — no API rate limits)
EXTRACTOR_BATCH_SIZE: int = int(os.getenv("EXTRACTOR_BATCH_SIZE", "10"))
EXTRACTOR_MAX_CONCURRENCY: int = int(os.getenv("EXTRACTOR_MAX_CONCURRENCY", "5"))
EXTRACTOR_MAX_TOKENS: int = int(os.getenv("EXTRACTOR_MAX_TOKENS", "2000"))
EXTRACTOR_RETRIES: int = int(os.getenv("EXTRACTOR_RETRIES", "3"))

# File handoff polling settings
TASK_POLL_INTERVAL: float = float(os.getenv("TASK_POLL_INTERVAL", "2.0"))
TASK_TIMEOUT_SECONDS: float = float(os.getenv("TASK_TIMEOUT_SECONDS", "300.0"))

# Validation thresholds
MIN_DETECTION_APPROACH_LEN: int = 50
MIN_EXTRACTION_CONFIDENCE: float = 0.4
NOVELTY_SIMILARITY_THRESHOLD: float = 0.85

# Default input from PROMPT 01
RAW_REPORTS_INPUT: Path = Path(os.getenv("JSONL_OUTPUT", DATA_DIR / "raw" / "reports.jsonl"))
