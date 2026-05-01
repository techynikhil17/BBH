"""Runtime configuration for the researcher agent.

No model / API key — Claude Code IS the agent. Settings here cover paths,
session storage, and scope-enforcement defaults.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

_BASE = Path(__file__).parent.parent

DATA_DIR: Path = Path(os.getenv("DATA_DIR", _BASE / "data"))

# Session state
SESSIONS_DIR: Path = Path(os.getenv("SESSIONS_DIR", DATA_DIR / "sessions"))
SESSIONS_DB: Path = Path(os.getenv("SESSIONS_DB", SESSIONS_DIR / "sessions.db"))

# Recon inputs
RECON_DIR: Path = Path(os.getenv("RECON_DIR", DATA_DIR / "recon"))

# Skill library (output of PROMPT 03)
SKILLS_DIR: Path = Path(os.getenv("SKILLS_DIR", _BASE / "skills"))

# Knowledge graph
KNOWLEDGE_DIR: Path = Path(__file__).parent / "knowledge"
CHAIN_GRAPH_PATH: Path = Path(os.getenv("CHAIN_GRAPH_PATH", KNOWLEDGE_DIR / "chain_graph.json"))

LOG_DIR: Path = Path(os.getenv("LOG_DIR", DATA_DIR / "logs"))
