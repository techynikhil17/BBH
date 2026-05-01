"""Recon module configuration.

The recon stage runs locally-installed CLI tools (subfinder, assetfinder,
httpx, nuclei, gau) over a target and produces a single ``recon.json`` the
researcher agent can consume via its ``--recon`` flag.

No API keys, no Anthropic dependency — this is plain subprocess automation.
"""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

_BASE = Path(__file__).parent.parent

DATA_DIR: Path = Path(os.getenv("DATA_DIR", _BASE / "data"))
RECON_DIR: Path = Path(os.getenv("RECON_DIR", DATA_DIR / "recon"))
LOG_DIR: Path = Path(os.getenv("LOG_DIR", DATA_DIR / "logs"))

# Per-tool timeouts (seconds). Tools that miss the deadline are killed and
# whatever they printed up to that point is parsed best-effort.
SUBFINDER_TIMEOUT: float = float(os.getenv("SUBFINDER_TIMEOUT", "300"))
ASSETFINDER_TIMEOUT: float = float(os.getenv("ASSETFINDER_TIMEOUT", "180"))
HTTPX_TIMEOUT: float = float(os.getenv("HTTPX_TIMEOUT", "600"))
NUCLEI_TIMEOUT: float = float(os.getenv("NUCLEI_TIMEOUT", "900"))
GAU_TIMEOUT: float = float(os.getenv("GAU_TIMEOUT", "300"))

# Be polite — bug bounty programs forbid floods even on reachable assets.
HTTPX_RATE_LIMIT: int = int(os.getenv("HTTPX_RATE_LIMIT", "50"))   # req / sec
NUCLEI_RATE_LIMIT: int = int(os.getenv("NUCLEI_RATE_LIMIT", "30"))  # req / sec

# Cap output sizes so a runaway tool doesn't fill the disk
MAX_SUBDOMAINS: int = int(os.getenv("MAX_SUBDOMAINS", "5000"))
MAX_HISTORICAL_URLS: int = int(os.getenv("MAX_HISTORICAL_URLS", "10000"))

# Nuclei templates: only run informational fingerprinting templates by default.
# Aggressive scanning of bounty targets often violates program rules.
NUCLEI_DEFAULT_SEVERITY: str = os.getenv("NUCLEI_DEFAULT_SEVERITY", "info,low")
NUCLEI_DEFAULT_TAGS: str = os.getenv("NUCLEI_DEFAULT_TAGS", "tech,fingerprint")
