from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

_BASE = Path(__file__).parent.parent

DATA_DIR = Path(os.getenv("DATA_DIR", _BASE / "data"))
DB_PATH = Path(os.getenv("DB_PATH", DATA_DIR / "reports.db"))
JSONL_OUTPUT = Path(os.getenv("JSONL_OUTPUT", DATA_DIR / "raw" / "reports.jsonl"))
LOG_DIR = Path(os.getenv("LOG_DIR", DATA_DIR / "logs"))

ALL_SOURCES = ["hackerone", "bugcrowd", "pentesterland", "github", "medium"]
