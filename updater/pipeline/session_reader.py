"""Load and validate a session result JSON file.

Wraps ``researcher.session.models.SessionResult`` parsing so the rest of
the updater works with typed objects only.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from researcher.session.models import SessionResult


class InvalidSessionError(Exception):
    pass


def read_session(path: Path | str) -> SessionResult:
    """Load and validate a session result JSON file.

    Raises:
        FileNotFoundError: when the file is missing
        InvalidSessionError: when the file is unreadable or malformed
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"session result not found: {path}")

    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise InvalidSessionError(f"could not read {path}: {exc}") from exc

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise InvalidSessionError(f"session result is not valid JSON ({path}): {exc}") from exc

    try:
        return SessionResult(**data)
    except ValidationError as exc:
        raise InvalidSessionError(f"session result schema mismatch ({path}): {exc}") from exc


def list_session_files(sessions_dir: Path) -> list[Path]:
    """Return every ``result.json`` under ``sessions_dir``."""
    sessions_dir = Path(sessions_dir)
    if not sessions_dir.exists():
        return []
    return sorted(sessions_dir.glob("*/result.json"))


def read_all_sessions(sessions_dir: Path) -> list[SessionResult]:
    """Best-effort: load every session result, skipping malformed files."""
    out: list[SessionResult] = []
    for p in list_session_files(sessions_dir):
        try:
            out.append(read_session(p))
        except (FileNotFoundError, InvalidSessionError):
            continue
    return out
