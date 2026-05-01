"""Skill semantic versioning.

Each skill.md carries ``**Version:** X.Y.Z`` and ``**Last Updated:** ...`` in
its header. This module:

- parses the current version from the file,
- decides patch vs minor based on which sections changed,
- writes the bumped version + today's date back into the header.

Major bumps are intentionally not automated — they imply a methodology change
that should be reviewed by a human and committed deliberately.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Iterable, Optional

import semver

from ..config import MINOR_SECTIONS, PATCH_SECTIONS


_VERSION_LINE_RE = re.compile(r"^(?P<prefix>\*\*Version:\*\*\s*)(?P<value>\S+)\s*$", re.MULTILINE)
_LAST_UPDATED_RE = re.compile(r"^(?P<prefix>\*\*Last Updated:\*\*\s*)(?P<value>.+?)\s*$", re.MULTILINE)


@dataclass
class BumpResult:
    old_version: str
    new_version: str
    bump_kind: str  # "patch" | "minor" | "none"


class VersionError(Exception):
    pass


def parse_current_version(text: str) -> str:
    """Return the current ``X.Y.Z`` string from the skill header.

    Defaults to ``1.0.0`` when no version line is present (skill files
    written before the field was required).
    """
    match = _VERSION_LINE_RE.search(text)
    if not match:
        return "1.0.0"
    candidate = match.group("value").strip()
    try:
        semver.Version.parse(candidate)
        return candidate
    except ValueError:
        return "1.0.0"


def decide_bump(changed_sections: Iterable[str]) -> str:
    """Map a set of changed-section labels to ``patch`` / ``minor`` / ``none``."""
    sections = set(changed_sections)
    if sections & MINOR_SECTIONS:
        return "minor"
    if sections & PATCH_SECTIONS:
        return "patch"
    return "none"


def bump_version_string(current: str, bump_kind: str) -> str:
    """Return the bumped version string. ``none`` returns ``current`` unchanged."""
    try:
        v = semver.Version.parse(current)
    except ValueError as exc:
        raise VersionError(f"invalid current version {current!r}: {exc}") from exc

    if bump_kind == "patch":
        return str(v.bump_patch())
    if bump_kind == "minor":
        return str(v.bump_minor())
    if bump_kind == "major":
        return str(v.bump_major())
    return current


def apply_bump(text: str, changed_sections: Iterable[str], *, today: Optional[str] = None) -> tuple[str, BumpResult]:
    """Bump the version line in ``text`` based on which sections changed.

    Also touches the ``Last Updated`` line so the skill timestamp stays
    truthful. Returns ``(new_text, BumpResult)``.
    """
    current = parse_current_version(text)
    kind = decide_bump(changed_sections)
    new_version = bump_version_string(current, kind)

    if kind == "none":
        # Nothing changed; leave the file alone.
        return text, BumpResult(old_version=current, new_version=current, bump_kind="none")

    today_str = today or date.today().isoformat()

    def _replace_version(match: re.Match) -> str:
        return f"{match.group('prefix')}{new_version}"

    def _replace_updated(match: re.Match) -> str:
        return f"{match.group('prefix')}{today_str}"

    new_text, n_v = _VERSION_LINE_RE.subn(_replace_version, text, count=1)
    if n_v == 0:
        # Header didn't have a version line — inject one after the skill title
        new_text = _inject_version_header(new_text, new_version, today_str)
    else:
        new_text, _ = _LAST_UPDATED_RE.subn(_replace_updated, new_text, count=1)

    return new_text, BumpResult(old_version=current, new_version=new_version, bump_kind=kind)


def _inject_version_header(text: str, version: str, today_str: str) -> str:
    """Add ``Version`` + ``Last Updated`` lines right after the ``# SKILL: ...`` title."""
    pattern = re.compile(r"(?P<title>^#\s+SKILL:.*?\n)", re.MULTILINE)
    inject = f"**Version:** {version}\n**Last Updated:** {today_str}\n"
    new_text, n = pattern.subn(lambda m: m.group("title") + inject, text, count=1)
    if n == 0:
        # No title either — prepend
        return inject + text
    return new_text
