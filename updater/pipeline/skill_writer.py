"""Apply Claude Code synthesis output to a skill file.

Three primitive operations:
- ``_append_table_rows``: append rows to the markdown table inside a section
- ``_append_list_items``: append checkbox / list items to a section's list
- ``_replace_section``: replace the body of a section (used for DETECTION SIGNALS)

The writer is transactional in the file-IO sense: it backs up the file
*before* mutating, validates the result, and restores from backup on any
validation or write failure.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from ..backup.manager import BackupManager
from ..validator import validate_text
from .version_manager import BumpResult, apply_bump


_SECTION_RE_TEMPLATE = (
    r"(?P<header>^{header}\s*\n)"
    r"(?P<body>(?:.|\n)*?)"
    r"(?P<terminator>(?=^##\s)|\Z)"
)


def _section_pattern(header: str) -> re.Pattern:
    return re.compile(
        _SECTION_RE_TEMPLATE.format(header=re.escape(header)),
        re.MULTILINE,
    )


@dataclass
class WriteResult:
    success: bool
    sections_changed: list[str] = field(default_factory=list)
    bump: Optional[BumpResult] = None
    backup_path: Optional[Path] = None
    errors: list[str] = field(default_factory=list)


class SkillWriter:
    """Apply task output to a skill file with automatic rollback on failure."""

    def __init__(self, backup_manager: Optional[BackupManager] = None) -> None:
        self._backups = backup_manager or BackupManager()

    def apply_update(
        self,
        skill_path: Path,
        task_output: dict,
        *,
        dry_run: bool = False,
    ) -> WriteResult:
        skill_path = Path(skill_path)
        if not skill_path.exists():
            return WriteResult(success=False, errors=[f"skill file not found: {skill_path}"])

        original = skill_path.read_text(encoding="utf-8")
        content = original
        changed_sections: list[str] = []

        rows = task_output.get("promoted_pattern_rows") or []
        if rows:
            new_content = self._append_table_rows(
                content, "## COMMON PATTERNS FROM REAL REPORTS", rows
            )
            if new_content is not None and new_content != content:
                content = new_content
                changed_sections.append("COMMON_PATTERNS")

        preconds = task_output.get("new_preconditions") or []
        if preconds:
            new_content = self._append_list_items(content, "## PRECONDITIONS", preconds)
            if new_content is not None and new_content != content:
                content = new_content
                changed_sections.append("PRECONDITIONS")

        assumptions = task_output.get("new_assumptions") or []
        if assumptions:
            new_content = self._append_list_items(
                content, "## ASSUMPTIONS TO CHALLENGE", assumptions
            )
            if new_content is not None and new_content != content:
                content = new_content
                changed_sections.append("ASSUMPTIONS")

        signals = task_output.get("updated_detection_signals")
        if signals:
            new_content = self._replace_section(content, "## DETECTION SIGNALS", signals)
            if new_content is not None and new_content != content:
                content = new_content
                changed_sections.append("DETECTION_SIGNALS")

        if not changed_sections:
            return WriteResult(
                success=True,
                sections_changed=[],
                errors=["nothing to apply"],
            )

        # Bump version (and Last Updated) based on which sections changed.
        content, bump = apply_bump(content, changed_sections)

        validation = validate_text(content, path=skill_path)
        if not validation.passed:
            return WriteResult(
                success=False,
                sections_changed=[],
                errors=[f"validation failed: {e}" for e in validation.errors],
            )

        if dry_run:
            return WriteResult(
                success=True,
                sections_changed=changed_sections,
                bump=bump,
                backup_path=None,
                errors=[],
            )

        backup_path = self._backups.create(skill_path)
        try:
            skill_path.write_text(content, encoding="utf-8")
        except OSError as exc:
            self._backups.restore(skill_path, backup_path)
            return WriteResult(
                success=False,
                sections_changed=[],
                errors=[f"write failed; restored from {backup_path}: {exc}"],
            )

        return WriteResult(
            success=True,
            sections_changed=changed_sections,
            bump=bump,
            backup_path=backup_path,
            errors=[],
        )

    # ---------- section primitives ----------

    @staticmethod
    def _append_table_rows(text: str, header: str, rows: Iterable[str]) -> Optional[str]:
        """Append each row at the end of the markdown table inside ``header``.

        If the section has only the table header + divider, rows go right
        after the divider. If rows already exist, the new ones are appended.
        """
        match = _section_pattern(header).search(text)
        if not match:
            return None
        body = match.group("body").rstrip("\n")
        new_rows = "\n".join(_normalize_table_row(r) for r in rows)
        if not new_rows:
            return None
        new_body = (body + "\n" + new_rows + "\n\n") if body else (new_rows + "\n\n")
        return text[: match.start("body")] + new_body + text[match.end("body") :]

    @staticmethod
    def _append_list_items(text: str, header: str, items: Iterable[str]) -> Optional[str]:
        """Append checkbox / bullet items at the end of the list inside ``header``."""
        match = _section_pattern(header).search(text)
        if not match:
            return None
        body = match.group("body").rstrip("\n")
        new_items = "\n".join(_normalize_list_item(i) for i in items if i)
        if not new_items:
            return None
        new_body = (body + "\n" + new_items + "\n\n") if body else (new_items + "\n\n")
        return text[: match.start("body")] + new_body + text[match.end("body") :]

    @staticmethod
    def _replace_section(text: str, header: str, new_body: str) -> Optional[str]:
        """Replace the body of a section. Caller supplies the new body sans header."""
        match = _section_pattern(header).search(text)
        if not match:
            return None
        body = new_body.rstrip("\n") + "\n\n"
        return text[: match.start("body")] + body + text[match.end("body") :]


def _normalize_table_row(row: str) -> str:
    row = (row or "").strip()
    if not row.startswith("|"):
        row = "| " + row
    if not row.endswith("|"):
        row = row + " |"
    return row


def _normalize_list_item(item: str) -> str:
    item = (item or "").strip()
    if not item:
        return ""
    if item.startswith("- ") or item.startswith("* "):
        return item
    return "- " + item
