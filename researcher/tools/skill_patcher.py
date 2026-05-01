"""Append-only updates to specific skill sections during a live session.

This module never rewrites a skill file. It locates one of the
``APPENDABLE_SECTIONS`` and inserts a row at the end of that section's
content, before the next ``## ...`` header. All other sections are left
exactly as they were.

That guarantee matters: skill files are versioned artifacts, and an
in-session "I saw something interesting" entry must never trample the
canonical content the generator produced.
"""

from __future__ import annotations

import re
from datetime import date
from pathlib import Path
from typing import Optional

from ..session.models import ChainHypothesis


APPENDABLE_SECTIONS: tuple[str, ...] = (
    "## NOVEL DISCOVERIES LOG",
    "## ATTACK CHAINS DISCOVERED",
    "## FAILED APPROACHES",
    "## ASSUMPTIONS TO CHALLENGE",
)


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


def _replace_section_body(text: str, header: str, new_body: str) -> Optional[str]:
    """Replace the *body* of a section while preserving its header.

    Returns the patched text or ``None`` if the section isn't present.
    """
    pat = _section_pattern(header)
    match = pat.search(text)
    if not match:
        return None
    return text[: match.start("body")] + new_body + text[match.end("body") :]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _write_atomic(path: Path, content: str) -> None:
    """Write ``content`` to ``path`` via tmp + rename so partial writes don't
    corrupt a skill file mid-session."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)


def _today() -> str:
    return date.today().isoformat()


class SkillPatcherError(Exception):
    """Generic failure (missing section, missing file, malformed content)."""


class SkillPatcher:
    """Append-only patches to specific skill.md sections."""

    APPENDABLE_SECTIONS = APPENDABLE_SECTIONS

    def __init__(self) -> None:
        pass

    # ---------- public API ----------

    def append_novel_discovery(
        self,
        skill_path: Path | str,
        session_id: str,
        discovery: str,
        chain_potential: str = "",
    ) -> bool:
        """Add a row to ``## NOVEL DISCOVERIES LOG``.

        Row format: ``| {today} | {session_id} | {discovery} | {chain_potential} | ⏳ |``
        """
        row = (
            f"| {_today()} | {session_id} | "
            f"{_escape_pipe(discovery)} | {_escape_pipe(chain_potential or '-')} | ⏳ |"
        )
        return self._append_to_table(skill_path, "## NOVEL DISCOVERIES LOG", row)

    def append_failed_approach(
        self,
        skill_path: Path | str,
        approach: str,
        reason: str,
        session_id: str,
    ) -> bool:
        """Add a row to ``## FAILED APPROACHES``.

        Row format: ``| {approach} | {reason} | {today} | {session_id} |``
        """
        row = (
            f"| {_escape_pipe(approach)} | {_escape_pipe(reason)} | "
            f"{_today()} | {session_id} |"
        )
        return self._append_to_table(skill_path, "## FAILED APPROACHES", row)

    def append_chain(
        self,
        skill_path: Path | str,
        chain: ChainHypothesis,
    ) -> bool:
        """Add a paragraph entry to ``## ATTACK CHAINS DISCOVERED``.

        Format::

            ### {chain_name} [{status}]
            **From:** {from_skill} → **To:** {to_skill}
            **Trigger:** {trigger}
            **Pivot:** {pivot}
            **Combined impact:** {combined_impact}
            **Session:** {session_id}  **Discovered:** {today}
        """
        block = (
            f"\n### {chain.chain_name} [{chain.status.value}]\n"
            f"**From:** {chain.from_skill} → **To:** {chain.to_skill}\n"
            f"**Trigger:** {chain.trigger}\n"
            f"**Pivot:** {chain.pivot}\n"
            f"**Combined impact:** {chain.combined_impact}\n"
            f"**Session:** {chain.session_id}  **Discovered:** {_today()}\n"
        )
        return self._append_block(skill_path, "## ATTACK CHAINS DISCOVERED", block)

    def append_assumption(
        self,
        skill_path: Path | str,
        assumption: str,
    ) -> bool:
        """Add a checkbox item to ``## ASSUMPTIONS TO CHALLENGE``.

        Format: ``- [ ] {assumption}``
        """
        line = f"- [ ] {assumption.strip()}"
        return self._append_block(skill_path, "## ASSUMPTIONS TO CHALLENGE", line + "\n")

    # ---------- internals ----------

    def _append_to_table(
        self,
        skill_path: Path | str,
        section_header: str,
        row: str,
    ) -> bool:
        """Insert ``row`` at the bottom of the table inside ``section_header``."""
        if section_header not in APPENDABLE_SECTIONS:
            raise SkillPatcherError(f"section {section_header!r} is not appendable")

        path = Path(skill_path)
        if not path.exists():
            raise SkillPatcherError(f"skill file not found: {path}")

        text = _read(path)
        pat = _section_pattern(section_header)
        match = pat.search(text)
        if not match:
            raise SkillPatcherError(f"section {section_header!r} not found in {path}")

        body = match.group("body")

        # Ensure the body ends with a newline; append the row; ensure trailing newline.
        body = body.rstrip("\n")
        if body:
            new_body = body + "\n" + row + "\n\n"
        else:
            new_body = row + "\n\n"

        new_text = _replace_section_body(text, section_header, new_body)
        if new_text is None:
            return False
        _write_atomic(path, new_text)
        return True

    def _append_block(
        self,
        skill_path: Path | str,
        section_header: str,
        block: str,
    ) -> bool:
        """Insert ``block`` at the end of ``section_header``'s body."""
        if section_header not in APPENDABLE_SECTIONS:
            raise SkillPatcherError(f"section {section_header!r} is not appendable")

        path = Path(skill_path)
        if not path.exists():
            raise SkillPatcherError(f"skill file not found: {path}")

        text = _read(path)
        pat = _section_pattern(section_header)
        match = pat.search(text)
        if not match:
            raise SkillPatcherError(f"section {section_header!r} not found in {path}")

        body = match.group("body").rstrip("\n")
        new_body = (body + "\n" if body else "") + block.rstrip("\n") + "\n\n"
        new_text = _replace_section_body(text, section_header, new_body)
        if new_text is None:
            return False
        _write_atomic(path, new_text)
        return True


def _escape_pipe(text: str) -> str:
    """Escape `|` so the value renders inside a markdown table cell."""
    return (text or "").replace("|", r"\|").strip() or "-"
