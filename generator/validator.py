"""Validate generated skill markdown files.

Two layers:
1. Structural — every required section is present in the right order.
2. Content — minimum content thresholds + prohibited-content scan
   (reuses the same regex catalog as the extractor's validator so we
   don't accidentally publish a payload through the skill pipeline).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .config import (
    MIN_OVERVIEW_CHARS,
    MIN_PRECONDITION_ITEMS,
    SKILLS_DIR,
)


REQUIRED_SECTIONS: tuple[str, ...] = (
    "OVERVIEW",
    "PRECONDITIONS",
    "DETECTION METHODOLOGY",
    "TESTING WORKFLOW",
    "COMMON PATTERNS FROM REAL REPORTS",
    "DETECTION SIGNALS",
    "CHAIN OPPORTUNITIES",
    "ASSUMPTIONS TO CHALLENGE",
    "SCOPE CHECKLIST",
    "NOVEL DISCOVERIES LOG",
    "ATTACK CHAINS DISCOVERED",
    "FAILED APPROACHES",
    "REPORTING TEMPLATE HINTS",
)


# Same shape as extractor/validator.py — keep these in sync if either gets
# new patterns. Tuned for high precision: false negatives are tolerable,
# false positives (rejecting valid skills) are not.
_PROHIBITED_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\bcurl\s+[^\s|]+\s*\|\s*(?:sh|bash|zsh)\b", "curl-pipe-to-shell"),
    (r"\bwget\s+[^\s|]+\s*\|\s*(?:sh|bash|zsh)\b", "wget-pipe-to-shell"),
    (r"\b/dev/tcp/\d", "reverse-shell-bash-tcp"),
    (r"\bnc\s+-e\s+/bin/(?:sh|bash)\b", "netcat-shell-exec"),
    (r"\bbash\s+-i\s*>&?\s*/dev/tcp/", "bash-reverse-shell"),
    (r"\b169\.254\.169\.254\b", "aws-metadata-ip-literal"),
    (r"metadata\.google\.internal", "gcp-metadata-host-literal"),
    (r"\bUNION\s+(?:ALL\s+)?SELECT\s+", "sql-union-payload"),
    (r"'(?:\s*OR\s*'?1'?\s*=\s*'?1|--)", "sql-tautology-payload"),
    (r"<script[^>]*>[^<]*(?:alert|prompt|confirm)\(", "xss-script-payload"),
    (r"javascript:\s*(?:alert|prompt|confirm)\(", "javascript-uri-payload"),
    (r"<!ENTITY\s+\w+\s+SYSTEM\s+", "xxe-entity-payload"),
    (r";\s*(?:cat\s+/etc/passwd|id|whoami|nc\s+-)", "cmd-injection-payload"),
    (r"echo\s+[A-Za-z0-9+/]{40,}=*\s*\|\s*base64\s+-d\s*\|\s*(?:sh|bash)", "encoded-shell-payload"),
)
_PROHIBITED_REGEX: tuple[tuple[re.Pattern, str], ...] = tuple(
    (re.compile(p, re.IGNORECASE), label) for p, label in _PROHIBITED_PATTERNS
)


_SECTION_HEADER_PATTERN = re.compile(r"^##\s+(?P<title>.+?)\s*$", re.MULTILINE)


@dataclass
class ValidationReport:
    """Result of validating one skill file."""

    path: Path
    ok: bool
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def _extract_section(text: str, header: str) -> Optional[str]:
    """Return the body of the ``## {header}`` section, or ``None`` if absent."""
    pattern = re.compile(
        rf"^##\s+{re.escape(header)}\s*\n(?P<body>(?:.|\n)*?)(?=^##\s|\Z)",
        re.MULTILINE,
    )
    match = pattern.search(text)
    return match.group("body") if match else None


def _section_order(text: str) -> list[str]:
    """Return the ordered list of ``## ...`` section titles found in ``text``."""
    return [m.group("title").strip() for m in _SECTION_HEADER_PATTERN.finditer(text)]


def _scan_prohibited(text: str) -> Optional[str]:
    for pattern, label in _PROHIBITED_REGEX:
        if pattern.search(text):
            return label
    return None


def validate_skill_text(text: str, *, path: Optional[Path] = None) -> ValidationReport:
    """Run all checks against the given skill markdown string."""
    report = ValidationReport(path=path or Path("<inline>"), ok=True)

    # 1. Header — must start with "# SKILL:" line
    if not text.lstrip().startswith("# SKILL:"):
        report.errors.append("missing top-level '# SKILL:' header")

    # 2. Required sections present
    found_sections = _section_order(text)
    found_set = set(found_sections)
    missing = [s for s in REQUIRED_SECTIONS if s not in found_set]
    if missing:
        report.errors.append(f"missing required sections: {', '.join(missing)}")

    # 3. Section order — required sections must appear in the spec order.
    #    Extra (non-required) sections are tolerated and ignored.
    required_in_order = [s for s in found_sections if s in REQUIRED_SECTIONS]
    if required_in_order != [s for s in REQUIRED_SECTIONS if s in found_set]:
        report.errors.append(
            "required sections appear out of expected order; "
            f"got {required_in_order}"
        )

    # 4. OVERVIEW length
    overview = _extract_section(text, "OVERVIEW")
    if overview is not None:
        # Strip placeholder-style bracketed instruction lines
        meaningful = re.sub(r"\[.*?\]", "", overview, flags=re.DOTALL).strip()
        if len(meaningful) < MIN_OVERVIEW_CHARS:
            report.errors.append(
                f"OVERVIEW must be at least {MIN_OVERVIEW_CHARS} chars of meaningful prose; "
                f"got {len(meaningful)}"
            )

    # 5. PRECONDITIONS — minimum N checklist items
    preconds = _extract_section(text, "PRECONDITIONS")
    if preconds is not None:
        items = re.findall(r"^\s*-\s*\[\s*[xX ]?\s*\]\s+\S", preconds, re.MULTILINE)
        if len(items) < MIN_PRECONDITION_ITEMS:
            report.errors.append(
                f"PRECONDITIONS must have at least {MIN_PRECONDITION_ITEMS} checklist items; "
                f"got {len(items)}"
            )

    # 6. COMMON PATTERNS table — at least one data row
    common = _extract_section(text, "COMMON PATTERNS FROM REAL REPORTS")
    if common is not None:
        # Data rows are pipe-delimited and not the header / divider lines
        data_rows = [
            line
            for line in common.splitlines()
            if line.strip().startswith("|")
            and "---" not in line
            and not re.match(r"^\|\s*Pattern\s*\|", line)
        ]
        if len(data_rows) < 1:
            report.errors.append("COMMON PATTERNS table must contain at least one data row")

    # 7. TESTING WORKFLOW — must contain at least one → arrow
    workflow = _extract_section(text, "TESTING WORKFLOW")
    if workflow is not None and "→" not in workflow:
        report.errors.append("TESTING WORKFLOW must contain at least one '→' arrow")

    # 8. Prohibited content scan across the entire skill
    match = _scan_prohibited(text)
    if match:
        report.errors.append(f"prohibited content detected: {match}")

    report.ok = not report.errors
    return report


def validate_skill_file(path: Path) -> ValidationReport:
    """Read the file at ``path`` and validate it."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return ValidationReport(path=path, ok=False, errors=[f"could not read file: {exc}"])
    return validate_skill_text(text, path=path)


def validate_skills_dir(skills_dir: Path = SKILLS_DIR) -> list[ValidationReport]:
    """Validate every ``skill.md`` under ``skills_dir`` (skipping ``_templates/``)."""
    if not skills_dir.exists():
        return []
    reports: list[ValidationReport] = []
    for path in sorted(skills_dir.rglob("skill.md")):
        if "_templates" in path.parts:
            continue
        reports.append(validate_skill_file(path))
    return reports
