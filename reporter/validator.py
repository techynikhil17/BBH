"""Quality checks for assembled reports.

The validator's job is to surface obvious issues before a human reviewer
sees the file: prohibited title language, vague impact, too-short
remediation, working exploit code that slipped through, and so on.

Failures are surfaced as ``flags`` on a ``ValidationResult`` rather than
exceptions — the assembler attaches them to the report draft so the
operator can address them or override.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .models import ReportDraft


TITLE_PROHIBITED: tuple[str, ...] = (
    "zero-day", "0day", "0-day", "hack", "hacked", "exploit", "critical bug", "pwn",
)

VAGUE_PHRASES: tuple[str, ...] = (
    "may be exposed",
    "could be accessed",
    "might allow",
    "potentially vulnerable",
    "could potentially",
    "may potentially",
    "data exposed",
    "information leaked",  # too generic without subject
)

GENERIC_REMEDIATION_PHRASES: tuple[str, ...] = (
    "validate input",
    "sanitize input",
    "follow best practices",
    "use proper validation",
)


# Same prohibited-payload regex catalog as the extractor / generator validators.
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
    (
        r"echo\s+[A-Za-z0-9+/]{40,}=*\s*\|\s*base64\s+-d\s*\|\s*(?:sh|bash)",
        "encoded-shell-payload",
    ),
)
_PROHIBITED_REGEX: tuple[tuple[re.Pattern, str], ...] = tuple(
    (re.compile(p, re.IGNORECASE), label) for p, label in _PROHIBITED_PATTERNS
)


MIN_STEPS = 3
MAX_TITLE_LEN = 80
MIN_IMPACT_CHARS = 100
MIN_REMEDIATION_CHARS = 100


@dataclass
class ValidationResult:
    passed: bool
    flags: list[str] = field(default_factory=list)


def _scan_prohibited(text: str) -> Optional[str]:
    for pattern, label in _PROHIBITED_REGEX:
        if pattern.search(text or ""):
            return label
    return None


def _count_steps(steps_text: str) -> int:
    """Count numbered list items in markdown."""
    if not steps_text:
        return 0
    matches = re.findall(r"^\s*\d+\.\s+\S", steps_text, re.MULTILINE)
    return len(matches)


def validate(report: ReportDraft) -> ValidationResult:
    flags: list[str] = []

    # Title
    title_lower = (report.title or "").lower()
    for word in TITLE_PROHIBITED:
        if word in title_lower:
            flags.append(f"title contains unprofessional term: {word!r}")
    if len(report.title or "") > MAX_TITLE_LEN:
        flags.append(f"title exceeds {MAX_TITLE_LEN} characters")
    if not (report.title or "").strip():
        flags.append("title is empty")

    # Steps
    step_count = _count_steps(report.steps_to_reproduce)
    if step_count < MIN_STEPS:
        flags.append(
            f"steps_to_reproduce has {step_count} numbered step(s); need at least {MIN_STEPS}"
        )

    # Impact specificity
    impact_lower = (report.impact_analysis or "").lower()
    for phrase in VAGUE_PHRASES:
        if phrase in impact_lower:
            flags.append(f"vague impact language: {phrase!r}")
    if len(report.impact_analysis or "") < MIN_IMPACT_CHARS:
        flags.append(
            f"impact_analysis is too short ({len(report.impact_analysis or '')} chars; "
            f"need >= {MIN_IMPACT_CHARS})"
        )

    # Remediation specificity
    remediation_lower = (report.remediation or "").lower()
    for phrase in GENERIC_REMEDIATION_PHRASES:
        if phrase in remediation_lower and len(report.remediation or "") < MIN_REMEDIATION_CHARS * 2:
            flags.append(f"generic remediation phrase without specifics: {phrase!r}")
    if len(report.remediation or "") < MIN_REMEDIATION_CHARS:
        flags.append(
            f"remediation is too short ({len(report.remediation or '')} chars; "
            f"need >= {MIN_REMEDIATION_CHARS})"
        )

    # Prohibited content scan across all narrative sections (and the rendered output).
    for label, text in (
        ("title", report.title),
        ("summary", report.summary),
        ("vulnerability_details", report.vulnerability_details),
        ("impact_analysis", report.impact_analysis),
        ("steps_to_reproduce", report.steps_to_reproduce),
        ("proof_of_concept", report.proof_of_concept),
        ("remediation", report.remediation),
        ("rendered_markdown", report.rendered_markdown),
    ):
        match = _scan_prohibited(text or "")
        if match:
            flags.append(f"prohibited content in {label}: {match}")

    return ValidationResult(passed=not flags, flags=flags)
