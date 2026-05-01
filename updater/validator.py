"""Validate updated skill files.

Reuses ``generator.validator`` so the rules are identical to whatever the
skill generator (PROMPT 03) enforces. We expose a tiny ``passed/errors``
shape because the skill writer's rollback path needs a binary signal.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from generator.validator import validate_skill_text


@dataclass
class ValidationOutcome:
    passed: bool
    errors: list[str]
    warnings: list[str]


def validate_text(text: str, *, path: Optional[Path] = None) -> ValidationOutcome:
    report = validate_skill_text(text, path=path)
    return ValidationOutcome(passed=report.ok, errors=list(report.errors), warnings=list(report.warnings))


def validate_file(path: Path) -> ValidationOutcome:
    return validate_text(path.read_text(encoding="utf-8"), path=path)
