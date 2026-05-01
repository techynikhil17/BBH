"""Validate extracted patterns before persistence.

Two layers:
1. Schema validation — Pydantic already enforces this on parse.
2. Content validation — heuristic checks that the extraction respects
   ethical-extraction rules (no shell commands, no exploit payloads, no
   verbatim PoCs) and meets minimum quality thresholds.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional

from .config import (
    MIN_DETECTION_APPROACH_LEN,
    MIN_EXTRACTION_CONFIDENCE,
)
from .models import ExtractedPattern
from .taxonomy import is_known_feature_type, is_known_vuln_class

# Patterns that suggest weaponized payload content rather than methodology.
# Tuned for high precision — false negatives are tolerable, false positives
# are not (we don't want to discard valid extractions).
_PROHIBITED_PATTERNS: tuple[tuple[str, str], ...] = (
    # Shell command pipelines / dangerous binaries piped to shells
    (r"\bcurl\s+[^\s|]+\s*\|\s*(?:sh|bash|zsh)\b", "curl-pipe-to-shell"),
    (r"\bwget\s+[^\s|]+\s*\|\s*(?:sh|bash|zsh)\b", "wget-pipe-to-shell"),
    # Reverse-shell payload signatures
    (r"\b/dev/tcp/\d", "reverse-shell-bash-tcp"),
    (r"\bnc\s+-e\s+/bin/(?:sh|bash)\b", "netcat-shell-exec"),
    (r"\bbash\s+-i\s*>&?\s*/dev/tcp/", "bash-reverse-shell"),
    # Cloud-metadata IP / common SSRF target literal
    (r"\b169\.254\.169\.254\b", "aws-metadata-ip-literal"),
    (r"metadata\.google\.internal", "gcp-metadata-host-literal"),
    # SQLi payload signatures
    (r"\bUNION\s+(?:ALL\s+)?SELECT\s+", "sql-union-payload"),
    (r"'(?:\s*OR\s*'?1'?\s*=\s*'?1|--)", "sql-tautology-payload"),
    # XSS payload signatures
    (r"<script[^>]*>[^<]*(?:alert|prompt|confirm)\(", "xss-script-payload"),
    (r"javascript:\s*(?:alert|prompt|confirm)\(", "javascript-uri-payload"),
    # XXE payload signatures
    (r"<!ENTITY\s+\w+\s+SYSTEM\s+", "xxe-entity-payload"),
    # Command-injection chained operators with binary execution
    (r";\s*(?:cat\s+/etc/passwd|id|whoami|nc\s+-)", "cmd-injection-payload"),
    # Base64-encoded shell signatures (rough heuristic)
    (r"echo\s+[A-Za-z0-9+/]{40,}=*\s*\|\s*base64\s+-d\s*\|\s*(?:sh|bash)", "encoded-shell-payload"),
)

_PROHIBITED_REGEX: tuple[tuple[re.Pattern, str], ...] = tuple(
    (re.compile(pat, re.IGNORECASE), label) for pat, label in _PROHIBITED_PATTERNS
)


@dataclass
class ValidationResult:
    ok: bool
    reason: Optional[str] = None
    novel_flag_should_set: bool = False  # validator may flag novelty when class isn't in taxonomy

    @classmethod
    def passing(cls, novel_flag_should_set: bool = False) -> "ValidationResult":
        return cls(ok=True, novel_flag_should_set=novel_flag_should_set)

    @classmethod
    def failing(cls, reason: str) -> "ValidationResult":
        return cls(ok=False, reason=reason)


def _scan_prohibited(text: str) -> Optional[str]:
    if not text:
        return None
    for pattern, label in _PROHIBITED_REGEX:
        if pattern.search(text):
            return label
    return None


def validate_pattern(pattern: ExtractedPattern) -> ValidationResult:
    """Run all validation checks against a pattern.

    Returns the first failure reason, or `passing()`. The caller decides what
    to do with failures — typically: log to validation_failures.jsonl and skip.
    """
    if pattern.skipped:
        # Skipped reports bypass content/quality checks — they're recorded separately.
        if not pattern.skip_reason:
            return ValidationResult.failing("skipped=True but no skip_reason")
        return ValidationResult.passing()

    # 1. Confidence threshold — discard low-confidence noise
    if pattern.extraction_confidence < MIN_EXTRACTION_CONFIDENCE:
        return ValidationResult.failing(
            f"extraction_confidence {pattern.extraction_confidence:.2f} below threshold {MIN_EXTRACTION_CONFIDENCE}"
        )

    # 2. Detection approach must be substantive
    if len(pattern.detection_approach.strip()) < MIN_DETECTION_APPROACH_LEN:
        return ValidationResult.failing(
            f"detection_approach too short ({len(pattern.detection_approach.strip())} chars, "
            f"need >= {MIN_DETECTION_APPROACH_LEN})"
        )

    # 3. Required text fields non-empty
    if not pattern.vuln_class.strip():
        return ValidationResult.failing("vuln_class is empty")
    if not pattern.affected_feature_type.strip():
        return ValidationResult.failing("affected_feature_type is empty")
    if not pattern.behavioral_signal.strip():
        return ValidationResult.failing("behavioral_signal is empty")
    if not pattern.root_cause_pattern.strip():
        return ValidationResult.failing("root_cause_pattern is empty")

    # 4. At least one precondition
    if not pattern.preconditions or not any(p.strip() for p in pattern.preconditions):
        return ValidationResult.failing("preconditions list must contain at least 1 non-empty entry")

    # 5. Taxonomy check — flag for novelty rather than reject if outside canonical
    novel_implied = False
    if not is_known_vuln_class(pattern.vuln_class) and not pattern.is_novel:
        novel_implied = True
    if not is_known_feature_type(pattern.affected_feature_type) and not pattern.is_novel:
        novel_implied = True

    # 6. Prohibited-content scan across all free-text fields
    fields_to_scan = (
        pattern.behavioral_signal,
        pattern.detection_approach,
        pattern.root_cause_pattern,
        pattern.chain_reasoning,
        pattern.novel_description or "",
        " ".join(pattern.preconditions),
    )
    for text in fields_to_scan:
        match = _scan_prohibited(text)
        if match:
            return ValidationResult.failing(f"prohibited content detected: {match}")

    # 7. Novel flag must have a description
    if pattern.is_novel and not (pattern.novel_description and pattern.novel_description.strip()):
        return ValidationResult.failing("is_novel=True but novel_description is empty")

    return ValidationResult.passing(novel_flag_should_set=novel_implied)
