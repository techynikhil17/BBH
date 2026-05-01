"""Group extracted patterns by (vuln_class, vuln_subtype).

Patterns whose group has fewer than ``MIN_PATTERNS_PER_GROUP`` entries are
recorded to ``data/insufficient_patterns.jsonl`` and excluded from generation
— a single-example skill is rarely useful.

Output ordering:
- groups with more patterns first (more signal → better skill)
- ties broken by average payout descending (proxy for impact)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Iterable

from ..config import (
    INSUFFICIENT_PATTERNS_JSONL,
    MIN_PATTERNS_PER_GROUP,
    PATTERNS_JSONL,
)
from ..models import PatternGroup

logger = logging.getLogger(__name__)


def load_patterns(path: Path = PATTERNS_JSONL) -> list[dict[str, Any]]:
    """Read every JSONL line as a pattern dict.

    Malformed lines are skipped with a warning rather than aborting the whole
    run — a single corrupt row shouldn't lose the rest of the library.
    """
    if not path.exists():
        logger.warning("patterns file not found: %s", path)
        return []
    rows: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                logger.warning("skipping malformed line %d in %s: %s", lineno, path, exc)
    return rows


def _group_key(pattern: dict[str, Any]) -> tuple[str, str]:
    vuln_class = (pattern.get("vuln_class") or "").strip().lower()
    vuln_subtype = (pattern.get("vuln_subtype") or "general").strip().lower()
    return vuln_class, vuln_subtype


def _avg_payout(patterns: list[dict[str, Any]]) -> float:
    """Average non-null `payout_usd` values; 0 when none are set."""
    payouts = [p.get("payout_usd") for p in patterns if isinstance(p.get("payout_usd"), (int, float))]
    return sum(payouts) / len(payouts) if payouts else 0.0


def group_patterns(
    patterns: Iterable[dict[str, Any]],
    *,
    min_patterns: int = MIN_PATTERNS_PER_GROUP,
) -> tuple[list[PatternGroup], list[dict[str, Any]]]:
    """Bucket patterns by (vuln_class, vuln_subtype).

    Returns
    -------
    (eligible_groups, insufficient_patterns)
        ``eligible_groups`` is sorted: pattern_count DESC, avg payout DESC.
        ``insufficient_patterns`` is the flat list of patterns that fell into
        groups smaller than the threshold — for the caller to write to
        ``insufficient_patterns.jsonl``.
    """
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for p in patterns:
        # Skip records that don't even have a vuln_class — they can't be grouped
        if not (p.get("vuln_class") or "").strip():
            continue
        # Skip the report-was-too-vague rows — they're not patterns
        if p.get("skipped"):
            continue
        buckets.setdefault(_group_key(p), []).append(p)

    eligible: list[PatternGroup] = []
    insufficient_patterns: list[dict[str, Any]] = []

    for (vc, vs), bucket in buckets.items():
        if len(bucket) < min_patterns:
            insufficient_patterns.extend(bucket)
            continue
        eligible.append(PatternGroup(vuln_class=vc, vuln_subtype=vs, patterns=bucket))

    eligible.sort(key=lambda g: (len(g.patterns), _avg_payout(g.patterns)), reverse=True)
    return eligible, insufficient_patterns


def write_insufficient_patterns(
    insufficient: list[dict[str, Any]],
    path: Path = INSUFFICIENT_PATTERNS_JSONL,
) -> int:
    """Persist the leftover pattern records to ``insufficient_patterns.jsonl``."""
    if not insufficient:
        return 0
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        for p in insufficient:
            fh.write(json.dumps(p) + "\n")
    return len(insufficient)
