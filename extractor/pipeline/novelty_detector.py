"""Novelty detector — local-only similarity since the API was removed.

For each ``is_novel=True`` candidate, compares against existing patterns in
the same vuln_class / feature_type bucket using Jaccard token overlap on
``detection_approach + root_cause_pattern``. If the closest neighbor exceeds
``similarity_threshold``, the candidate is demoted from novel.

The previous build had an LLM second-opinion path for borderline cases; the
file-handoff build drops it. Public method signatures (``evaluate``,
``review_all_novel``) are preserved so the CLI flow is unchanged.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Optional

from ..config import NOVELTY_SIMILARITY_THRESHOLD
from ..storage import PatternStorage

logger = logging.getLogger(__name__)

_TOKEN_SPLIT = re.compile(r"\W+")


def _local_similarity(candidate: dict[str, Any], existing: dict[str, Any]) -> float:
    """Jaccard similarity over tokens in detection_approach + root_cause_pattern."""

    def tokens(d: dict[str, Any]) -> set[str]:
        text = f"{d.get('detection_approach', '')} {d.get('root_cause_pattern', '')}".lower()
        return {t for t in _TOKEN_SPLIT.split(text) if len(t) > 2}

    a, b = tokens(candidate), tokens(existing)
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


class NoveltyDetector:
    """Re-evaluate novel-flagged patterns against the existing library."""

    def __init__(
        self,
        storage: PatternStorage,
        similarity_threshold: float = NOVELTY_SIMILARITY_THRESHOLD,
        # Compatibility kwargs — accepted but ignored. The previous version
        # took ``client``, ``model``, ``max_tokens``, ``use_llm`` to drive the
        # LLM second-opinion. Keeping them here means the CLI wiring keeps
        # working.
        client: Any = None,
        model: Optional[str] = None,
        max_tokens: int = 0,
        use_llm: Optional[bool] = None,
    ) -> None:
        self._storage = storage
        self._threshold = similarity_threshold

    async def evaluate(self, pattern_id: int, candidate: dict[str, Any]) -> dict[str, Any]:
        """Decide whether a candidate is genuinely novel.

        Returns: ``{is_genuinely_novel, similarity_score, matching_pattern_id, explanation}``.
        """
        existing = await self._storage.find_similar_patterns(
            vuln_class=candidate.get("vuln_class", ""),
            feature_type=candidate.get("affected_feature_type", ""),
            limit=20,
        )

        if not existing:
            return {
                "is_genuinely_novel": True,
                "similarity_score": 0.0,
                "matching_pattern_id": None,
                "explanation": "No existing patterns in same vuln_class/feature_type.",
            }

        ranked = sorted(
            (
                (_local_similarity(candidate, e), e)
                for e in existing
                if e["id"] != pattern_id  # don't compare against self
            ),
            key=lambda item: item[0],
            reverse=True,
        )
        if not ranked:
            return {
                "is_genuinely_novel": True,
                "similarity_score": 0.0,
                "matching_pattern_id": None,
                "explanation": "Only the candidate itself is present in the bucket.",
            }

        top_score, top_match = ranked[0]
        is_novel = top_score < self._threshold
        return {
            "is_genuinely_novel": is_novel,
            "similarity_score": top_score,
            "matching_pattern_id": None if is_novel else top_match["id"],
            "explanation": (
                f"Local Jaccard similarity {top_score:.2f} "
                f"({'below' if is_novel else 'meets or exceeds'} threshold {self._threshold:.2f})."
            ),
        }

    async def review_all_novel(self) -> dict[str, int]:
        """Walk every is_novel=True row, re-evaluate, demote false positives."""
        assert self._storage._conn is not None
        cursor = await self._storage._conn.execute(
            "SELECT id, raw_json FROM patterns WHERE is_novel = 1"
        )
        rows = await cursor.fetchall()

        stats = {"reviewed": 0, "confirmed_novel": 0, "demoted": 0, "errors": 0}
        for row in rows:
            stats["reviewed"] += 1
            try:
                candidate = json.loads(row["raw_json"])
            except json.JSONDecodeError:
                stats["errors"] += 1
                continue

            verdict = await self.evaluate(row["id"], candidate)
            if verdict["is_genuinely_novel"]:
                stats["confirmed_novel"] += 1
            else:
                await self._storage.update_novelty_flag(
                    pattern_id=row["id"],
                    is_novel=False,
                    description=None,
                )
                stats["demoted"] += 1

        return stats
