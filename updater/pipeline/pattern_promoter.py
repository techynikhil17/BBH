"""Cross-session pattern frequency tracking and promotion.

Walks every ``data/sessions/*/result.json`` to count how often each novel
observation appears across distinct sessions. Patterns that have been seen
in ``MIN_PROMOTION_SESSIONS`` or more sessions are eligible to be promoted
into the skill's ``COMMON PATTERNS`` table.

Two observations are considered "the same pattern" if they share:
- the same ``related_skill``, AND
- the same normalized description (collapsed whitespace, lower-cased,
  punctuation-trimmed).

That's deliberately conservative — false positives (treating two unrelated
descriptions as the same pattern) would be much worse than false negatives.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from researcher.session.models import ObservationType, SessionResult

from ..config import MIN_PROMOTION_SESSIONS, SESSIONS_DIR
from .session_reader import read_all_sessions


_NORMALIZE_RE = re.compile(r"\s+")
_PUNCT_TRIM = re.compile(r"[\s\.\,\;\:\-\—\!\?\(\)\[\]\{\}\"\']+$")


def _normalize_description(text: str) -> str:
    text = (text or "").strip().lower()
    text = _NORMALIZE_RE.sub(" ", text)
    text = _PUNCT_TRIM.sub("", text)
    return text


@dataclass
class PromotablePattern:
    """A novel pattern observed across enough sessions to graduate."""

    related_skill: str
    normalized_description: str
    representative_description: str  # the most-recent original phrasing
    sessions: list[str] = field(default_factory=list)
    chain_potentials: list[str] = field(default_factory=list)
    probe_examples: list[str] = field(default_factory=list)

    @property
    def session_count(self) -> int:
        return len(self.sessions)


@dataclass
class PromotionStatus:
    promotable: list[PromotablePattern]
    pending: list[PromotablePattern]  # seen once — needs 1 more session


class PatternPromoter:
    """Cross-session pattern bookkeeping."""

    def __init__(
        self,
        sessions_dir: Path = SESSIONS_DIR,
        min_sessions: int = MIN_PROMOTION_SESSIONS,
    ) -> None:
        self._sessions_dir = Path(sessions_dir)
        self._min_sessions = max(2, min_sessions)

    def status_for_skill(self, skill: str) -> PromotionStatus:
        """All promotable + pending patterns for a single skill."""
        sessions = read_all_sessions(self._sessions_dir)
        all_patterns = self._collect(sessions)
        promotable = []
        pending = []
        for p in all_patterns:
            if p.related_skill != skill:
                continue
            if p.session_count >= self._min_sessions:
                promotable.append(p)
            elif p.session_count >= 1:
                pending.append(p)
        return PromotionStatus(promotable=promotable, pending=pending)

    def all_status(self) -> dict[str, PromotionStatus]:
        """``{skill_path: PromotionStatus}`` across the whole library."""
        sessions = read_all_sessions(self._sessions_dir)
        patterns = self._collect(sessions)

        by_skill: dict[str, PromotionStatus] = {}
        grouped: dict[str, list[PromotablePattern]] = defaultdict(list)
        for p in patterns:
            grouped[p.related_skill].append(p)

        for skill, plist in grouped.items():
            promotable = [p for p in plist if p.session_count >= self._min_sessions]
            pending = [p for p in plist if 1 <= p.session_count < self._min_sessions]
            by_skill[skill] = PromotionStatus(promotable=promotable, pending=pending)
        return by_skill

    # ---------- internals ----------

    def _collect(self, sessions: Iterable[SessionResult]) -> list[PromotablePattern]:
        """Group novel observations across sessions."""
        # Key: (related_skill, normalized_description)
        index: dict[tuple[str, str], PromotablePattern] = {}
        for session in sessions:
            for obs in session.observations:
                if obs.observation_type != ObservationType.NOVEL:
                    continue
                norm = _normalize_description(obs.description)
                if not norm:
                    continue
                key = (obs.related_skill, norm)
                entry = index.get(key)
                if entry is None:
                    entry = PromotablePattern(
                        related_skill=obs.related_skill,
                        normalized_description=norm,
                        representative_description=obs.description.strip(),
                    )
                    index[key] = entry

                if session.session_id not in entry.sessions:
                    entry.sessions.append(session.session_id)
                if obs.chain_potential and obs.chain_potential not in entry.chain_potentials:
                    entry.chain_potentials.append(obs.chain_potential)
                if obs.probe_description and obs.probe_description not in entry.probe_examples:
                    entry.probe_examples.append(obs.probe_description)

                # Keep the most-recent natural phrasing as the representative
                entry.representative_description = obs.description.strip()

        return list(index.values())


def patterns_for_session(
    session: SessionResult,
    sessions_dir: Path = SESSIONS_DIR,
    min_sessions: int = MIN_PROMOTION_SESSIONS,
) -> PromotionStatus:
    """Return promotable + pending patterns RELEVANT to a specific session.

    This narrows the global view to patterns whose ``related_skill`` matches
    the session's skill — most callers want a per-session perspective.
    """
    promoter = PatternPromoter(sessions_dir=sessions_dir, min_sessions=min_sessions)
    return promoter.status_for_skill(session.skill_used)
