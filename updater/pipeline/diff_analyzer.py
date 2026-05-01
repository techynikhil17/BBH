"""Identify what's genuinely new in a session vs the existing skill file.

Outputs a ``DiffResult`` with separate buckets:
- novel_observations: novel observations not already in NOVEL DISCOVERIES LOG
- confirmed_chains: confirmed chains not already in ATTACK CHAINS DISCOVERED
- failed_approaches: failed approaches not already in FAILED APPROACHES
- promotable_patterns: novel patterns seen in 2+ sessions
- pending_patterns: novel patterns seen in 1 session (need 1 more)
- needs_structural_update: True when novel signals or chain_potentials hint
  that the skill might benefit from new preconditions / assumptions
- structural_hints: short list summarizing why
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from pydantic import BaseModel

from researcher.session.models import ChainStatus, ObservationType, SessionResult

from ..config import MIN_PROMOTION_SESSIONS, SESSIONS_DIR
from .pattern_promoter import (
    PatternPromoter,
    PromotablePattern,
    _normalize_description,
)


_NOVEL_LOG_HEADER = "## NOVEL DISCOVERIES LOG"
_CHAINS_HEADER = "## ATTACK CHAINS DISCOVERED"
_FAILED_HEADER = "## FAILED APPROACHES"


_SECTION_RE_TEMPLATE = (
    r"^{header}\s*\n(?P<body>(?:.|\n)*?)(?=^##\s|\Z)"
)


def _extract_section_body(text: str, header: str) -> str:
    pattern = re.compile(
        _SECTION_RE_TEMPLATE.format(header=re.escape(header)),
        re.MULTILINE,
    )
    match = pattern.search(text)
    return match.group("body") if match else ""


class DiffResult(BaseModel):
    skill_path: str
    novel_observations: list[dict] = []
    confirmed_chains: list[dict] = []
    failed_approaches: list[dict] = []
    promotable_patterns: list[dict] = []
    pending_patterns: list[dict] = []
    needs_structural_update: bool = False
    structural_hints: list[str] = []
    nothing_to_update: bool = False


@dataclass
class _SkillSnapshot:
    text: str
    novel_log_body: str
    chains_body: str
    failed_body: str


class DiffAnalyzer:
    """Compute the diff between a session and a skill file."""

    def __init__(
        self,
        sessions_dir: Path = SESSIONS_DIR,
        min_promotion_sessions: int = MIN_PROMOTION_SESSIONS,
    ) -> None:
        self._promoter = PatternPromoter(
            sessions_dir=sessions_dir, min_sessions=min_promotion_sessions
        )

    def analyze(self, session: SessionResult, skill_path: Path | str) -> DiffResult:
        skill_path = Path(skill_path)
        skill_text = skill_path.read_text(encoding="utf-8") if skill_path.exists() else ""
        snap = _SkillSnapshot(
            text=skill_text,
            novel_log_body=_extract_section_body(skill_text, _NOVEL_LOG_HEADER),
            chains_body=_extract_section_body(skill_text, _CHAINS_HEADER),
            failed_body=_extract_section_body(skill_text, _FAILED_HEADER),
        )

        novel_obs = self._novel_not_yet_logged(session, snap)
        confirmed_chains = self._chains_not_yet_logged(session, snap)
        failed = self._failed_not_yet_logged(session, snap)

        promotion = self._promoter.status_for_skill(session.skill_used)
        promotable = [self._promotable_dict(p) for p in promotion.promotable]
        pending = [self._promotable_dict(p) for p in promotion.pending]

        structural_hints = self._derive_structural_hints(session, snap, promotion.promotable)
        needs_structural = bool(structural_hints) or bool(promotable)

        nothing = (
            not novel_obs
            and not confirmed_chains
            and not failed
            and not promotable
            and not structural_hints
        )

        return DiffResult(
            skill_path=str(skill_path),
            novel_observations=novel_obs,
            confirmed_chains=confirmed_chains,
            failed_approaches=failed,
            promotable_patterns=promotable,
            pending_patterns=pending,
            needs_structural_update=needs_structural,
            structural_hints=structural_hints,
            nothing_to_update=nothing,
        )

    # ---------- internals ----------

    def _novel_not_yet_logged(self, session: SessionResult, snap: _SkillSnapshot) -> list[dict]:
        out: list[dict] = []
        existing = snap.novel_log_body.lower()
        for obs in session.observations:
            if obs.observation_type != ObservationType.NOVEL:
                continue
            normalized = _normalize_description(obs.description)
            # The log typically contains the full description in the third column;
            # if we can't find it, treat the observation as not yet logged.
            if normalized and normalized in existing:
                continue
            out.append(
                {
                    "observation_id": obs.observation_id,
                    "description": obs.description,
                    "probe_description": obs.probe_description,
                    "chain_potential": obs.chain_potential,
                }
            )
        return out

    def _chains_not_yet_logged(self, session: SessionResult, snap: _SkillSnapshot) -> list[dict]:
        out: list[dict] = []
        existing = snap.chains_body.lower()
        for chain in session.chains:
            if chain.status != ChainStatus.CONFIRMED:
                continue
            chain_signature = (
                f"{chain.from_skill.lower()}->{chain.to_skill.lower()}|"
                f"{_normalize_description(chain.chain_name)}"
            )
            simpler_signature = chain.chain_name.lower().strip()
            if (
                chain_signature in existing
                or (simpler_signature and simpler_signature in existing)
            ):
                continue
            out.append(chain.model_dump(mode="json"))
        return out

    def _failed_not_yet_logged(self, session: SessionResult, snap: _SkillSnapshot) -> list[dict]:
        out: list[dict] = []
        existing = snap.failed_body.lower()
        for fa in session.failed_approaches:
            normalized = _normalize_description(fa.approach)
            if normalized and normalized in existing:
                continue
            out.append(fa.model_dump(mode="json"))
        return out

    def _derive_structural_hints(
        self,
        session: SessionResult,
        snap: _SkillSnapshot,
        promotable: list[PromotablePattern],
    ) -> list[str]:
        hints: list[str] = []
        # Promotable patterns themselves are a strong signal.
        for p in promotable:
            hints.append(
                f"Promote pattern '{p.representative_description}' "
                f"(seen in {p.session_count} sessions)"
            )
        # Novel observations with chain potential suggest new ASSUMPTIONS to challenge.
        for obs in session.observations:
            if obs.observation_type == ObservationType.NOVEL and obs.chain_potential:
                hints.append(
                    f"Novel observation suggests chain to '{obs.chain_potential}': "
                    f"{obs.description[:80]}"
                )
        # New chain destinations might warrant a new precondition or signal.
        existing = (snap.text or "").lower()
        for chain in session.chains:
            if chain.status == ChainStatus.CONFIRMED and chain.to_skill.lower() not in existing:
                hints.append(
                    f"Confirmed chain to '{chain.to_skill}' is not referenced "
                    "anywhere in the skill body — consider DETECTION SIGNALS."
                )
        return hints

    @staticmethod
    def _promotable_dict(p: PromotablePattern) -> dict:
        return {
            "related_skill": p.related_skill,
            "description": p.representative_description,
            "normalized_description": p.normalized_description,
            "session_count": p.session_count,
            "sessions": list(p.sessions),
            "chain_potentials": list(p.chain_potentials),
            "probe_examples": list(p.probe_examples),
        }
