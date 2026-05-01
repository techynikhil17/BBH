"""Thin convenience wrapper around the session manager.

The live REPL hands raw observation/chain/failure dicts to this module; we
construct the typed model, persist via ``SessionManager``, and return the
stored object. Keeps ``main.py`` free of model-construction noise.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from ..session.manager import SessionManager
from ..session.models import (
    ChainHypothesis,
    ChainStatus,
    FailedApproach,
    Observation,
    ObservationType,
)


class SessionLogger:
    """Async helper for writing observations / chains / failures to a session."""

    def __init__(self, manager: SessionManager) -> None:
        self._manager = manager

    async def log_observation(
        self,
        *,
        session_id: str,
        observation_type: ObservationType,
        description: str,
        related_skill: str,
        probe_description: str,
        chain_potential: Optional[str] = None,
    ) -> Observation:
        observation = Observation(
            observation_id=uuid.uuid4().hex,
            session_id=session_id,
            observation_type=observation_type,
            description=description,
            related_skill=related_skill,
            probe_description=probe_description,
            chain_potential=chain_potential,
        )
        await self._manager.add_observation(observation)
        return observation

    async def log_chain(
        self,
        *,
        session_id: str,
        chain_name: str,
        from_skill: str,
        to_skill: str,
        trigger: str,
        pivot: str,
        combined_impact: str,
        status: ChainStatus = ChainStatus.HYPOTHETICAL,
        evidence_observation_ids: Optional[list[str]] = None,
    ) -> ChainHypothesis:
        chain = ChainHypothesis(
            chain_id=uuid.uuid4().hex,
            session_id=session_id,
            chain_name=chain_name,
            from_skill=from_skill,
            to_skill=to_skill,
            trigger=trigger,
            pivot=pivot,
            combined_impact=combined_impact,
            status=status,
            evidence_observation_ids=evidence_observation_ids or [],
        )
        await self._manager.add_chain(chain)
        return chain

    async def log_failed_approach(
        self,
        *,
        session_id: str,
        approach: str,
        reason: str,
        skill: str,
    ) -> FailedApproach:
        failed = FailedApproach(
            approach=approach,
            reason=reason,
            skill=skill,
            date=datetime.now().date().isoformat(),
            session_id=session_id,
        )
        await self._manager.add_failed_approach(failed)
        return failed
