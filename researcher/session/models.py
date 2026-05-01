"""Session data models — Pydantic v2.

Persisted in SQLite by ``session/manager.py`` and exported as JSON on
``end``. Free of any framework-specific tagging so tests can construct
them in isolation.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class ObservationType(str, Enum):
    POSITIVE = "positive"      # vulnerability signal present
    NEGATIVE = "negative"      # dead end, no signal observed
    NOVEL = "novel"            # unexpected behavior, not in skill file
    CHAIN = "chain"            # links to another vulnerability class


class ChainStatus(str, Enum):
    HYPOTHETICAL = "hypothetical"
    CONFIRMED = "confirmed"
    DISPROVED = "disproved"


class Observation(BaseModel):
    observation_id: str
    session_id: str
    observation_type: ObservationType
    description: str
    related_skill: str
    probe_description: str  # what was tested — abstract, no payloads
    chain_potential: Optional[str] = None
    timestamp: datetime = Field(default_factory=datetime.now)


class ChainHypothesis(BaseModel):
    chain_id: str
    session_id: str
    chain_name: str
    from_skill: str
    to_skill: str
    trigger: str
    pivot: str
    combined_impact: str
    status: ChainStatus
    evidence_observation_ids: list[str] = Field(default_factory=list)
    discovered_at: datetime = Field(default_factory=datetime.now)


class FailedApproach(BaseModel):
    approach: str
    reason: str
    skill: str
    date: str
    session_id: str


class SessionResult(BaseModel):
    session_id: str
    program: str
    target: str
    skill_used: str
    scope_file: str
    started_at: datetime
    ended_at: Optional[datetime] = None
    observations: list[Observation] = Field(default_factory=list)
    chains: list[ChainHypothesis] = Field(default_factory=list)
    failed_approaches: list[FailedApproach] = Field(default_factory=list)
    novel_signals: list[dict[str, Any]] = Field(default_factory=list)
    findings: list[dict[str, Any]] = Field(default_factory=list)
    skill_files_updated: list[str] = Field(default_factory=list)
    status: str = "active"  # active | completed | aborted
