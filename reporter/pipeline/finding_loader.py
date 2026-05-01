"""Construct ``Finding`` objects from a session result JSON.

Two paths:
- If ``session.findings`` is non-empty (someone has already curated the
  reportable findings), parse those dicts as ``Finding`` objects.
- Otherwise, derive findings from the session's confirmed signals:
    - each ``POSITIVE`` observation → one Finding
    - each ``CONFIRMED`` chain     → one chain-Finding
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Iterable, Optional

from researcher.session.models import (
    ChainHypothesis,
    ChainStatus,
    Observation,
    ObservationType,
    SessionResult,
)

from ..models import Finding

logger = logging.getLogger(__name__)


def _split_skill(skill_id: str) -> tuple[str, str]:
    parts = (skill_id or "").split("/", 1)
    return (parts[0] if parts else "", parts[1] if len(parts) > 1 else "")


def _from_observation(
    session: SessionResult,
    obs: Observation,
    index: int,
) -> Finding:
    vuln_class, vuln_subtype = _split_skill(obs.related_skill or session.skill_used)
    finding_id = f"F{index:03d}_{session.session_id}"
    return Finding(
        finding_id=finding_id,
        session_id=session.session_id,
        vuln_class=vuln_class,
        vuln_subtype=vuln_subtype,
        target=session.target,
        affected_feature=obs.related_skill or session.skill_used,
        severity="unknown",  # filled in after CVSS scoring
        confirmed=True,
        is_chain=False,
        chain_id=None,
        chain_name=None,
        chain_steps=None,
        observations=[obs.model_dump(mode="json")],
        evidence_description=obs.description,
        notes=obs.probe_description or "",
    )


def _from_chain(
    session: SessionResult,
    chain: ChainHypothesis,
    index: int,
) -> Finding:
    vuln_class, vuln_subtype = _split_skill(chain.from_skill)
    finding_id = f"F{index:03d}_chain_{session.session_id}"
    steps = []
    if chain.trigger:
        steps.append(f"Trigger: {chain.trigger}")
    if chain.pivot:
        steps.append(f"Pivot: {chain.pivot}")
    if chain.combined_impact:
        steps.append(f"Impact: {chain.combined_impact}")

    return Finding(
        finding_id=finding_id,
        session_id=session.session_id,
        vuln_class=vuln_class,
        vuln_subtype=vuln_subtype or "chain",
        target=session.target,
        affected_feature=chain.from_skill,
        severity="unknown",
        confirmed=True,
        is_chain=True,
        chain_id=chain.chain_id,
        chain_name=chain.chain_name,
        chain_steps=steps or None,
        observations=[],
        evidence_description=(
            f"Chain {chain.from_skill} → {chain.to_skill}: {chain.combined_impact}"
        ),
        notes=chain.trigger or "",
    )


def load_findings(session: SessionResult) -> list[Finding]:
    """Return the list of confirmed findings to report on for ``session``."""

    # Path 1: explicit curated list.
    if session.findings:
        out: list[Finding] = []
        for raw in session.findings:
            if not isinstance(raw, dict):
                continue
            try:
                out.append(Finding(**raw))
            except Exception as exc:
                logger.warning("skipping malformed finding entry: %s", exc)
        if out:
            return out

    # Path 2: derive from confirmed observations + chains.
    derived: list[Finding] = []
    index = 1
    for obs in session.observations:
        if obs.observation_type != ObservationType.POSITIVE:
            continue
        derived.append(_from_observation(session, obs, index))
        index += 1

    for chain in session.chains:
        if chain.status != ChainStatus.CONFIRMED:
            continue
        derived.append(_from_chain(session, chain, index))
        index += 1

    return derived


def filter_findings(
    findings: Iterable[Finding],
    *,
    finding_id: Optional[str] = None,
    chain_id: Optional[str] = None,
    confirmed_only: bool = True,
) -> list[Finding]:
    out: list[Finding] = []
    for f in findings:
        if confirmed_only and not f.confirmed:
            continue
        if finding_id and f.finding_id != finding_id:
            continue
        if chain_id and f.chain_id != chain_id:
            continue
        out.append(f)
    return out


def load_session_findings_from_path(path: Path) -> list[Finding]:
    """Convenience: read a session result file and return its derived findings."""
    raw = json.loads(path.read_text(encoding="utf-8"))
    session = SessionResult(**raw)
    return load_findings(session)
