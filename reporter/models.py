"""Pydantic models for the reporter pipeline."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class Finding(BaseModel):
    """A single confirmed finding extracted from a session result."""

    finding_id: str
    session_id: str
    vuln_class: str
    vuln_subtype: str = ""
    target: str
    affected_feature: str = ""
    severity: str = "unknown"  # critical | high | medium | low | unknown
    confirmed: bool = True
    is_chain: bool = False
    chain_id: Optional[str] = None
    chain_name: Optional[str] = None
    chain_steps: Optional[list[str]] = None
    observations: list[dict[str, Any]] = Field(default_factory=list)
    evidence_description: str = ""
    notes: str = ""
    # Hints used by the CVSS calculator. Optional; reasonable defaults inferred.
    oob_required: bool = False
    auth_required: bool = False
    user_interaction_required: bool = False


class CVSSResult(BaseModel):
    vector_string: str  # "CVSS:3.1/AV:N/AC:L/..."
    base_score: float
    severity_label: str  # Critical | High | Medium | Low | None
    breakdown: dict[str, str] = Field(default_factory=dict)
    impact_subscore: float = 0.0
    exploitability_subscore: float = 0.0


class EscalationResult(BaseModel):
    """Output of the chain escalator for a single chain."""

    applied: bool
    escalated_severity: str = ""
    reasoning: str = ""
    base_severity: str = ""
    chain_name: str = ""
    matched_rule: Optional[str] = None


class ReportDraft(BaseModel):
    finding_id: str
    session_id: str
    platform: str  # hackerone | bugcrowd | generic
    title: str
    summary: str
    vulnerability_details: str
    impact_analysis: str
    steps_to_reproduce: str
    proof_of_concept: str
    cvss: CVSSResult
    remediation: str
    references: dict[str, str] = Field(default_factory=dict)
    rendered_markdown: str = ""
    word_count: int = 0
    generated_at: datetime = Field(default_factory=datetime.now)
    requires_human_review: list[str] = Field(default_factory=list)
    quality_flags: list[str] = Field(default_factory=list)
