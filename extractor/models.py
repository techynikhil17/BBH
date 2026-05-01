"""Pydantic models for extracted vulnerability patterns.

`ExtractedPattern` is the canonical output shape — driven by JSON schema
constraint on the Anthropic API call so the model returns valid structured
data on every successful extraction.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class ChainPotential(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class ExtractedPattern(BaseModel):
    """Structured pattern extracted from a single bug bounty report.

    The schema below is the contract with the LLM — fields are intentionally
    flat (no nested objects) so JSON-schema-constrained generation stays simple.
    """

    # Source provenance
    source_url: str = Field(..., description="Original report URL")
    source_platform: str = Field(..., description="hackerone | bugcrowd | github | medium | pentesterland")

    # Classification
    vuln_class: str = Field(..., description="Canonical class (ssrf, rce, idor, ...)")
    vuln_subtype: str = Field(..., description="Sub-type, e.g., cloud-metadata, blind, second-order")
    cwe_id: Optional[str] = Field(None, description="CWE-XXX if determinable")

    # Context
    affected_feature_type: str = Field(..., description="Feature class — webhook, pdf_export, file_upload, ...")
    affected_stack_hints: list[str] = Field(default_factory=list, description="Tech stack hints, e.g., [aws, rails, graphql]")

    # Detection methodology
    behavioral_signal: str = Field(..., description="Observable behavior that indicated the vuln existed")
    detection_approach: str = Field(..., description="High-level methodology — NO PAYLOADS")
    oob_required: bool = Field(False, description="Does detection require out-of-band callbacks?")

    # Preconditions / root cause
    preconditions: list[str] = Field(default_factory=list, description="Conditions that must be true for vuln to exist")
    root_cause_pattern: str = Field(..., description="The developer mistake at the root of this vuln")

    # Chain potential
    chain_potential: ChainPotential = Field(ChainPotential.NONE)
    chain_targets: list[str] = Field(default_factory=list, description="Other vuln classes this could combine with")
    chain_reasoning: str = Field("", description="Why these targets")

    # Meta
    severity: Severity = Field(Severity.UNKNOWN)
    payout_usd: Optional[float] = Field(None, ge=0)
    is_novel: bool = Field(False, description="Pattern outside standard taxonomy?")
    novel_description: Optional[str] = Field(None, description="If novel, what's new about it")
    extraction_confidence: float = Field(..., ge=0.0, le=1.0)

    # Quality flags
    skipped: bool = Field(False)
    skip_reason: Optional[str] = Field(None)

    @field_validator("cwe_id")
    @classmethod
    def cwe_id_format(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip().upper()
        if not v:
            return None
        if not v.startswith("CWE-"):
            v = f"CWE-{v.lstrip('CWE').lstrip('-')}"
        return v


class SkippedReport(BaseModel):
    """Record for reports that the LLM determined were too vague to extract."""

    source_url: str
    source_platform: str
    skip_reason: str
    raw_title: Optional[str] = None


class ExtractionStats(BaseModel):
    processed: int = 0
    succeeded: int = 0
    skipped: int = 0
    errored: int = 0
    novel_flagged: int = 0
    validation_failed: int = 0


def extracted_pattern_json_schema() -> dict[str, Any]:
    """Return the JSON Schema sent to the Anthropic API for structured outputs.

    Pydantic's `.model_json_schema()` includes `$defs` for the enums; we inline
    them to a flat schema with `additionalProperties: false` (required by the
    structured-outputs contract).
    """
    schema = ExtractedPattern.model_json_schema()
    # Flatten by inlining enum $refs to their string-with-enum form
    defs = schema.pop("$defs", {})

    def inline(node: Any) -> Any:
        if isinstance(node, dict):
            if "$ref" in node:
                ref = node["$ref"].split("/")[-1]
                target = defs.get(ref, {})
                # Pydantic emits enums as {"enum": [...], "type": "string", "title": ...}
                resolved = {k: v for k, v in target.items() if k != "title"}
                return resolved
            return {k: inline(v) for k, v in node.items()}
        if isinstance(node, list):
            return [inline(item) for item in node]
        return node

    schema = inline(schema)
    schema["additionalProperties"] = False
    schema.pop("title", None)
    return schema
