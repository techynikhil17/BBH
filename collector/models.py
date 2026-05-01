from __future__ import annotations

import re
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, field_validator

_VALID_SOURCES = {"hackerone", "bugcrowd", "intigriti", "yeswehack", "huntr", "pentesterland"}

_SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
    "none": "none",
    "p1": "critical",
    "p2": "high",
    "p3": "medium",
    "p4": "low",
    "p5": "low",
}


def truncate_to_sentence(text: str, max_len: int) -> str:
    if len(text) <= max_len:
        return text
    chunk = text[:max_len]
    # Try to find last sentence boundary
    match = None
    for m in re.finditer(r"[.!?]", chunk):
        match = m
    if match and match.end() < max_len:
        return chunk[: match.end()]
    # Fall back to whitespace boundary
    idx = chunk.rfind(" ")
    if idx != -1:
        return chunk[:idx]
    # Hard cut
    return chunk


def normalize_severity(severity: str | None) -> str | None:
    if severity is None:
        return None
    normalized = _SEVERITY_MAP.get(severity.lower())
    if normalized is None:
        return "unknown"
    return normalized


class RawReport(BaseModel):
    source: str
    title: str
    url: str
    content_hash: str
    collected_at: datetime
    severity: Optional[str] = None
    program: Optional[str] = None
    bounty_usd: Optional[float] = None
    disclosed_at: Optional[datetime] = None
    vuln_type_tags: list[str] = []
    raw_content_preview: Optional[str] = None
    source_metadata: dict = {}

    @field_validator("source")
    @classmethod
    def source_must_be_valid(cls, v: str) -> str:
        if v not in _VALID_SOURCES:
            raise ValueError(f"source must be one of {_VALID_SOURCES}, got {v!r}")
        return v
