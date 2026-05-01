from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel

from .dedup import url_hash

SEVERITY_MAP: dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "p1": "critical",
    "p2": "high",
    "p3": "medium",
    "p4": "low",
    "p5": "low",
    "informational": "low",
    "none": "low",
}


def truncate_to_sentence(text: str, max_chars: int = 2000) -> str:
    if len(text) <= max_chars:
        return text
    chunk = text[:max_chars]
    for boundary in (".", "!", "?"):
        idx = chunk.rfind(boundary)
        if idx > max_chars // 2:
            return chunk[: idx + 1]
    idx = chunk.rfind(" ")
    if idx > 0:
        return chunk[:idx]
    return chunk


def normalize_severity(
    raw: Optional[str],
) -> Optional[Literal["critical", "high", "medium", "low", "unknown"]]:
    if raw is None:
        return None
    return SEVERITY_MAP.get(raw.lower().strip(), "unknown")  # type: ignore[return-value]


class RawReport(BaseModel):
    source: Literal["hackerone", "bugcrowd", "pentesterland", "github", "medium"]
    title: str
    url: str
    severity: Optional[Literal["critical", "high", "medium", "low", "unknown"]] = None
    program: Optional[str] = None
    bounty_usd: Optional[float] = None
    disclosed_at: Optional[datetime] = None
    vuln_type_tags: list[str] = []
    raw_content_preview: Optional[str] = None
    content_hash: str
    collected_at: datetime
    source_metadata: dict[str, Any] = {}
