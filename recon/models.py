"""Pydantic models for the recon pipeline."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, Field


class HttpService(BaseModel):
    """One live HTTP service detected by httpx."""

    url: str
    status_code: Optional[int] = None
    title: Optional[str] = None
    tech: list[str] = Field(default_factory=list)
    server: Optional[str] = None
    content_length: Optional[int] = None


class NucleiFinding(BaseModel):
    """One nuclei match — kept light, since we only run info/fingerprint templates."""

    template_id: str
    name: str = ""
    severity: str = "info"
    matched_at: str = ""
    tags: list[str] = Field(default_factory=list)


class ReconResult(BaseModel):
    """Output of one full recon run — written to ``data/recon/{target}.json``."""

    target: str
    scope_program: Optional[str] = None
    generated_at: datetime = Field(default_factory=datetime.now)

    subdomains: list[str] = Field(default_factory=list)
    in_scope_subdomains: list[str] = Field(default_factory=list)
    out_of_scope_subdomains: list[str] = Field(default_factory=list)

    live_services: list[HttpService] = Field(default_factory=list)
    tech_stack: list[str] = Field(default_factory=list)
    historical_urls: list[str] = Field(default_factory=list)
    nuclei_findings: list[NucleiFinding] = Field(default_factory=list)

    tools_run: list[str] = Field(default_factory=list)
    tools_skipped: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)

    def to_brief_dict(self) -> dict[str, Any]:
        """Compact shape consumed by the researcher's ``--recon`` flag.

        Keeps the keys the brief generator already knows how to render.
        """
        return {
            "target": self.target,
            "subdomains_in_scope": self.in_scope_subdomains[:50],
            "live_services_count": len(self.live_services),
            "stack": self.tech_stack,
            "interesting_endpoints": [
                s.url for s in self.live_services
                if s.status_code and 200 <= s.status_code < 300
            ][:25],
            "fingerprints": [
                f"{f.template_id}: {f.name}" for f in self.nuclei_findings
            ][:15],
            "historical_urls_count": len(self.historical_urls),
        }
