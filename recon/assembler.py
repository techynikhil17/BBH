"""Coordinate the recon runners and assemble a single ReconResult.

Pipeline order:
1. Subdomain enumeration (subfinder + assetfinder, dedup union)
2. Scope filter — out-of-scope hosts are recorded but never probed
3. HTTP probing (httpx) on in-scope hosts only
4. Optional historical URL harvest (gau / waybackurls)
5. Optional nuclei fingerprint scan over discovered live URLs

Each runner is independent — if one fails or its tool is missing, the rest
still run and the failure is recorded on the result. We never probe an
out-of-scope host, even if a runner's binary happens to be available.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from researcher.tools.scope_validator import ScopeValidator

from .models import HttpService, NucleiFinding, ReconResult
from .runners import (
    AssetfinderRunner,
    GauRunner,
    HttpxRunner,
    NucleiRunner,
    SubfinderRunner,
    WaybackurlsRunner,
)
from .scope_filter import filter_hosts

logger = logging.getLogger(__name__)


@dataclass
class ReconAssembler:
    """Drives the runners and merges their output."""

    subfinder: SubfinderRunner = None  # type: ignore[assignment]
    assetfinder: AssetfinderRunner = None  # type: ignore[assignment]
    httpx: HttpxRunner = None  # type: ignore[assignment]
    nuclei: NucleiRunner = None  # type: ignore[assignment]
    gau: GauRunner = None  # type: ignore[assignment]
    waybackurls: WaybackurlsRunner = None  # type: ignore[assignment]

    def __post_init__(self) -> None:
        # Default to fresh instances so callers can override individual runners
        # in tests by passing a mocked one.
        self.subfinder = self.subfinder or SubfinderRunner()
        self.assetfinder = self.assetfinder or AssetfinderRunner()
        self.httpx = self.httpx or HttpxRunner()
        self.nuclei = self.nuclei or NucleiRunner()
        self.gau = self.gau or GauRunner()
        self.waybackurls = self.waybackurls or WaybackurlsRunner()

    def run(
        self,
        target: str,
        *,
        scope_file: Optional[Path] = None,
        scope_program: Optional[str] = None,
        with_nuclei: bool = True,
        with_history: bool = True,
    ) -> ReconResult:
        result = ReconResult(target=target, scope_program=scope_program)

        # 1. Subdomain enumeration
        subdomains: set[str] = set()
        for runner in (self.subfinder, self.assetfinder):
            out = runner.run(target)
            if out.skipped:
                result.tools_skipped.append(runner.binary)
                continue
            if not out.ok:
                result.errors.append(f"{runner.binary}: {out.error or 'unknown'}")
                continue
            result.tools_run.append(runner.binary)
            subdomains.update(out.items)

        # Always include the bare target itself — useful if no enumeration ran.
        subdomains.add(target.strip().lower())

        result.subdomains = sorted(subdomains)

        # 2. Scope filtering
        validator: Optional[ScopeValidator] = None
        if scope_file is not None:
            try:
                validator = ScopeValidator.load(scope_file)
            except (FileNotFoundError, ValueError) as exc:
                result.errors.append(f"scope: {exc}")

        filtered = filter_hosts(result.subdomains, validator=validator)
        result.in_scope_subdomains = filtered.in_scope
        result.out_of_scope_subdomains = filtered.out_of_scope

        # 3. HTTP probing — in-scope only
        if result.in_scope_subdomains:
            probe = self.httpx.probe(result.in_scope_subdomains)
            if probe.skipped:
                result.tools_skipped.append(self.httpx.binary)
            elif probe.ok:
                result.tools_run.append(self.httpx.binary)
                result.live_services = list(probe.items)
            else:
                result.errors.append(f"{self.httpx.binary}: {probe.error or 'unknown'}")

        # 3b. Aggregate tech stack
        tech: set[str] = set()
        for service in result.live_services:
            for t in service.tech:
                tech.add(t.lower())
            if service.server:
                tech.add(service.server.lower())
        result.tech_stack = sorted(tech)

        # 4. Historical URLs (optional, network-heavy)
        if with_history:
            urls: set[str] = set()
            for runner in (self.gau, self.waybackurls):
                out = runner.run(target)
                if out.skipped:
                    result.tools_skipped.append(runner.binary)
                    continue
                if not out.ok:
                    result.errors.append(f"{runner.binary}: {out.error or 'unknown'}")
                    continue
                result.tools_run.append(runner.binary)
                urls.update(out.items)
            # We don't try to scope-filter raw URLs here — that's a job for the
            # researcher when it picks endpoints to probe. We do bound size.
            result.historical_urls = sorted(urls)[:5000]

        # 5. Nuclei fingerprinting (optional, only on live in-scope services)
        if with_nuclei and result.live_services:
            target_urls = [s.url for s in result.live_services if s.url]
            scan = self.nuclei.run(target_urls)
            if scan.skipped:
                result.tools_skipped.append(self.nuclei.binary)
            elif scan.ok:
                result.tools_run.append(self.nuclei.binary)
                result.nuclei_findings = list(scan.items)
            else:
                result.errors.append(f"{self.nuclei.binary}: {scan.error or 'unknown'}")

        # Dedup metadata lists (a runner could be both run AND skipped during
        # development if reused across calls; keep insertion order).
        result.tools_run = list(dict.fromkeys(result.tools_run))
        result.tools_skipped = list(dict.fromkeys(result.tools_skipped))

        return result
