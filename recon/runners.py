"""Subprocess wrappers for the recon CLI tools.

Each runner:
- detects whether its binary is on ``$PATH`` and gracefully no-ops if not,
- invokes the tool with a fixed, conservative argument set,
- parses stdout into Python objects,
- never raises on tool errors — failure is reported via the return value
  (``ok=False``, ``error=<reason>``) so a single broken tool doesn't kill
  the whole recon run.

Tool output formats (parsing contracts):
- subfinder / assetfinder: one hostname per line on stdout.
- httpx: ``-json`` flag → JSON line per host.
- gau / waybackurls: one URL per line.
- nuclei: ``-jsonl`` flag → JSON line per match.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

from .config import (
    ASSETFINDER_TIMEOUT,
    GAU_TIMEOUT,
    HTTPX_RATE_LIMIT,
    HTTPX_TIMEOUT,
    MAX_HISTORICAL_URLS,
    MAX_SUBDOMAINS,
    NUCLEI_DEFAULT_SEVERITY,
    NUCLEI_DEFAULT_TAGS,
    NUCLEI_RATE_LIMIT,
    NUCLEI_TIMEOUT,
    SUBFINDER_TIMEOUT,
)
from .models import HttpService, NucleiFinding

logger = logging.getLogger(__name__)


@dataclass
class RunnerOutput:
    """What a single runner returns."""

    tool: str
    ok: bool
    items: list[Any] = field(default_factory=list)
    skipped: bool = False
    error: Optional[str] = None


def _which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def _run_capture(
    cmd: list[str],
    *,
    timeout: float,
    stdin: Optional[str] = None,
) -> tuple[int, str, str]:
    """Run ``cmd`` synchronously and return ``(rc, stdout, stderr)``.

    Best-effort on timeout — kills the process and returns whatever was
    captured up to that point so partial results aren't lost.
    """
    try:
        completed = subprocess.run(
            cmd,
            input=stdin,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return completed.returncode, completed.stdout, completed.stderr
    except subprocess.TimeoutExpired as exc:
        # ``exc.stdout`` / ``exc.stderr`` are bytes when text=True isn't honored
        out = exc.stdout if isinstance(exc.stdout, str) else (exc.stdout or b"").decode(errors="replace")
        err = exc.stderr if isinstance(exc.stderr, str) else (exc.stderr or b"").decode(errors="replace")
        logger.warning("%s timed out after %.1fs", cmd[0], timeout)
        return 124, out, err
    except FileNotFoundError as exc:
        return 127, "", str(exc)


# ---------- subdomain enumeration ----------


class SubfinderRunner:
    """Passive subdomain enumeration via projectdiscovery/subfinder."""

    binary = "subfinder"

    def is_available(self) -> bool:
        return _which(self.binary) is not None

    def run(self, domain: str) -> RunnerOutput:
        if not self.is_available():
            return RunnerOutput(tool=self.binary, ok=False, skipped=True, error="not installed")
        cmd = [self.binary, "-d", domain, "-silent", "-all"]
        rc, stdout, stderr = _run_capture(cmd, timeout=SUBFINDER_TIMEOUT)
        if rc not in (0, 124):
            return RunnerOutput(tool=self.binary, ok=False, error=stderr.strip() or f"rc={rc}")
        items = [line.strip().lower() for line in stdout.splitlines() if line.strip()]
        return RunnerOutput(tool=self.binary, ok=True, items=items[:MAX_SUBDOMAINS])


class AssetfinderRunner:
    """Lightweight subdomain enumeration via tomnomnom/assetfinder."""

    binary = "assetfinder"

    def is_available(self) -> bool:
        return _which(self.binary) is not None

    def run(self, domain: str) -> RunnerOutput:
        if not self.is_available():
            return RunnerOutput(tool=self.binary, ok=False, skipped=True, error="not installed")
        cmd = [self.binary, "--subs-only", domain]
        rc, stdout, stderr = _run_capture(cmd, timeout=ASSETFINDER_TIMEOUT)
        if rc not in (0, 124):
            return RunnerOutput(tool=self.binary, ok=False, error=stderr.strip() or f"rc={rc}")
        items = [line.strip().lower() for line in stdout.splitlines() if line.strip()]
        return RunnerOutput(tool=self.binary, ok=True, items=items[:MAX_SUBDOMAINS])


# ---------- live-service probing ----------


class HttpxRunner:
    """Live HTTP probe + tech detection via projectdiscovery/httpx."""

    binary = "httpx"

    def is_available(self) -> bool:
        return _which(self.binary) is not None

    def probe(self, hosts: Iterable[str]) -> RunnerOutput:
        host_list = sorted({h.strip().lower() for h in hosts if h.strip()})
        if not host_list:
            return RunnerOutput(tool=self.binary, ok=True, items=[])
        if not self.is_available():
            return RunnerOutput(tool=self.binary, ok=False, skipped=True, error="not installed")

        cmd = [
            self.binary,
            "-silent",
            "-json",
            "-status-code",
            "-title",
            "-tech-detect",
            "-server",
            "-content-length",
            "-rate-limit", str(HTTPX_RATE_LIMIT),
            "-no-color",
        ]
        rc, stdout, stderr = _run_capture(
            cmd, timeout=HTTPX_TIMEOUT, stdin="\n".join(host_list)
        )
        if rc not in (0, 124):
            return RunnerOutput(tool=self.binary, ok=False, error=stderr.strip() or f"rc={rc}")

        services: list[HttpService] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            services.append(_httpx_to_service(payload))
        return RunnerOutput(tool=self.binary, ok=True, items=services)


def _httpx_to_service(payload: dict[str, Any]) -> HttpService:
    """Map httpx's JSON shape onto our ``HttpService`` model.

    httpx field names have changed across releases — we try a few alternatives.
    """
    url = payload.get("url") or payload.get("input") or ""
    status = payload.get("status_code") or payload.get("status-code") or payload.get("status")
    title = payload.get("title")
    server = payload.get("webserver") or payload.get("server")
    tech = payload.get("tech") or payload.get("technologies") or []
    if isinstance(tech, str):
        tech = [t.strip() for t in tech.split(",") if t.strip()]
    content_length = payload.get("content_length") or payload.get("content-length")

    return HttpService(
        url=url,
        status_code=int(status) if isinstance(status, (int, str)) and str(status).isdigit() else None,
        title=str(title)[:200] if title else None,
        tech=[str(t) for t in tech][:30],
        server=str(server)[:200] if server else None,
        content_length=int(content_length) if isinstance(content_length, (int, str)) and str(content_length).isdigit() else None,
    )


# ---------- tech fingerprint scan ----------


class NucleiRunner:
    """Targeted nuclei scan for tech fingerprinting (info/fingerprint tags only)."""

    binary = "nuclei"

    def is_available(self) -> bool:
        return _which(self.binary) is not None

    def run(
        self,
        urls: Iterable[str],
        *,
        severity: str = NUCLEI_DEFAULT_SEVERITY,
        tags: str = NUCLEI_DEFAULT_TAGS,
    ) -> RunnerOutput:
        url_list = sorted({u.strip() for u in urls if u.strip()})
        if not url_list:
            return RunnerOutput(tool=self.binary, ok=True, items=[])
        if not self.is_available():
            return RunnerOutput(tool=self.binary, ok=False, skipped=True, error="not installed")

        cmd = [
            self.binary,
            "-silent",
            "-jsonl",
            "-severity", severity,
            "-tags", tags,
            "-rate-limit", str(NUCLEI_RATE_LIMIT),
            "-no-color",
            "-disable-update-check",
        ]
        rc, stdout, stderr = _run_capture(
            cmd, timeout=NUCLEI_TIMEOUT, stdin="\n".join(url_list)
        )
        if rc not in (0, 124):
            return RunnerOutput(tool=self.binary, ok=False, error=stderr.strip() or f"rc={rc}")

        findings: list[NucleiFinding] = []
        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            findings.append(_nuclei_to_finding(payload))
        return RunnerOutput(tool=self.binary, ok=True, items=findings)


def _nuclei_to_finding(payload: dict[str, Any]) -> NucleiFinding:
    info = payload.get("info") or {}
    return NucleiFinding(
        template_id=str(payload.get("template-id") or payload.get("templateID") or ""),
        name=str(info.get("name") or ""),
        severity=str(info.get("severity") or "info"),
        matched_at=str(payload.get("matched-at") or payload.get("matched_at") or ""),
        tags=[t.strip() for t in (info.get("tags") or "").split(",") if t.strip()] if isinstance(info.get("tags"), str) else list(info.get("tags") or []),
    )


# ---------- historical URL harvest ----------


class GauRunner:
    """Historical URLs from public archives via lc/gau."""

    binary = "gau"

    def is_available(self) -> bool:
        return _which(self.binary) is not None

    def run(self, domain: str) -> RunnerOutput:
        if not self.is_available():
            return RunnerOutput(tool=self.binary, ok=False, skipped=True, error="not installed")
        cmd = [self.binary, "--threads", "5", domain]
        rc, stdout, stderr = _run_capture(cmd, timeout=GAU_TIMEOUT)
        if rc not in (0, 124):
            return RunnerOutput(tool=self.binary, ok=False, error=stderr.strip() or f"rc={rc}")
        items = [line.strip() for line in stdout.splitlines() if line.strip()][:MAX_HISTORICAL_URLS]
        return RunnerOutput(tool=self.binary, ok=True, items=items)


class WaybackurlsRunner:
    """Alternative historical URLs via tomnomnom/waybackurls."""

    binary = "waybackurls"

    def is_available(self) -> bool:
        return _which(self.binary) is not None

    def run(self, domain: str) -> RunnerOutput:
        if not self.is_available():
            return RunnerOutput(tool=self.binary, ok=False, skipped=True, error="not installed")
        cmd = [self.binary, domain]
        rc, stdout, stderr = _run_capture(cmd, timeout=GAU_TIMEOUT)
        if rc not in (0, 124):
            return RunnerOutput(tool=self.binary, ok=False, error=stderr.strip() or f"rc={rc}")
        items = [line.strip() for line in stdout.splitlines() if line.strip()][:MAX_HISTORICAL_URLS]
        return RunnerOutput(tool=self.binary, ok=True, items=items)
