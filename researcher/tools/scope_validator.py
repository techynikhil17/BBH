"""Scope validation — the hard gate.

Loaded from a ``scope.json`` per program and consulted before any session
starts AND before any test recommendation is acted on. There is no
override path: an out-of-scope target raises ``OutOfScopeError`` and the
session refuses to start.

scope.json shape:
    {
      "program": "shopify",
      "platform": "hackerone",
      "in_scope": [
        {"asset": "*.shopify.com", "type": "URL"},
        {"asset": "*.myshopify.com", "type": "URL"}
      ],
      "out_of_scope": ["help.shopify.com"],
      "rules": ["No automated scanning", "No DoS testing"]
    }
"""

from __future__ import annotations

import fnmatch
import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field


class OutOfScopeError(Exception):
    """Raised when a target is not in scope. Cannot be suppressed in production paths."""


class ScopeAsset(BaseModel):
    asset: str
    type: str = "URL"


class Scope(BaseModel):
    program: str
    platform: str = ""
    in_scope: list[ScopeAsset] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    rules: list[str] = Field(default_factory=list)


@dataclass
class ValidationResult:
    in_scope: bool
    reason: str
    matched_rule: Optional[str] = None


def _normalize_target(target: str) -> str:
    """Reduce a target to a comparable host string.

    - URLs collapse to their hostname.
    - Hostnames are lower-cased.
    - Trailing dots stripped.
    """
    target = (target or "").strip().lower()
    if not target:
        return ""
    if "://" in target:
        try:
            target = urlparse(target).hostname or target
        except ValueError:
            pass
    target = target.split("/", 1)[0]
    target = target.split(":", 1)[0]
    target = target.rstrip(".")
    return target


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _matches_pattern(host: str, pattern: str) -> bool:
    """Match ``host`` against an in-scope pattern.

    Supports:
        - exact matches (``api.shopify.com``)
        - subdomain wildcards (``*.shopify.com``)
        - URL prefixes that we collapse to a hostname before matching
        - IP literals
        - CIDR ranges (e.g., ``10.0.0.0/24``)
    """
    pattern = (pattern or "").strip().lower()
    if not pattern:
        return False
    # CIDR range
    if "/" in pattern and not pattern.startswith("*."):
        try:
            net = ipaddress.ip_network(pattern, strict=False)
            return _is_ip(host) and ipaddress.ip_address(host) in net
        except ValueError:
            pass
    # Strip leading scheme-prefix patterns like https://*.shopify.com
    if "://" in pattern:
        pattern = urlparse(pattern).hostname or pattern
    pattern = pattern.rstrip(".")
    return fnmatch.fnmatchcase(host, pattern)


class ScopeValidator:
    """Programmatic scope check.

    Always pass through ``validate_target`` before letting a session start —
    or before recommending any probe against a target derived from one.
    """

    def __init__(self, scope: Scope) -> None:
        self._scope = scope

    @classmethod
    def load(cls, scope_file: Path | str) -> "ScopeValidator":
        path = Path(scope_file)
        if not path.exists():
            raise FileNotFoundError(f"scope file not found: {path}")
        try:
            data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"scope file at {path} is not valid JSON: {exc}") from exc

        # Tolerate both shapes: full dicts in in_scope, or plain strings
        normalized_in_scope = []
        for entry in data.get("in_scope", []):
            if isinstance(entry, str):
                normalized_in_scope.append({"asset": entry, "type": "URL"})
            elif isinstance(entry, dict):
                normalized_in_scope.append(entry)
        data["in_scope"] = normalized_in_scope

        return cls(Scope(**data))

    @property
    def scope(self) -> Scope:
        return self._scope

    def validate_target(self, target: str) -> ValidationResult:
        host = _normalize_target(target)
        if not host:
            return ValidationResult(False, "empty target")

        # Out-of-scope wins over in-scope (explicit exclusion)
        for excl in self._scope.out_of_scope:
            if _matches_pattern(host, excl):
                return ValidationResult(
                    in_scope=False,
                    reason=f"target matches out-of-scope rule: {excl!r}",
                    matched_rule=excl,
                )

        for entry in self._scope.in_scope:
            if _matches_pattern(host, entry.asset):
                return ValidationResult(
                    in_scope=True,
                    reason=f"matches in-scope rule: {entry.asset!r} (type={entry.type})",
                    matched_rule=entry.asset,
                )

        return ValidationResult(
            in_scope=False,
            reason="no matching in-scope rule",
        )

    def assert_in_scope(self, target: str) -> ValidationResult:
        """Same as ``validate_target`` but raises ``OutOfScopeError`` on failure."""
        result = self.validate_target(target)
        if not result.in_scope:
            raise OutOfScopeError(
                f"target {target!r} is not in scope for {self._scope.program!r}: {result.reason}"
            )
        return result

    def render_summary(self) -> str:
        lines = [
            f"**Program:** {self._scope.program}",
            f"**Platform:** {self._scope.platform}" if self._scope.platform else "",
            "**In scope:**",
        ]
        lines.extend(f"  - `{a.asset}` ({a.type})" for a in self._scope.in_scope)
        if self._scope.out_of_scope:
            lines.append("**Out of scope:**")
            lines.extend(f"  - `{a}`" for a in self._scope.out_of_scope)
        if self._scope.rules:
            lines.append("**Rules:**")
            lines.extend(f"  - {r}" for r in self._scope.rules)
        return "\n".join(line for line in lines if line)
