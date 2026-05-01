"""Filter discovered hosts against a scope.json.

Reuses ``researcher.tools.scope_validator.ScopeValidator`` so the recon
stage and the live researcher session use byte-identical scope rules. A
host that's flagged out-of-scope here is one the researcher would refuse
to start a session against.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

from researcher.tools.scope_validator import ScopeValidator


@dataclass
class ScopeFilterResult:
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)


def filter_hosts(
    hosts: Iterable[str],
    *,
    scope_file: Optional[Path] = None,
    validator: Optional[ScopeValidator] = None,
) -> ScopeFilterResult:
    """Return ``(in_scope, out_of_scope)`` partitioning of ``hosts``.

    Pass either a path to ``scope.json`` or a pre-built ``ScopeValidator``.
    If neither is provided, every host is treated as in-scope (caller is
    responsible for scope discipline).
    """
    if validator is None and scope_file is not None:
        validator = ScopeValidator.load(scope_file)

    result = ScopeFilterResult()
    seen: set[str] = set()
    for host in hosts:
        normalized = (host or "").strip().lower()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        if validator is None:
            result.in_scope.append(normalized)
            continue
        decision = validator.validate_target(normalized)
        if decision.in_scope:
            result.in_scope.append(normalized)
        else:
            result.out_of_scope.append(normalized)
    return result
