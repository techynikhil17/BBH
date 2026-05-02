"""Hard scope gate for the orchestrator.

Wraps ``researcher.tools.scope_validator.ScopeValidator`` so the orchestrator
and the live researcher session enforce identical scope rules. Adds two
things on top:

1. **Persistent "active scope"** — when the user runs ``load-scope``, the
   raw scope.json is copied to ``data/sessions/active_scope.json``.
   ``is_loaded()`` checks for that file so any subcommand can refuse to
   start when no scope is active.

2. **Action-level gating** — actions like ``dos_test`` or
   ``automated_scan`` are checked against program rules. Some actions are
   permanently blocked regardless of scope content; others are blocked
   based on rule strings in ``scope.rules``.
"""

from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from researcher.tools.scope_validator import (
    OutOfScopeError,
    Scope,
    ScopeValidator,
    ValidationResult,
)

from .config import ACTIVE_SCOPE

logger = logging.getLogger(__name__)


# Actions that can never be authorized via a bug bounty scope.
_ALWAYS_BLOCKED_ACTIONS: frozenset[str] = frozenset({
    "dos_test",
    "ddos_test",
    "production_data_access",
    "production_data_exfil",
    "social_engineering",
    "physical_attack",
    "destructive_test",
})

# Tokens we look for in scope.rules to decide whether an action is allowed.
_AUTOMATED_SCAN_BLOCK_TOKENS: tuple[str, ...] = (
    "no automated scanning",
    "no automated scan",
    "manual testing only",
    "no automated tools",
    "no scanners",
)


@dataclass
class ActionResult:
    allowed: bool
    reason: str
    matched_rule: Optional[str] = None


class ScopeEnforcer:
    """Single source of truth for scope validation across the system.

    Stateful: ``load()`` persists the chosen scope to ``ACTIVE_SCOPE``.
    Subsequent calls reload from that file unless a new scope is loaded
    explicitly. ``unload()`` removes the persisted file.
    """

    def __init__(self, active_scope_path: Path = ACTIVE_SCOPE) -> None:
        self._active_scope_path = Path(active_scope_path)
        self._validator: Optional[ScopeValidator] = None
        # Cheap: re-load lazily on demand
        self._auto_load()

    # ---------- lifecycle ----------

    def load(self, program: str, scope_file: Path | str) -> Scope:
        """Validate ``scope_file`` and persist it as the active scope.

        Raises ``FileNotFoundError`` / ``ValueError`` on bad input.
        """
        path = Path(scope_file)
        if not path.exists():
            raise FileNotFoundError(f"scope file not found: {path}")

        validator = ScopeValidator.load(path)
        scope = validator.scope
        # Sanity-check the program name matches if both sides specified one
        if scope.program and scope.program.lower() != program.lower():
            logger.warning(
                "scope.program=%r differs from --program=%r; using scope.program",
                scope.program, program,
            )

        # Persist a normalized copy so reloads are deterministic
        self._active_scope_path.parent.mkdir(parents=True, exist_ok=True)
        # Write as JSON — Scope is a Pydantic model
        self._active_scope_path.write_text(scope.model_dump_json(indent=2), encoding="utf-8")

        self._validator = validator
        return scope

    def unload(self) -> None:
        """Remove the persisted active scope (forces a reload on next use)."""
        try:
            self._active_scope_path.unlink()
        except FileNotFoundError:
            pass
        self._validator = None

    def is_loaded(self) -> bool:
        """``True`` when an active scope is on disk and parses cleanly."""
        return self._validator is not None

    @property
    def scope(self) -> Optional[Scope]:
        return self._validator.scope if self._validator else None

    @property
    def active_scope_path(self) -> Path:
        return self._active_scope_path

    # ---------- target / action checks ----------

    def validate_target(self, target: str) -> ValidationResult:
        """Wraps ``ScopeValidator.validate_target`` with a "scope not loaded" guard."""
        if self._validator is None:
            return ValidationResult(
                in_scope=False,
                reason="no active scope — run `orchestrator.main load-scope` first",
                matched_rule=None,
            )
        return self._validator.validate_target(target)

    def assert_in_scope(self, target: str) -> ValidationResult:
        """Raise ``OutOfScopeError`` when ``target`` is not allowed."""
        result = self.validate_target(target)
        if not result.in_scope:
            raise OutOfScopeError(
                f"target {target!r} is not in scope: {result.reason}"
            )
        return result

    def validate_action(self, action: str) -> ActionResult:
        """Decide whether a named action is allowed under the active scope.

        Returns ``ActionResult(allowed=False, ...)`` when:
        - the action is in the always-blocked set, OR
        - the active scope's rules forbid it (e.g., 'No automated scanning').
        Unknown actions default to allowed (callers should use canonical names).
        """
        action_norm = (action or "").strip().lower()
        if not action_norm:
            return ActionResult(False, "empty action")

        if action_norm in _ALWAYS_BLOCKED_ACTIONS:
            return ActionResult(
                allowed=False,
                reason=f"action {action_norm!r} is permanently blocked by the system",
                matched_rule="system",
            )

        if self._validator is None:
            # Without a loaded scope we can't say — refuse so the operator
            # explicitly loads scope first.
            return ActionResult(
                allowed=False,
                reason="no active scope; load-scope first",
            )

        if action_norm in {"automated_scan", "automated_scanning", "scanning"}:
            for rule in self._validator.scope.rules:
                rule_lower = rule.lower()
                if any(token in rule_lower for token in _AUTOMATED_SCAN_BLOCK_TOKENS):
                    return ActionResult(
                        allowed=False,
                        reason=f"program rule blocks automated scanning: {rule!r}",
                        matched_rule=rule,
                    )

        return ActionResult(allowed=True, reason="allowed under current scope")

    # ---------- presentation ----------

    def get_scope_summary(self) -> str:
        if self._validator is None:
            return "_(no active scope — run load-scope to set one)_"
        return self._validator.render_summary()

    # ---------- internals ----------

    def _auto_load(self) -> None:
        """Try to load whatever's at ``ACTIVE_SCOPE`` on instantiation."""
        if not self._active_scope_path.exists():
            return
        try:
            data = json.loads(self._active_scope_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            logger.warning("active scope is unreadable: %s", exc)
            return
        try:
            scope = Scope(**data)
        except Exception as exc:  # pydantic errors are noisy; we just log + ignore
            logger.warning("active scope failed validation: %s", exc)
            return
        self._validator = ScopeValidator(scope)
