"""Rule-based severity escalation for confirmed chains.

Some chain combinations meaningfully change the severity of either component
on its own. ``CHAIN_ESCALATION_RULES`` enumerates the well-known cases. The
escalator is deterministic — no Claude Code reasoning required.

Each rule maps ``(from_class, to_class) → (severity, reasoning)``. We match on
the (lowered) skill identifiers and return ``EscalationResult.applied=True``
on a hit. When no rule matches we fall through to ``base_severity`` so the
caller can still surface the "this is part of a chain" context to the report
without claiming an escalation that isn't conventional.
"""

from __future__ import annotations

from dataclasses import dataclass

from researcher.session.models import ChainHypothesis

from ..models import EscalationResult


@dataclass(frozen=True)
class EscalationRule:
    from_class: str
    to_class: str
    escalated_severity: str
    reasoning: str


CHAIN_ESCALATION_RULES: tuple[EscalationRule, ...] = (
    EscalationRule(
        "ssrf", "rce", "critical",
        "SSRF reaches internal service that allows code execution — full RCE.",
    ),
    EscalationRule(
        "ssrf", "deserialization", "critical",
        "SSRF reaches internal endpoint with unsafe deserialization — RCE-equivalent impact.",
    ),
    EscalationRule(
        "ssrf", "info_disclosure", "high",
        "SSRF reaches sensitive internal data store — credential or PII leak.",
    ),
    EscalationRule(
        "idor", "auth_bypass", "critical",
        "IDOR enables session/state hijack — account takeover.",
    ),
    EscalationRule(
        "open_redirect", "oauth_misconfig", "high",
        "Open redirect on OAuth callback URL hijacks authorization codes — token theft.",
    ),
    EscalationRule(
        "xxe", "ssrf", "high",
        "XXE pivot to SSRF reaches internal services — internal network reachable.",
    ),
    EscalationRule(
        "race_condition", "business_logic", "high",
        "Race condition unlocks single-use business logic — fraud / duplication.",
    ),
    EscalationRule(
        "mass_assignment", "auth_bypass", "critical",
        "Mass assignment writes the role/permission field — privilege escalation.",
    ),
    EscalationRule(
        "file_upload", "rce", "critical",
        "File upload bypass writes executable to a web-served path — RCE.",
    ),
    EscalationRule(
        "subdomain_takeover", "oauth_misconfig", "high",
        "Subdomain takeover on an OAuth allow-listed origin — token redirect.",
    ),
    EscalationRule(
        "graphql", "info_disclosure", "high",
        "GraphQL introspection / batching surfaces data the resolver should not return.",
    ),
)


def _normalize(skill: str) -> str:
    """Pull the canonical vuln_class from a 'class/subtype' identifier."""
    return (skill or "").split("/", 1)[0].strip().lower()


def find_rule(from_skill: str, to_skill: str) -> EscalationRule | None:
    fc = _normalize(from_skill)
    tc = _normalize(to_skill)
    for rule in CHAIN_ESCALATION_RULES:
        if rule.from_class == fc and rule.to_class == tc:
            return rule
    return None


def escalate(chain: ChainHypothesis, base_severity: str = "medium") -> EscalationResult:
    """Compute escalation for one chain.

    ``base_severity`` is the severity of the chain's *from* component before
    the chain was demonstrated — it's preserved on the result so the caller
    can show "was X, escalates to Y".
    """
    rule = find_rule(chain.from_skill, chain.to_skill)
    if rule is None:
        return EscalationResult(
            applied=False,
            escalated_severity=base_severity,
            reasoning="No standard escalation rule matched; report each component's severity separately.",
            base_severity=base_severity,
            chain_name=chain.chain_name,
            matched_rule=None,
        )

    return EscalationResult(
        applied=True,
        escalated_severity=rule.escalated_severity,
        reasoning=rule.reasoning,
        base_severity=base_severity,
        chain_name=chain.chain_name,
        matched_rule=f"{rule.from_class}->{rule.to_class}",
    )
