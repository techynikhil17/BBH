"""Deterministic CVSS 3.1 base scoring.

We start from a per-vuln-class base vector (a sensible default — not a
prescriptive scoring authority) and adjust based on Finding hints:
- ``oob_required``                 → Attack Complexity ``L`` → ``H``
- ``auth_required``                → Privileges Required ``N`` → ``L``
- ``user_interaction_required``    → User Interaction ``N`` → ``R``

The base score is computed exactly per the CVSS 3.1 specification. Vector
strings are valid CVSS:3.1 strings; severity labels follow the published
qualitative ratings.
"""

from __future__ import annotations

from typing import Iterable

from ..models import CVSSResult, Finding


# Per-vuln-class base vectors (defaults; refined by Finding hints below).
BASE_VECTORS: dict[str, dict[str, str]] = {
    "rce":              {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "ssrf":             {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C", "C": "H", "I": "N", "A": "N"},
    "idor":             {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    "sqli":             {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "ssti":             {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "H"},
    "auth_bypass":      {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "xxe":              {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    "deserialization":  {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "race_condition":   {"AV": "N", "AC": "H", "PR": "L", "UI": "N", "S": "U", "C": "L", "I": "H", "A": "N"},
    "business_logic":   {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "L", "I": "H", "A": "N"},
    "mass_assignment":  {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "L", "I": "H", "A": "N"},
    "subdomain_takeover":{"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
    "file_upload":      {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "L", "I": "H", "A": "N"},
    "graphql":          {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    "oauth_misconfig":  {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "H", "I": "N", "A": "N"},
    "open_redirect":    {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
    "xss":              {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
    "csrf":             {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "L", "A": "N"},
    "info_disclosure":  {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    "path_traversal":   {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    "command_injection":{"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
}

_DEFAULT_VECTOR = BASE_VECTORS["business_logic"]


# CVSS 3.1 numeric tables.
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
# PR depends on Scope.
_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


def _roundup(value: float) -> float:
    """CVSS 3.1 ``roundup`` — the official integer-arithmetic implementation."""
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000
    return (int_input - (int_input % 10000) + 10000) / 100000


def _severity_label(score: float) -> str:
    if score == 0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


def _compute(vector: dict[str, str]) -> tuple[float, float, float]:
    """Return ``(base_score, impact_subscore, exploitability_subscore)``."""
    av = _AV[vector["AV"]]
    ac = _AC[vector["AC"]]
    scope = vector["S"]
    pr = _PR[scope][vector["PR"]]
    ui = _UI[vector["UI"]]
    c = _CIA[vector["C"]]
    i = _CIA[vector["I"]]
    a = _CIA[vector["A"]]

    isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope == "U":
        impact = 6.42 * isc_base
    else:
        impact = 7.52 * (isc_base - 0.029) - 3.25 * ((isc_base - 0.02) ** 15)

    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0:
        base_score = 0.0
    else:
        raw = impact + exploitability
        if scope == "C":
            raw *= 1.08
        base_score = _roundup(min(raw, 10.0))

    return base_score, impact, exploitability


def _to_vector_string(v: dict[str, str]) -> str:
    return (
        f"CVSS:3.1/AV:{v['AV']}/AC:{v['AC']}/PR:{v['PR']}/UI:{v['UI']}/"
        f"S:{v['S']}/C:{v['C']}/I:{v['I']}/A:{v['A']}"
    )


def _adjust_for_finding(vector: dict[str, str], finding: Finding) -> dict[str, str]:
    v = dict(vector)
    if finding.oob_required and v["AC"] == "L":
        v["AC"] = "H"
    if finding.auth_required and v["PR"] == "N":
        v["PR"] = "L"
    if finding.user_interaction_required and v["UI"] == "N":
        v["UI"] = "R"
    return v


def base_vector_for(vuln_class: str) -> dict[str, str]:
    """Return the base vector for ``vuln_class`` (or the default when unknown)."""
    return dict(BASE_VECTORS.get(vuln_class.lower(), _DEFAULT_VECTOR))


def calculate(finding: Finding) -> CVSSResult:
    """Score ``finding`` deterministically per CVSS 3.1."""
    vector = _adjust_for_finding(base_vector_for(finding.vuln_class), finding)
    base_score, impact, exploit = _compute(vector)

    breakdown = {
        "AV": f"{vector['AV']} (Attack Vector)",
        "AC": f"{vector['AC']} (Attack Complexity)",
        "PR": f"{vector['PR']} (Privileges Required)",
        "UI": f"{vector['UI']} (User Interaction)",
        "S": f"{vector['S']} (Scope)",
        "C": f"{vector['C']} (Confidentiality Impact)",
        "I": f"{vector['I']} (Integrity Impact)",
        "A": f"{vector['A']} (Availability Impact)",
    }

    return CVSSResult(
        vector_string=_to_vector_string(vector),
        base_score=base_score,
        severity_label=_severity_label(base_score),
        breakdown=breakdown,
        impact_subscore=round(impact, 2),
        exploitability_subscore=round(exploit, 2),
    )


def is_valid_vector_string(value: str) -> bool:
    """Quick check that ``value`` looks like a CVSS:3.1 vector string."""
    if not value or not value.startswith("CVSS:3.1/"):
        return False
    body = value[len("CVSS:3.1/"):]
    metrics: dict[str, str] = {}
    for part in body.split("/"):
        if ":" not in part:
            return False
        k, v = part.split(":", 1)
        metrics[k] = v
    required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
    return required.issubset(metrics.keys())
