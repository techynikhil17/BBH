"""Render the final markdown report from Claude Code's task output.

Task output supplies the seven narrative sections; CVSS, references and
the platform template are added by Python so the rendered file is
deterministic given the same task output + finding + cvss.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..config import TEMPLATE_DIR
from ..models import CVSSResult, EscalationResult, Finding, ReportDraft


# Reasonable defaults — extend as you learn more about each class.
CWE_MAP: dict[str, str] = {
    "ssrf": "CWE-918",
    "rce": "CWE-94",
    "idor": "CWE-639",
    "sqli": "CWE-89",
    "ssti": "CWE-1336",
    "auth_bypass": "CWE-287",
    "xxe": "CWE-611",
    "deserialization": "CWE-502",
    "race_condition": "CWE-362",
    "business_logic": "CWE-840",
    "mass_assignment": "CWE-915",
    "subdomain_takeover": "CWE-1395",
    "file_upload": "CWE-434",
    "graphql": "CWE-200",
    "oauth_misconfig": "CWE-352",
    "open_redirect": "CWE-601",
    "xss": "CWE-79",
    "csrf": "CWE-352",
    "info_disclosure": "CWE-200",
    "path_traversal": "CWE-22",
    "command_injection": "CWE-77",
}

OWASP_MAP: dict[str, str] = {
    "ssrf": "A10:2021",
    "rce": "A03:2021",
    "idor": "A01:2021",
    "sqli": "A03:2021",
    "ssti": "A03:2021",
    "auth_bypass": "A07:2021",
    "xxe": "A05:2021",
    "deserialization": "A08:2021",
    "race_condition": "A04:2021",
    "business_logic": "A04:2021",
    "mass_assignment": "A04:2021",
    "subdomain_takeover": "A05:2021",
    "file_upload": "A04:2021",
    "graphql": "A01:2021",
    "oauth_misconfig": "A07:2021",
    "open_redirect": "A01:2021",
    "xss": "A03:2021",
    "csrf": "A01:2021",
    "info_disclosure": "A01:2021",
    "path_traversal": "A01:2021",
    "command_injection": "A03:2021",
}


REQUIRED_KEYS: tuple[str, ...] = (
    "title",
    "summary",
    "vulnerability_details",
    "impact_analysis",
    "steps_to_reproduce",
    "proof_of_concept",
    "remediation",
)


_DEFAULT_HUMAN_REVIEW = (
    "Steps to Reproduce — verify reproducibility before submitting",
    "Proof of Concept — verify evidence is current and accurate",
    "CVSS Score — verify scoring matches actual impact",
)


def _references_for(finding: Finding) -> dict[str, str]:
    return {
        "cwe": CWE_MAP.get(finding.vuln_class, "CWE-20"),
        "owasp": OWASP_MAP.get(finding.vuln_class, "A04:2021"),
        "similar_reports": "",
    }


def _make_env(template_dir: Path = TEMPLATE_DIR) -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(disabled_extensions=("md", "j2"), default=False),
        trim_blocks=False,
        lstrip_blocks=False,
    )
    return env


def _missing_keys(task_output: dict[str, Any]) -> list[str]:
    return [k for k in REQUIRED_KEYS if not (task_output.get(k) or "").strip()] if isinstance(task_output, dict) else list(REQUIRED_KEYS)


def assemble_report(
    task_output: dict[str, Any],
    finding: Finding,
    cvss: CVSSResult,
    *,
    platform: str,
    template_dir: Path = TEMPLATE_DIR,
    chain_escalation: Optional[EscalationResult] = None,
) -> ReportDraft:
    """Render the report markdown for one finding.

    Raises ``ValueError`` when the task output is missing required keys.
    """
    missing = _missing_keys(task_output)
    if missing:
        raise ValueError(f"task output missing required sections: {', '.join(missing)}")

    env = _make_env(template_dir)
    template = env.get_template(f"{platform}.md.j2")
    references = _references_for(finding)

    rendered = template.render(
        title=task_output["title"].strip(),
        summary=task_output["summary"].strip(),
        vulnerability_details=task_output["vulnerability_details"].strip(),
        impact_analysis=task_output["impact_analysis"].strip(),
        steps_to_reproduce=task_output["steps_to_reproduce"].strip(),
        proof_of_concept=task_output["proof_of_concept"].strip(),
        remediation=task_output["remediation"].strip(),
        cvss=cvss,
        references=references,
        finding=finding,
    )

    return ReportDraft(
        finding_id=finding.finding_id,
        session_id=finding.session_id,
        platform=platform,
        title=task_output["title"].strip(),
        summary=task_output["summary"].strip(),
        vulnerability_details=task_output["vulnerability_details"].strip(),
        impact_analysis=task_output["impact_analysis"].strip(),
        steps_to_reproduce=task_output["steps_to_reproduce"].strip(),
        proof_of_concept=task_output["proof_of_concept"].strip(),
        remediation=task_output["remediation"].strip(),
        cvss=cvss,
        references=references,
        rendered_markdown=rendered,
        word_count=len(rendered.split()),
        generated_at=datetime.now(),
        requires_human_review=list(_DEFAULT_HUMAN_REVIEW),
        quality_flags=[],
    )


def assemble_chain_report(
    task_output: dict[str, Any],
    *,
    chain_finding: Finding,
    component_findings: list[Finding],
    cvss: CVSSResult,
    escalation: Optional[EscalationResult],
    template_dir: Path = TEMPLATE_DIR,
) -> ReportDraft:
    """Render the chain template for one chain finding."""
    missing = _missing_keys(task_output)
    if missing:
        raise ValueError(f"task output missing required sections: {', '.join(missing)}")

    env = _make_env(template_dir)
    template = env.get_template("chain_report.md.j2")
    references = _references_for(chain_finding)

    rendered = template.render(
        chain_name=chain_finding.chain_name or "Confirmed chain",
        target=chain_finding.target,
        from_skill=chain_finding.affected_feature.split("/", 1)[0] if "/" in chain_finding.affected_feature else chain_finding.affected_feature,
        to_skill=(chain_finding.notes or chain_finding.evidence_description or ""),
        cvss=cvss,
        escalation=escalation,
        summary=task_output["summary"].strip(),
        vulnerability_details=task_output["vulnerability_details"].strip(),
        impact_analysis=task_output["impact_analysis"].strip(),
        steps_to_reproduce=task_output["steps_to_reproduce"].strip(),
        proof_of_concept=task_output["proof_of_concept"].strip(),
        remediation=task_output["remediation"].strip(),
        chain_findings=[
            {
                "title": f.evidence_description or f.finding_id,
                "vulnerability_details": f.notes or f.evidence_description,
            }
            for f in component_findings
        ],
        references=references,
    )

    return ReportDraft(
        finding_id=chain_finding.finding_id,
        session_id=chain_finding.session_id,
        platform="chain",
        title=task_output["title"].strip(),
        summary=task_output["summary"].strip(),
        vulnerability_details=task_output["vulnerability_details"].strip(),
        impact_analysis=task_output["impact_analysis"].strip(),
        steps_to_reproduce=task_output["steps_to_reproduce"].strip(),
        proof_of_concept=task_output["proof_of_concept"].strip(),
        remediation=task_output["remediation"].strip(),
        cvss=cvss,
        references=references,
        rendered_markdown=rendered,
        word_count=len(rendered.split()),
        generated_at=datetime.now(),
        requires_human_review=list(_DEFAULT_HUMAN_REVIEW),
        quality_flags=[],
    )
