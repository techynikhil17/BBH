from datetime import datetime

import pytest

from researcher.session.models import (
    ChainHypothesis,
    ChainStatus,
    Observation,
    ObservationType,
    SessionResult,
)

from reporter.pipeline.finding_loader import filter_findings, load_findings


def _session(observations=None, chains=None, findings=None):
    return SessionResult(
        session_id="sess-1",
        program="shopify",
        target="api.shopify.com",
        skill_used="ssrf/cloud-metadata",
        scope_file="/scope.json",
        started_at=datetime(2026, 5, 1),
        observations=observations or [],
        chains=chains or [],
        findings=findings or [],
    )


def _obs(type_=ObservationType.POSITIVE, related_skill="ssrf/cloud-metadata", desc="Found something"):
    return Observation(
        observation_id="o1",
        session_id="sess-1",
        observation_type=type_,
        description=desc,
        related_skill=related_skill,
        probe_description="probe",
    )


def _chain(status=ChainStatus.CONFIRMED, from_s="ssrf/cloud-metadata", to_s="auth/jwt-bypass"):
    return ChainHypothesis(
        chain_id="c1",
        session_id="sess-1",
        chain_name=f"{from_s} → {to_s}",
        from_skill=from_s,
        to_skill=to_s,
        trigger="t",
        pivot="p",
        combined_impact="i",
        status=status,
    )


def test_load_from_explicit_findings_list():
    explicit = [{
        "finding_id": "F001",
        "session_id": "sess-1",
        "vuln_class": "ssrf",
        "vuln_subtype": "cloud-metadata",
        "target": "api.shopify.com",
        "affected_feature": "webhook",
        "severity": "high",
        "confirmed": True,
        "is_chain": False,
        "evidence_description": "from explicit list",
    }]
    findings = load_findings(_session(findings=explicit))
    assert len(findings) == 1
    assert findings[0].evidence_description == "from explicit list"


def test_derive_findings_from_positive_observations():
    s = _session(observations=[
        _obs(type_=ObservationType.POSITIVE, desc="Confirmed signal A"),
        _obs(type_=ObservationType.NEGATIVE, desc="Negative — not a finding"),
        _obs(type_=ObservationType.POSITIVE, desc="Confirmed signal B"),
    ])
    findings = load_findings(s)
    assert len(findings) == 2
    descs = [f.evidence_description for f in findings]
    assert "Confirmed signal A" in descs
    assert "Confirmed signal B" in descs


def test_novel_observations_not_treated_as_findings():
    s = _session(observations=[_obs(type_=ObservationType.NOVEL, desc="Interesting but unconfirmed")])
    assert load_findings(s) == []


def test_chain_finding_built_from_confirmed_chain():
    s = _session(chains=[_chain()])
    findings = load_findings(s)
    assert len(findings) == 1
    assert findings[0].is_chain
    assert findings[0].chain_id == "c1"
    assert findings[0].chain_steps  # has Trigger / Pivot / Impact


def test_unconfirmed_chain_skipped():
    s = _session(chains=[_chain(status=ChainStatus.HYPOTHETICAL)])
    assert load_findings(s) == []


def test_filter_by_finding_id():
    s = _session(observations=[_obs(desc="A"), _obs(desc="B")])
    all_f = load_findings(s)
    target_id = all_f[0].finding_id
    filtered = filter_findings(all_f, finding_id=target_id)
    assert len(filtered) == 1
    assert filtered[0].finding_id == target_id


def test_filter_by_chain_id():
    s = _session(chains=[_chain()])
    findings = load_findings(s)
    filtered = filter_findings(findings, chain_id="c1")
    assert len(filtered) == 1
    assert filtered[0].chain_id == "c1"


def test_finding_id_format():
    s = _session(observations=[_obs(desc="a")])
    findings = load_findings(s)
    assert findings[0].finding_id.startswith("F001_")
    assert "sess-1" in findings[0].finding_id


def test_vuln_class_split_from_skill():
    s = _session(observations=[_obs(related_skill="rce/ssti", desc="x")])
    findings = load_findings(s)
    assert findings[0].vuln_class == "rce"
    assert findings[0].vuln_subtype == "ssti"


def test_explicit_list_with_malformed_entry_is_skipped():
    explicit = [
        {"finding_id": "F001", "session_id": "sess-1", "vuln_class": "ssrf", "target": "x"},
        {"this": "is not a valid finding"},
    ]
    findings = load_findings(_session(findings=explicit))
    assert len(findings) == 1
