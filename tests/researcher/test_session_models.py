from datetime import datetime

import pytest

from researcher.session.models import (
    ChainHypothesis,
    ChainStatus,
    FailedApproach,
    Observation,
    ObservationType,
    SessionResult,
)


def test_observation_validation():
    obs = Observation(
        observation_id="o1",
        session_id="s1",
        observation_type=ObservationType.NOVEL,
        description="thing",
        related_skill="ssrf/cloud-metadata",
        probe_description="probed X",
    )
    assert obs.observation_type is ObservationType.NOVEL
    assert obs.chain_potential is None


def test_observation_type_enum_strings():
    assert ObservationType.POSITIVE.value == "positive"
    assert ObservationType.CHAIN.value == "chain"


def test_chain_hypothesis_evidence_default():
    chain = ChainHypothesis(
        chain_id="c1",
        session_id="s1",
        chain_name="x",
        from_skill="a",
        to_skill="b",
        trigger="t",
        pivot="p",
        combined_impact="i",
        status=ChainStatus.HYPOTHETICAL,
    )
    assert chain.evidence_observation_ids == []
    assert chain.status is ChainStatus.HYPOTHETICAL


def test_session_result_round_trip():
    s = SessionResult(
        session_id="sid",
        program="p",
        target="t",
        skill_used="ssrf/cloud-metadata",
        scope_file="/scope.json",
        started_at=datetime(2026, 5, 1, 12, 0, 0),
    )
    raw = s.model_dump_json()
    s2 = SessionResult.model_validate_json(raw)
    assert s2.session_id == "sid"
    assert s2.observations == []


def test_failed_approach_required_fields():
    with pytest.raises(Exception):
        FailedApproach(approach="x")  # type: ignore[arg-type]


def test_observation_invalid_type_rejected():
    with pytest.raises(Exception):
        Observation(
            observation_id="o",
            session_id="s",
            observation_type="banana",  # type: ignore[arg-type]
            description="d",
            related_skill="ssrf/x",
            probe_description="p",
        )
