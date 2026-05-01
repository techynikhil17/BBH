import json
from datetime import datetime
from pathlib import Path

import pytest

from researcher.session.models import (
    ChainHypothesis,
    ChainStatus,
    FailedApproach,
    Observation,
    ObservationType,
    SessionResult,
)
from updater.pipeline.diff_analyzer import DiffAnalyzer


_SKILL_TEXT = """# SKILL: SSRF
**Version:** 1.0.0

## NOVEL DISCOVERIES LOG
| Date | Session ID | Discovery | Chain Potential | Incorporated |
|------|------------|-----------|-----------------|--------------|
| 2026-04-01 | sess-old | reflected metadata header | high | ⏳ |

## ATTACK CHAINS DISCOVERED


## FAILED APPROACHES
| Approach | Why It Failed | Date | Session |
|----------|---------------|------|---------|
| host header | normalized | 2026-04-01 | sess-old |
"""


def _session(observations=None, chains=None, failed=None, sid="sess-new", skill="ssrf/cloud-metadata"):
    return SessionResult(
        session_id=sid,
        program="shopify",
        target="api.shopify.com",
        skill_used=skill,
        scope_file="/scope.json",
        started_at=datetime(2026, 5, 1),
        observations=observations or [],
        chains=chains or [],
        failed_approaches=failed or [],
    )


def _obs(desc, sid="sess-new", chain_potential=None, type_=ObservationType.NOVEL, skill="ssrf/cloud-metadata"):
    return Observation(
        observation_id=desc[:8],
        session_id=sid,
        observation_type=type_,
        description=desc,
        related_skill=skill,
        probe_description="probed",
        chain_potential=chain_potential,
    )


def _chain(name="A→B", from_s="ssrf/cloud-metadata", to_s="auth/jwt-bypass", sid="sess-new"):
    return ChainHypothesis(
        chain_id=name,
        session_id=sid,
        chain_name=name,
        from_skill=from_s,
        to_skill=to_s,
        trigger="t",
        pivot="p",
        combined_impact="i",
        status=ChainStatus.CONFIRMED,
    )


def _failed(approach, skill="ssrf/cloud-metadata", sid="sess-new"):
    return FailedApproach(approach=approach, reason="r", skill=skill, date="2026-05-01", session_id=sid)


def _setup_skill(tmp_path) -> Path:
    p = tmp_path / "skill.md"
    p.write_text(_SKILL_TEXT, encoding="utf-8")
    return p


def _write_session_dir(tmp_path, session: SessionResult):
    """Used so the pattern_promoter sees the session in its cross-session index."""
    d = tmp_path / "sessions" / session.session_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "result.json").write_text(session.model_dump_json(), encoding="utf-8")


def test_novel_already_logged_is_filtered(tmp_path):
    skill = _setup_skill(tmp_path)
    # Use an observation whose normalized form matches the existing log entry exactly
    session = _session(observations=[_obs("Reflected metadata header")])
    da = DiffAnalyzer(sessions_dir=tmp_path / "sessions")
    diff = da.analyze(session, skill)
    assert diff.novel_observations == []


def test_novel_not_yet_logged_is_returned(tmp_path):
    skill = _setup_skill(tmp_path)
    session = _session(observations=[_obs("Bypass via SVG image href")])
    da = DiffAnalyzer(sessions_dir=tmp_path / "sessions")
    diff = da.analyze(session, skill)
    assert len(diff.novel_observations) == 1
    assert "SVG image href" in diff.novel_observations[0]["description"]


def test_chains_not_yet_logged(tmp_path):
    skill = _setup_skill(tmp_path)
    session = _session(chains=[_chain(name="SSRF to Redis")])
    da = DiffAnalyzer(sessions_dir=tmp_path / "sessions")
    diff = da.analyze(session, skill)
    assert len(diff.confirmed_chains) == 1


def test_failed_already_logged_is_filtered(tmp_path):
    skill = _setup_skill(tmp_path)
    session = _session(failed=[_failed("host header")])
    da = DiffAnalyzer(sessions_dir=tmp_path / "sessions")
    diff = da.analyze(session, skill)
    assert diff.failed_approaches == []


def test_failed_not_yet_logged(tmp_path):
    skill = _setup_skill(tmp_path)
    session = _session(failed=[_failed("brand new approach we tried")])
    da = DiffAnalyzer(sessions_dir=tmp_path / "sessions")
    diff = da.analyze(session, skill)
    assert len(diff.failed_approaches) == 1


def test_promotable_pattern_after_two_sessions(tmp_path):
    """Two distinct sessions reporting the same novel description → promotable."""
    skill = _setup_skill(tmp_path)
    s1 = _session(
        sid="sess-1", observations=[_obs("Same novel pattern across runs", sid="sess-1")]
    )
    s2 = _session(
        sid="sess-2", observations=[_obs("Same novel pattern across runs", sid="sess-2")]
    )
    _write_session_dir(tmp_path, s1)
    _write_session_dir(tmp_path, s2)

    # Analyze against an arbitrary "current" session
    s3 = _session(sid="sess-3", observations=[_obs("Same novel pattern across runs", sid="sess-3")])
    da = DiffAnalyzer(sessions_dir=tmp_path / "sessions")
    diff = da.analyze(s3, skill)
    # s1 + s2 already gave us 2 sessions — promotable
    assert len(diff.promotable_patterns) == 1
    assert diff.needs_structural_update is True


def test_pending_pattern_after_one_session(tmp_path):
    skill = _setup_skill(tmp_path)
    s1 = _session(sid="sess-1", observations=[_obs("Only seen once", sid="sess-1")])
    _write_session_dir(tmp_path, s1)
    s2 = _session(sid="sess-2", observations=[_obs("Only seen once", sid="sess-2")])

    # Before s2 is persisted, only s1 has logged this pattern
    da = DiffAnalyzer(sessions_dir=tmp_path / "sessions")
    diff = da.analyze(s2, skill)
    # Pending: 1 session has logged it, needs 1 more
    assert len(diff.pending_patterns) == 1
    assert len(diff.promotable_patterns) == 0


def test_nothing_to_update(tmp_path):
    skill = _setup_skill(tmp_path)
    session = _session()  # no observations / chains / failures
    da = DiffAnalyzer(sessions_dir=tmp_path / "sessions")
    diff = da.analyze(session, skill)
    assert diff.nothing_to_update
