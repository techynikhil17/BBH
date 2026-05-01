from datetime import datetime

from researcher.prompts.session_brief import generate_session_brief
from researcher.session.models import (
    ChainHypothesis,
    ChainStatus,
    FailedApproach,
    Observation,
    ObservationType,
    SessionResult,
)


_SKILL_MD = """# SKILL: SSRF
**Category:** ssrf > cloud-metadata

---

## OVERVIEW
Body.

## PRECONDITIONS
- [ ] Endpoint accepts a user-supplied URL
- [ ] Server fetches the URL during normal operation

## ASSUMPTIONS TO CHALLENGE
- [ ] Internal hosts unreachable from outside

## FAILED APPROACHES
| Approach | Why It Failed | Date | Session |
|----------|---------------|------|---------|
| Tested host header | Server normalizes Host | 2026-01-01 | sess-old |

## REPORTING TEMPLATE HINTS
y
"""


def _session(session_id="sess1", with_obs=False, with_failed=False):
    obs = []
    if with_obs:
        obs = [
            Observation(
                observation_id="o1",
                session_id=session_id,
                observation_type=ObservationType.NOVEL,
                description="Saw weird header reflection",
                related_skill="ssrf/cloud-metadata",
                probe_description="Probed feedback endpoint",
            )
        ]
    failed = []
    if with_failed:
        failed = [
            FailedApproach(
                approach="Replayed token",
                reason="Token nonce changes per request",
                skill="ssrf/cloud-metadata",
                date="2026-05-01",
                session_id=session_id,
            )
        ]
    return SessionResult(
        session_id=session_id,
        program="shopify",
        target="api.shopify.com",
        skill_used="ssrf/cloud-metadata",
        scope_file="/scope.json",
        started_at=datetime(2026, 5, 1, 12, 0, 0),
        observations=obs,
        failed_approaches=failed,
    )


def test_brief_contains_required_sections():
    brief = generate_session_brief(
        skill_content=_SKILL_MD,
        session=_session(),
        recon_data={},
        chain_suggestions=[],
        observations_so_far=[],
        scope_summary="**Program:** shopify",
    )
    for header in (
        "RESEARCH BRIEF",
        "## SCOPE CONFIRMATION",
        "## TECH STACK",
        "## SKILL SUMMARY",
        "## CHAIN OPPORTUNITIES",
        "## SESSION OBSERVATIONS SO FAR",
        "## FAILED APPROACHES",
        "## YOUR TASK",
    ):
        assert header in brief, f"missing section: {header}"


def test_brief_includes_preconditions_and_assumptions():
    brief = generate_session_brief(
        skill_content=_SKILL_MD,
        session=_session(),
        recon_data={},
        chain_suggestions=[],
        observations_so_far=[],
    )
    assert "Endpoint accepts a user-supplied URL" in brief
    assert "Internal hosts unreachable from outside" in brief


def test_brief_includes_skill_failed_approaches():
    brief = generate_session_brief(
        skill_content=_SKILL_MD,
        session=_session(),
        recon_data={},
        chain_suggestions=[],
        observations_so_far=[],
    )
    assert "Tested host header" in brief
    assert "Server normalizes Host" in brief


def test_brief_renders_observations_table():
    s = _session(with_obs=True)
    brief = generate_session_brief(
        skill_content=_SKILL_MD,
        session=s,
        recon_data={},
        chain_suggestions=[],
        observations_so_far=s.observations,
    )
    assert "weird header reflection" in brief
    assert "novel" in brief


def test_brief_renders_chain_suggestions():
    chains = [
        {
            "from_skill": "ssrf/cloud-metadata",
            "to_skill": "auth/jwt-bypass",
            "frequency": 3,
            "confidence": "high",
            "trigger": "metadata reachable",
        }
    ]
    brief = generate_session_brief(
        skill_content=_SKILL_MD,
        session=_session(),
        recon_data={},
        chain_suggestions=chains,
        observations_so_far=[],
    )
    assert "auth/jwt-bypass" in brief
    assert "high" in brief


def test_brief_includes_session_failed_approaches():
    s = _session(with_failed=True)
    brief = generate_session_brief(
        skill_content=_SKILL_MD,
        session=s,
        recon_data={},
        chain_suggestions=[],
        observations_so_far=[],
    )
    assert "Replayed token" in brief
    assert "This session" in brief


def test_recon_block_renders():
    brief = generate_session_brief(
        skill_content=_SKILL_MD,
        session=_session(),
        recon_data={"stack": "rails", "cloud": "aws", "auth": "oauth"},
        chain_suggestions=[],
        observations_so_far=[],
    )
    assert "rails" in brief and "aws" in brief
