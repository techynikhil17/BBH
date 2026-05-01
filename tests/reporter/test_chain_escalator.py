from researcher.session.models import ChainHypothesis, ChainStatus

from reporter.pipeline.chain_escalator import (
    CHAIN_ESCALATION_RULES,
    escalate,
    find_rule,
)


def _chain(from_skill, to_skill, status=ChainStatus.CONFIRMED):
    return ChainHypothesis(
        chain_id="c1",
        session_id="s1",
        chain_name=f"{from_skill} → {to_skill}",
        from_skill=from_skill,
        to_skill=to_skill,
        trigger="t",
        pivot="p",
        combined_impact="i",
        status=status,
    )


def test_known_rule_ssrf_to_rce():
    rule = find_rule("ssrf/cloud-metadata", "rce/ssti")
    assert rule is not None
    assert rule.from_class == "ssrf"
    assert rule.to_class == "rce"
    assert rule.escalated_severity == "critical"


def test_known_rule_idor_to_auth_bypass():
    rule = find_rule("idor/seq", "auth_bypass/oauth")
    assert rule is not None
    assert rule.escalated_severity == "critical"


def test_unknown_rule_returns_none():
    assert find_rule("not_a_real", "still_not_real") is None


def test_escalate_applied_when_rule_matches():
    chain = _chain("ssrf/cloud-metadata", "rce/ssti")
    result = escalate(chain, base_severity="high")
    assert result.applied
    assert result.escalated_severity == "critical"
    assert "RCE" in result.reasoning or "code execution" in result.reasoning.lower()
    assert result.matched_rule == "ssrf->rce"
    assert result.base_severity == "high"


def test_escalate_no_rule_preserves_base_severity():
    chain = _chain("graphql/x", "csrf/y")  # no rule for this combo
    result = escalate(chain, base_severity="medium")
    assert not result.applied
    assert result.escalated_severity == "medium"
    assert result.matched_rule is None
    assert "no standard escalation" in result.reasoning.lower()


def test_all_rules_have_nonempty_reasoning():
    for rule in CHAIN_ESCALATION_RULES:
        assert rule.reasoning.strip()
        assert rule.escalated_severity in ("critical", "high", "medium", "low")


def test_class_extraction_handles_subtypes():
    """Rule lookup uses just the vuln_class part of the skill id."""
    chain = _chain("file_upload/avatars", "rce/php")
    result = escalate(chain)
    assert result.applied
    assert result.escalated_severity == "critical"
