import pytest

from reporter.models import Finding
from reporter.pipeline.cvss_calculator import (
    BASE_VECTORS,
    base_vector_for,
    calculate,
    is_valid_vector_string,
)


def _finding(vuln_class="ssrf", **kwargs) -> Finding:
    base = dict(
        finding_id="F001",
        session_id="s1",
        vuln_class=vuln_class,
        target="api.example.com",
    )
    base.update(kwargs)
    return Finding(**base)


def test_base_vector_known_class():
    v = base_vector_for("ssrf")
    assert v == BASE_VECTORS["ssrf"]


def test_base_vector_unknown_class_falls_back():
    v = base_vector_for("not_a_real_class")
    assert v == BASE_VECTORS["business_logic"]


def test_calculate_returns_valid_vector_string():
    result = calculate(_finding(vuln_class="ssrf"))
    assert is_valid_vector_string(result.vector_string)
    assert "CVSS:3.1/" in result.vector_string


def test_severity_labels_match_score():
    """Score → label mapping per CVSS 3.1 qualitative ratings."""
    rce = calculate(_finding(vuln_class="rce"))
    # RCE/N/L/N/N/C/H/H/H — scope changed, all-high → 10.0 critical
    assert rce.base_score >= 9.0
    assert rce.severity_label == "Critical"

    csrf = calculate(_finding(vuln_class="csrf"))
    # CSRF/N/L/N/R/U/N/L/N — should land in low
    assert 0 < csrf.base_score < 7
    assert csrf.severity_label in ("Low", "Medium")


def test_oob_required_raises_attack_complexity():
    """oob_required hint should bump AC L→H, lowering exploitability."""
    base = calculate(_finding(vuln_class="ssrf", oob_required=False))
    bumped = calculate(_finding(vuln_class="ssrf", oob_required=True))
    assert bumped.base_score <= base.base_score
    assert "AC:H" in bumped.vector_string
    assert "AC:L" in base.vector_string


def test_auth_required_raises_privileges_required():
    """auth_required hint should bump PR N→L when base PR was N."""
    # RCE base has PR:N; auth_required should push to PR:L
    base = calculate(_finding(vuln_class="rce", auth_required=False))
    auth = calculate(_finding(vuln_class="rce", auth_required=True))
    assert auth.base_score <= base.base_score
    assert "PR:L" in auth.vector_string
    assert "PR:N" in base.vector_string


def test_user_interaction_required_bumps_ui():
    base = calculate(_finding(vuln_class="ssrf", user_interaction_required=False))
    ui = calculate(_finding(vuln_class="ssrf", user_interaction_required=True))
    assert "UI:R" in ui.vector_string
    assert "UI:N" in base.vector_string
    assert ui.base_score <= base.base_score


def test_breakdown_contains_all_metrics():
    result = calculate(_finding(vuln_class="ssrf"))
    for metric in ("AV", "AC", "PR", "UI", "S", "C", "I", "A"):
        assert metric in result.breakdown


def test_score_is_rounded_to_one_decimal():
    """CVSS 3.1 mandates roundup to nearest tenth."""
    result = calculate(_finding(vuln_class="rce"))
    # Score's (10x) representation should be an integer
    times_ten = round(result.base_score * 10)
    assert abs(result.base_score * 10 - times_ten) < 1e-9


def test_is_valid_vector_string():
    assert is_valid_vector_string("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert not is_valid_vector_string("AV:N/AC:L")
    assert not is_valid_vector_string("")
    assert not is_valid_vector_string("CVSS:3.1/AV:N")  # missing required


def test_unknown_class_does_not_crash():
    result = calculate(_finding(vuln_class="totally_made_up"))
    assert result.base_score >= 0
    assert is_valid_vector_string(result.vector_string)


def test_critical_score_above_9():
    """RCE without auth or OOB should be critical."""
    result = calculate(_finding(vuln_class="rce"))
    assert result.severity_label == "Critical"
