import json
from datetime import datetime
from pathlib import Path

import pytest

from researcher.session.models import ChainHypothesis, ChainStatus
from updater.pipeline.chain_propagator import ChainPropagator


_SKILL_TEMPLATE = """# SKILL: {name}
**Version:** 1.0.0

## ATTACK CHAINS DISCOVERED


## REPORTING TEMPLATE HINTS
y
"""


def _setup_skills(tmp_path) -> Path:
    """Create skills/ssrf/cloud-metadata/skill.md and skills/auth/jwt-bypass/skill.md."""
    skills = tmp_path / "skills"
    a = skills / "ssrf" / "cloud-metadata"
    b = skills / "auth" / "jwt-bypass"
    a.mkdir(parents=True)
    b.mkdir(parents=True)
    (a / "skill.md").write_text(_SKILL_TEMPLATE.format(name="A"), encoding="utf-8")
    (b / "skill.md").write_text(_SKILL_TEMPLATE.format(name="B"), encoding="utf-8")
    return skills


def _chain():
    return ChainHypothesis(
        chain_id="c1",
        session_id="sess-1",
        chain_name="SSRF → JWT bypass",
        from_skill="ssrf/cloud-metadata",
        to_skill="auth/jwt-bypass",
        trigger="metadata reachable",
        pivot="exfil signing key",
        combined_impact="account takeover",
        status=ChainStatus.CONFIRMED,
    )


def test_propagate_updates_both_skill_files(tmp_path):
    skills = _setup_skills(tmp_path)
    graph = tmp_path / "graph.json"
    propagator = ChainPropagator(skills_dir=skills, graph_path=graph)
    result = propagator.propagate([_chain()])

    assert result.chains_propagated == 1
    assert len(result.skills_updated) == 2

    a_text = (skills / "ssrf" / "cloud-metadata" / "skill.md").read_text(encoding="utf-8")
    b_text = (skills / "auth" / "jwt-bypass" / "skill.md").read_text(encoding="utf-8")

    # Forward perspective on the from_skill, reverse on the to_skill
    assert "forward" in a_text.lower()
    assert "incoming chain" in b_text.lower()


def test_propagate_persists_to_graph(tmp_path):
    skills = _setup_skills(tmp_path)
    graph_path = tmp_path / "graph.json"
    propagator = ChainPropagator(skills_dir=skills, graph_path=graph_path)
    propagator.propagate([_chain()])

    assert graph_path.exists()
    data = json.loads(graph_path.read_text())
    assert any(
        c["from_skill"] == "ssrf/cloud-metadata" and c["to_skill"] == "auth/jwt-bypass"
        for c in data["chains"]
    )


def test_unconfirmed_chains_skipped(tmp_path):
    skills = _setup_skills(tmp_path)
    graph_path = tmp_path / "graph.json"
    chain = _chain().model_copy(update={"status": ChainStatus.HYPOTHETICAL})
    propagator = ChainPropagator(skills_dir=skills, graph_path=graph_path)
    result = propagator.propagate([chain])
    assert result.chains_propagated == 0
    assert result.skills_updated == []


def test_missing_skill_records_error(tmp_path):
    """When one side of a chain has no skill file, propagator records the error."""
    skills = tmp_path / "skills"
    (skills / "ssrf" / "cloud-metadata").mkdir(parents=True)
    (skills / "ssrf" / "cloud-metadata" / "skill.md").write_text(
        _SKILL_TEMPLATE.format(name="A"), encoding="utf-8"
    )
    # NOT creating auth/jwt-bypass

    graph_path = tmp_path / "graph.json"
    propagator = ChainPropagator(skills_dir=skills, graph_path=graph_path)
    result = propagator.propagate([_chain()])

    assert any("auth/jwt-bypass" in e for e in result.errors)
    # The chain still counts as propagated (one side did update + graph entry)
    assert result.chains_propagated == 1


def test_repeated_propagation_does_not_double_count_in_graph(tmp_path):
    skills = _setup_skills(tmp_path)
    graph_path = tmp_path / "graph.json"
    propagator = ChainPropagator(skills_dir=skills, graph_path=graph_path)

    chain = _chain()
    propagator.propagate([chain])
    propagator.propagate([chain])  # same session_id

    data = json.loads(graph_path.read_text())
    matching = [
        c for c in data["chains"]
        if c["from_skill"] == chain.from_skill and c["to_skill"] == chain.to_skill
    ]
    assert len(matching) == 1
    assert matching[0]["frequency"] == 1  # same session — no double-count
