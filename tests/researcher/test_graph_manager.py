import json
from pathlib import Path

import pytest

from researcher.knowledge.graph_manager import ChainGraph
from researcher.session.models import ChainHypothesis, ChainStatus


def _chain(name="A→B", from_s="ssrf/cloud-metadata", to_s="auth/jwt-bypass", session="s1"):
    return ChainHypothesis(
        chain_id=name,
        session_id=session,
        chain_name=name,
        from_skill=from_s,
        to_skill=to_s,
        trigger="trig",
        pivot="piv",
        combined_impact="impact",
        status=ChainStatus.CONFIRMED,
    )


def test_load_empty_when_missing(tmp_path):
    g = ChainGraph(tmp_path / "graph.json")
    assert g.get_top_chains() == []
    assert g.get_chain_suggestions("ssrf/cloud-metadata") == []


def test_add_then_persist(tmp_path):
    p = tmp_path / "graph.json"
    g = ChainGraph(p)
    g.add_confirmed_chain(_chain())
    assert p.exists()
    raw = json.loads(p.read_text())
    assert raw["chains"][0]["from_skill"] == "ssrf/cloud-metadata"


def test_duplicate_chain_increments_frequency(tmp_path):
    g = ChainGraph(tmp_path / "graph.json")
    g.add_confirmed_chain(_chain(session="s1"))
    g.add_confirmed_chain(_chain(session="s2"))
    g.add_confirmed_chain(_chain(session="s3"))
    top = g.get_top_chains()
    assert len(top) == 1
    assert top[0]["frequency"] == 3


def test_same_session_does_not_double_count(tmp_path):
    g = ChainGraph(tmp_path / "graph.json")
    g.add_confirmed_chain(_chain(session="s1"))
    g.add_confirmed_chain(_chain(session="s1"))
    assert g.get_top_chains()[0]["frequency"] == 1


def test_chain_suggestions_filtered_by_skill(tmp_path):
    g = ChainGraph(tmp_path / "graph.json")
    g.add_confirmed_chain(_chain(from_s="ssrf/cloud-metadata", to_s="auth/jwt-bypass", session="s1"))
    g.add_confirmed_chain(_chain(from_s="rce/ssti", to_s="info_disclosure", session="s2"))
    g.add_confirmed_chain(_chain(from_s="auth/jwt-bypass", to_s="rce/ssti", session="s3"))

    ssrf_chains = g.get_chain_suggestions("ssrf/cloud-metadata")
    assert len(ssrf_chains) == 1

    jwt_chains = g.get_chain_suggestions("auth/jwt-bypass")
    # As both source and target → 2 chains
    assert len(jwt_chains) == 2


def test_confidence_label_from_frequency(tmp_path):
    g = ChainGraph(tmp_path / "graph.json")
    g.add_confirmed_chain(_chain(session="s1"))
    g.add_confirmed_chain(_chain(session="s2"))
    g.add_confirmed_chain(_chain(session="s3"))
    suggestions = g.get_chain_suggestions("ssrf/cloud-metadata")
    assert suggestions[0]["confidence"] == "high"


def test_skill_relationships_split(tmp_path):
    g = ChainGraph(tmp_path / "graph.json")
    g.add_confirmed_chain(_chain(from_s="ssrf/cm", to_s="x"))
    g.add_confirmed_chain(_chain(from_s="y", to_s="ssrf/cm"))
    rels = g.get_skill_relationships("ssrf/cm")
    assert len(rels["outgoing"]) == 1
    assert len(rels["incoming"]) == 1


def test_export_summary_renders_table(tmp_path):
    g = ChainGraph(tmp_path / "graph.json")
    g.add_confirmed_chain(_chain())
    text = g.export_summary()
    assert "From" in text and "To" in text
    assert "ssrf/cloud-metadata" in text


def test_corrupt_graph_falls_back_to_empty(tmp_path):
    p = tmp_path / "graph.json"
    p.write_text("not json")
    g = ChainGraph(p)
    assert g.get_top_chains() == []
    # Now writing should still work
    g.add_confirmed_chain(_chain())
    assert len(g.get_top_chains()) == 1
