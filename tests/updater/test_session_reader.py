import json

import pytest

from updater.pipeline.session_reader import (
    InvalidSessionError,
    list_session_files,
    read_all_sessions,
    read_session,
)


def _valid_session_dict(**overrides):
    base = {
        "session_id": "shopify_20260501_abc",
        "program": "shopify",
        "target": "api.shopify.com",
        "skill_used": "ssrf/cloud-metadata",
        "scope_file": "/scope.json",
        "started_at": "2026-05-01T12:00:00",
        "ended_at": "2026-05-01T13:00:00",
        "observations": [],
        "chains": [],
        "failed_approaches": [],
        "skill_files_updated": [],
        "novel_signals": [],
        "findings": [],
        "status": "completed",
    }
    base.update(overrides)
    return base


def test_read_session_valid(tmp_path):
    p = tmp_path / "result.json"
    p.write_text(json.dumps(_valid_session_dict()))
    s = read_session(p)
    assert s.session_id == "shopify_20260501_abc"
    assert s.skill_used == "ssrf/cloud-metadata"


def test_read_session_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_session(tmp_path / "nope.json")


def test_read_session_malformed_json(tmp_path):
    p = tmp_path / "result.json"
    p.write_text("{not json")
    with pytest.raises(InvalidSessionError):
        read_session(p)


def test_read_session_schema_mismatch(tmp_path):
    p = tmp_path / "result.json"
    p.write_text(json.dumps({"session_id": "x"}))  # missing required fields
    with pytest.raises(InvalidSessionError):
        read_session(p)


def test_list_session_files(tmp_path):
    (tmp_path / "s1").mkdir()
    (tmp_path / "s1" / "result.json").write_text(json.dumps(_valid_session_dict(session_id="s1")))
    (tmp_path / "s2").mkdir()
    (tmp_path / "s2" / "result.json").write_text(json.dumps(_valid_session_dict(session_id="s2")))
    (tmp_path / "irrelevant.txt").write_text("ignore")
    files = list_session_files(tmp_path)
    assert len(files) == 2


def test_read_all_sessions_skips_malformed(tmp_path):
    (tmp_path / "good").mkdir()
    (tmp_path / "good" / "result.json").write_text(json.dumps(_valid_session_dict(session_id="good")))
    (tmp_path / "bad").mkdir()
    (tmp_path / "bad" / "result.json").write_text("{not json")
    sessions = read_all_sessions(tmp_path)
    assert len(sessions) == 1
    assert sessions[0].session_id == "good"
