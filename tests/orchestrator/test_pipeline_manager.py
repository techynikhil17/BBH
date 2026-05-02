from pathlib import Path
from unittest.mock import patch

import pytest

from orchestrator.pipeline_manager import PipelineManager, StageResult
from orchestrator.scope_enforcer import ScopeEnforcer


def test_session_blocked_when_no_scope_loaded(tmp_path):
    """run_session must refuse when no active scope is on disk."""
    enforcer = ScopeEnforcer(active_scope_path=tmp_path / "active.json")
    pm = PipelineManager(scope=enforcer)
    result = pm.run_session(args=["--program", "x", "--target", "y"])
    assert not result.ok
    assert "no active scope" in result.message.lower()


def test_run_extraction_returns_followup_command(tmp_path):
    """Stages that hand off to Claude Code must surface the next command."""
    pm = PipelineManager(scope=ScopeEnforcer(active_scope_path=tmp_path / "active.json"))
    # Mock the subprocess so we don't actually invoke the extractor
    with patch("orchestrator.pipeline_manager._run", return_value=(0, "", "")):
        result = pm.run_extraction(tmp_path / "fake.jsonl")
    assert result.requires_claude_code
    assert "extractor.main process-tasks" in result.next_command


def test_run_skill_generation_followup(tmp_path):
    pm = PipelineManager(scope=ScopeEnforcer(active_scope_path=tmp_path / "active.json"))
    with patch("orchestrator.pipeline_manager._run", return_value=(0, "", "")):
        result = pm.run_skill_generation(input_path=tmp_path / "p.jsonl", skills_dir=tmp_path / "s")
    assert result.requires_claude_code
    assert "generator.main process-tasks" in result.next_command


def test_run_update_followup(tmp_path):
    pm = PipelineManager(scope=ScopeEnforcer(active_scope_path=tmp_path / "active.json"))
    with patch("orchestrator.pipeline_manager._run", return_value=(0, "", "")):
        result = pm.run_update(tmp_path / "result.json", skills_dir=tmp_path / "s")
    assert result.requires_claude_code
    assert "updater.main process-tasks" in result.next_command


def test_run_report_generation_followup(tmp_path):
    pm = PipelineManager(scope=ScopeEnforcer(active_scope_path=tmp_path / "active.json"))
    with patch("orchestrator.pipeline_manager._run", return_value=(0, "", "")):
        result = pm.run_report_generation(tmp_path / "result.json", platform="hackerone", output_dir=tmp_path / "out")
    assert result.requires_claude_code
    assert "reporter.main process-tasks" in result.next_command


def test_failing_subprocess_returns_failure(tmp_path):
    pm = PipelineManager(scope=ScopeEnforcer(active_scope_path=tmp_path / "active.json"))
    with patch("orchestrator.pipeline_manager._run", return_value=(2, "", "boom")):
        result = pm.run_collection()
    assert not result.ok


def test_full_pipeline_stops_at_scope_gate(tmp_path):
    """When the scope file is missing, full_pipeline halts immediately."""
    enforcer = ScopeEnforcer(active_scope_path=tmp_path / "active.json")
    pm = PipelineManager(scope=enforcer)
    nonexistent_scope = tmp_path / "no_scope.json"
    results = pm.run_full_pipeline(
        program="x",
        scope_file=nonexistent_scope,
        confirm=False,
    )
    assert results
    assert results[-1].stage == "scope"
    assert not results[-1].ok


def test_full_pipeline_runs_collection_when_scope_loads(tmp_path):
    import json

    scope_file = tmp_path / "scope.json"
    scope_file.write_text(json.dumps({
        "program": "demo",
        "in_scope": [{"asset": "*.example.com", "type": "URL"}],
    }))

    enforcer = ScopeEnforcer(active_scope_path=tmp_path / "active.json")
    pm = PipelineManager(scope=enforcer)
    with patch("orchestrator.pipeline_manager._run", return_value=(0, "", "")):
        results = pm.run_full_pipeline(
            program="demo",
            scope_file=scope_file,
            confirm=False,
            limit=5,
        )
    stages = [r.stage for r in results]
    assert "collection" in stages
