import json

from orchestrator.task_router import TASK_TYPE_MAP, TaskRouter


def _write_task(pending, name, body):
    p = pending / name
    p.write_text(json.dumps(body))
    return p


def test_no_pending_returns_empty(tmp_path):
    router = TaskRouter(pending_dir=tmp_path / "pending", completed_dir=tmp_path / "completed")
    assert router.get_pending_tasks() == {}


def test_classify_by_explicit_task_type(tmp_path):
    pending = tmp_path / "pending"
    pending.mkdir()
    _write_task(pending, "skillgen_ssrf_cm.json",
                {"task_id": "skillgen_ssrf_cm", "task_type": "skill_generation"})
    _write_task(pending, "update_sess_ssrf_cm.json",
                {"task_id": "update_sess_ssrf_cm", "task_type": "skill_update"})
    _write_task(pending, "report_F001.json",
                {"task_id": "report_F001", "task_type": "report_generation"})

    router = TaskRouter(pending_dir=pending, completed_dir=tmp_path / "completed")
    groups = router.get_pending_tasks()
    assert set(groups.keys()) == {"skill_generation", "skill_update", "report_generation"}
    assert len(groups["skill_generation"]) == 1


def test_classify_by_filename_prefix_when_task_type_missing(tmp_path):
    """Tasks without an explicit task_type field should be routed via prefix."""
    pending = tmp_path / "pending"
    pending.mkdir()
    # Body has no task_type — router should classify by filename
    _write_task(pending, "skillgen_x.json", {"task_id": "skillgen_x"})
    _write_task(pending, "update_x.json", {"task_id": "update_x"})
    _write_task(pending, "report_x.json", {"task_id": "report_x"})

    router = TaskRouter(pending_dir=pending, completed_dir=tmp_path / "completed")
    groups = router.get_pending_tasks()
    assert "skill_generation" in groups
    assert "skill_update" in groups
    assert "report_generation" in groups


def test_unknown_prefix_falls_through_to_extraction(tmp_path):
    """A task lacking task_type AND a known prefix is classified as extraction.

    This mirrors the extractor's task_writer behavior — it doesn't tag a
    task_type field and uses uuid-only filenames.
    """
    pending = tmp_path / "pending"
    pending.mkdir()
    _write_task(pending, "abc123.json", {"task_id": "abc123"})

    router = TaskRouter(pending_dir=pending, completed_dir=tmp_path / "completed")
    groups = router.get_pending_tasks()
    assert "extraction" in groups
    assert len(groups["extraction"]) == 1


def test_malformed_task_is_skipped(tmp_path):
    pending = tmp_path / "pending"
    pending.mkdir()
    (pending / "good.json").write_text(json.dumps({"task_type": "skill_update"}))
    (pending / "bad.json").write_text("{not valid json")

    router = TaskRouter(pending_dir=pending, completed_dir=tmp_path / "completed")
    groups = router.get_pending_tasks()
    assert "skill_update" in groups
    assert len(groups.get("skill_update", [])) == 1


def test_task_type_map_has_correct_commands():
    """Each canonical task_type maps to a real component CLI command."""
    expected_commands = {
        "extraction": "python -m extractor.main process-tasks",
        "skill_generation": "python -m generator.main process-tasks",
        "skill_update": "python -m updater.main process-tasks",
        "report_generation": "python -m reporter.main process-tasks",
    }
    for task_type, expected in expected_commands.items():
        assert task_type in TASK_TYPE_MAP
        assert TASK_TYPE_MAP[task_type]["command"] == expected


def test_route_all_returns_grouping(tmp_path):
    pending = tmp_path / "pending"
    pending.mkdir()
    _write_task(pending, "skillgen_a.json", {"task_id": "skillgen_a", "task_type": "skill_generation"})

    router = TaskRouter(pending_dir=pending, completed_dir=tmp_path / "completed")
    groups = router.route_all()
    assert "skill_generation" in groups
