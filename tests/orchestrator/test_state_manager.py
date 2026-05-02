import pytest

from orchestrator.state_manager import StateManager


async def test_record_and_update_pipeline_run(tmp_path):
    db = tmp_path / "state.db"
    async with StateManager(db) as sm:
        run_id = await sm.record_pipeline_run("collection", detail={"sources": ["pentesterland"]})
        assert isinstance(run_id, int)
        await sm.update_pipeline_run(
            run_id, status="completed", result_path="/tmp/x", detail={"reports": 12},
        )
        history = await sm.get_pipeline_history()

    assert len(history) == 1
    assert history[0]["stage"] == "collection"
    assert history[0]["status"] == "completed"
    assert history[0]["result_path"] == "/tmp/x"


async def test_active_session_upsert(tmp_path):
    async with StateManager(tmp_path / "state.db") as sm:
        await sm.upsert_active_session(
            session_id="s1", program="shopify", target="api.shopify.com",
            skill="ssrf/cm", status="active",
        )
        active = await sm.get_active_sessions()
        assert len(active) == 1
        # Mark it ended
        await sm.upsert_active_session(
            session_id="s1", program="shopify", target="api.shopify.com",
            skill="ssrf/cm", status="completed", ended_at="2026-05-02T12:00:00",
        )
        active = await sm.get_active_sessions()
        assert active == []


async def test_skill_version_upsert(tmp_path):
    async with StateManager(tmp_path / "state.db") as sm:
        await sm.upsert_skill_version(
            "ssrf/cm", version="1.0.0", last_updated="2026-05-01",
            pattern_count=5, session_count=2,
        )
        # Upsert: bump version
        await sm.upsert_skill_version(
            "ssrf/cm", version="1.1.0", last_updated="2026-05-02",
            pattern_count=8, session_count=3,
        )
        stats = await sm.get_skill_stats()
    assert len(stats) == 1
    assert stats[0]["version"] == "1.1.0"
    assert stats[0]["pattern_count"] == 8


async def test_chain_stat_upsert_and_top(tmp_path):
    async with StateManager(tmp_path / "state.db") as sm:
        await sm.upsert_chain_stat("ssrf/cm", "rce/ssti", frequency=4, last_confirmed="2026-05-01")
        await sm.upsert_chain_stat("idor/x", "auth/y", frequency=2, last_confirmed="2026-05-02")
        top = await sm.get_chain_stats(top_n=10)
    assert len(top) == 2
    assert top[0]["from_skill"] == "ssrf/cm"
    assert top[0]["frequency"] == 4


async def test_task_history_records_and_completes(tmp_path):
    async with StateManager(tmp_path / "state.db") as sm:
        await sm.record_task("t1", "skill_generation", "generator")
        await sm.mark_task_complete("t1")
        rows = await sm.get_task_history()
    assert rows[0]["task_id"] == "t1"
    assert rows[0]["status"] == "completed"


async def test_system_summary_keys_present(tmp_path):
    async with StateManager(tmp_path / "state.db") as sm:
        # Empty DB
        summary = await sm.get_system_summary()
        for key in ("stage_counts", "skill_count", "pattern_count", "active_sessions", "top_chains"):
            assert key in summary

        # With content
        await sm.upsert_skill_version("a", version="1", last_updated="d", pattern_count=3)
        run_id = await sm.record_pipeline_run("collection")
        await sm.update_pipeline_run(run_id, "completed")
        summary = await sm.get_system_summary()

    assert summary["skill_count"] == 1
    assert summary["pattern_count"] == 3
    assert "collection" in summary["stage_counts"]


async def test_get_all_sessions_orders_newest_first(tmp_path):
    async with StateManager(tmp_path / "state.db") as sm:
        await sm.upsert_active_session(
            session_id="s1", program="p", target="t", skill="x",
            status="active", started_at="2026-05-01T10:00:00",
        )
        await sm.upsert_active_session(
            session_id="s2", program="p", target="t", skill="x",
            status="active", started_at="2026-05-02T10:00:00",
        )
        rows = await sm.get_all_sessions()
    assert rows[0]["session_id"] == "s2"
