"""Cross-component state in a single SQLite file.

Each component already manages its own state (extractor's pattern db,
researcher's session db, etc.). The orchestrator state DB tracks
*pipeline-level* facts: when each stage was run, what its result was,
which sessions are active, and a denormalized snapshot of skill / chain
counts for the dashboard.

The manager is async (``aiosqlite``). The dashboard renders best-effort
from whatever's there, so it tolerates missing rows / first-run states.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import aiosqlite

from .config import STATE_DB


_CREATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS pipeline_runs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    stage           TEXT NOT NULL,
    status          TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    completed_at    TEXT,
    result_path     TEXT,
    detail_json     TEXT
);
CREATE INDEX IF NOT EXISTS idx_pipeline_stage  ON pipeline_runs(stage);
CREATE INDEX IF NOT EXISTS idx_pipeline_status ON pipeline_runs(status);

CREATE TABLE IF NOT EXISTS active_sessions (
    session_id  TEXT PRIMARY KEY,
    program     TEXT NOT NULL,
    target      TEXT NOT NULL,
    skill       TEXT NOT NULL,
    status      TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    ended_at    TEXT
);

CREATE TABLE IF NOT EXISTS skill_versions (
    skill_path     TEXT PRIMARY KEY,
    version        TEXT,
    last_updated   TEXT,
    pattern_count  INTEGER DEFAULT 0,
    session_count  INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS chain_stats (
    from_skill        TEXT NOT NULL,
    to_skill          TEXT NOT NULL,
    frequency         INTEGER DEFAULT 0,
    last_confirmed    TEXT,
    combined_impact   TEXT,
    PRIMARY KEY (from_skill, to_skill)
);

CREATE TABLE IF NOT EXISTS task_history (
    task_id      TEXT PRIMARY KEY,
    task_type    TEXT NOT NULL,
    component    TEXT NOT NULL,
    status       TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    completed_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_task_status ON task_history(status);
CREATE INDEX IF NOT EXISTS idx_task_type   ON task_history(task_type);
"""


class StateManager:
    """Async SQLite wrapper. Use as ``async with StateManager() as sm: ...``."""

    def __init__(self, db_path: Path = STATE_DB) -> None:
        self._db_path = Path(db_path)
        self._conn: Optional[aiosqlite.Connection] = None

    async def __aenter__(self) -> "StateManager":
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(_CREATE_SCHEMA)
        await self._conn.commit()
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    # ---------- pipeline runs ----------

    async def record_pipeline_run(
        self,
        stage: str,
        *,
        detail: Optional[dict[str, Any]] = None,
    ) -> int:
        """Insert a new pipeline_runs row in ``running`` state. Returns id."""
        assert self._conn is not None
        cursor = await self._conn.execute(
            "INSERT INTO pipeline_runs (stage, status, started_at, detail_json) "
            "VALUES (?, 'running', ?, ?)",
            (stage, datetime.now().isoformat(), json.dumps(detail or {})),
        )
        await self._conn.commit()
        return int(cursor.lastrowid)

    async def update_pipeline_run(
        self,
        run_id: int,
        status: str,
        *,
        result_path: Optional[str] = None,
        detail: Optional[dict[str, Any]] = None,
    ) -> None:
        assert self._conn is not None
        await self._conn.execute(
            "UPDATE pipeline_runs SET status=?, completed_at=?, result_path=?, "
            "detail_json=COALESCE(?, detail_json) WHERE id=?",
            (
                status,
                datetime.now().isoformat(),
                result_path,
                json.dumps(detail) if detail is not None else None,
                run_id,
            ),
        )
        await self._conn.commit()

    async def get_pipeline_history(self, limit: int = 20) -> list[dict[str, Any]]:
        assert self._conn is not None
        cursor = await self._conn.execute(
            "SELECT * FROM pipeline_runs ORDER BY id DESC LIMIT ?", (limit,)
        )
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]

    # ---------- active sessions ----------

    async def upsert_active_session(
        self,
        *,
        session_id: str,
        program: str,
        target: str,
        skill: str,
        status: str,
        started_at: Optional[str] = None,
        ended_at: Optional[str] = None,
    ) -> None:
        assert self._conn is not None
        await self._conn.execute(
            """INSERT INTO active_sessions
               (session_id, program, target, skill, status, started_at, ended_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(session_id) DO UPDATE SET
                 status=excluded.status,
                 ended_at=excluded.ended_at""",
            (
                session_id, program, target, skill, status,
                started_at or datetime.now().isoformat(),
                ended_at,
            ),
        )
        await self._conn.commit()

    async def get_active_sessions(self) -> list[dict[str, Any]]:
        assert self._conn is not None
        cursor = await self._conn.execute(
            "SELECT * FROM active_sessions WHERE status = 'active' "
            "ORDER BY started_at DESC"
        )
        return [dict(r) for r in await cursor.fetchall()]

    async def get_all_sessions(self, limit: int = 50) -> list[dict[str, Any]]:
        assert self._conn is not None
        cursor = await self._conn.execute(
            "SELECT * FROM active_sessions ORDER BY started_at DESC LIMIT ?",
            (limit,),
        )
        return [dict(r) for r in await cursor.fetchall()]

    # ---------- skill / chain snapshots ----------

    async def upsert_skill_version(
        self,
        skill_path: str,
        *,
        version: str,
        last_updated: str,
        pattern_count: int,
        session_count: int = 0,
    ) -> None:
        assert self._conn is not None
        await self._conn.execute(
            """INSERT INTO skill_versions
               (skill_path, version, last_updated, pattern_count, session_count)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(skill_path) DO UPDATE SET
                 version=excluded.version,
                 last_updated=excluded.last_updated,
                 pattern_count=excluded.pattern_count,
                 session_count=excluded.session_count""",
            (skill_path, version, last_updated, pattern_count, session_count),
        )
        await self._conn.commit()

    async def get_skill_stats(self) -> list[dict[str, Any]]:
        assert self._conn is not None
        cursor = await self._conn.execute(
            "SELECT * FROM skill_versions ORDER BY last_updated DESC"
        )
        return [dict(r) for r in await cursor.fetchall()]

    async def upsert_chain_stat(
        self,
        from_skill: str,
        to_skill: str,
        *,
        frequency: int,
        last_confirmed: str,
        combined_impact: str = "",
    ) -> None:
        assert self._conn is not None
        await self._conn.execute(
            """INSERT INTO chain_stats
               (from_skill, to_skill, frequency, last_confirmed, combined_impact)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(from_skill, to_skill) DO UPDATE SET
                 frequency=excluded.frequency,
                 last_confirmed=excluded.last_confirmed,
                 combined_impact=excluded.combined_impact""",
            (from_skill, to_skill, frequency, last_confirmed, combined_impact),
        )
        await self._conn.commit()

    async def get_chain_stats(self, top_n: int = 10) -> list[dict[str, Any]]:
        assert self._conn is not None
        cursor = await self._conn.execute(
            "SELECT * FROM chain_stats ORDER BY frequency DESC LIMIT ?", (top_n,)
        )
        return [dict(r) for r in await cursor.fetchall()]

    # ---------- task history ----------

    async def record_task(
        self,
        task_id: str,
        task_type: str,
        component: str,
        *,
        status: str = "pending",
    ) -> None:
        assert self._conn is not None
        await self._conn.execute(
            """INSERT INTO task_history
               (task_id, task_type, component, status, created_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(task_id) DO UPDATE SET
                 status=excluded.status""",
            (task_id, task_type, component, status, datetime.now().isoformat()),
        )
        await self._conn.commit()

    async def mark_task_complete(self, task_id: str) -> None:
        assert self._conn is not None
        await self._conn.execute(
            "UPDATE task_history SET status='completed', completed_at=? "
            "WHERE task_id=?",
            (datetime.now().isoformat(), task_id),
        )
        await self._conn.commit()

    async def get_task_history(self, limit: int = 50) -> list[dict[str, Any]]:
        assert self._conn is not None
        cursor = await self._conn.execute(
            "SELECT * FROM task_history ORDER BY created_at DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in await cursor.fetchall()]

    # ---------- aggregate ----------

    async def get_system_summary(self) -> dict[str, Any]:
        """One-shot aggregate for the dashboard."""
        assert self._conn is not None

        # Totals per stage
        cursor = await self._conn.execute(
            "SELECT stage, status, COUNT(*) AS n FROM pipeline_runs "
            "GROUP BY stage, status"
        )
        stage_counts: dict[str, dict[str, int]] = {}
        for row in await cursor.fetchall():
            stage_counts.setdefault(row["stage"], {})[row["status"]] = row["n"]

        cursor = await self._conn.execute("SELECT COUNT(*) AS n FROM skill_versions")
        skill_count = (await cursor.fetchone())["n"]

        cursor = await self._conn.execute(
            "SELECT COALESCE(SUM(pattern_count), 0) AS n FROM skill_versions"
        )
        pattern_count = (await cursor.fetchone())["n"]

        active = await self.get_active_sessions()
        chain_top = await self.get_chain_stats(top_n=3)

        return {
            "stage_counts": stage_counts,
            "skill_count": skill_count,
            "pattern_count": pattern_count,
            "active_sessions": active,
            "top_chains": chain_top,
        }
