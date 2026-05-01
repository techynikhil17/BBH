"""Async SQLite session state.

Single DB at ``data/sessions/sessions.db`` with one row per session and
companion tables for observations, chains, failed approaches, novel
signals, findings, and skill files updated. Sessions can be resumed.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import aiosqlite

from .models import (
    ChainHypothesis,
    ChainStatus,
    FailedApproach,
    Observation,
    ObservationType,
    SessionResult,
)


_CREATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    program TEXT NOT NULL,
    target TEXT NOT NULL,
    skill_used TEXT NOT NULL,
    scope_file TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    skill_files_updated TEXT,
    novel_signals TEXT,
    findings TEXT
);
CREATE TABLE IF NOT EXISTS observations (
    observation_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    observation_type TEXT NOT NULL,
    description TEXT NOT NULL,
    related_skill TEXT,
    probe_description TEXT,
    chain_potential TEXT,
    timestamp TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS chains (
    chain_id TEXT PRIMARY KEY,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    chain_name TEXT NOT NULL,
    from_skill TEXT NOT NULL,
    to_skill TEXT NOT NULL,
    trigger_text TEXT,
    pivot TEXT,
    combined_impact TEXT,
    status TEXT NOT NULL,
    evidence_observation_ids TEXT,
    discovered_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS failed_approaches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(session_id) ON DELETE CASCADE,
    approach TEXT NOT NULL,
    reason TEXT NOT NULL,
    skill TEXT NOT NULL,
    date TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_obs_session ON observations(session_id);
CREATE INDEX IF NOT EXISTS idx_chains_session ON chains(session_id);
CREATE INDEX IF NOT EXISTS idx_failed_session ON failed_approaches(session_id);
"""


class SessionExistsError(Exception):
    pass


class SessionNotFoundError(Exception):
    pass


class SessionManager:
    """Async context manager wrapping SQLite session storage."""

    def __init__(self, db_path: Path | str) -> None:
        self._db_path = Path(db_path)
        self._conn: Optional[aiosqlite.Connection] = None

    async def __aenter__(self) -> "SessionManager":
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

    # ---------- session lifecycle ----------

    async def create_session(self, session: SessionResult) -> None:
        assert self._conn is not None
        try:
            await self._conn.execute(
                """INSERT INTO sessions
                   (session_id, program, target, skill_used, scope_file,
                    started_at, ended_at, status,
                    skill_files_updated, novel_signals, findings)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    session.session_id,
                    session.program,
                    session.target,
                    session.skill_used,
                    session.scope_file,
                    session.started_at.isoformat(),
                    session.ended_at.isoformat() if session.ended_at else None,
                    session.status,
                    json.dumps(session.skill_files_updated),
                    json.dumps(session.novel_signals),
                    json.dumps(session.findings),
                ),
            )
        except aiosqlite.IntegrityError as exc:
            raise SessionExistsError(f"session {session.session_id} already exists") from exc
        await self._conn.commit()

    async def end_session(
        self,
        session_id: str,
        status: str = "completed",
        ended_at: Optional[datetime] = None,
        skill_files_updated: Optional[list[str]] = None,
    ) -> None:
        assert self._conn is not None
        ts = (ended_at or datetime.now()).isoformat()
        params: tuple = (status, ts)
        sql = "UPDATE sessions SET status = ?, ended_at = ?"
        if skill_files_updated is not None:
            sql += ", skill_files_updated = ?"
            params = (status, ts, json.dumps(skill_files_updated))
        sql += " WHERE session_id = ?"
        params = params + (session_id,)
        cursor = await self._conn.execute(sql, params)
        if cursor.rowcount == 0:
            raise SessionNotFoundError(session_id)
        await self._conn.commit()

    async def get_session(self, session_id: str) -> SessionResult:
        assert self._conn is not None
        cursor = await self._conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        )
        row = await cursor.fetchone()
        if row is None:
            raise SessionNotFoundError(session_id)

        observations = await self._load_observations(session_id)
        chains = await self._load_chains(session_id)
        failed = await self._load_failed(session_id)

        return SessionResult(
            session_id=row["session_id"],
            program=row["program"],
            target=row["target"],
            skill_used=row["skill_used"],
            scope_file=row["scope_file"],
            started_at=datetime.fromisoformat(row["started_at"]),
            ended_at=datetime.fromisoformat(row["ended_at"]) if row["ended_at"] else None,
            status=row["status"],
            observations=observations,
            chains=chains,
            failed_approaches=failed,
            skill_files_updated=_json_loads_or_empty_list(row["skill_files_updated"]),
            novel_signals=_json_loads_or_empty_list(row["novel_signals"]),
            findings=_json_loads_or_empty_list(row["findings"]),
        )

    async def list_sessions(self) -> list[dict[str, Any]]:
        assert self._conn is not None
        cursor = await self._conn.execute(
            "SELECT session_id, program, target, skill_used, status, started_at, ended_at "
            "FROM sessions ORDER BY started_at DESC"
        )
        return [dict(row) for row in await cursor.fetchall()]

    async def append_skill_file_updated(self, session_id: str, skill_path: str) -> None:
        """Idempotently record that ``skill_path`` was patched in this session."""
        assert self._conn is not None
        session = await self.get_session(session_id)
        existing = list(session.skill_files_updated)
        if skill_path not in existing:
            existing.append(skill_path)
        await self._conn.execute(
            "UPDATE sessions SET skill_files_updated = ? WHERE session_id = ?",
            (json.dumps(existing), session_id),
        )
        await self._conn.commit()

    # ---------- mutators ----------

    async def add_observation(self, observation: Observation) -> None:
        assert self._conn is not None
        await self._conn.execute(
            """INSERT INTO observations
               (observation_id, session_id, observation_type, description,
                related_skill, probe_description, chain_potential, timestamp)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                observation.observation_id,
                observation.session_id,
                observation.observation_type.value,
                observation.description,
                observation.related_skill,
                observation.probe_description,
                observation.chain_potential,
                observation.timestamp.isoformat(),
            ),
        )
        await self._conn.commit()

    async def add_chain(self, chain: ChainHypothesis) -> None:
        assert self._conn is not None
        await self._conn.execute(
            """INSERT INTO chains
               (chain_id, session_id, chain_name, from_skill, to_skill,
                trigger_text, pivot, combined_impact, status,
                evidence_observation_ids, discovered_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (
                chain.chain_id,
                chain.session_id,
                chain.chain_name,
                chain.from_skill,
                chain.to_skill,
                chain.trigger,
                chain.pivot,
                chain.combined_impact,
                chain.status.value,
                json.dumps(chain.evidence_observation_ids),
                chain.discovered_at.isoformat(),
            ),
        )
        await self._conn.commit()

    async def add_failed_approach(self, failed: FailedApproach) -> None:
        assert self._conn is not None
        await self._conn.execute(
            """INSERT INTO failed_approaches
               (session_id, approach, reason, skill, date)
               VALUES (?,?,?,?,?)""",
            (failed.session_id, failed.approach, failed.reason, failed.skill, failed.date),
        )
        await self._conn.commit()

    # ---------- loaders ----------

    async def _load_observations(self, session_id: str) -> list[Observation]:
        assert self._conn is not None
        cursor = await self._conn.execute(
            "SELECT * FROM observations WHERE session_id = ? ORDER BY timestamp ASC",
            (session_id,),
        )
        rows = await cursor.fetchall()
        return [
            Observation(
                observation_id=r["observation_id"],
                session_id=r["session_id"],
                observation_type=ObservationType(r["observation_type"]),
                description=r["description"],
                related_skill=r["related_skill"] or "",
                probe_description=r["probe_description"] or "",
                chain_potential=r["chain_potential"],
                timestamp=datetime.fromisoformat(r["timestamp"]),
            )
            for r in rows
        ]

    async def _load_chains(self, session_id: str) -> list[ChainHypothesis]:
        assert self._conn is not None
        cursor = await self._conn.execute(
            "SELECT * FROM chains WHERE session_id = ? ORDER BY discovered_at ASC",
            (session_id,),
        )
        rows = await cursor.fetchall()
        return [
            ChainHypothesis(
                chain_id=r["chain_id"],
                session_id=r["session_id"],
                chain_name=r["chain_name"],
                from_skill=r["from_skill"],
                to_skill=r["to_skill"],
                trigger=r["trigger_text"] or "",
                pivot=r["pivot"] or "",
                combined_impact=r["combined_impact"] or "",
                status=ChainStatus(r["status"]),
                evidence_observation_ids=_json_loads_or_empty_list(r["evidence_observation_ids"]),
                discovered_at=datetime.fromisoformat(r["discovered_at"]),
            )
            for r in rows
        ]

    async def _load_failed(self, session_id: str) -> list[FailedApproach]:
        assert self._conn is not None
        cursor = await self._conn.execute(
            "SELECT * FROM failed_approaches WHERE session_id = ? ORDER BY id ASC",
            (session_id,),
        )
        rows = await cursor.fetchall()
        return [
            FailedApproach(
                approach=r["approach"],
                reason=r["reason"],
                skill=r["skill"],
                date=r["date"],
                session_id=r["session_id"],
            )
            for r in rows
        ]


def _json_loads_or_empty_list(value: Optional[str]) -> list:
    if not value:
        return []
    try:
        loaded = json.loads(value)
        return loaded if isinstance(loaded, list) else []
    except json.JSONDecodeError:
        return []
