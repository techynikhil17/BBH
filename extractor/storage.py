"""Async SQLite + JSONL storage for extracted patterns.

Two destinations on every accepted pattern:
1. SQLite — for queries (similarity search, stats, novelty comparison)
2. JSONL — for downstream pipelines (PROMPT 03+)

Skipped reports and novel-flagged patterns each go to their own JSONL.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import aiofiles
import aiosqlite

from .models import ExtractedPattern, SkippedReport

_CREATE_SCHEMA = """
CREATE TABLE IF NOT EXISTS patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_url TEXT NOT NULL UNIQUE,
    source_platform TEXT NOT NULL,
    vuln_class TEXT NOT NULL,
    vuln_subtype TEXT,
    cwe_id TEXT,
    affected_feature_type TEXT NOT NULL,
    affected_stack_hints TEXT,
    behavioral_signal TEXT,
    detection_approach TEXT,
    oob_required INTEGER,
    preconditions TEXT,
    root_cause_pattern TEXT,
    chain_potential TEXT,
    chain_targets TEXT,
    chain_reasoning TEXT,
    severity TEXT,
    payout_usd REAL,
    is_novel INTEGER,
    novel_description TEXT,
    extraction_confidence REAL,
    raw_json TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_patterns_vuln_class ON patterns(vuln_class);
CREATE INDEX IF NOT EXISTS idx_patterns_feature ON patterns(affected_feature_type);
CREATE INDEX IF NOT EXISTS idx_patterns_novel ON patterns(is_novel);
CREATE INDEX IF NOT EXISTS idx_patterns_severity ON patterns(severity);

CREATE TABLE IF NOT EXISTS skipped_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_url TEXT NOT NULL,
    source_platform TEXT,
    skip_reason TEXT,
    raw_title TEXT,
    created_at TEXT DEFAULT (datetime('now'))
);
"""


class PatternStorage:
    """Async context manager wrapping SQLite + JSONL writers."""

    def __init__(
        self,
        db_path: str | Path,
        jsonl_path: str | Path,
        novel_jsonl_path: str | Path,
        skipped_jsonl_path: str | Path,
    ) -> None:
        self._db_path = Path(db_path)
        self._jsonl_path = Path(jsonl_path)
        self._novel_jsonl_path = Path(novel_jsonl_path)
        self._skipped_jsonl_path = Path(skipped_jsonl_path)
        self._conn: Optional[aiosqlite.Connection] = None

    async def __aenter__(self) -> "PatternStorage":
        for p in (self._db_path, self._jsonl_path, self._novel_jsonl_path, self._skipped_jsonl_path):
            p.parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(_CREATE_SCHEMA)
        await self._conn.commit()
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def save_pattern(self, pattern: ExtractedPattern) -> Optional[int]:
        """Insert a validated pattern into SQLite + the appropriate JSONL.

        Returns the row id, or None if the URL was already present (idempotent).
        """
        assert self._conn is not None
        raw_json = pattern.model_dump_json()
        try:
            cursor = await self._conn.execute(
                """INSERT INTO patterns
                   (source_url, source_platform, vuln_class, vuln_subtype, cwe_id,
                    affected_feature_type, affected_stack_hints, behavioral_signal,
                    detection_approach, oob_required, preconditions, root_cause_pattern,
                    chain_potential, chain_targets, chain_reasoning, severity, payout_usd,
                    is_novel, novel_description, extraction_confidence, raw_json)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    pattern.source_url,
                    pattern.source_platform,
                    pattern.vuln_class,
                    pattern.vuln_subtype,
                    pattern.cwe_id,
                    pattern.affected_feature_type,
                    json.dumps(pattern.affected_stack_hints),
                    pattern.behavioral_signal,
                    pattern.detection_approach,
                    int(pattern.oob_required),
                    json.dumps(pattern.preconditions),
                    pattern.root_cause_pattern,
                    pattern.chain_potential.value,
                    json.dumps(pattern.chain_targets),
                    pattern.chain_reasoning,
                    pattern.severity.value,
                    pattern.payout_usd,
                    int(pattern.is_novel),
                    pattern.novel_description,
                    pattern.extraction_confidence,
                    raw_json,
                ),
            )
        except aiosqlite.IntegrityError:
            # URL already stored — idempotent skip
            return None

        await self._conn.commit()
        row_id = cursor.lastrowid

        async with aiofiles.open(self._jsonl_path, "a") as fh:
            await fh.write(raw_json + "\n")

        if pattern.is_novel:
            async with aiofiles.open(self._novel_jsonl_path, "a") as fh:
                await fh.write(raw_json + "\n")

        return row_id

    async def save_skipped(self, skipped: SkippedReport) -> None:
        """Record a report we couldn't extract a pattern from."""
        assert self._conn is not None
        await self._conn.execute(
            """INSERT INTO skipped_reports
               (source_url, source_platform, skip_reason, raw_title)
               VALUES (?,?,?,?)""",
            (skipped.source_url, skipped.source_platform, skipped.skip_reason, skipped.raw_title),
        )
        await self._conn.commit()

        async with aiofiles.open(self._skipped_jsonl_path, "a") as fh:
            await fh.write(skipped.model_dump_json() + "\n")

    async def find_similar_patterns(
        self,
        vuln_class: str,
        feature_type: str,
        limit: int = 20,
    ) -> list[dict[str, Any]]:
        """Fetch existing patterns sharing class and/or feature type.

        Used by the novelty detector to compare a candidate against neighbors.
        """
        assert self._conn is not None
        cursor = await self._conn.execute(
            """SELECT id, source_url, vuln_class, vuln_subtype, affected_feature_type,
                      detection_approach, root_cause_pattern, raw_json
               FROM patterns
               WHERE vuln_class = ? OR affected_feature_type = ?
               ORDER BY id DESC
               LIMIT ?""",
            (vuln_class, feature_type, limit),
        )
        rows = await cursor.fetchall()
        return [dict(row) for row in rows]

    async def update_novelty_flag(self, pattern_id: int, is_novel: bool, description: Optional[str] = None) -> None:
        """Used by the novelty detector to demote false-positive novel flags."""
        assert self._conn is not None
        await self._conn.execute(
            "UPDATE patterns SET is_novel = ?, novel_description = ? WHERE id = ?",
            (int(is_novel), description, pattern_id),
        )
        await self._conn.commit()

    async def stats(self) -> dict[str, Any]:
        """Aggregate counts for the `stats` CLI command."""
        assert self._conn is not None
        cursor = await self._conn.execute("SELECT COUNT(*) AS n FROM patterns")
        total = (await cursor.fetchone())["n"]

        cursor = await self._conn.execute(
            "SELECT vuln_class, COUNT(*) AS n FROM patterns GROUP BY vuln_class ORDER BY n DESC"
        )
        by_class = [dict(row) for row in await cursor.fetchall()]

        cursor = await self._conn.execute(
            "SELECT severity, COUNT(*) AS n FROM patterns GROUP BY severity ORDER BY n DESC"
        )
        by_severity = [dict(row) for row in await cursor.fetchall()]

        cursor = await self._conn.execute(
            "SELECT COUNT(*) AS n FROM patterns WHERE is_novel = 1"
        )
        novel = (await cursor.fetchone())["n"]

        cursor = await self._conn.execute("SELECT COUNT(*) AS n FROM skipped_reports")
        skipped = (await cursor.fetchone())["n"]

        return {
            "total_patterns": total,
            "novel_patterns": novel,
            "skipped_reports": skipped,
            "by_class": by_class,
            "by_severity": by_severity,
        }

    async def already_processed(self, source_url: str) -> bool:
        """Check whether we've already extracted (or skipped) this URL — supports resume."""
        assert self._conn is not None
        cursor = await self._conn.execute(
            "SELECT 1 FROM patterns WHERE source_url = ? UNION ALL SELECT 1 FROM skipped_reports WHERE source_url = ? LIMIT 1",
            (source_url, source_url),
        )
        return (await cursor.fetchone()) is not None
