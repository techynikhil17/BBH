from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

import aiofiles
import aiosqlite

from .models import RawReport

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS raw_reports (
    content_hash        TEXT PRIMARY KEY,
    source              TEXT NOT NULL,
    title               TEXT NOT NULL,
    url                 TEXT NOT NULL,
    severity            TEXT,
    program             TEXT,
    bounty_usd          REAL,
    disclosed_at        TEXT,
    vuln_type_tags      TEXT,
    raw_content_preview TEXT,
    collected_at        TEXT NOT NULL,
    source_metadata     TEXT
);
CREATE INDEX IF NOT EXISTS idx_source    ON raw_reports(source);
CREATE INDEX IF NOT EXISTS idx_severity  ON raw_reports(severity);
CREATE INDEX IF NOT EXISTS idx_disclosed ON raw_reports(disclosed_at);
"""


class Storage:
    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._conn: Optional[aiosqlite.Connection] = None

    async def __aenter__(self) -> "Storage":
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = await aiosqlite.connect(self._db_path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(_CREATE_TABLE)
        await self._conn.commit()
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._conn:
            await self._conn.close()

    async def save_report(self, report: RawReport) -> bool:
        cursor = await self._conn.execute(
            """INSERT OR IGNORE INTO raw_reports
               (content_hash,source,title,url,severity,program,bounty_usd,
                disclosed_at,vuln_type_tags,raw_content_preview,collected_at,source_metadata)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                report.content_hash,
                report.source,
                report.title,
                report.url,
                report.severity,
                report.program,
                report.bounty_usd,
                report.disclosed_at.isoformat() if report.disclosed_at else None,
                json.dumps(report.vuln_type_tags),
                report.raw_content_preview,
                report.collected_at.isoformat(),
                json.dumps(report.source_metadata),
            ),
        )
        await self._conn.commit()
        return cursor.rowcount == 1

    async def get_stats(self) -> dict[str, int]:
        cursor = await self._conn.execute(
            "SELECT source, COUNT(*) as cnt FROM raw_reports GROUP BY source"
        )
        rows = await cursor.fetchall()
        stats: dict[str, int] = {row["source"]: row["cnt"] for row in rows}
        stats["total"] = sum(stats.values())
        return stats

    async def get_reports_by_severity(self, severity: str) -> list[RawReport]:
        cursor = await self._conn.execute(
            "SELECT * FROM raw_reports WHERE severity = ?", (severity,)
        )
        rows = await cursor.fetchall()
        return [_row_to_report(row) for row in rows]

    async def export_to_jsonl(self, output_path: str) -> int:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        count = 0
        cursor = await self._conn.execute(
            "SELECT * FROM raw_reports ORDER BY collected_at"
        )
        async with aiofiles.open(output_path, "w") as fh:
            while True:
                rows = await cursor.fetchmany(500)
                if not rows:
                    break
                for row in rows:
                    await fh.write(_row_to_report(row).model_dump_json() + "\n")
                    count += 1
        return count

    async def get_uncollected_count(self) -> int:
        cursor = await self._conn.execute("SELECT COUNT(*) as cnt FROM raw_reports")
        row = await cursor.fetchone()
        return row["cnt"]


def _row_to_report(row: aiosqlite.Row) -> RawReport:
    return RawReport(
        content_hash=row["content_hash"],
        source=row["source"],
        title=row["title"],
        url=row["url"],
        severity=row["severity"],
        program=row["program"],
        bounty_usd=row["bounty_usd"],
        disclosed_at=(
            datetime.fromisoformat(row["disclosed_at"]) if row["disclosed_at"] else None
        ),
        vuln_type_tags=json.loads(row["vuln_type_tags"]) if row["vuln_type_tags"] else [],
        raw_content_preview=row["raw_content_preview"],
        collected_at=datetime.fromisoformat(row["collected_at"]),
        source_metadata=json.loads(row["source_metadata"]) if row["source_metadata"] else {},
    )
