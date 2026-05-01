"""Pre-write skill backups.

Every write to a skill.md file is preceded by ``BackupManager.create``, which
copies the file to ``skill.md.{timestamp}.bak`` next to it. On any write
failure the caller passes the backup path to ``restore`` to roll back.

Backups beyond ``MAX_BACKUPS_PER_SKILL`` are pruned newest-first so we never
let backup churn fill the working tree.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ..config import MAX_BACKUPS_PER_SKILL


_BACKUP_PATTERN = re.compile(r"\.(?P<ts>\d{8}_\d{6})\.bak$")
_BACKUP_FORMAT = "%Y%m%d_%H%M%S"


@dataclass
class BackupRecord:
    backup_path: Path
    original_path: Path
    timestamp: datetime


class BackupManager:
    """Filesystem-backed backups for a directory of skill files."""

    MAX_BACKUPS = MAX_BACKUPS_PER_SKILL

    def __init__(self, max_backups: int = MAX_BACKUPS_PER_SKILL) -> None:
        self.max_backups = max_backups

    # ---------- public API ----------

    def create(self, skill_path: Path) -> Path:
        """Snapshot ``skill_path`` to ``{name}.{timestamp}.bak``.

        Returns the backup path. Raises ``FileNotFoundError`` if the source
        doesn't exist.
        """
        skill_path = Path(skill_path)
        if not skill_path.exists():
            raise FileNotFoundError(f"cannot back up missing file: {skill_path}")

        ts = datetime.now().strftime(_BACKUP_FORMAT)
        backup_path = self._backup_path(skill_path, ts)
        shutil.copy2(skill_path, backup_path)
        self.prune(skill_path)
        return backup_path

    def restore(self, skill_path: Path, backup_path: Path) -> None:
        """Copy ``backup_path`` over ``skill_path``."""
        backup_path = Path(backup_path)
        if not backup_path.exists():
            raise FileNotFoundError(f"backup missing: {backup_path}")
        shutil.copy2(backup_path, skill_path)

    def list_backups(self, skill_path: Path) -> list[BackupRecord]:
        """Return all backups for ``skill_path``, newest first."""
        skill_path = Path(skill_path)
        candidates = []
        for p in skill_path.parent.glob(f"{skill_path.name}.*.bak"):
            ts = self._parse_timestamp(p)
            if ts is None:
                continue
            candidates.append(BackupRecord(backup_path=p, original_path=skill_path, timestamp=ts))
        candidates.sort(key=lambda r: r.timestamp, reverse=True)
        return candidates

    def find_backup(self, skill_path: Path, timestamp: str) -> Path:
        """Return the backup for ``skill_path`` matching the given timestamp string.

        Accepts the raw ``YYYYMMDD_HHMMSS`` form. Raises ``FileNotFoundError`` if
        no backup matches.
        """
        candidate = self._backup_path(Path(skill_path), timestamp)
        if not candidate.exists():
            raise FileNotFoundError(f"no backup at {candidate}")
        return candidate

    def prune(self, skill_path: Path) -> int:
        """Delete oldest backups until at most ``max_backups`` remain.

        Returns the number of backups removed.
        """
        backups = self.list_backups(skill_path)
        if len(backups) <= self.max_backups:
            return 0
        excess = backups[self.max_backups :]
        for record in excess:
            try:
                record.backup_path.unlink()
            except FileNotFoundError:
                pass
        return len(excess)

    # ---------- helpers ----------

    @staticmethod
    def _backup_path(skill_path: Path, timestamp: str) -> Path:
        return skill_path.with_name(f"{skill_path.name}.{timestamp}.bak")

    @staticmethod
    def _parse_timestamp(path: Path) -> datetime | None:
        match = _BACKUP_PATTERN.search(path.name)
        if not match:
            return None
        try:
            return datetime.strptime(match.group("ts"), _BACKUP_FORMAT)
        except ValueError:
            return None
