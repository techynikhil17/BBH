import time
from datetime import datetime

import pytest

from updater.backup.manager import BackupManager


def test_create_returns_backup_path(tmp_path):
    skill = tmp_path / "skill.md"
    skill.write_text("v1")
    bm = BackupManager()
    backup = bm.create(skill)
    assert backup.exists()
    assert backup.read_text() == "v1"
    assert backup.name.startswith("skill.md.")
    assert backup.name.endswith(".bak")


def test_create_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        BackupManager().create(tmp_path / "nope.md")


def test_restore_overwrites_with_backup(tmp_path):
    skill = tmp_path / "skill.md"
    skill.write_text("v1")
    bm = BackupManager()
    backup = bm.create(skill)
    skill.write_text("v2 mutated")
    bm.restore(skill, backup)
    assert skill.read_text() == "v1"


def test_restore_missing_backup_raises(tmp_path):
    skill = tmp_path / "skill.md"
    skill.write_text("v1")
    with pytest.raises(FileNotFoundError):
        BackupManager().restore(skill, tmp_path / "no.bak")


def test_list_backups_sorted_newest_first(tmp_path):
    skill = tmp_path / "skill.md"
    skill.write_text("v1")
    bm = BackupManager()
    b1 = bm.create(skill)
    time.sleep(1.1)  # ensure distinct second-resolution timestamp
    b2 = bm.create(skill)
    backups = bm.list_backups(skill)
    assert len(backups) >= 2
    # Newest first
    assert backups[0].backup_path.name >= backups[1].backup_path.name


def test_prune_to_max(tmp_path):
    skill = tmp_path / "skill.md"
    skill.write_text("v1")
    bm = BackupManager(max_backups=3)

    # Create 5 backups with distinct timestamps
    for _ in range(5):
        bm.create(skill)
        time.sleep(1.1)

    backups = bm.list_backups(skill)
    assert len(backups) == 3, f"expected 3 backups after prune, got {len(backups)}"


def test_find_backup_by_timestamp(tmp_path):
    skill = tmp_path / "skill.md"
    skill.write_text("v1")
    bm = BackupManager()
    backup = bm.create(skill)
    # The full backup filename is "skill.md.YYYYMMDD_HHMMSS.bak" — split on dots
    # and pull the ts segment specifically.
    parts = backup.name.split(".")
    ts = parts[2]  # ["skill", "md", "20260501_120000", "bak"]
    found = bm.find_backup(skill, ts)
    assert found == backup


def test_find_backup_missing_raises(tmp_path):
    skill = tmp_path / "skill.md"
    skill.write_text("v1")
    with pytest.raises(FileNotFoundError):
        BackupManager().find_backup(skill, "20990101_000000")
