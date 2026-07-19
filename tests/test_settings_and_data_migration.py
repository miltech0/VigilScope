from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from system_info.data_migration import (
    LegacyDataMigrationError,
    migrate_legacy_database,
)
from system_info.product import (
    DATA_MIGRATION_MARKER_FILENAME,
    DATABASE_FILENAME,
    LEGACY_DATABASE_FILENAME,
)
from system_info.settings import SettingsStore, detect_system_language


def _legacy_database(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE preserved (id INTEGER, note TEXT)")
        connection.execute("INSERT INTO preserved VALUES (1, 'kullanıcı notu')")
        connection.execute("PRAGMA user_version = 4")


def test_language_preference_is_saved_and_loaded(tmp_path: Path) -> None:
    store = SettingsStore(tmp_path, lambda: "tr-TR")
    assert store.load()["language"] == "tr"
    store.save_language("en")
    assert store.load()["language"] == "en"
    assert json.loads(store.path.read_text(encoding="utf-8")) == {"language": "en"}


def test_corrupt_settings_and_unknown_language_use_safe_default(tmp_path: Path) -> None:
    store = SettingsStore(tmp_path, lambda: "en-US")
    tmp_path.mkdir(exist_ok=True)
    store.path.write_text("{", encoding="utf-8")
    assert store.load()["language"] == "en"
    store.path.write_text('{"language":"xx"}', encoding="utf-8")
    assert store.load()["language"] == "en"
    assert detect_system_language(lambda: "tr-TR") == "tr"


def test_legacy_database_is_backed_up_without_deleting_source(tmp_path: Path) -> None:
    old_dir = tmp_path / "old"
    new_dir = tmp_path / "new"
    old_dir.mkdir()
    source = old_dir / LEGACY_DATABASE_FILENAME
    _legacy_database(source)

    result = migrate_legacy_database(old_dir, new_dir)

    destination = new_dir / DATABASE_FILENAME
    assert result["status"] == "completed"
    assert source.exists()
    assert destination.exists()
    assert (new_dir / DATA_MIGRATION_MARKER_FILENAME).exists()
    with sqlite3.connect(destination) as connection:
        assert connection.execute("SELECT note FROM preserved").fetchone()[0] == "kullanıcı notu"
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 4


def test_existing_destination_is_never_overwritten(tmp_path: Path) -> None:
    old_dir = tmp_path / "old"
    new_dir = tmp_path / "new"
    old_dir.mkdir()
    new_dir.mkdir()
    _legacy_database(old_dir / LEGACY_DATABASE_FILENAME)
    destination = new_dir / DATABASE_FILENAME
    destination.write_bytes(b"existing")
    result = migrate_legacy_database(old_dir, new_dir)
    assert result["status"] == "skipped_destination_exists"
    assert destination.read_bytes() == b"existing"


def test_failed_backup_rolls_back_destination(tmp_path: Path) -> None:
    old_dir = tmp_path / "old"
    new_dir = tmp_path / "new"
    old_dir.mkdir()
    _legacy_database(old_dir / LEGACY_DATABASE_FILENAME)

    def fail(_source: sqlite3.Connection, _destination: sqlite3.Connection) -> None:
        raise sqlite3.OperationalError("simulated backup failure")

    with pytest.raises(LegacyDataMigrationError):
        migrate_legacy_database(old_dir, new_dir, backup=fail)
    assert not (new_dir / DATABASE_FILENAME).exists()
    assert (old_dir / LEGACY_DATABASE_FILENAME).exists()

