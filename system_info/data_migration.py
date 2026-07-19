"""Safe one-time migration from the legacy application data directory."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from .filesystem_security import ensure_private_directory, ensure_private_file
from .product import (
    DATA_MIGRATION_MARKER_FILENAME,
    DATABASE_FILENAME,
    LEGACY_DATABASE_FILENAME,
)


class LegacyDataMigrationError(RuntimeError):
    """Raised when legacy data could not be copied without risking data loss."""


def migrate_legacy_database(
    legacy_data_dir: str | Path,
    new_data_dir: str | Path,
    *,
    backup: Callable[[sqlite3.Connection, sqlite3.Connection], None] | None = None,
) -> dict[str, Any]:
    """Copy a legacy SQLite database with the backup API and never overwrite data."""
    source_path = Path(legacy_data_dir) / LEGACY_DATABASE_FILENAME
    destination_dir = Path(new_data_dir)
    destination_path = destination_dir / DATABASE_FILENAME
    marker_path = destination_dir / DATA_MIGRATION_MARKER_FILENAME

    if destination_path.exists():
        return {
            "status": "skipped_destination_exists",
            "source": str(source_path),
            "destination": str(destination_path),
        }
    if not source_path.exists():
        return {
            "status": "skipped_source_missing",
            "source": str(source_path),
            "destination": str(destination_path),
        }

    ensure_private_directory(destination_dir)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{DATABASE_FILENAME}.",
        suffix=".tmp",
        dir=destination_dir,
    )
    os.close(descriptor)
    temporary_path = Path(temporary_name)
    source: sqlite3.Connection | None = None
    destination: sqlite3.Connection | None = None
    try:
        source = sqlite3.connect(source_path, timeout=10.0)
        source.execute("PRAGMA busy_timeout = 10000")
        destination = sqlite3.connect(temporary_path, timeout=10.0)
        (backup or _sqlite_backup)(source, destination)
        destination.commit()
        integrity = destination.execute("PRAGMA integrity_check").fetchone()
        if not integrity or str(integrity[0]).casefold() != "ok":
            raise sqlite3.DatabaseError(f"Integrity check failed: {integrity!r}")
        destination.close()
        destination = None
        source.close()
        source = None
        if destination_path.exists():
            temporary_path.unlink(missing_ok=True)
            return {
                "status": "skipped_destination_exists",
                "source": str(source_path),
                "destination": str(destination_path),
            }
        os.replace(temporary_path, destination_path)
        ensure_private_file(destination_path)
        marker = {
            "status": "completed",
            "migrated_at": datetime.now(timezone.utc).isoformat(),
            "source": str(source_path),
            "destination": str(destination_path),
        }
        _write_marker_atomically(marker_path, marker)
        return marker
    except Exception as exc:
        raise LegacyDataMigrationError(
            f"Legacy database migration failed: {exc}"
        ) from exc
    finally:
        if destination is not None:
            destination.close()
        if source is not None:
            source.close()
        temporary_path.unlink(missing_ok=True)


def _sqlite_backup(
    source: sqlite3.Connection,
    destination: sqlite3.Connection,
) -> None:
    source.backup(destination)


def _write_marker_atomically(path: Path, payload: dict[str, Any]) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        ensure_private_file(path)
    finally:
        temporary_path.unlink(missing_ok=True)

