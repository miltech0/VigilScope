"""Best-effort private filesystem permissions for local telemetry data."""

from __future__ import annotations

import os
from pathlib import Path


def ensure_private_directory(path: str | Path) -> Path:
    """Create a user-private directory where POSIX permission bits apply.

    On Windows, LocalAppData inherits the user's ACL and chmod does not provide
    equivalent ACL hardening, so the normal profile ACL remains authoritative.
    """
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        try:
            directory.chmod(0o700)
        except OSError:
            pass
    return directory


def ensure_private_file(path: str | Path) -> Path:
    """Apply owner-only permissions to a file on POSIX systems when possible."""
    file_path = Path(path)
    if os.name != "nt" and file_path.exists():
        try:
            file_path.chmod(0o600)
        except OSError:
            pass
    return file_path
