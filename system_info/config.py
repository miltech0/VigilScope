"""Central runtime and retention settings."""

from __future__ import annotations

import os
from pathlib import Path

from .product import (
    APP_DATA_DIRECTORY_NAME,
    DATABASE_FILENAME,
    LEGACY_APP_DATA_DIRECTORY_NAME,
)

MEASUREMENT_INTERVAL_SECONDS = 5
MEASUREMENT_RETENTION_DAYS = 7
CONNECTION_EVENT_RETENTION_DAYS = 14
PROCESS_EVENT_RETENTION_DAYS = 14
MAINTENANCE_INTERVAL_SECONDS = 60 * 60
PROCESS_REFRESH_INTERVAL_SECONDS = 2
LISTENING_EVENT_RETENTION_DAYS = 30
NETWORK_EVENT_RETENTION_DAYS = 30
REMOTE_ENDPOINT_RESEEN_DAYS = 30
DNS_CACHE_RETENTION_DAYS = 7
ENDPOINT_OBSERVATION_RETENTION_DAYS = 8
DNS_RESOLUTION_ENABLED_DEFAULT = False
DNS_LOOKUP_TIMEOUT_SECONDS = 2
NETWORK_RULE_NEW_PROCESS_SECONDS = 30
NETWORK_RULE_MANY_TARGETS_SECONDS = 60
NETWORK_RULE_MANY_TARGETS_COUNT = 20
DETECTION_POLL_INTERVAL_SECONDS = 2
DETECTION_BATCH_SIZE = 500
DETECTION_UI_LIMIT = 2000
DETECTION_PREVIEW_LIMIT = 5000
DETECTION_NOTIFICATION_MIN_SEVERITY = "high"

HISTORY_RANGES = {
    "last_15_minutes": 15 * 60,
    "last_1_hour": 60 * 60,
    "last_6_hours": 6 * 60 * 60,
    "last_24_hours": 24 * 60 * 60,
    "last_7_days": 7 * 24 * 60 * 60,
}


def get_app_data_dir() -> Path:
    """Return the platform data directory, independent from the source tree."""
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / APP_DATA_DIRECTORY_NAME


def get_legacy_app_data_dir() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    return base / LEGACY_APP_DATA_DIRECTORY_NAME


def get_database_path() -> Path:
    return get_app_data_dir() / DATABASE_FILENAME
