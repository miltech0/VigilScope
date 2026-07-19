"""Process start/stop event tracking and history filters."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .database import to_db_timestamp
from .process_models import ProcessIdentity, ProcessRecord, process_identity


def filter_process_events(
    events: list[dict[str, Any]],
    process_query: str = "",
    event_type: str = "all",
    username_query: str = "",
    path_query: str = "",
) -> list[dict[str, Any]]:
    process_needle = process_query.strip().casefold()
    user_needle = username_query.strip().casefold()
    path_needle = path_query.strip().casefold()
    return [
        event
        for event in events
        if (event_type in {"all", "Tümü", "All"} or event["event_type"] == event_type)
        and (
            not process_needle
            or process_needle in str(event["process_name"]).casefold()
        )
        and (not user_needle or user_needle in str(event["username"]).casefold())
        and (not path_needle or path_needle in str(event["exe"]).casefold())
    ]


class ProcessEventTracker:
    """Use PID and create time together to track process identity."""

    def __init__(self) -> None:
        self._previous: dict[ProcessIdentity, dict[str, Any]] | None = None

    def update(
        self,
        processes: list[ProcessRecord],
        timestamp: datetime | None = None,
    ) -> list[dict[str, Any]]:
        seen_at = to_db_timestamp(timestamp)
        current: dict[ProcessIdentity, dict[str, Any]] = {}
        for process in processes:
            identity = process_identity(process)
            record = dict(process)
            prior = self._previous.get(identity) if self._previous is not None else None
            record["_first_seen"] = prior.get("_first_seen", seen_at) if prior else seen_at
            record["_last_seen"] = seen_at
            current[identity] = record

        # The first scan is the normal startup baseline and emits no events.
        if self._previous is None:
            self._previous = current
            return []

        started = current.keys() - self._previous.keys()
        stopped = self._previous.keys() - current.keys()
        events = [
            self._make_event("process_started", seen_at, current[identity])
            for identity in sorted(started, key=_identity_sort_key)
        ]
        events.extend(
            self._make_event("process_stopped", seen_at, self._previous[identity])
            for identity in sorted(stopped, key=_identity_sort_key)
        )
        self._previous = current
        return events

    @staticmethod
    def _make_event(
        event_type: str, timestamp: str, record: dict[str, Any]
    ) -> dict[str, Any]:
        return {
            "timestamp": timestamp,
            "event_type": event_type,
            "pid": int(record["pid"]),
            "create_time": record.get("create_time"),
            "process_name": record.get("name", "Bilinmiyor"),
            "parent_pid": int(record.get("ppid", 0)),
            "parent_name": record.get("parent_name", "Bilinmiyor"),
            "username": record.get("username", "Bilinmiyor"),
            "exe": record.get("exe", "Bilinmiyor"),
            "command_line": record.get("command_line", "Bilinmiyor"),
            "first_seen": record.get("_first_seen", timestamp),
            "last_seen": record.get("_last_seen", timestamp),
        }


def _identity_sort_key(identity: ProcessIdentity) -> tuple[int, float]:
    return identity[0], identity[1] if identity[1] is not None else -1.0
