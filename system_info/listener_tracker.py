"""Track listener starts and stops with PID-reuse-safe identities."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .database import to_db_timestamp
from .network_models import ListeningPort

ListenerKey = tuple[str, str, str, str, str, str]


def listener_key(listener: ListeningPort) -> ListenerKey:
    created = listener.get("process_create_time")
    return (
        str(listener["protocol"]),
        str(listener["address_family"]),
        str(listener["local_ip"]),
        str(listener["local_port"]),
        str(listener.get("pid", "—")),
        str(created if created is not None else "unknown"),
    )


class ListenerTracker:
    def __init__(self) -> None:
        self._previous: dict[ListenerKey, dict[str, Any]] | None = None

    def update(
        self,
        listeners: tuple[ListeningPort, ...] | list[ListeningPort],
        timestamp: datetime | None = None,
    ) -> list[dict[str, Any]]:
        seen_at = to_db_timestamp(timestamp)
        current: dict[ListenerKey, dict[str, Any]] = {}
        for listener in listeners:
            key = listener_key(listener)
            previous = self._previous.get(key) if self._previous else None
            record = dict(listener)
            record["first_seen"] = previous.get("first_seen", seen_at) if previous else seen_at
            record["last_seen"] = seen_at
            record["seen_count"] = int(previous.get("seen_count", 0)) + 1 if previous else 1
            current[key] = record
        if self._previous is None:
            self._previous = current
            return []
        started = current.keys() - self._previous.keys()
        stopped = self._previous.keys() - current.keys()
        events = [
            self._event("listener_started", seen_at, current[key])
            for key in sorted(started)
        ]
        events.extend(
            self._event("listener_stopped", seen_at, self._previous[key])
            for key in sorted(stopped)
        )
        self._previous = current
        return events

    @staticmethod
    def _event(event_type: str, timestamp: str, item: dict[str, Any]) -> dict[str, Any]:
        return {"timestamp": timestamp, "event_type": event_type, **item}
