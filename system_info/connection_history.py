"""Detect opened and closed connections between successive snapshots."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any

from .database import to_db_timestamp

Connection = dict[str, str | int]
ConnectionKey = tuple[str, str, str, str, str, str]


def connection_key(connection: Mapping[str, Any]) -> ConnectionKey:
    return (
        str(connection["protocol"]),
        str(connection["pid"]),
        str(connection["local_ip"]),
        str(connection["local_port"]),
        str(connection["remote_ip"]),
        str(connection["remote_port"]),
    )


def filter_connection_events(
    events: list[dict[str, Any]],
    process_query: str = "",
    event_type: str = "all",
    protocol: str = "all",
) -> list[dict[str, Any]]:
    query = process_query.strip().casefold()
    return [
        event
        for event in events
        if (event_type in {"all", "Tümü", "All"} or event["event_type"] == event_type)
        and (protocol in {"all", "Tümü", "All"} or event["protocol"] == protocol)
        and (not query or query in str(event["process_name"]).casefold())
    ]


class ConnectionEventTracker:
    """Emit events only for connections that changed since the last snapshot."""

    def __init__(self) -> None:
        self._previous: dict[ConnectionKey, Connection] = {}

    def update(
        self,
        connections: list[Connection],
        timestamp: datetime | None = None,
    ) -> list[dict[str, str | int]]:
        current = {connection_key(item): dict(item) for item in connections}
        opened_keys = current.keys() - self._previous.keys()
        closed_keys = self._previous.keys() - current.keys()
        event_timestamp = to_db_timestamp(timestamp)

        events = [
            self._make_event(event_timestamp, "connection_opened", current[key])
            for key in sorted(opened_keys)
        ]
        events.extend(
            self._make_event(event_timestamp, "connection_closed", self._previous[key])
            for key in sorted(closed_keys)
        )
        self._previous = current
        return events

    @staticmethod
    def _make_event(
        timestamp: str, event_type: str, connection: Mapping[str, Any]
    ) -> dict[str, str | int]:
        return {
            "timestamp": timestamp,
            "event_type": event_type,
            "protocol": str(connection["protocol"]),
            "pid": connection["pid"],
            "process_name": str(connection["process_name"]),
            "local_ip": str(connection["local_ip"]),
            "local_port": connection["local_port"],
            "remote_ip": str(connection["remote_ip"]),
            "remote_port": connection["remote_port"],
            "status": str(connection["status"]),
        }
