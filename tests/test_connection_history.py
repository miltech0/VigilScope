from datetime import datetime, timezone

from system_info.connection_history import (
    ConnectionEventTracker,
    filter_connection_events,
)


def connection(process_name: str = "python.exe") -> dict[str, str | int]:
    return {
        "protocol": "TCP",
        "pid": 42,
        "process_name": process_name,
        "local_ip": "127.0.0.1",
        "local_port": 51_000,
        "remote_ip": "203.0.113.20",
        "remote_port": 443,
        "status": "BAĞLI",
    }


def test_open_event_is_detected() -> None:
    tracker = ConnectionEventTracker()

    events = tracker.update([connection()], datetime.now(timezone.utc))

    assert len(events) == 1
    assert events[0]["event_type"] == "connection_opened"
    assert events[0]["process_name"] == "python.exe"


def test_close_event_is_detected() -> None:
    tracker = ConnectionEventTracker()
    tracker.update([connection()])

    events = tracker.update([])

    assert len(events) == 1
    assert events[0]["event_type"] == "connection_closed"
    assert events[0]["remote_port"] == 443


def test_unchanged_connection_does_not_repeat_event() -> None:
    tracker = ConnectionEventTracker()
    first = tracker.update([connection()])
    second = tracker.update([connection()])
    third = tracker.update([connection()])

    assert len(first) == 1
    assert second == []
    assert third == []


def test_connection_events_can_be_filtered() -> None:
    events = [
        {
            "event_type": "connection_opened",
            "protocol": "TCP",
            "process_name": "python.exe",
        },
        {
            "event_type": "connection_closed",
            "protocol": "UDP",
            "process_name": "chrome.exe",
        },
    ]

    assert filter_connection_events(
        events, process_query="PYTHON", event_type="connection_opened", protocol="TCP"
    ) == [events[0]]
    assert filter_connection_events(events, protocol="UDP") == [events[1]]
