from datetime import datetime, timedelta, timezone

from system_info.listener_tracker import ListenerTracker


def listener(created: float = 1.0, port: int = 8000) -> dict:
    return {
        "protocol": "TCP",
        "address_family": "IPv4",
        "local_ip": "127.0.0.1",
        "local_port": port,
        "address_scope": "Loopback",
        "status": "DİNLİYOR",
        "pid": 42,
        "process_create_time": created,
        "process_name": "app.exe",
    }


def test_first_snapshot_is_baseline_and_changes_are_not_repeated() -> None:
    tracker = ListenerTracker()
    now = datetime.now(timezone.utc)
    item = listener()
    assert tracker.update([item], now) == []
    assert tracker.update([item], now + timedelta(seconds=1)) == []
    stopped = tracker.update([], now + timedelta(seconds=2))
    assert [event["event_type"] for event in stopped] == ["listener_stopped"]
    assert tracker.update([], now + timedelta(seconds=3)) == []
    started = tracker.update([item], now + timedelta(seconds=4))
    assert [event["event_type"] for event in started] == ["listener_started"]


def test_pid_reuse_with_new_creation_time_is_start_and_stop() -> None:
    tracker = ListenerTracker()
    tracker.update([listener(created=1.0)])
    events = tracker.update([listener(created=2.0)])
    assert {event["event_type"] for event in events} == {
        "listener_started",
        "listener_stopped",
    }
