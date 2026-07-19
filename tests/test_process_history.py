from datetime import datetime, timedelta, timezone

from system_info.process_history import ProcessEventTracker, filter_process_events


def process(pid: int, created: float, name: str = "app.exe") -> dict[str, object]:
    return {
        "pid": pid,
        "create_time": created,
        "name": name,
        "ppid": 1,
        "parent_name": "parent.exe",
        "username": "user",
        "exe": rf"C:\{name}",
        "command_line": name,
    }


def test_initial_snapshot_is_baseline_then_start_and_stop_are_detected() -> None:
    tracker = ProcessEventTracker()
    now = datetime.now(timezone.utc)
    baseline = process(1, 100.0)
    added = process(2, 200.0)

    assert tracker.update([baseline], now) == []
    started = tracker.update([baseline, added], now + timedelta(seconds=2))
    unchanged = tracker.update([baseline, added], now + timedelta(seconds=4))
    stopped = tracker.update([baseline], now + timedelta(seconds=6))
    repeated = tracker.update([baseline], now + timedelta(seconds=8))

    assert [event["event_type"] for event in started] == ["process_started"]
    assert started[0]["pid"] == 2
    assert unchanged == []
    assert [event["event_type"] for event in stopped] == ["process_stopped"]
    assert stopped[0]["pid"] == 2
    assert repeated == []


def test_pid_reuse_with_different_creation_time_is_two_events() -> None:
    tracker = ProcessEventTracker()
    tracker.update([process(50, 1_000.0, "old.exe")])

    events = tracker.update([process(50, 2_000.0, "new.exe")])

    assert {(event["event_type"], event["process_name"]) for event in events} == {
        ("process_stopped", "old.exe"),
        ("process_started", "new.exe"),
    }


def test_process_event_filters_and_empty_data() -> None:
    events = [
        {
            "event_type": "process_started",
            "process_name": "python.exe",
            "username": "Alice",
            "exe": r"C:\Python\python.exe",
        },
        {
            "event_type": "process_stopped",
            "process_name": "chrome.exe",
            "username": "Bob",
            "exe": r"C:\Chrome\chrome.exe",
        },
    ]
    assert filter_process_events(
        events,
        process_query="PYTHON",
        event_type="process_started",
        username_query="alice",
        path_query=r"\python",
    ) == [events[0]]
    assert filter_process_events([], process_query="anything") == []
