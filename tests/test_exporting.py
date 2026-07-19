import csv
import json

from system_info.exporting import export_history_csv, export_history_json


def sample_data() -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    measurements = [
        {
            "timestamp": "2026-07-18T10:00:00Z",
            "cpu_percent": 25.0,
            "ram_percent": 50.0,
            "ram_used_bytes": 1_024,
            "disk_percent": 60.0,
            "active_connections": 8,
            "net_bytes_sent": 100,
            "net_bytes_recv": 200,
        }
    ]
    events = [
        {
            "timestamp": "2026-07-18T10:00:01Z",
            "event_type": "Açıldı",
            "protocol": "TCP",
            "pid": "42",
            "process_name": "örnek.exe",
            "local_ip": "127.0.0.1",
            "local_port": "50000",
            "remote_ip": "203.0.113.10",
            "remote_port": "443",
            "status": "BAĞLI",
        }
    ]
    return measurements, events


def test_csv_export_is_utf8_and_contains_both_record_types(tmp_path) -> None:
    measurements, events = sample_data()
    path = tmp_path / "history.csv"

    export_history_csv(path, measurements, events)

    with path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["Record Type"] for row in rows] == [
        "measurement",
        "connection_event",
    ]
    assert rows[1]["Process Name"] == "örnek.exe"


def test_json_export_is_utf8_and_structured(tmp_path) -> None:
    measurements, events = sample_data()
    path = tmp_path / "history.json"

    export_history_json(path, measurements, events)

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["system_measurements"] == measurements
    assert payload["connection_events"] == events
    assert "örnek.exe" in path.read_text(encoding="utf-8")


def test_empty_exports_are_valid(tmp_path) -> None:
    csv_path = tmp_path / "empty.csv"
    json_path = tmp_path / "empty.json"

    export_history_csv(csv_path, [], [])
    export_history_json(json_path, [], [])

    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        assert list(csv.DictReader(handle)) == []
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["metadata"]["product"] == "VigilScope"
    assert payload["system_measurements"] == []
    assert payload["connection_events"] == []
    assert payload["process_events"] == []
    assert payload["network_events"] == []
    assert payload["network_findings"] == []


def test_process_events_are_exported_and_secrets_are_masked(tmp_path) -> None:
    process_events = [
        {
            "timestamp": "2026-07-18T10:00:02Z",
            "event_type": "Başladı",
            "pid": 88,
            "create_time": 1_700_000_000.0,
            "process_name": "worker.exe",
            "parent_pid": 1,
            "parent_name": "service.exe",
            "username": "user",
            "exe": r"C:\worker.exe",
            "command_line": "worker.exe --api-key secret-value",
            "first_seen": "2026-07-18T10:00:02Z",
            "last_seen": "2026-07-18T10:00:02Z",
        }
    ]
    csv_path = tmp_path / "process.csv"
    json_path = tmp_path / "process.json"

    export_history_csv(csv_path, [], [], process_events)
    export_history_json(json_path, [], [], process_events)

    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        csv_row = next(csv.DictReader(handle))
    json_row = json.loads(json_path.read_text(encoding="utf-8"))["process_events"][0]
    assert csv_row["Record Type"] == "process_event"
    assert csv_row["Command Line"] == "worker.exe --api-key ***"
    assert json_row["command_line"] == "worker.exe --api-key ***"


def test_network_events_and_findings_are_exported(tmp_path) -> None:
    event = {
        "timestamp": "2026-07-18T10:00:00Z",
        "event_type": "Yeni Uzak Hedef",
        "protocol": "TCP",
        "process_name": "client.exe",
        "pid": "10",
        "remote_ip": "8.8.8.8",
        "remote_port": "443",
        "description": "Pasif gözlem",
    }
    finding = {
        "timestamp": "2026-07-18T10:00:00Z",
        "rule_id": "NET-004",
        "severity": "Düşük",
        "title": "Yeni hedef",
        "status": "Açık",
    }
    csv_path = tmp_path / "network.csv"
    json_path = tmp_path / "network.json"
    export_history_csv(csv_path, [], [], [], [event], [finding])
    export_history_json(json_path, [], [], [], [event], [finding])
    with csv_path.open(encoding="utf-8-sig", newline="") as handle:
        rows = list(csv.DictReader(handle))
    assert [row["Record Type"] for row in rows] == [
        "network_event",
        "network_finding",
    ]
    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["network_events"] == [event]
    assert payload["network_findings"] == [finding]
