import json
import time
from datetime import datetime, timedelta, timezone

import pytest

from system_info.alert_repository import AlertRepository
from system_info.database import HistoryDatabase, to_db_timestamp
from system_info.detection_exporting import (
    export_detection_csv,
    export_detection_json,
    export_single_alert_json,
    export_single_case_json,
)
from system_info.detection_service import DetectionService, DetectionWorker
from system_info.event_normalizer import normalize_source_event
from system_info.rule_loader import load_rule_file
from system_info.suppression_service import SuppressionService


@pytest.fixture
def detection(tmp_path):
    database = HistoryDatabase(tmp_path / "detection.db")
    database.initialize()
    repository = AlertRepository(database)
    service = DetectionService(repository, baseline_existing=False)
    return database, repository, service


def process_event(timestamp, record_id=1, **overrides):
    value = {
        "timestamp": to_db_timestamp(timestamp),
        "event_type": "Başladı",
        "pid": 42,
        "create_time": 100.0,
        "process_name": "powershell.exe",
        "parent_pid": 10,
        "parent_name": "winword.exe",
        "username": "user",
        "exe": r"C:\Windows\powershell.exe",
        "command_line": "powershell -enc AAA --password secret",
        "first_seen": to_db_timestamp(timestamp),
        "last_seen": to_db_timestamp(timestamp),
    }
    value.update(overrides)
    return value


def test_single_event_alarm_dedup_occurrence_and_evidence(detection) -> None:
    database, repository, service = detection
    now = datetime.now(timezone.utc)
    database.insert_process_events([process_event(now)])
    result = service.process_once()
    assert result["processed_events"] == 1
    rules = {item["rule_id"] for item in repository.list_alerts()}
    assert {"PROC-001", "PROC-004"} <= rules
    alert = next(item for item in repository.list_alerts() if item["rule_id"] == "PROC-001")
    details = repository.alert_details(alert["id"])
    assert alert["occurrence_count"] == 1
    assert len(details["evidence"]) == 1
    assert "secret" not in details["evidence"][0]["evidence_json"]

    # Rewinding a checkpoint does not increment an alert for identical evidence.
    with database._connection() as connection, connection:
        connection.execute(
            "UPDATE detection_checkpoints SET last_record_id=0 WHERE source_table='process_events'"
        )
    service.process_once()
    repeated = repository.alert_details(alert["id"])
    assert repeated["occurrence_count"] == 1
    assert len(repeated["evidence"]) == 1

    database.insert_process_events(
        [
            process_event(
                now + timedelta(seconds=1),
                pid=42,
                create_time=100.0,
            )
        ]
    )
    service.process_once()
    updated = next(item for item in repository.list_alerts() if item["rule_id"] == "PROC-001")
    assert updated["occurrence_count"] == 2
    assert updated["first_seen"] < updated["last_seen"]


def test_checkpoint_restart_baseline_and_failed_batch(detection, monkeypatch) -> None:
    database, repository, service = detection
    now = datetime.now(timezone.utc)
    database.insert_process_events([process_event(now)])
    service.process_once()
    checkpoint = repository.checkpoint("process_events")
    restarted = DetectionService(repository, baseline_existing=True)
    assert repository.checkpoint("process_events") == checkpoint
    assert restarted.process_once()["processed_events"] == 0

    database.insert_process_events([process_event(now + timedelta(seconds=1), pid=99)])
    prior = repository.checkpoint("process_events")

    def fail(*_args, **_kwargs):
        raise RuntimeError("rule failure")

    monkeypatch.setattr(service, "_evaluate_batch", fail)
    with pytest.raises(RuntimeError):
        service.process_once()
    assert repository.checkpoint("process_events") == prior


def test_first_install_baselines_existing_history(tmp_path) -> None:
    database = HistoryDatabase(tmp_path / "baseline.db")
    database.initialize()
    now = datetime.now(timezone.utc)
    database.insert_process_events([process_event(now)])
    repository = AlertRepository(database)
    service = DetectionService(repository, baseline_existing=True)
    assert service.process_once()["processed_events"] == 0
    assert repository.list_alerts() == []


def test_alert_status_history_note_case_and_timeline(detection) -> None:
    database, repository, service = detection
    now = datetime.now(timezone.utc)
    database.insert_process_events([process_event(now)])
    service.process_once()
    alert = repository.list_alerts()[0]
    repository.set_alert_status(alert["id"], "investigating", "İlk inceleme")
    repository.add_alert_note(alert["id"], "Komut satırı doğrulanacak.")
    details = repository.alert_details(alert["id"])
    assert details["status"] == "investigating"
    assert details["notes"][0]["note_text"] == "Komut satırı doğrulanacak."
    assert details["status_history"][-1]["old_status"] == "new"

    case_id = repository.create_case(
        "PowerShell incelemesi",
        "Yerel olay dosyası",
        "high",
        [alert["id"]],
    )
    repository.add_case_note(case_id, "Birleşik zaman çizelgesi incelendi.")
    case = repository.case_details(case_id)
    assert len(case["alerts"]) == 1
    assert case["timeline"]
    assert case["notes"]
    repository.remove_alert_from_case(case_id, alert["id"])
    assert repository.case_details(case_id)["alerts"] == []
    repository.add_alert_to_case(case_id, alert["id"])
    assert len(repository.case_details(case_id)["alerts"]) == 1


def test_suppression_expiry_and_broad_warning(detection) -> None:
    database, repository, service = detection
    suppression = SuppressionService(repository)
    suppression_id, broad = suppression.create(
        "PowerShell",
        {"field": "process_name", "operator": "equals", "value": "powershell.exe"},
        "Test",
    )
    assert broad is True
    now = datetime.now(timezone.utc)
    database.insert_process_events([process_event(now)])
    service.process_once()
    assert repository.list_alerts() == []
    item = repository.list_suppressions()[0]
    assert item["occurrence_count"] >= 1

    with database._connection() as connection, connection:
        connection.execute(
            "UPDATE suppressions SET expires_at=? WHERE id=?",
            (to_db_timestamp(now - timedelta(seconds=1)), suppression_id),
        )
    database.insert_process_events([process_event(now + timedelta(seconds=2), pid=77)])
    service.process_once()
    assert repository.list_alerts()


def test_rule_preview_does_not_create_alert_or_move_checkpoint(detection) -> None:
    database, repository, service = detection
    now = datetime.now(timezone.utc)
    database.insert_process_events([process_event(now)])
    service.process_once()
    rule = next(item for item in repository.list_rules() if item["id"] == "PROC-001")
    checkpoint = repository.checkpoint("process_events")
    alert_count = len(repository.list_alerts())
    result = service.preview_rule(rule, now - timedelta(minutes=1))
    assert result["total_matches"] == 1
    assert repository.checkpoint("process_events") == checkpoint
    assert len(repository.list_alerts()) == alert_count


def test_cross_source_correlation_is_processed_in_timestamp_order(detection) -> None:
    database, repository, service = detection
    now = datetime.now(timezone.utc)
    created = now.timestamp()
    database.insert_process_events(
        [process_event(now, create_time=created, command_line="powershell")]
    )
    with database._connection() as connection, connection:
        connection.execute(
            """
            INSERT INTO network_events (
                timestamp, event_type, protocol, process_name, pid,
                local_ip, local_port, remote_ip, remote_port, address_scope,
                description, details_json
            ) VALUES (?, 'Yeni Uzak Hedef', 'TCP', 'powershell.exe', '42',
                      '10.0.0.2', '50000', '8.8.8.8', '443',
                      'Genel / public', 'Yeni hedef', ?)
            """,
            (
                to_db_timestamp(now + timedelta(seconds=10)),
                json.dumps(
                    {
                        "process_create_time": created,
                        "parent_pid": 10,
                        "parent_process_name": "winword.exe",
                        "username": "user",
                        "process_path": r"C:\Windows\powershell.exe",
                    }
                ),
            ),
        )
        connection.execute(
            """
            INSERT INTO listening_port_events (
                timestamp, event_type, protocol, address_family, local_ip,
                local_port, address_scope, pid, process_create_time,
                process_name, process_path, username, parent_pid,
                parent_process_name, first_seen, last_seen, details_json
            ) VALUES (?, 'Dinleme Başladı', 'TCP', 'IPv4', '0.0.0.0',
                      8080, 'Tüm arayüzler', '42', ?, 'powershell.exe',
                      'C:\\Windows\\powershell.exe', 'user', 10,
                      'winword.exe', ?, ?, ?)
            """,
            (
                to_db_timestamp(now + timedelta(seconds=20)),
                created,
                to_db_timestamp(now + timedelta(seconds=20)),
                to_db_timestamp(now + timedelta(seconds=20)),
                json.dumps({"command_line": "powershell"}),
            ),
        )
    service.process_once()
    assert "CORR-001" in {item["rule_id"] for item in repository.list_alerts()}


def test_user_rule_crud_and_builtin_delete_protection(detection) -> None:
    _database, repository, _service = detection
    rule = {
        "id": "USER-900",
        "title": "Notepad",
        "description": "Notepad başladı",
        "enabled": True,
        "severity": "info",
        "category": "Kullanıcı",
        "event_types": ["process_started"],
        "conditions": {
            "field": "process_name",
            "operator": "equals",
            "value": "notepad.exe",
        },
    }
    repository.save_user_rule(rule)
    assert any(item["id"] == "USER-900" for item in repository.list_rules())
    repository.delete_user_rule("USER-900")
    assert not any(item["id"] == "USER-900" for item in repository.list_rules())
    with pytest.raises(Exception, match="Built-in"):
        repository.delete_user_rule("PROC-001")


def test_detection_exports_are_utf8_masked_and_empty_safe(detection, tmp_path) -> None:
    database, repository, service = detection
    empty_csv = tmp_path / "empty.csv"
    empty_json = tmp_path / "empty.json"
    export_detection_csv(empty_csv, repository)
    export_detection_json(empty_json, repository)
    assert json.loads(empty_json.read_text(encoding="utf-8"))["alerts"] == []

    now = datetime.now(timezone.utc)
    database.insert_process_events([process_event(now)])
    service.process_once()
    alert = repository.list_alerts()[0]
    case_id = repository.create_case("Test", "", "info", [alert["id"]])
    csv_path = tmp_path / "all.csv"
    json_path = tmp_path / "all.json"
    alert_path = tmp_path / "alert.json"
    case_path = tmp_path / "case.json"
    export_detection_csv(csv_path, repository)
    export_detection_json(json_path, repository)
    export_single_alert_json(alert_path, repository, alert["id"])
    export_single_case_json(case_path, repository, case_id)
    content = json_path.read_text(encoding="utf-8")
    assert "secret" not in content
    assert "--password ***" in content
    assert csv_path.read_bytes().startswith(b"\xef\xbb\xbf")
    assert json.loads(alert_path.read_text(encoding="utf-8"))["evidence"]
    assert json.loads(case_path.read_text(encoding="utf-8"))["timeline"]


def test_worker_stops_cleanly(detection) -> None:
    _database, _repository, service = detection
    worker = DetectionWorker(service, interval_seconds=0.05)
    worker.start()
    time.sleep(0.1)
    assert worker.running
    worker.stop(timeout=1)
    assert not worker.running


def test_maintenance_does_not_delete_alerts_cases_or_checkpoints(detection) -> None:
    database, repository, service = detection
    now = datetime.now(timezone.utc)
    database.insert_process_events([process_event(now)])
    service.process_once()
    alert = repository.list_alerts()[0]
    repository.create_case("Kalıcı olay", "", "info", [alert["id"]])
    checkpoint = repository.checkpoint("process_events")
    database.cleanup_old_records(now=now + timedelta(days=365))
    assert repository.list_alerts()
    assert repository.list_cases()
    assert repository.checkpoint("process_events") == checkpoint


def test_closed_alert_reopens_only_when_rule_requests_it(detection) -> None:
    _database, repository, _service = detection
    rule = next(item for item in load_rule_file() if item["id"] == "PROC-001")
    first = normalize_source_event(
        "process_events",
        {"id": 900, **process_event(datetime.now(timezone.utc))},
    )
    assert first is not None
    dedup = repository.deduplication_key(rule, first)
    alert_id, _, _ = repository.upsert_alert(rule, [first], dedup)
    repository.set_alert_status(alert_id, "closed")
    second = normalize_source_event(
        "process_events",
        {
            "id": 901,
            **process_event(
                datetime.now(timezone.utc) + timedelta(seconds=1),
            ),
        },
    )
    assert second is not None
    repository.upsert_alert(rule, [second], dedup)
    assert repository.alert_details(alert_id)["status"] == "closed"

    reopening = dict(rule)
    reopening["deduplication"] = {
        **rule["deduplication"],
        "reopen_closed": True,
    }
    third = normalize_source_event(
        "process_events",
        {
            "id": 902,
            **process_event(
                datetime.now(timezone.utc) + timedelta(seconds=2),
            ),
        },
    )
    assert third is not None
    repository.upsert_alert(reopening, [third], dedup)
    assert repository.alert_details(alert_id)["status"] == "new"


def test_expected_baseline_lowers_severity_and_preserves_note(detection) -> None:
    _database, repository, _service = detection
    rule = next(item for item in load_rule_file() if item["id"] == "NET-103")
    event = normalize_source_event(
        "listening_port_events",
        {
            "id": 950,
            "timestamp": to_db_timestamp(),
            "event_type": "Dinleme Başladı",
            "protocol": "TCP",
            "address_family": "IPv4",
            "local_ip": "0.0.0.0",
            "local_port": 8080,
            "address_scope": "Tüm arayüzler",
            "pid": "42",
            "process_create_time": 100.0,
            "process_name": "server.exe",
            "process_path": r"C:\server.exe",
            "username": "user",
            "parent_pid": 1,
            "parent_process_name": "parent.exe",
            "details_json": "{}",
            "is_expected": 1,
            "user_note": "Kullanıcı tarafından bekleniyor",
        },
    )
    assert event is not None
    alert_id, _, _ = repository.upsert_alert(
        rule,
        [event],
        repository.deduplication_key(rule, event),
    )
    alert = repository.alert_details(alert_id)
    assert alert["severity"] == "low"
    assert alert["expected_behavior"] == 1
    assert alert["expected_note"] == "Kullanıcı tarafından bekleniyor"
