from datetime import datetime, timedelta, timezone

import pytest

from system_info.correlation_engine import correlate
from system_info.event_normalizer import normalize_source_event
from system_info.rule_engine import compare, match_condition, rule_matches_event
from system_info.rule_loader import load_rule_file
from system_info.rule_validator import RuleValidationError, validate_rule


def process_row(**overrides):
    row = {
        "id": 1,
        "timestamp": "2026-07-19T10:00:00Z",
        "event_type": "Başladı",
        "pid": 42,
        "create_time": 100.0,
        "process_name": "powershell.exe",
        "parent_pid": 10,
        "parent_name": "winword.exe",
        "username": "user",
        "exe": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "command_line": "powershell -enc AAA --token secret",
        "first_seen": "2026-07-19T10:00:00Z",
        "last_seen": "2026-07-19T10:00:00Z",
    }
    row.update(overrides)
    return row


def event(event_type="process_started", seconds=0, **overrides):
    value = {
        "event_id": f"event:{event_type}:{seconds}:{overrides.get('pid', '42')}",
        "event_type": event_type,
        "timestamp": (
            datetime(2026, 7, 19, 10, tzinfo=timezone.utc)
            + timedelta(seconds=seconds)
        ).isoformat().replace("+00:00", "Z"),
        "hostname": "host",
        "username": "user",
        "process_name": "powershell.exe",
        "pid": "42",
        "process_create_time": 100.0,
        "parent_pid": "10",
        "parent_process_name": "winword.exe",
        "executable_path": r"C:\Temp\powershell.exe",
        "masked_command_line": "powershell -enc AAA --token ***",
        "protocol": "TCP",
        "local_ip": "10.0.0.2",
        "local_port": "50000",
        "remote_ip": "8.8.8.8",
        "remote_port": "443",
        "address_scope": "Genel / public",
        "source_table": "process_events",
        "source_record_id": seconds + 1,
        "additional_data": {},
    }
    value.update(overrides)
    return value


def test_process_event_normalization_masks_and_maps_fields() -> None:
    normalized = normalize_source_event(
        "process_events",
        process_row(token="another-secret"),
    )
    assert normalized is not None
    assert normalized["event_type"] == "process_started"
    assert normalized["parent_process_name"] == "winword.exe"
    assert normalized["process_create_time"] == 100.0
    assert "--token ***" in normalized["masked_command_line"]
    assert "secret" not in str(normalized["additional_data"])
    assert normalized["additional_data"]["token"] == "***"


def test_missing_and_access_denied_fields_are_safe() -> None:
    normalized = normalize_source_event(
        "process_events",
        process_row(
            username="Erişim yok",
            exe=None,
            command_line=None,
            create_time=None,
        ),
    )
    assert normalized is not None
    assert normalized["username"] == "Erişim yok"
    assert normalized["executable_path"] == "unknown"
    assert normalized["process_create_time"] is None


def test_listener_remote_endpoint_and_finding_normalization() -> None:
    listener = normalize_source_event(
        "listening_port_events",
        {
            "id": 2,
            "timestamp": "2026-07-19T10:00:00Z",
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
            "details_json": '{"command_line":"server --api-key secret"}',
            "is_expected": 1,
            "user_note": "Yerel geliştirme",
        },
    )
    endpoint = normalize_source_event(
        "network_events",
        {
            "id": 3,
            "timestamp": "2026-07-19T10:00:05Z",
            "event_type": "Yeni Uzak Hedef",
            "protocol": "TCP",
            "process_name": "server.exe",
            "pid": "42",
            "local_ip": "10.0.0.2",
            "local_port": "50000",
            "remote_ip": "8.8.8.8",
            "remote_port": "443",
            "address_scope": "Genel / public",
            "details_json": '{"process_create_time":100.0}',
        },
    )
    finding = normalize_source_event(
        "network_findings",
        {
            "id": 4,
            "timestamp": "2026-07-19T10:00:06Z",
            "rule_id": "NET-003",
            "process_name": "server.exe",
            "pid": "42",
            "evidence_json": "{}",
        },
    )
    assert listener and listener["event_type"] == "listener_started"
    assert listener["additional_data"]["is_expected"] is True
    assert "secret" not in listener["masked_command_line"]
    assert endpoint and endpoint["event_type"] == "remote_endpoint_new"
    assert endpoint["process_create_time"] == 100.0
    assert finding and finding["event_type"] == "network_finding"


def test_and_or_not_and_case_insensitive_matching() -> None:
    sample = event()
    condition = {
        "all": [
            {"field": "process_name", "operator": "equals", "value": "POWERSHELL.EXE"},
            {
                "any": [
                    {"field": "parent_process_name", "operator": "contains", "value": "word"},
                    {"field": "pid", "operator": "equals", "value": "999"},
                ]
            },
            {
                "not": {
                    "field": "username",
                    "operator": "equals",
                    "value": "system",
                }
            },
        ]
    }
    assert match_condition(condition, sample)


@pytest.mark.parametrize(
    ("operator", "expected", "result"),
    [
        ("greater_than", 40, True),
        ("greater_or_equal", 42, True),
        ("less_than", 50, True),
        ("less_or_equal", 42, True),
        ("wildcard", "4*", True),
        ("in", ["41", "42"], True),
        ("not_in", ["1", "2"], True),
    ],
)
def test_numeric_wildcard_and_membership(operator, expected, result) -> None:
    assert compare("42", operator, expected) is result


def test_valid_regex_and_invalid_or_long_regex() -> None:
    assert compare("powershell -ENC AAA", "regex", r"(^|\s)-enc(\s|$)")
    with pytest.raises(RuleValidationError):
        validate_rule(
            _rule(
                conditions={
                    "field": "process_name",
                    "operator": "regex",
                    "value": "(",
                }
            )
        )
    with pytest.raises(RuleValidationError):
        validate_rule(
            _rule(
                conditions={
                    "field": "process_name",
                    "operator": "regex",
                    "value": "(a+)+$",
                }
            )
        )
    with pytest.raises(RuleValidationError):
        validate_rule(
            _rule(
                conditions={
                    "field": "process_name",
                    "operator": "regex",
                    "value": "a" * 257,
                }
            )
        )


def test_rule_validation_rejects_severity_and_unknown_event() -> None:
    with pytest.raises(RuleValidationError, match="severity"):
        validate_rule(_rule(severity="Çok"))
    with pytest.raises(RuleValidationError, match="unknown"):
        validate_rule(_rule(event_types=["unknown_event"]))


def test_single_event_builtin_rules_and_metadata() -> None:
    rules = {rule["id"]: rule for rule in load_rule_file()}
    normalized = normalize_source_event("process_events", process_row())
    assert normalized is not None
    assert rule_matches_event(rules["PROC-001"], normalized)
    assert rule_matches_event(rules["PROC-004"], normalized)
    assert all(rule["false_positives"] for rule in rules.values())
    assert rules["PROC-004"]["mitre_attack"][0]["technique_id"] == "T1059.001"


def test_remaining_single_event_builtin_rules() -> None:
    rules = {rule["id"]: rule for rule in load_rule_file()}
    browser = normalize_source_event(
        "process_events",
        process_row(parent_name="chrome.exe", command_line="powershell"),
    )
    downloaded = normalize_source_event(
        "process_events",
        process_row(
            process_name="setup.exe",
            parent_name="explorer.exe",
            exe=r"C:\Users\user\Downloads\setup.exe",
            command_line="setup.exe",
        ),
    )
    unusual = normalize_source_event(
        "process_events",
        process_row(parent_name="strange.exe", command_line="powershell"),
    )
    assert browser and rule_matches_event(rules["PROC-002"], browser)
    assert downloaded and rule_matches_event(rules["PROC-003"], downloaded)
    assert unusual and rule_matches_event(rules["PROC-005"], unusual)

    listener = event(
        "listener_started",
        5,
        local_ip="0.0.0.0",
        local_port="55000",
        address_scope="Tüm arayüzler",
        additional_data={"is_expected": False},
    )
    assert rule_matches_event(rules["NET-103"], listener)
    assert rule_matches_event(rules["NET-104"], listener)


def test_sequence_count_and_distinct_count_correlation() -> None:
    rules = {rule["id"]: rule for rule in load_rule_file()}
    sequence_events = [
        event("process_started", 0),
        event("remote_endpoint_new", 10, source_table="network_events", source_record_id=2),
        event("listener_started", 20, source_table="listening_port_events", source_record_id=3),
    ]
    result = correlate(rules["CORR-001"], sequence_events, sequence_events[-1])
    assert result and [item["event_type"] for item in result] == [
        "process_started",
        "remote_endpoint_new",
        "listener_started",
    ]

    child_events = [
        event("process_started", index, event_id=f"child:{index}", source_record_id=index)
        for index in range(15)
    ]
    assert correlate(rules["PROC-006"], child_events, child_events[-1])

    targets = [
        event(
            "remote_endpoint_new",
            index,
            event_id=f"target:{index}",
            remote_ip=f"8.8.4.{index}",
            source_table="network_events",
            source_record_id=index,
        )
        for index in range(20)
    ]
    assert correlate(rules["NET-101"], targets, targets[-1])


def test_process_network_listener_and_parent_correlations() -> None:
    rules = {rule["id"]: rule for rule in load_rule_file()}
    started = event("process_started", 0)
    remote = event(
        "remote_endpoint_new",
        10,
        source_table="network_events",
        source_record_id=2,
    )
    listener = event(
        "listener_started",
        20,
        source_table="listening_port_events",
        source_record_id=3,
        local_ip="0.0.0.0",
        address_scope="Tüm arayüzler",
    )
    assert correlate(rules["PROC-007"], [started, remote], remote)
    assert correlate(rules["PROC-008"], [started, remote], remote)
    assert correlate(rules["PROC-009"], [started, listener], listener)
    assert correlate(rules["NET-102"], [started, listener], listener)

    first_child = event(
        "process_started",
        0,
        event_id="child:1",
        pid="41",
        process_create_time=101.0,
        parent_pid="10",
    )
    second_child = event(
        "process_started",
        5,
        event_id="child:2",
        pid="42",
        process_create_time=102.0,
        parent_pid="10",
    )
    child_remote = event(
        "remote_endpoint_new",
        15,
        event_id="remote:2",
        pid="42",
        process_create_time=102.0,
        parent_pid="10",
    )
    assert correlate(
        rules["CORR-002"],
        [first_child, second_child, child_remote],
        child_remote,
    )


def test_pid_reuse_does_not_correlate_different_create_time() -> None:
    rule = {item["id"]: item for item in load_rule_file()}["CORR-001"]
    events = [
        event("process_started", 0, process_create_time=100.0),
        event("remote_endpoint_new", 10, process_create_time=200.0),
        event("listener_started", 20, process_create_time=200.0),
    ]
    assert correlate(rule, events, events[-1]) is None


def _rule(**overrides):
    rule = {
        "id": "USER-001",
        "title": "Test",
        "description": "Test kuralı",
        "enabled": True,
        "severity": "info",
        "category": "Test",
        "event_types": ["process_started"],
        "conditions": {},
    }
    rule.update(overrides)
    return rule
