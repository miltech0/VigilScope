from __future__ import annotations

import csv
import os
from pathlib import Path

import pytest

from system_info.event_normalizer import _sanitize
from system_info.export_security import sanitize_csv_value
from system_info.exporting import export_history_csv
from system_info.filesystem_security import ensure_private_directory, ensure_private_file
from system_info.rule_loader import (
    MAX_RULE_FILE_BYTES,
    RuleValidationError,
    load_rule_file,
    parse_rule_text,
)


def _minimal_rule() -> str:
    return """
    {
      "id": "USR-001",
      "title": "Example",
      "description": "Example rule",
      "severity": "low",
      "category": "Test",
      "event_types": ["process_started"],
      "conditions": {
        "field": "process_name",
        "operator": "equals",
        "value": "example.exe"
      }
    }
    """


@pytest.mark.parametrize("value", ["=2+2", "+cmd", "-1+1", "@SUM(A1)", "  =1+1"])
def test_csv_formula_values_are_forced_to_text(value: str) -> None:
    assert sanitize_csv_value(value).startswith("'")


def test_normal_csv_and_numeric_values_are_preserved() -> None:
    assert sanitize_csv_value("chrome.exe") == "chrome.exe"
    assert sanitize_csv_value(42) == 42


def test_history_csv_neutralizes_untrusted_process_names(tmp_path: Path) -> None:
    path = tmp_path / "history.csv"
    export_history_csv(
        path,
        measurements=[],
        events=[
            {
                "timestamp": "2026-01-01T00:00:00Z",
                "process_name": "=HYPERLINK(\"https://example.invalid\")",
            }
        ],
    )
    with path.open(encoding="utf-8-sig", newline="") as handle:
        row = next(csv.DictReader(handle))
    assert any(str(value).startswith("'") for value in row.values())


def test_duplicate_rule_keys_are_rejected() -> None:
    text = _minimal_rule().replace(
        '"title": "Example",',
        '"title": "Example", "title": "Duplicate",',
    )
    with pytest.raises(RuleValidationError, match="Duplicate JSON key"):
        parse_rule_text(text)


def test_oversized_rule_file_is_rejected_before_parsing(tmp_path: Path) -> None:
    path = tmp_path / "too-large.json"
    path.write_bytes(b" " * (MAX_RULE_FILE_BYTES + 1))
    with pytest.raises(RuleValidationError, match="too large"):
        load_rule_file(path)


def test_unknown_rule_fields_are_rejected() -> None:
    text = _minimal_rule().replace(
        '"conditions": {',
        '"unexpected_command": "never execute this", "conditions": {',
    )
    with pytest.raises(RuleValidationError, match="unknown fields"):
        parse_rule_text(text)


def test_nested_evidence_strings_mask_common_secrets() -> None:
    assert _sanitize("request token=secret-value", "message") == "request token=***"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits are not Windows ACLs")
def test_private_filesystem_permissions(tmp_path: Path) -> None:
    directory = ensure_private_directory(tmp_path / "private")
    file_path = directory / "data.txt"
    file_path.write_text("data", encoding="utf-8")
    ensure_private_file(file_path)
    assert directory.stat().st_mode & 0o777 == 0o700
    assert file_path.stat().st_mode & 0o777 == 0o600
