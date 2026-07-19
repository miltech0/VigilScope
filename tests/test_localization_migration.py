from __future__ import annotations

import json
import sqlite3

from system_info.database import HistoryDatabase


def test_v4_turkish_and_english_enums_migrate_to_canonical_codes(tmp_path) -> None:
    path = tmp_path / "legacy-v4.db"
    database = HistoryDatabase(path)
    with sqlite3.connect(path) as connection:
        connection.row_factory = sqlite3.Row
        database._migrate_to_v1(connection)
        database._migrate_to_v2(connection)
        database._migrate_to_v3(connection)
        database._migrate_to_v4(connection)
        connection.execute(
            """
            INSERT INTO alerts (
                created_at, updated_at, first_seen, last_seen, rule_id,
                rule_version, title, description, severity, category, status,
                hostname, username, process_name, pid, parent_process_name,
                executable_path, masked_command_line, local_address,
                remote_address, remote_ip, mitre_tactics, mitre_techniques,
                deduplication_key, evidence_summary, evidence_json
            ) VALUES (
                'x','x','x','x','TEST-001','1','title','description',
                'Yüksek','category','İnceleniyor','host','user','app','1',
                'parent','path','cmd','—','—','—','[]','[]','dedup','summary','{}'
            )
            """
        )
        connection.execute(
            "INSERT INTO network_findings (dedup_key,timestamp,rule_id,severity,title,"
            "description,process_name,pid,local_address,remote_address,first_seen,"
            "last_seen,status,evidence_json) VALUES "
            "('f','x','NET-001','Low','title','description','app','1','—','—',"
            "'x','x','Yoksayıldı','{}')"
        )
        connection.execute(
            "INSERT INTO alert_notes(alert_id,created_at,author,note_text) "
            "VALUES (1,'x','user','Bu not çevrilmemeli')"
        )
        connection.execute("PRAGMA user_version = 4")

    database.initialize()

    with sqlite3.connect(path) as connection:
        alert = connection.execute(
            "SELECT severity,status FROM alerts"
        ).fetchone()
        finding = connection.execute(
            "SELECT severity,status FROM network_findings"
        ).fetchone()
        note = connection.execute("SELECT note_text FROM alert_notes").fetchone()[0]
    assert alert == ("high", "investigating")
    assert finding == ("low", "ignored")
    assert note == "Bu not çevrilmemeli"
    database.initialize()
    assert database.schema_version() == 5


def test_rule_json_structural_enum_migrates_without_changing_user_text(tmp_path) -> None:
    path = tmp_path / "rules-v4.db"
    database = HistoryDatabase(path)
    database.initialize()
    content = {
        "id": "USER-001",
        "title": "Orta isimli kullanıcı kuralı",
        "description": "Yüksek sözcüğü korunmalı",
        "severity": "Bilgi",
        "event_types": ["process_started"],
        "category": "Kullanıcı",
    }
    with database._connection() as connection, connection:
        connection.execute(
            "INSERT INTO detection_rules(rule_id,title,description,severity,category,"
            "version,content_json,created_at,updated_at) VALUES "
            "('USER-001',?,?,?,?,?,?, 'x','x')",
            (
                content["title"],
                content["description"],
                "Bilgi",
                content["category"],
                "1",
                json.dumps(content, ensure_ascii=False),
            ),
        )
        connection.execute("PRAGMA user_version = 4")
    database.initialize()
    with database._connection() as connection:
        row = connection.execute(
            "SELECT severity,content_json FROM detection_rules WHERE rule_id='USER-001'"
        ).fetchone()
    migrated = json.loads(row["content_json"])
    assert row["severity"] == "info"
    assert migrated["severity"] == "info"
    assert migrated["title"] == content["title"]
    assert migrated["description"] == content["description"]

