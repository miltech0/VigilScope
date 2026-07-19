"""Explainable, passive, read-only NET-001 through NET-007 finding rules."""

from __future__ import annotations

import json
from typing import Any

from .address_utils import ALL_INTERFACES, LOOPBACK, PRIVATE, PUBLIC

DISCLAIMER = "This finding alone is not proof of malicious activity."


def listener_findings(
    listener: dict[str, Any],
    was_known: bool,
    is_expected: bool = False,
) -> list[dict[str, Any]]:
    scope = listener["address_scope"]
    address = f"{listener['local_ip']}:{listener['local_port']}"
    identity = _listener_identity(listener)
    if scope == LOOPBACK:
        severity = "info"
    elif scope == ALL_INTERFACES:
        severity = "medium"
    elif scope == PRIVATE:
        severity = "low"
    else:
        severity = "low"
    if is_expected:
        severity = "info"

    findings = [
        _finding(
            f"NET-001|{identity}",
            "NET-001",
            severity,
            "A new listening port opened",
            f"{listener['process_name']} started listening on {address}. {DISCLAIMER}",
            listener,
            local_address=address,
        )
    ]
    if scope == ALL_INTERFACES:
        findings.append(
            _finding(
                f"NET-002|{identity}",
                "NET-002",
                "medium" if not is_expected else "info",
                "Listening on all network interfaces",
                f"The port is bound to all local network interfaces. {DISCLAIMER}",
                listener,
                local_address=address,
            )
        )
    path = str(listener.get("process_path", "")).replace("/", "\\").casefold()
    if any(
        marker in path
        for marker in (
            "\\appdata\\local\\temp\\",
            "\\windows\\temp\\",
            "\\downloads\\",
            "\\temp\\",
        )
    ):
        findings.append(
            _finding(
                f"NET-003|{identity}",
                "NET-003",
                "medium" if not is_expected else "info",
                "Listener running from a temporary or downloaded location",
                f"The listening process runs from a temporary or download folder. {DISCLAIMER}",
                listener,
                local_address=address,
            )
        )
    if not was_known:
        findings.append(
            _finding(
                f"NET-007|{listener['protocol']}|{scope}|{listener['local_port']}|{listener['process_name']}",
                "NET-007",
                "medium" if scope == ALL_INTERFACES and not is_expected else "low",
                "Previously unseen local listening port",
                f"This protocol/scope/port/process combination was absent from the baseline. {DISCLAIMER}",
                listener,
                local_address=address,
            )
        )
    return findings


def public_endpoint_findings(
    connection: dict[str, Any],
    is_new: bool,
    process_is_recent: bool,
    is_expected: bool = False,
) -> list[dict[str, Any]]:
    if connection.get("remote_scope") != PUBLIC:
        return []
    remote = f"{connection['remote_ip']}:{connection['remote_port']}"
    process_key = (
        f"{connection.get('pid')}|{connection.get('process_create_time')}"
    )
    findings: list[dict[str, Any]] = []
    if is_new:
        findings.append(
            _finding(
                f"NET-004|{connection['protocol']}|{remote}|{process_key}",
                "NET-004",
                "info" if is_expected else "low",
                "First-seen public remote endpoint",
                f"The process connected to a public endpoint absent from the baseline. {DISCLAIMER}",
                connection,
                remote_address=remote,
            )
        )
    if is_new and process_is_recent:
        findings.append(
            _finding(
                f"NET-005|{connection['protocol']}|{remote}|{process_key}",
                "NET-005",
                "info" if is_expected else "low",
                "New process connected to a public endpoint shortly after start",
                f"A public connection was observed shortly after process start. {DISCLAIMER}",
                connection,
                remote_address=remote,
            )
        )
    return findings


def many_targets_finding(
    process_key: str,
    connections: list[dict[str, Any]],
    threshold: int,
    window_seconds: int,
) -> dict[str, Any] | None:
    public_targets = {
        (item["protocol"], item["remote_ip"], item["remote_port"])
        for item in connections
        if item.get("remote_scope") == PUBLIC
    }
    if len(public_targets) < threshold:
        return None
    sample = connections[0]
    return _finding(
        f"NET-006|{process_key}",
        "NET-006",
        "medium",
        "Many public endpoints in a short period",
        (
            f"{len(public_targets)} unique public endpoints were seen in a "
            f"{window_seconds}-second observation window. Normal applications "
            f"such as browsers may trigger this finding. {DISCLAIMER}"
        ),
        sample,
        remote_address=f"{len(public_targets)} unique endpoints",
        extra={"target_count": len(public_targets), "threshold": threshold},
    )


def _finding(
    dedup_key: str,
    rule_id: str,
    severity: str,
    title: str,
    description: str,
    source: dict[str, Any],
    local_address: str = "—",
    remote_address: str = "—",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence = {**source, **(extra or {})}
    return {
        "dedup_key": dedup_key,
        "rule_id": rule_id,
        "severity": severity,
        "title": title,
        "description": description,
        "process_name": source.get("process_name", "unknown"),
        "pid": source.get("pid", "—"),
        "process_create_time": source.get("process_create_time"),
        "local_address": local_address,
        "remote_address": remote_address,
        "evidence_json": json.dumps(evidence, ensure_ascii=False, default=str),
    }


def _listener_identity(listener: dict[str, Any]) -> str:
    return "|".join(
        str(listener.get(field))
        for field in (
            "protocol",
            "address_family",
            "local_ip",
            "local_port",
            "pid",
            "process_create_time",
        )
    )
