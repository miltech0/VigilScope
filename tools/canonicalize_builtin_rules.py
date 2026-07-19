"""Rewrite bundled rules to canonical English metadata and language-independent enums."""

from __future__ import annotations

import json
from pathlib import Path

RULE_TEXT = {
    "PROC-001": (
        "Office application launched a command or script interpreter",
        "An Office application was observed launching a command or script interpreter.",
        "Process Chain",
        ["Enterprise add-ins and legitimate Office automation."],
        ["Verify the parent-child chain.", "Review the masked command line and executable path."],
    ),
    "PROC-002": (
        "Browser or PDF reader launched a command interpreter",
        "A command or script interpreter was observed under a browser or PDF reader.",
        "Process Chain",
        ["Legitimate browser helpers, PDF automation, and developer tools."],
        ["Verify parent and child executable paths.", "Review related network events."],
    ),
    "PROC-003": (
        "Process launched from a temporary or Downloads folder",
        "An executable was launched from a temporary directory or the user's Downloads folder.",
        "Execution Location",
        ["Installers and legitimate portable applications downloaded by the user."],
        ["Verify the file source and signature with operating-system tools."],
    ),
    "PROC-004": (
        "PowerShell encoded command indicator",
        "A common argument associated with encoded PowerShell commands was observed.",
        "Command Interpreter",
        ["Legitimate administration and software-deployment scripts may use encoded commands."],
        ["Verify the command source and parent process.", "Review related network and listener events."],
    ),
    "PROC-005": (
        "Command interpreter launched by an unusual parent",
        "A command or script interpreter was launched outside the common expected parent list.",
        "Process Chain",
        ["Enterprise agents, schedulers, and application-specific automation."],
        ["Verify the parent executable path and command line."],
    ),
    "PROC-006": (
        "Many child processes in a short period",
        "At least 15 new child processes were observed under the same parent PID within 30 seconds.",
        "Process Volume",
        ["Installers, build systems, and developer tools."],
        ["Review the child process list and parent executable path."],
    ),
    "PROC-007": (
        "New process connected to a public endpoint shortly after start",
        "A newly observed process identity connected to a public remote endpoint within 30 seconds.",
        "Process and Network Correlation",
        ["Browsers, updaters, and cloud clients."],
        ["Verify the endpoint, process path, and parent chain."],
    ),
    "PROC-008": (
        "Process from a temporary location connected to a public endpoint",
        "A process launched from Temp or Downloads connected to a public remote endpoint.",
        "Process and Network Correlation",
        ["Legitimate installers and portable applications."],
        ["Verify the file source and remote endpoint."],
    ),
    "PROC-009": (
        "Process from a temporary location opened a listening port",
        "A process launched from Temp or Downloads opened a local listening port.",
        "Process and Network Correlation",
        ["Development servers and legitimate tools running from a temporary directory."],
        ["Verify the listening scope and process executable."],
    ),
    "NET-101": (
        "Many unique public endpoints in a short period",
        "The same process connected to at least 20 unique public endpoints within 60 seconds.",
        "Network Volume",
        ["Browsers, game clients, updaters, and applications using CDNs."],
        ["Compare the endpoint list with the application's expected network behavior."],
    ),
    "NET-102": (
        "New process started listening on all interfaces",
        "A new process started listening on 0.0.0.0 or :: within 30 seconds.",
        "Listener Correlation",
        ["Legitimate local servers and development tools."],
        ["Observe and verify the port, executable path, and firewall scope."],
    ),
    "NET-103": (
        "New listening port not marked as expected",
        "A listening port not explicitly marked as expected by the user opened.",
        "Listener Baseline",
        ["Newly installed or first-used legitimate server applications."],
        ["Verify the process opening the port and its listening scope."],
    ),
    "NET-104": (
        "Unexpected high-numbered listening port",
        "A process not marked as expected started listening on port 49152 or higher.",
        "Listener Baseline",
        ["Many legitimate applications use dynamic high-numbered ports."],
        ["Verify the process network role and whether the port is expected."],
    ),
    "CORR-001": (
        "Process, public connection, and new listener sequence",
        "The same process identity started, connected to a public endpoint, and opened a listening port within 60 seconds.",
        "Multi-stage Correlation",
        ["Legitimate applications may contact an external service and open a local service on first run."],
        ["Review the full evidence timeline, executable path, and endpoints together."],
    ),
    "CORR-002": (
        "Parent launched multiple interpreters followed by a public connection",
        "Multiple script interpreters and related public endpoint behavior were observed under the same parent.",
        "Multi-stage Correlation",
        ["Automation, build, and management systems may launch multiple interpreters."],
        ["Verify the parent process, child command lines, and public endpoints."],
    ),
}

SEVERITY = {
    "Bilgi": "info",
    "Düşük": "low",
    "Orta": "medium",
    "Yüksek": "high",
    "Kritik": "critical",
}


def _normalize_values(value: object) -> object:
    if isinstance(value, dict):
        return {key: _normalize_values(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_values(item) for item in value]
    if value == "Genel / public":
        return "public"
    return value


def main() -> None:
    path = Path(__file__).resolve().parent.parent / "rules" / "builtin_rules.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    for rule in payload["rules"]:
        title, description, category, false_positives, steps = RULE_TEXT[rule["id"]]
        rule["title"] = title
        rule["description"] = description
        rule["category"] = category
        rule["false_positives"] = false_positives
        rule["investigation_steps"] = steps
        rule["severity"] = SEVERITY.get(rule["severity"], rule["severity"])
        rule["title_key"] = f"rules.{rule['id']}.title"
        rule["description_key"] = f"rules.{rule['id']}.description"
        rule["category_key"] = f"rules.{rule['id']}.category"
        rule["conditions"] = _normalize_values(rule.get("conditions", {}))
        if "correlation" in rule:
            rule["correlation"] = _normalize_values(rule["correlation"])
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
