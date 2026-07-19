# VigilScope

Privacy-first local Windows endpoint visibility, detection, and incident
investigation workbench built with Python.

[![CI](https://github.com/miltech0/VigilScope/actions/workflows/ci.yml/badge.svg)](https://github.com/miltech0/VigilScope/actions/workflows/ci.yml)
[![CodeQL](https://github.com/miltech0/VigilScope/actions/workflows/codeql.yml/badge.svg)](https://github.com/miltech0/VigilScope/actions/workflows/codeql.yml)
[![Latest release](https://img.shields.io/github/v/release/miltech0/VigilScope?display_name=tag)](https://github.com/miltech0/VigilScope/releases/latest)

VigilScope is an EDR-inspired, passive desktop application for understanding
what is happening on one local Windows computer. It combines system metrics,
process visibility, network observations, explainable detection rules, alerts,
and case-oriented investigation without claiming to be a commercial EDR.

## Download

Windows x64 builds are published on the
[GitHub Releases page](https://github.com/miltech0/VigilScope/releases). Each
release includes:

- `VigilScope.exe`;
- `VigilScope.exe.sha256`;
- a ZIP archive containing the executable, checksum, README, and security policy.

Verify the executable before running it:

```powershell
.\scripts\verify_release.ps1 `
  -ExePath .\VigilScope.exe `
  -ChecksumPath .\VigilScope.exe.sha256
```

Release binaries are built from the tagged source on GitHub-hosted Windows
runners. They are currently **unsigned**, so Windows SmartScreen or antivirus
products may show a reputation warning. Review the source, verify the checksum,
and download only from this repository's Releases page.

## Overview

VigilScope collects operating-system information through `psutil`, stores
history in a local SQLite database, and presents the data in a dark Tkinter
interface. The application is designed for educational, personal, and
defensive-security use.

English and Turkish are available at runtime. The flag buttons in the
application header switch every rebuilt main view without restarting the
application. The selected language is saved for the next launch.

## Key Features

- Overview cards for CPU, memory, disk, and active connections.
- Sortable active TCP and UDP connection table with process lookup.
- Detailed process list, filters, process tree, and read-only process details.
- Passive listening-port and remote-endpoint baselines.
- Explainable network findings with expected-baseline notes.
- System, connection, process, and network event history.
- Data-only built-in and user-authored detection rules.
- Alert evidence, analyst notes, suppressions, MITRE ATT&CK mappings, and cases.
- UTF-8 CSV and canonical JSON exports with sensitive command-line masking.
- Runtime Turkish/English language switching with localized dates and enums.

## Screenshots

Real project screenshots are not bundled yet. See
[`docs/screenshots/README.md`](docs/screenshots/README.md) for the capture
checklist and naming guidance. No mock or fabricated product screenshots are
used.

## Language Support

The supported language codes are:

- `tr` — Türkçe
- `en` — English

Translations live in `locales/tr.json`, `locales/en.json`, and the matching
rule-translation files under `locales/rules/`. Both locale catalogs use the
same keys and parameter names. Missing translations fall back to English;
missing English keys produce a visible development warning instead of
crashing the UI.

On first launch, a Turkish Windows display language selects Turkish. Other
display languages select English. Later launches use the saved preference from
`settings.json`.

## Architecture

The application separates collection, persistence, analysis, presentation,
and localization:

- `system_info/product.py` contains canonical product metadata and filenames.
- `system_info/settings.py` loads and atomically saves user preferences.
- `system_info/i18n.py` provides thread-safe key-based translations, enum
  presentation, callbacks, and date/number formatting.
- `system_info/data_migration.py` performs the one-time legacy database backup.
- `system_info/database.py` owns repeatable SQLite schema upgrades.
- `system_info/app.py` coordinates the Tkinter lifecycle and background tasks.
- `system_info/process_*` modules collect, filter, compare, and present process
  data.
- `system_info/network_*` modules build one shared passive network snapshot,
  maintain baselines, and create explainable findings.
- `system_info/detection_*`, `rule_*`, and `correlation_engine.py` implement the
  data-only detection and investigation workflow.
- `system_info/exporting.py` and `detection_exporting.py` create masked exports.

Background workers never update Tkinter widgets directly. Results return
through queues and are applied on the UI thread. Duplicate process and network
scans are suppressed rather than queued indefinitely.

## Detection Engine

Built-in rules are canonical English JSON records in
[`rules/builtin_rules.json`](rules/builtin_rules.json). Matching uses stable
event, severity, status, and address-scope codes—not translated labels.
Turkish built-in rule titles, descriptions, and categories are resolved by
rule ID from the locale catalog.

Rules compare normalized fields and support bounded sequence, count, and
distinct-count correlations. They do not execute Python, PowerShell, shell
commands, or code embedded in JSON. User rules remain in the language in which
the user wrote them and are never machine-translated.

Alerts are investigative signals, not proof of malware. Expected baselines can
reduce a finding or alert's effective severity, but VigilScope never marks an
endpoint trustworthy automatically.

## Network Analysis

Network Analysis reuses one local `psutil.net_connections` snapshot for active
connections, listeners, endpoint baselines, network events, and findings.

A listening port is a local socket waiting for traffic. Address scope matters:

- **Loopback** (`127.0.0.1`, `::1`) is reachable only from the same computer.
- **Private network** addresses are intended for local network ranges.
- **All interfaces** (`0.0.0.0`, `::`) binds the listener to every matching
  local interface and deserves additional review.
- **Public** identifies globally routable remote addresses.

The first network snapshot is a baseline and does not generate a burst of
“started” or “new endpoint” events. Later changes create canonical network
events. A remote endpoint is identified by protocol, IP, and port; process
usage is tracked separately.

Optional reverse DNS uses only the operating system resolver, runs in bounded
background work, and caches results. VigilScope does not use WHOIS, geolocation,
ASN, reputation, or threat-intelligence APIs.

## Process Monitoring

The Processes tab refreshes every two seconds by default and supports:

- text, status, minimum CPU, minimum RAM, and network-activity filters;
- stable numeric and text sorting;
- a parent-child process tree with orphan and cycle protection;
- read-only process details, command line, path, working directory, open file
  count when available, related connections, children, and parent chain.

PID alone is not a durable identity because Windows can reuse it. VigilScope
uses PID plus process creation time whenever possible. The first process
snapshot is treated as the normal baseline; start and stop events begin with
subsequent changes.

`Access Denied`, `Terminated`, and `Unknown` are safe display states. One
inaccessible or disappearing process does not abort the complete snapshot.
Command lines are collected without blocking per-process CPU calls.

VigilScope intentionally has no process termination, suspension, deletion, or
other intervention controls.

## History and SQLite Storage

The active database is:

```text
%LOCALAPPDATA%\VigilScope\vigilscope.db
```

On non-Windows development systems, the equivalent XDG data directory is used.
SQLite uses WAL mode, foreign keys, a busy timeout, short-lived connections,
and repeatable schema migrations. Canonical timestamps remain in the database;
display formatting is applied only in the UI.

Default retention:

- system measurements: 7 days;
- connection events: 14 days;
- process events: 14 days;
- listening-port and network events: 30 days;
- endpoint hourly observations: 8 days;
- DNS cache: 7 days;
- remote-endpoint baselines: not automatically deleted;
- findings, alerts, cases, notes, and detection checkpoints: not removed by
  routine retention cleanup.

Retention values are centralized in `system_info/config.py`.

### Legacy data migration

If the new database does not exist and this legacy database is present:

```text
%LOCALAPPDATA%\SistemBilgisi\system_history.db
```

VigilScope uses SQLite's backup API to create the new database, verifies its
integrity, writes a migration marker, and leaves the original folder untouched.
It never overwrites an existing `vigilscope.db` and never copies a live WAL
database as an uncontrolled raw file operation.

Schema version 5 normalizes legacy Turkish or English enum labels to stable
codes while preserving alerts, evidence, cases, notes, baselines, free-form
rule text, and user-authored notes.

## Alerts and Cases

Alerts preserve their evidence, first and last observation, repeat count,
status history, and analyst notes. Cases associate selected alerts into an
investigation timeline without deleting the source records. “Case” means an
investigation file; “event” means a raw system or network observation.

Alert status codes are `new`, `investigating`, `confirmed`,
`false_positive`, `ignored`, and `closed`. Localized labels are presentation
only.

## MITRE ATT&CK Mapping

Built-in rules may contain official MITRE ATT&CK tactic and technique IDs and
English technique names. The coverage view summarizes mappings for enabled
rules and observed alerts. It is behavioral classification, not a claim of
complete enterprise ATT&CK coverage.

## Privacy

VigilScope is local-first. It does not upload telemetry and does not send IP
addresses, process names, usernames, paths, command lines, events, findings,
alerts, or cases to external services. Common password, token, API-key, and
Bearer patterns are masked before command-line presentation and export.

The local database and exports can still contain sensitive endpoint metadata,
including usernames, process paths, IP addresses, ports, timestamps, and
analyst notes. Protect `%LOCALAPPDATA%\VigilScope`, treat exported files as
sensitive, and remove private data before attaching screenshots or reports to
public issues. The database is not application-level encrypted; it relies on
the operating-system user-profile permissions. Optional reverse DNS uses the
computer's configured DNS resolver and is disabled by default.

## Safety Model

The application is passive and read-only.

- It does not actively scan ports or remote computers.
- It does not send or inject packets.
- It does not terminate or suspend processes.
- It does not block or terminate network connections.
- It does not modify Windows Firewall.
- It does not execute commands on remote systems.
- It does not automatically block IP addresses.
- It does not upload telemetry.
- It does not contact external threat-intelligence services.

## Requirements

- Windows 10 or later is the primary target.
- Python 3.11 or later.
- Tkinter, included with standard Windows Python distributions.
- Runtime dependencies pinned in `requirements.txt` (`psutil==7.2.2` and `regex==2026.7.10`).

Some process and socket fields require elevated Windows permissions. The
application remains usable without elevation and reports inaccessible fields
safely.

## Installation from Source

PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
```

No heavy plotting library or network-service SDK is required.

## Running the Application

```powershell
.\.venv\Scripts\python.exe main.py
```

Run the non-GUI health check:

```powershell
.\.venv\Scripts\python.exe main.py --check
```

## Running Tests

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m compileall -q main.py system_info tests tools
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m bandit -r system_info main.py -q
.\.venv\Scripts\python.exe -m pip_audit -r requirements.txt --strict
.\.venv\Scripts\python.exe -m pip check
```

## Building the Windows Executable

On Windows, install the build dependencies and run:

```powershell
.\scripts\build_windows.ps1
```

The build uses `VigilScope.spec`, bundles the locale catalogs, built-in rules,
flags, and application icon, then runs the packaged `--check` health test and
creates a SHA-256 checksum. PyInstaller builds for the operating system on
which it runs; the official Windows executable is therefore produced on a
Windows runner.

Pushing a version tag starts the release workflow:

```powershell
git tag v0.1.0
git push origin v0.1.0
```

A manual workflow run builds an artifact without creating a GitHub Release.

## Data Storage

The application directory is:

```text
%LOCALAPPDATA%\VigilScope
```

It contains:

- `vigilscope.db` and SQLite-managed WAL/SHM files while active;
- `settings.json`, atomically written as UTF-8;
- `.legacy-data-migrated.json` after a successful legacy migration.

Source folders are not used for runtime databases or transient user data.

## Built-in Rules

Built-in rules are versioned, canonical English, data-only records. Their IDs,
matching fields, MITRE IDs, protocol values, paths, and other technical values
are never translated. Disabling a built-in rule is supported; deleting or
editing its canonical definition in the UI is intentionally restricted.

## Creating User Rules

The rule editor accepts JSON conditions and bounded correlation settings.
Validate and preview a rule against local history before saving it. User titles,
descriptions, categories, false-positive notes, and investigation steps remain
exactly as authored.

## Exporting Data

History, detections, findings, alerts, and cases support UTF-8 CSV or JSON
exports where applicable.

- CSV headers follow the active display language.
- JSON field names remain canonical English for machine compatibility.
- JSON bundles include `product`, `display_language`, and ISO `exported_at`
  metadata.
- Default filenames use safe English names such as
  `vigilscope_history_2026-07-19.json`.
- Common command-line secrets remain masked.

## Security Verification

The repository runs tests on Windows and Linux, Ruff, Bandit, dependency
auditing, committed-secret detection, and CodeQL. The release workflow reruns
source validation before packaging. See [`SECURITY_AUDIT.md`](SECURITY_AUDIT.md)
for the reviewed attack surface, remediated findings, validation evidence, and
residual risks. Automated tooling reduces risk but does not prove that the
software is vulnerability-free.

Security vulnerabilities should be reported privately through
[GitHub Security Advisories](https://github.com/miltech0/VigilScope/security/advisories/new),
not through a public issue.

## Known Limitations

- `psutil` exposes operating-system socket tables, not packet payloads.
- Short-lived connections and processes can appear and disappear between
  snapshots.
- Access permissions can hide process owner, path, command line, or socket PID.
- Reverse DNS can time out or return no hostname.
- Baseline and explainable rules can produce false positives, especially for
  browsers, developer tools, installers, and updaters.
- Runtime language switching rebuilds the main interface and closes open detail
  windows; reopen a detail record to view it in the new language.
- The local telemetry database is not encrypted by the application.
- Official binaries are not code-signed and may trigger reputation warnings.
- Static analysis and automated tests cannot guarantee absence of vulnerabilities.
- This project is not a replacement for commercial endpoint protection.

## Project Structure

```text
assets/flags/              Bundled TR and GB flag PNGs
docs/screenshots/          Screenshot contribution guidance
packaging/                 Windows executable metadata
scripts/                   Build and checksum verification scripts
.github/workflows/         CI, CodeQL, and Windows release automation
locales/                   English and Turkish UI/rule catalogs
rules/                     Canonical built-in JSON detection rules
system_info/               Application, services, repositories, and UI modules
tests/                     Isolated automated tests
tools/                     Reproducible asset and rule maintenance scripts
main.py                    Application entry point
requirements.txt           Runtime dependency pin
requirements-dev.txt       Test and security-tool dependency pins
requirements-build.txt     PyInstaller build dependency pin
VigilScope.spec            Reproducible executable bundle configuration
SECURITY_AUDIT.md          Security review scope, fixes, and residual risks
```

## Roadmap

Potential future work includes more complete keyboard navigation, richer
localized analyst guidance, pagination for very large case histories, signed
release packaging, and additional explainable passive rules. Roadmap items are
not promises and are not represented as implemented features.

## Disclaimer

VigilScope is an educational and personal defensive-security project. Alerts
and findings are investigative signals, not proof of malware. It is not a
full-featured commercial EDR and is not a replacement for commercial endpoint
protection, organizational monitoring, incident-response procedures, or
professional security advice.
