# Security Policy

## Supported Versions

Security fixes are applied to the latest tagged release and the `main` branch.
Older experimental builds are not supported.

## Reporting a Vulnerability

Use the repository's private
[GitHub Security Advisory form](https://github.com/miltech0/VigilScope/security/advisories/new).
Do not open a public issue before a fix is available.

Include:

- the affected version or commit;
- clear reproduction steps;
- expected security impact;
- the smallest safe proof of concept;
- suggested remediation, when available.

Do not include real passwords, tokens, private IP inventories, usernames,
command lines, database files, analyst notes, or other endpoint telemetry.
Sanitize screenshots and exports before sharing them.

## Security Model

VigilScope is a local, passive, educational defensive-security application. It
is not a security boundary and is not a replacement for commercial endpoint
protection.

The application intentionally does not:

- terminate or suspend processes;
- block network connections;
- modify Windows Firewall;
- actively scan remote systems;
- inject or capture packet payloads;
- upload telemetry;
- contact external threat-intelligence services;
- execute code from detection-rule files.

Relevant reports include unsafe local-data handling, secret leakage, rule-file
parsing issues, regex denial of service, CSV/JSON export problems, SQL query
construction, migration failures, unintended external network activity, build
pipeline compromise, and privilege-boundary mistakes.

## Local Data

VigilScope stores endpoint telemetry under `%LOCALAPPDATA%\VigilScope`. The
SQLite database is not encrypted by the application and relies on Windows
user-profile access controls. Exports can contain sensitive metadata and should
be handled accordingly.

## Release Integrity

Each release includes a SHA-256 checksum. Release binaries are currently
unsigned; checksum verification establishes file integrity relative to the
published release but does not provide publisher identity in the same way as a
trusted code-signing certificate.
