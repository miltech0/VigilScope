# Changelog

All notable changes to VigilScope are documented here.

## 0.1.0 — 2026-07-19

### Added

- Passive local system, process, connection, listening-port, and endpoint views.
- SQLite history, baselines, findings, detection rules, alerts, suppressions, and cases.
- English and Turkish runtime localization.
- Data-only rule validation with bounded matching and correlation.
- GitHub Actions CI, CodeQL, dependency auditing, secret scanning, and Windows release builds.
- PyInstaller packaging, application icon, release checksum, and verification script.

### Security hardening

- Bounded rule-file sizes, object depth, condition counts, and regex execution time.
- Duplicate JSON key rejection for rule and locale data.
- Spreadsheet formula-injection protection for CSV exports.
- Recursive secret masking in exported evidence.
- Private runtime-data permissions where supported.
- Reviewed and constrained dynamic SQL construction.
- Portable disk collection and null network-counter handling.
- Sanitized public repository history without personal author metadata.
