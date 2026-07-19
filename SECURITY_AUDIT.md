# VigilScope Security Audit

**Review date:** 2026-07-19  
**Reviewed version:** 0.1.0 release candidate  
**Scope:** Python source, bundled rules and locales, SQLite access, exports,
filesystem behavior, background workers, dependency declarations, Git history,
and Windows release automation.

## Executive Summary

The project was reviewed before public release. No known credential, private
endpoint database, log file, export, or API key remains in the release tree.
The original development history contained a personal author name and email;
the public package replaces that history with a new, sanitized root commit.

The review found several denial-of-service, privacy, export, portability, and
reliability weaknesses. They were remediated before this report was generated.
No high-confidence remote-code-execution path, active network attack feature,
shell-command execution path, unsafe deserialization path, or user-controlled
SQL identifier was found.

This result is not a proof that the software is vulnerability-free. VigilScope
observes security-sensitive local metadata and should be treated as an
educational defensive tool, not as a security boundary or commercial endpoint
protection product.

## Review Methods

- Manual review of source modules, data flows, filesystem writes, database
  queries, rule loading, regex matching, exports, and background workers.
- Repository-wide searches for credentials, personal information, dangerous
  Python APIs, network clients, subprocess execution, unsafe deserialization,
  and runtime databases.
- Automated unit and integration tests.
- Ruff static analysis.
- Bandit security-oriented static analysis, with each narrowly suppressed SQL
  construction reviewed for fixed identifiers and parameterized values.
- PyInstaller bundle creation and packaged `--check` execution on the available
  host platform.
- Git author, committer, tracked-file, and historical-object review.
- CI configuration for `pip-audit`, committed-secret scanning, and CodeQL.

## Remediated Findings

### VS-SEC-001 — Personal data in Git history

**Severity:** High privacy impact  
**Status:** Fixed

Every original commit included a real personal author name and Gmail address.
Deleting those strings from current files would not remove them from historical
commits.

**Remediation:** The public repository is supplied with a new Git history and a
single root commit authored as `miltech0 <miltech0@users.noreply.github.com>`.
The old `.git` object database is not included.

### VS-SEC-002 — Unbounded user-rule input

**Severity:** Medium  
**Status:** Fixed

User-controlled rule JSON could consume excessive memory or processing time
through very large files, duplicate keys, deeply nested conditions, oversized
lists, or excessive rule counts.

**Remediation:** Rule loading now rejects duplicate keys and enforces limits on
file size, individual rule size, rule count, nesting depth, field names, text
length, list length, and condition count. Import failures are handled without
replacing valid rules.

### VS-SEC-003 — Regex denial-of-service exposure

**Severity:** Medium  
**Status:** Fixed

Static regex validation alone cannot reliably prevent catastrophic
backtracking.

**Remediation:** Regex patterns retain conservative syntax and size validation
and are executed through the `regex` package with a strict per-match timeout.
Invalid patterns and timeouts fail closed without stopping the detection
worker.

### VS-SEC-004 — CSV spreadsheet formula injection

**Severity:** Medium  
**Status:** Fixed

Exported process names, paths, command lines, notes, or evidence beginning with
spreadsheet formula characters could execute as a formula when opened in some
spreadsheet applications.

**Remediation:** CSV cells beginning with formula-control characters or leading
control whitespace are neutralized before writing. JSON output remains
canonical and is not modified in this way.

### VS-SEC-005 — Incomplete recursive secret masking

**Severity:** Medium privacy impact  
**Status:** Fixed

Some nested evidence fields could bypass command-line-focused masking.

**Remediation:** Detection evidence and exported nested structures now apply
recursive best-effort masking for common password, token, API-key, and Bearer
patterns. This is defense in depth and cannot recognize every possible secret
format.

### VS-SEC-006 — Runtime-data permissions on non-Windows systems

**Severity:** Low  
**Status:** Fixed

Development systems could create data directories and files with permissions
that were broader than necessary, depending on the user's umask.

**Remediation:** VigilScope applies owner-only directory and file modes on POSIX
systems on a best-effort basis. Windows storage remains under LocalAppData and
relies on the user's profile ACL.

### VS-SEC-007 — Background history worker crash

**Severity:** Low reliability impact  
**Status:** Fixed

A platform returning `None` from `psutil.net_io_counters()` could cause the
history worker to raise an exception.

**Remediation:** Missing counters are handled as zero-value data and the worker
continues safely.

### VS-SEC-008 — Disk enumeration portability failure

**Severity:** Low reliability impact  
**Status:** Fixed

A system with no usable partition list could leave the overview without disk
information and fail an existing test.

**Remediation:** The collector uses a portable root-filesystem fallback and
continues to handle inaccessible mount points individually.

### VS-SEC-009 — Dynamic SQL review and constraint

**Severity:** Medium if identifiers became user-controlled  
**Status:** Reviewed and constrained

Several queries assemble clause fragments, placeholder lists, or migration
identifiers dynamically.

**Remediation:** Values remain parameterized. Dynamic identifiers originate
from fixed internal mappings or fixed field lists, query-source choices use
allowlisted branches, and migration mappings are not user-configurable. Narrow
Bandit suppressions document the reviewed locations. No rule field, UI string,
path, IP address, or user note is interpolated as a SQL identifier.

### VS-SEC-010 — Release-build reproducibility and integrity

**Severity:** Medium supply-chain impact  
**Status:** Fixed within current project scope

There was no public, repeatable Windows packaging path or checksum.

**Remediation:** The repository includes pinned runtime/build dependencies, a
PyInstaller specification, Windows version metadata, a build script, CI checks,
CodeQL, Dependabot, release automation on GitHub-hosted Windows runners, and a
SHA-256 checksum for every release executable.

## Data and Network Behavior

- The application reads local process, socket, memory, disk, and hostname data.
- The application does not actively scan ports or remote hosts.
- The application does not send or inject packets.
- The application does not terminate processes or connections.
- The application does not modify Windows Firewall.
- The application does not execute commands from rule files.
- The application does not use external reputation, WHOIS, ASN, geolocation, or
  threat-intelligence APIs.
- Optional reverse DNS is disabled by default. When enabled, it uses the
  operating system's configured DNS resolver and therefore can expose the
  queried address to that resolver.

## Validation Results

- Automated tests: **137 passed, 1 skipped** on the audit host. The skipped test
  requires a graphical Tk display unavailable in the headless environment.
- Ruff: **passed**.
- Bandit: **passed** after review of narrowly suppressed fixed-identifier SQL
  construction.
- Python bytecode compilation: **passed**.
- Source `--check` health test: **passed**.
- PyInstaller package build on the audit host: **passed**.
- Packaged `--version` and `--check`: **passed**.
- Personal-data scan of the public tree: **no developer name, personal email,
  Windows account name, or original project path found**.
- Git history scan: **only the sanitized noreply identity remains**.

A local `pip-audit` query could not complete because the isolated audit runtime
had no DNS access. The repository runs `pip-audit --strict` in GitHub Actions
where network access is available. Runtime dependencies are pinned, and
Dependabot is configured for weekly package and workflow updates.

## Residual Risks and Limitations

1. **Unsigned executable:** The project has no trusted Windows code-signing
   certificate. SmartScreen or antivirus reputation systems can warn about a
   new PyInstaller executable. SHA-256 verification detects file changes but
   does not replace publisher authentication.
2. **Sensitive local telemetry:** The SQLite database and exports can contain
   usernames, paths, IP addresses, ports, timestamps, and analyst notes. The
   database is not encrypted by the application and relies on user-profile
   permissions.
3. **Best-effort masking:** Secret masking recognizes common patterns, not every
   custom credential format. Review exports before sharing them.
4. **Privilege-dependent visibility:** Windows can deny access to process paths,
   owners, command lines, or socket ownership. Missing data is displayed safely
   but can reduce detection context.
5. **Snapshot gaps:** Very short-lived processes and network connections can
   start and end between collection intervals.
6. **False positives:** Baseline and behavioral rules can flag normal browsers,
   installers, updaters, games, and development tools.
7. **Rule-engine complexity:** Size, depth, count, and regex-time limits reduce
   denial-of-service risk but do not establish a formal resource bound for all
   possible rule combinations.
8. **Automated analysis limits:** Tests, Bandit, Ruff, CodeQL, dependency audits,
   and manual review can miss defects.

## Public Release Checklist

- [x] Current source tree contains no known personal developer information.
- [x] Historical personal Git metadata is removed from the clean repository.
- [x] Runtime databases, WAL files, logs, exports, caches, and environments are
      excluded.
- [x] Rule files are data-only and bounded.
- [x] CSV exports are formula-safe.
- [x] Release builds include checksums.
- [x] CI and CodeQL workflows are present.
- [x] Private vulnerability-reporting instructions are present.
- [ ] Windows release workflow has completed successfully for the public tag.
- [ ] Repository visibility has been changed to Public by the repository owner.
- [ ] A trusted code-signing certificate has been configured (optional and not
      currently available).
