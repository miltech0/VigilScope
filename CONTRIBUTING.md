# Contributing to VigilScope

Thank you for improving VigilScope. Keep contributions passive, local-first,
explainable, and read-only.

## Development

1. Create a virtual environment.
2. Install `requirements-dev.txt`.
3. Make focused changes with English comments, docstrings, logs, tests, and
   repository-facing documentation.
4. Put user-visible text in both locale catalogs. Keep the English and Turkish
   key sets and placeholders identical.
5. Use canonical internal enum codes; never use translated labels as database
   identities or query values.
6. Add isolated tests that use temporary databases and mocked system data.
7. Never commit endpoint databases, exports, logs, credentials, or personal
   filesystem paths.

Before submitting a change, run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m compileall -q main.py system_info tests tools
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m bandit -r system_info main.py -q
.\.venv\Scripts\python.exe -m pip_audit -r requirements.txt --strict
.\.venv\Scripts\python.exe -m pip check
.\.venv\Scripts\python.exe main.py --check
```

Do not add active scanning, packet injection, process termination, connection
blocking, firewall modification, telemetry upload, or automatic
threat-intelligence requests.

Report vulnerabilities privately according to `SECURITY.md`.
