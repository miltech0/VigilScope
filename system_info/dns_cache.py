"""Optional reverse-DNS cache using only the operating-system resolver."""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, TimeoutError
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

from .config import DNS_CACHE_RETENTION_DAYS, DNS_LOOKUP_TIMEOUT_SECONDS
from .database import HistoryDatabase, to_db_timestamp


class DnsResolverCache:
    def __init__(
        self,
        database: HistoryDatabase,
        resolver: Callable[[str], tuple[str, list[str], list[str]]] | None = None,
        timeout_seconds: float = DNS_LOOKUP_TIMEOUT_SECONDS,
    ) -> None:
        self.database = database
        self.resolver = resolver or socket.gethostbyaddr
        self.timeout_seconds = timeout_seconds
        self._executor = ThreadPoolExecutor(
            max_workers=2,
            thread_name_prefix="reverse-dns-resolver",
        )

    def resolve(self, ip_address: str) -> str:
        now = datetime.now(timezone.utc)
        with self.database._connection() as connection:
            row = connection.execute(
                "SELECT hostname, expires_at FROM dns_cache WHERE ip_address=?",
                (ip_address,),
            ).fetchone()
        if row:
            try:
                expiry = datetime.fromisoformat(
                    str(row["expires_at"]).replace("Z", "+00:00")
                )
                if expiry > now:
                    return str(row["hostname"])
            except ValueError:
                pass
        try:
            future = self._executor.submit(self.resolver, ip_address)
            hostname = (
                future.result(timeout=self.timeout_seconds)[0]
                or "Çözümlenemedi"
            )
        except (OSError, socket.herror, socket.gaierror, TimeoutError):
            hostname = "Çözümlenemedi"
        with self.database._connection() as connection, connection:
            connection.execute(
                """
                INSERT INTO dns_cache(ip_address, hostname, resolved_at, expires_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(ip_address) DO UPDATE SET
                    hostname=excluded.hostname,
                    resolved_at=excluded.resolved_at,
                    expires_at=excluded.expires_at
                """,
                (
                    ip_address,
                    hostname,
                    to_db_timestamp(now),
                    to_db_timestamp(now + timedelta(days=DNS_CACHE_RETENTION_DAYS)),
                ),
            )
        return hostname

    def close(self) -> None:
        """Bekleyen çözümlemeleri iptal eder; çalışan sistem çağrısını zorla kesmez."""
        self._executor.shutdown(wait=False, cancel_futures=True)
