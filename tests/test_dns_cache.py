import time

from system_info.database import HistoryDatabase
from system_info.dns_cache import DnsResolverCache


def test_dns_result_is_cached_without_second_lookup(tmp_path) -> None:
    database = HistoryDatabase(tmp_path / "dns.db")
    database.initialize()
    calls = {"count": 0}

    def resolver(ip):
        calls["count"] += 1
        return "dns.google", [], [ip]

    cache = DnsResolverCache(database, resolver)
    assert cache.resolve("8.8.8.8") == "dns.google"
    assert cache.resolve("8.8.8.8") == "dns.google"
    assert calls["count"] == 1
    cache.close()


def test_dns_failure_is_safe_and_cached(tmp_path) -> None:
    database = HistoryDatabase(tmp_path / "dns-failure.db")
    database.initialize()

    def resolver(_ip):
        raise OSError("offline")

    cache = DnsResolverCache(database, resolver)
    assert cache.resolve("192.0.2.1") == "Çözümlenemedi"
    assert cache.resolve("192.0.2.1") == "Çözümlenemedi"
    cache.close()


def test_dns_timeout_is_safe_and_cached(tmp_path) -> None:
    database = HistoryDatabase(tmp_path / "dns-timeout.db")
    database.initialize()

    def slow_resolver(_ip):
        time.sleep(0.05)
        return "late.example", [], []

    cache = DnsResolverCache(database, slow_resolver, timeout_seconds=0.01)
    assert cache.resolve("203.0.113.10") == "Çözümlenemedi"
    assert cache.resolve("203.0.113.10") == "Çözümlenemedi"
    cache.close()
