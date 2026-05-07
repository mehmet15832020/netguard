"""
dns_resolver testleri — PTR lookup, cache davranışı, hata yönetimi.
"""
import socket
import time
from unittest.mock import patch

import pytest

from server.dns_resolver import _cache, clear_cache, resolve_hostname


@pytest.fixture(autouse=True)
def clean_cache():
    clear_cache()
    yield
    clear_cache()


def test_resolve_known_loopback():
    """127.0.0.1 → 'localhost' (veya sistem hostname)."""
    result = resolve_hostname("127.0.0.1")
    assert result is not None


def test_resolve_returns_none_on_error():
    """Geçersiz IP veya PTR kaydı olmayan IP → None."""
    with patch("server.dns_resolver._executor") as mock_exec:
        future_mock = mock_exec.submit.return_value
        future_mock.result.side_effect = socket.herror("no PTR")
        result = resolve_hostname("192.0.2.1")
    assert result is None


def test_cache_hit_avoids_second_lookup():
    """İkinci çağrı socket.gethostbyaddr'ı çağırmamalı."""
    with patch("server.dns_resolver._executor") as mock_exec:
        future_mock = mock_exec.submit.return_value
        future_mock.result.return_value = ("testhost.local", [], ["10.0.0.1"])

        resolve_hostname("10.0.0.1")
        resolve_hostname("10.0.0.1")

    assert mock_exec.submit.call_count == 1


def test_cache_miss_on_expiry():
    """TTL dolduğunda ikinci sorgu atılmalı."""
    with patch("server.dns_resolver._executor") as mock_exec:
        future_mock = mock_exec.submit.return_value
        future_mock.result.return_value = ("host.local", [], ["10.0.0.2"])

        resolve_hostname("10.0.0.2")
        _cache["10.0.0.2"] = (_cache["10.0.0.2"][0], time.monotonic() - 1)  # TTL'yi geçir
        resolve_hostname("10.0.0.2")

    assert mock_exec.submit.call_count == 2


def test_timeout_returns_none():
    """1s zaman aşımında None döner, uygulama çökmez."""
    import concurrent.futures
    with patch("server.dns_resolver._executor") as mock_exec:
        future_mock = mock_exec.submit.return_value
        future_mock.result.side_effect = concurrent.futures.TimeoutError

        result = resolve_hostname("203.0.113.1")

    assert result is None


def test_empty_ip_returns_none():
    """Boş string None döner."""
    assert resolve_hostname("") is None


def test_failure_cached_for_miss_ttl():
    """Başarısız lookup miss TTL ile cache'e girer, tekrar sorgu yapmaz."""
    with patch("server.dns_resolver._executor") as mock_exec:
        future_mock = mock_exec.submit.return_value
        future_mock.result.side_effect = socket.gaierror("NXDOMAIN")

        resolve_hostname("198.51.100.1")
        resolve_hostname("198.51.100.1")  # cache'ten gelmeli

    assert mock_exec.submit.call_count == 1
    cached_val, _ = _cache["198.51.100.1"]
    assert cached_val is None
