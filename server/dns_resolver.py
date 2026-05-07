"""
PTR (reverse DNS) çözümleyici — IP → hostname.
ThreadPoolExecutor tabanlı: event loop'u bloklamamak için.
TTL cache: başarılı 300s, başarısız 60s.

resolve_hostname()       — senkron, cache'e yazar (test/CLI kullanımı)
resolve_and_update_bg()  — fire-and-forget; asyncio event loop'u bloklamaz
"""
import concurrent.futures
import logging
import socket
import time
from typing import Optional

logger = logging.getLogger(__name__)

_TTL_HIT  = 300.0
_TTL_MISS =  60.0
_TIMEOUT  =   1.0

_cache: dict[str, tuple[Optional[str], float]] = {}
_executor    = concurrent.futures.ThreadPoolExecutor(max_workers=4, thread_name_prefix="dns")
_bg_executor = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="dns-bg")


def resolve_hostname(ip: str) -> Optional[str]:
    """
    IP adresini PTR kaydıyla hostname'e çevirir.
    Başarısız veya zaman aşımında None döner (IP gösterilmeye devam eder).
    """
    if not ip:
        return None

    now = time.monotonic()
    cached = _cache.get(ip)
    if cached is not None:
        hostname, expiry = cached
        if now < expiry:
            return hostname

    try:
        future = _executor.submit(socket.gethostbyaddr, ip)
        hostname, _, _ = future.result(timeout=_TIMEOUT)
        _cache[ip] = (hostname, now + _TTL_HIT)
        return hostname
    except concurrent.futures.TimeoutError:
        logger.debug("DNS timeout: %s", ip)
        _cache[ip] = (None, now + _TTL_MISS)
        return None
    except (socket.herror, socket.gaierror, OSError):
        _cache[ip] = (None, now + _TTL_MISS)
        return None


def _resolve_and_update(log_id: str, source_ip: Optional[str], dest_ip: Optional[str]) -> None:
    """Arka plan thread'inde DNS çöz, DB'yi güncelle."""
    src_host = resolve_hostname(source_ip) if source_ip else None
    dst_host = resolve_hostname(dest_ip)   if dest_ip   else None
    if src_host is not None or dst_host is not None:
        try:
            from server.database import db
            db.update_log_hostnames(log_id, src_host, dst_host)
        except Exception as exc:
            logger.debug("DNS hostname güncelleme hatası [%s]: %s", log_id, exc)


def resolve_and_update_bg(log_id: str, source_ip: Optional[str], dest_ip: Optional[str]) -> None:
    """
    Fire-and-forget: asyncio event loop'unu bloklamaz.
    Logyu DB'ye kaydettikten SONRA çağır (log_id gerekli).
    """
    if not source_ip and not dest_ip:
        return
    _bg_executor.submit(_resolve_and_update, log_id, source_ip, dest_ip)


def clear_cache() -> None:
    """Test yardımcısı — cache'i temizler."""
    _cache.clear()
