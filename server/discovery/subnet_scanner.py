"""
NetGuard — Subnet Scanner

Bir CIDR bloğunu asyncio ile paralel tarar.
Her aktif IP için fingerprinter'a geçilir.
"""

import asyncio
import logging
from ipaddress import ip_network, IPv4Network
from typing import AsyncIterator

from server.uptime_checker import ping

logger = logging.getLogger(__name__)

_MAX_CONCURRENT = 50   # aynı anda max ping sayısı
_PING_TIMEOUT   = 1.5  # saniye — tarama hızı için kısa


async def _probe_ip(sem: asyncio.Semaphore, ip: str) -> dict | None:
    """Tek IP'yi ping ile dener. Aktifse dict döner, değilse None."""
    async with sem:
        result = await ping(ip, count=1, timeout=_PING_TIMEOUT)
        if result["reachable"]:
            return {"ip": ip, "rtt_ms": result["rtt_ms"]}
        return None


async def sweep(cidr: str) -> list[dict]:
    """
    CIDR bloğundaki tüm host IP'lerini tarar.
    Döndürür: [{"ip": "...", "rtt_ms": ...}, ...]
    """
    try:
        network: IPv4Network = ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"Geçersiz CIDR: {cidr}") from exc

    hosts = list(network.hosts())
    if not hosts:
        return []

    logger.info(f"Subnet tarama başladı: {cidr} ({len(hosts)} host)")
    sem = asyncio.Semaphore(_MAX_CONCURRENT)
    tasks = [_probe_ip(sem, str(ip)) for ip in hosts]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    active = [r for r in results if isinstance(r, dict)]
    logger.info(f"Subnet tarama bitti: {cidr} → {len(active)}/{len(hosts)} aktif host")
    return active


async def sweep_iter(cidr: str, batch_size: int = 50) -> AsyncIterator[dict]:
    """
    CIDR bloğunu toplu tarar, her aktif IP'yi hemen yield eder.
    Büyük subnetler için bellek dostu alternatif.
    """
    try:
        network: IPv4Network = ip_network(cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"Geçersiz CIDR: {cidr}") from exc

    hosts = list(network.hosts())
    sem = asyncio.Semaphore(_MAX_CONCURRENT)

    for i in range(0, len(hosts), batch_size):
        batch = hosts[i:i + batch_size]
        tasks = [_probe_ip(sem, str(ip)) for ip in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, dict):
                yield r
