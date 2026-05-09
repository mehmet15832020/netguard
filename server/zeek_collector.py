"""
NetGuard — Zeek JSON log collector.

Zeek'in ürettiği JSON loglarını izler, NormalizedLog'a çevirir ve
normalized_logs tablosuna yazar. Her log dosyası için byte offset saklanır
(restart güvenli — aynı satırı iki kez işlemez).

Desteklenen log türleri: dns, http, conn, ssl
"""

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Callable, Optional

from server.database import db
from server.parsers.zeek import parse_conn, parse_dns, parse_http, parse_ssl

logger = logging.getLogger(__name__)

ZEEK_LOG_DIR   = Path(os.getenv("ZEEK_LOG_DIR", "/zeek-logs"))
POLL_INTERVAL  = int(os.getenv("ZEEK_POLL_INTERVAL", "5"))
TENANT_ID      = "default"

_PARSERS: dict[str, Callable] = {
    "dns":  parse_dns,
    "http": parse_http,
    "conn": parse_conn,
    "ssl":  parse_ssl,
}

_offsets: dict[str, int] = {}


def _find_log_file(log_type: str) -> Optional[Path]:
    """
    Zeek log dosyasını birden fazla olası konumda arar.
    Zeek sürümüne göre logs/current/ altında veya doğrudan ZEEK_LOG_DIR içinde
    olabilir.
    """
    candidates = [
        ZEEK_LOG_DIR / f"{log_type}.log",
        ZEEK_LOG_DIR / "logs" / "current" / f"{log_type}.log",
        ZEEK_LOG_DIR / "current" / f"{log_type}.log",
    ]
    for p in candidates:
        if p.exists():
            return p
    return None


def collect_once() -> int:
    """
    Tüm aktif Zeek log dosyalarını tara.
    Döner: normalize edilip kaydedilen satır sayısı.
    """
    if not ZEEK_LOG_DIR.exists():
        return 0

    total = 0
    for log_type, parser in _PARSERS.items():
        log_file = _find_log_file(log_type)
        if log_file is None:
            continue
        total += _process_file(log_file, parser)
    return total


def _process_file(log_file: Path, parser: Callable) -> int:
    key = str(log_file.resolve())
    offset = _offsets.get(key, 0)

    try:
        size = log_file.stat().st_size
    except OSError:
        return 0

    if size < offset:
        offset = 0

    if size == offset:
        return 0

    written = 0
    try:
        with log_file.open("rb") as fh:
            fh.seek(offset)
            for raw_line in fh:
                offset += len(raw_line)
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "ts" not in row:
                    continue
                try:
                    log_entry = parser(row)
                except Exception as exc:
                    logger.debug("Zeek satır parse hatası: %s", exc)
                    continue
                if log_entry is None:
                    continue
                try:
                    db.save_normalized_log(log_entry, tenant_id=TENANT_ID)
                    written += 1
                except Exception as exc:
                    logger.error("Zeek log kaydedilemedi: %s", exc)
    except OSError as exc:
        logger.error("Zeek log okunamadı [%s]: %s", log_file.name, exc)
        return written

    _offsets[key] = offset
    if written:
        logger.debug("Zeek [%s]: %d satır yazıldı", log_file.name, written)
    return written


async def run_zeek_collector() -> None:
    """asyncio task — Zeek log poll döngüsü."""
    logger.info(
        "Zeek log collector başlatıldı (dizin: %s, poll: %ss)",
        ZEEK_LOG_DIR, POLL_INTERVAL,
    )
    while True:
        try:
            collect_once()
        except Exception as exc:
            logger.error("Zeek collector hatası: %s", exc)
        await asyncio.sleep(POLL_INTERVAL)
