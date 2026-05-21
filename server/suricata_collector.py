"""
NetGuard — Suricata EVE JSON log collector.

Suricata'nın ürettiği EVE JSON loglarını izler, NormalizedLog'a çevirir ve
normalized_logs tablosuna yazar. Byte offset saklanır (restart güvenli).

EVE JSON kaynak: /var/log/suricata/eve.json (varsayılan, SURICATA_EVE_LOG ile override)
"""

import asyncio
import json
import logging
import os
import time
from pathlib import Path

from server.log_store import log_store
from server.parsers.suricata import parse_eve_line

logger = logging.getLogger(__name__)

SURICATA_EVE_LOG  = Path(os.getenv("SURICATA_EVE_LOG", "/var/log/suricata/eve.json"))
POLL_INTERVAL     = int(os.getenv("SURICATA_POLL_INTERVAL", "5"))
_OFFSET_FILE      = Path(os.getenv("SURICATA_OFFSET_FILE", "/tmp/netguard_suricata_offset.json"))
_LOG_RETENTION_DAYS = int(os.getenv("SURICATA_LOG_RETENTION_DAYS", "7"))
_CLEANUP_INTERVAL   = 3600


def _load_state() -> tuple[int, int]:
    """Offset ve inode'u diskten oku. Döner: (offset, inode)."""
    try:
        if _OFFSET_FILE.exists():
            data = json.loads(_OFFSET_FILE.read_text(encoding="utf-8"))
            entry = data.get(str(SURICATA_EVE_LOG), {})
            if isinstance(entry, dict):
                return int(entry.get("offset", 0)), int(entry.get("inode", 0))
            # Eski format: sadece offset sayısı
            return int(entry), 0
    except Exception as exc:
        logger.warning("Suricata offset okunamadı: %s", exc)
    return 0, 0


def _save_offset(offset: int, inode: int) -> None:
    try:
        _OFFSET_FILE.write_text(
            json.dumps({str(SURICATA_EVE_LOG): {"offset": offset, "inode": inode}}),
            encoding="utf-8",
        )
    except Exception as exc:
        logger.warning("Suricata offset kaydedilemedi: %s", exc)


_offset: int
_inode: int
_offset, _inode = _load_state()


def collect_once() -> int:
    """
    EVE JSON dosyasını yeni satırlar için tara.
    Döner: normalize edilip kaydedilen satır sayısı.
    """
    global _offset, _inode

    if not SURICATA_EVE_LOG.exists():
        return 0

    try:
        stat = SURICATA_EVE_LOG.stat()
        size     = stat.st_size
        cur_inode = stat.st_ino
    except OSError:
        return 0

    # Log rotation: inode değiştiyse (SIGHUP + rename) veya dosya küçüldüyse sıfırla
    if cur_inode != _inode or size < _offset:
        logger.info("Suricata EVE log döndü (inode %d→%d) — offset sıfırlandı", _inode, cur_inode)
        _offset = 0
        _inode  = cur_inode

    if size == _offset:
        return 0

    written = 0
    try:
        with SURICATA_EVE_LOG.open("rb") as fh:
            fh.seek(_offset)
            for raw_line in fh:
                _offset += len(raw_line)
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "event_type" not in row or "timestamp" not in row:
                    continue
                log_entry = parse_eve_line(row)
                if log_entry is None:
                    continue
                try:
                    log_store.save(log_entry)
                    written += 1
                except Exception as exc:
                    logger.error("Suricata log kaydedilemedi: %s", exc)
    except OSError as exc:
        logger.error("Suricata EVE log okunamadı: %s", exc)
        return written

    _save_offset(_offset, _inode)
    if written:
        logger.debug("Suricata: %d satır yazıldı", written)
    return written


def cleanup_old_logs() -> int:
    """
    SURICATA_EVE_LOG ile aynı dizindeki rotation dosyalarını
    _LOG_RETENTION_DAYS günden eski olanları siler.
    """
    log_dir = SURICATA_EVE_LOG.parent
    if not log_dir.exists():
        return 0
    cutoff  = time.time() - _LOG_RETENTION_DAYS * 86400
    deleted = 0
    eve_stem = SURICATA_EVE_LOG.stem  # "eve"
    for f in log_dir.iterdir():
        # Yalnızca eve.json'dan rotation dosyalarını sil (ör. eve.1.json, eve.2024-01-01.json)
        # stats.log, fast.log gibi sibling log dosyalarına dokunma
        is_rotation = (
            f.is_file()
            and f.name != SURICATA_EVE_LOG.name
            and f.name.startswith(eve_stem + ".")
        )
        if not is_rotation:
            continue
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
                deleted += 1
                logger.info("Eski Suricata log silindi: %s", f.name)
        except OSError:
            pass
    return deleted


async def run_suricata_collector() -> None:
    """asyncio task — Suricata EVE JSON poll döngüsü."""
    logger.info(
        "Suricata EVE collector başlatıldı (dosya: %s, poll: %ss, retention: %dd)",
        SURICATA_EVE_LOG, POLL_INTERVAL, _LOG_RETENTION_DAYS,
    )
    last_cleanup = 0.0
    while True:
        try:
            collect_once()
        except Exception as exc:
            logger.error("Suricata collector hatası: %s", exc)
        now = time.time()
        if now - last_cleanup > _CLEANUP_INTERVAL:
            try:
                cleanup_old_logs()
            except Exception as exc:
                logger.error("Suricata cleanup hatası: %s", exc)
            last_cleanup = now
        await asyncio.sleep(POLL_INTERVAL)
