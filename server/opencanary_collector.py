"""
NetGuard — OpenCanary honeypot JSON log collector.

OpenCanary'nin ürettiği JSON loglarını izler, NormalizedLog'a çevirir ve
normalized_logs tablosuna yazar. Byte offset + inode saklanır (restart güvenli).

Log dosyası: /var/log/opencanary/opencanary.log (OPENCANARY_LOG_FILE env ile override)
"""

import asyncio
import json
import logging
import os
import tempfile
import time
from pathlib import Path

from server.log_store import log_store
from server.parsers.opencanary import parse_opencanary_line

logger = logging.getLogger(__name__)

OPENCANARY_LOG_FILE  = Path(os.getenv("OPENCANARY_LOG_FILE", "/var/log/opencanary/opencanary.log"))
POLL_INTERVAL        = int(os.getenv("OPENCANARY_POLL_INTERVAL", "5"))
_OFFSET_FILE         = Path(os.getenv("OPENCANARY_OFFSET_FILE", "/var/lib/netguard/opencanary_offset.json"))
_LOG_RETENTION_DAYS  = int(os.getenv("OPENCANARY_LOG_RETENTION_DAYS", "7"))
_CLEANUP_INTERVAL    = 3600


def _load_state() -> tuple[int, int]:
    try:
        if _OFFSET_FILE.exists():
            data = json.loads(_OFFSET_FILE.read_text(encoding="utf-8"))
            entry = data.get(str(OPENCANARY_LOG_FILE), {})
            if isinstance(entry, dict):
                return int(entry.get("offset", 0)), int(entry.get("inode", 0))
            return int(entry), 0
    except Exception as exc:
        logger.warning("OpenCanary offset okunamadı: %s", exc)
    return 0, 0


def _save_offset(offset: int, inode: int) -> None:
    try:
        _OFFSET_FILE.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps({str(OPENCANARY_LOG_FILE): {"offset": offset, "inode": inode}})
        fd, tmp_path = tempfile.mkstemp(
            dir=_OFFSET_FILE.parent, prefix=".opencanary_offset_", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, _OFFSET_FILE)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except Exception as exc:
        logger.warning("OpenCanary offset kaydedilemedi: %s", exc)


_offset: int
_inode: int
_offset, _inode = _load_state()


def collect_once() -> int:
    """
    OpenCanary JSON log dosyasını yeni satırlar için tara.
    Döner: normalize edilip kaydedilen satır sayısı.
    """
    global _offset, _inode

    if not OPENCANARY_LOG_FILE.exists():
        return 0

    try:
        stat    = OPENCANARY_LOG_FILE.stat()
        size    = stat.st_size
        cur_inode = stat.st_ino
    except OSError:
        return 0

    if cur_inode != _inode or size < _offset:
        logger.info("OpenCanary log döndü (inode %d→%d) — offset sıfırlandı", _inode, cur_inode)
        _offset = 0
        _inode  = cur_inode

    if size == _offset:
        return 0

    written      = 0
    start_offset = _offset
    try:
        with OPENCANARY_LOG_FILE.open("rb") as fh:
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
                if "logtype" not in row or ("utc_time" not in row and "local_time" not in row):
                    continue
                try:
                    log_entry = parse_opencanary_line(row)
                except Exception as exc:
                    logger.debug("OpenCanary satır parse hatası: %s", exc)
                    continue
                if log_entry is None:
                    continue
                try:
                    log_store.save(log_entry)
                    written += 1
                except Exception as exc:
                    logger.error("OpenCanary log kaydedilemedi: %s", exc)
    except OSError as exc:
        logger.error("OpenCanary log okunamadı: %s", exc)
        _offset = start_offset
        return written

    _save_offset(_offset, _inode)
    if written:
        logger.debug("OpenCanary: %d satır yazıldı", written)
    return written


def cleanup_old_logs() -> int:
    log_dir = OPENCANARY_LOG_FILE.parent
    if not log_dir.exists():
        return 0
    cutoff  = time.time() - _LOG_RETENTION_DAYS * 86400
    deleted = 0
    for f in log_dir.iterdir():
        if not f.is_file() or f.name == OPENCANARY_LOG_FILE.name:
            continue
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
                deleted += 1
                logger.info("Eski OpenCanary log silindi: %s", f.name)
        except OSError:
            pass
    return deleted


async def run_opencanary_collector() -> None:
    """asyncio task — OpenCanary log poll döngüsü."""
    logger.info(
        "OpenCanary collector başlatıldı (dosya: %s, poll: %ss, retention: %dd)",
        OPENCANARY_LOG_FILE, POLL_INTERVAL, _LOG_RETENTION_DAYS,
    )
    last_cleanup = 0.0
    while True:
        try:
            await asyncio.to_thread(collect_once)
        except Exception as exc:
            logger.error("OpenCanary collector hatası: %s", exc)
        now = time.time()
        if now - last_cleanup > _CLEANUP_INTERVAL:
            try:
                await asyncio.to_thread(cleanup_old_logs)
            except Exception as exc:
                logger.error("OpenCanary cleanup hatası: %s", exc)
            last_cleanup = now
        await asyncio.sleep(POLL_INTERVAL)
