"""
NetGuard — Zeek JSON log collector.

Zeek'in ürettiği JSON loglarını izler, NormalizedLog'a çevirir ve
normalized_logs tablosuna yazar. Her log dosyası için byte offset saklanır
(restart güvenli — aynı satırı iki kez işlemez).

Desteklenen log türleri: dns, http, conn, ssl, ssh, notice, x509, smtp, ftp,
                         weird, dpd, files, rdp, kerberos, smb_files, dce_rpc
"""

import asyncio
import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Callable, Optional

from server.file_watch import DebouncedDirectoryWatcher
from server.log_store import log_store
from server.parsers.zeek import (
    parse_conn, parse_dns, parse_ftp, parse_http,
    parse_notice, parse_smtp, parse_ssh, parse_ssl, parse_x509,
    parse_weird, parse_dpd, parse_files,
    parse_rdp, parse_kerberos, parse_smb_files, parse_dce_rpc,
)

logger = logging.getLogger(__name__)

ZEEK_LOG_DIR    = Path(os.getenv("ZEEK_LOG_DIR", "/zeek-logs"))
POLL_INTERVAL   = int(os.getenv("ZEEK_POLL_INTERVAL", "5"))
TENANT_ID       = "default"
ZEEK_OFFSET_FILE = Path(os.getenv("ZEEK_OFFSET_FILE", "/tmp/netguard_zeek_offsets.json"))

_PARSERS: dict[str, Callable] = {
    "dns":    parse_dns,
    "http":   parse_http,
    "conn":   parse_conn,
    "ssl":    parse_ssl,
    "ssh":    parse_ssh,
    "notice": parse_notice,
    "x509":   parse_x509,
    "smtp":   parse_smtp,
    "ftp":    parse_ftp,
    "weird":     parse_weird,
    "dpd":       parse_dpd,
    "files":     parse_files,
    "rdp":       parse_rdp,
    "kerberos":  parse_kerberos,
    "smb_files": parse_smb_files,
    "dce_rpc":   parse_dce_rpc,
}


def _load_offsets() -> dict[str, dict[str, int]]:
    """
    Disk'teki offset dosyasını oku — Filebeat registry pattern (offset + inode).

    Eski format ({"path": offset_int}) ile geriye uyumlu: bulunca {"offset": N, "inode": 0}
    şeklinde yükseltilir — inode 0 olduğu için ilk taramada inode senkronize edilir,
    veri kaybı olmaz (sadece bir kerelik gereksiz inode güncelleme).
    """
    try:
        if ZEEK_OFFSET_FILE.exists():
            raw = json.loads(ZEEK_OFFSET_FILE.read_text(encoding="utf-8"))
            upgraded = {}
            for path, entry in raw.items():
                if isinstance(entry, dict):
                    upgraded[path] = {"offset": int(entry.get("offset", 0)), "inode": int(entry.get("inode", 0))}
                else:
                    upgraded[path] = {"offset": int(entry), "inode": 0}
            return upgraded
    except Exception as exc:
        logger.warning("Zeek offset dosyası okunamadı: %s", exc)
    return {}


def _save_offsets() -> None:
    """Offset'leri atomik write ile sakla (tempfile + os.replace) — Suricata collector ile tutarlı."""
    try:
        ZEEK_OFFSET_FILE.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(_offsets)
        fd, tmp_path = tempfile.mkstemp(
            dir=ZEEK_OFFSET_FILE.parent, prefix=".zeek_offsets_", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(content)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_path, ZEEK_OFFSET_FILE)
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
    except Exception as exc:
        logger.warning("Zeek offset kaydedilemedi: %s", exc)


_offsets: dict[str, dict[str, int]] = _load_offsets()


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
    entry = _offsets.get(key, {"offset": 0, "inode": 0})
    offset = entry["offset"]
    inode = entry["inode"]

    try:
        stat = log_file.stat()
        size = stat.st_size
        cur_inode = stat.st_ino
    except OSError:
        return 0

    # Log rotation: inode değiştiyse (logrotate/Zeek archive_log) veya dosya küçüldüyse sıfırla
    if cur_inode != inode or size < offset:
        if inode:
            logger.info(
                "Zeek log döndü [%s] (inode %d→%d) — offset sıfırlandı",
                log_file.name, inode, cur_inode,
            )
        offset = 0
        inode = cur_inode

    if size == offset:
        _offsets[key] = {"offset": offset, "inode": inode}
        return 0

    written = 0
    start_offset = offset
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
                    log_store.save(log_entry)
                    written += 1
                except Exception as exc:
                    logger.error("Zeek log kaydedilemedi: %s", exc)
                    # At-least-once: bu satır bir sonraki taramada tekrar denensin
                    offset -= len(raw_line)
                    break
    except OSError as exc:
        logger.error("Zeek log okunamadı [%s]: %s", log_file.name, exc)
        offset = start_offset

    _offsets[key] = {"offset": offset, "inode": inode}
    _save_offsets()
    if written:
        logger.debug("Zeek [%s]: %d satır yazıldı", log_file.name, written)
    return written


_LOG_RETENTION_DAYS = int(os.getenv("ZEEK_LOG_RETENTION_DAYS", "7"))
_CLEANUP_INTERVAL   = 3600  # saatte bir eski dosya taraması


def cleanup_old_logs() -> int:
    """
    ZEEK_LOG_DIR içindeki rotation sonrası tarihli log dosyalarını
    _LOG_RETENTION_DAYS günden eski olanları siler.
    Döner: silinen dosya sayısı.
    """
    if not ZEEK_LOG_DIR.exists():
        return 0
    cutoff = time.time() - _LOG_RETENTION_DAYS * 86400
    deleted = 0
    for f in ZEEK_LOG_DIR.iterdir():
        # Tarihli rotation dosyaları: dns.2024-01-01-00.00.00.log biçiminde
        if f.is_file() and f.suffix == ".log" and "." in f.stem:
            try:
                if f.stat().st_mtime < cutoff:
                    f.unlink()
                    deleted += 1
                    logger.info("Eski Zeek log silindi: %s", f.name)
            except OSError:
                pass
    return deleted


async def run_zeek_collector() -> None:
    """
    asyncio task — Zeek log izleme döngüsü.

    inotify (watchdog) dosya değişiminde anında tetikler; POLL_INTERVAL
    saniyede bir de zaten çalışır (fallback — dizin henüz yoksa, inotify
    desteklenmeyen dosya sisteminde veya event kaçırılırsa veri kaybı olmaz).
    """
    logger.info(
        "Zeek log collector başlatıldı (dizin: %s, poll: %ss, retention: %dd)",
        ZEEK_LOG_DIR, POLL_INTERVAL, _LOG_RETENTION_DAYS,
    )
    loop = asyncio.get_running_loop()
    trigger = asyncio.Event()
    watcher = DebouncedDirectoryWatcher(ZEEK_LOG_DIR, trigger.set, loop)
    watcher.start()

    last_cleanup = 0.0
    try:
        while True:
            try:
                collect_once()
            except Exception as exc:
                logger.error("Zeek collector hatası: %s", exc)
            now = time.time()
            if now - last_cleanup > _CLEANUP_INTERVAL:
                try:
                    cleanup_old_logs()
                except Exception as exc:
                    logger.error("Zeek cleanup hatası: %s", exc)
                last_cleanup = now
            trigger.clear()
            try:
                await asyncio.wait_for(trigger.wait(), timeout=POLL_INTERVAL)
            except asyncio.TimeoutError:
                pass
    finally:
        watcher.stop()
