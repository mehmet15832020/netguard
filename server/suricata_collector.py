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
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from server.file_watch import DebouncedDirectoryWatcher
from server.log_store import log_store
from server.parsers.suricata import parse_eve_line
from shared.models import CorrelatedEvent

logger = logging.getLogger(__name__)

SURICATA_EVE_LOG  = Path(os.getenv("SURICATA_EVE_LOG", "/var/log/suricata/eve.json"))
POLL_INTERVAL     = int(os.getenv("SURICATA_POLL_INTERVAL", "5"))
_OFFSET_FILE      = Path(os.getenv("SURICATA_OFFSET_FILE", "/var/lib/netguard/suricata_offset.json"))
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
    """Offset'i atomik write ile sakla (tempfile + os.replace)."""
    try:
        _OFFSET_FILE.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps({str(SURICATA_EVE_LOG): {"offset": offset, "inode": inode}})
        fd, tmp_path = tempfile.mkstemp(
            dir=_OFFSET_FILE.parent, prefix=".suricata_offset_", suffix=".tmp"
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
        logger.warning("Suricata offset kaydedilemedi: %s", exc)


_offset: int
_inode: int
_offset, _inode = _load_state()

_REALTIME_IDS_ALERT = os.getenv("SURICATA_REALTIME_ALERT", "1") == "1"

# Modül düzeyinde import — patch edilebilmesi için (test)
from server.database import db


def _dispatch_ids_alert(row: dict, log_entry) -> None:
    """
    O1 — Suricata IDS alert'leri için gerçek zamanlı CorrelatedEvent üret.
    60s korelasyon döngüsünü bypass eder.
    NIST SP 800-94 §4.3.1: single-event high/critical must be real-time.
    """
    if not _REALTIME_IDS_ALERT:
        return
    if log_entry.severity not in ("critical", "high"):
        return
    try:
        alert_obj = row.get("alert", {})
        sig = alert_obj.get("signature", "Suricata IDS Alert")
        sid = str(alert_obj.get("signature_id", ""))
        mitre = alert_obj.get("metadata", {}).get("attack_target", [])
        ts = log_entry.timestamp or datetime.now(timezone.utc)
        src_ip = log_entry.source_ip or "unknown"

        event = CorrelatedEvent(
            corr_id=str(uuid.uuid4()),
            rule_id=f"suricata_ids_{sid}" if sid else "suricata_ids_realtime",
            rule_name=sig,
            event_action="suricata_ids_alert_detected",
            severity=log_entry.severity,
            group_value=src_ip,
            group_by_field="source_ip",
            matched_count=1,
            window_seconds=0,
            first_seen=ts,
            last_seen=ts,
            message=log_entry.message or sig,
            mitre_techniques=mitre if isinstance(mitre, list) else [],
        )
        saved = db.save_correlated_event(event)
        if saved:
            logger.info(
                "O1 realtime IDS alert: sid=%s src=%s sev=%s",
                sid, src_ip, log_entry.severity,
            )
            from server.attack_chain import attack_chain_tracker
            attack_chain_tracker.record(event)
    except Exception as exc:
        logger.warning("O1 realtime IDS alert gönderilemedi: %s", exc)


def collect_once() -> int:
    """
    EVE JSON dosyasını yeni satırlar için tara.
    Döner: normalize edilip kaydedilen satır sayısı.

    Bu fonksiyon senkron / blocking I/O içerir.
    asyncio bağlamında asyncio.to_thread() ile çağrılmalıdır.
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
    start_offset = _offset
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
                    # At-least-once: rollback offset so this line is retried
                    _offset -= len(raw_line)
                    break
                # O1 — Suricata IDS alert: 60s döngüyü bypass eden gerçek zamanlı alert
                # NIST SP 800-94 §4.3.1: single-event high/critical alerts must be real-time
                if row.get("event_type") == "alert" and log_entry.severity in ("critical", "high"):
                    _dispatch_ids_alert(row, log_entry)
    except OSError as exc:
        logger.error("Suricata EVE log okunamadı: %s", exc)
        _offset = start_offset
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
    """
    asyncio task — Suricata EVE JSON izleme döngüsü.

    inotify (watchdog) dosya değişiminde anında tetikler; POLL_INTERVAL
    saniyede bir de zaten çalışır (fallback — dizin henüz yoksa, inotify
    desteklenmeyen dosya sisteminde veya event kaçırılırsa veri kaybı olmaz).
    """
    logger.info(
        "Suricata EVE collector başlatıldı (dosya: %s, poll: %ss, retention: %dd)",
        SURICATA_EVE_LOG, POLL_INTERVAL, _LOG_RETENTION_DAYS,
    )
    loop = asyncio.get_running_loop()
    trigger = asyncio.Event()
    watcher = DebouncedDirectoryWatcher(
        SURICATA_EVE_LOG.parent, trigger.set, loop, watch_file=SURICATA_EVE_LOG,
    )
    watcher.start()

    last_cleanup = 0.0
    try:
        while True:
            try:
                await asyncio.to_thread(collect_once)
            except Exception as exc:
                logger.error("Suricata collector hatası: %s", exc)
            now = time.time()
            if now - last_cleanup > _CLEANUP_INTERVAL:
                try:
                    await asyncio.to_thread(cleanup_old_logs)
                except Exception as exc:
                    logger.error("Suricata cleanup hatası: %s", exc)
                last_cleanup = now
            trigger.clear()
            try:
                await asyncio.wait_for(trigger.wait(), timeout=POLL_INTERVAL)
            except asyncio.TimeoutError:
                pass
    finally:
        watcher.stop()
