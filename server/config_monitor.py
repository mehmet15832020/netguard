"""
NetGuard Server — Konfigürasyon Dosyası Checksum Takibi

Kritik sistem dosyalarının SHA-256 hash'ini periyodik kontrol eder.
Değişiklik tespit edildiğinde güvenlik olayı üretir.

İzlenen dosyalar .env ile genişletilebilir (WATCHED_FILES=... virgülle ayrılmış).
"""

import hashlib
import logging
import os
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from shared.models import SecurityEvent, SecurityEventType
from server.database import db

logger = logging.getLogger(__name__)

# Varsayılan olarak izlenen kritik dosyalar
_DEFAULT_WATCHED = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/hosts",
]


def _load_watched_files() -> list[str]:
    """
    İzlenecek dosyaları yükle.
    WATCHED_FILES env var varsa onu kullan, yoksa default listeyi.
    """
    env_val = os.getenv("WATCHED_FILES", "")
    if env_val.strip():
        return [f.strip() for f in env_val.split(",") if f.strip()]
    return _DEFAULT_WATCHED


def _sha256(path: Path) -> Optional[str]:
    """Dosyanın SHA-256 hash'ini döndür. Erişilemezse None."""
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, FileNotFoundError, OSError):
        return None


class ConfigMonitor:
    """
    Dosya hash'lerini hatırlar, değişince event üretir.
    İlk çalıştırmada baseline alır.
    """

    def __init__(self):
        self._hashes: dict[str, Optional[str]] = {}  # path → hash
        self._files: list[str] = _load_watched_files()

    def check(self, agent_id: str) -> list[SecurityEvent]:
        """
        Tüm izlenen dosyaları kontrol et.
        İlk çağrıda baseline alır, sonrasında değişiklikleri döndürür.
        """
        hostname = socket.gethostname()
        now = datetime.now(timezone.utc)
        events: list[SecurityEvent] = []

        for file_path in self._files:
            path = Path(file_path)
            current_hash = _sha256(path)

            if file_path not in self._hashes:
                # Baseline — ilk ölçüm
                self._hashes[file_path] = current_hash
                if current_hash:
                    logger.debug(f"Checksum baseline: {file_path} → {current_hash[:12]}…")
                else:
                    logger.debug(f"Checksum baseline: {file_path} → erişilemiyor")
                continue

            previous_hash = self._hashes[file_path]

            if current_hash != previous_hash:
                severity = "critical" if file_path in {
                    "/etc/passwd", "/etc/shadow", "/etc/sudoers"
                } else "warning"

                event = SecurityEvent(
                    event_id   = str(uuid.uuid4()),
                    agent_id   = agent_id,
                    hostname   = hostname,
                    event_type = SecurityEventType.CHECKSUM_CHANGED,
                    severity   = severity,
                    message    = f"Kritik dosya değişti: {file_path}",
                    raw_data   = (
                        f"önceki={previous_hash or 'yok'} "
                        f"yeni={current_hash or 'silindi'}"
                    ),
                    occurred_at= now,
                )
                db.save_security_event(event)
                events.append(event)
                logger.warning(f"DOSYA DEĞİŞTİ: {file_path}")
                self._hashes[file_path] = current_hash

        return events

    def reload_file_list(self) -> None:
        """İzlenen dosya listesini env'den yeniden yükle."""
        self._files = _load_watched_files()
        logger.info(f"İzlenen dosyalar güncellendi: {self._files}")


# Global instance
config_monitor = ConfigMonitor()
