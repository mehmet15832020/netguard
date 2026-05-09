"""
NetGuard — V1-6: False Positive Manager

Korelasyon çıktılarını, CIDR destekli suppression kurallarına göre filtreler.
Eşleşen event'ler için incident/alert üretilmez; normalized_logs kaydı korunur.

Kural önbelleği 5 dakikada bir yenilenir (DB'den tekrar okur).
"""

import ipaddress
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

_CACHE_TTL = 300  # saniye


def _ip_matches(ip: Optional[str], pattern: Optional[str]) -> bool:
    """IP'nin CIDR pattern'ine girip girmediğini kontrol eder. pattern=None → her IP eşleşir."""
    if not pattern:
        return True
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(pattern, strict=False)
    except ValueError:
        return ip == pattern


def _rule_matches(
    rule: dict,
    event_action: str,
    source_ip: Optional[str],
    destination_ip: Optional[str] = None,
    destination_port: Optional[str] = None,
    observer_hostname: Optional[str] = None,
) -> bool:
    """Tek bir FP kuralının verilen olaya uyup uymadığını döner."""
    if not rule.get("is_active"):
        return False
    expires_at = rule.get("expires_at")
    if expires_at and expires_at < datetime.now(timezone.utc).isoformat():
        return False
    if rule.get("event_action") and rule["event_action"] != event_action:
        return False
    if not _ip_matches(source_ip, rule.get("source_ip")):
        return False
    if rule.get("destination_ip") and destination_ip != rule["destination_ip"]:
        return False
    if rule.get("destination_port") and str(destination_port or "") != rule["destination_port"]:
        return False
    if rule.get("observer_hostname") and observer_hostname != rule["observer_hostname"]:
        return False
    return True


class FPManager:
    """Thread-safe FP kural önbelleği ve eşleşme motoru."""

    def __init__(self) -> None:
        self._rules: list[dict] = []
        self._last_loaded: float = 0.0
        self._lock = threading.Lock()

    def _refresh_if_stale(self, tenant_id: str = "default") -> None:
        if time.monotonic() - self._last_loaded > _CACHE_TTL:
            with self._lock:
                if time.monotonic() - self._last_loaded > _CACHE_TTL:
                    from server.database import db
                    self._rules = db.get_active_fp_rules(tenant_id)
                    self._last_loaded = time.monotonic()
                    logger.debug("FP kuralları yenilendi: %d kural", len(self._rules))

    def is_suppressed(
        self,
        event_action: str,
        source_ip: Optional[str],
        destination_ip: Optional[str] = None,
        destination_port: Optional[str] = None,
        observer_hostname: Optional[str] = None,
        tenant_id: str = "default",
    ) -> Optional[str]:
        """Eşleşen kural varsa fp_rule_id döner, yoksa None döner."""
        self._refresh_if_stale(tenant_id)
        for rule in self._rules:
            if _rule_matches(rule, event_action, source_ip, destination_ip,
                             destination_port, observer_hostname):
                return rule["fp_rule_id"]
        return None

    def invalidate(self) -> None:
        """Kural eklenince/silinince çağrılır; önbelleği temizler."""
        self._last_loaded = 0.0


fp_manager = FPManager()
