"""
NetGuard — Multi-Stage Attack Chain Detector

Standart SIEM ürünlerinin yaptığının ötesine geçer: tek bir eşik kuralı
tetiklemek yerine, aynı kaynaktan gelen FARKLI saldırı aşamalarını zamanla
takip eder ve bir kill chain örüntüsü tespit ettiğinde yüksek öncelikli
alert üretir.

Kill Chain Aşamaları (Lockheed Martin / MITRE ATT&CK):
  RECON       → port_scan, dns_anomaly            (Keşif)
  WEAPONIZE   → windows_brute_force, ssh_failure  (Silahlanma / Erişim Denemeleri)
  ACCESS      → ssh_success, windows_logon_success (İlk Erişim)
  EXECUTE     → windows_process_create, sudo_abuse (Komut Çalıştırma)
  LATERAL     → lateral_movement, windows_lateral  (Yanal Hareket)

Tetikleme:
  2 farklı aşama / 30 dakika → PARTIAL_ATTACK_CHAIN (warning)
  3+ farklı aşama / 30 dakika → FULL_ATTACK_CHAIN (critical)

Her IP için aşama kaydı bellekte tutulur; 30 dakika geçmişe düşen
kayıtlar otomatik temizlenir.
"""

import logging
import threading
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Optional

logger = logging.getLogger(__name__)

CHAIN_WINDOW_SEC = 1800   # 30 dakika
PARTIAL_THRESHOLD = 2     # uyarı eşiği
FULL_THRESHOLD    = 3     # kritik eşiği

STAGE_MAP: dict[str, str] = {
    # event_type prefix → stage adı
    # Raw log event types
    "port_scan":                 "recon",
    "dns_anomaly":               "recon",
    "ssh_failure":               "weaponize",
    "windows_logon_failure":     "weaponize",
    "windows_brute_force":       "weaponize",
    "brute_force":               "weaponize",
    "ssh_success":               "access",
    "windows_logon_success":     "access",
    "windows_lateral_movement":  "access",
    "windows_process_create":    "execute",
    "sudo_abuse":                "execute",
    "lateral_movement":          "lateral",
    "windows_lateral":           "lateral",
    # Correlated event output types (sigma rule output)
    "ssh_brute_force":           "weaponize",
    "windows_pass_the_hash":     "weaponize",
    "port_scan_detected":        "recon",
    "arp_attack":                "recon",
    "ssh_lateral":               "lateral",
}

STAGE_LABELS = {
    "recon":      "Keşif",
    "weaponize":  "Erişim Denemeleri",
    "access":     "İlk Erişim",
    "execute":    "Komut Çalıştırma",
    "lateral":    "Yanal Hareket",
}


def _resolve_stage(event_type: str) -> Optional[str]:
    for prefix, stage in STAGE_MAP.items():
        if event_type.startswith(prefix):
            return stage
    return None


class AttackChainTracker:
    """
    Thread-safe. Her src_ip için aşama → zaman damgaları listesi tutar.
    Periyodik temizlik için _purge() çağrısı dahilidir.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # {src_ip: {stage: [datetime, ...]}}
        self._chains: dict[str, dict[str, list[datetime]]] = defaultdict(lambda: defaultdict(list))

    def record(self, src_ip: str, event_type: str, occurred_at: Optional[datetime] = None) -> Optional[dict]:
        """
        Yeni bir event kaydeder. Zincir tamamlanmışsa tetikleme dict'i döner,
        aksi hâlde None döner.

        Dönüş örneği:
          {
            "chain_type": "FULL_ATTACK_CHAIN",
            "severity":   "critical",
            "src_ip":     "10.0.0.5",
            "stages":     ["recon", "weaponize", "access"],
            "stage_labels": ["Keşif", "Erişim Denemeleri", "İlk Erişim"],
            "message":    "...",
            "event_type": "full_attack_chain_detected",
          }
        """
        if not src_ip or src_ip in ("-", "None", "none"):
            return None

        stage = _resolve_stage(event_type)
        if not stage:
            return None

        now = occurred_at or datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=CHAIN_WINDOW_SEC)

        with self._lock:
            bucket = self._chains[src_ip]
            bucket[stage].append(now)

            # Pencere dışı kayıtları temizle
            for s in list(bucket.keys()):
                bucket[s] = [t for t in bucket[s] if t >= cutoff]
                if not bucket[s]:
                    del bucket[s]

            active_stages = list(bucket.keys())
            stage_count = len(active_stages)

            if stage_count >= FULL_THRESHOLD:
                return self._build_trigger(src_ip, active_stages, "FULL_ATTACK_CHAIN", "critical")
            if stage_count >= PARTIAL_THRESHOLD:
                return self._build_trigger(src_ip, active_stages, "PARTIAL_ATTACK_CHAIN", "warning")

        return None

    def _build_trigger(self, src_ip: str, stages: list[str], chain_type: str, severity: str) -> dict:
        labels = [STAGE_LABELS.get(s, s) for s in stages]
        chain_str = " → ".join(labels)
        level = "TAM" if chain_type == "FULL_ATTACK_CHAIN" else "KISMİ"
        return {
            "chain_type":   chain_type,
            "severity":     severity,
            "src_ip":       src_ip,
            "stages":       stages,
            "stage_labels": labels,
            "event_type":   chain_type.lower() + "_detected",
            "message":      (
                f"{level} SALDIRI ZİNCİRİ — {src_ip}: "
                f"{chain_str} "
                f"({len(stages)} aşama / {CHAIN_WINDOW_SEC // 60} dakika)"
            ),
        }

    def get_chains(self) -> dict:
        """Aktif zincirlerin anlık görüntüsü (UI / API için)."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=CHAIN_WINDOW_SEC)
        result = {}
        with self._lock:
            for ip, bucket in self._chains.items():
                active = {s: len([t for t in ts if t >= cutoff])
                          for s, ts in bucket.items()
                          if any(t >= cutoff for t in ts)}
                if active:
                    result[ip] = active
        return result

    def purge(self) -> None:
        """Süresi geçmiş kayıtları temizler. Periyodik çağrılabilir."""
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=CHAIN_WINDOW_SEC)
        with self._lock:
            for ip in list(self._chains.keys()):
                bucket = self._chains[ip]
                for s in list(bucket.keys()):
                    bucket[s] = [t for t in bucket[s] if t >= cutoff]
                    if not bucket[s]:
                        del bucket[s]
                if not bucket:
                    del self._chains[ip]


def chain_trigger_to_correlated_event(trigger: dict, db_save: bool = True):
    """
    AttackChainTracker'dan gelen tetikleme dict'ini CorrelatedEvent'e dönüştürür
    ve isteğe bağlı olarak DB'ye kaydeder.
    """
    from shared.models import CorrelatedEvent
    now = datetime.now(timezone.utc)
    event = CorrelatedEvent(
        corr_id        = str(uuid.uuid4()),
        rule_id        = trigger["chain_type"].lower(),
        rule_name      = trigger["chain_type"].replace("_", " ").title(),
        event_type     = trigger["event_type"],
        severity       = trigger["severity"],
        group_value    = trigger["src_ip"],
        matched_count  = len(trigger["stages"]),
        window_seconds = CHAIN_WINDOW_SEC,
        first_seen     = now,
        last_seen      = now,
        message        = trigger["message"],
    )
    if db_save:
        try:
            from server.database import db
            db.save_correlated_event(event)
        except Exception as exc:
            logger.warning(f"Attack chain event kaydedilemedi: {exc}")
    return event


# Global singleton
attack_chain_tracker = AttackChainTracker()
