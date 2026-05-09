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
    # event_action → stage adı
    # Raw log event types
    "port_scan":                 "recon",
    "dns_anomaly":               "recon",
    "ssh_failure":               "weaponize",
    "windows_logon_failure":     "weaponize",
    "windows_brute_force":       "weaponize",
    "brute_force":               "weaponize",
    "ssh_success":               "access",
    "windows_logon_success":     "access",
    "windows_lateral_movement":  "lateral",   # MITRE ATT&CK: Lateral Movement taktiği (T1550/T1569)
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
    "anomaly_detected":              "recon",
    "asset_anomaly_detected":        "recon",
    "web_scan_detected":             "recon",
    "multi_source_attack_detected":  "recon",
}

# Longest-prefix-first sıralama — belirsiz prefix eşleşmelerinde daha uzun (özgül) prefix kazanır.
# Endüstri standardı: routing table longest-match, Suricata rule priority aynı prensibi kullanır.
_STAGE_MAP_BY_LEN: list[tuple[str, str]] = sorted(
    STAGE_MAP.items(), key=lambda x: len(x[0]), reverse=True
)

STAGE_LABELS = {
    "recon":      "Keşif",
    "weaponize":  "Erişim Denemeleri",
    "access":     "İlk Erişim",
    "execute":    "Komut Çalıştırma",
    "lateral":    "Yanal Hareket",
}


def _resolve_stage(event_action: str) -> Optional[str]:
    # Exact match önce — en kesin eşleşme
    if event_action in STAGE_MAP:
        return STAGE_MAP[event_action]
    # Prefix fallback — raw event_action'lar için (örn. "port_scan_attempt" → "port_scan")
    # Uzun prefix kısa prefix'e göre önceliklidir (longest-match)
    for prefix, stage in _STAGE_MAP_BY_LEN:
        if event_action.startswith(prefix):
            return stage
    return None


class AttackChainTracker:
    """
    Thread-safe. Her source_ip için aşama → zaman damgaları listesi tutar.
    Periyodik temizlik için _purge() çağrısı dahilidir.
    """

    def __init__(self):
        self._lock = threading.Lock()
        # {source_ip: {stage: [datetime, ...]}}
        self._chains: dict[str, dict[str, list[datetime]]] = defaultdict(lambda: defaultdict(list))

    def record(self, source_ip: str, event_action: str, occurred_at: Optional[datetime] = None) -> Optional[dict]:
        """
        Yeni bir event kaydeder. Zincir tamamlanmışsa tetikleme dict'i döner,
        aksi hâlde None döner.

        Dönüş örneği:
          {
            "chain_type": "FULL_ATTACK_CHAIN",
            "severity":   "critical",
            "source_ip":     "10.0.0.5",
            "stages":     ["recon", "weaponize", "access"],
            "stage_labels": ["Keşif", "Erişim Denemeleri", "İlk Erişim"],
            "message":    "...",
            "event_action": "full_attack_chain_detected",
          }
        """
        if not source_ip or source_ip in ("-", "None", "none"):
            return None

        stage = _resolve_stage(event_action)
        if not stage:
            return None

        now = occurred_at or datetime.now(timezone.utc)
        cutoff = now - timedelta(seconds=CHAIN_WINDOW_SEC)

        trigger: Optional[dict] = None

        with self._lock:
            bucket = self._chains[source_ip]
            bucket[stage].append(now)

            # Pencere dışı kayıtları temizle
            for s in list(bucket.keys()):
                bucket[s] = [t for t in bucket[s] if t >= cutoff]
                if not bucket[s]:
                    del bucket[s]

            active_stages = list(bucket.keys())
            stage_count = len(active_stages)

            if stage_count >= FULL_THRESHOLD:
                trigger = self._build_trigger(source_ip, active_stages, "FULL_ATTACK_CHAIN", "critical")
            elif stage_count >= PARTIAL_THRESHOLD:
                trigger = self._build_trigger(source_ip, active_stages, "PARTIAL_ATTACK_CHAIN", "warning")

        # Lock dışında I/O — in-memory state ile tutarlı (lock içinde güncellendi)
        try:
            from server.database import db
            db.save_chain_stage(source_ip, stage, now)
        except Exception as exc:
            logger.debug(f"Chain stage DB kaydedilemedi [{source_ip}/{stage}]: {exc}")

        return trigger

    def _build_trigger(self, source_ip: str, stages: list[str], chain_type: str, severity: str) -> dict:
        labels = [STAGE_LABELS.get(s, s) for s in stages]
        chain_str = " → ".join(labels)
        level = "TAM" if chain_type == "FULL_ATTACK_CHAIN" else "KISMİ"
        return {
            "chain_type":   chain_type,
            "severity":     severity,
            "source_ip":       source_ip,
            "stages":       stages,
            "stage_labels": labels,
            "event_action":   chain_type.lower() + "_detected",
            "message":      (
                f"{level} SALDIRI ZİNCİRİ — {source_ip}: "
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
        try:
            from server.database import db
            db.purge_old_chain_stages(CHAIN_WINDOW_SEC)
        except Exception as exc:
            logger.debug(f"Chain state DB temizlenemedi: {exc}")

    def restore_from_db(self) -> None:
        """Sunucu başlangıcında DB'den aktif chain state'i yükle."""
        try:
            from server.database import db
            stages = db.get_active_chain_stages(CHAIN_WINDOW_SEC)
            with self._lock:
                self._chains = defaultdict(lambda: defaultdict(list))
                for source_ip, stage_dict in stages.items():
                    for stage, timestamps in stage_dict.items():
                        self._chains[source_ip][stage] = list(timestamps)
            count = len(self._chains)
            if count:
                logger.info(f"Attack chain restore: {count} aktif IP DB'den yüklendi")
        except Exception as exc:
            logger.warning(f"Attack chain DB restore başarısız: {exc}")


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
        event_action     = trigger["event_action"],
        severity       = trigger["severity"],
        group_value    = trigger["source_ip"],
        group_by_field = "source_ip",
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
