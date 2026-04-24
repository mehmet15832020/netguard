"""
NetGuard — Log Korelasyon Motoru

Normalize edilmiş logları zaman penceresi içinde gruplara göre sayar.
Eşik aşılırsa CorrelatedEvent üretir ve DB'ye yazar.

Kurallar kodda değil — config/correlation_rules.json dosyasından okunur.
Dosyayı değiştirip reload_rules() çağırmak yeterlidir.

Kural şeması (JSON):
  rule_id         — benzersiz kural kimliği
  name            — okunabilir isim
  description     — açıklama
  match_event_type — normalize logda eşleşecek event_type (prefix LIKE)
  match_severity  — (opsiyonel) sadece bu severity'deki logları say
  group_by        — "src_ip" veya "source_host"
  window_seconds  — zaman penceresi
  threshold       — eşik — bu kadar log gelirse tetikle
  severity        — üretilen CorrelatedEvent'in severity'si
  output_event_type — üretilen CorrelatedEvent'in event_type'ı
  enabled         — true/false
"""

import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from server.database import db
from shared.models import CorrelatedEvent

logger = logging.getLogger(__name__)


def _ti_lookup_bg(ip: str) -> None:
    try:
        from server import threat_intel
        threat_intel.lookup(ip)
    except Exception as exc:
        logger.debug(f"TI arka plan sorgusu başarısız [{ip}]: {exc}")


RULES_PATH = os.getenv(
    "NETGUARD_CORRELATION_RULES",
    str(Path(__file__).parent.parent / "config" / "correlation_rules.json"),
)

SIGMA_RULES_DIR = os.getenv(
    "NETGUARD_SIGMA_RULES_DIR",
    str(Path(__file__).parent.parent / "config" / "sigma_rules"),
)


# ------------------------------------------------------------------ #
#  Kural veri yapısı
# ------------------------------------------------------------------ #

@dataclass
class CorrelationRule:
    rule_id: str
    name: str
    description: str
    match_event_type: str      # prefix — LIKE sorgusu için
    group_by: str              # "src_ip" | "source_host"
    window_seconds: int
    threshold: int
    severity: str
    output_event_type: str
    enabled: bool
    match_severity: Optional[str] = None   # opsiyonel severity filtresi


# ------------------------------------------------------------------ #
#  Korelasyon motoru
# ------------------------------------------------------------------ #

class Correlator:
    """
    Normalize edilmiş logları periyodik olarak tarar,
    aktif kurallara göre korelasyon olayları üretir.
    """

    def __init__(self, rules_path: str = RULES_PATH, sigma_dir: str = SIGMA_RULES_DIR):
        self._rules_path = rules_path
        self._sigma_dir  = sigma_dir
        self._rules: list[CorrelationRule] = []
        self.load_rules()

    # ------------------------------------------------------------------ #
    #  Kural yükleme
    # ------------------------------------------------------------------ #

    def load_rules(self) -> int:
        """
        Kuralları iki kaynaktan yükle: SIGMA YAML dizini + JSON dosyası.
        Aynı rule_id varsa SIGMA kuralı önceliklidir.
        Döner: yüklenen etkin kural sayısı.
        """
        rule_map: dict[str, CorrelationRule] = {}

        # 1) JSON kuralları (eski format, geriye dönük uyumluluk)
        path = Path(self._rules_path)
        if path.exists():
            try:
                with open(path, encoding="utf-8") as f:
                    raw = json.load(f)
                for item in raw:
                    if not item.get("enabled", True):
                        continue
                    try:
                        rule = CorrelationRule(
                            rule_id           = item["rule_id"],
                            name              = item["name"],
                            description       = item.get("description", ""),
                            match_event_type  = item["match_event_type"],
                            group_by          = item.get("group_by", "src_ip"),
                            window_seconds    = int(item["window_seconds"]),
                            threshold         = int(item["threshold"]),
                            severity          = item.get("severity", "warning"),
                            output_event_type = item["output_event_type"],
                            enabled           = True,
                            match_severity    = item.get("match_severity"),
                        )
                        rule_map[rule.rule_id] = rule
                    except KeyError as exc:
                        logger.error(f"JSON kural alanı eksik ({item.get('rule_id', '?')}): {exc}")
            except (json.JSONDecodeError, OSError) as exc:
                logger.error(f"JSON kural dosyası okunamadı: {exc}")

        # 2) SIGMA kuralları — aynı rule_id varsa JSON'u override eder
        try:
            from server.sigma_parser import load_sigma_rules_from_dir
            sigma_rules = load_sigma_rules_from_dir(self._sigma_dir)
            for rule in sigma_rules:
                rule_map[rule.rule_id] = rule
        except Exception as exc:
            logger.error(f"SIGMA kural yükleme hatası: {exc}")

        self._rules = list(rule_map.values())
        logger.info(f"{len(self._rules)} korelasyon kuralı yüklendi: {[r.rule_id for r in self._rules]}")
        return len(self._rules)

    @property
    def rules(self) -> list[CorrelationRule]:
        return list(self._rules)

    # ------------------------------------------------------------------ #
    #  Korelasyon çalıştırma
    # ------------------------------------------------------------------ #

    def run(self) -> list[CorrelatedEvent]:
        """
        Tüm aktif kuralları çalıştır.
        Üretilen CorrelatedEvent listesini döner.
        """
        produced: list[CorrelatedEvent] = []
        for rule in self._rules:
            events = self._apply_rule(rule)
            produced.extend(events)
        return produced

    def _apply_rule(self, rule: CorrelationRule) -> list[CorrelatedEvent]:
        """
        Tek bir kuralı uygula:
        1. Zaman penceresindeki eşleşen logları DB'den al
        2. group_by alanına göre grupla
        3. Eşiği aşan gruplar için CorrelatedEvent üret
        """
        since = datetime.now(timezone.utc) - timedelta(seconds=rule.window_seconds)
        since_iso = since.isoformat()

        # Tüm group_by değerlerini bulmak için distinct sorgu
        group_col = "src_ip" if rule.group_by == "src_ip" else "source_host"

        with db._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT {group_col} as grp_val, COUNT(*) as cnt,
                       MIN(timestamp) as first_ts, MAX(timestamp) as last_ts
                FROM normalized_logs
                WHERE event_type LIKE ?
                  AND timestamp >= ?
                  {"AND severity = ?" if rule.match_severity else ""}
                  AND {group_col} IS NOT NULL
                GROUP BY {group_col}
                HAVING cnt >= ?
                """,
                (
                    f"{rule.match_event_type}%",
                    since_iso,
                    *(([rule.match_severity]) if rule.match_severity else []),
                    rule.threshold,
                ),
            ).fetchall()

        produced = []
        for row in rows:
            group_value = row["grp_val"]
            count       = row["cnt"]
            first_seen  = datetime.fromisoformat(row["first_ts"])
            last_seen   = datetime.fromisoformat(row["last_ts"])

            event = CorrelatedEvent(
                corr_id        = str(uuid.uuid4()),
                rule_id        = rule.rule_id,
                rule_name      = rule.name,
                event_type     = rule.output_event_type,
                severity       = rule.severity,
                group_value    = group_value,
                matched_count  = count,
                window_seconds = rule.window_seconds,
                first_seen     = first_seen,
                last_seen      = last_seen,
                message        = (
                    f"{rule.name}: {group_value} kaynağından "
                    f"{rule.window_seconds}s içinde {count} olay "
                    f"(eşik: {rule.threshold})"
                ),
            )

            saved = db.save_correlated_event(event)
            if saved:
                produced.append(event)
                logger.warning(
                    f"Korelasyon tetiklendi [{rule.rule_id}]: "
                    f"{group_value} — {count} olay / {rule.window_seconds}s"
                )
                self._create_alert(event)
                self._create_incident_from_corr(event)
                try:
                    from server.notifier import notifier
                    notifier.notify_correlated(event)
                except Exception as exc:
                    logger.warning(f"Notifier hatası: {exc}")
                if event.group_value:
                    import threading
                    threading.Thread(
                        target=_ti_lookup_bg, args=(event.group_value,), daemon=True
                    ).start()

        return produced

    def _create_incident_from_corr(self, event: CorrelatedEvent) -> None:
        try:
            from server.database import db
            from shared.models import Incident, IncidentStatus

            last_seen_iso = event.last_seen.isoformat() if hasattr(event.last_seen, "isoformat") else event.last_seen
            existing_id = db.find_open_incident_for_rule(event.rule_id, event.group_value)
            if existing_id:
                db.escalate_incident_severity(existing_id, event.severity)
                db.add_incident_event(
                    incident_id=existing_id,
                    event_id=event.corr_id,
                    event_type=event.event_type,
                    severity=event.severity,
                    message=event.message,
                    occurred_at=last_seen_iso,
                )
            else:
                incident = Incident(
                    incident_id=str(uuid.uuid4()),
                    title=event.message,
                    description=f"Otomatik: {event.event_type} — {event.group_value}",
                    severity=event.severity,
                    status=IncidentStatus.OPEN,
                    source_event_id=event.corr_id,
                    source_type="correlated_event",
                    created_by="correlator",
                    rule_id=event.rule_id,
                    group_value=event.group_value,
                )
                db.create_incident(incident)
                db.add_incident_event(
                    incident_id=incident.incident_id,
                    event_id=event.corr_id,
                    event_type=event.event_type,
                    severity=event.severity,
                    message=event.message,
                    occurred_at=last_seen_iso,
                )
        except Exception as exc:
            logger.error(f"Otomatik incident oluşturulamadı [{event.rule_id}]: {exc}")

    def _create_alert(self, event: CorrelatedEvent) -> None:
        """Korelasyon eventinden Alert üret ve storage'a kaydet."""
        try:
            from server.storage import storage
            from shared.models import Alert, AlertSeverity, AlertStatus

            severity_map = {
                "critical": AlertSeverity.CRITICAL,
                "warning":  AlertSeverity.WARNING,
                "info":     AlertSeverity.INFO,
            }
            alert = Alert(
                alert_id     = str(uuid.uuid4()),
                agent_id     = "correlator",
                hostname     = event.group_value,
                severity     = severity_map.get(event.severity, AlertSeverity.WARNING),
                status       = AlertStatus.ACTIVE,
                metric       = event.event_type,
                message      = event.message,
                value        = float(event.matched_count),
                threshold    = 0.0,
                triggered_at = event.last_seen,
            )
            storage.store_alert(alert)
        except Exception as exc:
            logger.error(f"Alert üretilemedi [{event.rule_id}]: {exc}")


# Global instance
correlator = Correlator()
