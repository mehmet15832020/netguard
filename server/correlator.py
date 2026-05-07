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
  match_event_action — normalize logda eşleşecek event_action (prefix LIKE)
  match_severity  — (opsiyonel) sadece bu severity'deki logları say
  group_by        — "source_ip" veya "observer_hostname"
  window_seconds  — zaman penceresi
  threshold       — eşik — bu kadar log gelirse tetikle
  severity        — üretilen CorrelatedEvent'in severity'si
  output_event_action — üretilen CorrelatedEvent'in event_action'ı
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
from server.mitre import parse_mitre_tags
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

SIGMA_RULES_V2_DIR = os.getenv(
    "NETGUARD_SIGMA_RULES_V2_DIR",
    str(Path(__file__).parent.parent / "config" / "sigma_rules_v2"),
)

_VALID_GROUP_COLS: frozenset[str] = frozenset({
    "source_ip", "destination_ip", "observer_hostname", "username", "hostname",
    "event_action", "event_category", "tenant_id", "source_type",
    "network_protocol", "source_port", "destination_port", "device_id",
})
# Pre-built COUNT(DISTINCT col) ifadeleri — runtime f-string interpolasyon riski yok
_COUNT_DISTINCT_EXPRS: dict[str, str] = {col: f"COUNT(DISTINCT {col})" for col in _VALID_GROUP_COLS}


# ------------------------------------------------------------------ #
#  Kural veri yapısı
# ------------------------------------------------------------------ #

@dataclass
class CorrelationRule:
    rule_id: str
    name: str
    description: str
    match_event_action: str      # prefix — LIKE sorgusu için
    group_by: str              # "source_ip" | "observer_hostname"
    window_seconds: int
    threshold: int
    severity: str
    output_event_action: str
    enabled: bool
    match_severity: Optional[str] = None   # opsiyonel severity filtresi
    keywords: Optional[list] = None        # mesajda aranacak anahtar kelimeler (OR)
    distinct_by: Optional[str] = None      # count(distinct field) — password spray için
    tags: list = None                      # Sigma tags → MITRE etiketleri


# ------------------------------------------------------------------ #
#  Korelasyon motoru
# ------------------------------------------------------------------ #

class Correlator:
    """
    Normalize edilmiş logları periyodik olarak tarar,
    aktif kurallara göre korelasyon olayları üretir.
    """

    def __init__(
        self,
        rules_path:     str = RULES_PATH,
        sigma_dir:      str = SIGMA_RULES_DIR,
        sigma_v2_dir:   Optional[str] = None,
    ):
        self._rules_path   = rules_path
        self._sigma_dir    = sigma_dir
        # None → runtime'da SIGMA_RULES_V2_DIR okunur (monkeypatch uyumlu)
        self._sigma_v2_dir = sigma_v2_dir if sigma_v2_dir is not None else SIGMA_RULES_V2_DIR
        self._rules: list[CorrelationRule] = []
        from server.sigma_executor import SigmaExecutor
        self._sigma_executor = SigmaExecutor(rules_dir=self._sigma_v2_dir)
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
                            match_event_action  = item["match_event_action"],
                            group_by          = item.get("group_by", "source_ip"),
                            window_seconds    = int(item["window_seconds"]),
                            threshold         = int(item["threshold"]),
                            severity          = item.get("severity", "warning"),
                            output_event_action = item["output_event_action"],
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
        Tüm aktif kuralları çalıştır — eski format (JSON/sigma_v1) + pySigma (sigma_v2).
        Üretilen CorrelatedEvent listesini döner.
        """
        produced: list[CorrelatedEvent] = []

        # Mevcut CorrelationRule akışı (JSON + sigma_v1 YAML)
        for rule in self._rules:
            events = self._apply_rule(rule)
            produced.extend(events)

        # pySigma akışı (sigma_v2 YAML)
        if self._sigma_executor.rules:
            produced.extend(self._run_sigma_v2())

        return produced

    def _run_sigma_v2(self) -> list[CorrelatedEvent]:
        """pySigma (sigma_rules_v2) kurallarını çalıştırır."""
        from server.mitre import parse_mitre_tags
        produced: list[CorrelatedEvent] = []

        # Önce tüm satırları topla — read connection'ı yazma işlemlerinden önce kapat
        rule_hits: list[tuple] = []
        with db._connect() as conn:
            for rule in self._sigma_executor.rules:
                rows = self._sigma_executor.execute_rule(rule, conn, tenant_id="default")
                rule_hits.extend((rule, row) for row in rows)

        # Read connection kapatıldı — şimdi güvenle write işlemleri yapılabilir
        for rule, row in rule_hits:
            group_val = str(row.get("group_value") or "unknown")
            count     = int(row.get("event_count", 1))
            now       = datetime.now(timezone.utc)

            first_seen = (
                datetime.fromisoformat(row["first_ts"]).replace(tzinfo=timezone.utc)
                if row.get("first_ts") else now
            )
            last_seen = (
                datetime.fromisoformat(row["last_ts"]).replace(tzinfo=timezone.utc)
                if row.get("last_ts") else now
            )

            event = CorrelatedEvent(
                corr_id        = str(uuid.uuid4()),
                rule_id        = rule.rule_id,
                rule_name      = rule.title,
                event_action   = rule.output_event_action,
                severity       = rule.severity,
                group_value    = group_val,
                matched_count  = count,
                window_seconds = rule.window_seconds,
                first_seen     = first_seen,
                last_seen      = last_seen,
                message        = (
                    f"{rule.title}: {group_val} kaynağından "
                    f"{rule.window_seconds}s içinde {count} olay"
                ),
                **parse_mitre_tags(rule.tags),
            )

            saved = db.save_correlated_event(event)
            if saved:
                produced.append(event)
                logger.warning(
                    "pySigma tetiklendi [%s]: %s — %d olay / %ds",
                    rule.rule_id, group_val, count, rule.window_seconds,
                )
                try:
                    from server.ws_manager import ws_manager
                    ws_manager.broadcast_from_thread(
                        "correlated_event", event.model_dump(mode="json")
                    )
                except Exception:
                    pass
                self._create_alert(event)
                self._create_incident_from_corr(event)
                self._check_attack_chain(event)
                try:
                    from server.notifier import notifier
                    notifier.notify_correlated(event)
                except Exception as exc:
                    logger.warning("Notifier hatası: %s", exc)
                if group_val:
                    import threading
                    threading.Thread(
                        target=_ti_lookup_bg, args=(group_val,), daemon=True
                    ).start()

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

        if rule.group_by not in _VALID_GROUP_COLS:
            logger.warning("Rule %s: geçersiz group_by '%s', atlanıyor", rule.rule_id, rule.group_by)
            return []
        group_col = rule.group_by

        if rule.distinct_by and rule.distinct_by not in _VALID_GROUP_COLS:
            logger.warning("Rule %s: geçersiz distinct_by '%s', atlanıyor", rule.rule_id, rule.distinct_by)
            return []
        count_expr = _COUNT_DISTINCT_EXPRS[rule.distinct_by] if rule.distinct_by else "COUNT(*)"

        kw_clause  = ""
        kw_params: list = []
        if rule.keywords:
            parts = " OR ".join("message LIKE ?" for _ in rule.keywords)
            kw_clause = f"AND ({parts})"
            for kw in rule.keywords:
                kw_params += [f"%{kw}%"]

        with db._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT {group_col} as grp_val,
                       {count_expr} as cnt,
                       MIN(timestamp) as first_ts, MAX(timestamp) as last_ts
                FROM normalized_logs
                WHERE event_action LIKE ?
                  AND timestamp >= ?
                  {"AND severity = ?" if rule.match_severity else ""}
                  AND {group_col} IS NOT NULL
                  {kw_clause}
                GROUP BY {group_col}
                HAVING cnt >= ?
                """,
                (
                    f"{rule.match_event_action}%",
                    since_iso,
                    *(([rule.match_severity]) if rule.match_severity else []),
                    *kw_params,
                    rule.threshold,
                ),
            ).fetchall()

        produced = []
        for row in rows:
            group_value = row["grp_val"]
            count       = row["cnt"]
            first_seen  = datetime.fromisoformat(row["first_ts"]).replace(tzinfo=timezone.utc)
            last_seen   = datetime.fromisoformat(row["last_ts"]).replace(tzinfo=timezone.utc)

            event = CorrelatedEvent(
                corr_id        = str(uuid.uuid4()),
                rule_id        = rule.rule_id,
                rule_name      = rule.name,
                event_action     = rule.output_event_action,
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
                **parse_mitre_tags(rule.tags or []),
            )

            saved = db.save_correlated_event(event)
            if saved:
                produced.append(event)
                logger.warning(
                    f"Korelasyon tetiklendi [{rule.rule_id}]: "
                    f"{group_value} — {count} olay / {rule.window_seconds}s"
                )
                try:
                    from server.ws_manager import ws_manager
                    ws_manager.broadcast_from_thread("correlated_event", event.model_dump(mode="json"))
                except Exception:
                    pass
                self._create_alert(event)
                self._create_incident_from_corr(event)
                self._check_attack_chain(event)
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
            from server import threat_intel
            from server.incident_priority import compute_priority_score

            # TI lookup önce — priority score ve severity escalation için gerekli
            try:
                ti = threat_intel.lookup(event.group_value)
                ti_score = ti.get("score", 0) if ti else 0
            except Exception as exc:
                logger.debug("TI lookup başarısız [%s]: %s", event.group_value, exc)
                ti_score = 0

            last_seen_iso = event.last_seen.isoformat() if hasattr(event.last_seen, "isoformat") else event.last_seen
            existing_id = db.find_open_incident_for_rule(event.rule_id, event.group_value)
            if existing_id:
                db.escalate_incident_severity(existing_id, event.severity)
                db.add_incident_event(
                    incident_id=existing_id,
                    event_id=event.corr_id,
                    event_action=event.event_action,
                    severity=event.severity,
                    message=event.message,
                    occurred_at=last_seen_iso,
                )
                # Severity yükseldiyse priority_score'u da güncelle
                effective_sev = "critical" if ti_score >= 70 else event.severity
                db.update_incident(existing_id, priority_score=compute_priority_score(effective_sev, ti_score))
                incident_id = existing_id
            else:
                effective_severity = "critical" if ti_score >= 70 else event.severity
                priority = compute_priority_score(effective_severity, ti_score)
                incident = Incident(
                    incident_id=str(uuid.uuid4()),
                    title=event.message,
                    description=f"Otomatik: {event.event_action} — {event.group_value}",
                    severity=effective_severity,
                    status=IncidentStatus.OPEN,
                    source_event_id=event.corr_id,
                    source_type="correlated_event",
                    created_by="correlator",
                    rule_id=event.rule_id,
                    group_value=event.group_value,
                    priority_score=priority,
                )
                db.create_incident(incident)
                db.add_incident_event(
                    incident_id=incident.incident_id,
                    event_id=event.corr_id,
                    event_action=event.event_action,
                    severity=event.severity,
                    message=event.message,
                    occurred_at=last_seen_iso,
                )
                incident_id = incident.incident_id
                try:
                    from server.ws_manager import ws_manager
                    ws_manager.broadcast_from_thread("incident", {
                        "incident_id": incident.incident_id,
                        "severity": incident.severity,
                        "status": incident.status.value,
                        "title": incident.title,
                        "priority_score": incident.priority_score,
                    })
                except Exception:
                    pass

            if ti_score >= 70:
                db.escalate_incident_severity(incident_id, "critical")
                logger.warning(
                    f"TI escalation: {event.group_value} AbuseIPDB score={ti_score} → incident critical"
                )
        except Exception as exc:
            logger.error(f"Otomatik incident oluşturulamadı [{event.rule_id}]: {exc}")

    def _check_attack_chain(self, event: CorrelatedEvent) -> None:
        try:
            from server.attack_chain import attack_chain_tracker, chain_trigger_to_correlated_event
            trigger = attack_chain_tracker.record(
                source_ip=event.group_value,
                event_action=event.event_action,
            )
            if trigger:
                chain_event = chain_trigger_to_correlated_event(trigger, db_save=True)
                self._create_alert(chain_event)
                self._create_incident_from_corr(chain_event)
                logger.warning(
                    f"SALDIRI ZİNCİRİ tespit edildi: {event.group_value} "
                    f"— {trigger['chain_type']}"
                )
        except Exception as exc:
            logger.error(f"Attack chain kontrol hatası: {exc}")

    def _create_alert(self, event: CorrelatedEvent) -> None:
        """Korelasyon eventinden Alert üret ve SQLite'a kaydet."""
        try:
            from server.database import db
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
                metric       = event.event_action,
                message      = event.message,
                value        = float(event.matched_count),
                threshold    = 0.0,
                triggered_at = event.last_seen,
            )
            db.save_alert(alert)
        except Exception as exc:
            logger.error(f"Alert üretilemedi [{event.rule_id}]: {exc}")


# Global instance
correlator = Correlator()
