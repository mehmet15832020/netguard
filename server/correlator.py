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
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from server.database import db
from server.fp_manager import fp_manager
from server.mitre import parse_mitre_tags
from shared.models import CorrelatedEvent

logger = logging.getLogger(__name__)

_NOTIFY_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix='ng-notify')
_TI_EXECUTOR     = ThreadPoolExecutor(max_workers=2, thread_name_prefix='ng-ti')


def _ti_lookup_bg(ip: str) -> None:
    try:
        from server import threat_intel
        threat_intel.lookup(ip)
    except Exception as exc:
        logger.debug(f"TI arka plan sorgusu başarısız [{ip}]: {exc}")


def _notify_bg(event) -> None:
    try:
        from server.notifier import notifier
        notifier.notify_correlated(event)
    except Exception as exc:
        logger.warning("Notifier hatası: %s", exc)


RULES_PATH = os.getenv(
    "NETGUARD_CORRELATION_RULES",
    str(Path(__file__).parent.parent / "config" / "correlation_rules.json"),
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
        rules_path:   str = RULES_PATH,
        sigma_v2_dir: Optional[str] = None,
    ):
        self._rules_path   = rules_path
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
        JSON korelasyon kurallarını yükle.
        Döner: yüklenen etkin kural sayısı.
        """
        rule_map: dict[str, CorrelationRule] = {}

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
                            rule_id             = item["rule_id"],
                            name                = item["name"],
                            description         = item.get("description", ""),
                            match_event_action  = item["match_event_action"],
                            group_by            = item.get("group_by", "source_ip"),
                            window_seconds      = int(item["window_seconds"]),
                            threshold           = int(item["threshold"]),
                            severity            = item.get("severity", "warning"),
                            output_event_action = item["output_event_action"],
                            enabled             = True,
                            match_severity      = item.get("match_severity"),
                            keywords            = item.get("keywords"),
                            distinct_by         = item.get("distinct_by"),
                            tags                = item.get("tags", []),
                        )
                        rule_map[rule.rule_id] = rule
                    except KeyError as exc:
                        logger.error(f"JSON kural alanı eksik ({item.get('rule_id', '?')}): {exc}")
            except (json.JSONDecodeError, OSError) as exc:
                logger.error(f"JSON kural dosyası okunamadı: {exc}")

        self._rules = list(rule_map.values())
        sigma_count = self._sigma_executor.load_dir()
        total = len(self._rules) + sigma_count
        logger.info(
            "%d korelasyon kuralı yüklendi (JSON=%d, Sigma=%d): %s",
            total, len(self._rules), sigma_count, [r.rule_id for r in self._rules],
        )
        return total

    @property
    def rules(self) -> list[CorrelationRule]:
        return list(self._rules)

    # ------------------------------------------------------------------ #
    #  Korelasyon çalıştırma
    # ------------------------------------------------------------------ #

    def run(self) -> list[CorrelatedEvent]:
        """
        Tüm aktif kuralları çalıştır — JSON korelasyon kuralları + pySigma (sigma_v2).
        Üretilen CorrelatedEvent listesini döner.
        """
        produced: list[CorrelatedEvent] = []

        # JSON korelasyon kuralları akışı
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
        _mgmt_ips = frozenset(
            ip.strip()
            for ip in os.getenv("NETGUARD_MANAGEMENT_IPS", "").split(",")
            if ip.strip()
        )
        for rule, row in rule_hits:
            group_val = str(row.get("group_value") or "unknown")
            count     = int(row.get("event_count", 1))
            now       = datetime.now(timezone.utc)

            def _parse_ts(val) -> datetime:
                if isinstance(val, datetime):
                    return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
                return datetime.fromisoformat(val).replace(tzinfo=timezone.utc)

            first_seen = _parse_ts(row["first_ts"]) if row.get("first_ts") else now
            last_seen  = _parse_ts(row["last_ts"])  if row.get("last_ts")  else now

            event = CorrelatedEvent(
                corr_id        = str(uuid.uuid4()),
                rule_id        = rule.rule_id,
                rule_name      = rule.title,
                event_action   = rule.output_event_action,
                severity       = rule.severity,
                group_value    = group_val,
                group_by_field = rule.group_by_fields[0] if rule.group_by_fields else "source_ip",
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
                if self._is_fp_suppressed(event):
                    continue
                if _mgmt_ips and event.group_by_field == "source_ip" and event.group_value in _mgmt_ips:
                    continue
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
                except Exception as exc:
                    logger.debug("ws broadcast: %s", exc)
                self._create_alert(event)
                self._create_incident_from_corr(event)
                self._check_attack_chain(event)
                _NOTIFY_EXECUTOR.submit(_notify_bg, event)
                if group_val:
                    _TI_EXECUTOR.submit(_ti_lookup_bg, group_val)

        return produced

    def _apply_rule(self, rule: CorrelationRule) -> list[CorrelatedEvent]:
        """
        Tek bir kuralı uygula:
        1. Zaman penceresindeki eşleşen logları DB'den al
        2. group_by alanına göre grupla
        3. Eşiği aşan gruplar için CorrelatedEvent üret
        """
        since = datetime.now(timezone.utc) - timedelta(seconds=rule.window_seconds)

        if rule.group_by not in _VALID_GROUP_COLS:
            logger.warning("Rule %s: geçersiz group_by '%s', atlanıyor", rule.rule_id, rule.group_by)
            return []
        group_col = rule.group_by

        if rule.distinct_by and rule.distinct_by not in _VALID_GROUP_COLS:
            logger.warning("Rule %s: geçersiz distinct_by '%s', atlanıyor", rule.rule_id, rule.distinct_by)
            return []
        count_expr = _COUNT_DISTINCT_EXPRS[rule.distinct_by] if rule.distinct_by else "COUNT(*)"

        rows = db.query_correlated_log_groups(
            event_action_prefix=rule.match_event_action,
            since=since,
            group_col=group_col,
            count_expr=count_expr,
            threshold=rule.threshold,
            match_severity=rule.match_severity,
            keywords=rule.keywords or [],
        )

        _mgmt_ips = frozenset(
            ip.strip()
            for ip in os.getenv("NETGUARD_MANAGEMENT_IPS", "").split(",")
            if ip.strip()
        )

        produced = []
        for row in rows:
            group_value = row["grp_val"]
            if _mgmt_ips and rule.group_by == "source_ip" and group_value in _mgmt_ips:
                continue
            count       = row["cnt"]
            def _parse_ts2(val) -> datetime:
                if isinstance(val, datetime):
                    return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
                return datetime.fromisoformat(str(val)).replace(tzinfo=timezone.utc)

            first_seen  = _parse_ts2(row["first_ts"])
            last_seen   = _parse_ts2(row["last_ts"])

            event = CorrelatedEvent(
                corr_id        = str(uuid.uuid4()),
                rule_id        = rule.rule_id,
                rule_name      = rule.name,
                event_action     = rule.output_event_action,
                severity       = rule.severity,
                group_value    = group_value,
                group_by_field = rule.group_by,
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
                if self._is_fp_suppressed(event):
                    continue
                produced.append(event)
                logger.warning(
                    f"Korelasyon tetiklendi [{rule.rule_id}]: "
                    f"{group_value} — {count} olay / {rule.window_seconds}s"
                )
                try:
                    from server.ws_manager import ws_manager
                    ws_manager.broadcast_from_thread("correlated_event", event.model_dump(mode="json"))
                except Exception as exc:
                    logger.debug("ws broadcast: %s", exc)
                self._create_alert(event)
                self._create_incident_from_corr(event)
                self._check_attack_chain(event)
                import threading
                threading.Thread(target=_notify_bg, args=(event,), daemon=True).start()
                if event.group_value:
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
                    group_by_field=event.group_by_field,
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
                except Exception as exc:
                    logger.debug("ws broadcast: %s", exc)

            if ti_score >= 70:
                db.escalate_incident_severity(incident_id, "critical")
                logger.warning(
                    f"TI escalation: {event.group_value} AbuseIPDB score={ti_score} → incident critical"
                )
        except Exception as exc:
            logger.error(f"Otomatik incident oluşturulamadı [{event.rule_id}]: {exc}")

    def _check_attack_chain(self, event: CorrelatedEvent) -> None:
        import ipaddress
        if event.group_by_field != "source_ip":
            logger.debug(
                "kill chain skipped — group_by=%s value=%s",
                event.group_by_field, event.group_value,
            )
            return
        try:
            ipaddress.ip_address(event.group_value)
        except (ValueError, TypeError):
            logger.debug(
                "kill chain skipped — group_by=%s value=%s IP değil",
                event.group_by_field, event.group_value,
            )
            return
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
                try:
                    from server.ws_manager import ws_manager
                    ws_manager.broadcast_from_thread("attack_chain", {
                        "source_ip":  event.group_value,
                        "chain_type": trigger["chain_type"],
                        "severity":   chain_event.severity,
                    })
                except Exception as ws_exc:
                    logger.debug("attack_chain ws broadcast: %s", ws_exc)
        except Exception as exc:
            logger.error(f"Attack chain kontrol hatası: {exc}")

    def dispatch_chain_event(self, chain_event: CorrelatedEvent) -> None:
        """
        Kill chain trigger'ından üretilen event'i tam pipeline'dan geçirir.
        correlator dışından (agents.py gibi) çağrılabilir — tek dispatch noktası.
        """
        self._create_alert(chain_event)
        self._create_incident_from_corr(chain_event)

    def _is_fp_suppressed(self, event: CorrelatedEvent, tenant_id: str = "default") -> bool:
        """FP kuralı eşleşirse True döner ve hit_count arttırır."""
        source_ip         = event.group_value if event.group_by_field == "source_ip"         else None
        observer_hostname = event.group_value if event.group_by_field == "observer_hostname" else None
        rule_id = fp_manager.is_suppressed(
            event_action=event.event_action,
            source_ip=source_ip,
            observer_hostname=observer_hostname,
            tenant_id=tenant_id,
        )
        if rule_id:
            db.increment_fp_hit(rule_id)
            logger.info(
                "FP baskılandı [kural=%s]: %s — %s",
                rule_id, event.event_action, event.group_value,
            )
            return True
        return False

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
