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

RULES_PATH = os.getenv(
    "NETGUARD_CORRELATION_RULES",
    str(Path(__file__).parent.parent / "config" / "correlation_rules.json"),
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

    def __init__(self, rules_path: str = RULES_PATH):
        self._rules_path = rules_path
        self._rules: list[CorrelationRule] = []
        self.load_rules()

    # ------------------------------------------------------------------ #
    #  Kural yükleme
    # ------------------------------------------------------------------ #

    def load_rules(self) -> int:
        """
        JSON dosyasından kuralları yükle.
        Dosya bulunamazsa uyarı verir, mevcut kuralları korur.
        Döner: yüklenen etkin kural sayısı.
        """
        path = Path(self._rules_path)
        if not path.exists():
            logger.warning(f"Korelasyon kural dosyası bulunamadı: {path}")
            return 0

        try:
            with open(path, encoding="utf-8") as f:
                raw = json.load(f)
        except (json.JSONDecodeError, OSError) as exc:
            logger.error(f"Kural dosyası okunamadı: {exc}")
            return 0

        rules = []
        for item in raw:
            if not item.get("enabled", True):
                continue
            try:
                rules.append(CorrelationRule(
                    rule_id          = item["rule_id"],
                    name             = item["name"],
                    description      = item.get("description", ""),
                    match_event_type = item["match_event_type"],
                    group_by         = item.get("group_by", "src_ip"),
                    window_seconds   = int(item["window_seconds"]),
                    threshold        = int(item["threshold"]),
                    severity         = item.get("severity", "warning"),
                    output_event_type= item["output_event_type"],
                    enabled          = True,
                    match_severity   = item.get("match_severity"),
                ))
            except KeyError as exc:
                logger.error(f"Kural alanı eksik ({item.get('rule_id', '?')}): {exc}")

        self._rules = rules
        logger.info(f"{len(rules)} korelasyon kuralı yüklendi: {[r.rule_id for r in rules]}")
        return len(rules)

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

        return produced


# Global instance
correlator = Correlator()
