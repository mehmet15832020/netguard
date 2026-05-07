"""
pySigma tabanlı Sigma rule executor.

config/sigma_rules_v2/ dizinindeki yeni format YAML kurallarını yükler,
NetGuardSQLiteBackend aracılığıyla SQL'e çevirir ve normalized_logs tablosuna karşı çalıştırır.

Kural formatı (YAML multi-doc):
  --- (1. belge: temel detection)
  title: SSH Failure Base
  name: <rule_name>          ← correlation rule'dan referans edilir
  status: stable
  logsource:
      category: authentication
  detection:
      selection:
          event_action: ssh_failure
      condition: selection
  level: medium
  ---  (2. belge: aggregation/correlation)
  title: SSH Brute Force
  id: <UUID>
  correlation:
      type: event_count
      rules: <rule_name>     ← 1. belgedeki name
      group-by: [source_ip]
      timespan: 5m
      condition:
          gte: 5
  level: high
  tags: [attack.t1110]
"""

import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import ClassVar, Optional

import yaml
from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule

logger = logging.getLogger(__name__)

_SIGMA_RULES_V2_DIR = str(
    Path(__file__).parent.parent / "config" / "sigma_rules_v2"
)

_LEVEL_TO_SEVERITY = {
    "informational": "info",
    "low":           "info",
    "medium":        "warning",
    "high":          "high",
    "critical":      "critical",
}


# ------------------------------------------------------------------ #
#  Custom SQLite Backend
# ------------------------------------------------------------------ #

class _NetGuardSQLiteBackend(sqliteBackend):
    """pySigma SQLite backend — normalized_logs tablosuna karşı sorgu üretir."""

    table: ClassVar[str] = "normalized_logs"
    correlation_search_single_rule_expression: ClassVar[Optional[str]] = (
        "SELECT * FROM normalized_logs WHERE {query}{normalization}"
    )
    correlation_search_multi_rule_query_expression: ClassVar[Optional[str]] = (
        "SELECT *, '{ruleid}' AS sigma_rule_id FROM normalized_logs WHERE {query}{normalization}"
    )


def _inject_time_window(sql: str, window_seconds: int) -> str:
    """
    pySigma'nın ürettiği SQL'e zaman penceresi filtresi ekler.

    Korelasyon sorgusu için:  subquery WHERE ... → WHERE ... AND timestamp >= ...
    Basit detection sorgusu için: WHERE ... → WHERE ... AND timestamp >= ...
    """
    time_filter = f" AND timestamp >= datetime('now', '-{window_seconds} seconds')"

    # Korelasyon sorgusu: ... FROM (...WHERE...) AS subquery ...
    result = re.sub(
        r"(SELECT \* FROM normalized_logs WHERE )(.*?)(\) AS subquery)",
        lambda m: m.group(1) + m.group(2) + time_filter + m.group(3),
        sql,
        flags=re.DOTALL,
    )
    if result != sql:
        return result

    # Basit detection sorgusu: SELECT * FROM normalized_logs WHERE ...
    if "WHERE" in sql:
        return sql + time_filter

    return sql


# ------------------------------------------------------------------ #
#  SigmaExecutableRule — tek bir çalıştırılabilir kural
# ------------------------------------------------------------------ #

@dataclass
class SigmaExecutableRule:
    rule_id:            str
    title:              str
    severity:           str
    sql:                str          # Zaman pencereli, çalışmaya hazır SQL
    window_seconds:     int
    group_by_fields:    list[str]    # Korelasyon için GROUP BY alanları
    is_correlation:     bool         # True: count-based; False: per-event
    tags:               list[str]    = field(default_factory=list)
    output_event_action: str         = ""   # e.g. "ssh_brute_force_detected"

    def __post_init__(self) -> None:
        if not self.output_event_action:
            slug = re.sub(r"[^a-z0-9]+", "_", self.title.lower()).strip("_")
            self.output_event_action = f"{slug}_detected"


# ------------------------------------------------------------------ #
#  SigmaExecutor — yükleme + çalıştırma
# ------------------------------------------------------------------ #

class SigmaExecutor:
    """
    Sigma kurallarını yükler (pySigma formatı) ve normalized_logs tablosuna karşı çalıştırır.
    Correlator.run() içinde mevcut CorrelationRule akışına paralel çalışır.
    """

    def __init__(self, rules_dir: str = _SIGMA_RULES_V2_DIR) -> None:
        self._dir = rules_dir
        self._backend = _NetGuardSQLiteBackend()
        self._rules: list[SigmaExecutableRule] = []
        self.load_dir()

    def load_dir(self) -> int:
        """rules_dir'deki tüm YAML dosyalarını yükler. Yüklenen kural sayısını döner."""
        self._rules.clear()
        path = Path(self._dir)
        if not path.exists():
            logger.debug("sigma_rules_v2 dizini bulunamadı: %s", self._dir)
            return 0

        for yml_file in sorted(path.glob("*.yml")):
            try:
                loaded = self._load_file(yml_file)
                self._rules.extend(loaded)
            except Exception as exc:
                logger.error("pySigma kural yükleme hatası [%s]: %s", yml_file.name, exc)

        logger.info(
            "pySigma kurallar yüklendi: %d kural (%s)",
            len(self._rules),
            [r.rule_id for r in self._rules],
        )
        return len(self._rules)

    def _load_file(self, path: Path) -> list[SigmaExecutableRule]:
        """Tek bir YAML dosyasından (multi-doc) kuralları yükler."""
        from sigma.rule import SigmaRule as _SigmaRule

        raw = path.read_text(encoding="utf-8")
        dicts = list(yaml.safe_load_all(raw))
        if not dicts:
            return []

        col = SigmaCollection.from_dicts(dicts)
        queries = self._backend.convert(col)

        # Hangi kurallar sorgu üretir?
        # Base kurallar (correlation tarafından referans edilenler) bağımsız sorgu üretmez.
        # SigmaCorrelationRule + referans edilmeyen bağımsız SigmaRule sorgu üretir.
        referenced_names: set[str] = set()
        for rule in col.rules:
            if isinstance(rule, SigmaCorrelationRule):
                for ref in (rule.rules or []):
                    referenced_names.add(ref.reference)  # ref.reference: düz string

        executable_rules = []
        for rule in col.rules:
            if isinstance(rule, SigmaCorrelationRule):
                executable_rules.append(("correlation", rule))
            elif isinstance(rule, _SigmaRule):
                rule_name = getattr(rule, "name", None) or rule.title
                if rule_name not in referenced_names:
                    executable_rules.append(("detection", rule))

        results: list[SigmaExecutableRule] = []
        for i, (kind, rule) in enumerate(executable_rules):
            if i >= len(queries):
                break
            sql_raw = queries[i]

            if kind == "correlation":
                cr: SigmaCorrelationRule = rule
                win_sec    = cr.timespan.seconds
                group_by   = cr.group_by or []
                level_name = cr.level.name.lower() if cr.level else "medium"
                severity   = _LEVEL_TO_SEVERITY.get(level_name, "warning")
                tags       = [str(t) for t in (cr.tags or [])]
                rule_id    = str(cr.id) if cr.id else str(uuid.uuid4())
                final_sql  = _inject_time_window(sql_raw, win_sec)

                results.append(SigmaExecutableRule(
                    rule_id         = rule_id,
                    title           = cr.title,
                    severity        = severity,
                    sql             = final_sql,
                    window_seconds  = win_sec,
                    group_by_fields = group_by,
                    is_correlation  = True,
                    tags            = tags,
                ))

            else:  # simple detection
                dr: _SigmaRule = rule
                level_name = dr.level.name.lower() if dr.level else "medium"
                severity   = _LEVEL_TO_SEVERITY.get(level_name, "warning")
                tags       = [str(t) for t in (dr.tags or [])]
                rule_id    = str(dr.id) if dr.id else str(uuid.uuid4())
                # Basit detection kuralları için 60 saniyelik pencere (correlator döngüsü)
                final_sql  = _inject_time_window(sql_raw, 60)

                results.append(SigmaExecutableRule(
                    rule_id         = rule_id,
                    title           = dr.title,
                    severity        = severity,
                    sql             = final_sql,
                    window_seconds  = 60,
                    group_by_fields = [],
                    is_correlation  = False,
                    tags            = tags,
                ))

        return results

    @property
    def rules(self) -> list[SigmaExecutableRule]:
        return list(self._rules)

    def execute_rule(self, rule: SigmaExecutableRule, conn) -> list[dict]:
        """
        Tek bir kuralın SQL'ini çalıştırır.
        Her satır bir dict: {"group_value": ..., "event_count": ...}
        """
        try:
            rows = conn.execute(rule.sql).fetchall()
        except Exception as exc:
            logger.error("pySigma SQL yürütme hatası [%s]: %s", rule.rule_id, exc)
            return []

        results = []
        for row in rows:
            keys = row.keys()
            if rule.is_correlation:
                group_fields = rule.group_by_fields
                group_val = (
                    row[group_fields[0]] if group_fields and group_fields[0] in keys
                    else (list(row)[0] if len(keys) >= 1 else "unknown")
                )
                count = row["event_count"] if "event_count" in keys else 1
            else:
                keys_set = set(row.keys())
                group_val = (
                    row["source_ip"]        if "source_ip"        in keys_set else
                    row["observer_hostname"] if "observer_hostname" in keys_set else
                    "unknown"
                )
                count = 1

            results.append({
                "group_value": group_val,
                "event_count": count,
                "timestamp":   datetime.now(timezone.utc).isoformat(),
            })

        return results
