"""
NetGuard — SIGMA Kural Parser

SIGMA (https://github.com/SigmaHQ/sigma) formatındaki YAML kurallarını
NetGuard CorrelationRule yapısına dönüştürür.

Desteklenen SIGMA alt kümesi:
  - Aggregation condition: selection | count() by <field> > <N>
  - Timeframe: Ns / Nm / Nh / Nd
  - Level → severity mapping
  - selection.event_type → match_event_type
  - selection.severity → match_severity (opsiyonel)
"""

import logging
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

logger = logging.getLogger(__name__)

LEVEL_TO_SEVERITY = {
    "informational": "info",
    "low":           "info",
    "medium":        "warning",
    "high":          "critical",
    "critical":      "critical",
}


@dataclass
class SigmaRule:
    title:         str
    rule_id:       str
    status:        str
    description:   str
    level:         str
    logsource:     dict
    detection:     dict
    tags:          list[str] = field(default_factory=list)
    falsepositives: list[str] = field(default_factory=list)
    enabled:       bool = True


def parse_timeframe(tf: str) -> int:
    """'5m' → 300, '1h' → 3600, '30s' → 30, '2d' → 172800"""
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    m = re.fullmatch(r"(\d+)([smhd])", tf.strip().lower())
    if not m:
        raise ValueError(f"Geçersiz timeframe formatı: {tf!r}")
    return int(m.group(1)) * units[m.group(2)]


def parse_condition(condition: str) -> tuple[str, int, Optional[str]]:
    """
    'selection | count() by src_ip > 5'              → ('src_ip', 5, None)
    'selection | count(distinct username) by src_ip > 10' → ('src_ip', 10, 'username')
    Döner: (group_by_field, threshold, distinct_by_or_None)
    """
    distinct_by: Optional[str] = None
    dm = re.search(r"count\(distinct\s+(\w+)\)", condition, re.IGNORECASE)
    if dm:
        distinct_by = dm.group(1)

    m = re.search(r"by\s+(\w+)\s*>=?\s*(\d+)", condition)
    if not m:
        raise ValueError(f"Condition parse hatası (beklenen: ... by <field> > <N>): {condition!r}")
    return m.group(1), int(m.group(2)), distinct_by


def sigma_to_correlation_rule(sigma: SigmaRule):
    """SigmaRule → CorrelationRule (server.correlator modülünden import edilir)."""
    from server.correlator import CorrelationRule

    detection  = sigma.detection
    selection  = detection.get("selection", {})
    condition  = detection.get("condition", "")
    timeframe  = str(detection.get("timeframe", "5m"))

    event_type     = selection.get("event_type", "")
    match_severity = selection.get("severity")
    keywords       = selection.get("keywords") or None

    group_by, threshold, distinct_by = parse_condition(condition)
    window_seconds = parse_timeframe(timeframe)
    severity       = LEVEL_TO_SEVERITY.get(sigma.level.lower(), "warning")

    rule_id_slug       = re.sub(r"[^a-z0-9_]", "_", sigma.rule_id.lower())
    output_event_type  = f"{rule_id_slug}_detected"

    return CorrelationRule(
        rule_id           = sigma.rule_id,
        name              = sigma.title,
        description       = sigma.description,
        match_event_type  = event_type,
        group_by          = group_by,
        window_seconds    = window_seconds,
        threshold         = threshold,
        severity          = severity,
        output_event_type = output_event_type,
        enabled           = sigma.enabled,
        match_severity    = match_severity,
        keywords          = keywords,
        distinct_by       = distinct_by,
    )


def parse_sigma_file(path: Path) -> Optional[SigmaRule]:
    """Tek bir SIGMA YAML dosyasını oku ve SigmaRule döndür. Hata olursa None."""
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as exc:
        logger.error(f"SIGMA dosyası okunamadı ({path.name}): {exc}")
        return None

    if not isinstance(data, dict):
        logger.error(f"SIGMA dosyası geçersiz format ({path.name})")
        return None

    required = ("title", "detection", "level")
    for key in required:
        if key not in data:
            logger.error(f"SIGMA kuralı eksik alan '{key}': {path.name}")
            return None

    try:
        parse_condition(data["detection"].get("condition", ""))
        parse_timeframe(str(data["detection"].get("timeframe", "5m")))

    except ValueError as exc:
        logger.error(f"SIGMA kural hatası ({path.name}): {exc}")
        return None

    rule_id = str(data.get("id", path.stem))

    return SigmaRule(
        title          = data["title"],
        rule_id        = rule_id,
        status         = data.get("status", "experimental"),
        description    = data.get("description", ""),
        level          = data["level"],
        logsource      = data.get("logsource", {}),
        detection      = data["detection"],
        tags           = data.get("tags", []),
        falsepositives = data.get("falsepositives", []),
        enabled        = data.get("enabled", True),
    )


def load_sigma_rules_from_dir(sigma_dir: str) -> list:
    """
    Bir dizindeki tüm .yml / .yaml dosyalarını yükle.
    CorrelationRule listesi döner (başarısız dosyalar atlanır).
    """
    directory = Path(sigma_dir)
    if not directory.exists():
        logger.debug(f"SIGMA kural dizini bulunamadı: {directory}")
        return []

    rules = []
    for yaml_path in sorted(directory.glob("**/*.y*ml")):
        sigma = parse_sigma_file(yaml_path)
        if sigma is None or not sigma.enabled:
            continue
        try:
            rule = sigma_to_correlation_rule(sigma)
            rules.append(rule)
            logger.debug(f"SIGMA kural yüklendi: {rule.rule_id}")
        except Exception as exc:
            logger.error(f"SIGMA dönüşüm hatası ({yaml_path.name}): {exc}")

    logger.info(f"{len(rules)} SIGMA kuralı yüklendi: {sigma_dir}")
    return rules
