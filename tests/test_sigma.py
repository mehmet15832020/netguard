"""
Tests for SIGMA rule parser and NetGuard integration.
"""

import textwrap
import tempfile
from pathlib import Path

import pytest

from server.sigma_parser import (
    parse_timeframe,
    parse_condition,
    parse_sigma_file,
    sigma_to_correlation_rule,
    load_sigma_rules_from_dir,
    LEVEL_TO_SEVERITY,
)


# ------------------------------------------------------------------ #
#  parse_timeframe
# ------------------------------------------------------------------ #

@pytest.mark.parametrize("tf,expected", [
    ("5m",  300),
    ("1h",  3600),
    ("30s", 30),
    ("2d",  172800),
    ("1m",  60),
    ("10m", 600),
])
def test_parse_timeframe_valid(tf, expected):
    assert parse_timeframe(tf) == expected


def test_parse_timeframe_invalid():
    with pytest.raises(ValueError):
        parse_timeframe("5x")


def test_parse_timeframe_invalid_empty():
    with pytest.raises(ValueError):
        parse_timeframe("")


# ------------------------------------------------------------------ #
#  parse_condition
# ------------------------------------------------------------------ #

@pytest.mark.parametrize("condition,expected", [
    ("selection | count() by src_ip > 5",                          ("src_ip", 5, None)),
    ("selection | count(src_ip) by src_ip > 5",                    ("src_ip", 5, None)),
    ("selection | count() by source_host > 3",                     ("source_host", 3, None)),
    ("selection | count() by src_ip >= 10",                        ("src_ip", 10, None)),
    ("selection | count(distinct username) by src_ip > 10",        ("src_ip", 10, "username")),
    ("selection | count(distinct source_host) by src_ip > 3",      ("src_ip", 3, "source_host")),
])
def test_parse_condition_valid(condition, expected):
    assert parse_condition(condition) == expected


def test_parse_condition_invalid():
    with pytest.raises(ValueError):
        parse_condition("selection | count() > 5")


def test_parse_condition_distinct_sets_distinct_by():
    _, _, distinct_by = parse_condition("selection | count(distinct username) by src_ip > 5")
    assert distinct_by == "username"


# ------------------------------------------------------------------ #
#  Level → severity
# ------------------------------------------------------------------ #

def test_level_to_severity_mapping():
    assert LEVEL_TO_SEVERITY["informational"] == "info"
    assert LEVEL_TO_SEVERITY["low"]           == "info"
    assert LEVEL_TO_SEVERITY["medium"]        == "warning"
    assert LEVEL_TO_SEVERITY["high"]          == "critical"
    assert LEVEL_TO_SEVERITY["critical"]      == "critical"


# ------------------------------------------------------------------ #
#  parse_sigma_file
# ------------------------------------------------------------------ #

VALID_SIGMA_YAML = textwrap.dedent("""\
    title: SSH Brute Force Test
    id: ssh_brute_force_test
    status: stable
    description: Test kuralı
    logsource:
        category: authentication
        product: linux
    detection:
        selection:
            event_type: ssh_failure
        condition: selection | count() by src_ip > 5
        timeframe: 5m
    level: high
    tags:
        - attack.t1110
    falsepositives:
        - Yönetici aktiviteleri
""")


def _write_tmp_yaml(content: str) -> Path:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False, encoding="utf-8")
    f.write(content)
    f.flush()
    return Path(f.name)


def test_parse_sigma_file_valid():
    path = _write_tmp_yaml(VALID_SIGMA_YAML)
    try:
        sigma = parse_sigma_file(path)
        assert sigma is not None
        assert sigma.rule_id == "ssh_brute_force_test"
        assert sigma.title   == "SSH Brute Force Test"
        assert sigma.level   == "high"
        assert sigma.detection["selection"]["event_type"] == "ssh_failure"
    finally:
        path.unlink(missing_ok=True)


def test_parse_sigma_file_missing_required_field():
    yaml_no_level = VALID_SIGMA_YAML.replace("level: high\n", "")
    path = _write_tmp_yaml(yaml_no_level)
    try:
        sigma = parse_sigma_file(path)
        assert sigma is None
    finally:
        path.unlink(missing_ok=True)


def test_parse_sigma_file_invalid_condition():
    bad = VALID_SIGMA_YAML.replace(
        "condition: selection | count() by src_ip > 5",
        "condition: selection"
    )
    path = _write_tmp_yaml(bad)
    try:
        sigma = parse_sigma_file(path)
        assert sigma is None
    finally:
        path.unlink(missing_ok=True)


def test_parse_sigma_file_invalid_timeframe():
    bad = VALID_SIGMA_YAML.replace("timeframe: 5m", "timeframe: 5x")
    path = _write_tmp_yaml(bad)
    try:
        sigma = parse_sigma_file(path)
        assert sigma is None
    finally:
        path.unlink(missing_ok=True)


def test_parse_sigma_file_not_found():
    sigma = parse_sigma_file(Path("/nonexistent/rule.yml"))
    assert sigma is None


# ------------------------------------------------------------------ #
#  sigma_to_correlation_rule
# ------------------------------------------------------------------ #

def test_sigma_to_correlation_rule():
    path = _write_tmp_yaml(VALID_SIGMA_YAML)
    try:
        sigma = parse_sigma_file(path)
        assert sigma is not None
        rule = sigma_to_correlation_rule(sigma)

        assert rule.rule_id           == "ssh_brute_force_test"
        assert rule.name              == "SSH Brute Force Test"
        assert rule.match_event_type  == "ssh_failure"
        assert rule.group_by          == "src_ip"
        assert rule.window_seconds    == 300
        assert rule.threshold         == 5
        assert rule.severity          == "critical"
        assert rule.output_event_type == "ssh_brute_force_test_detected"
        assert rule.enabled           is True
        assert rule.match_severity    is None
    finally:
        path.unlink(missing_ok=True)


def test_sigma_to_correlation_rule_with_severity_filter():
    yaml_with_sev = VALID_SIGMA_YAML.replace(
        "        event_type: ssh_failure",
        "        event_type: ssh_failure\n        severity: warning"
    )
    path = _write_tmp_yaml(yaml_with_sev)
    try:
        sigma = parse_sigma_file(path)
        assert sigma is not None
        rule = sigma_to_correlation_rule(sigma)
        assert rule.match_severity == "warning"
    finally:
        path.unlink(missing_ok=True)


# ------------------------------------------------------------------ #
#  load_sigma_rules_from_dir
# ------------------------------------------------------------------ #

def test_load_sigma_rules_from_dir(tmp_path):
    (tmp_path / "rule1.yml").write_text(VALID_SIGMA_YAML, encoding="utf-8")
    second = VALID_SIGMA_YAML.replace("ssh_brute_force_test", "port_scan_test") \
                             .replace("SSH Brute Force Test", "Port Scan Test")
    (tmp_path / "rule2.yml").write_text(second, encoding="utf-8")

    rules = load_sigma_rules_from_dir(str(tmp_path))
    assert len(rules) == 2
    rule_ids = {r.rule_id for r in rules}
    assert "ssh_brute_force_test" in rule_ids
    assert "port_scan_test" in rule_ids


def test_load_sigma_rules_skips_invalid(tmp_path):
    (tmp_path / "valid.yml").write_text(VALID_SIGMA_YAML, encoding="utf-8")
    (tmp_path / "invalid.yml").write_text("not: valid: yaml: [", encoding="utf-8")

    rules = load_sigma_rules_from_dir(str(tmp_path))
    assert len(rules) == 1


def test_load_sigma_rules_nonexistent_dir():
    rules = load_sigma_rules_from_dir("/nonexistent/sigma_rules")
    assert rules == []


def test_load_sigma_rules_skips_disabled(tmp_path):
    disabled = VALID_SIGMA_YAML + "enabled: false\n"
    (tmp_path / "disabled.yml").write_text(disabled, encoding="utf-8")

    rules = load_sigma_rules_from_dir(str(tmp_path))
    assert len(rules) == 0


# ------------------------------------------------------------------ #
#  Gerçek SIGMA dosyaları testi
# ------------------------------------------------------------------ #

def test_real_sigma_rules_load():
    """config/sigma_rules/ dizinindeki tüm gerçek kurallar geçerli olmalı."""
    sigma_dir = Path(__file__).parent.parent / "config" / "sigma_rules"
    if not sigma_dir.exists():
        pytest.skip("config/sigma_rules/ dizini yok")

    rules = load_sigma_rules_from_dir(str(sigma_dir))
    yaml_files = list(sigma_dir.glob("**/*.y*ml"))

    assert len(rules) == len(yaml_files), (
        f"{len(yaml_files)} SIGMA dosyası var ama sadece {len(rules)} yüklendi"
    )
    assert len(rules) > 0, "Hiç SIGMA kuralı yüklenemedi"


def test_real_sigma_rule_ids_unique():
    """Gerçek SIGMA kurallarının rule_id'leri benzersiz olmalı."""
    sigma_dir = Path(__file__).parent.parent / "config" / "sigma_rules"
    if not sigma_dir.exists():
        pytest.skip("config/sigma_rules/ dizini yok")

    rules = load_sigma_rules_from_dir(str(sigma_dir))
    ids = [r.rule_id for r in rules]
    assert len(ids) == len(set(ids)), "Duplicate rule_id tespit edildi"


# ------------------------------------------------------------------ #
#  Windows kuralları + yeni parser özellikleri
# ------------------------------------------------------------------ #

def test_windows_rules_load(tmp_path):
    """keywords ve distinct_by içeren kurallar doğru parse edilmeli."""
    rule_yaml = textwrap.dedent("""\
        title: Windows Password Spray Test
        id: win_spray_test
        status: stable
        description: Test
        logsource:
            category: authentication
            product: windows
        detection:
            selection:
                event_type: windows_logon_failure
            condition: selection | count(distinct username) by src_ip > 5
            timeframe: 5m
        level: high
        tags:
            - attack.t1110.003
        falsepositives: []
    """)
    p = tmp_path / "win_spray.yml"
    p.write_text(rule_yaml, encoding="utf-8")
    rules = load_sigma_rules_from_dir(str(tmp_path))
    assert len(rules) == 1
    assert rules[0].distinct_by == "username"
    assert rules[0].rule_id == "win_spray_test"


def test_keywords_parsed_from_sigma(tmp_path):
    """selection.keywords listesi CorrelationRule.keywords'e aktarılmalı."""
    rule_yaml = textwrap.dedent("""\
        title: Suspicious Process Test
        id: suspicious_proc_test
        status: stable
        description: Test
        logsource:
            category: process_creation
            product: windows
        detection:
            selection:
                event_type: windows_process_create
                keywords:
                    - mimikatz
                    - lsass
            condition: selection | count() by source_host > 1
            timeframe: 5m
        level: critical
        falsepositives: []
    """)
    p = tmp_path / "sus_proc.yml"
    p.write_text(rule_yaml, encoding="utf-8")
    rules = load_sigma_rules_from_dir(str(tmp_path))
    assert len(rules) == 1
    assert rules[0].keywords == ["mimikatz", "lsass"]


def test_real_windows_sigma_rules_load():
    """Windows Sigma kuralları gerçek dosyadan yüklenebilmeli."""
    sigma_dir = Path(__file__).parent.parent / "config" / "sigma_rules"
    if not sigma_dir.exists():
        pytest.skip("config/sigma_rules/ dizini yok")
    rules = load_sigma_rules_from_dir(str(sigma_dir))
    rule_ids = {r.rule_id for r in rules}
    windows_rules = {
        "windows_brute_force",
        "windows_password_spray",
        "windows_suspicious_process",
        "windows_lateral_movement",
        "windows_pass_the_hash",
    }
    for rid in windows_rules:
        assert rid in rule_ids, f"Beklenen Windows kuralı bulunamadı: {rid}"

    spray = next(r for r in rules if r.rule_id == "windows_password_spray")
    assert spray.distinct_by == "username"

    sus = next(r for r in rules if r.rule_id == "windows_suspicious_process")
    assert sus.keywords is not None
    assert "mimikatz" in sus.keywords
