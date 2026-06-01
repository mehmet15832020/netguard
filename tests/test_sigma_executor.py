"""
sigma_executor testleri — pySigma kural yükleme, SQL üretimi, yürütme.
"""
import re
from pathlib import Path

import pytest

from server.sigma_executor import (
    SigmaExecutor, SigmaExecutableRule, _inject_time_window,
    _pg_ilike, _pg_escape_percent, _pg_fix_having,
)


# ------------------------------------------------------------------ #
#  _inject_time_window
# ------------------------------------------------------------------ #

def test_inject_into_correlation_subquery():
    sql = (
        "SELECT source_ip, COUNT(*) AS event_count "
        "FROM (SELECT * FROM normalized_logs WHERE event_action LIKE 'x') AS subquery "
        "GROUP BY source_ip HAVING event_count >= 5"
    )
    result = _inject_time_window(sql, 300)
    assert "timestamp >= NOW() - INTERVAL '300 seconds'" in result
    assert "AS subquery" in result


def test_inject_into_simple_detection():
    sql = "SELECT * FROM normalized_logs WHERE event_action LIKE 'ssh_failure'"
    result = _inject_time_window(sql, 60)
    assert "timestamp >= NOW() - INTERVAL '60 seconds'" in result
    assert result.endswith(result)


def test_inject_preserves_having_clause():
    sql = (
        "SELECT source_ip, COUNT(*) AS event_count "
        "FROM (SELECT * FROM normalized_logs WHERE event_action = 'fail') AS subquery "
        "GROUP BY source_ip HAVING event_count >= 10"
    )
    result = _inject_time_window(sql, 120)
    assert "HAVING event_count >= 10" in result


# ------------------------------------------------------------------ #
#  SigmaExecutor — dizin yükleme
# ------------------------------------------------------------------ #

def test_executor_loads_rules_from_dir(tmp_path: Path):
    """Gerçek sigma_rules_v2 dizininden kural yükleme."""
    rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
    ex = SigmaExecutor(str(rules_dir))
    assert len(ex.rules) >= 2  # en az port_scan + ssh_brute_force


def test_executor_empty_on_missing_dir(tmp_path: Path):
    ex = SigmaExecutor(str(tmp_path / "nonexistent"))
    assert ex.rules == []


def test_executor_correlation_rule_attributes(tmp_path: Path):
    rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
    ex = SigmaExecutor(str(rules_dir))
    corr_rules = [r for r in ex.rules if r.is_correlation]
    assert corr_rules, "En az bir correlation rule olmalı"
    for r in corr_rules:
        assert r.window_seconds > 0
        assert r.severity in ("info", "warning", "high", "critical")
        assert "normalized_logs" in r.sql
        assert "HAVING" in r.sql
        assert "NOW() - INTERVAL" in r.sql  # time window enjekte edildi


def test_executor_detection_rule_attributes(tmp_path: Path):
    rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
    ex = SigmaExecutor(str(rules_dir))
    det_rules = [r for r in ex.rules if not r.is_correlation]
    for r in det_rules:
        assert "normalized_logs" in r.sql
        assert "NOW() - INTERVAL" in r.sql


# ------------------------------------------------------------------ #
#  _pg_ilike
# ------------------------------------------------------------------ #

def test_pg_ilike_converts_like_to_ilike():
    sql = "SELECT * FROM normalized_logs WHERE message LIKE '%union select%' ESCAPE '\\'"
    result = _pg_ilike(sql)
    assert "ILIKE" in result
    assert "LIKE" not in result.replace("ILIKE", "")


def test_pg_ilike_handles_multiple_likes():
    sql = "WHERE event_action LIKE 'x' AND message LIKE '%y%'"
    result = _pg_ilike(sql)
    assert result.count("ILIKE") == 2
    assert "LIKE" not in result.replace("ILIKE", "")


def test_pg_ilike_preserves_having_and_subquery():
    sql = (
        "SELECT source_ip, COUNT(*) AS event_count "
        "FROM (SELECT * FROM normalized_logs WHERE event_action LIKE 'ssh_failure') AS subquery "
        "GROUP BY source_ip HAVING event_count >= 5"
    )
    result = _pg_ilike(sql)
    assert "ILIKE" in result
    assert "HAVING event_count >= 5" in result
    assert "AS subquery" in result


# ------------------------------------------------------------------ #
#  _pg_escape_percent
# ------------------------------------------------------------------ #

def test_pg_escape_percent_escapes_like_wildcards():
    sql = "WHERE message LIKE '%certificate%' ESCAPE '\\'"
    result = _pg_escape_percent(sql)
    assert "%%certificate%%" in result
    assert "'%certificate%'" not in result


def test_pg_escape_percent_handles_multiple():
    sql = "message LIKE '%union%' OR message LIKE '%drop%'"
    result = _pg_escape_percent(sql)
    assert result.count("%%") == 4


def test_pg_escape_percent_no_op_on_no_percent():
    sql = "WHERE event_action ILIKE 'ssh_failure'"
    assert _pg_escape_percent(sql) == sql


# ------------------------------------------------------------------ #
#  _pg_fix_having
# ------------------------------------------------------------------ #

def test_pg_fix_having_replaces_alias():
    sql = "GROUP BY source_ip HAVING event_count >= 5"
    result = _pg_fix_having(sql)
    assert "HAVING COUNT(*) >= 5" in result
    assert "event_count" not in result


def test_pg_fix_having_handles_gt():
    sql = "HAVING event_count > 100"
    result = _pg_fix_having(sql)
    assert "COUNT(*) > 100" in result


def test_pg_fix_having_preserves_group_by():
    sql = "GROUP BY source_ip HAVING event_count >= 10 ORDER BY source_ip"
    result = _pg_fix_having(sql)
    assert "GROUP BY source_ip" in result
    assert "COUNT(*) >= 10" in result


def test_pg_fix_having_no_op_when_count_already_used():
    sql = "GROUP BY source_ip HAVING COUNT(*) >= 5"
    result = _pg_fix_having(sql)
    assert result == sql


# ------------------------------------------------------------------ #
#  SigmaExecutor — SQL yürütme
# ------------------------------------------------------------------ #

def test_execute_correlation_rule_returns_match(mem_db):
    """5 dakika içinde 5+ ssh_failure → satır döner."""
    for i in range(6):
        mem_db.execute(
            "INSERT INTO normalized_logs "
            "(log_id, source_type, timestamp, event_action, source_ip, message) "
            "VALUES (%s, 'syslog', NOW() - INTERVAL '1 minutes', 'ssh_failure', '1.2.3.4', 'SSH fail')",
            (f"log-{i}",),
        )
    mem_db.commit()

    rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
    ex = SigmaExecutor(str(rules_dir))
    ssh_rule = next((r for r in ex.rules if r.title == "SSH Brute Force"), None)
    assert ssh_rule is not None

    rows = ex.execute_rule(ssh_rule, mem_db)
    assert len(rows) == 1
    assert rows[0]["group_value"] == "1.2.3.4"
    assert rows[0]["event_count"] >= 5


def test_execute_correlation_rule_no_match_below_threshold(mem_db):
    """Eşiğin altında → boş liste."""
    for i in range(3):
        mem_db.execute(
            "INSERT INTO normalized_logs "
            "(log_id, source_type, timestamp, event_action, source_ip, message) "
            "VALUES (%s, 'syslog', NOW() - INTERVAL '1 minutes', 'ssh_failure', '1.2.3.4', 'SSH fail')",
            (f"log-{i}",),
        )
    mem_db.commit()

    rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
    ex = SigmaExecutor(str(rules_dir))
    ssh_rule = next((r for r in ex.rules if r.title == "SSH Brute Force"), None)
    assert ssh_rule is not None

    rows = ex.execute_rule(ssh_rule, mem_db)
    assert rows == []


def test_execute_detection_rule_wildcard_match(mem_db):
    """SQL injection LIKE sorgusu — mesaj içinde anahtar kelime varsa eşleşir."""
    mem_db.execute(
        "INSERT INTO normalized_logs "
        "(log_id, source_type, timestamp, event_action, source_ip, message) "
        "VALUES ('x1', 'syslog', NOW() - INTERVAL '10 seconds', 'web_request', '5.6.7.8', "
        "'GET /search?q=union select * FROM users')"
    )
    mem_db.commit()

    rules_dir = Path(__file__).parent.parent / "config" / "sigma_rules_v2"
    ex = SigmaExecutor(str(rules_dir))
    sqli_rule = next((r for r in ex.rules if "injection" in r.title.lower()), None)
    assert sqli_rule is not None

    rows = ex.execute_rule(sqli_rule, mem_db)
    assert len(rows) == 1


def test_output_event_action_generated():
    """output_event_action title'dan otomatik üretilmeli."""
    r = SigmaExecutableRule(
        rule_id="x", title="My Test Rule",
        severity="high", sql="SELECT 1",
        window_seconds=60, group_by_fields=[],
        is_correlation=False
    )
    assert r.output_event_action == "my_test_rule_detected"
