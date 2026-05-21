"""
Network Intelligence API — birim + entegrasyon testleri.
GET /api/v1/network/intelligence
"""
import uuid
from datetime import datetime, timezone, timedelta

import pytest
from fastapi.testclient import TestClient
from server.main import app

# Modül düzeyinde client — lifespan tetiklenmez (port çakışması yok)
_client = TestClient(app)


# ─────────────────────────────────────────────────────────────────────────────
#  Fixture — izole DB + test client
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def client(tmp_db, admin_token):
    """tmp_db ile monkeypatch yapılmış izole test istemcisi."""
    _client.headers.update({"Authorization": f"Bearer {admin_token}"})
    yield _client
    _client.headers.pop("Authorization", None)


def _insert_log(tmp_db, event_action, source_ip="1.2.3.4",
                severity="info", minutes_ago=5,
                destination_ip=None, message="test"):
    with tmp_db._connect() as conn:
        conn.execute(
            """
            INSERT INTO normalized_logs
              (log_id, raw_id, source_type, observer_hostname,
               timestamp, received_at, processed_at, severity, event_category,
               event_action, source_ip, destination_ip,
               message, tags, tenant_id)
            VALUES (?, ?, 'zeek', 'zeek',
                    datetime('now', ?), datetime('now', ?), datetime('now'),
                    ?, 'network',
                    ?, ?, ?,
                    ?, '[]', 'default')
            """,
            (
                str(uuid.uuid4()), str(uuid.uuid4()),
                f"-{minutes_ago} minutes", f"-{minutes_ago} minutes",
                severity, event_action,
                source_ip, destination_ip or source_ip,
                message,
            ),
        )


# ─────────────────────────────────────────────────────────────────────────────
#  1. API — temel yanıt yapısı
# ─────────────────────────────────────────────────────────────────────────────

class TestNetworkIntelAPI:
    def test_endpoint_exists_and_returns_200(self, client):
        resp = client.get("/api/v1/network/intelligence")
        assert resp.status_code == 200

    def test_response_has_required_keys(self, client):
        resp = client.get("/api/v1/network/intelligence")
        data = resp.json()
        required = {
            "hours", "summary", "zeek_distribution",
            "ja3_suspicious", "ssl_anomalies", "self_signed_certs",
            "ftp_sensitive", "smtp_sessions", "top_sources",
            "dns_top", "timeline",
        }
        assert required.issubset(data.keys())

    def test_summary_has_all_counters(self, client):
        resp = client.get("/api/v1/network/intelligence")
        summary = resp.json()["summary"]
        required = {
            "ja3_suspicious_count", "ssl_anomaly_count", "self_signed_cert_count",
            "ftp_sensitive_count", "smtp_session_count", "zeek_total_24h",
        }
        assert required.issubset(summary.keys())

    def test_empty_db_returns_zeros(self, client):
        resp = client.get("/api/v1/network/intelligence")
        summary = resp.json()["summary"]
        assert summary["ja3_suspicious_count"] == 0
        assert summary["zeek_total_24h"] == 0

    def test_hours_param_accepted(self, client):
        for h in [1, 6, 24, 48]:
            resp = client.get(f"/api/v1/network/intelligence?hours={h}")
            assert resp.status_code == 200
            assert resp.json()["hours"] == h

    def test_invalid_hours_clamped(self, client):
        resp = client.get("/api/v1/network/intelligence?hours=999")
        assert resp.status_code == 200

    def test_requires_auth(self):
        c = TestClient(app)
        resp = c.get("/api/v1/network/intelligence")
        assert resp.status_code == 401


# ─────────────────────────────────────────────────────────────────────────────
#  2. TLS şüpheli parmak izi tespiti (JA4 birincil, JA3 legacy)
# ─────────────────────────────────────────────────────────────────────────────

class TestJA3Detection:
    def test_ja3_suspicious_count(self, client, tmp_db):
        for _ in range(3):
            _insert_log(
                tmp_db, "tls_suspicious_fingerprint",
                source_ip="10.0.0.5",
                severity="critical",
                message="SSL/TLS c2.evil.com JA3=eb989049… [KNOWN_MALWARE_JA3]",
            )

        resp = client.get("/api/v1/network/intelligence")
        data = resp.json()
        assert data["summary"]["ja3_suspicious_count"] == 3
        assert len(data["ja3_suspicious"]) == 3

    def test_ja3_event_has_source_ip(self, client, tmp_db):
        _insert_log(
            tmp_db, "tls_suspicious_fingerprint",
            source_ip="185.220.101.45",
            message="SSL/TLS bad [KNOWN_MALWARE_JA3]",
        )

        resp = client.get("/api/v1/network/intelligence")
        events = resp.json()["ja3_suspicious"]
        assert len(events) >= 1
        assert any(e["source_ip"] == "185.220.101.45" for e in events)

    def test_normal_ssl_not_in_ja3_suspicious(self, client, tmp_db):
        _insert_log(
            tmp_db, "ssl_connection",
            source_ip="10.0.0.1",
            severity="info",
            message="SSL/TLS google.com",
        )

        resp = client.get("/api/v1/network/intelligence")
        assert resp.json()["summary"]["ja3_suspicious_count"] == 0

    def test_ja4_detection_appears_in_list(self, client, tmp_db):
        _insert_log(
            tmp_db, "tls_suspicious_fingerprint",
            source_ip="5.6.7.8",
            severity="critical",
            message="SSL/TLS c2.evil.com JA4=t13d1516h2_8daaf… [KNOWN_MALWARE_JA4]",
        )

        resp = client.get("/api/v1/network/intelligence")
        data = resp.json()
        assert data["summary"]["ja3_suspicious_count"] >= 1
        ja4_events = [e for e in data["ja3_suspicious"] if e["fingerprint_type"] == "ja4"]
        assert len(ja4_events) >= 1

    def test_fingerprint_type_ja3_for_ja3_events(self, client, tmp_db):
        _insert_log(
            tmp_db, "tls_suspicious_fingerprint",
            source_ip="5.6.7.9",
            severity="critical",
            message="SSL/TLS malware.com JA3=eb989049… [KNOWN_MALWARE_JA3]",
        )

        resp = client.get("/api/v1/network/intelligence")
        events = resp.json()["ja3_suspicious"]
        ja3_events = [e for e in events if e["source_ip"] == "5.6.7.9"]
        assert len(ja3_events) >= 1
        assert ja3_events[0]["fingerprint_type"] == "ja3"

    def test_fingerprint_type_ja4_for_ja4_events(self, client, tmp_db):
        _insert_log(
            tmp_db, "tls_suspicious_fingerprint",
            source_ip="5.6.7.10",
            severity="critical",
            message="SSL/TLS c2.evil.com JA4=t13d1516h2_8daaf… [KNOWN_MALWARE_JA4]",
        )

        resp = client.get("/api/v1/network/intelligence")
        events = resp.json()["ja3_suspicious"]
        ja4_events = [e for e in events if e["source_ip"] == "5.6.7.10"]
        assert len(ja4_events) >= 1
        assert ja4_events[0]["fingerprint_type"] == "ja4"

    def test_bad_ja3_with_normal_ja4_fingerprint_type_ja3(self, client, tmp_db):
        """bad_ja3 + normal_ja4 senaryosu: route 'ja3' döndürmeli."""
        _insert_log(
            tmp_db, "tls_suspicious_fingerprint",
            source_ip="5.6.7.11",
            severity="critical",
            message="SSL/TLS c2.evil.com JA4=t13d1234h2_aabbcc… JA3=eb989049…[KNOWN_MALWARE_JA3]",
        )

        resp = client.get("/api/v1/network/intelligence")
        events = resp.json()["ja3_suspicious"]
        matched = [e for e in events if e["source_ip"] == "5.6.7.11"]
        assert len(matched) >= 1
        assert matched[0]["fingerprint_type"] == "ja3"

    def test_e2e_parse_ssl_to_route_ja4(self, client, tmp_db):
        """parse_ssl → log → route: gerçek parser çıktısından fingerprint_type doğrula."""
        from server.parsers.zeek import parse_ssl, _KNOWN_BAD_JA4
        bad_ja4 = next(iter(_KNOWN_BAD_JA4))
        row = {
            "ts": 1700000000.0, "id.orig_h": "9.8.7.6", "id.resp_h": "203.0.113.1",
            "id.resp_p": 443, "server_name": "c2.evil.example", "subject": "",
            "validation_status": "ok", "ja4": bad_ja4,
        }
        log = parse_ssl(row)
        assert log is not None
        assert log.event_action == "tls_suspicious_fingerprint"

        _insert_log(
            tmp_db, log.event_action,
            source_ip="9.8.7.6",
            severity=log.severity,
            message=log.message,
        )

        resp = client.get("/api/v1/network/intelligence")
        events = resp.json()["ja3_suspicious"]
        matched = [e for e in events if e["source_ip"] == "9.8.7.6"]
        assert len(matched) >= 1
        assert matched[0]["fingerprint_type"] == "ja4"


# ─────────────────────────────────────────────────────────────────────────────
#  3. SSL Anomali tespiti
# ─────────────────────────────────────────────────────────────────────────────

class TestSSLAnomalyDetection:
    def test_ssl_warning_counted(self, client, tmp_db):
        _insert_log(
            tmp_db, "ssl_connection",
            source_ip="10.0.0.2",
            severity="warning",
            message="SSL/TLS bad.local (certificate has expired)",
        )

        resp = client.get("/api/v1/network/intelligence")
        data = resp.json()
        assert data["summary"]["ssl_anomaly_count"] >= 1
        events = data["ssl_anomalies"]
        assert any("10.0.0.2" == e["source_ip"] for e in events)

    def test_ssl_info_not_in_anomalies(self, client, tmp_db):
        _insert_log(
            tmp_db, "ssl_connection",
            severity="info",
            message="SSL/TLS github.com",
        )

        resp = client.get("/api/v1/network/intelligence")
        assert resp.json()["summary"]["ssl_anomaly_count"] == 0


# ─────────────────────────────────────────────────────────────────────────────
#  4. x509 Self-Signed
# ─────────────────────────────────────────────────────────────────────────────

class TestX509Detection:
    def test_self_signed_counted(self, client, tmp_db):
        for _ in range(2):
            _insert_log(
                tmp_db, "x509_certificate",
                source_ip=None,
                severity="warning",
                message="X.509 cert: CN=evil.local [SELF-SIGNED]",
            )

        resp = client.get("/api/v1/network/intelligence")
        assert resp.json()["summary"]["self_signed_cert_count"] == 2

    def test_normal_x509_not_counted(self, client, tmp_db):
        _insert_log(
            tmp_db, "x509_certificate",
            severity="info",
            message="X.509 cert: api.github.com issued by DigiCert",
        )

        resp = client.get("/api/v1/network/intelligence")
        assert resp.json()["summary"]["self_signed_cert_count"] == 0


# ─────────────────────────────────────────────────────────────────────────────
#  5. FTP + SMTP
# ─────────────────────────────────────────────────────────────────────────────

class TestFTPSMTPDetection:
    def test_ftp_sensitive_counted(self, client, tmp_db):
        _insert_log(
            tmp_db, "ftp_command",
            source_ip="10.0.0.100",
            severity="warning",
            message="FTP RETR user=anon arg=secrets.zip",
        )

        resp = client.get("/api/v1/network/intelligence")
        assert resp.json()["summary"]["ftp_sensitive_count"] >= 1

    def test_smtp_session_counted(self, client, tmp_db):
        for _ in range(5):
            _insert_log(
                tmp_db, "smtp_session",
                source_ip="10.0.0.10",
                message="SMTP from=bot@spam.com to=victim@co.com subj=Invoice",
            )

        resp = client.get("/api/v1/network/intelligence")
        assert resp.json()["summary"]["smtp_session_count"] == 5


# ─────────────────────────────────────────────────────────────────────────────
#  6. Zeek dağılımı + top sources + timeline
# ─────────────────────────────────────────────────────────────────────────────

class TestZeekAggregations:
    def test_zeek_distribution_populated(self, client, tmp_db):
        for action in ["dns_query", "dns_query", "ssl_connection", "ftp_command"]:
            _insert_log(tmp_db, action, source_ip="10.0.0.1")

        resp = client.get("/api/v1/network/intelligence")
        dist = resp.json()["zeek_distribution"]
        assert dist.get("dns_query", 0) == 2
        assert dist.get("ssl_connection", 0) == 1

    def test_top_sources_ranked(self, client, tmp_db):
        for _ in range(5):
            _insert_log(tmp_db, "ssl_connection", source_ip="192.168.1.100")
        for _ in range(2):
            _insert_log(tmp_db, "dns_query", source_ip="192.168.1.200")

        resp = client.get("/api/v1/network/intelligence")
        sources = resp.json()["top_sources"]
        assert len(sources) >= 2
        assert sources[0]["count"] >= sources[1]["count"]

    def test_timeline_grouped_by_hour(self, client, tmp_db):
        for _ in range(3):
            _insert_log(tmp_db, "dns_query", source_ip="10.0.0.1", minutes_ago=10)

        resp = client.get("/api/v1/network/intelligence")
        timeline = resp.json()["timeline"]
        assert len(timeline) >= 1
        total = sum(t["v"] for t in timeline)
        assert total >= 3

    def test_zeek_total_24h_matches_sum(self, client, tmp_db):
        for action in ["dns_query", "ssl_connection", "ftp_command"]:
            _insert_log(tmp_db, action, source_ip="10.0.0.1")

        resp = client.get("/api/v1/network/intelligence")
        data = resp.json()
        dist_total = sum(data["zeek_distribution"].values())
        assert data["summary"]["zeek_total_24h"] == dist_total
