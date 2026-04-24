"""Web server log parser testleri — nginx/Apache Combined + nginx error."""

import pytest
from server.parsers.web_log import parse_access_log, parse_nginx_error, detect_and_parse

# ── Örnek log satırları ──────────────────────────────────────────────────────

NGINX_200 = (
    '1.2.3.4 - - [24/Apr/2024:10:00:01 +0000] '
    '"GET /index.html HTTP/1.1" 200 1234 '
    '"-" "Mozilla/5.0"'
)

NGINX_404 = (
    '5.6.7.8 - - [24/Apr/2024:10:00:02 +0000] '
    '"GET /nonexistent HTTP/1.1" 404 162 '
    '"-" "curl/7.88.1"'
)

NGINX_401 = (
    '9.10.11.12 - admin [24/Apr/2024:10:00:03 +0000] '
    '"POST /api/login HTTP/1.1" 401 45 '
    '"-" "python-requests/2.28"'
)

NGINX_403 = (
    '13.14.15.16 - - [24/Apr/2024:10:00:04 +0000] '
    '"GET /admin HTTP/1.1" 403 153 '
    '"-" "Nikto/2.1.6"'
)

NGINX_500 = (
    '192.168.1.100 - - [24/Apr/2024:10:00:05 +0000] '
    '"POST /api/data HTTP/1.1" 500 89 '
    '"-" "python-requests/2.28"'
)

APACHE_200 = (
    '10.0.0.5 - frank [24/Apr/2024:10:00:06 +0000] '
    '"GET /report.pdf HTTP/1.1" 200 51200 '
    '"http://example.com" "Mozilla/5.0"'
)

NGINX_ERROR = (
    '2024/04/24 10:00:07 [error] 1234#1234: *1 '
    'connect() failed (111: Connection refused) while connecting to upstream, '
    'client: 1.2.3.4, server: example.com'
)

NGINX_WARN = (
    '2024/04/24 10:00:08 [warn] 1234#1234: *2 '
    'upstream server temporarily disabled while connecting to upstream, '
    'client: 5.6.7.8, server: example.com'
)

INVALID = "this is not a web log line at all"


class TestAccessLogParser:
    def test_200_parsed(self):
        log = parse_access_log(NGINX_200)
        assert log is not None
        assert log.event_type == "web_request"
        assert log.severity == "info"
        assert log.src_ip == "1.2.3.4"

    def test_404_is_client_error(self):
        log = parse_access_log(NGINX_404)
        assert log is not None
        assert log.event_type == "web_client_error"
        assert log.severity == "info"
        assert log.src_ip == "5.6.7.8"

    def test_401_is_auth_fail(self):
        log = parse_access_log(NGINX_401)
        assert log is not None
        assert log.event_type == "web_auth_fail"
        assert log.severity == "warning"

    def test_403_is_auth_fail(self):
        log = parse_access_log(NGINX_403)
        assert log is not None
        assert log.event_type == "web_auth_fail"
        assert log.severity == "warning"

    def test_500_is_server_error(self):
        log = parse_access_log(NGINX_500)
        assert log is not None
        assert log.event_type == "web_server_error"
        assert log.severity == "warning"

    def test_username_extracted(self):
        log = parse_access_log(NGINX_401)
        assert log.username == "admin"

    def test_dash_username_is_none(self):
        log = parse_access_log(NGINX_200)
        assert log.username is None

    def test_extra_fields(self):
        log = parse_access_log(NGINX_200)
        assert log.extra["method"] == "GET"
        assert log.extra["path"] == "/index.html"
        assert log.extra["status"] == 200

    def test_protocol_extracted(self):
        log = parse_access_log(NGINX_200)
        assert log.protocol == "http"

    def test_source_type_nginx(self):
        log = parse_access_log(NGINX_200)
        assert log.source_type == "nginx"

    def test_apache_combined_parsed(self):
        log = parse_access_log(APACHE_200)
        assert log is not None
        assert log.event_type == "web_request"
        assert log.src_ip == "10.0.0.5"
        assert log.username == "frank"

    def test_referer_and_ua_in_extra(self):
        log = parse_access_log(APACHE_200)
        assert log.extra["referer"] == "http://example.com"
        assert "Mozilla" in log.extra["user_agent"]

    def test_invalid_returns_none(self):
        assert parse_access_log(INVALID) is None

    def test_message_format(self):
        log = parse_access_log(NGINX_200)
        assert "GET" in log.message
        assert "200" in log.message

    def test_source_host_passed(self):
        log = parse_access_log(NGINX_200, source_host="web-server-01")
        assert log.source_host == "web-server-01"


class TestNginxErrorParser:
    def test_error_parsed(self):
        log = parse_nginx_error(NGINX_ERROR)
        assert log is not None
        assert log.event_type == "web_error"
        assert log.severity == "high"

    def test_warn_severity(self):
        log = parse_nginx_error(NGINX_WARN)
        assert log is not None
        assert log.severity == "warning"

    def test_client_ip_extracted(self):
        log = parse_nginx_error(NGINX_ERROR)
        assert log.src_ip == "1.2.3.4"

    def test_message_contains_level(self):
        log = parse_nginx_error(NGINX_ERROR)
        assert "[error]" in log.message

    def test_extra_fields(self):
        log = parse_nginx_error(NGINX_ERROR)
        assert log.extra["level"] == "error"
        assert "connect() failed" in log.extra["raw_msg"]

    def test_invalid_returns_none(self):
        assert parse_nginx_error(INVALID) is None

    def test_source_type_nginx(self):
        log = parse_nginx_error(NGINX_ERROR)
        assert log.source_type == "nginx"


class TestAutoDetect:
    def test_detects_access_log(self):
        log = detect_and_parse(NGINX_200)
        assert log is not None
        assert log.event_type == "web_request"

    def test_detects_nginx_error(self):
        log = detect_and_parse(NGINX_ERROR)
        assert log is not None
        assert log.event_type == "web_error"

    def test_unknown_returns_none(self):
        assert detect_and_parse(INVALID) is None

    def test_empty_returns_none(self):
        assert detect_and_parse("") is None
        assert detect_and_parse("   ") is None
