"""
A2 — agent/tls_config.resolve_tls_verify() testleri.

Agent HTTP client'larının (MetricSender, LogShipper) sunucu sertifikasını
varsayılan olarak doğruladığını, özel CA bundle desteklediğini ve
doğrulamayı kapatmanın açıkça uyarıldığını garanti eder.
"""

import logging

import pytest

from agent.tls_config import resolve_tls_verify


class TestResolveTlsVerify:
    def test_defaults_to_true_when_no_env_set(self, monkeypatch):
        monkeypatch.delenv("NETGUARD_CA_BUNDLE", raising=False)
        monkeypatch.delenv("NETGUARD_VERIFY_TLS", raising=False)
        assert resolve_tls_verify() is True

    def test_ca_bundle_env_takes_priority(self, monkeypatch):
        monkeypatch.setenv("NETGUARD_CA_BUNDLE", "/etc/netguard/ca.pem")
        monkeypatch.setenv("NETGUARD_VERIFY_TLS", "false")
        assert resolve_tls_verify() == "/etc/netguard/ca.pem"

    def test_verify_tls_false_disables_verification(self, monkeypatch):
        monkeypatch.delenv("NETGUARD_CA_BUNDLE", raising=False)
        monkeypatch.setenv("NETGUARD_VERIFY_TLS", "false")
        assert resolve_tls_verify() is False

    def test_verify_tls_false_logs_warning(self, monkeypatch, caplog):
        monkeypatch.delenv("NETGUARD_CA_BUNDLE", raising=False)
        monkeypatch.setenv("NETGUARD_VERIFY_TLS", "false")
        with caplog.at_level(logging.WARNING, logger="agent.tls_config"):
            resolve_tls_verify()
        assert "MITM" in caplog.text

    def test_verify_tls_true_explicit_no_warning(self, monkeypatch, caplog):
        monkeypatch.delenv("NETGUARD_CA_BUNDLE", raising=False)
        monkeypatch.setenv("NETGUARD_VERIFY_TLS", "true")
        with caplog.at_level(logging.WARNING, logger="agent.tls_config"):
            result = resolve_tls_verify()
        assert result is True
        assert caplog.text == ""
