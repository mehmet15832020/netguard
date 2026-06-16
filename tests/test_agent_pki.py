"""
A3 — server/agent_pki.py testleri.

CA üretimi (idempotent), agent sertifikası imzalama (CN doğru, CA tarafından
imzalanmış, geçerlilik süresi), serial/fingerprint tutarlılığı.
"""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import NameOID

from server import agent_pki


@pytest.fixture(autouse=True)
def isolated_ca_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENT_CA_DIR", str(tmp_path / "agent_ca"))


class TestEnsureCa:
    def test_creates_ca_files_on_first_call(self, tmp_path):
        cert_pem, key_pem = agent_pki.ensure_ca()
        ca_dir = tmp_path / "agent_ca"
        assert (ca_dir / agent_pki.CA_CERT_FILENAME).exists()
        assert (ca_dir / agent_pki.CA_KEY_FILENAME).exists()
        assert cert_pem.startswith(b"-----BEGIN CERTIFICATE-----")

    def test_idempotent_returns_same_ca(self):
        cert1, key1 = agent_pki.ensure_ca()
        cert2, key2 = agent_pki.ensure_ca()
        assert cert1 == cert2
        assert key1 == key2

    def test_ca_cert_is_self_signed_with_cert_sign_usage(self):
        cert_pem, _ = agent_pki.ensure_ca()
        cert = x509.load_pem_x509_certificate(cert_pem)
        assert cert.issuer == cert.subject
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        assert key_usage.key_cert_sign is True

    def test_key_file_permissions_restricted(self, tmp_path):
        agent_pki.ensure_ca()
        key_path = tmp_path / "agent_ca" / agent_pki.CA_KEY_FILENAME
        mode = key_path.stat().st_mode & 0o777
        assert mode == 0o600


class TestIssueAgentCertificate:
    def test_cn_matches_agent_id(self):
        cert_pem, _, _, _, _ = agent_pki.issue_agent_certificate("agent-007")
        cert = x509.load_pem_x509_certificate(cert_pem)
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert cn == "agent-007"

    def test_signed_by_ca(self):
        ca_cert_pem, _ = agent_pki.ensure_ca()
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)

        cert_pem, _, _, _, _ = agent_pki.issue_agent_certificate("agent-008")
        cert = x509.load_pem_x509_certificate(cert_pem)
        assert cert.issuer == ca_cert.subject

        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )

    def test_validity_period_matches_requested_days(self):
        cert_pem, _, _, _, expires_at = agent_pki.issue_agent_certificate("agent-009", validity_days=30)
        cert = x509.load_pem_x509_certificate(cert_pem)
        delta = cert.not_valid_after_utc - cert.not_valid_before_utc
        assert 29 <= delta.days <= 30
        assert abs((expires_at - cert.not_valid_after_utc).total_seconds()) < 2

    def test_default_validity_is_90_days(self):
        _, _, _, _, expires_at = agent_pki.issue_agent_certificate("agent-010")
        now = datetime.datetime.now(datetime.timezone.utc)
        assert 88 <= (expires_at - now).days <= 90

    def test_serial_is_decimal_string(self):
        _, _, serial, _, _ = agent_pki.issue_agent_certificate("agent-011")
        assert serial.isdigit()

    def test_fingerprint_is_sha256_hex(self):
        _, _, _, fingerprint, _ = agent_pki.issue_agent_certificate("agent-012")
        assert len(fingerprint) == 64
        int(fingerprint, 16)  # ValueError fırlatmazsa hex'tir

    def test_two_issuances_have_different_serials(self):
        _, _, serial1, _, _ = agent_pki.issue_agent_certificate("agent-013")
        _, _, serial2, _, _ = agent_pki.issue_agent_certificate("agent-013")
        assert serial1 != serial2
