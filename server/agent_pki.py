"""
NetGuard — Agent mTLS PKI (A3)

Agent'lara özel x509 client sertifikası üretir. CN=agent_id olacak şekilde
imzalanan bu sertifika, nginx'in ssl_verify_client doğrulamasından geçer ve
doğrulanmış CN backend'e X-SSL-Client-DN header'ı ile iletilir
(bkz. server/auth.py::get_agent_identity_verified, nginx/netguard.conf).

CA bir kez üretilir, diskte saklanır (AGENT_CA_DIR, varsayılan config/agent_ca/).
Her agent sertifikası bu CA ile imzalanır, varsayılan geçerlilik 90 gün
(NIST SP 800-204A §kısa ömürlü kimlik bilgisi önerisi).

Kaynak: NIST SP 800-204A (mTLS servis kimliği için de facto standart),
Wazuh agent identity verification (CN-bound client certificate modeli).
"""

import datetime
import logging
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)

DEFAULT_CA_DIR = "config/agent_ca"
CA_CERT_FILENAME = "ca.pem"
CA_KEY_FILENAME = "ca-key.pem"
DEFAULT_CERT_VALIDITY_DAYS = 90
_CA_KEY_SIZE = 2048


def _ca_dir() -> Path:
    return Path(os.getenv("AGENT_CA_DIR", DEFAULT_CA_DIR))


def ensure_ca() -> tuple[bytes, bytes]:
    """
    Agent CA'yı diskten yükler; yoksa üretir.
    Döndürür: (ca_cert_pem, ca_key_pem)
    """
    ca_dir = _ca_dir()
    cert_path = ca_dir / CA_CERT_FILENAME
    key_path = ca_dir / CA_KEY_FILENAME

    if cert_path.exists() and key_path.exists():
        return cert_path.read_bytes(), key_path.read_bytes()

    ca_dir.mkdir(parents=True, exist_ok=True)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=_CA_KEY_SIZE)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "TR"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetGuard"),
        x509.NameAttribute(NameOID.COMMON_NAME, "NetGuard Agent CA"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    key_pem = ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)
    os.chmod(key_path, 0o600)
    logger.info(f"Agent CA üretildi → {ca_dir}")
    return cert_pem, key_pem


def issue_agent_certificate(
    agent_id: str, validity_days: int = DEFAULT_CERT_VALIDITY_DAYS,
) -> tuple[bytes, bytes, str, str, "datetime.datetime"]:
    """
    agent_id'yi CN olarak taşıyan, CA ile imzalı client sertifikası üretir.
    Döndürür: (cert_pem, key_pem, serial_number_decimal, fingerprint_sha256_hex, expires_at)
    """
    ca_cert_pem, ca_key_pem = ensure_ca()
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

    agent_key = rsa.generate_private_key(public_exponent=65537, key_size=_CA_KEY_SIZE)
    subject = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetGuard"),
        x509.NameAttribute(NameOID.COMMON_NAME, agent_id),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    expires_at = now + datetime.timedelta(days=validity_days)

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(agent_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(expires_at)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = agent_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # Decimal string olarak saklanır — nginx $ssl_client_serial hex/renklendirme
    # farklarından (büyük/küçük harf, sıfır dolgu, ':' ayraçı) bağımsız karşılaştırma.
    serial_decimal = str(cert.serial_number)
    fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    return cert_pem, key_pem, serial_decimal, fingerprint, expires_at
