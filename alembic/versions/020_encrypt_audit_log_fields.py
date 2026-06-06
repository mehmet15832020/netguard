"""Encrypt audit_log.detail and audit_log.ip_address at rest (T2-2).

Revision ID: 020
Revises: 019
Create Date: 2026-06-06

audit_log.detail ve audit_log.ip_address Fernet (AES-128-CBC + HMAC-SHA256)
ile şifrelenir. Hash zinciri bütünlüğü korunur: SHA-256 plaintext üzerinden
hesaplanmıştır, şifreli değer yalnızca diskte saklanır.

NETGUARD_ENCRYPTION_KEY tanımlı değilse migration no-op olarak çalışır.

Kaynak: NIST SP 800-111 §4.2, CIS Controls v8.1 §3.11,
        OWASP Cryptographic Storage CS, KVKK m.12
"""

import logging
import os

from alembic import op
from sqlalchemy import text

revision = "020"
down_revision = "019"
branch_labels = None
depends_on = None

logger = logging.getLogger(__name__)

_KEY_ENV = "NETGUARD_ENCRYPTION_KEY"
_FERNET_PREFIX = "gAAAAA"


def _fernet():
    raw = os.environ.get(_KEY_ENV, "").strip()
    if not raw:
        return None
    from cryptography.fernet import Fernet
    return Fernet(raw.encode())


def _is_encrypted(value: str) -> bool:
    return value.startswith(_FERNET_PREFIX)


def upgrade():
    f = _fernet()
    if f is None:
        logger.warning(
            "%s tanımlı değil — audit_log.detail ve ip_address şifrelenmedi. "
            "Anahtarı set edip 'alembic upgrade head' tekrar çalıştırın.",
            _KEY_ENV,
        )
        return

    conn = op.get_bind()
    rows = conn.execute(
        text("SELECT id, detail, ip_address FROM audit_log")
    ).fetchall()

    updated = 0
    for row in rows:
        row_id, detail, ip_address = row[0], row[1], row[2]
        new_detail = detail
        new_ip = ip_address

        if detail and not _is_encrypted(detail):
            new_detail = f.encrypt(detail.encode()).decode()
        if ip_address and not _is_encrypted(ip_address):
            new_ip = f.encrypt(ip_address.encode()).decode()

        if new_detail != detail or new_ip != ip_address:
            conn.execute(
                text("UPDATE audit_log SET detail=:d, ip_address=:ip WHERE id=:id"),
                {"d": new_detail, "ip": new_ip, "id": row_id},
            )
            updated += 1

    logger.info("audit_log şifreleme tamamlandı: %d satır güncellendi", updated)


def downgrade():
    f = _fernet()
    if f is None:
        logger.warning("%s tanımlı değil — downgrade atlandı", _KEY_ENV)
        return

    conn = op.get_bind()
    rows = conn.execute(
        text("SELECT id, detail, ip_address FROM audit_log")
    ).fetchall()

    for row in rows:
        row_id, detail, ip_address = row[0], row[1], row[2]
        new_detail = detail
        new_ip = ip_address

        if detail and _is_encrypted(detail):
            new_detail = f.decrypt(detail.encode()).decode()
        if ip_address and _is_encrypted(ip_address):
            new_ip = f.decrypt(ip_address.encode()).decode()

        if new_detail != detail or new_ip != ip_address:
            conn.execute(
                text("UPDATE audit_log SET detail=:d, ip_address=:ip WHERE id=:id"),
                {"d": new_detail, "ip": new_ip, "id": row_id},
            )
