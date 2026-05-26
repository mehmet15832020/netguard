"""Encrypt existing TOTP secrets at rest (T2-2).

Revision ID: 012
Revises: 011
Create Date: 2026-05-26

Mevcut plaintext totp_secret değerlerini Fernet ile şifreler.
NETGUARD_ENCRYPTION_KEY env tanımlı değilse migration atlanır (no-op).

Kaynak: OWASP Cryptographic Storage CS, NIST SP 800-111, CIS Controls v8.1 §3.11
"""

import logging
import os

from alembic import op
import sqlalchemy as sa
from sqlalchemy import text

revision = "012"
down_revision = "011"
branch_labels = None
depends_on = None

logger = logging.getLogger(__name__)

_KEY_ENV = "NETGUARD_ENCRYPTION_KEY"


def _fernet():
    raw = os.environ.get(_KEY_ENV)
    if not raw:
        return None
    from cryptography.fernet import Fernet
    return Fernet(raw.strip().encode())


def upgrade():
    f = _fernet()
    if f is None:
        logger.warning(
            "%s tanımlı değil — mevcut totp_secret'lar şifrelenmedi. "
            "Anahtarı set edip 'alembic upgrade head' tekrar çalıştırın.",
            _KEY_ENV,
        )
        return

    conn = op.get_bind()
    rows = conn.execute(
        text("SELECT username, totp_secret FROM db_users WHERE totp_secret IS NOT NULL")
    ).fetchall()

    encrypted_count = 0
    for row in rows:
        username, secret = row[0], row[1]
        if not secret:
            continue
        try:
            f.decrypt(secret.encode())
            continue
        except Exception:
            pass
        encrypted = f.encrypt(secret.encode()).decode()
        conn.execute(
            text("UPDATE db_users SET totp_secret = :s WHERE username = :u"),
            {"s": encrypted, "u": username},
        )
        encrypted_count += 1

    logger.info("TOTP şifreleme tamamlandı: %d kullanıcı güncellendi", encrypted_count)


def downgrade():
    f = _fernet()
    if f is None:
        logger.warning("%s tanımlı değil — downgrade atlandı", _KEY_ENV)
        return

    conn = op.get_bind()
    rows = conn.execute(
        text("SELECT username, totp_secret FROM db_users WHERE totp_secret IS NOT NULL")
    ).fetchall()

    for row in rows:
        username, secret = row[0], row[1]
        if not secret:
            continue
        try:
            plaintext = f.decrypt(secret.encode()).decode()
            conn.execute(
                text("UPDATE db_users SET totp_secret = :s WHERE username = :u"),
                {"s": plaintext, "u": username},
            )
        except Exception:
            pass
