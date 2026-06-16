"""Agent mTLS sertifika kayıtları (A3).

Revision ID: 022
Revises: 021
Create Date: 2026-06-16

Her agent'a verilen client sertifikasının metadata'sını saklar — özel anahtar
DB'ye yazılmaz, sadece üretim anında agent'a bir kez gösterilir. Bu tablo
iptal (revocation) ve süre kontrolü için kullanılır.

Kaynak: NIST SP 800-204A (kimlik bilgisi iptal edilebilirliği)
"""

from alembic import op
from sqlalchemy import text

revision = "022"
down_revision = "021"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE TABLE IF NOT EXISTS agent_certificates (
            id              SERIAL PRIMARY KEY,
            agent_id        TEXT NOT NULL,
            serial_number   TEXT NOT NULL,
            fingerprint_sha256 TEXT NOT NULL,
            issued_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            expires_at      TIMESTAMPTZ NOT NULL,
            revoked_at      TIMESTAMPTZ,
            UNIQUE (agent_id, serial_number)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_agent_certificates_agent_id ON agent_certificates (agent_id)")


def downgrade():
    op.execute("DROP TABLE IF EXISTS agent_certificates CASCADE")
