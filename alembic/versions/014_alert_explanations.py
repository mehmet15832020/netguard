"""alert_explanations tablosu — F4 AI Alert Explainer cache.

Correlated event başına AI açıklaması 24 saat DB cache'de tutulur.
Tenant isolation: (corr_id, tenant_id) UNIQUE.

Revision ID: 014
Revises: 013
"""

from alembic import op
import sqlalchemy as sa

revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
        CREATE TABLE IF NOT EXISTS alert_explanations (
            id          SERIAL PRIMARY KEY,
            corr_id     TEXT NOT NULL,
            tenant_id   TEXT NOT NULL,
            explanation TEXT NOT NULL,
            model       TEXT NOT NULL DEFAULT 'claude-haiku-4-5-20251001',
            input_tokens  INTEGER NOT NULL DEFAULT 0,
            output_tokens INTEGER NOT NULL DEFAULT 0,
            created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (corr_id, tenant_id)
        )
    """)
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_alert_explanations_corr_tenant "
        "ON alert_explanations (corr_id, tenant_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_alert_explanations_created "
        "ON alert_explanations (created_at DESC)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS alert_explanations")
