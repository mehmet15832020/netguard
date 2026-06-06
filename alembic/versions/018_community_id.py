"""normalized_logs.community_id kolonu — C1 NSM cross-source korelasyon.

Zeek + Suricata + NetFlow kayıtlarını aynı TCP bağlantısı üzerinden
pivot etmek için Corelight Community ID standardı (1:xxxx= formatı).

Revision ID: 018
Revises: 017
"""

from alembic import op

revision = "018"
down_revision = "017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("ALTER TABLE normalized_logs ADD COLUMN IF NOT EXISTS community_id VARCHAR(50)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_norm_logs_community_id ON normalized_logs (community_id) WHERE community_id IS NOT NULL")


def downgrade() -> None:
    op.execute("DROP INDEX IF EXISTS idx_norm_logs_community_id")
    op.execute("ALTER TABLE normalized_logs DROP COLUMN IF EXISTS community_id")
