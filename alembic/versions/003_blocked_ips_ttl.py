"""Add expires_at column to blocked_ips."""
from alembic import op
import sqlalchemy as sa

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("blocked_ips", sa.Column("expires_at", sa.TIMESTAMP(timezone=True), nullable=True))
    op.create_index("idx_blocked_expires", "blocked_ips", ["expires_at"])


def downgrade() -> None:
    op.drop_index("idx_blocked_expires", table_name="blocked_ips")
    op.drop_column("blocked_ips", "expires_at")
