"""Add SHA-256 hash chain columns to audit_log.

Revision ID: 006
Revises: 005
Create Date: 2026-05-21

NIST SP 800-92 §3.2 + NIS2 Article 21(2)(i): Tamperproof audit log.
previous_hash → önceki kaydın entry_hash'i (genesis: "0"*64)
entry_hash    → SHA-256(event_id|actor|action|resource|detail|ip_address|timestamp|previous_hash)
"""

from alembic import op
import sqlalchemy as sa

revision = "006"
down_revision = "005"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("audit_log", sa.Column("previous_hash", sa.Text(), nullable=True))
    op.add_column("audit_log", sa.Column("entry_hash", sa.Text(), nullable=True))
    op.create_index("idx_audit_entry_hash", "audit_log", ["entry_hash"])


def downgrade():
    op.drop_index("idx_audit_entry_hash", table_name="audit_log")
    op.drop_column("audit_log", "entry_hash")
    op.drop_column("audit_log", "previous_hash")
