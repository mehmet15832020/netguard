"""Add TOTP columns to db_users.

Revision ID: 010
Revises: 009
Create Date: 2026-05-23

TOTP (Time-based One-Time Password) MFA desteği için db_users tablosuna
totp_secret ve totp_enabled kolonları eklenir.
"""

import sqlalchemy as sa
from alembic import op

revision = "010"
down_revision = "009"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("db_users", sa.Column("totp_secret", sa.Text(), nullable=True))
    op.add_column(
        "db_users",
        sa.Column("totp_enabled", sa.Integer(), server_default="0", nullable=False),
    )


def downgrade():
    op.drop_column("db_users", "totp_enabled")
    op.drop_column("db_users", "totp_secret")
