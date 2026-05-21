"""Add Feodo/ThreatFox/GreyNoise columns to threat_intel_cache.

Revision ID: 005
Revises: 004
Create Date: 2026-05-21
"""

from alembic import op
import sqlalchemy as sa

revision = "005"
down_revision = "004"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
        "threat_intel_cache",
        sa.Column("feodo_listed", sa.Boolean(), server_default="false", nullable=False),
    )
    op.add_column(
        "threat_intel_cache",
        sa.Column("feodo_malware", sa.Text(), nullable=True),
    )
    op.add_column(
        "threat_intel_cache",
        sa.Column("threatfox_score", sa.Integer(), server_default="0", nullable=False),
    )
    op.add_column(
        "threat_intel_cache",
        sa.Column("threatfox_malware", sa.Text(), nullable=True),
    )
    op.add_column(
        "threat_intel_cache",
        sa.Column("greynoise_noise", sa.Boolean(), server_default="false", nullable=False),
    )
    op.add_column(
        "threat_intel_cache",
        sa.Column("greynoise_riot", sa.Boolean(), server_default="false", nullable=False),
    )
    op.add_column(
        "threat_intel_cache",
        sa.Column("greynoise_classification", sa.Text(), nullable=True),
    )
    op.add_column(
        "threat_intel_cache",
        sa.Column("composite_score", sa.Integer(), server_default="0", nullable=False),
    )


def downgrade():
    op.drop_column("threat_intel_cache", "composite_score")
    op.drop_column("threat_intel_cache", "greynoise_classification")
    op.drop_column("threat_intel_cache", "greynoise_riot")
    op.drop_column("threat_intel_cache", "greynoise_noise")
    op.drop_column("threat_intel_cache", "threatfox_malware")
    op.drop_column("threat_intel_cache", "threatfox_score")
    op.drop_column("threat_intel_cache", "feodo_malware")
    op.drop_column("threat_intel_cache", "feodo_listed")
