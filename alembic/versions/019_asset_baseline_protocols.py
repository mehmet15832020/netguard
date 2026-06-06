"""asset_baselines.typical_protocols kolonu — C3 port/protokol profil genişletme.

Per-IP network_protocol baseline: "Bu IP daha önce hiç SMB kullanmadı" anomali
tespiti için (NIST SP 800-94 §4.1 behavioral profiling).

Revision ID: 019
Revises: 018
"""

from alembic import op

revision = "019"
down_revision = "018"


def upgrade():
    op.execute(
        "ALTER TABLE asset_baselines "
        "ADD COLUMN IF NOT EXISTS typical_protocols TEXT NOT NULL DEFAULT '[]'"
    )


def downgrade():
    op.execute(
        "ALTER TABLE asset_baselines DROP COLUMN IF EXISTS typical_protocols"
    )
