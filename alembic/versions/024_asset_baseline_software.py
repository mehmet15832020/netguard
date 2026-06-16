"""asset_baselines.detected_software kolonu — C5 pasif yazılım fingerprinting.

Revision ID: 024
Revises: 023
Create Date: 2026-06-16

Zeek software.log'dan pasif olarak tespit edilen yazılım/versiyon bilgisini
IP'nin asset baseline kaydına ekler — eski/savunmasız sistemlerin görünür
olması için (NIST SP 800-94 §4.1 behavioral/asset profiling).

019_asset_baseline_protocols.py ile aynı desen.
"""

from alembic import op

revision = "024"
down_revision = "023"


def upgrade():
    op.execute(
        "ALTER TABLE asset_baselines "
        "ADD COLUMN IF NOT EXISTS detected_software TEXT NOT NULL DEFAULT '[]'"
    )


def downgrade():
    op.execute(
        "ALTER TABLE asset_baselines DROP COLUMN IF EXISTS detected_software"
    )
