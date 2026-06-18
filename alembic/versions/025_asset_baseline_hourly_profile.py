"""asset_baselines.hour_of_day_profile kolonu — I1 temporal trafik profili.

Revision ID: 025
Revises: 024
Create Date: 2026-06-18

Her IP'nin 24 saatlik aktivite dağılımını saklar: saat 0-23 → event sayısı.
Sessiz saatlerdeki (z-score < -1.5) anormal aktiviteyi tespit etmek için
kullanılır (SANS NSM temporal analysis, Darktrace saatlik profil modeli).
"""

from alembic import op

revision = "025"
down_revision = "024"


def upgrade():
    op.execute(
        "ALTER TABLE asset_baselines "
        "ADD COLUMN IF NOT EXISTS hour_of_day_profile TEXT NOT NULL DEFAULT '{}'"
    )


def downgrade():
    op.execute(
        "ALTER TABLE asset_baselines DROP COLUMN IF EXISTS hour_of_day_profile"
    )
