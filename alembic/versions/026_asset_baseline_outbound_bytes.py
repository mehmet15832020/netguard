"""asset_baselines outbound bytes baseline — I2 exfiltration hacim tespiti.

Revision ID: 026
Revises: 025
Create Date: 2026-06-18

Her IP'nin dış ağa gönderdiği günlük byte ortalaması ve standart sapması.
mean + 3*stddev aşılırsa data_exfil_volume_anomaly üretilir.
Kaynak: Verizon DBIR 2025; CIS Controls v8 §13.6; MITRE ATT&CK T1048.
"""

from alembic import op

revision = "026"
down_revision = "025"


def upgrade():
    op.execute(
        "ALTER TABLE asset_baselines "
        "ADD COLUMN IF NOT EXISTS outbound_bytes_daily_avg DOUBLE PRECISION NOT NULL DEFAULT 0"
    )
    op.execute(
        "ALTER TABLE asset_baselines "
        "ADD COLUMN IF NOT EXISTS outbound_bytes_stddev DOUBLE PRECISION NOT NULL DEFAULT 0"
    )


def downgrade():
    op.execute("ALTER TABLE asset_baselines DROP COLUMN IF EXISTS outbound_bytes_daily_avg")
    op.execute("ALTER TABLE asset_baselines DROP COLUMN IF EXISTS outbound_bytes_stddev")
