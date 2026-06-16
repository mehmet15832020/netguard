"""DHCP MAC geçmişi — IP başına görülen MAC adresleri (C1).

Revision ID: 023
Revises: 022
Create Date: 2026-06-16

Zeek dhcp.log'dan IP→MAC eşleşmelerini saklar. Bilinen bir IP'de farklı bir
MAC görülürse (DHCP spoofing / cihaz değişimi) dhcp_new_mac_detected alert'i
bu tabloya bakılarak üretilir.

Kaynak: NIST SP 800-94 §3.3 (asset identification), Security Onion/Malcolm
dhcp.log önceliği.
"""

from alembic import op

revision = "023"
down_revision = "022"
branch_labels = None
depends_on = None


def upgrade():
    op.execute("""
        CREATE TABLE IF NOT EXISTS dhcp_mac_history (
            id           SERIAL PRIMARY KEY,
            ip_address   TEXT NOT NULL,
            mac_address  TEXT NOT NULL,
            first_seen   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            last_seen    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            UNIQUE (ip_address, mac_address)
        )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_dhcp_mac_history_ip ON dhcp_mac_history (ip_address)")


def downgrade():
    op.execute("DROP TABLE IF EXISTS dhcp_mac_history CASCADE")
