"""PostgreSQL Row Level Security — tenant izolasyonu (T2-4).

Revision ID: 021
Revises: 020
Create Date: 2026-06-06

Tüm tenant_id kolonuna sahip veri tablolarında RLS etkinleştirilir.
Policy: tenant context set edilmemişse (NULL) tüm satırlar görünür;
set edilmişse yalnızca eşleşen tenant_id görünür.

Kaynak: PostgreSQL RLS Docs §5.8, CIS PostgreSQL Benchmark §6.2,
        NIST SP 800-162 (ABAC), OWASP ASVS §4.1.3, PCI DSS §7.2
"""

from alembic import op
from sqlalchemy import text

revision = "021"
down_revision = "020"
branch_labels = None
depends_on = None

_RLS_TABLES = [
    # normalized_logs: TimescaleDB hypertable (compression) — RLS desteklenmiyor
    # audit_log: tenant_id kolonu yok — global audit log
    "alerts",
    "incidents",
    "blocked_ips",
    "asset_baselines",
    "correlated_events",
    "alert_explanations",
    "attack_chain_state",
    "devices",
    "fp_rules",
    "saved_hunts",
    "security_events",
]


def upgrade():
    conn = op.get_bind()
    for table in _RLS_TABLES:
        conn.execute(text(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"))
        conn.execute(text(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY"))
        conn.execute(text(f"""
            CREATE POLICY tenant_isolation ON {table}
            USING (
                current_setting('app.current_tenant', true) IS NULL
                OR current_setting('app.current_tenant', true) = ''
                OR tenant_id = current_setting('app.current_tenant', true)
            )
        """))


def downgrade():
    conn = op.get_bind()
    for table in reversed(_RLS_TABLES):
        conn.execute(text(f"DROP POLICY IF EXISTS tenant_isolation ON {table}"))
        conn.execute(text(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY"))
        conn.execute(text(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"))
