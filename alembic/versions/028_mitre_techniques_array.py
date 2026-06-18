"""correlated_events mitre_techniques+tactics TEXT → TEXT[] + GIN index.

Revision ID: 028
Revises: 027
Create Date: 2026-06-18

mitre_techniques ve mitre_tactics kolonları virgüllü TEXT'ten TEXT[] array'e çevriliyor.
ANY() operatörü ve GIN indexleri ile teknik bazlı sorgular etkinleşiyor.
Kaynak: PostgreSQL Array Best Practices; MITRE ATT&CK teknik sorgu desenleri.
"""

from alembic import op

revision = "028"
down_revision = "027"


def upgrade():
    # Önce DEFAULT kısıtını kaldır
    op.execute("ALTER TABLE correlated_events ALTER COLUMN mitre_techniques DROP DEFAULT")
    # Virgüllü TEXT → TEXT[] (boş string → boş array)
    op.execute(
        """
        ALTER TABLE correlated_events
        ALTER COLUMN mitre_techniques TYPE TEXT[]
        USING CASE
            WHEN mitre_techniques = '' THEN ARRAY[]::TEXT[]
            ELSE string_to_array(mitre_techniques, ',')
        END
        """
    )
    op.execute("ALTER TABLE correlated_events ALTER COLUMN mitre_techniques SET DEFAULT ARRAY[]::TEXT[]")

    op.execute("ALTER TABLE correlated_events ALTER COLUMN mitre_tactics DROP DEFAULT")
    op.execute(
        """
        ALTER TABLE correlated_events
        ALTER COLUMN mitre_tactics TYPE TEXT[]
        USING CASE
            WHEN mitre_tactics = '' THEN ARRAY[]::TEXT[]
            ELSE string_to_array(mitre_tactics, ',')
        END
        """
    )
    op.execute("ALTER TABLE correlated_events ALTER COLUMN mitre_tactics SET DEFAULT ARRAY[]::TEXT[]")

    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_corr_events_mitre_techniques_gin "
        "ON correlated_events USING GIN (mitre_techniques)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_corr_events_mitre_tactics_gin "
        "ON correlated_events USING GIN (mitre_tactics)"
    )


def downgrade():
    op.execute("DROP INDEX IF EXISTS idx_corr_events_mitre_techniques_gin")
    op.execute("DROP INDEX IF EXISTS idx_corr_events_mitre_tactics_gin")
    op.execute("ALTER TABLE correlated_events ALTER COLUMN mitre_techniques DROP DEFAULT")
    op.execute(
        """
        ALTER TABLE correlated_events
        ALTER COLUMN mitre_techniques TYPE TEXT
        USING array_to_string(mitre_techniques, ',')
        """
    )
    op.execute("ALTER TABLE correlated_events ALTER COLUMN mitre_techniques SET DEFAULT ''")
    op.execute("ALTER TABLE correlated_events ALTER COLUMN mitre_tactics DROP DEFAULT")
    op.execute(
        """
        ALTER TABLE correlated_events
        ALTER COLUMN mitre_tactics TYPE TEXT
        USING array_to_string(mitre_tactics, ',')
        """
    )
    op.execute("ALTER TABLE correlated_events ALTER COLUMN mitre_tactics SET DEFAULT ''")
