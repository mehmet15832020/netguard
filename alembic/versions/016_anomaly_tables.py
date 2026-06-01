"""016_anomaly_tables

Revision ID: 016
Revises: 015
Create Date: 2026-06-01
"""

from alembic import op

revision = "016"
down_revision = "015"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS anomaly_baselines (
            entity_id    TEXT             NOT NULL,
            metric       TEXT             NOT NULL,
            hour_bucket  INTEGER          NOT NULL,
            mean         DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            m2           DOUBLE PRECISION NOT NULL DEFAULT 0.0,
            sample_count INTEGER          NOT NULL DEFAULT 0,
            last_updated TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
            PRIMARY KEY (entity_id, metric, hour_bucket)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_anom_bl_entity "
        "ON anomaly_baselines(entity_id)"
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS anomaly_results (
            result_id      TEXT             PRIMARY KEY,
            entity_id      TEXT             NOT NULL,
            metric         TEXT             NOT NULL,
            observed_value DOUBLE PRECISION NOT NULL,
            baseline_mean  DOUBLE PRECISION NOT NULL,
            baseline_std   DOUBLE PRECISION NOT NULL,
            z_score        DOUBLE PRECISION NOT NULL,
            severity       TEXT             NOT NULL,
            confidence     DOUBLE PRECISION NOT NULL,
            message        TEXT             NOT NULL,
            detected_at    TIMESTAMPTZ      NOT NULL DEFAULT NOW(),
            extra          JSONB            NOT NULL DEFAULT '{}'
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_anom_res_entity "
        "ON anomaly_results(entity_id, detected_at)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS idx_anom_res_severity "
        "ON anomaly_results(severity)"
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS anomaly_results")
    op.execute("DROP TABLE IF EXISTS anomaly_baselines")
