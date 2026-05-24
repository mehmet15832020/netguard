"""Analytics performans: destination_ip, destination_port, network_protocol composite index.

Revision ID: 011
Revises: 010
Create Date: 2026-05-24
"""
from alembic import op

revision = "011"
down_revision = "010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_index(
        "idx_norm_dst_ip_time",
        "normalized_logs",
        ["received_at", "destination_ip"],
    )
    op.create_index(
        "idx_norm_dport_time",
        "normalized_logs",
        ["received_at", "destination_port"],
    )
    op.create_index(
        "idx_norm_proto_time",
        "normalized_logs",
        ["received_at", "network_protocol"],
    )


def downgrade() -> None:
    op.drop_index("idx_norm_dst_ip_time", table_name="normalized_logs")
    op.drop_index("idx_norm_dport_time",  table_name="normalized_logs")
    op.drop_index("idx_norm_proto_time",  table_name="normalized_logs")
