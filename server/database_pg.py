"""Backward compatibility re-export — use server.database directly."""
from server.database import (
    DatabaseManager,
    db,
    _fp_row_to_dict,
    _audit_content,
    _AUDIT_CHAIN_GENESIS,
    _AUDIT_CHAIN_LOCK_ID,
    DATABASE_URL,
)

__all__ = [
    "DatabaseManager",
    "db",
    "_fp_row_to_dict",
    "_audit_content",
    "_AUDIT_CHAIN_GENESIS",
    "_AUDIT_CHAIN_LOCK_ID",
    "DATABASE_URL",
]
