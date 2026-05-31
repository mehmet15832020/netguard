"""
LogStore — normalized_logs için depolama soyutlaması.

Şu an: PostgreSQL + TimescaleDB (PostgreSQLLogStore)
Gelecekte: ElasticsearchLogStore (aynı interface, farklı backend)

Geçiş stratejisi (Strangler Fig):
    1. Tüm normalized_logs erişimi bu interface üzerinden geçer
    2. ElasticsearchLogStore implement edilir
    3. Yeni loglar ES'e yönlendirilir, eskiler PG'de kalır
    4. PG kademeli olarak emekli edilir
"""
from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from shared.models import NormalizedLog


@runtime_checkable
class LogStore(Protocol):
    """normalized_logs tablosu için depolama protokolü."""

    def save(self, log: NormalizedLog, tenant_id: str = "default") -> None:
        """Tek bir normalize log kaydını sakla."""
        ...

    def save_batch(self, logs: list[NormalizedLog], tenant_id: str = "default") -> None:
        """Birden fazla log kaydını toplu sakla."""
        ...

    def search(
        self,
        *,
        tenant_id: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        event_action: str | None = None,
        event_category: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        keyword: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        """Filtrelere göre log arama."""
        ...

    def count_by_group(
        self,
        group_by: str,
        *,
        event_action: str | None = None,
        message_filter: str | None = None,
        since: datetime,
        until: datetime | None = None,
        tenant_id: str | None = None,
    ) -> list[tuple[str, int]]:
        """(group_value, count) çiftleri — korelasyon kuralları için."""
        ...

    def get_connection(self):
        """Ham DB bağlantısı — Sigma SQL executor için (ES geçişinde kaldırılır)."""
        ...


from server.database import db as _db

_VALID_LOG_GROUP_COLS: frozenset[str] = frozenset({
    "source_ip", "destination_ip", "observer_hostname", "username",
    "event_action", "event_category", "tenant_id", "source_type",
    "network_protocol", "source_port", "destination_port", "severity",
})


class PostgreSQLLogStore:
    """LogStore'un PostgreSQL + TimescaleDB implementasyonu."""

    def save(self, log: NormalizedLog, tenant_id: str = "default") -> None:
        _db.save_normalized_log(log, tenant_id=tenant_id)

    def save_batch(self, logs: list[NormalizedLog], tenant_id: str = "default") -> None:
        for log in logs:
            _db.save_normalized_log(log, tenant_id=tenant_id)

    def search(
        self,
        *,
        tenant_id: str | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        event_action: str | None = None,
        event_category: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        keyword: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict]:
        clauses: list[str] = []
        params: list = []

        if tenant_id is not None:
            clauses.append("tenant_id = %s")
            params.append(tenant_id)
        if source_ip is not None:
            clauses.append("source_ip = %s")
            params.append(source_ip)
        if destination_ip is not None:
            clauses.append("destination_ip = %s")
            params.append(destination_ip)
        if event_action is not None:
            clauses.append("event_action = %s")
            params.append(event_action)
        if event_category is not None:
            clauses.append("event_category = %s")
            params.append(event_category)
        if since is not None:
            clauses.append("timestamp >= %s")
            params.append(since)
        if until is not None:
            clauses.append("timestamp <= %s")
            params.append(until)
        if keyword is not None:
            clauses.append("message ILIKE %s")
            params.append(f"%{keyword}%")

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.extend([limit, offset])

        with _db._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM normalized_logs {where} ORDER BY timestamp DESC LIMIT %s OFFSET %s",
                params,
            ).fetchall()

        return [dict(r) for r in rows]

    def count_by_group(
        self,
        group_by: str,
        *,
        event_action: str | None = None,
        message_filter: str | None = None,
        since: datetime,
        until: datetime | None = None,
        tenant_id: str | None = None,
    ) -> list[tuple[str, int]]:
        if group_by not in _VALID_LOG_GROUP_COLS:
            raise ValueError(
                f"Geçersiz group_by kolonu: {group_by!r}. "
                f"İzin verilenler: {sorted(_VALID_LOG_GROUP_COLS)}"
            )
        if since is None:
            raise ValueError("since parametresi zorunludur (NIST SP 800-94 §6.1)")

        clauses: list[str] = [f"{group_by} IS NOT NULL", "timestamp >= %s"]
        params: list = [since]

        if until is not None:
            clauses.append("timestamp <= %s")
            params.append(until)
        if event_action is not None:
            clauses.append("event_action = %s")
            params.append(event_action)
        if message_filter is not None:
            escaped = message_filter.replace("%", r"\%").replace("_", r"\_")
            clauses.append(r"message ILIKE %s ESCAPE '\'")
            params.append(f"%{escaped}%")
        if tenant_id is not None:
            clauses.append("tenant_id = %s")
            params.append(tenant_id)

        where = "WHERE " + " AND ".join(clauses)

        with _db._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT {group_by}, COUNT(*) AS cnt
                FROM normalized_logs
                {where}
                GROUP BY {group_by}
                ORDER BY cnt DESC
                """,
                params,
            ).fetchall()

        return [(str(row[group_by]), row["cnt"]) for row in rows]

    def get_connection(self):
        return _db._connect()


log_store: LogStore = PostgreSQLLogStore()
