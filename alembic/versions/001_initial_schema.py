"""NetGuard initial PostgreSQL schema + TimescaleDB hypertables

Revision ID: 001
Revises:
Create Date: 2026-05-09
"""
from alembic import op

revision = "001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE")

    # ── Tenants ───────────────────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS tenants (
        id         TEXT PRIMARY KEY,
        name       TEXT NOT NULL,
        is_active  INTEGER NOT NULL DEFAULT 1,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """)
    op.execute("INSERT INTO tenants (id, name) VALUES ('default', 'Default') ON CONFLICT DO NOTHING")

    # ── Sites ─────────────────────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS sites (
        id         TEXT PRIMARY KEY,
        tenant_id  TEXT NOT NULL REFERENCES tenants(id),
        name       TEXT NOT NULL,
        location   TEXT NOT NULL DEFAULT '',
        tz         TEXT NOT NULL DEFAULT 'UTC',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_sites_tenant ON sites(tenant_id)")

    # ── DB Users ──────────────────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS db_users (
        username      TEXT PRIMARY KEY,
        password_hash TEXT NOT NULL,
        role          TEXT NOT NULL DEFAULT 'viewer',
        tenant_id     TEXT REFERENCES tenants(id),
        created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_db_users_tenant ON db_users(tenant_id)")

    # ── Alerts ────────────────────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id           BIGINT GENERATED ALWAYS AS IDENTITY,
        alert_id     TEXT UNIQUE NOT NULL,
        agent_id     TEXT NOT NULL,
        hostname     TEXT NOT NULL,
        severity     TEXT NOT NULL,
        status       TEXT NOT NULL DEFAULT 'active',
        metric       TEXT NOT NULL,
        message      TEXT NOT NULL,
        value        REAL NOT NULL,
        threshold    REAL NOT NULL,
        triggered_at TIMESTAMPTZ NOT NULL,
        resolved_at  TIMESTAMPTZ,
        tenant_id    TEXT NOT NULL DEFAULT 'default',
        PRIMARY KEY (id)
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_alerts_agent  ON alerts(agent_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant_id)")

    # ── Security Events ───────────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        event_id     TEXT UNIQUE NOT NULL,
        agent_id     TEXT NOT NULL,
        hostname     TEXT NOT NULL,
        event_action TEXT NOT NULL,
        severity     TEXT NOT NULL,
        source_ip    TEXT,
        username     TEXT,
        message      TEXT NOT NULL,
        raw_data     TEXT,
        occurred_at  TIMESTAMPTZ NOT NULL,
        created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        tenant_id    TEXT NOT NULL DEFAULT 'default'
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_sec_action ON security_events(event_action)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_sec_agent  ON security_events(agent_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_sec_time   ON security_events(occurred_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_sec_srcip  ON security_events(source_ip)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_sec_tenant ON security_events(tenant_id)")

    # ── Raw Logs ──────────────────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS raw_logs (
        id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        raw_id            TEXT UNIQUE NOT NULL,
        source_type       TEXT,
        observer_hostname TEXT NOT NULL,
        received_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        raw_content       TEXT NOT NULL,
        parse_status      TEXT NOT NULL DEFAULT 'pending',
        normalized_log_id TEXT
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_raw_host         ON raw_logs(observer_hostname)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_raw_received     ON raw_logs(received_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_raw_parse_status ON raw_logs(parse_status)")

    # ── Normalized Logs (TimescaleDB hypertable) ──────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS normalized_logs (
        id                   BIGINT GENERATED ALWAYS AS IDENTITY,
        log_id               TEXT UNIQUE NOT NULL,
        raw_id               TEXT,
        source_type          TEXT NOT NULL,
        tenant_id            TEXT NOT NULL DEFAULT 'default',
        observer_hostname    TEXT NOT NULL DEFAULT '',
        timestamp            TIMESTAMPTZ NOT NULL,
        received_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        severity             TEXT NOT NULL DEFAULT 'info',
        event_category       TEXT NOT NULL DEFAULT '',
        event_action         TEXT NOT NULL DEFAULT '',
        source_ip            TEXT,
        destination_ip       TEXT,
        source_hostname      TEXT,
        destination_hostname TEXT,
        source_port          INTEGER,
        destination_port     INTEGER,
        network_protocol     TEXT,
        username             TEXT,
        message              TEXT NOT NULL DEFAULT '',
        tags                 TEXT NOT NULL DEFAULT '[]',
        extra                TEXT NOT NULL DEFAULT '{}',
        processed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (id, received_at)
    )
    """)
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_norm_log_id       ON normalized_logs(log_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_norm_timestamp           ON normalized_logs(timestamp DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_norm_received_at         ON normalized_logs(received_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_norm_source_type         ON normalized_logs(source_type)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_norm_event_category      ON normalized_logs(event_category)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_norm_event_action        ON normalized_logs(event_action)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_norm_source_ip           ON normalized_logs(source_ip)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_norm_corr_query          ON normalized_logs(event_action, timestamp, source_ip)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_norm_tenant              ON normalized_logs(tenant_id)")
    op.execute("""
    CREATE INDEX IF NOT EXISTS idx_norm_fts ON normalized_logs
        USING GIN (
            to_tsvector('simple',
                COALESCE(message, '') || ' ' ||
                COALESCE(source_ip, '') || ' ' ||
                COALESCE(destination_ip, '') || ' ' ||
                COALESCE(observer_hostname, '') || ' ' ||
                COALESCE(username, '') || ' ' ||
                COALESCE(event_action, '')
            )
        )
    """)

    # TimescaleDB hypertable aktivasyonu (TimescaleDB yoksa sessizce atla)
    try:
        op.execute("SELECT create_hypertable('normalized_logs', 'received_at', if_not_exists => TRUE)")
        op.execute("""
            SELECT add_compression_policy('normalized_logs',
                INTERVAL '7 days', if_not_exists => TRUE)
        """)
    except Exception:
        pass

    # ── Correlated Events ─────────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS correlated_events (
        id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        corr_id          TEXT UNIQUE NOT NULL,
        rule_id          TEXT NOT NULL,
        rule_name        TEXT NOT NULL,
        event_action     TEXT NOT NULL,
        severity         TEXT NOT NULL,
        group_value      TEXT NOT NULL,
        matched_count    INTEGER NOT NULL,
        window_seconds   INTEGER NOT NULL,
        first_seen       TIMESTAMPTZ NOT NULL,
        last_seen        TIMESTAMPTZ NOT NULL,
        message          TEXT NOT NULL,
        created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        mitre_techniques TEXT NOT NULL DEFAULT '',
        mitre_tactics    TEXT NOT NULL DEFAULT '',
        tenant_id        TEXT NOT NULL DEFAULT 'default'
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_corr_rule_id     ON correlated_events(rule_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_corr_event_action ON correlated_events(event_action)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_corr_group_value ON correlated_events(group_value)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_corr_created_at  ON correlated_events(created_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_corr_tenant      ON correlated_events(tenant_id)")

    # ── Devices ───────────────────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        device_id              TEXT PRIMARY KEY,
        name                   TEXT NOT NULL,
        ip                     TEXT DEFAULT '',
        mac                    TEXT DEFAULT '',
        type                   TEXT NOT NULL DEFAULT 'discovered',
        vendor                 TEXT DEFAULT '',
        os_info                TEXT DEFAULT '',
        status                 TEXT DEFAULT 'unknown',
        first_seen             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        last_seen              TIMESTAMPTZ,
        snmp_community         TEXT DEFAULT '',
        snmp_version           TEXT DEFAULT 'v2c',
        snmp_v3_username       TEXT DEFAULT '',
        snmp_v3_auth_protocol  TEXT DEFAULT 'SHA',
        snmp_v3_auth_key       TEXT DEFAULT '',
        snmp_v3_priv_protocol  TEXT DEFAULT 'AES',
        snmp_v3_priv_key       TEXT DEFAULT '',
        risk_score             INTEGER DEFAULT 0,
        segment                TEXT DEFAULT '',
        notes                  TEXT DEFAULT '',
        tenant_id              TEXT NOT NULL DEFAULT 'default'
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_devices_type   ON devices(type)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_devices_status ON devices(status)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_devices_ip     ON devices(ip)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_devices_tenant ON devices(tenant_id)")

    # ── SNMP Devices (legacy) ─────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS snmp_devices (
        id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        host       TEXT UNIQUE NOT NULL,
        community  TEXT NOT NULL DEFAULT 'public',
        label      TEXT NOT NULL DEFAULT '',
        enabled    INTEGER NOT NULL DEFAULT 1,
        added_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """)

    # ── SNMP Poll History ─────────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS snmp_poll_history (
        host      TEXT NOT NULL,
        if_index  TEXT NOT NULL,
        if_name   TEXT NOT NULL,
        polled_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        hc_in     BIGINT NOT NULL DEFAULT 0,
        hc_out    BIGINT NOT NULL DEFAULT 0,
        PRIMARY KEY (host, if_index)
    )
    """)

    # ── Service Checks ────────────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS service_checks (
        id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        device_id  TEXT NOT NULL,
        check_type TEXT NOT NULL,
        target     TEXT NOT NULL,
        port       INTEGER,
        status     TEXT NOT NULL,
        rtt_ms     REAL,
        checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        details    TEXT DEFAULT ''
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_svc_device  ON service_checks(device_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_svc_checked ON service_checks(checked_at DESC)")

    # ── API Keys ──────────────────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS api_keys (
        agent_id   TEXT PRIMARY KEY,
        api_key    TEXT NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """)

    # ── Audit Log ─────────────────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS audit_log (
        id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        event_id   TEXT UNIQUE NOT NULL,
        actor      TEXT NOT NULL,
        action     TEXT NOT NULL,
        resource   TEXT NOT NULL,
        detail     TEXT,
        ip_address TEXT,
        timestamp  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor     ON audit_log(actor)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_action    ON audit_log(action)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC)")

    # ── Threat Intel Cache ────────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS threat_intel_cache (
        ip            TEXT PRIMARY KEY,
        score         INTEGER NOT NULL,
        total_reports INTEGER NOT NULL DEFAULT 0,
        country_code  TEXT,
        isp           TEXT,
        queried_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """)

    # ── Token Blacklist ───────────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS token_blacklist (
        jti        TEXT PRIMARY KEY,
        expires_at TIMESTAMPTZ NOT NULL
    )
    """)

    # ── Topology ──────────────────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS topology_nodes (
        device_id  TEXT PRIMARY KEY,
        name       TEXT NOT NULL,
        ip         TEXT DEFAULT '',
        type       TEXT DEFAULT 'unknown',
        vendor     TEXT DEFAULT '',
        os_info    TEXT DEFAULT '',
        layer      INTEGER DEFAULT 3,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """)
    op.execute("""
    CREATE TABLE IF NOT EXISTS topology_edges (
        id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        src_id     TEXT NOT NULL,
        dst_id     TEXT NOT NULL,
        link_type  TEXT NOT NULL DEFAULT 'ip',
        discovered TEXT NOT NULL DEFAULT 'arp',
        updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        UNIQUE (src_id, dst_id, link_type)
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_topo_edges_src ON topology_edges(src_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_topo_edges_dst ON topology_edges(dst_id)")

    # ── Incidents ─────────────────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id     TEXT PRIMARY KEY,
        title           TEXT NOT NULL,
        description     TEXT DEFAULT '',
        severity        TEXT NOT NULL,
        status          TEXT NOT NULL DEFAULT 'open',
        assigned_to     TEXT,
        source_event_id TEXT,
        source_type     TEXT,
        created_by      TEXT NOT NULL,
        notes           TEXT DEFAULT '',
        rule_id         TEXT,
        group_value     TEXT,
        group_by_field  TEXT DEFAULT 'source_ip',
        priority_score  INTEGER DEFAULT 0,
        closure_note    TEXT DEFAULT '',
        created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        resolved_at     TIMESTAMPTZ,
        acknowledged_at TIMESTAMPTZ,
        tenant_id       TEXT NOT NULL DEFAULT 'default'
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_incidents_status     ON incidents(status)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_incidents_severity   ON incidents(severity)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_incidents_created    ON incidents(created_at DESC)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_incidents_rule_group ON incidents(rule_id, group_value)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_incidents_tenant     ON incidents(tenant_id)")

    op.execute("""
    CREATE TABLE IF NOT EXISTS incident_events (
        id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        incident_id TEXT NOT NULL,
        event_id    TEXT NOT NULL,
        event_action TEXT NOT NULL,
        severity    TEXT NOT NULL,
        message     TEXT NOT NULL,
        occurred_at TIMESTAMPTZ NOT NULL,
        added_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_inc_events_incident ON incident_events(incident_id)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_inc_events_occurred ON incident_events(occurred_at DESC)")

    # ── Attack Chain State ────────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS attack_chain_state (
        id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
        source_ip   TEXT NOT NULL,
        stage       TEXT NOT NULL,
        occurred_at TIMESTAMPTZ NOT NULL,
        tenant_id   TEXT NOT NULL DEFAULT 'default',
        created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_chain_src_ip   ON attack_chain_state(source_ip)")
    op.execute("CREATE INDEX IF NOT EXISTS idx_chain_occurred ON attack_chain_state(occurred_at DESC)")

    # ── Asset Baselines ───────────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS asset_baselines (
        source_ip             TEXT NOT NULL,
        tenant_id             TEXT NOT NULL DEFAULT 'default',
        first_seen_at         TIMESTAMPTZ NOT NULL,
        last_seen_at          TIMESTAMPTZ NOT NULL,
        avg_events_per_hour   REAL NOT NULL DEFAULT 0,
        typical_ports         TEXT NOT NULL DEFAULT '[]',
        typical_destinations  TEXT NOT NULL DEFAULT '[]',
        typical_event_actions TEXT NOT NULL DEFAULT '[]',
        sample_hours          INTEGER NOT NULL DEFAULT 0,
        updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        PRIMARY KEY (source_ip, tenant_id)
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_asset_baselines_tenant ON asset_baselines(tenant_id)")

    # ── False Positive Rules ──────────────────────────────────────────
    op.execute("""
    CREATE TABLE IF NOT EXISTS fp_rules (
        fp_rule_id        TEXT PRIMARY KEY,
        event_action      TEXT,
        source_ip         TEXT,
        destination_ip    TEXT,
        destination_port  TEXT,
        observer_hostname TEXT,
        tenant_id         TEXT NOT NULL DEFAULT 'default',
        reason            TEXT NOT NULL,
        created_by        TEXT NOT NULL DEFAULT 'admin',
        created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expires_at        TIMESTAMPTZ,
        is_active         INTEGER NOT NULL DEFAULT 1,
        hit_count         INTEGER NOT NULL DEFAULT 0
    )
    """)
    op.execute("CREATE INDEX IF NOT EXISTS idx_fp_rules_tenant_active ON fp_rules(tenant_id, is_active)")


def downgrade() -> None:
    for table in [
        "fp_rules", "asset_baselines", "attack_chain_state",
        "incident_events", "incidents", "topology_edges", "topology_nodes",
        "token_blacklist", "threat_intel_cache", "audit_log", "api_keys",
        "service_checks", "snmp_poll_history", "snmp_devices", "devices",
        "correlated_events", "normalized_logs", "raw_logs",
        "security_events", "alerts", "db_users", "sites", "tenants",
    ]:
        op.execute(f"DROP TABLE IF EXISTS {table} CASCADE")
