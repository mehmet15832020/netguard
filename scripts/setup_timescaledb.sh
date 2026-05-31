#!/usr/bin/env bash
# NetGuard — TimescaleDB kurulum scripti (Ubuntu 24.04 + PostgreSQL 16)
# Çalıştır: sudo bash scripts/setup_timescaledb.sh
set -euo pipefail

PG_VERSION=16
REQUIRED_EXT="timescaledb-2-postgresql-${PG_VERSION}"

echo "=== NetGuard TimescaleDB Kurulumu ==="
echo "Platform: $(lsb_release -d | cut -f2)"
echo "PostgreSQL: ${PG_VERSION}"
echo ""

# TimescaleDB paket deposu
echo "[1/5] Paket deposu ekleniyor..."
apt-get install -y --quiet gnupg apt-transport-https lsb-release wget

GPG_KEY_FILE="/etc/apt/trusted.gpg.d/timescaledb.gpg"
wget --tries=3 --timeout=15 -qO /tmp/timescaledb.gpgkey \
    https://packagecloud.io/timescale/timescaledb/gpgkey
gpg --dearmor -o "${GPG_KEY_FILE}" /tmp/timescaledb.gpgkey
rm -f /tmp/timescaledb.gpgkey

echo "deb [signed-by=${GPG_KEY_FILE}] https://packagecloud.io/timescale/timescaledb/ubuntu/ $(lsb_release -cs) main" \
    > /etc/apt/sources.list.d/timescaledb.list
apt-get update -q

# Paket kurulumu
echo "[2/5] ${REQUIRED_EXT} kuruluyor..."
apt-get install -y "${REQUIRED_EXT}"

# PostgreSQL otomatik tuning (shared_preload_libraries dahil)
echo "[3/5] postgresql.conf optimize ediliyor..."
timescaledb-tune --quiet --yes --pg-version "${PG_VERSION}"

# PostgreSQL yeniden başlat
echo "[4/5] PostgreSQL yeniden başlatılıyor..."
systemctl restart "postgresql@${PG_VERSION}-main" 2>/dev/null \
    || systemctl restart postgresql

# Kurulum doğrulama (paket + runtime load)
echo "[5/5] Kurulum doğrulanıyor..."
PRELOAD=$(sudo -u postgres psql -tAc "SHOW shared_preload_libraries" 2>/dev/null || echo "")
if echo "${PRELOAD}" | grep -q "timescaledb"; then
    echo "    ✓ shared_preload_libraries = '${PRELOAD}'"
else
    echo "    ✗ timescaledb shared_preload_libraries içinde değil"
    echo "      timescaledb-tune düzgün çalışmamış olabilir. Elle ekleyin:"
    echo "      echo \"shared_preload_libraries = 'timescaledb'\" >> /etc/postgresql/${PG_VERSION}/main/postgresql.conf"
    echo "      systemctl restart postgresql"
    exit 1
fi

if sudo -u postgres psql -tAc "SELECT extname FROM pg_extension WHERE extname='timescaledb'" \
        2>/dev/null | grep -q "timescaledb"; then
    TS_VER=$(sudo -u postgres psql -tAc \
        "SELECT extversion FROM pg_extension WHERE extname='timescaledb'" \
        2>/dev/null | tr -d ' ')
    echo "    ✓ TimescaleDB ${TS_VER} runtime'da aktif"
else
    echo "    ℹ Extension henüz aktif değil — Alembic migration sonrası aktifleşir"
fi

echo ""
echo "=== Kurulum tamamlandı ==="
echo ""
echo "Sonraki adım — Alembic migration:"
echo "  cd /home/netguard/netguard"
echo "  source venv/bin/activate"
echo "  DATABASE_URL='postgresql://netguard:<şifre>@localhost:5432/netguard' \\"
echo "    alembic upgrade head"
echo ""
echo "Migration sonrası hypertable doğrulama:"
echo "  sudo -u postgres psql netguard -c \\"
echo "    \"SELECT hypertable_name, num_chunks FROM timescaledb_information.hypertables;\""
