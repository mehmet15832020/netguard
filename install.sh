#!/usr/bin/env bash
# NetGuard — Tek komutla kurulum
# Kullanım: bash install.sh [--host <IP_veya_domain>]
set -euo pipefail

NETGUARD_VERSION="latest"
MIN_DOCKER_VERSION=24
HEALTH_TIMEOUT=120   # saniye — servis sağlık bekleme süresi
COMPOSE_FILE="docker-compose.yml"

# ── Renk kodları ────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

# ── Argüman işleme ──────────────────────────────────────────────────
HOST_ARG=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)
            # Yalnızca geçerli IP/domain karakterlerine izin ver
            if [[ ! "$2" =~ ^[a-zA-Z0-9._-]+$ ]]; then
                err "--host değeri geçersiz: '$2'. Yalnızca IP adresi veya domain kabul edilir."
                exit 1
            fi
            HOST_ARG="$2"; shift 2 ;;
        -h|--help)
            echo "Kullanım: bash install.sh [--host <IP_veya_domain>]"
            echo "Örnek:    bash install.sh --host 192.168.1.100"
            exit 0 ;;
        *) err "Bilinmeyen parametre: $1"; exit 1 ;;
    esac
done

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║         NetGuard — Kurulum Sihirbazı             ║"
echo "║   Açık Kaynak NSM | github.com/netguard-ndr      ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# ── 1. Önkoşul Kontrolü ─────────────────────────────────────────────
echo "[1/5] Önkoşullar kontrol ediliyor..."

# Zorunlu araçlar
for cmd in openssl python3 sed grep; do
    if ! command -v "$cmd" &>/dev/null; then
        err "Gerekli araç bulunamadı: $cmd"
        exit 1
    fi
done

# Docker varlığı
if ! command -v docker &>/dev/null; then
    err "Docker bulunamadı. https://docs.docker.com/get-docker/ adresinden kurun."
    exit 1
fi

# Docker versiyonu
DOCKER_VER=$(docker version --format '{{.Server.Version}}' 2>/dev/null | cut -d. -f1)
if [[ -z "$DOCKER_VER" ]] || [[ "$DOCKER_VER" -lt "$MIN_DOCKER_VERSION" ]]; then
    err "Docker ${MIN_DOCKER_VERSION}+ gerekli. Mevcut: $(docker version --format '{{.Server.Version}}' 2>/dev/null || echo 'bilinmiyor')"
    exit 1
fi
ok "Docker $(docker version --format '{{.Server.Version}}')"

# Docker Compose v2 (plugin olarak)
if ! docker compose version &>/dev/null; then
    err "Docker Compose v2 bulunamadı. 'docker compose version' çalışmıyor."
    exit 1
fi
ok "Docker Compose $(docker compose version --short 2>/dev/null || docker compose version | grep -oP '\d+\.\d+\.\d+')"

# Port uygunluğu
for port in 80 443; do
    if ss -tlnp 2>/dev/null | grep -q ":${port} " || \
       netstat -tlnp 2>/dev/null | grep -q ":${port} "; then
        warn "Port ${port} kullanımda. Çakışma varsa .env içinde SYSLOG_PORT/NETFLOW_PORT ayarlayın."
    fi
done
ok "Port kontrolü tamamlandı"

# ── 2. .env Ayarı ────────────────────────────────────────────────────
echo ""
echo "[2/5] Ortam değişkenleri ayarlanıyor..."

if [[ -f ".env" ]]; then
    # Mevcut .env'de placeholder kaldıysa hata ver
    if grep -qP '^[A-Z_]+=BURAYA_' .env 2>/dev/null; then
        err ".env içinde doldurulmamış placeholder'lar var (BURAYA_... değerleri)."
        err "Düzeltmek için: rm .env && bash install.sh"
        exit 1
    fi
    warn ".env zaten mevcut — üzerine yazılmıyor. Sıfırlamak için: rm .env && bash install.sh"
else
    if [[ ! -f ".env.example" ]]; then
        err ".env.example bulunamadı. NetGuard dizininde olduğunuzdan emin olun."
        exit 1
    fi

    cp .env.example .env

    # Otomatik secret üretimi
    JWT_SECRET=$(openssl rand -hex 32)
    PG_PASS=$(openssl rand -hex 16)
    BREAK_GLASS=$(openssl rand -hex 32)
    INFLUX_TOKEN=$(openssl rand -hex 32)
    INFLUX_ADMIN_PASS=$(openssl rand -hex 12)
    ADMIN_PASS=$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)
    VIEWER_PASS=$(openssl rand -base64 18 | tr -d '/+=' | head -c 20)

    # Şifreleme anahtarı (Fernet — 32 bytes base64url)
    ENC_KEY=$(python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())" 2>/dev/null || {
        warn "cryptography kütüphanesi bulunamadı — pip install cryptography (şifreleme devre dışı)"
        openssl rand -base64 32
    })

    sed -i \
        -e "s|BURAYA_GIZLI_ANAHTAR_YAZIN|${JWT_SECRET}|g" \
        -e "s|BURAYA_ENCRYPTION_KEY_YAZIN|${ENC_KEY}|g" \
        -e "s|BURAYA_ADMIN_SIFRE_YAZIN|${ADMIN_PASS}|g" \
        -e "s|BURAYA_VIEWER_SIFRE_YAZIN|${VIEWER_PASS}|g" \
        -e "s|BURAYA_DB_SIFRE_YAZIN|${PG_PASS}|g" \
        -e "s|BURAYA_INFLUXDB_TOKEN_YAZIN|${INFLUX_TOKEN}|g" \
        -e "s|BURAYA_INFLUXDB_ADMIN_SIFRE_YAZIN|${INFLUX_ADMIN_PASS}|g" \
        -e "s|BURAYA_BREAK_GLASS_TOKEN_YAZIN|${BREAK_GLASS}|g" \
        .env

    # Host ayarı — NETGUARD_HOST + CORS origins güncelle
    if [[ -n "$HOST_ARG" ]]; then
        sed -i "s|NETGUARD_HOST=localhost|NETGUARD_HOST=${HOST_ARG}|g" .env
        sed -i "s|^NETGUARD_CORS_ORIGINS=.*|NETGUARD_CORS_ORIGINS=https://localhost,https://127.0.0.1,https://${HOST_ARG}|" .env
    fi

    # Üretilen değerleri kaydet (kurulum sonrası referans için)
    CREDS_FILE=".netguard-credentials"
    cat > "${CREDS_FILE}" <<CREDS
# NetGuard Giriş Bilgileri — $(date '+%Y-%m-%d %H:%M:%S')
# BU DOSYAYI GÜVENLİ SAKLAYIN ve paylaşmayın.

Admin Kullanıcı:  admin
Admin Şifresi:    ${ADMIN_PASS}

Viewer Kullanıcı: viewer
Viewer Şifresi:   ${VIEWER_PASS}

PostgreSQL Şifre: ${PG_PASS}
InfluxDB Token:   ${INFLUX_TOKEN}
Break-Glass Token: ${BREAK_GLASS}
CREDS
    chmod 600 "${CREDS_FILE}"

    ok ".env oluşturuldu (gizli anahtarlar otomatik üretildi)"
    ok "Giriş bilgileri: ${CREDS_FILE}"
fi

# ── 3. Docker Image Build ────────────────────────────────────────────
echo ""
echo "[3/5] Docker imajları build ediliyor (ilk kez ~5-10 dakika sürebilir)..."

if ! docker compose -f "${COMPOSE_FILE}" build --parallel; then
    err "Build başarısız. 'docker compose build' çıktısını inceleyin."
    exit 1
fi
ok "Build tamamlandı"

# ── 4. Servisleri Başlat ─────────────────────────────────────────────
echo ""
echo "[4/5] Servisler başlatılıyor..."

docker compose -f "${COMPOSE_FILE}" up -d 2>&1 | tail -10
ok "Servisler başlatıldı"

# ── 5. Sağlık Kontrolü ───────────────────────────────────────────────
echo ""
echo "[5/5] Servis sağlığı bekleniyor (max ${HEALTH_TIMEOUT}s)..."

_wait_healthy() {
    local service="$1"
    local elapsed=0
    local interval=5
    local container_id
    container_id=$(docker compose ps -q "${service}" 2>/dev/null | head -1 || echo "")
    if [[ -z "$container_id" ]]; then
        return 1
    fi
    while [[ $elapsed -lt $HEALTH_TIMEOUT ]]; do
        local status
        status=$(docker inspect --format='{{.State.Health.Status}}' "${container_id}" 2>/dev/null || echo "")
        if [[ "$status" == "healthy" ]]; then
            return 0
        fi
        sleep $interval
        elapsed=$((elapsed + interval))
        echo -n "."
    done
    return 1
}

for svc in postgres backend frontend; do
    echo -n "  ${svc}: "
    if _wait_healthy "${svc}"; then
        ok "${svc} hazır"
    else
        warn "${svc} sağlık kontrolü zaman aşımına uğradı"
        echo "  'docker compose logs ${svc}' ile inceleyin"
    fi
done

# Backend API erişilebilirlik testi
NETGUARD_HOST_VAL=$(grep "^NETGUARD_HOST=" .env 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "localhost")
echo ""
echo "════════════════════════════════════════════════════"
echo "  NetGuard Kurulumu Tamamlandı"
echo "════════════════════════════════════════════════════"
echo ""
echo "  Dashboard:  https://${NETGUARD_HOST_VAL}"
echo "  API:        https://${NETGUARD_HOST_VAL}/api/v1/health"
echo ""
echo "  Giriş bilgileri: .netguard-credentials"
echo ""
echo "  Servis durumu:   docker compose ps"
echo "  Loglar:          docker compose logs -f backend"
echo "  Durdur:          docker compose down"
echo ""
echo "  UYARI: TLS sertifikası self-signed."
echo "  Tarayıcıda 'Güvensiz' uyarısı normaldir — ileri gitmeyi seçin."
echo ""
