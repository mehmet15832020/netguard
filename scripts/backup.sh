#!/usr/bin/env bash
# NetGuard — Yedekleme Scripti
#
# Kullanım:
#   bash scripts/backup.sh [--dir <hedef_dizin>] [--password <şifre>]
#
# Ortam değişkenleri (.env'den otomatik okunur):
#   BACKUP_DIR       — yedek hedef dizini (varsayılan: ./backups)
#   BACKUP_PASSWORD  — .env şifreleme parolası (yoksa şifreleme atlanır, uyarı verilir)
#   POSTGRES_PASSWORD — PostgreSQL bağlantı parolası
#
# Retention: 7 günlük + 4 haftalık yedek korunur.
#
# RTO/RPO tablosu:
#   RPO (Recovery Point Objective): ~24 saat (günlük yedek)
#   RTO (Recovery Time Objective):  ~30 dakika (restore.sh)
#   Kaynak: CIS Controls v8.1 §11.2, NIST SP 800-34 Rev 1 §3.4
#
# Yedeklenen bileşenler:
#   1. PostgreSQL veritabanı (pg_dump -Fc)
#   2. config/ dizini (sigma/korelasyon kuralları, zeek config)
#   3. .env + .netguard-credentials (OpenSSL AES-256-CBC şifreli)
#   4. ssl_certs Docker volume (TLS sertifikaları)
#   5. netguard_data Docker volume (SQLite anomaly DB)
#
# Yedeklenmeyen bileşenler:
#   - zeek_logs — geçici log, yeniden üretilir
#   - influxdb_data — zaman serisi metrikleri, yeniden üretilir (opsiyonel)

set -euo pipefail

# ── Renk kodları ────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

# ── Argüman işleme ──────────────────────────────────────────────────
BACKUP_DIR_ARG=""
BACKUP_PASS_ARG=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir)      BACKUP_DIR_ARG="$2"; shift 2 ;;
        --password) BACKUP_PASS_ARG="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,30p' "$0" | grep '^#' | sed 's/^# \?//'
            exit 0 ;;
        *) err "Bilinmeyen parametre: $1"; exit 1 ;;
    esac
done

# ── Proje kökü ──────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_ROOT}"

# ── .env yükle ──────────────────────────────────────────────────────
if [[ -f ".env" ]]; then
    # Yalnızca güvenli KEY=VALUE satırlarını yükle
    while IFS= read -r line; do
        if [[ "$line" =~ ^[A-Z_][A-Z0-9_]*= ]] && [[ ! "$line" =~ ^# ]]; then
            declare -x "${line%%=*}"="${line#*=}" 2>/dev/null || true
        fi
    done < .env
fi

# ── Parametreler ────────────────────────────────────────────────────
BACKUP_DIR="${BACKUP_DIR_ARG:-${BACKUP_DIR:-${PROJECT_ROOT}/backups}}"
BACKUP_PASSWORD="${BACKUP_PASS_ARG:-${BACKUP_PASSWORD:-}}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-netguard_dev}"
DATE=$(date '+%Y%m%d_%H%M%S')
DAY_OF_WEEK=$(date '+%u')   # 1=Pazartesi ... 7=Pazar
BACKUP_SET="${BACKUP_DIR}/daily/${DATE}"
WEEKLY_LINK="${BACKUP_DIR}/weekly"
MANIFEST="${BACKUP_SET}/MANIFEST.sha256"

mkdir -p "${BACKUP_SET}" "${WEEKLY_LINK}"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║         NetGuard — Yedekleme Başlıyor            ║"
echo "╚══════════════════════════════════════════════════╝"
echo "  Hedef: ${BACKUP_SET}"
echo ""

# ── Şifreleme uyarısı ────────────────────────────────────────────────
if [[ -z "${BACKUP_PASSWORD}" ]]; then
    warn ".env şifrelemesi devre dışı — BACKUP_PASSWORD tanımlanmamış"
    warn ".env içinde BACKUP_PASSWORD=<güçlü_şifre> ekleyin veya --password kullanın"
fi

# ── Yardımcı: checksum ekle ──────────────────────────────────────────
_add_checksum() {
    local file="$1"
    sha256sum "${file}" | awk '{print $1, "'"$(basename "${file}")"'"}' >> "${MANIFEST}"
}

# ── 1. PostgreSQL yedeği ─────────────────────────────────────────────
echo "[1/5] PostgreSQL veritabanı yedekleniyor..."

PG_DUMP_FILE="${BACKUP_SET}/postgres_${DATE}.dump"

if docker compose ps postgres 2>/dev/null | grep -q "running\|Up"; then
    docker compose exec -T postgres \
        env PGPASSWORD="${POSTGRES_PASSWORD}" \
        pg_dump -U netguard -d netguard -Fc \
        > "${PG_DUMP_FILE}" 2>/dev/null

    if [[ ! -s "${PG_DUMP_FILE}" ]]; then
        err "pg_dump çıktısı boş — PostgreSQL bağlantısını kontrol edin"
        exit 1
    fi
    _add_checksum "${PG_DUMP_FILE}"
    ok "PostgreSQL yedeklendi ($(du -sh "${PG_DUMP_FILE}" | cut -f1))"
else
    warn "PostgreSQL container çalışmıyor — DB yedeği atlandı"
fi

# ── 2. Config dizini yedeği ──────────────────────────────────────────
echo "[2/5] Konfigürasyon dosyaları yedekleniyor..."

CONFIG_FILE="${BACKUP_SET}/config_${DATE}.tar.gz"
tar -czf "${CONFIG_FILE}" -C "${PROJECT_ROOT}" config/ 2>/dev/null

_add_checksum "${CONFIG_FILE}"
ok "Config yedeklendi ($(du -sh "${CONFIG_FILE}" | cut -f1))"

# ── 3. .env ve kimlik bilgileri yedeği ───────────────────────────────
echo "[3/5] Ortam değişkenleri ve kimlik bilgileri yedekleniyor..."

ENV_FILES=()
[[ -f ".env" ]] && ENV_FILES+=(".env")
[[ -f ".netguard-credentials" ]] && ENV_FILES+=(".netguard-credentials")

if [[ ${#ENV_FILES[@]} -gt 0 ]]; then
    ENV_TAR="${BACKUP_SET}/env_${DATE}.tar.gz"
    tar -czf "${ENV_TAR}" -C "${PROJECT_ROOT}" "${ENV_FILES[@]}" 2>/dev/null

    if [[ -n "${BACKUP_PASSWORD}" ]]; then
        ENV_ENC="${ENV_TAR}.enc"
        openssl enc -aes-256-cbc -pbkdf2 -iter 100000 \
            -pass "pass:${BACKUP_PASSWORD}" \
            -in "${ENV_TAR}" -out "${ENV_ENC}"
        rm -f "${ENV_TAR}"
        _add_checksum "${ENV_ENC}"
        ok ".env şifreli yedeklendi ($(du -sh "${ENV_ENC}" | cut -f1))"
    else
        _add_checksum "${ENV_TAR}"
        warn ".env şifrelenmeden yedeklendi (güvensiz!)"
    fi
else
    warn ".env dosyası bulunamadı — ortam değişkeni yedeği atlandı"
fi

# ── 4. Docker volume yedekleri ───────────────────────────────────────
echo "[4/5] Docker volume'ları yedekleniyor..."

_backup_volume() {
    local volume_name="$1"
    local label="$2"
    local out_file="${BACKUP_SET}/${label}_${DATE}.tar.gz"

    # Volume var mı?
    if ! docker volume inspect "${volume_name}" &>/dev/null; then
        warn "Volume '${volume_name}' bulunamadı — atlandı"
        return 0
    fi

    docker run --rm \
        -v "${volume_name}:/backup-src:ro" \
        alpine:latest \
        tar -czf - -C /backup-src . \
        > "${out_file}" 2>/dev/null

    if [[ -s "${out_file}" ]]; then
        _add_checksum "${out_file}"
        ok "${label} volume yedeklendi ($(du -sh "${out_file}" | cut -f1))"
    else
        rm -f "${out_file}"
        warn "${label} volume yedeği boş — atlandı"
    fi
}

_backup_volume "netguard_ssl_certs" "ssl_certs"
_backup_volume "netguard_netguard_data" "netguard_data"

# ── 5. Haftalık yedek referansı ──────────────────────────────────────
echo "[5/5] Retention politikası uygulanıyor..."

# Pazar günü (7) → haftalık yedek sembolik linki güncelle
if [[ "${DAY_OF_WEEK}" == "7" ]]; then
    WEEKLY_TARGET="${WEEKLY_LINK}/$(date '+%Y_W%V')"
    ln -sfn "${BACKUP_SET}" "${WEEKLY_TARGET}"
    ok "Haftalık yedek referansı: ${WEEKLY_TARGET}"
fi

# 7 günden eski günlük yedekleri sil
find "${BACKUP_DIR}/daily" -maxdepth 1 -type d -mtime +7 | while read -r old_dir; do
    rm -rf "${old_dir}"
    echo "  Eski yedek silindi: $(basename "${old_dir}")"
done

# 4 haftadan eski haftalık referansları sil (sadece link)
find "${WEEKLY_LINK}" -maxdepth 1 -type l -mtime +28 | while read -r old_link; do
    rm -f "${old_link}"
    echo "  Eski haftalık referans silindi: $(basename "${old_link}")"
done

ok "Retention politikası uygulandı (7 günlük + 4 haftalık)"

# ── Özet ────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════"
echo "  Yedekleme Tamamlandı"
echo "════════════════════════════════════════════════════"
echo ""
echo "  Konum:   ${BACKUP_SET}"
echo "  Boyut:   $(du -sh "${BACKUP_SET}" | cut -f1)"
echo "  Manifest: ${MANIFEST}"
echo ""
echo "  Geri yüklemek için:"
echo "    bash scripts/restore.sh --dir ${BACKUP_DIR} --date ${DATE}"
echo ""
echo "  Doğrulamak için:"
echo "    bash scripts/verify-backup.sh --set ${BACKUP_SET}"
echo ""
