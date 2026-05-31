#!/usr/bin/env bash
# NetGuard — Geri Yükleme Scripti
#
# Kullanım:
#   bash scripts/restore.sh --dir <yedek_dizini> --date <YYYYMMDD_HHMMSS>
#   bash scripts/restore.sh --dir <yedek_dizini>              # en son yedek
#   bash scripts/restore.sh --set <tam_yedek_seti_yolu>
#   bash scripts/restore.sh --set <yol> --dry-run
#
# Seçenekler:
#   --dir <dizin>    Yedek ana dizini (backup.sh --dir ile aynı değer)
#   --date <tarih>   Belirli bir tarihli yedeği geri yükle (YYYYMMDD_HHMMSS)
#   --set <yol>      Tam yedek seti dizini
#   --password <şifre> .env dosyası çözme parolası
#   --dry-run        Dosyaları kopyalamadan adımları göster
#   --skip-db        Veritabanı geri yüklemesini atla
#   --skip-volumes   Volume geri yüklemesini atla
#
# Restore sırası (NIST SP 800-34 §4.1):
#   1. Servisleri durdur
#   2. PostgreSQL geri yükle (pg_restore)
#   3. Config geri yükle
#   4. .env geri yükle (şifreli ise çöz)
#   5. Docker volume'larını geri yükle
#   6. Servisleri başlat
#   7. Sağlık kontrolü

set -euo pipefail

# ── Renk kodları ────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }
dry()  { echo -e "  [DRY-RUN] $*"; }

# ── Argüman işleme ──────────────────────────────────────────────────
BACKUP_DIR_ARG=""
DATE_ARG=""
SET_ARG=""
BACKUP_PASS_ARG=""
DRY_RUN=0
SKIP_DB=0
SKIP_VOLUMES=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir)       BACKUP_DIR_ARG="$2"; shift 2 ;;
        --date)      DATE_ARG="$2"; shift 2 ;;
        --set)       SET_ARG="$2"; shift 2 ;;
        --password)  BACKUP_PASS_ARG="$2"; shift 2 ;;
        --dry-run)   DRY_RUN=1; shift ;;
        --skip-db)   SKIP_DB=1; shift ;;
        --skip-volumes) SKIP_VOLUMES=1; shift ;;
        -h|--help)
            sed -n '2,35p' "$0" | grep '^#' | sed 's/^# \?//'
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
    while IFS= read -r line; do
        if [[ "$line" =~ ^[A-Z_][A-Z0-9_]*= ]] && [[ ! "$line" =~ ^# ]]; then
            declare -x "${line%%=*}"="${line#*=}" 2>/dev/null || true
        fi
    done < .env
fi

BACKUP_PASSWORD="${BACKUP_PASS_ARG:-${BACKUP_PASSWORD:-}}"
POSTGRES_PASSWORD="${POSTGRES_PASSWORD:-netguard_dev}"
BACKUP_DIR="${BACKUP_DIR_ARG:-${BACKUP_DIR:-${PROJECT_ROOT}/backups}}"

# ── Yedek seti belirle ───────────────────────────────────────────────
BACKUP_SET=""
if [[ -n "${SET_ARG}" ]]; then
    BACKUP_SET="${SET_ARG}"
elif [[ -n "${DATE_ARG}" ]]; then
    BACKUP_SET="${BACKUP_DIR}/daily/${DATE_ARG}"
elif [[ -n "${BACKUP_DIR_ARG}" ]]; then
    # En son günlük yedeği bul
    BACKUP_SET=$(find "${BACKUP_DIR}/daily" -maxdepth 1 -type d \
        | sort | tail -1 2>/dev/null || echo "")
fi

if [[ -z "${BACKUP_SET}" ]] || [[ ! -d "${BACKUP_SET}" ]]; then
    err "Yedek seti bulunamadı. --set veya --dir ile belirtin."
    err "Mevcut yedekler: ls ${BACKUP_DIR}/daily/"
    exit 1
fi

MANIFEST="${BACKUP_SET}/MANIFEST.sha256"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║         NetGuard — Geri Yükleme Başlıyor         ║"
[[ ${DRY_RUN} -eq 1 ]] && \
echo "║              *** DRY-RUN MODU ***                ║"
echo "╚══════════════════════════════════════════════════╝"
echo "  Kaynak: ${BACKUP_SET}"
echo ""

# ── Manifest doğrulaması ─────────────────────────────────────────────
if [[ -f "${MANIFEST}" ]]; then
    echo "Yedek bütünlüğü doğrulanıyor..."
    VERIFY_FAILED=0
    while IFS= read -r line; do
        expected_hash=$(echo "${line}" | awk '{print $1}')
        filename=$(echo "${line}" | awk '{print $2}')
        full_path="${BACKUP_SET}/${filename}"
        if [[ -f "${full_path}" ]]; then
            actual_hash=$(sha256sum "${full_path}" | awk '{print $1}')
            if [[ "${actual_hash}" != "${expected_hash}" ]]; then
                err "Checksum uyuşmazlığı: ${filename}"
                VERIFY_FAILED=1
            fi
        else
            warn "Manifest'te kayıtlı dosya bulunamadı: ${filename}"
        fi
    done < "${MANIFEST}"
    if [[ ${VERIFY_FAILED} -eq 1 ]]; then
        err "Yedek bütünlüğü doğrulanamadı — restore iptal edildi"
        exit 1
    fi
    ok "Manifest doğrulandı"
else
    warn "MANIFEST.sha256 bulunamadı — bütünlük kontrolü atlandı"
fi

# ── Kullanıcı onayı ─────────────────────────────────────────────────
if [[ ${DRY_RUN} -eq 0 ]]; then
    echo ""
    warn "Bu işlem mevcut veritabanını ve konfigürasyonu ÜZERİNE YAZACAK!"
    echo -n "  Devam etmek istiyor musunuz? [yes/N]: "
    read -r confirm
    if [[ "${confirm}" != "yes" ]]; then
        echo "İptal edildi."
        exit 0
    fi
fi

# ── 1. Servisleri durdur ─────────────────────────────────────────────
echo ""
echo "[1/6] Servisler durduruluyor..."

if [[ ${DRY_RUN} -eq 1 ]]; then
    dry "docker compose down"
else
    docker compose down 2>/dev/null || true
    ok "Servisler durduruldu"
fi

# ── 2. PostgreSQL geri yükle ─────────────────────────────────────────
if [[ ${SKIP_DB} -eq 0 ]]; then
    echo "[2/6] PostgreSQL geri yükleniyor..."

    PG_DUMP=$(find "${BACKUP_SET}" -name "postgres_*.dump" | head -1 || echo "")
    if [[ -n "${PG_DUMP}" ]] && [[ -f "${PG_DUMP}" ]]; then
        if [[ ${DRY_RUN} -eq 1 ]]; then
            dry "docker compose up -d postgres && pg_restore ${PG_DUMP}"
        else
            docker compose up -d postgres
            echo -n "  PostgreSQL hazır bekleniyor"
            for _ in $(seq 1 24); do
                if docker compose exec -T postgres \
                    pg_isready -U netguard -d netguard &>/dev/null; then
                    break
                fi
                echo -n "."
                sleep 5
            done
            echo ""

            # Mevcut DB'yi temizle ve geri yükle
            docker compose exec -T postgres \
                env PGPASSWORD="${POSTGRES_PASSWORD}" \
                psql -U netguard -d postgres -c \
                "DROP DATABASE IF EXISTS netguard;" 2>/dev/null || true

            docker compose exec -T postgres \
                env PGPASSWORD="${POSTGRES_PASSWORD}" \
                psql -U netguard -d postgres -c \
                "CREATE DATABASE netguard;" 2>/dev/null

            docker compose exec -T postgres \
                env PGPASSWORD="${POSTGRES_PASSWORD}" \
                pg_restore -U netguard -d netguard --no-owner --role=netguard \
                < "${PG_DUMP}"

            ok "PostgreSQL geri yüklendi"
        fi
    else
        warn "PostgreSQL dump dosyası bulunamadı — DB geri yüklemesi atlandı"
    fi
else
    warn "DB geri yüklemesi atlandı (--skip-db)"
fi

# ── 3. Config geri yükle ─────────────────────────────────────────────
echo "[3/6] Konfigürasyon dosyaları geri yükleniyor..."

CONFIG_TAR=$(find "${BACKUP_SET}" -name "config_*.tar.gz" | head -1 || echo "")
if [[ -n "${CONFIG_TAR}" ]] && [[ -f "${CONFIG_TAR}" ]]; then
    if [[ ${DRY_RUN} -eq 1 ]]; then
        dry "tar -xzf ${CONFIG_TAR} -C ${PROJECT_ROOT}/"
    else
        cp -r "${PROJECT_ROOT}/config" "${PROJECT_ROOT}/config.bak.${DATE_ARG:-$(date +%s)}" 2>/dev/null || true
        tar -xzf "${CONFIG_TAR}" -C "${PROJECT_ROOT}/"
        ok "Config geri yüklendi"
    fi
else
    warn "Config arşivi bulunamadı — atlandı"
fi

# ── 4. .env geri yükle ───────────────────────────────────────────────
echo "[4/6] Ortam değişkenleri geri yükleniyor..."

ENV_ENC=$(find "${BACKUP_SET}" -name "env_*.tar.gz.enc" | head -1 || echo "")
ENV_TAR=$(find "${BACKUP_SET}" -name "env_*.tar.gz" ! -name "*.enc" | head -1 || echo "")

if [[ -n "${ENV_ENC}" ]] && [[ -f "${ENV_ENC}" ]]; then
    if [[ -z "${BACKUP_PASSWORD}" ]]; then
        err "Şifreli .env dosyası bulundu ama BACKUP_PASSWORD tanımlanmamış"
        err "--password parametresi ile şifre girin"
        exit 1
    fi
    if [[ ${DRY_RUN} -eq 1 ]]; then
        dry "openssl dec ${ENV_ENC} | tar -xz -C ${PROJECT_ROOT}/"
    else
        cp "${PROJECT_ROOT}/.env" "${PROJECT_ROOT}/.env.bak.$(date +%s)" 2>/dev/null || true
        openssl enc -d -aes-256-cbc -pbkdf2 -iter 100000 \
            -pass "pass:${BACKUP_PASSWORD}" \
            -in "${ENV_ENC}" \
            | tar -xzf - -C "${PROJECT_ROOT}/"
        ok ".env (şifreli) geri yüklendi"
    fi
elif [[ -n "${ENV_TAR}" ]] && [[ -f "${ENV_TAR}" ]]; then
    if [[ ${DRY_RUN} -eq 1 ]]; then
        dry "tar -xzf ${ENV_TAR} -C ${PROJECT_ROOT}/"
    else
        cp "${PROJECT_ROOT}/.env" "${PROJECT_ROOT}/.env.bak.$(date +%s)" 2>/dev/null || true
        tar -xzf "${ENV_TAR}" -C "${PROJECT_ROOT}/"
        ok ".env geri yüklendi"
    fi
else
    warn ".env arşivi bulunamadı — atlandı"
fi

# ── 5. Docker volume'larını geri yükle ───────────────────────────────
if [[ ${SKIP_VOLUMES} -eq 0 ]]; then
    echo "[5/6] Docker volume'ları geri yükleniyor..."

    _restore_volume() {
        local label="$1"
        local volume_name="$2"
        local tar_file
        tar_file=$(find "${BACKUP_SET}" -name "${label}_*.tar.gz" | head -1 || echo "")

        if [[ -z "${tar_file}" ]] || [[ ! -f "${tar_file}" ]]; then
            warn "${label} volume yedeği bulunamadı — atlandı"
            return 0
        fi

        if [[ ${DRY_RUN} -eq 1 ]]; then
            dry "docker volume restore ${volume_name} < ${tar_file}"
            return 0
        fi

        docker volume create "${volume_name}" &>/dev/null || true
        docker run --rm \
            -v "${volume_name}:/restore-dst" \
            -i alpine:latest \
            tar -xzf - -C /restore-dst \
            < "${tar_file}"
        ok "${label} volume geri yüklendi"
    }

    _restore_volume "ssl_certs"    "netguard_ssl_certs"
    _restore_volume "netguard_data" "netguard_netguard_data"
else
    warn "Volume geri yüklemesi atlandı (--skip-volumes)"
fi

# ── 6. Servisleri başlat ─────────────────────────────────────────────
echo "[6/6] Servisler başlatılıyor..."

if [[ ${DRY_RUN} -eq 1 ]]; then
    dry "docker compose up -d"
    dry "Sağlık kontrolü: docker compose ps"
else
    docker compose up -d
    echo -n "  Backend hazır bekleniyor"
    for _ in $(seq 1 24); do
        status=$(docker inspect --format='{{.State.Health.Status}}' \
            "$(docker compose ps -q backend 2>/dev/null | head -1)" 2>/dev/null || echo "")
        if [[ "${status}" == "healthy" ]]; then break; fi
        echo -n "."
        sleep 5
    done
    echo ""
    ok "Servisler başlatıldı"
fi

echo ""
echo "════════════════════════════════════════════════════"
[[ ${DRY_RUN} -eq 1 ]] && echo "  Dry-run tamamlandı (değişiklik yapılmadı)" \
                        || echo "  Geri Yükleme Tamamlandı"
echo "════════════════════════════════════════════════════"
echo ""
[[ ${DRY_RUN} -eq 0 ]] && echo "  Durum kontrolü: docker compose ps"
echo ""
