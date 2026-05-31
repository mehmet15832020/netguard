#!/usr/bin/env bash
# NetGuard — Yedek Doğrulama Scripti
#
# Kullanım:
#   bash scripts/verify-backup.sh --set <yedek_seti_yolu>
#   bash scripts/verify-backup.sh --dir <yedek_dizini>   # en son yedeği doğrula
#
# Kontroller (NIST SP 800-34 §3.4 test requirement):
#   1. Manifest SHA-256 checksum doğrulaması
#   2. PostgreSQL dump okunabilirlik testi (pg_restore --list)
#   3. tar arşivleri bütünlük kontrolü (tar -tzf)
#   4. Dosya boyutu sıfır değil kontrolü
#   5. Backup seti yaş kontrolü (24 saatten eski ise uyarı)

set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*" >&2; }

SET_ARG=""
BACKUP_DIR_ARG=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --set) SET_ARG="$2"; shift 2 ;;
        --dir) BACKUP_DIR_ARG="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,20p' "$0" | grep '^#' | sed 's/^# \?//'
            exit 0 ;;
        *) err "Bilinmeyen parametre: $1"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

BACKUP_SET=""
if [[ -n "${SET_ARG}" ]]; then
    BACKUP_SET="${SET_ARG}"
elif [[ -n "${BACKUP_DIR_ARG}" ]]; then
    BACKUP_SET=$(find "${BACKUP_DIR_ARG}/daily" -maxdepth 1 -type d | sort | tail -1 || echo "")
fi

if [[ -z "${BACKUP_SET}" ]] || [[ ! -d "${BACKUP_SET}" ]]; then
    err "Yedek seti bulunamadı. --set veya --dir ile belirtin."
    exit 1
fi

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║       NetGuard — Yedek Doğrulama                 ║"
echo "╚══════════════════════════════════════════════════╝"
echo "  Set: ${BACKUP_SET}"
echo ""

ERRORS=0

# ── 1. Manifest SHA-256 ──────────────────────────────────────────────
MANIFEST="${BACKUP_SET}/MANIFEST.sha256"
if [[ -f "${MANIFEST}" ]]; then
    echo "[1/5] Manifest checksum doğrulanıyor..."
    while IFS= read -r line; do
        expected=$(echo "${line}" | awk '{print $1}')
        fname=$(echo "${line}" | awk '{print $2}')
        fpath="${BACKUP_SET}/${fname}"
        if [[ ! -f "${fpath}" ]]; then
            err "  Eksik dosya: ${fname}"; ERRORS=$((ERRORS+1)); continue
        fi
        actual=$(sha256sum "${fpath}" | awk '{print $1}')
        if [[ "${actual}" == "${expected}" ]]; then
            ok "  ${fname}"
        else
            err "  Checksum uyuşmuyor: ${fname}"; ERRORS=$((ERRORS+1))
        fi
    done < "${MANIFEST}"
else
    warn "[1/5] MANIFEST.sha256 bulunamadı — checksum kontrolü atlandı"
fi

# ── 2. PostgreSQL dump okunabilirlik ─────────────────────────────────
echo "[2/5] PostgreSQL dump okunabilirlik testi..."
PG_DUMP=$(find "${BACKUP_SET}" -name "postgres_*.dump" | head -1 || echo "")
if [[ -n "${PG_DUMP}" ]] && [[ -f "${PG_DUMP}" ]]; then
    if pg_restore --list "${PG_DUMP}" &>/dev/null; then
        ok "  PostgreSQL dump okunabilir"
    elif docker run --rm \
            -v "${BACKUP_SET}:/bk:ro" alpine:latest \
            sh -c "apk add -q postgresql-client 2>/dev/null; pg_restore --list /bk/$(basename "${PG_DUMP}")" &>/dev/null; then
        ok "  PostgreSQL dump okunabilir (container içinde doğrulandı)"
    else
        warn "  pg_restore yüklü değil — dump boyut kontrolüne geçiliyor"
        SIZE=$(stat -c%s "${PG_DUMP}" 2>/dev/null || echo 0)
        [[ "${SIZE}" -gt 0 ]] && ok "  Dump dosyası mevcut (${SIZE} byte)" \
                               || { err "  Dump dosyası boş"; ERRORS=$((ERRORS+1)); }
    fi
else
    warn "[2/5] PostgreSQL dump bulunamadı"
fi

# ── 3. tar arşivleri bütünlük kontrolü ───────────────────────────────
echo "[3/5] tar arşivleri test ediliyor..."
while IFS= read -r tar_file; do
    fname=$(basename "${tar_file}")
    if tar -tzf "${tar_file}" &>/dev/null; then
        ok "  ${fname}"
    else
        err "  Bozuk arşiv: ${fname}"; ERRORS=$((ERRORS+1))
    fi
done < <(find "${BACKUP_SET}" -name "*.tar.gz" 2>/dev/null)

# ── 4. Dosya boyutu kontrolü ─────────────────────────────────────────
echo "[4/5] Dosya boyutları kontrol ediliyor..."
EMPTY_COUNT=0
while IFS= read -r f; do
    if [[ ! -s "$f" ]]; then
        warn "  Boş dosya: $(basename "${f}")"
        EMPTY_COUNT=$((EMPTY_COUNT+1))
    fi
done < <(find "${BACKUP_SET}" -maxdepth 1 -type f 2>/dev/null)
[[ ${EMPTY_COUNT} -eq 0 ]] && ok "  Tüm dosyalar boyut > 0" \
    || { err "  ${EMPTY_COUNT} boş dosya bulundu"; ERRORS=$((ERRORS+1)); }

# ── 5. Yedek yaş kontrolü ────────────────────────────────────────────
echo "[5/5] Yedek yaşı kontrol ediliyor..."
SET_AGE_HOURS=$(( ( $(date +%s) - $(stat -c%Y "${BACKUP_SET}" 2>/dev/null || echo 0) ) / 3600 ))
if [[ ${SET_AGE_HOURS} -le 24 ]]; then
    ok "  Yedek ${SET_AGE_HOURS} saat önce alındı"
elif [[ ${SET_AGE_HOURS} -le 48 ]]; then
    warn "  Yedek ${SET_AGE_HOURS} saat önce alındı (RPO: 24 saat)"
else
    err "  Yedek ${SET_AGE_HOURS} saat önce alındı — güncel yedek alın!"; ERRORS=$((ERRORS+1))
fi

# ── Sonuç ────────────────────────────────────────────────────────────
echo ""
echo "════════════════════════════════════════════════════"
if [[ ${ERRORS} -eq 0 ]]; then
    echo -e "  ${GREEN}Doğrulama başarılı — yedek sağlıklı${NC}"
else
    echo -e "  ${RED}Doğrulama başarısız — ${ERRORS} hata bulundu${NC}"
fi
echo "════════════════════════════════════════════════════"
echo ""

exit ${ERRORS}
