#!/bin/bash
# NetGuard — Suricata ET Kural Otomatik Güncelleme
#
# Kullanım:
#   suricata-update-cron.sh [job_id]
#
# Ortam değişkenleri (override için):
#   SURICATA_CONF     /etc/suricata/suricata.yaml
#   SURICATA_OUTPUT   /var/lib/suricata/update/rules
#   DISABLE_CONF      /etc/suricata/disable.conf
#   MODIFY_CONF       /etc/suricata/modify.conf
#   STATE_FILE        /var/lib/netguard/suricata_update_state.json
#   LOG_FILE          /var/log/netguard/suricata-update.log
#   SURICATA_SOURCES  et/open (boşlukla ayrılmış liste)
#
# Kaynaklar:
#   CIS Controls v8.1 Safeguard 13.8 — IDS kural güncelliği
#   NIST SP 800-94 §4.1 — Signature update automation

set -euo pipefail

SURICATA_CONF="${SURICATA_CONF:-/etc/suricata/suricata.yaml}"
SURICATA_OUTPUT="${SURICATA_OUTPUT:-/var/lib/suricata/update/rules}"
DISABLE_CONF="${DISABLE_CONF:-/etc/suricata/disable.conf}"
MODIFY_CONF="${MODIFY_CONF:-/etc/suricata/modify.conf}"
STATE_FILE="${STATE_FILE:-/var/lib/netguard/suricata_update_state.json}"
LOG_FILE="${LOG_FILE:-/var/log/netguard/suricata-update.log}"
LOCK_FILE="${LOCK_FILE:-/var/lock/netguard-suricata-update.lock}"
SURICATA_SOURCES="${SURICATA_SOURCES:-et/open}"

JOB_ID="${1:-manual-$(date +%s)}"

_log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }

_write_state() {
    local status="$1" rule_count="${2:-0}" reload_status="${3:-not_attempted}"
    local error_msg="${4:-null}" duration_ms="${5:-0}" checksum="${6:-}"
    mkdir -p "$(dirname "$STATE_FILE")"
    local checksum_field
    checksum_field="$([ -n "$checksum" ] && echo "\"$checksum\"" || echo "null")"
    local error_field
    error_field="$([ "$error_msg" = "null" ] && echo "null" || echo "\"$error_msg\"")"
    cat > "$STATE_FILE" <<JSON
{
  "job_id": "$JOB_ID",
  "last_updated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "rule_count": $rule_count,
  "status": "$status",
  "reload_status": "$reload_status",
  "duration_ms": $duration_ms,
  "error": $error_field,
  "checksum": $checksum_field,
  "sources": "$(echo "$SURICATA_SOURCES" | tr ' ' ',')"
}
JSON
}

mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$STATE_FILE")"

(
    flock -n 200 || {
        _log "ERROR: Başka bir update işi çalışıyor (lock: $LOCK_FILE)" | tee -a "$LOG_FILE"
        exit 1
    }

    {
        _log "N4 Suricata kural güncelleme başladı — job=$JOB_ID"
        START_NS=$(date +%s%N)

        _write_state "running" 0 "not_attempted" "null" 0

        # suricata-update argümanları
        UPDATE_ARGS=(
            "--no-reload"
            "--output" "$SURICATA_OUTPUT"
        )
        [ -f "$SURICATA_CONF" ]   && UPDATE_ARGS+=("--suricata-conf" "$SURICATA_CONF")
        [ -f "$DISABLE_CONF" ]    && UPDATE_ARGS+=("--disable-conf"  "$DISABLE_CONF")
        [ -f "$MODIFY_CONF" ]     && UPDATE_ARGS+=("--modify-conf"   "$MODIFY_CONF")
        for src in $SURICATA_SOURCES; do
            UPDATE_ARGS+=("-s" "$src")
        done

        _log "Komut: suricata-update ${UPDATE_ARGS[*]}"

        UPDATE_STATUS="failed"
        RULE_COUNT=0
        RELOAD_STATUS="not_attempted"
        CHECKSUM=""
        ERROR_MSG="null"

        if suricata-update "${UPDATE_ARGS[@]}" 2>&1; then
            UPDATE_STATUS="success"
            RULES_FILE="$SURICATA_OUTPUT/suricata.rules"
            if [ -f "$RULES_FILE" ]; then
                RULE_COUNT=$(grep -cE '^(alert|drop|pass|reject) ' "$RULES_FILE" 2>/dev/null || echo 0)
                CHECKSUM=$(sha256sum "$RULES_FILE" | awk '{print $1}')
            fi
            _log "Kural güncelleme başarılı: $RULE_COUNT kural"

            # Live reload: suricatasc önce, USR2 fallback
            if command -v suricatasc &>/dev/null; then
                _log "Reload: suricatasc -c reload-rules"
                if RELOAD_OUT=$(suricatasc -c reload-rules 2>&1); then
                    if echo "$RELOAD_OUT" | grep -q '"return".*"OK"'; then
                        RELOAD_STATUS="ok"
                        _log "Reload başarılı"
                    else
                        RELOAD_STATUS="failed"
                        UPDATE_STATUS="partial"
                        _log "WARN: suricatasc reload başarısız: $RELOAD_OUT"
                    fi
                else
                    RELOAD_STATUS="socket_error"
                    UPDATE_STATUS="partial"
                    _log "WARN: suricatasc bağlanamadı, USR2 deneniyor"
                    _try_usr2_reload || true
                fi
            else
                _log "suricatasc yok, USR2 deneniyor"
                if _try_usr2_reload; then
                    RELOAD_STATUS="usr2_ok"
                else
                    RELOAD_STATUS="reload_unavailable"
                    UPDATE_STATUS="partial"
                fi
            fi
        else
            UPDATE_STATUS="failed"
            ERROR_MSG="suricata-update exit non-zero"
            _log "HATA: suricata-update başarısız"
        fi

        END_NS=$(date +%s%N)
        DURATION_MS=$(( (END_NS - START_NS) / 1000000 ))

        _write_state "$UPDATE_STATUS" "$RULE_COUNT" "$RELOAD_STATUS" \
                     "$ERROR_MSG" "$DURATION_MS" "$CHECKSUM"

        _log "Tamamlandı: status=$UPDATE_STATUS kurallar=$RULE_COUNT reload=$RELOAD_STATUS süre=${DURATION_MS}ms"

    } 2>&1 | tee -a "$LOG_FILE"

) 200>"$LOCK_FILE"

_try_usr2_reload() {
    for pid_file in /var/run/suricata/suricata.pid /var/run/suricata.pid; do
        if [ -f "$pid_file" ]; then
            local pid
            pid=$(cat "$pid_file")
            if kill -0 "$pid" 2>/dev/null; then
                kill -USR2 "$pid" && _log "USR2 gönderildi (PID=$pid)" && return 0
            fi
        fi
    done
    return 1
}
