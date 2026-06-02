#!/bin/bash
# NetGuard — Suricata ET Kural Otomatik Güncelleme
#
# Kullanım: suricata-update-cron.sh [job_id]
#
# Env override: SURICATA_CONF, SURICATA_OUTPUT, DISABLE_CONF,
#               MODIFY_CONF, STATE_FILE, LOG_FILE, SURICATA_SOURCES
#
# Kaynaklar: CIS Controls v8.1 Safeguard 13.8, NIST SP 800-94 §4.1

set -euo pipefail

SURICATA_CONF="${SURICATA_CONF:-/etc/suricata/suricata.yaml}"
SURICATA_OUTPUT="${SURICATA_OUTPUT:-/var/lib/suricata/rules}"
DISABLE_CONF="${DISABLE_CONF:-/etc/suricata/disable.conf}"
MODIFY_CONF="${MODIFY_CONF:-/etc/suricata/modify.conf}"
STATE_FILE="${STATE_FILE:-/var/lib/netguard/suricata_update_state.json}"
LOG_FILE="${LOG_FILE:-/var/log/netguard/suricata-update.log}"
LOCK_FILE="${LOCK_FILE:-/var/lock/netguard-suricata-update.lock}"
SURICATA_SOURCES="${SURICATA_SOURCES:-et/open}"

JOB_ID="${1:-manual-$(date +%s)}"

mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$STATE_FILE")"

_log() {
    echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" | tee -a "$LOG_FILE"
}

_write_state() {
    local status="$1" rule_count="${2:-0}" reload_status="${3:-not_attempted}"
    local error_msg="${4:-null}" duration_ms="${5:-0}" checksum="${6:-}"
    local checksum_json error_json
    checksum_json="$([ -n "$checksum" ] && printf '"%s"' "$checksum" || echo "null")"
    error_json="$([ "$error_msg" = "null" ] && echo "null" || printf '"%s"' "$error_msg")"
    cat > "$STATE_FILE" <<JSON
{
  "job_id": "$JOB_ID",
  "last_updated": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "rule_count": $rule_count,
  "status": "$status",
  "reload_status": "$reload_status",
  "duration_ms": $duration_ms,
  "error": $error_json,
  "checksum": $checksum_json,
  "sources": "$SURICATA_SOURCES"
}
JSON
}

_try_reload() {
    if command -v suricatasc &>/dev/null; then
        local out
        out=$(suricatasc -c reload-rules 2>&1) || true
        if echo "$out" | grep -q '"return".*"OK"'; then
            echo "ok"
        else
            _log "WARN: suricatasc reload yanıtı: $out"
            echo "failed"
        fi
    else
        for pid_file in /var/run/suricata/suricata.pid /var/run/suricata.pid; do
            if [ -f "$pid_file" ]; then
                local pid; pid=$(cat "$pid_file")
                if kill -0 "$pid" 2>/dev/null && kill -USR2 "$pid" 2>/dev/null; then
                    _log "USR2 gönderildi (PID=$pid)"
                    echo "usr2_ok"
                    return
                fi
            fi
        done
        echo "reload_unavailable"
    fi
}

(
    flock -n 200 || {
        _log "ERROR: Başka bir güncelleme çalışıyor — çıkılıyor"
        exit 1
    }

    _log "Başladı: job=$JOB_ID"
    START_NS=$(date +%s%N)
    _write_state "running"

    # Kaynakları etkinleştir (bir kez yeterli, idempotent)
    for src in $SURICATA_SOURCES; do
        suricata-update enable-source "$src" >> "$LOG_FILE" 2>&1 || true
    done

    # Kural güncelleme argümanları
    UPDATE_ARGS=("--no-reload" "-o" "$SURICATA_OUTPUT")
    [ -f "$SURICATA_CONF" ] && UPDATE_ARGS+=("--suricata-conf" "$SURICATA_CONF")
    [ -f "$DISABLE_CONF"  ] && UPDATE_ARGS+=("--disable-conf"  "$DISABLE_CONF")
    [ -f "$MODIFY_CONF"   ] && UPDATE_ARGS+=("--modify-conf"   "$MODIFY_CONF")

    _log "Komut: suricata-update ${UPDATE_ARGS[*]}"

    UPDATE_STATUS="failed"
    RULE_COUNT=0
    RELOAD_STATUS="not_attempted"
    CHECKSUM=""
    ERROR_MSG="suricata-update exit non-zero"

    set +e
    suricata-update "${UPDATE_ARGS[@]}" >> "$LOG_FILE" 2>&1
    UPDATE_EXIT=$?
    set -e

    if [ $UPDATE_EXIT -eq 0 ]; then
        UPDATE_STATUS="success"
        ERROR_MSG="null"
        RULES_FILE="$SURICATA_OUTPUT/suricata.rules"
        if [ -f "$RULES_FILE" ]; then
            RULE_COUNT=$(grep -cE '^(alert|drop|pass|reject) ' "$RULES_FILE" 2>/dev/null || echo 0)
            CHECKSUM=$(sha256sum "$RULES_FILE" | awk '{print $1}')
        fi
        _log "Güncelleme başarılı: $RULE_COUNT kural"

        RELOAD_STATUS=$(_try_reload)
        _log "Reload: $RELOAD_STATUS"
        if [ "$RELOAD_STATUS" = "failed" ]; then
            UPDATE_STATUS="partial"
        fi
    else
        _log "HATA: suricata-update başarısız (exit=$UPDATE_EXIT)"
    fi

    END_NS=$(date +%s%N)
    DURATION_MS=$(( (END_NS - START_NS) / 1000000 ))

    _write_state "$UPDATE_STATUS" "$RULE_COUNT" "$RELOAD_STATUS" \
                 "$ERROR_MSG" "$DURATION_MS" "$CHECKSUM"

    _log "Tamamlandı: status=$UPDATE_STATUS kurallar=$RULE_COUNT reload=$RELOAD_STATUS süre=${DURATION_MS}ms"

) 200>"$LOCK_FILE"
