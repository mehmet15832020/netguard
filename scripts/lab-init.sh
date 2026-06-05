#!/bin/bash
# NetGuard Lab Initialization Script
# GNS3 proje node'larının network/servislerini başlatır
# Systemd service tarafından GNS3 başladıktan sonra çalıştırılır

set -euo pipefail

LOG="/var/log/netguard-lab-init.log"
GNS3_URL="http://localhost:3080"
GNS3_CREDS="admin:KLMwSeS0mklkToRm5EAWuhBgumnr0HHrD2ezvIVikaeDy3V5AJmYC3AsbMIMytaK"
PROJECT_ID="733f4176-b1dc-4632-916a-a60228f2b316"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG"; }

log "=== NetGuard Lab Init başlıyor ==="

# 1. GNS3 API hazır mı bekle
log "GNS3 API bekleniyor..."
for i in $(seq 1 30); do
    if curl -sf -u "$GNS3_CREDS" "$GNS3_URL/v2/version" > /dev/null 2>&1; then
        log "GNS3 API hazır."
        break
    fi
    sleep 2
done

# 2. Proje açık mı kontrol et, değilse aç
STATUS=$(curl -sf -u "$GNS3_CREDS" "$GNS3_URL/v2/projects/$PROJECT_ID" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null || echo "unknown")
log "Proje durumu: $STATUS"

if [ "$STATUS" != "opened" ]; then
    log "Proje açılıyor..."
    curl -sf -u "$GNS3_CREDS" -X POST "$GNS3_URL/v2/projects/$PROJECT_ID/open" > /dev/null 2>&1 || true
    sleep 5
fi

# 3. Tüm node'ları başlat
log "Node'lar başlatılıyor..."
curl -sf -u "$GNS3_CREDS" -X POST "$GNS3_URL/v2/projects/$PROJECT_ID/nodes/start" > /dev/null 2>&1 || true
sleep 30

# 4. Alpine WebServer ISOLINUX prompt'unu geç (Enter gönder)
log "Alpine ISOLINUX boot prompt geçiliyor..."
WEBSERVER_MON=$(ps aux 2>/dev/null | grep "qemu.*WebServer" | grep -oP 'monitor tcp:127.0.0.1:\K[0-9]+' | head -1)
if [ -n "$WEBSERVER_MON" ]; then
    echo "sendkey ret" | nc -q1 127.0.0.1 "$WEBSERVER_MON" > /dev/null 2>&1 || true
    log "Alpine Enter gönderildi (port $WEBSERVER_MON)"
fi

# 5. Host route'ları güncelle
log "Host route'ları güncelleniyor..."
sudo ip route replace 192.168.203.134/32 dev br-44b4e83253ed 2>/dev/null || true

# 6. MGMT bridge fix
log "MGMT bridge kontrol ediliyor..."
if ! ping -c1 -W2 192.168.203.134 > /dev/null 2>&1; then
    log "MGMT bridge fix çalıştırılıyor..."
    ~/fix-gns3-mgmt-bridge.sh 2>/dev/null || true
    sleep 5
fi

# 7. NetGuard Server kontrolü
log "NetGuard Server bekleniyor..."
for i in $(seq 1 20); do
    if curl -skf https://192.168.203.134/api/v1/health > /dev/null 2>&1; then
        log "NetGuard Server hazır."
        break
    fi
    sleep 5
done

log "=== Lab Init tamamlandı ==="
