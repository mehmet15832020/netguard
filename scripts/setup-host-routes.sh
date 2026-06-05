#!/bin/bash
# NetGuard host route'larını dinamik olarak ayarlar
# Docker network ID'sini otomatik bulur

set -euo pipefail

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

# netguard_netguard_net Docker network'ünden bridge adını dinamik bul
BRIDGE=""
for i in $(seq 1 15); do
    NET_ID=$(docker network inspect netguard_netguard_net --format '{{.Id}}' 2>/dev/null) && \
        BRIDGE="br-${NET_ID:0:12}" && break
    log "Docker network bekleniyor... ($i/15)"
    sleep 3
done

if [ -z "$BRIDGE" ]; then
    log "HATA: netguard_netguard_net Docker network bulunamadı"
    exit 1
fi

log "Docker bridge: $BRIDGE"

# NetGuard Server MGMT route'u ekle (192.168.203.134 → MGMT bridge üzerinden)
sudo /sbin/ip route replace 192.168.203.134/32 dev "$BRIDGE" && \
    log "Route eklendi: 192.168.203.134/32 dev $BRIDGE" || \
    log "UYARI: Route eklenemedi (sudo yetkisi gerekiyor - /etc/sudoers.d/netguard-routes kontrol et)"
