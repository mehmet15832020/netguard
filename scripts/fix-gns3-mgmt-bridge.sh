#!/bin/bash
# GNS3 MGMT-Bridge ubridge port fix
# Çalıştırma: MGMT-Bridge ubridge başlatıldıktan sonra
# Referans: GNS3 cloud.py _add_ubridge_connection + QEMU netdev socket assignment

set -euo pipefail

MGMT_UBRIDGE_PORT=45951
BRIDGE_NAME="d8a4410d-b745-435d-bdff-e886835ec066-0"
DOCKER_BRIDGE="br-44b4e83253ed"
TAP_NAME="gns3tap1-0"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

# QEMU gns3-1 portlarını bul (NetGuard-Server1 adapter 1)
find_qemu_ports() {
    ps aux | grep "34545fb4" | grep -v grep | grep -oP "socket,id=gns3-1,udp=127\.0\.0\.1:\K[0-9]+" | head -1
}

log "MGMT-Bridge ubridge fix başlıyor..."

# ubridge kontrolünü bekle
for i in $(seq 1 30); do
    if nc -z 127.0.0.1 $MGMT_UBRIDGE_PORT 2>/dev/null; then
        log "ubridge port $MGMT_UBRIDGE_PORT hazır"
        break
    fi
    sleep 2
done

# QEMU portları bul
QEMU_REMOTE=$(find_qemu_ports)
if [ -z "$QEMU_REMOTE" ]; then
    log "HATA: QEMU gns3-1 portu bulunamadı"
    exit 1
fi

# QEMU gns3-1: udp=REMOTE,localaddr=LOCAL
QEMU_LOCAL=$(ps aux | grep "34545fb4" | grep -v grep | grep -oP "socket,id=gns3-1.*?localaddr=127\.0\.0\.1:\K[0-9]+" | head -1)
log "QEMU gns3-1: local=$QEMU_LOCAL remote=$QEMU_REMOTE"

# Mevcut port yapılandırmasını kontrol et
CURRENT=$(echo "bridge list" | nc -w 1 127.0.0.1 $MGMT_UBRIDGE_PORT 2>/dev/null | grep "$BRIDGE_NAME" || true)
log "Mevcut bridge: $CURRENT"

# Bridge yeniden yapılandır
{
    echo "bridge stop $BRIDGE_NAME"
    sleep 0.3
    echo "bridge delete $BRIDGE_NAME"
    sleep 0.3
    echo "bridge create $BRIDGE_NAME"
    sleep 0.3
    # QEMU receives on LOCAL, sends to REMOTE
    # MGMT-Bridge: lport=REMOTE (receive from QEMU), rport=LOCAL (send to QEMU)
    echo "bridge add_nio_udp $BRIDGE_NAME $QEMU_REMOTE 127.0.0.1 $QEMU_LOCAL"
    sleep 0.3
    echo "bridge add_nio_tap $BRIDGE_NAME $TAP_NAME"
    sleep 0.5
} | nc -w 3 127.0.0.1 $MGMT_UBRIDGE_PORT

sleep 1

# TAP bridge'e ekle
{
    echo "brctl addif \"$DOCKER_BRIDGE\" \"$TAP_NAME\""
    sleep 0.3
    echo "bridge start $BRIDGE_NAME"
    sleep 0.3
} | nc -w 3 127.0.0.1 $MGMT_UBRIDGE_PORT

# TAP up yap
ip link set $TAP_NAME up 2>/dev/null || true

log "MGMT-Bridge fix tamamlandı. TAP: $TAP_NAME → $DOCKER_BRIDGE"

# Proxy ARP etkinleştir (192.168.203.134'e host'tan erişim için)
if ssh -i /home/mehmet/.ssh/id_ed25519 -o StrictHostKeyChecking=no -o ConnectTimeout=5 netguard@172.18.0.134 \
    "echo 1 | sudo tee /proc/sys/net/ipv4/conf/ens4/proxy_arp > /dev/null" 2>/dev/null; then
    log "Proxy ARP ens4 etkinleştirildi"
fi
