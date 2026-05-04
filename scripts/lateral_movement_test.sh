#!/bin/bash
# Lateral Movement Demo Scripti
#
# Kullanım (Kali'de):
#   1. Önce Agent VM'e SSH gir:
#      ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.142
#   2. Agent VM'de bu scripti çalıştır:
#      bash lateral_movement_test.sh
#
# Ne yapar:
#   Agent VM'den (192.168.203.142) iç ağdaki diğer makinelere
#   SSH/SMB/RDP portlarına bağlantı dener.
#   NetGuard'ın LateralMovementDetector'ı bunu tespit eder.

set -e

TARGETS=(
    "192.168.203.134"   # NetGuard server
    "192.168.203.200"   # VyOS router
    "192.168.203.132"   # Kali
)

PORTS=(22 445 3389)

echo "[*] Lateral movement simülasyonu başlıyor..."
echo "[*] Kaynak: $(hostname -I | awk '{print $1}')"
echo ""

for target in "${TARGETS[@]}"; do
    for port in "${PORTS[@]}"; do
        echo "[*] Deneniyor: $target:$port"
        # timeout 1 ile bağlantı dene — başarısız olsa da SYN paketi gönderilir
        timeout 1 bash -c "echo > /dev/tcp/$target/$port" 2>/dev/null || true
        sleep 0.2
    done
done

echo ""
echo "[+] Bitti. NetGuard dashboard'da Alerts ve Kill Chain kontrol et."
echo "[+] Beklenen: lateral_movement eventi → LATERAL aşaması"
