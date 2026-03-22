#!/bin/bash
# NetGuard Agent kurulum scripti
# Kullanım: bash install-agent.sh <SERVER_IP>
# Örnek:    bash install-agent.sh 192.168.203.134

set -e  # Hata olursa dur

SERVER_IP=${1:?"Kullanım: bash install-agent.sh <SERVER_IP>"}

echo "=================================================="
echo "NetGuard Agent Kurulumu"
echo "Server: $SERVER_IP"
echo "=================================================="

# 1. Sistem güncelleme
echo "[1/5] Sistem güncelleniyor..."
sudo apt update -qq
sudo apt install -y python3 python3-pip python3-venv git -qq

# 2. Kodu kopyala (server'dan değil, bu scriptle birlikte gelir)
echo "[2/5] NetGuard kodu hazırlanıyor..."
cd ~
if [ -d "netguard" ]; then
    echo "netguard klasörü zaten var, güncelleniyor..."
    cd netguard
else
    echo "HATA: netguard klasörü bulunamadı."
    echo "Önce: scp -r <ana_makine_ip>:~/netguard ~/"
    exit 1
fi

# 3. Python sanal ortamı
echo "[3/5] Python ortamı kuruluyor..."
python3 -m venv venv
source venv/bin/activate
python3 -m ensurepip --upgrade 2>/dev/null || true
pip install --upgrade pip -q
pip install -r requirements.txt -q

# 4. Systemd servis dosyası
echo "[4/5] Agent servisi oluşturuluyor..."
AGENT_SERVICE="/etc/systemd/system/netguard-agent.service"
sudo tee $AGENT_SERVICE > /dev/null << EOF
[Unit]
Description=NetGuard Agent
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$HOME/netguard
Environment="NETGUARD_SERVER_URL=http://${SERVER_IP}:8000"
ExecStart=$HOME/netguard/venv/bin/python3 -m agent.main
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# 5. Servisi başlat
echo "[5/5] Agent servisi başlatılıyor..."
sudo systemctl daemon-reload
sudo systemctl enable netguard-agent
sudo systemctl start netguard-agent
sleep 2
sudo systemctl status netguard-agent --no-pager

echo ""
echo "=================================================="
echo "Kurulum tamamlandı!"
echo "Server: http://${SERVER_IP}:8000"
echo "Log: journalctl -u netguard-agent -f"
echo "=================================================="
