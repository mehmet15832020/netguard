#!/bin/bash
# NetGuard Agent kurulum scripti — VM2 (agent) üzerinde root olarak çalıştır
# Kullanım: sudo bash scripts/setup-agent.sh <SERVER_URL> <API_KEY>

set -e

SERVER_URL="${1:-http://192.168.203.134:8000}"
API_KEY="${2:-}"
INSTALL_DIR="/home/netguard/netguard"
SERVICE_FILE="/etc/systemd/system/netguard-agent.service"

echo "[1/5] netguard kullanıcısı adm grubuna ekleniyor (auth.log erişimi)..."
usermod -aG adm netguard 2>/dev/null || true

echo "[2/5] .env dosyası yazılıyor..."
cat > "$INSTALL_DIR/.env" << EOF
NETGUARD_SERVER_URL=$SERVER_URL
NETGUARD_API_KEY=$API_KEY
EOF
chmod 600 "$INSTALL_DIR/.env"

echo "[3/5] Python bağımlılıkları güncelleniyor..."
sudo -u netguard "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q

echo "[4/5] Systemd servisi kuruluyor..."
cp "$INSTALL_DIR/scripts/netguard-agent.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable netguard-agent
systemctl restart netguard-agent

echo "[5/5] Servis durumu:"
systemctl status netguard-agent --no-pager -l

echo ""
echo "Kurulum tamamlandı."
echo "Log takibi: journalctl -fu netguard-agent"
