#!/bin/bash
# NetGuard Server kurulum scripti — VM1 (server) üzerinde root olarak çalıştır
# Kullanım: sudo bash scripts/setup-server.sh

set -e

INSTALL_DIR="/home/netguard/netguard"
SERVICE_FILE="/etc/systemd/system/netguard-server.service"

echo "[1/4] Python bağımlılıkları güncelleniyor..."
sudo -u netguard "$INSTALL_DIR/venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt" -q

echo "[2/4] .env kontrolü..."
if [ ! -f "$INSTALL_DIR/.env" ]; then
    echo "HATA: $INSTALL_DIR/.env bulunamadı. Önce .env dosyasını oluşturun."
    exit 1
fi
grep -q "JWT_SECRET_KEY" "$INSTALL_DIR/.env" || echo "JWT_SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_hex(32))')" >> "$INSTALL_DIR/.env"
grep -q "ADMIN_PASSWORD" "$INSTALL_DIR/.env" || echo "ADMIN_PASSWORD=netguard123" >> "$INSTALL_DIR/.env"

echo "[3/4] Systemd servisi kuruluyor..."
cp "$INSTALL_DIR/scripts/netguard-server.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable netguard-server
systemctl restart netguard-server

echo "[4/4] Servis durumu:"
systemctl status netguard-server --no-pager -l

echo ""
echo "Kurulum tamamlandı."
echo "Log takibi: journalctl -fu netguard-server"
