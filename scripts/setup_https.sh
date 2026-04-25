#!/usr/bin/env bash
# NetGuard — HTTPS / TLS kurulum scripti (T1-1)
# Çalıştır: bash scripts/setup_https.sh
set -e

SERVER_IP="192.168.203.134"
CERT_DIR="/etc/ssl/netguard"
NGINX_SITE="/etc/nginx/sites-available/netguard"
NGINX_ENABLED="/etc/nginx/sites-enabled/netguard"

echo "=== NetGuard HTTPS Kurulumu ==="

# 1. nginx yüklü değilse kur
if ! command -v nginx &>/dev/null; then
    echo "[1/5] nginx kuruluyor..."
    apt-get update -qq && apt-get install -y nginx
else
    echo "[1/5] nginx zaten kurulu."
fi

# 2. Self-signed sertifika oluştur
echo "[2/5] Self-signed sertifika oluşturuluyor..."
mkdir -p "$CERT_DIR"
openssl req -x509 -nodes -days 3650 \
    -newkey rsa:2048 \
    -keyout "$CERT_DIR/key.pem" \
    -out    "$CERT_DIR/cert.pem" \
    -subj   "/C=TR/ST=Istanbul/O=NetGuard/CN=$SERVER_IP" \
    -addext "subjectAltName=IP:$SERVER_IP"
chmod 600 "$CERT_DIR/key.pem"
echo "    Sertifika: $CERT_DIR/cert.pem"

# 3. nginx konfigürasyonunu kopyala
echo "[3/5] nginx konfigürasyonu ayarlanıyor..."
cp "$(dirname "$0")/../nginx/netguard.conf" "$NGINX_SITE"
ln -sf "$NGINX_SITE" "$NGINX_ENABLED"

# Varsayılan site'ı devre dışı bırak
rm -f /etc/nginx/sites-enabled/default

# 4. nginx konfigürasyonunu test et
echo "[4/5] Konfigürasyon test ediliyor..."
nginx -t

# 5. nginx'i yeniden başlat ve systemctl ile etkinleştir
echo "[5/5] nginx başlatılıyor..."
systemctl enable nginx
systemctl restart nginx

echo ""
echo "=== Kurulum tamamlandı ==="
echo "Dashboard : https://$SERVER_IP"
echo "API       : https://$SERVER_IP/api/v1/"
echo "Not: Self-signed sertifika kullandığı için tarayıcı uyarısı verecek."
echo "     'Gelişmiş → Devam et' seçeneğiyle geçebilirsin."
