#!/bin/sh
set -e

CERT_DIR=/etc/ssl/netguard
CERT=$CERT_DIR/cert.pem
KEY=$CERT_DIR/key.pem

if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "[nginx] SSL sertifikası oluşturuluyor..."
    mkdir -p "$CERT_DIR"
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$KEY" \
        -out "$CERT" \
        -subj "/C=TR/ST=Istanbul/L=Istanbul/O=NetGuard/CN=netguard" \
        -addext "subjectAltName=IP:127.0.0.1,DNS:localhost,DNS:netguard"
    echo "[nginx] SSL sertifikası oluşturuldu."
fi

exec "$@"
