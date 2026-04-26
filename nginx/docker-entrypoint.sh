#!/bin/sh
set -e

CERT_DIR=/etc/ssl/netguard
CERT=$CERT_DIR/cert.pem
KEY=$CERT_DIR/key.pem

if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
    echo "[nginx] SSL sertifikası oluşturuluyor..."
    mkdir -p "$CERT_DIR"

    SAN="IP:127.0.0.1,DNS:localhost,DNS:netguard"
    if [ -n "$NETGUARD_HOST" ]; then
        case "$NETGUARD_HOST" in
            [0-9]*) SAN="$SAN,IP:$NETGUARD_HOST" ;;
            *)      SAN="$SAN,DNS:$NETGUARD_HOST" ;;
        esac
    fi

    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
        -keyout "$KEY" \
        -out "$CERT" \
        -subj "/C=TR/ST=Istanbul/L=Istanbul/O=NetGuard/CN=netguard" \
        -addext "subjectAltName=$SAN"
    echo "[nginx] SSL sertifikası oluşturuldu ($SAN)."
fi

exec "$@"
