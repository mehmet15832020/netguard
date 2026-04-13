#!/bin/bash
# NetGuard Server — VM1'e deploy script
# Kullanım: bash scripts/deploy-server.sh

set -e
SERVER="netguard@192.168.203.134"

echo "NetGuard Server deploy ediliyor..."

rsync -av --exclude='__pycache__' ~/netguard/server/ $SERVER:~/netguard/server/
rsync -av --exclude='__pycache__' ~/netguard/shared/ $SERVER:~/netguard/shared/

ssh $SERVER "sudo systemctl restart netguard-server && sleep 2 && systemctl is-active netguard-server"

echo "Deploy tamamlandı."
