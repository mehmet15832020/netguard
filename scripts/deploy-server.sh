#!/bin/bash
# NetGuard Server — VM1'e deploy script
# Kullanım: bash scripts/deploy-server.sh

set -e
SERVER="netguard@192.168.203.134"

echo "NetGuard Server deploy ediliyor..."

scp -r ~/netguard/server $SERVER:~/netguard/
scp ~/netguard/shared/models.py $SERVER:~/netguard/shared/
scp ~/netguard/shared/protocol.py $SERVER:~/netguard/shared/

ssh $SERVER "sudo systemctl restart netguard-server && sleep 2 && systemctl is-active netguard-server"

echo "Deploy tamamlandı."
