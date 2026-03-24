#!/bin/bash
# NetGuard Agent — VM'lere deploy script
set -e

for HOST in netguard@192.168.203.142; do
    echo "Agent deploy ediliyor: $HOST"
    scp ~/netguard/agent/main.py $HOST:~/netguard/agent/
    scp ~/netguard/agent/collector.py $HOST:~/netguard/agent/
    scp ~/netguard/agent/sender.py $HOST:~/netguard/agent/
    scp ~/netguard/agent/traffic_collector.py $HOST:~/netguard/agent/
    scp ~/netguard/shared/models.py $HOST:~/netguard/shared/
    scp ~/netguard/shared/protocol.py $HOST:~/netguard/shared/
    ssh $HOST "sudo systemctl restart netguard-agent"
    echo "✓ $HOST tamamlandı"
done
echo "Agent deploy tamamlandı."
