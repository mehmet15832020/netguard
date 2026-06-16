"""
NetGuard — DHCP MAC Baseline (C1 + F1 paylaşılan mantık)

Bir IP için daha önce farklı bir MAC görülmüşse uyarı üretir (DHCP spoofing /
cihaz değişimi — NIST SP 800-94 §3.3). Kaynak fark etmez: Zeek dhcp.log
(pasif gözlem, C1) ve firewall DHCP syslog'u (ISC dhcpd/Kea/FortiGate,
yetkili sunucu kaydı, F1) aynı `dhcp_mac_history` tablosunu paylaşır —
ikisi birlikte tam IP→MAC geçmişi verir.

IP hiç görülmemişse (ilk kayıt) alert üretilmez — DHCP havuzunda yeni adres
dağıtımı normaldir, sadece *değişim* ilginçtir.
"""

import uuid
from typing import Optional

from shared.models import LogCategory, NormalizedLog


def check_dhcp_mac_baseline(log_entry: NormalizedLog) -> Optional[NormalizedLog]:
    ip = log_entry.source_ip
    mac = log_entry.extra.get("mac")
    if not ip or not mac:
        return None

    from server.database import db
    known_macs = db.get_known_macs_for_ip(ip)
    db.record_dhcp_mac(ip, mac)

    if known_macs and mac not in known_macs:
        return NormalizedLog(
            log_id=str(uuid.uuid4()),
            raw_id=str(uuid.uuid4()),
            source_type=log_entry.source_type,
            observer_hostname=log_entry.observer_hostname,
            timestamp=log_entry.timestamp,
            severity="warning",
            event_category=LogCategory.NETWORK,
            event_action="dhcp_new_mac_detected",
            source_ip=ip,
            message=(
                f"IP {ip} için yeni MAC görüldü: {mac} "
                f"(önceki: {', '.join(known_macs)})"
            ),
            tags=["dhcp", "mac_change"],
            extra={"mac": mac, "previous_macs": known_macs},
        )
    return None
