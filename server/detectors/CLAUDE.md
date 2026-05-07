# Detection Agent — Bağlam

NetGuard detection modülleri: `server/detectors/`

## Her Detector İçin Kural
- Sonuçları `normalized_logs` tablosuna yaz — `db.save_normalized_log()` kullan
- Field'lar: `src_ip`, `dst_ip`, `event_type`, `category="network"`, `tenant_id="default"`
- Kill chain stage'e bağlamak için: attack_chain.py import et, `attack_chain_tracker.record()` çağır
- Her yeni detector için `tests/test_detectors_[isim].py` yaz

## Kill Chain Stage Mapping
```
RECON      → port_scan, arp_sweep, dns_flood, anomaly_detected, web_scan
WEAPONIZE  → ssh_brute_force, auth_failure (threshold exceeded)
ACCESS     → ssh_success (after brute force), web_auth_fail_then_success
LATERAL    → lateral_movement (iç→iç SSH/SMB/RDP scan)
EXECUTE    → (henüz yok — V1 kapsamı)
```

## Mevcut Detectors
- `port_scan.py` — pyshark SYN sniffer → RECON
- `lateral.py` — iç→iç servis tarama → LATERAL
- `arp_detector.py` — ARP sweep → RECON
- `dns_detector.py` — DNS flood → RECON
- `icmp_detector.py` — ICMP flood → RECON
