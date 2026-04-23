# NetGuard — Claude Rehberi

Bu dosya Claude Code'un her oturumda otomatik okuduğu proje rehberidir.

---

## Proje Kimliği

NetGuard: NMS + CSNM (Continuous Network Security Monitoring) birleşimi.
Her ağ olayını hem performans hem güvenlik boyutuyla analiz eden unified platform.
**Hedef kitle:** Splunk/QRadar bütçesi olmayan KOBİ ve orta ölçekli kurumlar.

---

## Mevcut Durum

### Tamamlanan (Faz 0–8 + Güvenlik Sertleştirme) ✓

| Faz | İçerik |
|-----|--------|
| Faz 0 | Zemin: env, API key SQLite, JWT secret, CORS |
| Faz 1 | Unified Device Model (`devices` tablosu) |
| Faz 2 | NMS Çekirdeği: SNMP walk, uptime, TRAP alıcı |
| Faz 3 | Auto-Discovery: subnet sweep, vendor fingerprinting |
| Faz 4 | Topology Engine: SNMP ARP walk, LLDP |
| Faz 5 | Cross-Domain Correlation motoru |
| Faz 6 | Frontend: devices, discovery, topology, overview |
| Faz 7 | SNMPv3 + Security Hardening |
| Faz 8 | Raporlama: /reports/summary, 4 CSV endpoint |
| Güvenlik+ | API key SHA-256 hash, JWT refresh+blacklist hazırlığı, HTTP security headers, audit log, maintenance dashboard, üretim korelasyon kuralları (7 kural) |

**Test durumu: 353 test, tümü geçiyor.**

---

## Aktif Yol Haritası

### Tier 1 — Platform Tamamlama (Öncelikli)

| # | Görev | Durum |
|---|-------|-------|
| T1-1 | HTTPS / TLS (nginx + self-signed) | ⏳ |
| T1-2 | JWT logout + token blacklist | ⏳ |
| T1-3 | Notifier → Correlated Events (email/webhook) | ⏳ |
| T1-4 | Audit log UI sayfası | ⏳ |

### Tier 2 — Veri Zenginleştirme

| # | Görev | Durum |
|---|-------|-------|
| T2-1 | Threat Intelligence (AbuseIPDB ücretsiz API) | ⏳ |
| T2-2 | Firewall log parser (pfSense/Cisco ASA/FortiGate) | ⏳ |
| T2-3 | Web log parser (nginx/Apache access.log) | ⏳ |
| T2-4 | NetFlow v5/v9 receiver (UDP parse) | ⏳ |

### Tier 3 — Kurumsal Özellikler

| # | Görev | Durum |
|---|-------|-------|
| T3-1 | Incident yönetimi (open/investigating/resolved + atama) | ⏳ |
| T3-2 | Windows agent (WMI / EVTX parser, Event Log 4625/4624/4688) | ⏳ |
| T3-3 | Saldırı timeline görselleştirme | ⏳ |
| T3-4 | Compliance raporu (PCI DSS / ISO 27001 otomatik eşleştirme) | ⏳ |

### Tier 4 — İleri Seviye

| # | Görev | Durum |
|---|-------|-------|
| T4-1 | Anomaly detection (baseline + sapma) | ⏳ |
| T4-2 | Docker deployment (docker-compose) | ⏳ |
| T4-3 | Multi-site / multi-tenant | ⏳ |
| T4-4 | GNS3 lab entegrasyonu | ⏳ |

---

## Lab Ortamı Stratejisi

### Mevcut Lab

| Makine | IP | Rol |
|--------|----|-----|
| NetGuard Server | 192.168.203.134 | Server + dashboard (systemd: netguard.service) |
| Agent VM (Ubuntu) | 192.168.203.142 | Linux agent (systemd: netguard-agent.service) |
| Kali | 192.168.203.132 | Saldırı testleri |

### Önerilen Genişleme: 2 Aşama

**Aşama 1 — Doğrudan VM Ekle (GNS3 gerekmez, hızlı)**
- **pfSense VM** — Gerçek firewall. Syslog + SNMP destekler. Firewall log parser testi için.
- **VyOS VM** — Açık kaynak router. BGP/OSPF + SNMP + syslog + NetFlow export. Ücretsiz.

**Aşama 2 — GNS3 ile Tam Topoloji**
GNS3 VM (VMware appliance) üzerine:
- pfSense (firewall/NAT)
- VyOS (router, BGP/OSPF)
- Mikrotik CHR (ücretsiz, Türkiye'de yaygın switch/router)
- OpenWrt (edge router)
- Linux VM'ler (sunucu simülasyonu)

GNS3'ün artısı: Sanal switch/kablo altyapısıyla karmaşık VLAN ve routing senaryoları.
Cisco image gerektirmez — VyOS + Mikrotik CHR + pfSense tamamen ücretsiz.

### Hangi Protokolden Ne Elde Edilir

| Protokol | Kaynak cihaz | NetGuard katkısı |
|----------|-------------|-----------------|
| SNMP v2c/v3 | Router, switch, firewall | Interface istatistikleri, CPU/RAM, uptime |
| Syslog UDP 514 | Firewall, router | Allow/deny logları, auth events |
| NetFlow v5/v9 | VyOS router, Cisco | Trafik akış analizi (kim kime ne kadar) |
| LLDP | Switch, router | Fiziksel topoloji bağlantıları |
| SNMP TRAP | Tüm ağ cihazları | Anlık event (interface down, auth fail) |
| pfSense syslog | pfSense | Kural bazlı firewall logları |
| Mikrotik syslog | Mikrotik CHR | RouterOS eventi, DHCP, OSPF |

---

## Mimari Kararlar (Değiştirme)

- **Veritabanı:** SQLite (WAL mode) + InfluxDB (zaman serisi metrikler)
- **Device modeli:** agents + SNMP + discovered → hepsi `devices` tablosunda birleşir
- **Korelasyon:** `config/correlation_rules.json` (threshold tabanlı) + `config/sigma_rules/` (YAML)
- **Token güvenliği:** verify_token(token, token_type="access"|"refresh") — tip karıştırma engeli
- **API key:** SHA-256 hash saklanır, plaintext asla DB'ye yazılmaz
- **tmp_db fixture:** conftest.py'da tanımlı, tüm test dosyaları kullanabilir

---

## Commit Kuralları

- Her görev ayrı commit
- Format: Conventional Commits — `fix(auth): ...`, `feat(discovery): ...`
- Her modül için test yaz, testler geçmeden commit atma
- Commit sonrası push

## Kod Kuralları

- Yorum yazma (açıklayıcı isimler yeterli)
- Error handling sadece gerçek sınır noktalarında (user input, external API)
- Mevcut pattern'leri takip et (yeni route → routes/ altına, router'ı main.py'a ekle)

## Test Çalıştırma

```bash
cd /home/mehmet/netguard
pytest tests/ -q
```

## SSH Erişim

```bash
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.134   # server
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.142   # agent
```
