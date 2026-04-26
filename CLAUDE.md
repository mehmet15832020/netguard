# NetGuard — Claude Rehberi

Bu dosya Claude Code'un her oturumda otomatik okuduğu proje rehberidir.

---

## Proje Kimliği

NetGuard: NMS + CSNM (Continuous Network Security Monitoring) birleşimi.
Her ağ olayını hem performans hem güvenlik boyutuyla analiz eden unified platform.
**Hedef kitle:** Splunk/QRadar bütçesi olmayan KOBİ ve orta ölçekli kurumlar.

---

## Mevcut Durum

### Tamamlanan (Faz 0–8 + Güvenlik Sertleştirme + T1 + GNS3 Lab) ✓

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
| Güvenlik+ | API key SHA-256 hash, JWT refresh+blacklist, HTTP security headers, audit log, 7 korelasyon kuralı |
| T1-1 | HTTPS/TLS (nginx + self-signed) ✅ |
| T1-2 | JWT logout + token blacklist ✅ |
| T1-3 | Notifier → Correlated Events ✅ |
| T1-4 | Audit log UI sayfası ✅ |
| T2-1 | Threat Intelligence (AbuseIPDB API) ✅ |
| T2-2 | Firewall log parser (OPNsense + VyOS + pfSense/ASA/FortiGate) ✅ |
| T2-3 | Web log parser (nginx access + error log, API endpoint) ✅ |
| T2-4 | NetFlow v5/v9 receiver (UDP 2055) ✅ |
| T3-1 | Incident yönetimi (open/investigating/resolved + atama) ✅ |
| T3-2 | Windows agent EVTX parser (4625/4624/4688) ✅ |
| T3-3 | Saldırı timeline (attack_chain.py + /timeline UI) ✅ |
| T3-4 | Compliance raporu (PCI DSS / ISO 27001) ✅ |
| GNS3 Lab | OPNsense + VyOS + Alpine WebServer tam kurulu, veriler akıyor ✅ |

**Test durumu: 561 test, tümü geçiyor.**

---

## Aktif Yol Haritası

### Tier 1 — Platform Tamamlama ✅ TAMAMLANDI
### Tier 2 — Veri Zenginleştirme ✅ TAMAMLANDI
### Tier 3 — Kurumsal Özellikler ✅ TAMAMLANDI (T3-2 kısmen: EVTX parser var, Windows agent servisi yok)

### Tier 4 — İleri Seviye

| # | Görev | Durum |
|---|-------|-------|
| T4-1 | Anomaly detection (baseline + sapma) | ⏳ **SIRA** |
| T4-2 | Docker deployment (docker-compose) | ⏳ |
| T4-3 | Multi-site / multi-tenant | ⏳ |
| T4-4 | GNS3 lab entegrasyonu | ✅ |

---

## GNS3 Lab — Mevcut Durum

### Topoloji

```
INTERNET (Cloud/enp1s0) — kablo yok
    │
OPNsense 26.1.2  vtnet0=WAN, vtnet1=LAN(10.0.30.1/24)
    console: VNC :5900   RAM: 3GB   root/opnsense
    │ 10.0.30.0/24
VyOS rolling     eth0=10.0.30.2, eth1=192.168.203.200, eth2=10.0.10.1
    console: telnet :5018   vyos/vyos
    ├── DMZ-Switch → Alpine WebServer (10.0.10.2)  console: telnet :5019
    └── LAN-Switch → Host1, Host2, Kali-Bridge(vmnet8→NetGuard)
```

### Veri Akışı (Çalışanlar)

| Kaynak | Protokol | Hedef | Durum |
|--------|----------|-------|-------|
| OPNsense | Syslog UDP 514 | NetGuard:5140 | ✅ akıyor |
| VyOS | Syslog UDP 514 | NetGuard:5140 | ✅ akıyor |
| VyOS | SNMP v2c community=public | NetGuard | ✅ çalışıyor |
| VyOS | NetFlow v9 UDP 2055 | NetGuard | ✅ konfigüre (doğrulanmadı) |
| Alpine nginx | Syslog access_log | NetGuard:5140 | ✅ akıyor |

### Reboot Sonrası Yapılacaklar

**NetGuard VM (192.168.203.134) — her reboot'ta:**
```bash
sudo ip route add 10.0.30.0/24 via 192.168.203.200
sudo ip route add 10.0.10.0/24 via 192.168.203.200
sudo sysctl -w net.ipv4.ip_forward=1
sudo sysctl -w net.ipv4.conf.all.rp_filter=0
sudo iptables -t nat -A POSTROUTING -s 10.0.0.0/8 -o ens33 -j MASQUERADE
sudo iptables -t nat -A PREROUTING -p udp --dport 514 -j REDIRECT --to-port 5140
```

**VyOS — her reboot'ta (kernel route için):**
```bash
sudo ip route replace default via 192.168.203.134
```

**Alpine WebServer — her reboot'ta:**
```bash
ip link set eth0 up
ip addr add 10.0.10.2/24 dev eth0
ip route add default via 10.0.10.1
echo "nameserver 8.8.8.8" > /etc/resolv.conf
nginx
```

### Lab Makine Listesi

| Makine | IP | Rol |
|--------|----|-----|
| NetGuard Server | 192.168.203.134 | Server + dashboard (systemd: netguard.service) |
| Agent VM (Ubuntu) | 192.168.203.142 | Linux agent (systemd: netguard-agent.service) |
| Kali | 192.168.203.132 | Saldırı testleri |
| VyOS (GNS3) | 192.168.203.200 / 10.0.30.2 | Router, NetFlow, SNMP |
| OPNsense (GNS3) | 10.0.30.1 | Firewall |
| Alpine WebServer (GNS3) | 10.0.10.2 | nginx web server |

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
