# NetGuard — Claude Rehberi

Bu dosya Claude Code'un her oturumda otomatik okuduğu proje rehberidir.
Her yeni özellik veya değişiklikten sonra bu dosya güncellenmeli.

---

## Temel İlke — Her Adımda Ön Planda Tut (Değiştirme)

**NetGuard bir hikayesi olan üründür. Her kod değişikliği bu hikayeye hizmet etmeli.**

Hikaye:
> Bir IT yöneticisi sabah işe gelir. Dashboard açar. Geceyi özetleyen bir güvenlik durumu görür.
> Anormal bir trafik tespit edilmiş, kill chain'in 2. aşamasına ulaşmış, incident açılmış.
> Bir tıkla zaman çizelgesine bakar — hangi IP, hangi port, hangi saat. Karar verir.

**Her geliştirme adımında şu soruyu sor:**
- Bu değişiklik o IT yöneticisinin işini somut olarak kolaylaştırıyor mu?
- Ürünün bütününde anlamlı, görünür ve profesyonel bir etki yaratıyor mu?
- "Demo'da gösterilince etkileyici" mi?

**Kaçınılacaklar:**
- Arka planda çalışıp UI'da görünmeyen "altyapı" işleri (zorunlu olmadıkça)
- Kullanıcıya değer katmayan teknik refactor
- Parça parça, birbirinden kopuk özellikler

**Her commit şu testi geçmeli:** "Bu değişikliği demo'da gösterebilir miyim? Birisi görünce 'bu işe yarıyor' der mi?"

---

## Ürün Kimliği (Değiştirme)

**NetGuard: Kurumsal bütçesi olmayan orta ölçekli şirketler için açık kaynak NDR platformu.**

> "Splunk yıllık 50K dolar. QRadar 30K dolar. NetGuard: açık kaynak, Docker ile 30 dakikada kurulum."

**Hedef kitle:** 50–500 çalışanlı, siber güvenlik bütçesi kısıtlı şirketlerin IT yöneticileri.

**Ürünü bir cümleyle tanımlama:**
NetGuard, ağ trafiğini ve host loglarını birden fazla protokolden toplar, korelasyon + kill chain analizi ile tehditleri tespit eder, incident workflow ile yanıt verir.

**Bu ürün ne DEĞİLDİR:**
- Wireshark (paket yakalayıcı) değil — tespiti amaçlar, ham veriyi değil
- Zabbix gibi saf NMS değil — güvenlik tespiti önceliktir
- Splunk gibi log yöneticisi değil — ağ odaklıdır

---

## Mimari — Üç Katman

```
KOLEKSIYON          TESPIT              YANIT
──────────          ──────              ─────
Agent (psutil)      Korelasyon motoru   Incident yönetimi
SNMP v2c/v3         Sigma kuralları     Saldırı timeline
Syslog (firewall)   Kill chain (5 aşama) Alert + bildirim
NetFlow v5/v9       Anomaly detection   Compliance raporu
EVTX (Windows)      MITRE ATT&CK       Audit log
Web log (nginx)     Threat intel
pyshark (SYN/BPF)   ARP/DNS/ICMP det.
         │                  │                  │
         └──────────────────┴──────────────────┘
                        Event Bus
                    (normalized_logs)
```

---

## Tamamlanan Modüller

### Koleksiyon Katmanı
| Modül | Dosya | Durum |
|-------|-------|-------|
| Linux Agent (CPU/RAM/disk/net) | `agent/collector.py` | ✅ Systemd servisi var |
| SNMP v2c/v3 polling + TRAP | `server/snmp_collector.py`, `server/snmp_trap_receiver.py` | ✅ |
| Syslog parser (OPNsense/VyOS/pfSense/ASA/FortiGate) | `server/parsers/firewall.py` | ✅ |
| NetFlow v5/v9 binary parser | `server/parsers/netflow.py`, `server/netflow_receiver.py` | ✅ |
| EVTX parser (4624/4625/4688) | `server/evtx_parser.py` | ✅ |
| Web log parser (nginx access+error) | `server/parsers/web_log.py` | ✅ |
| pyshark SYN paket sniffer | `server/detectors/port_scan.py` | ✅ Gerçek paket analizi |
| Traffic collector (agent tarafı) | `agent/traffic_collector.py` | ⚠️ Server'a bağlı değil |

### Tespit Katmanı
| Modül | Dosya | Durum |
|-------|-------|-------|
| Korelasyon motoru (JSON kurallar) | `server/correlator.py` | ✅ 7 aktif kural |
| Sigma kural parser (YAML) | `server/sigma_parser.py` | ✅ |
| Kill chain dedektörü (5 aşama) | `server/attack_chain.py` | ✅ RECON→LATERAL |
| MITRE ATT&CK eşleme | `server/mitre.py` | ✅ |
| Anomaly detection (Welford + IsolationForest) | `server/anomaly/` | ✅ |
| AbuseIPDB tehdit istihbaratı | `server/threat_intel.py` | ✅ |
| ARP spoof dedektörü | `server/detectors/arp_spoof.py` | ✅ |
| DNS anomali dedektörü | `server/detectors/dns_anomaly.py` | ✅ |
| ICMP flood dedektörü | `server/detectors/icmp_flood.py` | ✅ |

### Yanıt Katmanı
| Modül | Dosya | Durum |
|-------|-------|-------|
| Incident yönetimi (open/investigating/resolved) | `server/routes/incidents.py` | ✅ |
| Saldırı zaman çizelgesi | `server/attack_chain.py`, `/timeline` UI | ✅ |
| Webhook + email bildirimi | `server/notifier.py` | ⚠️ Sadece korelasyon tetikliyor |
| Audit log | `server/database.py` | ✅ |
| PCI DSS / ISO 27001 compliance raporu | `server/compliance.py` | ✅ |

### Platform
| Modül | Durum |
|-------|-------|
| JWT (access 60dk + refresh 7gün + blacklist) | ✅ |
| API key (SHA-256 hash) | ✅ |
| Multi-tenant (tenant → site → device, JWT tid) | ✅ |
| TLS (nginx reverse proxy, self-signed) | ✅ |
| Docker deployment (docker-compose + InfluxDB) | ✅ |
| Rate limiting (slowapi) | ✅ |
| Log retention (hot/warm/cold) | ✅ |
| InfluxDB zaman serisi | ✅ yazılıyor, ⚠️ frontend'de grafik YOK |

**Test durumu: ~620 test, tümü geçiyor.**

---

## Aktif Yol Haritası

Hoca geri bildirimi ve ürün kimliği analizi sonrası belirlenen öncelikli görevler.
**Kural:** Yeni özellik eklemek yerine mevcut modülleri derinleştir ve birbirine bağla.

### Aşama 1 — Temizlik ve Sağlamlık ✅ TAMAMLANDI

| # | Görev | Durum |
|---|-------|-------|
| A1-1 | In-memory storage kaldır → agent alert'leri SQLite'a | ✅ |
| A1-2 | SQLite FTS5 ile log full-text arama | ✅ |
| A1-3 | Bildirim pipeline tamamla → anomaly + agent alert da notify etsin | ✅ |

### Aşama 2 — UI Kimlik Operasyonu ✅ TAMAMLANDI

| # | Görev | Durum |
|---|-------|-------|
| A2-1 | Sidebar yeniden yapılandır (19 flat → 5 grup) | ✅ |
| A2-2 | Ana sayfa: Güvenlik Durumu + Risk Skoru | ✅ |
| A2-3 | InfluxDB grafiklerini frontend'e bağla (CPU/net/log hacmi) | ✅ |
| A2-4 | Cihaz detay sayfası (grafik + alert + SNMP özeti) | ✅ |

### Aşama 3 — NDR Derinliği ✅ TAMAMLANDI

| # | Görev | Durum |
|---|-------|-------|
| A3-1 | Kill chain dedektörünü ürünün merkezi yap (API + UI) | ✅ |
| A3-2 | agent/traffic_collector.py'yi server'a bağla | ✅ |
| A3-3 | MITRE ATT&CK görselleştirme derinleştir (heat map) | ✅ |

### Aşama 4 — Lab Testi + Sunum Hazırlığı (AKTİF)

| # | Görev | Dosyalar | Durum |
|---|-------|---------|-------|
| **L0-1** | **`correlator.py:186` `raw_log` → `message` bug fix** | `server/correlator.py` | 🔴 KRİTİK — her dakika korelasyon fail oluyor |
| **L0-2** | **Server'a `git pull` + servis restart** | server VM | 🔴 Server eski commit'te (fab9b9c), yeni özellikler aktif değil |
| L1-1 | Agent traffic collector doğrula (pyshark aktif mi?) | `agent/traffic_collector.py` | ⏳ |
| L1-2 | VyOS SNMP polling doğrula | GNS3 + server logs | ⏳ |
| L1-3 | VyOS NetFlow akışı doğrula | GNS3 + server logs | ⏳ |
| L2-1 | Kali → SSH Brute Force → `ssh_brute_force` kuralı tetikle | Kali: `hydra` | ⏳ |
| L2-2 | Kali → Port Scan → `port_scan_detected` kuralı tetikle | Kali: `nmap -sS` | ⏳ |
| L2-3 | Kali → ICMP Flood → `icmp_flood_detected` tetikle | Kali: `hping3 --flood` | ⏳ |
| L3-1 | Kill chain uçtan uca: RECON→WEAPONIZE→ACCESS (3 aşama = partial_attack_chain) | Kali sekans | ⏳ |
| L4-1 | Dashboard UI doğrula (overview/timeline/mitre/alerts tüm verili) | Tarayıcı | ⏳ |
| A4-2 | README ve mimari belgeleme | `README.md` | ⏳ |

---

## Kırmızı Çizgiler — Artık Eklenmeyecekler

Aşağıdakiler tartışılmadan reddedilecek. Bunları eklemek "çorba" sorununu derinleştirir:

| Teklif | Neden Red |
|--------|-----------|
| Vulnerability scanner (OpenVAS/Nessus) | Farklı ürün kategorisi |
| Template sistemi (Cisco Router template) | Önce mevcut modüller tamamlansın |
| Rule editor UI | Sonraya; önce mevcut kurallar anlamlı gösterilsin |
| PagerDuty/Opsgenie entegrasyonu | Önce temel email/webhook sağlam olsun |
| Rootkit tespiti | EDR alanı, NDR değil |
| Active Response (otomatik IP blok) | Sonraya; önce tespit derinleşsin |
| FIM (File Integrity Monitoring) | Wazuh'un alanı |

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

### Makine Listesi

| Makine | IP | Rol |
|--------|----|-----|
| NetGuard Server | 192.168.203.134 | Server + dashboard (systemd: netguard.service) |
| Agent VM (Ubuntu) | 192.168.203.142 | Linux agent (systemd: netguard-agent.service) |
| Kali | 192.168.203.132 | Saldırı testleri |
| VyOS (GNS3) | 192.168.203.200 / 10.0.30.2 | Router, NetFlow, SNMP |
| OPNsense (GNS3) | 10.0.30.1 | Firewall |
| Alpine WebServer (GNS3) | 10.0.10.2 | nginx web server |

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

**VyOS — her reboot'ta:**
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

### Protokol → Kazanım Tablosu

| Protokol | Kaynak | NetGuard katkısı |
|----------|--------|-----------------|
| SNMP v2c/v3 | Router, switch, firewall | Interface istatistikleri, CPU/RAM, uptime |
| Syslog UDP 514 | Firewall, router | Allow/deny logları, auth events |
| NetFlow v5/v9 | VyOS router | Trafik akış analizi (kim kime ne kadar) |
| LLDP | Switch, router | Fiziksel topoloji bağlantıları |
| SNMP TRAP | Tüm ağ cihazları | Anlık event (interface down, auth fail) |
| pyshark (BPF) | NetGuard'ın kendi arayüzü | SYN scan, port tarama, anomali |

---

## Mimari Kararlar (Değiştirme)

- **Kimlik:** NDR (Network Detection and Response) — NMS + SIEM değil
- **Veritabanı:** SQLite WAL + InfluxDB (zaman serisi)
- **Event pipeline:** Her kaynak → `normalized_logs` tablosu (tek merkezi tablo)
- **Device modeli:** agent + SNMP + discovered → hepsi `devices` tablosunda
- **Korelasyon:** `config/correlation_rules.json` + `config/sigma_rules/` YAML
- **Token güvenliği:** `verify_token(token, token_type="access"|"refresh")` — tip karıştırma engeli
- **API key:** SHA-256 hash saklanır, plaintext asla DB'ye yazılmaz
- **Multi-tenant:** `tenant_scope(user)` → superadmin için `None`, diğerleri için `tenant_id`
- **Test fixture:** `tmp_db` conftest.py'da tanımlı, tüm test dosyaları kullanabilir

---

## Bilinen Sorunlar — Aktif

- **`server/correlator.py:186`** — `raw_log` kolonu yok, korelasyon her dakika `ERROR: no such column: raw_log` veriyor. `raw_log LIKE ?` → silinmeli (sadece `message LIKE ?` yeterli). **L0-1 ile düzeltilecek.**
- **Server eski commit'te** — Production VM (192.168.203.134) `fab9b9c` commit'inde, local `9c83b72`'de. `git pull` + servis restart gerekli. **L0-2 ile düzeltilecek.**
- **Server DB tabloları boş** — `normalized_logs: 40624` satır var ama `correlated_events: 73`, `alerts: 88` görece az. Korelasyon bug'ı yüzünden birikmemiş.
- `server/storage.py` — InMemoryStorage hâlâ var (A1-1 tamamlandı ama server güncellenmedi)

## Çözülmüş Sorunlar (Referans)

- `agent/traffic_collector.py` → server'a bağlandı (A3-2) ✅
- InfluxDB frontend grafikleri → tamamlandı (A2-3) ✅
- `notifier.py` → anomaly + agent alert bildirimleri eklendi (A1-3) ✅

---

## Commit Kuralları

- Her görev ayrı commit
- Format: `fix(auth): ...`, `feat(discovery): ...`, `feat(ndr): ...`
- Her modül için test yaz; testler geçmeden commit atma
- Commit sonrası push

## Kod Kuralları

- Yorum yazma (açıklayıcı isimler yeterli)
- Error handling sadece gerçek sınır noktalarında (user input, external API)
- Mevcut pattern'leri takip et: yeni route → `routes/` altına, router'ı `main.py`'a ekle
- Yeni UI sayfası → `dashboard-v2/src/app/(protected)/` altına

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
