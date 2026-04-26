# NetGuard — Açık Kaynak NDR Platformu

**Kurumsal bütçesi olmayan orta ölçekli şirketler için Network Detection and Response.**

> Splunk yıllık $50.000. QRadar $30.000. NetGuard: açık kaynak, Docker ile 30 dakikada kurulum.

NetGuard, ağ trafiğini ve host loglarını birden fazla protokolden toplar; korelasyon motoru, 5 aşamalı kill chain analizi ve MITRE ATT&CK eşlemesiyle tehditleri tespit eder; incident yönetimi ile yanıt verir.

**Hedef kitle:** 50–500 çalışanlı, Splunk/QRadar bütçesi olmayan şirketlerin IT yöneticileri.

---

## Ne Yapar?

```
┌─────────────────────────────────────────────────────────────────┐
│                      KOLEKSIYON                                 │
│                                                                 │
│  Linux Agent    SNMP v2c/v3    Syslog UDP     NetFlow v5/v9    │
│  (CPU/RAM/disk) (router/switch) (firewall log) (trafik akışı)  │
│                                                                 │
│  Windows EVTX   Web Log        pyshark         SNMP TRAP       │
│  (4624/4625/    (nginx access/ (SYN paket      (anlık event)   │
│   4688)          error log)     analizi)                       │
└─────────────────────────┬───────────────────────────────────────┘
                           │ Her kaynak → NormalizedLog
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                       TESPİT                                    │
│                                                                 │
│  Korelasyon Motoru    Sigma Kuralları    Anomaly Detection      │
│  (JSON tabanlı,       (YAML format,      (Welford Z-score +     │
│   zaman penceresi)     7 aktif kural)    Isolation Forest)      │
│                                                                 │
│  Kill Chain (5 aşama)   MITRE ATT&CK     Threat Intelligence   │
│  RECON → WEAPONIZE →   eşleme           (AbuseIPDB)           │
│  ACCESS → EXECUTE →                                             │
│  LATERAL                                                        │
└─────────────────────────┬───────────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────────┐
│                        YANIT                                    │
│                                                                 │
│  Incident Yönetimi    Saldırı Timeline    Webhook / Email       │
│  (open → investi-     (kill chain görsel) (kritik olay         │
│   gating → resolved)                      bildirimi)           │
│                                                                 │
│  Compliance Raporu    Audit Log                                 │
│  (PCI DSS / ISO 27001) (tüm admin işlemleri)                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Özellikler

### Koleksiyon

- **Linux Agent** — CPU, RAM, disk, network, process snapshot (psutil); systemd servisi olarak çalışır
- **SNMP v2c / v3** — Interface istatistikleri, uptime, sys_descr, ARP/LLDP walk; periyodik polling
- **SNMP TRAP Alıcı** — UDP 162; anlık event normalize edilip DB'ye yazılır
- **Syslog Alıcı** — UDP 5140; OPNsense, VyOS, pfSense, Cisco ASA, FortiGate logları ayrıştırılır
- **NetFlow v5/v9** — UDP 2055; binary parser, trafik akış analizi (kaynak/hedef IP, port, byte)
- **Windows EVTX Parser** — EventID 4624 (başarılı giriş), 4625 (başarısız), 4688 (process oluşturma)
- **Web Log Parser** — nginx access + error log; SQLi, path traversal, tarama girişimi tespiti
- **pyshark Paket Analizi** — TCP SYN tabanlı gerçek zamanlı port tarama tespiti; BPF filtre ile

### Tespit

- **Korelasyon Motoru** — `config/correlation_rules.json` dosyasından okunan threshold tabanlı kurallar; kodda değişiklik yapmadan kural eklenebilir
- **Sigma Kural Desteği** — SIGMA YAML formatındaki kuralları NetGuard motoruna dönüştüren parser; `config/sigma_rules/` dizininden yüklenir
- **Kill Chain Dedektörü** — Aynı kaynak IP'den 30 dakika içinde birden fazla saldırı aşaması tespit edildiğinde otomatik uyarı üretir

  | Aşama | Tetikleyen event tipleri |
  |-------|--------------------------|
  | RECON | port_scan, dns_anomaly |
  | WEAPONIZE | ssh_failure, windows_logon_failure, brute_force |
  | ACCESS | ssh_success, windows_logon_success |
  | EXECUTE | windows_process_create, sudo_abuse |
  | LATERAL | lateral_movement, windows_lateral |

- **MITRE ATT&CK Eşleme** — Tespit edilen event tipleri ATT&CK taktik ve tekniklerine otomatik eşlenir
- **Anomaly Detection** — Welford online baseline (saatlik, per-entity) + Isolation Forest (çok boyutlu); 5 dakikalık döngü ile çalışır
- **Tehdit İstihbaratı** — Şüpheli IP'ler AbuseIPDB'ye sorgulanır; risk skoru, ülke, kategori kayıt edilir
- **Ağ Dedektörleri** — ARP spoofing, ICMP flood, DNS sorgu patlaması

### Aktif Korelasyon Kuralları

| Kural | Eşik | Önem |
|-------|------|------|
| SSH Brute Force | 5+ başarısız giriş / 60s | Kritik |
| Port Tarama | 15+ farklı port / 60s | Yüksek |
| ARP Spoofing | 1 tespit / 120s | Kritik |
| ICMP Flood | 1 tespit / 120s | Yüksek |
| DNS Patlaması | 20+ sorgu / 60s | Orta |
| Sudo Kötüye Kullanım | 5+ kullanım / 120s | Uyarı |
| Lateral Movement | 3+ ssh_success farklı hedefe / 300s | Yüksek |

### Yanıt

- **Incident Yönetimi** — Alert → Incident dönüşümü; open / investigating / resolved durumları; kullanıcı atama; notlar
- **Saldırı Zaman Çizelgesi** — Kill chain aşamalarını zaman ekseninde görselleştirir; hangi IP hangi aşamayı ne zaman tamamladı
- **Webhook + Email** — Kritik korelasyon olaylarında Discord/Slack webhook veya SMTP bildirimi
- **Compliance Raporu** — PCI DSS v4.0 ve ISO 27001:2022 maddelerini mevcut loglarla otomatik eşleştirir; PDF/JSON export
- **Audit Log** — Tüm admin işlemleri (giriş, cihaz ekleme, kural değiştirme) kayıt altında

### Platform

- **JWT Auth** — Access token (60 dk) + Refresh token (7 gün) + Token blacklist (logout desteği)
- **API Key** — SHA-256 hash ile saklanır; plaintext asla DB'ye yazılmaz
- **Multi-Tenant** — Tenant → Site → Device hiyerarşisi; JWT "tid" claim ile izolasyon; superadmin tüm verilere erişir
- **TLS** — nginx reverse proxy; self-signed sertifika (üretimde Let's Encrypt ile değiştirilebilir)
- **Rate Limiting** — Login: 5/dk, Refresh: 10/dk, SNMP poll: 10/dk (slowapi)
- **Log Retention** — Hot (SQLite, 30–365 gün) → Warm (JSON.gz arşiv, 1 yıl); yapılandırılabilir eşikler
- **Docker** — docker-compose ile tek komut kurulum; nginx + FastAPI + Next.js + InfluxDB

### Dashboard (19 Sayfa)

| Bölüm | Sayfalar |
|-------|---------|
| Genel Bakış | Güvenlik Durumu, Risk Skoru, Son Olaylar |
| Koleksiyon | Agents, Cihazlar, Keşif, Log Kaynakları |
| Tespit | Güvenlik Olayları, Korelasyon, Anomali, Tehdit İstihbaratı, MITRE ATT&CK |
| Yanıt | İncidentler, Uyarılar, Saldırı Zaman Çizelgesi, Raporlar |
| Yönetim | Kullanıcılar, Ayarlar, Denetim Günlüğü, Bakım |

---

## Kurulum

### Docker ile (Önerilen)

```bash
git clone https://github.com/mehmetcapar/netguard.git
cd netguard

# Ortam değişkenlerini ayarla
cp .env.example .env
# .env dosyasını düzenle (JWT_SECRET_KEY ve ADMIN_PASSWORD zorunlu)

docker compose up -d
```

Dashboard: `https://localhost` (ilk girişte self-signed sertifika uyarısı çıkar)

### Manuel Kurulum

#### Gereksinimler

```bash
# Ubuntu/Debian
sudo apt install python3.12 python3.12-venv nodejs npm tshark
sudo usermod -aG wireshark $USER   # pyshark için (logout/login gerekir)
```

#### Backend

```bash
cd netguard
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# .env dosyasını düzenle

uvicorn server.main:app --host 0.0.0.0 --port 8000
```

#### Frontend

```bash
cd dashboard-v2
npm install
npm run build
npm start    # veya: npm run dev (geliştirme modunda)
```

#### Agent (İzlenen Makinelere)

```bash
# Agent VM'e kopyala ve çalıştır
scp -r agent/ user@192.168.x.x:~/netguard-agent/
ssh user@192.168.x.x
cd netguard-agent
pip install psutil httpx

# .env oluştur
echo "NETGUARD_SERVER=http://192.168.203.134:8000" > .env
echo "AGENT_API_KEY=<dashboard'dan alınan key>" >> .env

python main.py
```

### Zorunlu .env Değişkenleri

```env
# Zorunlu
JWT_SECRET_KEY=          # python3 -c 'import secrets; print(secrets.token_hex(32))'
ADMIN_PASSWORD=          # Dashboard admin şifresi
VIEWER_PASSWORD=         # Dashboard viewer şifresi

# Ağ arayüzü (pyshark için)
NETGUARD_INTERFACE=ens33

# CORS (frontend URL'leri)
NETGUARD_CORS_ORIGINS=http://localhost:3000,https://192.168.203.134

# Log retention (gün)
NETGUARD_RETAIN_NORMALIZED_DAYS=30
NETGUARD_RETAIN_SECURITY_DAYS=90
NETGUARD_RETAIN_CORRELATED_DAYS=365
NETGUARD_RETAIN_ALERTS_DAYS=90

# Bildirim (opsiyonel)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_TO=
WEBHOOK_URL=             # Discord veya Slack webhook URL

# InfluxDB (opsiyonel — metrik grafikleri için)
INFLUXDB_URL=http://localhost:8086
INFLUXDB_TOKEN=
INFLUXDB_ORG=
INFLUXDB_BUCKET=netguard

# Tehdit istihbaratı (opsiyonel)
ABUSEIPDB_API_KEY=       # https://www.abuseipdb.com/api adresinden ücretsiz
```

---

## GNS3 Lab Ortamı

Proje, gerçek ağ cihazlarını simüle eden GNS3 lab ortamıyla test edilmektedir.

### Topoloji

```
OPNsense Firewall (10.0.30.1)
    │ LAN 10.0.30.0/24
VyOS Router (10.0.30.2 / 192.168.203.200)
    ├── Alpine WebServer (10.0.10.2)  — nginx, syslog gönderir
    └── Kali Linux (192.168.203.132) — saldırı testleri

NetGuard Server (192.168.203.134)   — merkez izleme
Agent VM Ubuntu (192.168.203.142)   — host agent
```

### Veri Akışları

| Kaynak | Protokol | NetGuard'a katkısı |
|--------|----------|-------------------|
| OPNsense | Syslog UDP 514 | Firewall allow/deny logları |
| VyOS | Syslog UDP 514 | Router event logları |
| VyOS | SNMP v2c | Interface istatistikleri, uptime |
| VyOS | NetFlow v9 | Trafik akış analizi |
| Alpine nginx | Syslog | Web erişim logları |
| Agent VM | HTTP API | CPU, RAM, disk, network metrikleri |

### Demo Saldırı Senaryosu

```bash
# Kali'den (192.168.203.132)

# 1. RECON — Port tarama
nmap -sS 192.168.203.134

# 2. WEAPONIZE — SSH brute force
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.203.134

# 3. NetGuard'da beklenen:
#    → port_scan_attempt → korelasyon tetikler
#    → ssh_failure × 5+ → "SSH Brute Force" incident açılır
#    → kill chain: RECON + WEAPONIZE → PARTIAL_ATTACK_CHAIN uyarısı
#    → Webhook bildirimi gönderilir
```

---

## Teknoloji Yığını

### Backend
| Teknoloji | Kullanım |
|-----------|---------|
| Python 3.12 + FastAPI | ASGI sunucu, async endpoint'ler |
| SQLite (WAL modu) | Event'ler, cihazlar, incident'lar, audit |
| InfluxDB | Zaman serisi metrikler (SNMP, agent) |
| pyshark | TCP SYN paket analizi, port tarama tespiti |
| psutil | Agent tarafında sistem metrikleri |
| python-jose + bcrypt | JWT + şifre hash |
| slowapi | Rate limiting |
| httpx | Async HTTP (webhook bildirimi) |
| scikit-learn + numpy | Isolation Forest anomaly detection |
| PyYAML | Sigma kural parser |

### Frontend
| Teknoloji | Kullanım |
|-----------|---------|
| Next.js 14 + React | App Router, SSR |
| TypeScript | Tip güvenliği |
| TanStack Query v5 | Server state, önbellekleme |
| Zustand v5 | Global state (alert store, metrics store) |
| ECharts | Topoloji haritası, grafikler |
| shadcn/ui + Tailwind CSS | UI bileşenleri |

### Protokoller

| Protokol | Port | Amaç |
|----------|------|-------|
| HTTPS | 443 | Dashboard (nginx TLS) |
| REST API | 8000 | Dashboard ↔ Server |
| WebSocket | 8000/ws | Gerçek zamanlı metrik ve alert akışı |
| Syslog UDP | 5140 | Cihaz logları (514'ten yönlendirilir) |
| SNMP UDP | 161 | Cihaz metrikleri |
| SNMP TRAP UDP | 162 | Anlık event bildirimi |
| NetFlow UDP | 2055 | Trafik akış verisi |

---

## Proje Yapısı

```
netguard/
├── agent/                          # İzlenen makinelerde çalışan agent
│   ├── main.py                     # Agent başlatma ve döngü
│   ├── collector.py                # psutil ile sistem metrikleri
│   ├── traffic_collector.py        # pyshark ile trafik analizi
│   ├── log_shipper.py              # Syslog/auth.log gönderimi
│   ├── windows_log_shipper.py      # Windows EVTX gönderimi
│   └── sender.py                  # HTTP ile server'a gönderim
│
├── server/                         # Merkezi server
│   ├── main.py                     # FastAPI app, router kayıtları, startup
│   ├── database.py                 # SQLite katmanı (WAL, tüm CRUD)
│   ├── auth.py                     # JWT, API key, tenant_scope
│   ├── correlator.py               # Korelasyon motoru (JSON + Sigma kuralları)
│   ├── attack_chain.py             # Kill chain dedektörü (5 aşama)
│   ├── anomaly/                    # Anomaly detection modülü
│   │   ├── engine.py               # Ana döngü (5 dk)
│   │   ├── baseline.py             # Welford online istatistik
│   │   ├── detector.py             # Z-score + Isolation Forest
│   │   └── collector.py            # Metrik toplama
│   ├── detectors/                  # Ağ saldırı dedektörleri
│   │   ├── port_scan.py            # pyshark SYN analizi
│   │   ├── arp_spoof.py
│   │   ├── icmp_flood.py
│   │   └── dns_anomaly.py
│   ├── parsers/                    # Log ayrıştırıcılar
│   │   ├── firewall.py             # OPNsense/VyOS/pfSense/ASA/FortiGate
│   │   ├── netflow.py              # NetFlow v5/v9 binary parser
│   │   └── web_log.py              # nginx access + error log
│   ├── discovery/                  # Ağ keşfi
│   │   ├── subnet_scanner.py       # ICMP + TCP sweep
│   │   └── fingerprinter.py        # SNMP + port tabanlı cihaz tanımlama
│   ├── topology/
│   │   └── builder.py              # SNMP ARP/LLDP walk, topoloji grafiği
│   ├── routes/                     # API endpoint'leri (her modül ayrı dosya)
│   │   ├── auth.py                 # Login, logout, refresh, /me
│   │   ├── agents.py               # Agent kaydı, metrik alma
│   │   ├── alerts.py               # Alert listesi ve özet
│   │   ├── anomaly.py              # Anomaly sonuçları
│   │   ├── compliance.py           # PCI DSS / ISO 27001 raporu
│   │   ├── correlation.py          # Correlated event'ler, kural yönetimi
│   │   ├── devices.py              # Cihaz CRUD
│   │   ├── discovery.py            # Subnet tarama, keşif sonuçları
│   │   ├── evtx.py                 # Windows EVTX yükleme ve sorgulama
│   │   ├── incidents.py            # Incident CRUD, durum güncellemesi
│   │   ├── logs.py                 # Normalize log listeleme ve arama
│   │   ├── mitre.py                # MITRE ATT&CK eşleme
│   │   ├── netflow.py              # NetFlow akış sorgulama
│   │   ├── reports.py              # Özet rapor, CSV export
│   │   ├── security.py             # Security event listesi
│   │   ├── sigma.py                # Sigma kural yönetimi
│   │   ├── snmp.py                 # SNMP cihaz yönetimi, anlık poll
│   │   ├── tenants.py              # Multi-tenant CRUD
│   │   ├── threat_intel.py         # AbuseIPDB sorgu ve önbellek
│   │   ├── topology.py             # Topoloji verisi
│   │   └── ws.py                   # WebSocket (gerçek zamanlı akış)
│   ├── compliance.py               # Compliance hesaplama motoru
│   ├── evtx_parser.py              # EVTX binary parser
│   ├── influx_writer.py            # InfluxDB yazma katmanı
│   ├── log_normalizer.py           # Raw log → NormalizedLog dönüşümü
│   ├── mitre.py                    # MITRE ATT&CK veri ve eşleme
│   ├── netflow_receiver.py         # UDP 2055 NetFlow alıcı
│   ├── notifier.py                 # Webhook + email bildirim
│   ├── retention.py                # Log retention (hot/warm/cold)
│   ├── sigma_parser.py             # YAML → CorrelationRule dönüştürücü
│   ├── snmp_collector.py           # SNMP polling döngüsü
│   ├── snmp_trap_receiver.py       # UDP 162 TRAP alıcı
│   ├── syslog_receiver.py          # UDP 5140 syslog alıcı
│   └── threat_intel.py             # AbuseIPDB istemcisi + SQLite önbellekleme
│
├── shared/                         # Agent ve server'ın ortak kullandığı modüller
│   ├── models.py                   # Pydantic veri modelleri (AgentStatus, SecurityEvent, vb.)
│   └── protocol.py                 # Protokol sabitleri
│
├── config/                         # Kural dosyaları (kod değişikliği gerektirmez)
│   ├── correlation_rules.json      # 7 aktif korelasyon kuralı
│   └── sigma_rules/                # YAML formatında Sigma kuralları
│
├── dashboard-v2/                   # Next.js frontend
│   └── src/app/(protected)/        # Dashboard sayfaları (auth zorunlu)
│
├── nginx/                          # nginx TLS yapılandırması
├── docker-compose.yml              # Tek komut deployment
├── Dockerfile                      # Backend image
├── tests/                          # ~620 pytest testi
└── docs/                           # Teknik belgeler
```

---

## Testler

```bash
pytest tests/ -q               # Tüm testler
pytest tests/test_auth.py      # Belirli modül
pytest tests/ -k "tenant"      # Anahtar kelimeyle filtrele
pytest tests/ --tb=short       # Kısa hata çıktısı
```

**Kapsanan modüller:** alert engine, anomaly detection, attack chain, auth, collector, compliance, correlation, database, detectors, devices, discovery, EVTX, firewall parser, incidents, log normalizer, MITRE, models, NetFlow parser, notifier, NTP validator, reports, retention, security, security log parser, Sigma, SNMP, tenants, threat intel, topology, uptime checker, web log parser, Windows log shipper.

---

## API Dokümantasyonu

Sunucu çalışırken: `http://localhost:8000/docs` (Swagger UI)

---

## Geliştirici

**Mehmet Çapar** — Sakarya Üniversitesi, Bilgisayar Mühendisliği  
Proje: Bitirme / Mezuniyet Tezi — 2026
