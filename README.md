# NetGuard

**Unified Network Intelligence Platform** — NMS (Network Management System) ve CSNM (Continuous Network Security Monitoring) birleşimi.

> "Ağımda şu an ne oluyor — ve bu bir performans problemi mi, güvenlik tehdidi mi, yoksa her ikisi mi?"

Geleneksel araçlar bu iki soruyu ayrı dünyalarda yanıtlar: NMS araçları performansı, SIEM araçları güvenliği izler. NetGuard her iki boyutu tek bir platformda birleştirir. Splunk/QRadar bütçesi olmayan KOBİ ve orta ölçekli kurumlar için tasarlanmıştır.

---

## Mimari

```
┌─────────────────────────────────────────────────────────────────────┐
│                       VERİ TOPLAMA KATMANI                          │
│                                                                     │
│  Linux Agent     SNMP v2c/v3    Syslog       SNMP TRAP             │
│  (psutil)        (asyncio)      UDP:5140     UDP:162               │
│                                                                     │
│  Paket Sniffer   Auto-Discovery  NetFlow*    Firewall Log*         │
│  (tshark/SYN)    (subnet sweep)  UDP:2055    (pfSense/ASA)         │
└──────────────────────────────┬──────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    UNIFIED EVENT PIPELINE                           │
│                                                                     │
│  Her kaynak → NormalizedLog formatına dönüşür                      │
│  Her event: device_id + timestamp + severity + category            │
└──────────────────────────────┬──────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    INTELLIGENCE ENGINE                              │
│                                                                     │
│  Correlation Engine    SIGMA Rules      Attack Detectors           │
│  (JSON rules, time     (yaml rules)     (ARP spoof, port scan,     │
│   window, threshold)                    ICMP flood, DNS burst)     │
│                                                                     │
│  Threat Intel*         Incident Mgmt*   Anomaly Detection*         │
│  (AbuseIPDB)           (open/closed)    (baseline + delta)         │
└──────────────────────────────┬──────────────────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    NEXT.JS DASHBOARD                                │
│                                                                     │
│  Overview (Network Command Center)   Topology Map                  │
│  Security Events    Correlation      Alerts    Logs                │
│  Devices    SNMP    Discovery        Reports   Maintenance         │
│                                                                     │
│  Attack Timeline*   Incident Center*   Compliance Reports*         │
└─────────────────────────────────────────────────────────────────────┘

* = Yol haritasında, henüz tamamlanmadı
```

---

## Tamamlanan Özellikler

### Veri Toplama
- [x] **Linux Agent** — CPU, RAM, disk, network interface, process snapshot (psutil)
- [x] **SNMP v2c/v3** — Interface istatistikleri, uptime, sys_descr, sys_name, ARP/LLDP walk
- [x] **SNMP TRAP Alıcı** — UDP 162, trap normalize + DB'ye yaz
- [x] **Syslog Alıcı** — UDP 5140, raw log depolama
- [x] **Paket Sniffer** — TCP SYN tabanlı gerçek zamanlı port tarama tespiti (tshark)
- [x] **Auto-Discovery** — Subnet sweep, ICMP + TCP probe, vendor fingerprinting
- [x] **Uptime Checker** — ICMP + TCP probe, cihaz erişilebilirlik takibi

### Güvenlik İzleme
- [x] **Auth Log Parser** — SSH failure/success, sudo kullanımı (auth.log)
- [x] **Port Scan Dedektörü** — SYN paket analizi, IP başına unique port sayımı
- [x] **ARP Spoof Dedektörü** — Çakışan MAC-IP eşleşmesi tespiti
- [x] **ICMP Flood Dedektörü** — Paket/saniye eşik aşımı
- [x] **DNS Anomali Dedektörü** — Anormal DNS sorgu patlaması
- [x] **Korelasyon Motoru** — Zaman pencereli kural eşleştirme (JSON tabanlı kurallar)
- [x] **SIGMA Kural Desteği** — YAML formatında 6 ek kural

### Korelasyon Kuralları (Aktif)
| Kural | Tetikleyici | Eşik |
|-------|------------|------|
| SSH Brute Force | 5+ ssh_failure / 60s | critical |
| Port Tarama | 1+ port_scan_attempt / 120s | high |
| ARP Spoofing | 1+ arp_spoof_attempt / 120s | critical |
| ICMP Flood | 1+ icmp_flood_attempt / 120s | high |
| DNS Patlaması | 20+ dns_query_burst / 60s | medium |
| Sudo Kötüye Kullanım | 5+ sudo_usage / 120s | warning |
| Lateral Movement | 3+ ssh_success / 300s (aynı IP) | high |

### Ağ Yönetimi
- [x] **Topology Engine** — SNMP ARP walk + LLDP komşu keşfi, interaktif harita
- [x] **Device Registry** — Unified device model (agent + SNMP + discovered tek tabloda)
- [x] **SNMP Poll History** — Zaman serisi metrik geçmişi
- [x] **NTP Doğrulama** — Sistem saati sapma tespiti

### Platform / Güvenlik
- [x] **JWT Auth** — Access token (60dk) + Refresh token (7 gün), tip kontrolü
- [x] **API Key Auth** — SHA-256 hash'li saklama, tek gösterim politikası
- [x] **HTTP Security Headers** — X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy
- [x] **Rate Limiting** — Login: 5/dk, Refresh: 10/dk (slowapi)
- [x] **Audit Log** — Admin eylemleri DB'ye yazılıyor (api_key.create, api_key.delete, retention.cleanup)
- [x] **Log Retention** — Tiered: Hot (SQLite, 30–365 gün) → Warm (JSON.gz arşiv, 1 yıl) → Cold (kapsam dışı)
- [x] **CORS** — Env'den yapılandırılabilir origin listesi
- [x] **Admin / Viewer rolleri** — Route bazlı yetkilendirme

### Dashboard Sayfaları
| Sayfa | URL | İçerik |
|-------|-----|--------|
| Genel Bakış | /overview | Network Command Center, mini topoloji, canlı alertler |
| Cihazlar | /devices | Cihaz listesi, SNMP ayarları, durum |
| Topoloji | /topology | İnteraktif L2/L3 harita |
| Keşif | /discovery | Subnet tarama, yeni cihaz tespiti |
| Agents | /agents | Agent listesi, detay sayfası |
| Alertler | /alerts | Aktif/çözümlendi, severity filtre |
| Güvenlik | /security | Security event listesi, filtreleme |
| Korelasyon | /correlation | Correlated event + aktif kurallar |
| Loglar | /logs | Normalized log arama |
| SNMP | /snmp | Manuel cihaz sorgulama (v2c/v3) |
| Raporlar | /reports | Özet rapor + 4 CSV indirme |
| Bakım | /maintenance | DB boyutları, retention policy, manual cleanup |
| Ayarlar | /settings | Kullanıcı tercihleri |

### API
- [x] REST API `/api/v1/` — 15+ router, tam CRUD
- [x] WebSocket `/ws` — Gerçek zamanlı metrik ve alert akışı
- [x] OpenAPI dokümantasyonu `/docs`

### Test
- [x] **353 test** — pytest, tümü geçiyor
- Kapsanan modüller: agent, auth, alerts, correlator, database, detectors, logs, maintenance, reports, retention, security, SNMP, topology

---

## Yol Haritası

### Tier 1 — Platform Tamamlama
- [ ] **HTTPS / TLS** — nginx reverse proxy, self-signed veya Let's Encrypt
- [ ] **JWT Logout + Token Blacklist** — /auth/logout, SQLite blacklist tablosu
- [ ] **Notifier → Correlated Events** — Kritik saldırı tespiti → email/Discord webhook
- [ ] **Audit Log UI** — /maintenance/audit backend var, dashboard sayfası yok

### Tier 2 — Veri Zenginleştirme
- [ ] **Threat Intelligence** — Tespit edilen IP → AbuseIPDB ücretsiz API → itibar skoru + ülke + kategori
- [ ] **Firewall Log Parser** — pfSense, Cisco ASA, FortiGate syslog → normalized security events
- [ ] **Web Log Parser** — nginx/Apache access.log → SQLi, path traversal, brute force tespiti
- [ ] **NetFlow v5/v9 Receiver** — UDP parse → trafik akış analizi (kim kime ne kadar)

### Tier 3 — Kurumsal Özellikler
- [ ] **Incident Yönetimi** — Alert → Incident, atama, durum takibi (open / investigating / resolved), zaman çizelgesi
- [ ] **Windows Agent** — Python + WMI/EVTX: Event Log 4625/4624/4688 (başarısız giriş, process, servis)
- [ ] **Saldırı Timeline** — Brute force → port scan → başarılı giriş zincirini görsel göster
- [ ] **Compliance Raporu** — Mevcut verileri PCI DSS ve ISO 27001 maddelerine otomatik eşleştir

### Tier 4 — İleri Seviye
- [ ] **Anomaly Detection** — Normal trafik baseline'ı öğren, istatistiksel sapma yakala
- [ ] **Docker Deployment** — docker-compose ile tek komut kurulum
- [ ] **Multi-Site / Multi-Tenant** — Birden fazla şube / müşteri izolasyonu
- [ ] **GNS3 Lab Entegrasyonu** — pfSense + VyOS + Mikrotik CHR ile sanal ağ topolojisi

---

## Lab Ortamı

### Mevcut

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  NetGuard    │     │  Agent VM    │     │  Kali Linux  │
│  Server      │◄────│  Ubuntu      │     │  (saldırı)   │
│  .134        │     │  .142        │     │  .132        │
└──────────────┘     └──────────────┘     └──────────────┘
        192.168.203.0/24
```

### Hedef Lab (Tier 2–3 testleri için)

```
┌──────────────┐   syslog/SNMP   ┌──────────────┐
│  pfSense VM  │────────────────►│  NetGuard    │
│  (firewall)  │                 │  Server .134 │
└──────┬───────┘                 └──────▲───────┘
       │ NAT/routing                    │ SNMP/NetFlow
┌──────▼───────┐                 ┌──────┴───────┐
│  VyOS VM     │────────────────►│  Agent VM    │
│  (router)    │   syslog/NFlow  │  .142        │
└──────┬───────┘                 └──────────────┘
       │
┌──────▼───────┐
│  Mikrotik    │  (switch simülasyonu, Türkiye'de yaygın)
│  CHR (free)  │
└──────────────┘
```

### Lab Araçları Karşılaştırması

| Araç | Ücretsiz mi? | Kurulum | Cisco image gerekir mi? | NetGuard için uygunluk |
|------|-------------|---------|------------------------|----------------------|
| pfSense VM | Evet | Kolay (ISO) | Hayır | Firewall log testi için ideal |
| VyOS | Evet | Orta | Hayır | Router/NetFlow testi için ideal |
| Mikrotik CHR | Evet (<1Mbps) | Kolay | Hayır | Türkiye ortamı simülasyonu |
| GNS3 + yukarıdakiler | Evet | Orta-Zor | Hayır | Karmaşık topoloji testi |
| EVE-NG Community | Evet (sınırlı) | Zor | Hayır | Multi-vendor |
| Cisco CML Community | Hayır ($199/yıl) | Orta | Evet (dahil) | Cisco odaklı |

**Öneri:** Önce pfSense + VyOS VM'leri doğrudan VMware'e ekle (GNS3 gerekmez). Firewall log parser ve NetFlow receiver çalıştıktan sonra GNS3 ile karmaşık topoloji testine geç.

---

## Teknoloji Yığını

### Backend
- **Python 3.12** + **FastAPI** (ASGI, async)
- **SQLite** (WAL modu) — event'ler, cihazlar, topoloji, audit
- **InfluxDB** — zaman serisi metrikler
- **tshark** — paket yakalama (port scan, ARP, ICMP, DNS dedektörleri)
- **psutil** — sistem metrikleri (agent tarafı)
- **python-jose** + **bcrypt** — JWT + şifre hash
- **hashlib (SHA-256)** — API key hash
- **slowapi** — rate limiting
- **httpx** — async HTTP (webhook bildirimi)

### Frontend
- **Next.js** + **React** (App Router)
- **TypeScript**
- **TanStack Query v5** — server state, cache
- **Zustand v5** — global state (alert store, metrics store)
- **ECharts** — topoloji haritası ve grafikler
- **shadcn/ui** + **Tailwind CSS** — UI bileşenleri

### İletişim Protokolleri
| Protokol | Port | Amaç |
|----------|------|-------|
| REST API | 8000 | Dashboard ↔ Server |
| WebSocket | 8000/ws | Gerçek zamanlı akış |
| Syslog UDP | 5140 | Cihaz logları |
| SNMP UDP | 161 | Cihaz metrikleri |
| SNMP TRAP UDP | 162 | Anlık event bildirimi |
| NetFlow UDP | 2055* | Trafik akış verisi |

*Henüz tamamlanmadı

---

## Kurulum

### Gereksinimler
- Python 3.12+
- Node.js 20+
- tshark: `sudo apt install tshark`
- InfluxDB (opsiyonel, metrikler için)

### Backend
```bash
git clone https://github.com/mehmet15832020/netguard.git
cd netguard
pip install -r requirements.txt

# Zorunlu .env ayarları
cp .env.example .env
# JWT_SECRET_KEY= python3 -c 'import secrets; print(secrets.token_hex(32))'
# ADMIN_PASSWORD=
# NETGUARD_INTERFACE=ens33

uvicorn server.main:app --host 0.0.0.0 --port 8000
```

### Frontend
```bash
cd dashboard-v2
npm install
npm run dev     # geliştirme: localhost:3000
npm run build   # production build
```

### Systemd (Üretim)
```bash
# Agent VM
sudo systemctl enable --now netguard-agent.service

# Server VM
sudo systemctl enable --now netguard.service
```

### Önemli .env Değişkenleri
```env
# Zorunlu
JWT_SECRET_KEY=           # python3 -c 'import secrets; print(secrets.token_hex(32))'
ADMIN_PASSWORD=           # Dashboard admin şifresi
VIEWER_PASSWORD=          # Dashboard viewer şifresi

# Ağ
NETGUARD_INTERFACE=ens33  # Paket yakalama arayüzü
NETGUARD_CORS_ORIGINS=http://localhost:3000,http://192.168.1.x:3000

# Retention (gün)
NETGUARD_RETAIN_NORMALIZED_DAYS=30
NETGUARD_RETAIN_SECURITY_DAYS=90
NETGUARD_RETAIN_CORRELATED_DAYS=365
NETGUARD_RETAIN_ALERTS_DAYS=90
NETGUARD_ARCHIVE_DIR=/var/lib/netguard/archive

# Bildirim (opsiyonel)
SMTP_HOST=smtp.gmail.com
SMTP_USER=
SMTP_PASSWORD=
SMTP_TO=
WEBHOOK_URL=              # Discord veya Slack webhook

# InfluxDB (opsiyonel)
INFLUXDB_URL=http://localhost:8086
INFLUXDB_TOKEN=
INFLUXDB_ORG=
INFLUXDB_BUCKET=
```

---

## Test

```bash
pytest tests/ -q           # Tüm testler
pytest tests/test_auth.py  # Sadece auth testleri
pytest tests/ -k "snmp"    # SNMP testleri
```

---

## Proje Yapısı

```
netguard/
├── agent/                     # Agent — izlenen makinelerde çalışır
│   ├── collector.py            # psutil ile sistem metrikleri
│   ├── traffic_collector.py   # tshark paket analizi
│   └── sender.py              # HTTP ile server'a gönderim
├── server/                    # Merkezi server
│   ├── main.py                # FastAPI app + async döngüler
│   ├── database.py            # SQLite katmanı (WAL)
│   ├── auth.py                # JWT + API key auth
│   ├── correlator.py          # Korelasyon motoru
│   ├── retention.py           # Log retention (hot/warm/cold)
│   ├── notifier.py            # Email + webhook bildirimi
│   ├── detectors/             # Ağ saldırı dedektörleri
│   │   ├── port_scan.py
│   │   ├── arp_spoof.py
│   │   ├── icmp_flood.py
│   │   └── dns_anomaly.py
│   ├── topology/              # Topoloji motoru
│   │   └── builder.py
│   └── routes/                # API endpoint'leri
│       ├── auth.py
│       ├── agents.py
│       ├── alerts.py
│       ├── security.py
│       ├── correlation.py
│       ├── devices.py
│       ├── topology.py
│       ├── reports.py
│       ├── maintenance.py
│       └── ...
├── dashboard-v2/              # Next.js frontend
│   └── src/app/(protected)/   # Dashboard sayfaları
├── shared/                    # Ortak modeller
│   ├── models.py
│   └── protocol.py
├── config/                    # Kural dosyaları
│   ├── correlation_rules.json  # 7 üretim korelasyon kuralı
│   └── sigma_rules/           # 6 SIGMA YAML kuralı
└── tests/                     # 353 pytest testi
```

---

## Geliştirici

**Mehmet Çapar** — Sakarya Üniversitesi, Bilgisayar Mühendisliği
