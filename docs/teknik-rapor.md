# NetGuard — Teknik Rapor
**Hedef kitle:** Ürünü geliştiren, genişleten veya entegre eden yazılım mühendisleri  
**Versiyon:** 0.1.0 · Faz 8 tamamlandı · Hazırlanma tarihi: Nisan 2026  
**Test durumu:** 314 test, tümü geçiyor

---

## İçindekiler

1. [Proje Kimliği ve Kapsam](#1-proje-kimliği-ve-kapsam)
2. [Yüksek Seviye Mimari](#2-yüksek-seviye-mimari)
3. [Teknoloji Stack](#3-teknoloji-stack)
4. [Dizin Yapısı — Tam Ağaç](#4-dizin-yapısı--tam-ağaç)
5. [Backend Modülleri — Detaylı Analiz](#5-backend-modülleri--detaylı-analiz)
6. [API Endpoint Referansı](#6-api-endpoint-referansı)
7. [Veritabanı Şeması](#7-veritabanı-şeması)
8. [Veri Akışları](#8-veri-akışları)
9. [Güvenlik Modeli](#9-güvenlik-modeli)
10. [Frontend Mimarisi](#10-frontend-mimarisi)
11. [Agent Mimarisi](#11-agent-mimarisi)
12. [Test Altyapısı](#12-test-altyapısı)
13. [Çevre Değişkenleri (Environment)](#13-çevre-değişkenleri-environment)
14. [Bağımlılıklar ve Kütüphaneler](#14-bağımlılıklar-ve-kütüphaneler)
15. [Bilinen Sınırlamalar ve Geliştirme Fırsatları](#15-bilinen-sınırlamalar-ve-geliştirme-fırsatları)

---

## 1. Proje Kimliği ve Kapsam

NetGuard, iki geleneksel disiplini birleştiren bir **Unified Network Intelligence Platform**'dur:

| Disiplin | Açıklama | NetGuard'daki Karşılığı |
|---|---|---|
| NMS (Network Management System) | Performans izleme, uptime, SNMP polling | Agent metrikleri, SNMP collector, uptime checker |
| CSNM (Continuous Security Network Monitoring) | Güvenlik olayı tespiti, korelasyon | Dedektörler, log parser, correlator |

### Temel İlkeler

- **Unified Device Model:** Agent, SNMP ve discovery yoluyla bulunan her cihaz aynı `devices` tablosunda, aynı `device_id` ile temsil edilir.
- **Cross-Domain Correlation:** Performans olayları (cihaz down) ile güvenlik olayları (SSH brute force) aynı pipeline'dan geçer; birlikte analiz edilebilir.
- **Modüler Tasarım:** Her sorumluluk kendi modülüne ayrılmıştır. Yeni bir dedektör, kural veya route eklemek için mevcut kodu değiştirmeye gerek yoktur.
- **İki Katmanlı Depolama:** Anlık erişim için RAM cache (`InMemoryStorage`), kalıcılık için SQLite, zaman serisi için InfluxDB.

### Mevcut Lab Ortamı

```
VM1  192.168.203.134  →  NetGuard Server + Dashboard (port 8000, 3000)
VM2  192.168.203.142  →  Agent (Kali — saldırı testleri)
```

---

## 2. Yüksek Seviye Mimari

```
┌─────────────────────────────────────────────────────────────────────┐
│                          KULLANICI KATMANI                          │
│  Browser → Next.js Dashboard (port 3000)                            │
│           JWT Auth  ·  WebSocket real-time  ·  REST API calls       │
└─────────────────────────────────────────────┬───────────────────────┘
                                              │ HTTP/WS
┌─────────────────────────────────────────────▼───────────────────────┐
│                     FASTAPI SUNUCU (port 8000)                      │
│                                                                      │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────────────┐   │
│  │  API Routes │  │  Background  │  │  Passive Receivers       │   │
│  │  (13 grup) │  │  Loops (6×)  │  │  Syslog UDP:5140         │   │
│  │            │  │              │  │  SNMP TRAP UDP           │   │
│  └──────┬─────┘  └──────┬───────┘  └──────────┬───────────────┘   │
│         │               │                      │                    │
│  ┌──────▼───────────────▼──────────────────────▼───────────────┐   │
│  │                    CORE ENGINE                               │   │
│  │  AlertEngine · Correlator · DetectorManager · LogNormalizer │   │
│  │  NTPValidator · Notifier · WebSocketManager                 │   │
│  └──────────────────────────┬───────────────────────────────────┘   │
│                             │                                        │
│  ┌──────────────────────────▼───────────────────────────────────┐   │
│  │                    DEPOLAMA KATMANI                          │   │
│  │  SQLite (WAL) ·  InMemoryStorage (RAM)  ·  InfluxDB         │   │
│  └──────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
           ↑                           ↑
  Agent push (HTTP)            SNMP pull (UDP 161)
  API Key auth                 Community / USM v3
  
┌──────────────────────┐    ┌─────────────────────────┐
│  NetGuard Agent      │    │  Ağ Cihazı (Router vb.) │
│  psutil collector    │    │  SNMPv2c / SNMPv3        │
│  traffic collector   │    │  ARP / LLDP              │
│  sender (10s)        │    │                          │
└──────────────────────┘    └─────────────────────────┘
```

### Bileşen Sorumlulukları

| Katman | Bileşen | Sorumluluk |
|---|---|---|
| Kullanıcı | Next.js Dashboard | Görselleştirme, konfigürasyon |
| API | FastAPI routes | İstek validation, auth, iş mantığına yönlendirme |
| Engine | AlertEngine | Metrik eşik kontrolü → Alert üretimi |
| Engine | Correlator | Zaman penceresi analizi → CorrelatedEvent |
| Engine | DetectorManager | Anlık ağ anomali tespiti |
| Engine | LogNormalizer | Farklı format → tek NormalizedLog şeması |
| Collector | SNMPCollector | SNMP GET/WALK, interface stats, bandwidth delta |
| Collector | UptimeChecker | ICMP/TCP/HTTP cihaz erişilebilirlik |
| Collector | SecurityLogParser | /var/log/auth.log → SecurityEvent |
| Listener | SyslogReceiver | UDP 5140, harici syslog akışı |
| Listener | SNMPTrapReceiver | Cihazlardan gelen TRAP olayları |
| Storage | DatabaseManager | SQLite thread-safe CRUD |
| Storage | InMemoryStorage | RAM cache (1 saat geçmiş) |
| Storage | InfluxWriter | Zaman serisi (metrikler) |
| Notifier | Notifier | Email + Webhook (Discord/Slack) |

---

## 3. Teknoloji Stack

### Backend

| Kütüphane | Versiyon | Kullanım |
|---|---|---|
| **FastAPI** | 0.115.0 | Web framework, async HTTP, OpenAPI docs |
| **Uvicorn** | latest | ASGI sunucu |
| **Pydantic** | 2.8.2 | Veri modelleri, validation, serialization |
| **Starlette** | 0.38.6 | WebSocket, middleware (FastAPI alt yapısı) |
| **python-jose** | 3.5.0 | JWT token oluşturma ve doğrulama (HS256) |
| **bcrypt** | 4.0.1 | Parola hash (passlib wrapper) |
| **slowapi** | 0.1.9 | Rate limiting (endpoint seviyesi) |
| **python-dotenv** | 1.0.1 | .env dosyası yükleme |
| **pysnmp** | 7.1.22 | SNMP v2c/v3 asyncio, TRAP receiver |
| **psutil** | 6.0.0 | CPU, RAM, disk, network, process metrikleri |
| **httpx** | 0.27.2 | Async HTTP client (uptime checker) |
| **ntplib** | 0.4.0 | NTP sorgulama (saat doğrulama) |
| **influxdb-client** | 1.50.0 | InfluxDB yazma (zaman serisi) |
| **pyshark** | 0.6 | tshark wrapper (port scan dedektörü) |
| **lxml** | 6.0.2 | XML/HTML parsing |

### Frontend

| Kütüphane | Versiyon | Kullanım |
|---|---|---|
| **Next.js** | 16.2.3 (Turbopack) | React framework, App Router |
| **React** | 19.2.4 | UI bileşenleri |
| **TypeScript** | ^5 | Tip güvenliği |
| **TailwindCSS** | ^4 | Utility-first CSS |
| **echarts** | ^6.0.0 | Grafik ve topoloji haritası (ECharts graph) |
| **@tanstack/react-query** | ^5.99.0 | Server state, polling, cache |
| **zustand** | ^5.0.12 | Client state yönetimi |
| **lucide-react** | ^1.8.0 | İkon seti |
| **shadcn/ui** | ^4.2.0 | UI bileşen kütüphanesi (Button, Card, Table vb.) |
| **axios** | ^1.15.0 | HTTP client |
| **zod** | ^4.3.6 | Frontend form validasyon |

### Veritabanı ve Altyapı

| Teknoloji | Kullanım |
|---|---|
| **SQLite (WAL mode)** | Tüm kalıcı veri — alerts, events, devices, logs, topology |
| **InfluxDB** | Metrik zaman serisi (CPU, RAM, bandwidth trend) |
| **Python asyncio** | SNMP polling, discovery, uptime check, background döngüler |
| **Threading (Lock)** | InMemoryStorage thread-safety |

---

## 4. Dizin Yapısı — Tam Ağaç

```
netguard/
├── agent/                          # Izlenen sunuculara kurulan istemci
│   ├── main.py                     # Giriş noktası, döngü yönetimi
│   ├── collector.py                # psutil → MetricSnapshot
│   ├── sender.py                   # HTTP → server'a gönderim
│   ├── snmp_collector.py           # (eski SNMP kodu, kullanım dışı)
│   └── traffic_collector.py        # Ağ trafiği özeti, şüpheli paket tespiti
│
├── server/                         # FastAPI backend
│   ├── main.py                     # FastAPI app, CORS, lifespan, 6 background loop
│   ├── auth.py                     # JWT (kullanıcı) + API Key (agent) auth
│   ├── database.py                 # SQLite yöneticisi, tüm CRUD operasyonları
│   ├── storage.py                  # RAM cache (InMemoryStorage)
│   ├── alert_engine.py             # Metrik eşik → Alert üretimi
│   ├── correlator.py               # Zaman penceresi → CorrelatedEvent
│   ├── log_normalizer.py           # Çok kaynak → NormalizedLog
│   ├── security_log_parser.py      # /var/log/auth.log parse
│   ├── snmp_collector.py           # SNMP v2c/v3 GET/WALK, bandwidth delta
│   ├── snmp_auth.py                # SNMP auth nesne builder (v2c/v3)
│   ├── snmp_trap_receiver.py       # UDP SNMP TRAP alıcısı
│   ├── syslog_receiver.py          # UDP 5140 syslog alıcısı
│   ├── uptime_checker.py           # ICMP/TCP/HTTP cihaz erişilebilirlik
│   ├── ntp_validator.py            # NTP saat doğrulama
│   ├── influx_writer.py            # InfluxDB metrik yazıcısı
│   ├── notifier.py                 # Email + Webhook bildirimleri
│   ├── ws_manager.py               # WebSocket broadcast yönetimi
│   ├── port_monitor.py             # Açık port değişimi takibi
│   ├── config_monitor.py           # Kritik dosya checksum takibi
│   │
│   ├── routes/                     # FastAPI router modülleri (1 grup = 1 dosya)
│   │   ├── auth.py                 # /auth/* (login, me, agent-key)
│   │   ├── health.py               # /health
│   │   ├── agents.py               # /agents/* (register, metrics, list, detail)
│   │   ├── alerts.py               # /alerts/* (list, summary)
│   │   ├── devices.py              # /devices/* (list, detail)
│   │   ├── snmp.py                 # /snmp/* (poll, devices CRUD)
│   │   ├── security.py             # /security/* (events, summary, scan)
│   │   ├── logs.py                 # /logs/* (normalized, raw, ingest)
│   │   ├── correlation.py          # /correlation/* (events, rules, run)
│   │   ├── discovery.py            # /discovery/* (scan, status, results)
│   │   ├── topology.py             # /topology/* (graph, refresh)
│   │   ├── reports.py              # /reports/* (summary, CSV download)
│   │   └── ws.py                   # /ws WebSocket
│   │
│   ├── detectors/                  # Ağ anomali dedektörleri
│   │   ├── base.py                 # BaseDetector abstract class
│   │   ├── manager.py              # Tüm dedektörleri çalıştır → DB yaz
│   │   ├── port_scan.py            # TCP SYN sniff → port tarama tespiti
│   │   ├── arp_spoof.py            # /proc/net/arp → MAC değişimi tespiti
│   │   ├── icmp_flood.py           # /proc/net/snmp → ICMP rate tespiti
│   │   └── dns_anomaly.py          # UDP port 53 bağlantı sayısı
│   │
│   ├── discovery/                  # Ağ keşfi modülleri
│   │   ├── subnet_scanner.py       # Async ping sweep (50 eşzamanlı)
│   │   └── fingerprinter.py        # Port tarama + banner grab + SNMP
│   │
│   └── topology/                   # L2/L3 topoloji engine
│       └── builder.py              # ARP walk + LLDP + subnet fallback
│
├── shared/                         # Agent + Server arasında paylaşılan kod
│   ├── models.py                   # Tüm Pydantic modeller ve enum'lar
│   └── protocol.py                 # API sabitleri, limitler, URL şablonları
│
├── config/
│   └── correlation_rules.json      # Hot-reload edilebilen korelasyon kuralları
│
├── tests/                          # pytest test suite (314 test)
│   ├── conftest.py                 # tmp_db fixture, admin_token fixture
│   ├── test_alert_engine.py
│   ├── test_auth.py
│   ├── test_collector.py
│   ├── test_correlation_routes.py
│   ├── test_correlator.py
│   ├── test_cross_domain_correlation.py
│   ├── test_database.py
│   ├── test_detectors.py
│   ├── test_devices.py
│   ├── test_discovery.py
│   ├── test_log_normalizer.py
│   ├── test_models.py
│   ├── test_ntp_validator.py
│   ├── test_reports.py
│   ├── test_security_log_parser.py
│   ├── test_security_routes.py
│   ├── test_server.py
│   ├── test_snmp.py
│   ├── test_snmp_routes.py
│   ├── test_snmp_trap_receiver.py
│   ├── test_snmpv3.py
│   ├── test_topology.py
│   └── test_uptime_checker.py
│
├── dashboard-v2/                   # Next.js frontend
│   ├── src/
│   │   ├── app/
│   │   │   ├── page.tsx            # / → /overview yönlendirme
│   │   │   ├── login/page.tsx      # Giriş ekranı
│   │   │   └── (protected)/        # Auth gerektiren sayfalar
│   │   │       ├── layout.tsx      # Sidebar + auth guard
│   │   │       ├── overview/       # Ana dashboard (mini topoloji + özetler)
│   │   │       ├── agents/         # Agent listesi + [id] detay
│   │   │       ├── devices/        # Unified cihaz envanteri
│   │   │       ├── topology/       # ECharts topoloji haritası
│   │   │       ├── discovery/      # Subnet tarama + sonuçlar
│   │   │       ├── alerts/         # Alert listesi
│   │   │       ├── security/       # Güvenlik olayları
│   │   │       ├── logs/           # Normalize loglar
│   │   │       ├── correlation/    # Korelasyon olayları + kural editörü
│   │   │       ├── snmp/           # SNMP sorgu (v2c + v3 form)
│   │   │       ├── reports/        # Özet + CSV indirme
│   │   │       └── settings/       # Ayarlar
│   │   ├── components/
│   │   │   ├── layout/Sidebar.tsx  # Navigasyon sidebar
│   │   │   ├── metrics/            # MetricCard, CPUChart, MemoryGauge
│   │   │   ├── topology/MiniTopology.tsx  # Overview için mini harita
│   │   │   ├── charts/             # Trend grafikleri
│   │   │   ├── ui/                 # shadcn bileşenleri
│   │   │   └── alerts/, logs/, correlation/, settings/
│   │   ├── lib/
│   │   │   ├── api.ts              # Tüm API client fonksiyonları
│   │   │   └── utils.ts            # cn() helper
│   │   ├── hooks/
│   │   │   ├── useMetrics.ts       # Agent snapshot hooks
│   │   │   ├── useAlerts.ts        # Alert polling
│   │   │   └── useWebSocket.ts     # WS bağlantı yönetimi
│   │   └── types/
│   │       └── models.ts           # TypeScript arayüz tanımları
│   └── package.json
│
├── docs/                           # Dokümantasyon
│   ├── teknik-rapor.md             # Bu dosya
│   └── kullanici-kilavuzu.md       # Kullanıcı kılavuzu
│
├── requirements.txt                # Python bağımlılıkları
├── CLAUDE.md                       # AI geliştirme rehberi
└── .env (oluşturulması gerekir)    # Ortam değişkenleri
```

---

## 5. Backend Modülleri — Detaylı Analiz

### 5.1 `server/main.py` — Uygulama Giriş Noktası

**Bağlandığı modüller:** Tüm routes, influx_writer, SyslogReceiver, SNMPTrapReceiver

**Lifespan (startup/shutdown):**
Sunucu başladığında 6 background asyncio task başlatılır, kapanışta iptal edilir:

```python
asyncio.create_task(_security_scan_loop())  # 60s: auth.log + port + config
asyncio.create_task(_ntp_check_loop())      # 300s: sistem saati
asyncio.create_task(_correlation_loop())    # 60s: korelasyon motoru
asyncio.create_task(_detector_loop())       # 30s: ağ dedektörleri
asyncio.create_task(_snmp_poll_loop())      # 60s: SNMP cihaz sorgu
asyncio.create_task(_uptime_check_loop())   # 60s: cihaz erişilebilirlik
```

**SNMP Poll Döngüsü Önemli Detay:**
```python
# Şu an sadece snmp_devices tablosundan alıyor, devices'tan değil
devices = db.get_snmp_devices(enabled_only=True)
results = await asyncio.gather(*[poll_device_async(d["host"], d["community"]) ...])
```
> **Not:** Bu bir tutarsızlık. devices tablosundaki snmp_version='v3' olan cihazlar için v3 parametreleri kullanılmıyor. Düzeltme gerekiyor.

**Ortam Değişkeni Sabitleri:**
```
SECURITY_SCAN_INTERVAL  = 60s
NETGUARD_NTP_CHECK_INTERVAL = 300s
NETGUARD_CORR_INTERVAL  = 60s
NETGUARD_DETECTOR_INTERVAL  = 30s
NETGUARD_SNMP_INTERVAL  = 60s
NETGUARD_UPTIME_INTERVAL = 60s
```

---

### 5.2 `server/database.py` — SQLite Yöneticisi

**Mimari kararlar:**
- WAL (Write-Ahead Log) modu: eşzamanlı okuma/yazma (dashboard sorgusu + agent yazması)
- `threading.Lock` ile thread-safety: her bağlantı kendi context'i
- `conn.row_factory = sqlite3.Row`: sütun adına erişim (`row["alert_id"]`)
- `INSERT OR REPLACE` / `ON CONFLICT DO UPDATE`: idempotent yazma
- İdempotent migration: `ALTER TABLE ADD COLUMN IF NOT EXISTS` benzeri mantık

**Global instance:** `db = DatabaseManager()` — tüm modüller bu nesneyi import eder.

**Kritik metod: `save_correlated_event()`**
```python
# Aynı rule_id + group_value + window için duplicate önleme
# Son WINDOW_SECONDS içinde aynı kural tetiklendiyse yeni kayıt oluşturma
```

**Migration sistemi:**
- `_migrate_snmp_to_devices()`: eski snmp_devices → devices tablosu (Faz 1)
- `_migrate_snmpv3_columns()`: 5 yeni kolon idempotent ekleme (Faz 7)

---

### 5.3 `server/auth.py` — Kimlik Doğrulama

**İki farklı auth akışı:**

**Akış 1 — Kullanıcı (Dashboard):**
```
POST /auth/login → authenticate_user() → create_access_token() → JWT
Her istek: Authorization: Bearer <token> → get_current_user() Depends()
```

**Akış 2 — Agent:**
```
POST /auth/agent-key (admin) → register_agent_key() → API key DB'ye kaydedilir
Her istek: X-API-Key: <key> → verify_api_key() → agent_id
```

**Önemli Sınırlamalar:**
- Kullanıcı bilgileri hardcoded sözlükte (`_USERS_DB`), gerçek bir DB tablosunda değil
- Admin ve Viewer kullanıcısı var, şifreler env değişkenlerinden alınıyor
- Token yenileme (refresh token) mekanizması yok; token süresi dolunca tekrar login

**Rate Limiting:**
```python
@router.post("/auth/login")
@limiter.limit("5/minute")  # IP başına 5 deneme/dakika
```

---

### 5.4 `server/alert_engine.py` — Alert Motoru

**Mimari Özelliği:** Alert Engine, Storage katmanına bağlı değil. `evaluate(snapshot) → list[Alert]` döner, kaydetmek router'ın sorumluluğu.

**5 Sabit Kural (kodda hardcoded, JSON konfigürasyon yok):**

| rule_id | Metrik | Eşik | Severity |
|---|---|---|---|
| cpu_high | CPU kullanımı | > %80 | WARNING |
| ram_high | RAM kullanımı | > %85 | WARNING |
| disk_high | Kök disk (/) | > %90 | CRITICAL |
| bandwidth_high | Toplam inbound | > 100 Mbps | WARNING |
| suspicious_traffic | Şüpheli paket | > 10 adet | CRITICAL |

**Duplicate Önleme:**
```python
self._active: dict[str, str] = {}  # "agent_id:rule_id" → alert_id
# Zaten aktif alert varsa yeni oluşturma
# Kural pasif hale gelirse otomatik RESOLVED
```

**Geliştirme Notu:** Alert kuralları da korelasyon kuralları gibi JSON'a taşınabilir, hot-reload desteklenebilir.

---

### 5.5 `server/correlator.py` — Korelasyon Motoru

**Kural Şeması (JSON):**
```json
{
  "rule_id": "brute_force_ssh",
  "name": "SSH Brute Force",
  "match_event_type": "ssh_failure",   // LIKE prefix sorgusu
  "match_severity": "warning",          // opsiyonel filtre
  "group_by": "src_ip",                // veya "source_host"
  "window_seconds": 300,
  "threshold": 5,
  "severity": "critical",
  "output_event_type": "ssh_brute_force_detected",
  "enabled": true
}
```

**Çalışma Mantığı:**
```sql
SELECT src_ip, COUNT(*) as cnt, MIN(timestamp), MAX(timestamp)
FROM normalized_logs
WHERE event_type LIKE 'ssh_failure%'
  AND timestamp >= (now - 300s)
GROUP BY src_ip
HAVING cnt >= 5
```

**Mevcut kural dosyası sadece 1 test kuralı içeriyor.** Gerçek brute force, DDoS, port tarama kuralları eklenmeye hazır.

---

### 5.6 `server/detectors/` — Anlık Dedektörler

#### 5.6.1 `port_scan.py` — Port Tarama Dedektörü
- **Mekanizma:** `pyshark` (tshark wrapper) ile TCP SYN paketleri yakalanır
- **Thread:** Arka planda sürekli sniff, `_seen: dict[str, set[int]]` window'u
- **Trigger:** Tek IP'den 60s içinde 15+ farklı port → `port_scan_attempt`
- **Gereksinim:** `tshark` yüklü olmalı, network interface erişimi

#### 5.6.2 `arp_spoof.py` — ARP Spoofing Dedektörü
- **Mekanizma:** `/proc/net/arp` dosyasını parse eder (Linux-only)
- **Track:** `_known: dict[str, str]` → IP → MAC eşlemesi
- **Trigger:** Bilinen IP için MAC değişimi → `arp_spoof_attempt`
- **Ek kontrol:** Aynı MAC → birden fazla IP → muhtemel MITM

#### 5.6.3 `icmp_flood.py` — ICMP Flood Dedektörü
- **Mekanizma:** `/proc/net/snmp` → `Icmp: InMsgs` sayacı delta hesabı
- **Trigger:** InMsgs delta / elapsed_sec > 100 pkt/s → `icmp_flood`
- **State:** `_prev_count`, `_prev_time` (tek state, multi-interface yok)

#### 5.6.4 `dns_anomaly.py` — DNS Anomali Dedektörü
- **Mekanizma:** `/proc/net/udp` parse → hex encoding → port 53'e giden bağlantı sayısı
- **Fallback:** `psutil.net_connections("udp")` (daha kolay ama yavaş)
- **Trigger:** port 53 UDP > 30 bağlantı → `dns_anomaly`

**Tüm dedektörler `NormalizedLog` + `SecurityEvent` çifti üretir.**

---

### 5.7 `server/snmp_collector.py` ve `snmp_auth.py`

**Bandwidth Delta Algoritması:**
```python
# İki poll arası delta (64-bit overflow-safe)
elapsed = current_time - prev_time
in_bps = (new_hc_in - prev_hc_in) * 8 / elapsed
# 64-bit overflow durumu:
in_bps = (_MAX_COUNTER64 - prev + new) * 8 / elapsed
```

**Interface Walk Önceliği:**
1. 64-bit HCInOctets/HCOutOctets (RFC 2863)
2. Fallback: 32-bit ifInOctets/ifOutOctets (RFC 1213)

**v3 Auth Builder (`snmp_auth.py`):**
```python
def build_snmp_auth(snmp_version, community, v3_username,
                    v3_auth_protocol, v3_auth_key,
                    v3_priv_protocol, v3_priv_key):
    if snmp_version == "v3":
        if v3_auth_key and v3_priv_key:
            return UsmUserData(...)  # authPriv
        elif v3_auth_key:
            return UsmUserData(...)  # authNoPriv
        else:
            return UsmUserData(...)  # noAuthNoPriv
    return CommunityData(community, mpModel=1)  # v2c
```

---

### 5.8 `server/security_log_parser.py`

**Dosya:** `/var/log/auth.log` (env değişkeni AUTH_LOG_PATH ile değiştirilebilir)

**Her çalışmada son 500 satır okunur** (`max_lines=500`). Bu stateless bir yaklaşım — her scan tüm son satırları yeniden işler. Duplicate kaydı önleyen `INSERT OR IGNORE` mantığı DB'de.

**Brute Force Tespiti:**
```python
# DB'ye SSH_FAILURE kaydedildikten sonra:
count = db.count_recent_failures(source_ip, since_5min_ago)
if count >= 5:
    emit BRUTE_FORCE event
```

**Double Yazma:** Her SecurityEvent için ayrıca `normalized_logs` tablosuna da yazılır → Correlator tarafından işlenebilir.

---

### 5.9 `server/uptime_checker.py`

**Kontrol Protokolleri (sırayla):**
1. ICMP ping (3 paket, 3s timeout) → rtt_ms, packet_loss_pct
2. TCP port 22, 80, 443, 161 (sadece ping başarılıysa)
3. HTTP check — url'si varsa

**State Tracking:** `_prev_status[device_id]` — sadece durum değişimini event olarak yaz
```python
if old_status != new_status:
    _emit_status_event(dev, new_status)  # DEVICE_DOWN veya DEVICE_UP
    # → security_events + normalized_logs
```

---

### 5.10 `server/syslog_receiver.py` ve `snmp_trap_receiver.py`

**SyslogReceiver:**
```python
class _SyslogProtocol(asyncio.DatagramProtocol):
    def datagram_received(self, data, addr):
        msg = data.decode(errors="replace")
        log_normalizer.process_and_store(msg, source_host=addr[0])
```
Her UDP paketi → `log_normalizer` → `raw_logs` + `normalized_logs`

**SNMPTrapReceiver:** SNMP TRAP v2/v3 UDP alıcısı. Gelen TRAP'ları `normalized_logs`'a yazar.

---

### 5.11 `server/topology/builder.py`

**Topoloji Build Sırası:**
```
1. devices tablosu → tüm cihazlar topology_nodes'a
2. type="snmp" olan cihazlar için:
   a. _walk_arp()  → ARP table → IP eşleşmesi → "arp" edge
   b. _walk_lldp() → LLDP neighbors → "lldp" edge (ethernet)
3. Hiç edge yoksa:
   c. _subnet_edges() → aynı /24 subnet → "subnet" edge (zayıf)
```

**Not:** Her refresh tam yeniden inşa. Artımlı güncelleme yok.

---

### 5.12 `server/log_normalizer.py`

**Desteklenen Kaynaklar ve Tespit Mantığı:**

| Kaynak | Tespit Yöntemi | Çıktı event_type Örnekleri |
|---|---|---|
| Suricata EVE | JSON `event_type` alanı var | alert, dns, http, flow |
| Zeek | TSV format, tab-separated | conn, dns, http, notice |
| Wazuh | JSON `rule` + `agent` alanları | wazuh_alert, wazuh_syscheck |
| auth.log | "Failed password" / "Accepted" regex | ssh_failure, ssh_success, sudo_usage |
| Syslog (default) | Diğer her şey | syslog_generic |

**NTP Timestamp Validasyonu:**
Her normalize edilen loga şu tag'lar eklenebilir: `ntp_ok`, `too_far_past`, `too_far_future`

---

### 5.13 `server/notifier.py`

**Email (SMTP):**
```python
# Gmail için: SMTP_HOST=smtp.gmail.com, SMTP_PORT=587, App Password gerekli
msg = EmailMessage()
msg["From"] = SMTP_FROM
msg["To"] = SMTP_TO
```

**Discord Webhook:**
```json
{
  "embeds": [{
    "title": "NetGuard Alert",
    "color": 15158332,   // red for critical
    "fields": [{"name": "Severity", "value": "CRITICAL"}]
  }]
}
```

**Slack Webhook:**
```json
{
  "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": "..."}}]
}
```

---

## 6. API Endpoint Referansı

Base URL: `http://<server>:8000/api/v1`  
Dokümantasyon: `http://<server>:8000/docs` (Swagger UI)

### Auth
| Method | Path | Auth | Rate Limit | Açıklama |
|---|---|---|---|---|
| POST | /auth/login | None | 5/min | JWT token al |
| GET | /auth/me | JWT | - | Oturum bilgisi |
| POST | /auth/agent-key | JWT+Admin | - | Agent API key oluştur |

### Agents
| Method | Path | Auth | Açıklama |
|---|---|---|---|
| POST | /agents/register | API Key | Agent kaydı |
| POST | /agents/metrics | API Key | MetricSnapshot gönder |
| GET | /agents | JWT | Tüm agent listesi |
| GET | /agents/{id}/latest | JWT | Son snapshot |
| GET | /agents/{id}/history | JWT | Geçmiş (?limit=60) |
| GET | /agents/{id}/traffic | JWT | Trafik özeti |
| GET | /agents/{id}/processes | JWT | Süreç listesi |

### Devices
| Method | Path | Auth | Açıklama |
|---|---|---|---|
| GET | /devices | JWT | Tüm cihazlar (?device_type=) |
| GET | /devices/{id} | JWT | Tek cihaz detayı |

### SNMP
| Method | Path | Auth | Rate Limit | Açıklama |
|---|---|---|---|---|
| POST | /snmp/poll | JWT | 10/min | Anlık sorgulama |
| GET | /snmp/devices | JWT | - | Kayıtlı cihazlar |
| POST | /snmp/devices | JWT | - | Cihaz ekle |
| DELETE | /snmp/devices/{host} | JWT | - | Cihaz sil |

### Security
| Method | Path | Auth | Açıklama |
|---|---|---|---|
| GET | /security/events | JWT | Güvenlik olayları |
| GET | /security/events/summary | JWT | Tipe göre özet |
| POST | /security/scan | JWT | Manuel tarama tetikle |

### Correlation
| Method | Path | Auth | Açıklama |
|---|---|---|---|
| GET | /correlation/events | JWT | Korelasyon olayları |
| GET | /correlation/rules | JWT | Aktif kurallar |
| PUT | /correlation/rules | JWT+Admin | Kuralları güncelle |
| POST | /correlation/run | JWT | Manuel çalıştır |
| POST | /correlation/rules/reload | JWT+Admin | Kural dosyasını yenile |

### Discovery
| Method | Path | Auth | Açıklama |
|---|---|---|---|
| POST | /discovery/scan | JWT | Subnet taraması başlat |
| GET | /discovery/status | JWT | Tarama durumu |
| GET | /discovery/results | JWT | Keşfedilen cihazlar |

### Topology
| Method | Path | Auth | Açıklama |
|---|---|---|---|
| GET | /topology/graph | JWT | Node + Edge listesi |
| POST | /topology/refresh | JWT+Admin | Topoloji yeniden oluştur |

### Logs
| Method | Path | Auth | Açıklama |
|---|---|---|---|
| GET | /logs/normalized | JWT | Normalize loglar |
| GET | /logs/raw | JWT | Ham loglar |
| POST | /logs/ingest | JWT | Manuel log ekleme |

### Alerts
| Method | Path | Auth | Açıklama |
|---|---|---|---|
| GET | /alerts | JWT | Alert listesi (?status=active) |
| GET | /alerts/summary | JWT | Aktif/çözümlü özet |

### Reports
| Method | Path | Auth | Açıklama |
|---|---|---|---|
| GET | /reports/summary | JWT | JSON özet |
| GET | /reports/devices.csv | JWT | CSV indir |
| GET | /reports/alerts.csv | JWT | CSV indir |
| GET | /reports/security.csv | JWT | CSV indir |
| GET | /reports/topology.csv | JWT | CSV indir |

### WebSocket
| Protocol | Path | Auth | Açıklama |
|---|---|---|---|
| WS | /ws | JWT (query param) | Real-time metric/alert broadcast |

---

## 7. Veritabanı Şeması

### Tablo Listesi

| Tablo | Satır Tipi | Birincil Anahtar | Önemli Endeksler |
|---|---|---|---|
| alerts | Metrik alert | alert_id (UUID) | status, agent_id |
| security_events | Güvenlik olayı | event_id (UUID) | event_type, agent_id, occurred_at, source_ip |
| raw_logs | Ham log | raw_id (UUID) | normalized (bool), source_host, received_at |
| normalized_logs | Normalize log | log_id (UUID) | timestamp, source_type, category, src_ip, event_type |
| correlated_events | Korelasyon sonucu | corr_id (UUID) | (unique: rule_id+group_value+window dedup) |
| devices | Unified cihaz | device_id (TEXT) | type, status, ip |
| snmp_devices | Legacy SNMP | id (INT) | host (UNIQUE) |
| snmp_poll_history | SNMP sayaç tarihi | (host, if_index) | PRIMARY KEY |
| service_checks | Uptime sonucu | id (INT) | device_id, checked_at |
| topology_nodes | Topoloji düğümü | device_id (TEXT) | - |
| topology_edges | Topoloji kenarı | id (INT) | UNIQUE(src_id, dst_id, link_type) |
| api_keys | Agent auth | agent_id (TEXT) | - |

### Kritik Tablo: `devices`

```sql
CREATE TABLE devices (
    device_id       TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    ip              TEXT DEFAULT '',
    mac             TEXT DEFAULT '',
    type            TEXT NOT NULL DEFAULT 'discovered',
    -- type değerleri: agent | snmp | discovered | hybrid
    vendor          TEXT DEFAULT '',
    os_info         TEXT DEFAULT '',
    status          TEXT DEFAULT 'unknown',
    -- status değerleri: up | down | unknown
    first_seen      TEXT NOT NULL,    -- ISO 8601 UTC
    last_seen       TEXT,
    snmp_community  TEXT DEFAULT '',
    snmp_version    TEXT DEFAULT 'v2c',  -- v2c | v3
    -- v3 alanları (Faz 7 migration):
    snmp_v3_username      TEXT DEFAULT '',
    snmp_v3_auth_protocol TEXT DEFAULT 'SHA',  -- SHA | MD5
    snmp_v3_auth_key      TEXT DEFAULT '',
    snmp_v3_priv_protocol TEXT DEFAULT 'AES',  -- AES | DES
    snmp_v3_priv_key      TEXT DEFAULT '',
    risk_score      INTEGER DEFAULT 0,
    segment         TEXT DEFAULT '',
    notes           TEXT DEFAULT ''
);
```

### Kritik Tablo: `normalized_logs`

Bu tablo tüm güvenlik olaylarının birleşim noktasıdır. Correlator bu tabloyu sorgular.

```sql
CREATE TABLE normalized_logs (
    log_id       TEXT UNIQUE NOT NULL,
    raw_id       TEXT NOT NULL,          -- raw_logs'a FK
    source_type  TEXT NOT NULL,          -- suricata | zeek | wazuh | auth_log | syslog | netguard
    source_host  TEXT NOT NULL,
    timestamp    TEXT NOT NULL,          -- ISO 8601 UTC (indeksli)
    severity     TEXT NOT NULL,          -- info | warning | critical
    category     TEXT NOT NULL,          -- authentication | network | intrusion | system | unknown
    event_type   TEXT NOT NULL,          -- ssh_failure | port_scan_attempt | device_down | ...
    src_ip       TEXT,
    dst_ip       TEXT,
    src_port     INTEGER,
    dst_port     INTEGER,
    username     TEXT,
    message      TEXT NOT NULL,
    tags         TEXT NOT NULL DEFAULT '[]',  -- JSON array
    processed_at TEXT NOT NULL
);
```

### `normalized_logs` Event Type Kataloğu

| event_type | Kaynak | Açıklama |
|---|---|---|
| ssh_failure | auth_log | Başarısız SSH girişi |
| ssh_success | auth_log | Başarılı SSH girişi |
| sudo_usage | auth_log | sudo komutu kullanımı |
| brute_force | auth_log | 5 dakikada 5+ SSH hata |
| port_scan_attempt | detector | TCP SYN port tarama |
| arp_spoof_attempt | detector | MAC adres değişimi |
| icmp_flood | detector | ICMP flood tespiti |
| dns_anomaly | detector | Anormal DNS bağlantı |
| device_down | uptime | Cihaz erişilemiyor |
| device_up | uptime | Cihaz tekrar erişilir |
| snmp_trap | trap_receiver | SNMP TRAP alındı |
| syslog_generic | syslog | Genel syslog mesajı |

---

## 8. Veri Akışları

### 8.1 Agent → Server Metrik Akışı

```
Agent (her 10s):
  collect_snapshot() → MetricSnapshot (psutil verileri)
  traffic_collector.get_latest() → TrafficSummary ekle
  sender.send_snapshot() → POST /api/v1/agents/metrics

Server (agents.py router):
  1. storage.store_snapshot(snapshot) → RAM cache (360 kayıt)
  2. influx_writer.write_metrics(snapshot) → InfluxDB
  3. alert_engine.evaluate(snapshot) → list[Alert]
  4. for alert in alerts:
       db.save_alert(alert)
       notifier.notify(alert)
  5. ws_manager.broadcast("metric", snapshot) → WebSocket clients
```

### 8.2 Güvenlik Olayı Akışı (auth.log)

```
_security_scan_loop() (her 60s):
  parse_auth_log(agent_id) →
    for satır in son_500_satır:
      if SSH_FAILURE regex eşleşirse:
        SecurityEvent(SSH_FAILURE) → db.save_security_event()
        NormalizedLog(ssh_failure) → db.save_normalized_log()
        count_recent_failures() →
          if >= 5: SecurityEvent(BRUTE_FORCE) → db.save_security_event()
```

### 8.3 Korelasyon Akışı

```
_correlation_loop() (her 60s):
  correlator.run() →
    for kural in kurallar:
      SQL: SELECT src_ip, COUNT(*) FROM normalized_logs
           WHERE event_type LIKE 'ssh_failure%'
             AND timestamp >= now - 300s
           GROUP BY src_ip HAVING COUNT >= 5
      →
      CorrelatedEvent → db.save_correlated_event()
      (duplicate: aynı rule+group+window içinde tekrar kaydetme)
```

### 8.4 SNMP Discovery Akışı

```
POST /discovery/scan {cidr: "192.168.1.0/24", community: "public"}
  → asyncio.create_task(_run_scan())
  → GET /discovery/status (polling)

_run_scan():
  subnet_scanner.sweep("192.168.1.0/24") →
    asyncio: ping her IP → [{ip, rtt_ms}, ...]  (max 50 eşzamanlı)
  for ip in alive_ips:
    fingerprinter.fingerprint(ip) →
      - TCP port tarama (22, 80, 443, 161, 445, 3389, 8080, 8443)
      - Banner grab
      - SNMP sysDescr/sysName (community ile)
      - MAC → OUI vendor lookup
    → {"ip", "open_ports", "vendor", "sys_name", "os_hint"}
    db.save_device(...)  # type="discovered"

POST /topology/refresh (admin):
  topology_builder.build_topology() →
    1. get_devices() → upsert_topology_node() hepsi için
    2. snmp devices: _walk_arp() + _walk_lldp() → upsert_topology_edge()
    3. Hiç edge yoksa: _subnet_edges() → subnet fallback edges
```

### 8.5 Harici Syslog Akışı

```
Harici cihaz (router/switch/firewall):
  UDP → 192.168.203.134:5140

SyslogReceiver._SyslogProtocol.datagram_received():
  → log_normalizer.process_and_store(msg, addr[0])
  → raw_logs + normalized_logs DB'ye kaydedilir
  → Correlator tarafından pick-up edilir
```

---

## 9. Güvenlik Modeli

### 9.1 Kimlik Doğrulama Katmanları

```
Katman 1 — Dashboard kullanıcısı:
  JWT (HS256), 60 dakika ömür, Bearer token
  Roller: admin | viewer
  Şifreler: bcrypt hash, env değişkenlerinden alınır

Katman 2 — Agent:
  secrets.token_urlsafe(32) → API key
  DB'ye kaydedilir, constant-time compare (timing attack önlemi)
  X-API-Key header

Katman 3 — Rate Limiting:
  slowapi: 5/min login, 10/min SNMP poll
```

### 9.2 Secret Yönetimi

| Secret | Depolama | Notlar |
|---|---|---|
| JWT_SECRET_KEY | .env dosyası | Min 32 karakter önerilir |
| Admin/Viewer şifreleri | .env → bcrypt hash | Değiştirilebilir |
| Agent API keys | SQLite api_keys tablosu | Plaintext (iyileştirme gerekli) |
| SNMP v3 auth/priv keys | SQLite devices tablosu | API response'dan çıkarılıyor |
| SMTP şifresi | .env dosyası | Plaintext (iyileştirme gerekli) |

### 9.3 API Güvenliği

- **CORS:** Whitelist-based; env değişkeniyle dinamik konfigürasyon
- **v3 Key Masking:** `GET /snmp/devices` response'da `snmp_v3_auth_key` ve `snmp_v3_priv_key` çıkarılır
- **CSV Reports:** Auth gerektiriyor; v3 key'ler CSV'ye yazılmıyor
- **Input Validation:** Pydantic V2 — tüm request body'ler validate edilir

---

## 10. Frontend Mimarisi

### 10.1 Routing Yapısı

```
/ → redirect → /overview
/login → unauthenticated
/(protected)/* → JWT kontrol → layout.tsx → Sidebar + content
```

### 10.2 API İstemcisi (`lib/api.ts`)

Tüm HTTP çağrıları tek bir `request<T>()` fonksiyonundan geçer:
```typescript
async function request<T>(path, options?):
  - Authorization: Bearer <token from localStorage>
  - 401 → /login redirect
  - JSON parse
```

**API Grupları:**
```typescript
authApi.login()
agentsApi.list(), getLatestSnapshot(), getHistory()
alertsApi.list(), summary()
securityApi.listEvents(), summary(), triggerScan()
logsApi.listNormalized(), listRaw(), ingest()
devicesApi.list(), get()
discoveryApi.scan(), status(), results()
snmpApi.poll(SNMPPollParams), listDevices(), addDevice(), removeDevice()
topologyApi.getGraph(), refresh()
correlationApi.listEvents(), listRules(), updateRules(), run()
reportsApi.summary(), download(type)  // type: devices|alerts|security|topology
```

### 10.3 Real-Time Güncellemeler

```typescript
// hooks/useWebSocket.ts
ws = new WebSocket(`ws://server:8000/ws?token=<jwt>`)
ws.onmessage = ({data}) => {
  const msg = JSON.parse(data)  // {type: "metric" | "alert", data: {...}}
  if (msg.type === "metric") updateAgentSnapshot(msg.data)
  if (msg.type === "alert") addAlert(msg.data)
}
```

### 10.4 Data Fetching Stratejisi

React Query `refetchInterval` değerleri:
- Metrikler: 10s (agent push hızıyla senkron)
- Alertler: 15s
- Topoloji: 60s
- Security events: 30s
- Reports summary: 60s

### 10.5 Topoloji Haritası (ECharts)

```typescript
// topology/page.tsx + MiniTopology.tsx
// ECharts graph tipi, force layout
series: [{
  type: 'graph',
  layout: 'force',
  force: { repulsion: 80, gravity: 0.15, edgeLength: 60 },
  data: nodes.map(n => ({
    ...n,
    symbolSize: n.node_type === 'router' ? 16 : 10,
    itemStyle: { color: NODE_COLOR[n.node_type] }
  }))
}]
```

**Node Renk/Şekil Kodlaması:**
| Tip | Renk | Şekil |
|---|---|---|
| router | indigo (#6366f1) | diamond |
| switch | mavi (#3b82f6) | rect |
| server | yeşil (#10b981) | roundRect |
| agent | mor (#8b5cf6) | circle |
| snmp | cyan (#06b6d4) | circle |
| discovered | amber (#f59e0b) | triangle |
| unknown | gri (#71717a) | circle |

---

## 11. Agent Mimarisi

### 11.1 Agent Dosyaları

```
agent/
├── main.py           # Giriş, konfigürasyon, döngü
├── collector.py      # psutil → MetricSnapshot
├── sender.py         # HTTP POST → server
└── traffic_collector.py  # Ağ trafiği analizi
```

### 11.2 Collector (`agent/collector.py`)

**Hangi Metrikler Toplanıyor:**
```python
cpu:     psutil.cpu_percent(interval=1), getloadavg(), cpu_count(logical=False)
memory:  virtual_memory() → total/used/available bytes
disk:    disk_partitions() + disk_usage() → max MAX_DISK_ENTRIES (20)
network: net_io_counters(pernic=True) → bytes/packets sent/recv
         net_connections() → ConnectionStats (established/time_wait/listen)
         bandwidth: (current - prev) / elapsed  (delta hesaplaması)
process: process_iter(['pid','name','cpu_percent','memory_percent','status','username'])
         → top 10 by CPU + top 10 by memory
```

**Agent ID:** `uuid.UUID(int=uuid.getnode())` → MAC adresi bazlı, tekrarlanabilir.

### 11.3 Traffic Collector (`agent/traffic_collector.py`)

Arka plan thread'i, ağ trafiğini analiz eder:
- Protocol dağılımı: TCP / UDP / DNS
- Top source/destination IP'ler
- `suspicious_packet_count` (SYN flood belirtisi vb.)

### 11.4 Sender (`agent/sender.py`)

```python
# Başlangıçta:
POST /agents/register → AgentRegistration → device kaydı

# Her 10s:
POST /agents/metrics → MetricSnapshot → server işleme
```

Başarısız gönderimlerde retry yok — sadece log. Server geçici çevrimdışıysa metrikler kaybolur.

---

## 12. Test Altyapısı

### 12.1 Fixtures (`tests/conftest.py`)

```python
@pytest.fixture()
def tmp_db(tmp_path):
    """Her test için izole, geçici SQLite DB."""
    db = DatabaseManager(str(tmp_path / "test.db"))
    return db

@pytest.fixture()
def admin_token():
    """Rate limit'i tetiklemeden JWT üret."""
    return create_access_token(username="admin", role="admin")
```

**Önemli:** Test dosyalarında `from server.auth import create_access_token` kullanılır; `/auth/login` endpoint'i çağrılmaz (rate limit bypass).

### 12.2 Test Kapsamı

| Test Dosyası | Test Sayısı | Kapsadığı Alan |
|---|---|---|
| test_alert_engine | ~8 | Alert üretimi, duplicate önleme, resolve |
| test_auth | ~6 | Login, token, admin guard |
| test_snmpv3 | 14 | v3 auth builder, DB migration |
| test_cross_domain_correlation | 13 | Faz 5 entegrasyon testi |
| test_reports | 12 | CSV endpoint, auth, secret masking |
| test_correlation_routes | ~10 | Korelasyon API |
| test_detectors | ~12 | 4 dedektör |
| test_database | ~20 | CRUD operasyonları |
| test_snmp_routes | ~8 | SNMP API endpoint'leri |
| **Toplam** | **314** | |

### 12.3 Test Çalıştırma

```bash
cd /home/mehmet/netguard
pytest tests/ -q           # Tümü
pytest tests/ -v           # Verbose
pytest tests/test_snmpv3.py -v  # Tek modül
pytest tests/ -k "auth"   # Pattern ile filtre
```

---

## 13. Çevre Değişkenleri (Environment)

### Zorunlu

| Değişken | Açıklama |
|---|---|
| `JWT_SECRET_KEY` | JWT imzalama anahtarı (min 32 karakter) |

### Sunucu

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `NETGUARD_DB_PATH` | `netguard.db` | SQLite dosya yolu |
| `NETGUARD_CORS_ORIGINS` | localhost:3000 + VM IP'ler | CORS whitelist (virgülle ayrılmış) |
| `AGENT_ID` | hostname | Server tarafı güvenlik taraması için |

### Döngü Aralıkları (saniye)

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `SECURITY_SCAN_INTERVAL` | 60 | auth.log + port + config scan |
| `NETGUARD_NTP_CHECK_INTERVAL` | 300 | NTP saat kontrolü |
| `NETGUARD_CORR_INTERVAL` | 60 | Korelasyon döngüsü |
| `NETGUARD_DETECTOR_INTERVAL` | 30 | Dedektör döngüsü |
| `NETGUARD_SNMP_INTERVAL` | 60 | SNMP polling |
| `NETGUARD_UPTIME_INTERVAL` | 60 | Uptime check |

### Dedektör Eşikleri

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `NETGUARD_PORTSCAN_THRESHOLD` | 15 | Saniyede port sayısı |
| `NETGUARD_PORTSCAN_WINDOW` | 60 | Tarama penceresi (saniye) |
| `NETGUARD_ICMP_THRESHOLD` | 100 | ICMP paket/s eşiği |
| `NETGUARD_DNS_THRESHOLD` | 30 | DNS bağlantı sayısı |

### NTP

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `NTP_SERVER` | pool.ntp.org | NTP sunucu adresi |
| `SYSTEM_CLOCK_WARN` | 5 | Saniye sapma uyarı eşiği |
| `SYSTEM_CLOCK_CRIT` | 60 | Saniye sapma kritik eşiği |
| `LOG_TS_MAX_PAST` | 3600 | Log timestamp geçmişe sapma (saniye) |
| `LOG_TS_MAX_FUTURE` | 60 | Log timestamp geleceğe sapma (saniye) |

### Bildirim

| Değişken | Açıklama |
|---|---|
| `SMTP_HOST` | SMTP sunucu |
| `SMTP_PORT` | SMTP port (587 TLS) |
| `SMTP_USER` | SMTP kullanıcı adı |
| `SMTP_PASSWORD` | SMTP şifresi |
| `SMTP_FROM` | Gönderen adres |
| `SMTP_TO` | Alıcı adres |
| `WEBHOOK_URL` | Discord/Slack webhook URL'i |
| `WEBHOOK_TYPE` | discord veya slack |

### Auth

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `ADMIN_USERNAME` | admin | Admin kullanıcı adı |
| `ADMIN_PASSWORD` | netguard123 | Admin şifresi (mutlaka değiştirin) |
| `VIEWER_USERNAME` | viewer | Viewer kullanıcı adı |
| `VIEWER_PASSWORD` | view123 | Viewer şifresi |
| `JWT_EXPIRE_MINUTES` | 60 | Token ömrü |

### Agent (agent/main.py)

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `NETGUARD_SERVER_URL` | http://localhost:8000 | Server adresi |
| `NETGUARD_SEND_INTERVAL` | 10 | Gönderim aralığı (saniye) |
| `NETGUARD_ENABLE_TRAFFIC` | true | Traffic collector aktif/pasif |

---

## 14. Bağımlılıklar ve Kütüphaneler

### Python (`requirements.txt`)

**Core Framework:**
- `fastapi==0.115.0` — REST + WebSocket framework
- `uvicorn[standard]` — ASGI sunucu (uvloop + http-tools ile standard profil)
- `pydantic==2.8.2` — Veri modelleme ve validation
- `starlette==0.38.6` — FastAPI alt yapısı, middleware

**Güvenlik:**
- `python-jose==3.5.0` — JWT oluşturma (RS256/HS256 desteği var ama HS256 kullanılıyor)
- `bcrypt==4.0.1` — Parola hash (argon2 değil, orta güvenlik seviyesi)
- `passlib==1.7.4` — bcrypt wrapper
- `cryptography==46.0.6` — jose bağımlılığı

**Ağ/SNMP:**
- `pysnmp==7.1.22` — SNMP v2c + v3 asyncio, USM, TRAP alıcısı
- `pyshark==0.6` — tshark Python wrapper (port scan dedektörü)
- `httpx==0.27.2` — Async HTTP client (uptime checker)

**Sistem Metrikleri:**
- `psutil==6.0.0` — CPU, RAM, disk, ağ, süreç metrikleri

**Veritabanı:**
- `influxdb-client==1.50.0` — InfluxDB v2 Python client

**Yardımcı:**
- `python-dotenv==1.0.1` — .env dosyası desteği
- `ntplib==0.4.0` — NTP UDP sorgusu
- `slowapi==0.1.9` — FastAPI rate limiting
- `limits==5.8.0` — slowapi bağımlılığı (Redis de destekler, şu an in-memory)

**Notlar:**
- `pyshark` tshark gerektirir: `sudo apt-get install tshark`
- `pysnmp 7.x` — breaking changes var 6.x'e göre; usmHMACMD5AuthProtocol `pysnmp.hlapi.asyncio`'dan import edilmeli

### Node.js (`dashboard-v2/package.json`)

**Üretim:**
- `next@16.2.3` — Turbopack dahil
- `react@19.2.4` — Yeni features (Suspense, Server Components)
- `echarts@^6.0.0` — Topoloji ve grafik
- `@tanstack/react-query@^5.99.0` — API state yönetimi
- `zustand@^5.0.12` — Global state
- `shadcn@^4.2.0` — Bileşen kütüphanesi (Radix UI tabanlı)
- `tailwindcss@^4` — Utility CSS
- `lucide-react@^1.8.0` — İkon seti
- `axios@^1.15.0` — HTTP client (api.ts'de fetch de kullanılıyor)
- `zod@^4.3.6` — Schema validation

---

## 15. Bilinen Sınırlamalar ve Geliştirme Fırsatları

### Kritik Eksikler (Üretim Öncesi)

| # | Sorun | Etki | Çözüm |
|---|---|---|---|
| 1 | SNMP poll loop v3 parametrelerini kullanmıyor | v3 cihazlar community ile sorgulanıyor | `_snmp_poll_loop`'u `devices` tablosundan okuyacak şekilde güncelle |
| 2 | Agent API key'leri plaintext DB'de | Güvenlik riski | Hash'leyerek sakla (bcrypt/SHA256) |
| 3 | Kullanıcı tablosu hardcoded | Üretimde sorun | SQLite `users` tablosuna taşı |
| 4 | JWT refresh token yok | Sık logout | Refresh token endpoint ekle |
| 5 | Auth.log okuma her 60s tüm son 500 satırı işliyor | Duplicate event riski | Son okunan pozisyonu (`inode + offset`) takip et |
| 6 | `correlation_rules.json` sadece 1 test kuralı | Korelasyon pasif | Gerçek kurallar ekle |
| 7 | `tshark` root veya wireshark grubunda çalışıyor | PortScanDetector üretime hazır değil | Alternatif: eBPF veya iptables LOG |
| 8 | Log retention yok | SQLite şişer | Periyodik cleanup veya archive |

### Mimari Geliştirme Fırsatları

| # | Geliştirme | Açıklama |
|---|---|---|
| 1 | Alert kural JSON konfigürasyonu | Alert Engine'i de Correlator gibi JSON rule tabanlı yap |
| 2 | InfluxDB dashboard | Grafana entegrasyonu (datasource var) |
| 3 | Agent güncelleme mekanizması | Sürüm kontrolü, otomatik güncelleme |
| 4 | Multi-tenancy | Kullanıcı başına cihaz izolasyonu |
| 5 | SNMP v3 discovery | Discovery sırasında v3 deneme |
| 6 | LDAP/SAML auth | Kurumsal auth entegrasyonu |
| 7 | Kafka/Redis queue | Yüksek log hacmi için asenkron pipeline |
| 8 | Sertifika tabanlı agent auth | TLS mutual auth (mTLS) |

### Ölçek Sınırları

Mevcut mimariyle pratik üst sınırlar:

| Bileşen | Pratik Limit | Neden |
|---|---|---|
| Agent sayısı | ~50 | RAM cache her agent için 360 snapshot |
| SNMP cihaz sayısı | ~100 | 60s'de paralel poll (asyncio) |
| normalized_logs tablosu | ~1M satır | SQLite'ın makul limiti |
| WebSocket client | ~20 | Sync broadcast (asyncio ile artırılabilir) |
| Topoloji node | ~200 | ECharts force-layout performansı |

---

*Bu doküman NetGuard v0.1.0 kaynak kodundan üretilmiştir. Güncel tut: her Faz tamamlandığında ilgili bölümleri revize et.*
