# NetGuard

**Unified Network Intelligence Platform** — NMS (Network Management System) ve CSNM (Continuous Network Security Monitoring) birleşimi.

Her ağ olayını hem performans hem güvenlik boyutuyla anlayan, topoloji üzerinde birleştiren ve çapraz korelasyon yapan bütünleşik izleme platformu.

---

## Ürün Vizyonu

Geleneksel araçlar iki ayrı dünyada çalışır: NMS araçları "Ağım sağlıklı mı?" sorusunu yanıtlar, güvenlik araçları "Ağım güvende mi?" sorusunu yanıtlar. NetGuard bu iki soruyu tek bir soruda birleştirir:

> **"Ağımda şu an ne oluyor — ve bu bir performans problemi mi, güvenlik tehdidi mi, yoksa her ikisi mi?"**

---

## Mimari

```
┌──────────────────────────────────────────────────────────────┐
│                    VERİ TOPLAMA KATMANI                      │
│  Agent(psutil) │ SNMP(v2c/v3) │ TRAP(UDP:162) │ ICMP/TCP   │
│  Syslog(UDP:5140) │ pyshark(paket yakalama) │ Auto-Discovery│
└───────────────────────────┬──────────────────────────────────┘
                            ▼
┌──────────────────────────────────────────────────────────────┐
│                 UNIFIED EVENT PIPELINE                       │
│  Her kaynak → tek formata dönüşür                           │
│  Her event: device_id + performans boyutu + güvenlik boyutu │
└───────────────────────────┬──────────────────────────────────┘
                            ▼
┌──────────────────────────────────────────────────────────────┐
│               INTELLIGENCE ENGINE                            │
│  Cross-Domain Correlator  │  Topology Engine                │
│  Incident Engine          │  Alert Engine v2                │
└───────────────────────────┬──────────────────────────────────┘
                            ▼
┌──────────────────────────────────────────────────────────────┐
│              NEXT.JS DASHBOARD                               │
│  Network Command Center (topoloji haritası + canlı events)  │
│  Device 360° │ Incident Center │ Security Intel │ Discovery  │
└──────────────────────────────────────────────────────────────┘
```

---

## Özellikler

### Tamamlanan
- **Agent İzleme** — CPU, RAM, disk, network, process metrikleri (psutil)
- **SNMP Polling** — Router, switch, ağ cihazları (SNMPv2c, asyncio)
- **Paket Analizi** — TCP SYN tabanlı port tarama tespiti (pyshark)
- **Saldırı Dedektörleri** — Port tarama, ARP spoofing, ICMP flood, DNS anomalisi
- **Güvenlik Log Analizi** — auth.log brute force, SSH başarısız giriş, sudo takibi
- **Korelasyon Motoru** — JSON tabanlı kurallar, zaman penceresi korelasyonu
- **Syslog Toplayıcı** — UDP 5140, Suricata/Zeek/Wazuh/auth.log normalize
- **Alert Motoru** — Eşik tabanlı, deduplication, otomatik resolve
- **NTP Doğrulama** — Sistem saati sapma tespiti
- **JWT + API Key Auth** — Kullanıcı dashboard erişimi + agent kimlik doğrulama
- **Dashboard** — Next.js 16, React 19, TanStack Query, Zustand, ECharts

### Geliştirme Yol Haritası (8 Faz)

| Faz | Konu | Durum |
|-----|------|-------|
| 0 | Zemin Temizleme (kritik bug düzeltmeleri) | 🔄 Devam ediyor |
| 1 | Unified Device Model | ⏳ Bekliyor |
| 2 | NMS Çekirdeği (SNMP v2, GETBULK, uptime, TRAP) | ⏳ Bekliyor |
| 3 | Auto-Discovery (subnet sweep, vendor tespiti) | ⏳ Bekliyor |
| 4 | Topology Engine (L2/L3 harita) | ⏳ Bekliyor |
| 5 | Cross-Domain Correlation | ⏳ Bekliyor |
| 6 | Frontend Dönüşümü (topology-first) | ⏳ Bekliyor |
| 7 | SNMPv3 + Security Hardening | ⏳ Bekliyor |
| 8 | Raporlama + Polish | ⏳ Bekliyor |

---

## Teknoloji Yığını

### Backend
- **Python 3.12** + **FastAPI** (ASGI, async)
- **SQLite** (WAL modu) — olaylar, cihazlar, topoloji
- **InfluxDB** — zaman serisi metrikler
- **pysnmp** — SNMP v2c/v3
- **pyshark** — paket yakalama (tshark)
- **psutil** — sistem metrikleri
- **python-jose** + **bcrypt** — JWT auth

### Frontend
- **Next.js 16** + **React 19** (App Router)
- **TypeScript**
- **TanStack Query v5** — server state
- **Zustand v5** — global state
- **ECharts** — grafikler ve topoloji haritası
- **shadcn/ui** + **Tailwind CSS v4**

### İletişim
- **REST API** (`/api/v1/`)
- **WebSocket** (`/ws`) — gerçek zamanlı metrik ve alert akışı
- **UDP 5140** — Syslog alıcı
- **UDP 162** — SNMP TRAP alıcı (Faz 2)

---

## Proje Yapısı

```
netguard/
├── agent/              # İzlenen makinelerde çalışan veri toplayıcı
│   ├── collector.py    # psutil ile sistem metrikleri
│   ├── traffic_collector.py  # pyshark paket analizi
│   ├── snmp_collector.py     # SNMP GET sorguları
│   └── sender.py       # HTTP ile server'a gönderim
├── server/             # Merkezi işleme ve API
│   ├── main.py         # FastAPI uygulaması + async döngüler
│   ├── database.py     # SQLite katmanı (WAL modu)
│   ├── alert_engine.py # Eşik tabanlı alert üretimi
│   ├── correlator.py   # Log korelasyon motoru
│   ├── detectors/      # Ağ saldırı dedektörleri
│   ├── routes/         # REST API endpoint'leri
│   └── ...
├── dashboard-v2/       # Next.js frontend
│   └── src/app/        # App Router sayfaları
├── shared/             # Ortak modeller ve protokol
├── config/             # Korelasyon kuralları (JSON)
├── tests/              # pytest test dosyaları
└── scripts/            # Kurulum scriptleri
```

---

## Kurulum

### Gereksinimler
- Python 3.12+
- Node.js 18+
- tshark (pyshark için)
- InfluxDB (opsiyonel)

### Backend
```bash
pip install -r requirements.txt
cp .env.example .env   # .env dosyasını düzenle
uvicorn server.main:app --reload
```

### Frontend
```bash
cd dashboard-v2
npm install
npm run dev
```

### .env Değişkenleri
```env
JWT_SECRET_KEY=          # Zorunlu — rastgele güçlü bir değer
ADMIN_PASSWORD=          # Dashboard admin şifresi
VIEWER_PASSWORD=         # Dashboard viewer şifresi
NETGUARD_INTERFACE=ens33 # Paket yakalama arayüzü
NETGUARD_CORS_ORIGINS=http://localhost:3000
INFLUXDB_TOKEN=          # InfluxDB (opsiyonel)
```

---

## Test

```bash
pytest tests/ -v
```

170+ test, tümü geçiyor.

---

## Geliştirici

**Mehmet Çapar** — Sakarya Üniversitesi, Bilgisayar Mühendisliği  
Danışman: Prof. Dr. İbrahim ÖZÇELİK
