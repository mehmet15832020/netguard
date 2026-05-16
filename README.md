# NetGuard

**Orta ölçekli şirketler için açık kaynak ağ güvenlik izleme platformu (NSM/NDR-lite).**

> Splunk $50.000/yıl. QRadar $30.000/yıl. NetGuard: açık kaynak, Docker ile 30 dakikada kurulum.

NetGuard; ağ trafiğini ve host loglarını Syslog, NetFlow, SNMP, Zeek, Agent ve EVTX kaynaklarından toplar. Paylı tespit motoru (pySigma v2 + JSON korelasyon + ML anomaly), 5 aşamalı kill chain analizi ve MITRE ATT&CK eşlemesiyle tehditleri tespit eder. Kritik saldırıları OPNsense ve VyOS üzerinden otomatik veya manuel olarak engeller.

**Hedef kitle:** 50–500 çalışanlı, kurumsal SIEM bütçesi olmayan şirketlerin IT/güvenlik yöneticileri.

---

## Neler Yapar?

```
COLLECT            DETECT                       RESPOND
───────            ──────                       ───────
Syslog             pySigma v2 (30+ kural)       Incident yönetimi
NetFlow v5/v9      JSON korelasyon motoru        Kill chain timeline
SNMP v2c/v3        5 aşamalı kill chain          Email + webhook
Zeek TAP           IsolationForest anomaly       OPNsense REST blok
Agent (psutil)     MITRE ATT&CK eşleme           VyOS SSH fallback
EVTX (Windows)     Threat intel (AbuseIPDB)      Audit log
pyshark (SYN)      ARP/DNS/ICMP/lateral det.     Progressive TTL
```

---

## Özellikler

### Veri Toplama

| Kaynak | Protokol | Toplanan Veri |
|--------|----------|---------------|
| Linux/Windows Agent | HTTP API | CPU, RAM, disk, ağ, process snapshot |
| SNMP v2c/v3 | UDP 161 | Interface istatistikleri, uptime, ARP/LLDP |
| SNMP TRAP | UDP 162 | Anlık cihaz event'leri |
| Syslog | UDP 5140 | OPNsense, VyOS, pfSense, Cisco ASA, FortiGate |
| NetFlow v5/v9 | UDP 2055 | Trafik akış analizi (IP, port, byte) |
| Zeek TAP | Log dosyası | DNS, HTTP, SSL/TLS, SSH, Conn, x509, SMTP, FTP |
| Windows EVTX | HTTP API | EventID 4624/4625/4688 (giriş, process) |
| Web log | Syslog | nginx access/error; SQLi, path traversal tespiti |
| pyshark | Paket | TCP SYN tabanlı gerçek zamanlı port tarama |

### Tespit

**pySigma v2 (30+ kural — `config/sigma_rules_v2/`):**

| Kural Grubu | İçerik |
|-------------|--------|
| `ssh_brute_force` | SSH başarısız giriş spike'ı |
| `auth_and_web` | Web tarama, SQL injection, başarılı SSH |
| `windows_events` | Brute force, pass-the-hash, password spray, şüpheli process, lateral movement |
| `port_scan` | TCP SYN tarama |
| `network_community` | ARP spoof, ICMP flood, DNS burst, DNS tüneli (TXT sorgu) |
| `c2_and_exfil` | C2 iletişimi, veri sızdırma kalıpları |
| `zeek_advanced` | JA3/TLS parmak izi, x509 anomaly, SMTP/FTP şüpheli davranış |
| `web_attacks` | Path traversal, command injection, XSS pattern |
| `sql_injection` | SQL injection kalıpları |
| `anomaly_and_impact` | Anomaly spike, darbe tespiti |
| `device_and_snmp` | Cihaz kesintisi, SNMP trap patlaması |

**5 Aşamalı Kill Chain:**

| Aşama | Tetikleyiciler |
|-------|---------------|
| RECON | port_scan, dns_anomaly, web_scan, multi_source_attack |
| WEAPONIZE | ssh_failure, windows_logon_failure, brute_force |
| ACCESS | ssh_success, windows_logon_success |
| EXECUTE | sudo_usage, windows_process_create |
| LATERAL | lateral_movement, windows_lateral |

4+ aşama → `FULL_ATTACK_CHAIN` → critical incident + email/webhook + (opsiyonel) otomatik IP bloğu.

**ML Anomaly Detection:**
- Welford online baseline (per-IP, saatlik güncelleme)
- Isolation Forest (çok boyutlu, scikit-learn)
- 5 dakikalık döngü, `anomaly_spike` event'i üretir

**Ağ Dedektörleri (pyshark tabanlı):**
- Port scan (TCP SYN), ARP spoofing, ICMP flood, DNS sorgu patlaması, lateral movement (iç→iç SSH/SMB/RDP)

**MITRE ATT&CK:** Her tespit olayı otomatik olarak ATT&CK taktik ve tekniklerine eşlenir.

**Tehdit İstihbaratı:** Şüpheli IP'ler AbuseIPDB'ye sorgulanır; risk skoru ≥ 70 → incident severity `critical`'e yükseltilir.

**Network Intelligence:** JA3/JA4 TLS parmak izi, x509 sertifika analizi, SMTP/FTP oturum tespiti; `/network/intelligence` sayfasında görselleştirilir.

### Aktif Yanıt (P1–P8)

Kill chain tespitinde veya manuel olarak IP engelleyebilir:

- **OPNsense REST API** → alias tabanlı firewall kuralı (`NETGUARD_BLOCK` alias)
- **VyOS SSH fallback** → OPNsense ulaşılamazsa paramiko ile kural push
- **Güvenlik geçitleri (bu sıra değişmez):** RFC1918 koruması → false positive gate → severity eşiği → duplicate kontrolü
- **Progressive TTL:** 1. ihlal 1s, 2. 4s, 3. 24s, 4.+ 168s (Wazuh `repeated_offenders` eşdeğeri)
- **Break-glass:** `BREAK_GLASS_TOKEN` env ile JWT bypass, acil unblock
- **Blok doğrulama:** Firewall'da gerçekten bloklu mu? Orphan/phantom tespiti
- **Port/protocol granülaritesi:** Tüm IP yerine belirli port+protokol bloklanabilir
- **Audit log:** Tüm aktif yanıt işlemleri actor/reason ile kayıt altında

### Platform

- **Auth:** JWT access (60 dk) + refresh (7 gün) + API key (SHA-256); token tipi karıştırma engeli
- **Rate limiting:** Login 5/dk, refresh 10/dk; slowapi
- **Compliance API:** PCI DSS v4.0 ve ISO 27001:2022 kontrol eşlemesi; JSON export
- **Audit log:** Tüm admin işlemleri (giriş, kural değiştirme, incident güncelleme, blok)
- **Log retention:** Hot (30–365 gün) → Warm (JSON.gz arşiv, 1 yıl); yapılandırılabilir
- **WebSocket:** Gerçek zamanlı alert ve metrik akışı
- **Alembic:** Veritabanı şema migration yönetimi

### Dashboard (20+ Sayfa)

Overview · Logs · Incidents · Aktif Bloklar · Alerts · Agents · Correlation · Network Intelligence · MITRE ATT&CK · Timeline · Topology · Devices/SNMP/Discovery · Settings/Audit · Reports/Security/Compliance

---

## Hızlı Başlangıç

### Gereksinimler

- Docker + Docker Compose v2
- 4 GB RAM, 20 GB disk
- Linux host önerilen (pyshark için `NET_RAW` capability)

### 3 Adımda Kurulum

```bash
git clone https://github.com/mehmetcapar/netguard.git
cd netguard
cp .env.example .env
```

`.env` dosyasını düzenle — minimum zorunlu alanlar:

```env
JWT_SECRET_KEY=<buraya-rastgele-string>   # openssl rand -hex 32
ADMIN_PASSWORD=<güçlü-şifre>
POSTGRES_PASSWORD=<db-şifresi>
INFLUXDB_TOKEN=<influx-token>
INFLUXDB_ADMIN_PASSWORD=<influx-admin-şifresi>
INFLUXDB_ORG=netguard
INFLUXDB_BUCKET=netguard
NETGUARD_HOST=localhost                   # veya sunucu IP'si
ZEEK_INTERFACE=eth0                       # izlenecek ağ arayüzü
```

```bash
docker compose up -d
```

Dashboard: `https://localhost` · API Dokümantasyonu: `https://localhost/api/v1/docs`

İlk açılışta self-signed sertifika uyarısı çıkar — geliştirme ortamında güvenle geçilebilir.

---

## Kurulum — Manuel

### Sistem Gereksinimleri

```bash
# Ubuntu 22.04 / 24.04
sudo apt install python3.12 python3.12-venv nodejs npm tshark snmp
sudo usermod -aG wireshark $USER   # pyshark için — logout/login gerekir
```

### PostgreSQL + TimescaleDB

```bash
# TimescaleDB kurulum (Ubuntu)
sudo apt install -y postgresql-16
sudo -u postgres psql -c "CREATE DATABASE netguard; CREATE USER netguard WITH PASSWORD 'şifre'; GRANT ALL ON DATABASE netguard TO netguard;"
# TimescaleDB extension kurulum: https://docs.timescale.com/self-hosted/latest/install/
```

### Backend

```bash
cd netguard
python3.12 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# .env dosyasını düzenle

# Veritabanı şemasını oluştur
DATABASE_URL="postgresql://netguard:şifre@localhost:5432/netguard" alembic upgrade head

# Sunucuyu başlat
uvicorn server.main:app --host 0.0.0.0 --port 8000
```

### Frontend

```bash
cd dashboard-v2
npm install
npm run build
npm start          # production
# veya: npm run dev   # geliştirme
```

### Agent (İzlenecek Makine)

```bash
scp -r agent/ user@192.168.x.x:~/netguard-agent/
ssh user@192.168.x.x "cd ~/netguard-agent && pip install psutil httpx python-dotenv"

# .env oluştur
cat > ~/netguard-agent/.env << EOF
NETGUARD_SERVER=http://192.168.203.134:8000
AGENT_API_KEY=<dashboard Agents sayfasından alınan key>
EOF

python main.py
```

### Zeek (Opsiyonel — Network Intelligence için)

```bash
# Zeek LTS kurulum: https://docs.zeek.org/en/master/install.html
zeek -i eth0 /usr/local/zeek/share/zeek/site/local.zeek

# NetGuard'a Zeek log dizinini belirt:
ZEEK_LOG_DIR=/var/log/zeek/current   # .env'e ekle
```

---

## Yapılandırma

### Zorunlu

| Değişken | Açıklama |
|----------|---------|
| `JWT_SECRET_KEY` | JWT imzalama anahtarı — `openssl rand -hex 32` |
| `ADMIN_PASSWORD` | Dashboard admin şifresi |
| `DATABASE_URL` | PostgreSQL bağlantı URL'si |
| `POSTGRES_PASSWORD` | PostgreSQL şifresi |
| `INFLUXDB_TOKEN` | InfluxDB API token |
| `INFLUXDB_ADMIN_PASSWORD` | InfluxDB admin şifresi |
| `INFLUXDB_ORG` | InfluxDB organizasyon adı |
| `INFLUXDB_BUCKET` | InfluxDB bucket adı |

### Ağ

| Değişken | Varsayılan | Açıklama |
|----------|-----------|---------|
| `NETGUARD_INTERFACE` | `eth0` | pyshark paket yakalama arayüzü |
| `ZEEK_INTERFACE` | `vmnet8` | Zeek izleme arayüzü (Docker) |
| `ZEEK_LOG_DIR` | `/zeek-logs` | Zeek log dizini |
| `NETGUARD_CORS_ORIGINS` | `https://localhost` | Frontend URL'leri (virgülle ayrılmış) |
| `NETGUARD_HOST` | `localhost` | Sunucu IP/hostname (nginx + WebSocket için) |
| `SYSLOG_PORT` | `5140` | Syslog UDP port |
| `NETFLOW_PORT` | `2055` | NetFlow UDP port |

### Aktif Yanıt

| Değişken | Açıklama |
|----------|---------|
| `OPNSENSE_HOST` | OPNsense IP adresi |
| `OPNSENSE_KEY` | OPNsense API key |
| `OPNSENSE_SECRET` | OPNsense API secret |
| `OPNSENSE_BLOCK_ALIAS` | Firewall alias adı (`NETGUARD_BLOCK`) |
| `VYOS_HOST` | VyOS SSH adresi |
| `VYOS_USER` | VyOS SSH kullanıcısı |
| `VYOS_KEY_PATH` | VyOS SSH özel anahtar yolu |
| `VYOS_FW_NAME` | VyOS firewall kural adı (`BLOCK-LIST`) |
| `PROTECTED_CIDRS` | Hiçbir zaman engellenmeyecek IP'ler |
| `BLOCK_MIN_SEVERITY` | Minimum severity eşiği (`high`) |
| `BLOCK_PROGRESSIVE_TTL` | Progressive TTL değerleri saat cinsinden (`1,4,24,168`) |
| `BREAK_GLASS_TOKEN` | Acil unblock token — `openssl rand -hex 32` |
| `AUTO_BLOCK_ON_FULL_CHAIN` | `1` → FULL_ATTACK_CHAIN'de otomatik blok (varsayılan `0`) |

### Bildirim

| Değişken | Açıklama |
|----------|---------|
| `SMTP_HOST` | SMTP sunucu adresi |
| `SMTP_PORT` | SMTP port (genellikle `587`) |
| `SMTP_USER` | SMTP kullanıcı adı |
| `SMTP_PASSWORD` | SMTP şifresi |
| `SMTP_TO` | Bildirim e-posta adresi |
| `WEBHOOK_URL` | Discord veya Slack webhook URL |

### Tehdit İstihbaratı

| Değişken | Açıklama |
|----------|---------|
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key ([ücretsiz](https://www.abuseipdb.com/api)) |

---

## Sigma Kuralı Ekleme

NetGuard, standart SIGMA formatını destekler. Kural eklemek için kod değişikliği gerekmez:

```yaml
# config/sigma_rules_v2/ornek.yml
title: Örnek Kural
name: ornek_kural
status: stable
logsource:
    category: network
detection:
    keywords:
        event_action:
            - 'ssh_failure'
    condition: keywords
    timeframe: 5m
    count: 10
    groupby: source_ip
level: high
```

```bash
# Doğrulama
curl -X POST https://localhost/api/v1/sigma/validate \
     -H "Authorization: Bearer $TOKEN" \
     -F "file=@ornek.yml"
```

---

## JSON Korelasyon Kuralı Ekleme

`config/correlation_rules.json` dosyasına sunucu yeniden başlatılmadan kural eklenebilir:

```json
{
  "id": "ornek_kural",
  "name": "Örnek Korelasyon",
  "event_types": ["ssh_failure", "port_scan_attempt"],
  "threshold": 3,
  "window_seconds": 300,
  "severity": "high",
  "kill_chain_stage": "RECON"
}
```

---

## Ağ Konfigürasyonu

### Syslog Yönlendirme

**OPNsense:** System → Log Files → Settings → Remote Logging → `192.168.x.x:5140`

**VyOS:**
```bash
set system syslog host 192.168.203.134 facility all level info
set system syslog host 192.168.203.134 port 5140
commit && save
```

**NetFlow (VyOS):**
```bash
set system flow-accounting interface eth0
set system flow-accounting netflow server 192.168.203.134 port 2055
set system flow-accounting netflow version 9
commit && save
```

### SNMP Ekleme

```bash
curl -X POST https://localhost/api/v1/snmp/devices \
     -H "Authorization: Bearer $TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"ip": "10.0.30.2", "community": "public", "version": "v2c"}'
```

---

## Teknoloji Yığını

### Backend

| Teknoloji | Sürüm | Kullanım |
|-----------|-------|---------|
| Python | 3.12 | Runtime |
| FastAPI | 0.115 | ASGI API sunucusu |
| PostgreSQL | 16 | İlişkisel veri (log, incident, cihaz) |
| TimescaleDB | latest | Zaman serisi optimizasyonu normalized_logs için |
| InfluxDB | 2.7 | SNMP/agent metrik zaman serileri |
| Zeek | LTS | Ağ trafiği analizi (DNS, HTTP, SSL, x509) |
| pySigma | 1.3.3 | SIGMA kural motoru |
| scikit-learn | ≥1.5 | Isolation Forest anomaly detection |
| pyshark | 0.6 | TCP SYN paket analizi |
| pysnmp | 7.1 | SNMP v2c/v3 polling ve trap |
| paramiko | ≥3.0 | VyOS SSH aktif yanıt |
| psycopg | ≥3.2 | PostgreSQL async sürücüsü |
| Alembic | ≥1.13 | DB şema migration |
| slowapi | 0.1.9 | Rate limiting |

### Frontend

| Teknoloji | Sürüm | Kullanım |
|-----------|-------|---------|
| Next.js | 14 | App Router, SSR |
| TypeScript | — | Tip güvenliği |
| TanStack Query | v5 | Server state ve önbellekleme |
| Zustand | v5 | Global UI state |
| ECharts | — | Topoloji haritası, grafikler |
| shadcn/ui + Tailwind | — | UI bileşenleri |

### Altyapı

| Bileşen | Kullanım |
|---------|---------|
| nginx | TLS reverse proxy, WebSocket proxy |
| Docker Compose | Tek komut deployment |
| Alembic | Veritabanı migration |

### Portlar

| Port | Protokol | Hizmet |
|------|----------|--------|
| 443 | TCP/HTTPS | Dashboard + API (nginx) |
| 80 | TCP/HTTP | HTTPS yönlendirme |
| 8000 | TCP | FastAPI (dahili) |
| 5140 | UDP | Syslog alıcı |
| 2055 | UDP | NetFlow alıcı |
| 161 | UDP | SNMP polling (giden) |
| 162 | UDP | SNMP TRAP alıcı |

---

## Proje Yapısı

```
netguard/
├── agent/                     # İzlenen makinelerde çalışan agent (psutil)
├── server/
│   ├── main.py                # FastAPI app, async döngüler, startup
│   ├── database.py            # DB factory (PG prod / SQLite test)
│   ├── database_pg.py         # PostgreSQL + TimescaleDB implementasyonu
│   ├── auth.py                # JWT + API key + tenant scope
│   ├── correlator.py          # Korelasyon motoru (JSON + pySigma v2, 60s)
│   ├── sigma_executor.py      # pySigma v2 çalıştırıcı
│   ├── attack_chain.py        # Kill chain dedektörü (5 aşama)
│   ├── active_response.py     # OPNsense REST + VyOS SSH IP bloklama
│   ├── anomaly/               # IsolationForest + Welford anomaly
│   ├── detectors/             # port_scan, arp, dns, icmp, lateral
│   ├── parsers/               # firewall, netflow, web_log, zeek
│   ├── discovery/             # subnet_scanner, fingerprinter
│   ├── routes/                # 30 API endpoint modülü
│   ├── log_normalizer.py      # Raw log → NormalizedLog dönüşümü
│   ├── incident_enricher.py   # Incident + MITRE + threat intel
│   ├── threat_intel.py        # AbuseIPDB istemcisi
│   ├── zeek_collector.py      # Zeek log tail (9 log tipi)
│   ├── netflow_receiver.py    # NetFlow v5/v9 UDP alıcı
│   ├── syslog_receiver.py     # Syslog UDP alıcı
│   ├── snmp_collector.py      # SNMP polling döngüsü
│   ├── notifier.py            # Email + webhook bildirimi
│   └── retention.py           # Log retention (hot/warm/cold)
├── shared/
│   └── models.py              # Pydantic modelleri (Agent↔Server)
├── config/
│   ├── correlation_rules.json # JSON korelasyon kuralları
│   └── sigma_rules_v2/        # pySigma v2 YAML (11 dosya, 30+ kural)
├── dashboard-v2/              # Next.js frontend
├── alembic/                   # DB migration dosyaları (001–004)
├── tests/                     # 1151 pytest testi
├── docker-compose.yml
├── Dockerfile
└── .env.example
```

---

## Testler

```bash
# Tüm testler
pytest tests/ -q

# Belirli modül
pytest tests/test_attack_chain.py -v

# Anahtar kelimeyle filtrele
pytest tests/ -k "active_response"

# PostgreSQL testleri (Docker gerekir)
DATABASE_URL="postgresql://netguard:test@localhost:5432/netguard_test" pytest tests/ -q
```

**1151 test · 56 test dosyası** — alert engine, anomaly, attack chain, auth, compliance, correlator, database, detectors, discovery, EVTX, incidents, log normalizer, MITRE, netflow, notifier, retention, sigma, SNMP, threat intel, topology ve daha fazlası.

---

## API

Sunucu çalışırken Swagger UI: `https://localhost/api/v1/docs`

```bash
# Token al
TOKEN=$(curl -s -k -X POST https://localhost/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"şifre"}' | jq -r .access_token)

# Son 50 log
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost/api/v1/logs?limit=50" | jq

# IP blokla
curl -sk -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  https://localhost/api/v1/response/block \
  -d '{"ip":"1.2.3.4","reason":"manuel blok","source_incident_id":42}'
```

---

## Geliştirici

**Mehmet Çapar** — [20mehmetcapar02@gmail.com](mailto:20mehmetcapar02@gmail.com)

Hata bildirimi ve öneriler için GitHub Issues kullanabilirsiniz.
