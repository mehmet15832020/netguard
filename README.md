# NetGuard

**Orta ölçekli şirketler için açık kaynak Network Security Monitoring (NSM) platformu.**

> Splunk $50.000/yıl. QRadar $30.000/yıl. NetGuard: açık kaynak, Docker ile ~30 dakikada kurulum.

NetGuard; syslog, NetFlow/IPFIX/sFlow, SNMP, Zeek, Suricata, Windows Agent, EVTX ve bulut denetim kayıtları (M365/Google Workspace) gibi çoklu kaynaktan ağ ve host verisi toplar. pySigma kural motoru, JSON korelasyon ve makine öğrenmesi tabanlı anomali tespitini birlikte çalıştırarak 5 aşamalı kill chain analizi ve MITRE ATT&CK eşlemesiyle saldırıları ortaya çıkarır. Kritik tehditleri OPNsense veya VyOS üzerinden otomatik ya da manuel olarak engeller.

**Hedef kitle:** 50–500 çalışanlı, kurumsal SIEM bütçesi olmayan şirketlerin IT/güvenlik yöneticileri.

**Konumlandırma:** NetGuard bir **NSM** platformudur — ağ trafiği toplama, davranışsal analiz, imza tabanlı tespit, akış korelasyonu, alert ve sınırlı IP blokajı sunar. Wireshark (PCAP analizi), Wazuh (endpoint/HIDS), Splunk (genel amaçlı log) veya Darktrace (full NDR + UEBA) ile aynı kategoride değildir; cloud log toplama, kullanıcı davranış analitiği (UEBA) ve otomatik SOAR playbook'ları kapsam dışıdır.

---

## Neden NetGuard?

Ticari SIEM/NDR ürünleri KOBİ bütçesinin çok üzerinde fiyatlandırılır; açık kaynak alternatiflerin çoğu (Zeek, Suricata, Wazuh) tek başına yalnızca veri toplar veya tek bir alana (endpoint) odaklanır, uçtan uca korelasyon ve yanıt iş akışı sunmaz. NetGuard bu boşluğu dolduracak şekilde tasarlandı: tek bir Docker Compose komutuyla kurulan, tüm ağ kaynaklarını tek bir korelasyon hattında birleştiren ve tespitten engellemeye kadar giden bütünleşik bir platform.

---

## Mimari

```
COLLECT                       DETECT                          RESPOND
───────                       ──────                          ───────
Syslog (firewall)             JSON korelasyon motoru          Incident yönetimi
SNMP v2c/v3 + TRAP            pySigma v2 (153 kural)          Kill chain timeline
NetFlow v5/v9/IPFIX/sFlow     Kill chain (5 aşama)             Email + webhook
Zeek TAP (21 log tipi)        IsolationForest anomaly         OPNsense REST blok
Suricata EVE JSON             MITRE ATT&CK eşleme             VyOS SSH fallback
Linux/Windows Agent (mTLS)    ARP/DNS/ICMP/port scan det.     Progressive TTL + break-glass
Windows EVTX (60+ EID)        Beaconing (C2 IAT analizi)      Tamperproof audit log (SHA-256)
OpenCanary (honeypot)         Threat intel (composite 0-100)
M365 + Google Workspace       Community ID cross-source pivot
CISA KEV beslemesi            Network behavioral baseline
```

**Pipeline:** Kaynak → `normalized_logs` (ECS alanları) → korelasyon/dedektörler → kill chain → incident → aktif yanıt

---

## Özellikler

### Veri Toplama

| Kaynak | Protokol/Yöntem | Toplanan Veri |
|--------|------------------|----------------|
| Syslog | UDP 5140, TCP/TLS 6010/6514 | OPNsense, VyOS, pfSense, Cisco ASA, FortiGate, nginx |
| NetFlow / IPFIX / sFlow | UDP 2055 / 6343 | Trafik akış analizi (IP, port, byte, flow) |
| SNMP v2c/v3 + TRAP | UDP 161/162 | Interface istatistikleri, uptime, ARP/LLDP, anlık event |
| Zeek TAP | Log dosyası (21 log tipi) | conn, dns, http, ssl, ssh, notice, smtp, ftp, rdp, kerberos, smb, dce_rpc, weird, dpd, files, dhcp, tunnel, pe, ntp ve daha fazlası |
| Suricata EVE JSON | Log dosyası | IDS alert, HTTP/TLS/SSH anomaly, 45.000+ ET kuralı (otomatik güncelleme) |
| Linux/Windows Agent | HTTPS + mTLS (opsiyonel) | CPU, RAM, disk, ağ, process, security event |
| Windows EVTX | HTTP API | 60+ EventID — Security/Sysmon/PowerShell/System/AppLocker (5 kanal) |
| OpenCanary | Honeypot log | 12 servis tipi (SSH, HTTP, SMB, RDP, MySQL vb. sahte servis erişimi) |
| Microsoft 365 / Google Workspace | Audit API polling | Yönetici işlemleri, oturum açma anomalisi |
| CISA KEV | Beslemesi (otomatik) | Aktif istismar edilen CVE listesi → threat intel zenginleştirme |

### Tespit Motoru

**pySigma v2 — `config/sigma_rules_v2/` (15 dosya, 153 çalıştırılabilir kural):**

| Kural Dosyası | İçerik |
|----------------|--------|
| `ssh_brute_force` | SSH başarısız giriş spike'ı |
| `auth_and_web` | Web tarama, SQL injection, başarılı SSH |
| `windows_events` | Brute force, pass-the-hash, password spray, şüpheli process, lateral movement |
| `port_scan` | TCP SYN tarama |
| `network_community` | ARP spoof, ICMP flood, DNS burst, Community ID korelasyonu |
| `dns_tunneling` | Entropi tabanlı DNS tünel tespiti, uzun sorgu, NXDOMAIN spike |
| `c2_and_exfil` | C2 iletişimi, beaconing, veri sızdırma kalıpları |
| `zeek_advanced` | JA4/JA3 TLS parmak izi, x509 anomaly, RDP/Kerberos/SMB, weird/dpd log |
| `suricata_ids` | Suricata EVE alert, HTTP/TLS/SSH anomaly |
| `netflow` | Large flow, suspicious port, tünel burst |
| `web_attacks` | Path traversal, command injection, XSS kalıbı |
| `sql_injection` | SQL injection kalıpları |
| `anomaly_and_impact` | ML anomaly spike, darbe tespiti |
| `device_and_snmp` | Cihaz kesintisi, SNMP trap patlaması |
| `opencanary` | Honeypot etkileşim tespiti |

**5 Aşamalı Kill Chain:**

| Aşama | Tetikleyiciler |
|-------|-----------------|
| RECON | port_scan, dns_anomaly, web_scan, multi_source_attack |
| WEAPONIZE | ssh_failure, windows_logon_failure, brute_force |
| ACCESS | ssh_success, windows_logon_success |
| EXECUTE | sudo_usage, windows_process_create |
| LATERAL | lateral_movement, windows_lateral |

4+ aşama (recon zorunlu) → `FULL_ATTACK_CHAIN` → critical incident + email/webhook + (opsiyonel) otomatik IP bloğu.

**Diğer tespit yetenekleri:**
- **ML Anomaly Detection** — Welford online baseline (per-IP) + Isolation Forest (scikit-learn), kill chain'e entegre
- **Beaconing/C2 tespiti** — inter-arrival time (IAT) analizi, Bessel düzeltmeli standart sapma (RITA metodolojisi)
- **Network behavioral baseline** — per-IP 7 günlük protokol/port profili, yeni port/protokol anomalisi (NIST SP 800-94)
- **Community ID cross-source pivot** — Zeek/Suricata/NetFlow kayıtlarında aynı TCP bağlantısını tek kimlikle eşleştirir
- **Çoklu threat intelligence** — AbuseIPDB + Feodo Tracker + ThreatFox + GreyNoise + CISA KEV, composite skor (0-100)
- **MITRE ATT&CK** — her tespit olayı otomatik ATT&CK taktik/tekniğine eşlenir; Navigator matrix + coverage gap analizi
- **AI Alert Explainer** — Groq Llama 3.3 70B ile doğal dilde alert açıklaması (24 saat cache, prompt injection izolasyonu)
- **Threat Hunt Workbench** — no-code sorgu builder, kayıtlı aramalar
- **Sigma Rule Backtest Engine** — yeni kuralı geçmiş veriye karşı test etme

### Aktif Yanıt

Kill chain tespitinde veya manuel olarak IP engelleyebilir — bu sıra değişmez:

```
1. RFC1918 / PROTECTED_CIDRS kontrolü → 400
2. False positive gate (CIDR + TTL bazlı suppress) → 409 (force=true ile geçilebilir)
3. Severity eşiği kontrolü → 422
4. Duplicate kontrolü → 409
5. OPNsense REST API → ulaşılamazsa VyOS SSH fallback
6. DB: blocked_ips (expires_at + offense_count)
7. Audit log (zorunlu)
```

- **Progressive TTL** — 1. ihlal 1s, 2. 4s, 3. 24s, 4.+ 168s
- **Break-glass** — `BREAK_GLASS_TOKEN` ile JWT bypass, acil unblock
- **Blok doğrulama** — firewall'da gerçekten bloklu mu, orphan/phantom tespiti
- **Port/protokol granülaritesi** — tüm IP yerine belirli port+protokol bloklanabilir

### Platform / Güvenlik

- **Kimlik doğrulama** — JWT access (60dk) + refresh (7gün) + API key (SHA-256 hash) + agent mTLS; token tipi karıştırma engeli (`verify_token(token, token_type=)`)
- **MFA/TOTP** — pyotp tabanlı iki faktörlü doğrulama
- **Multi-tenant izolasyon** — PostgreSQL Row-Level Security (RLS), 11 tabloda tenant scope
- **Tamperproof audit log** — SHA-256 zincirleme (NIST SP 800-92 §3.2), at-rest şifreleme
- **Agent mTLS** — opsiyonel client sertifikası, 90 günlük geçerlilik (NIST SP 800-204A)
- **Rate limiting** — SlowAPI, sistematik middleware (`default_limits=["60/minute"]`, kritik endpoint'lerde daha sıkı)
- **Compliance API** — PCI DSS v4.0 ve ISO 27001:2022 kontrol eşlemesi
- **Sensor health** — Zeek paket düşüş oranı, Suricata kernel drop, agent arayüz durumu (CIS Control 13.1)
- **Log retention** — hot/warm/cold katmanlı saklama, yapılandırılabilir gün sayısı
- **WebSocket** — gerçek zamanlı log/alert akışı (TanStack Virtual ile sanal liste)
- **Alembic** — 28 migration, versiyonlu DB şema yönetimi

### Dashboard (40+ Sayfa)

Overview (bento grid) · Logs (canlı akış) · Incidents · Aktif Bloklar · Alerts · Agents · Correlation (AI Explainer) · Network Intelligence · MITRE ATT&CK Navigator · Kill Chain Timeline · Topology · Devices/SNMP/Discovery · Settings/Audit · Reports/Security/Uyumluluk · Threat Hunt Workbench · Sigma Rules/Wizard/Editor · Correlation Rules · Top Talkers · Alert Volume · Protocol Distribution · Traffic Volume · East-West Matrix · Asset Risk Heatmap · MTTD/MTTR · DNS Analysis · TLS Fingerprints · Beaconing · Failed Auth · Threat Intel Summary

---

## Hızlı Başlangıç

### Gereksinimler

- Docker + Docker Compose v2
- 4 GB RAM, 20 GB disk
- Linux host önerilen (Zeek/pyshark için `NET_RAW` capability)

### Kurulum

```bash
git clone https://github.com/mehmet15832020/netguard.git
cd netguard
cp .env.example .env
```

`.env` dosyasını düzenle — minimum zorunlu alanlar:

```env
JWT_SECRET_KEY=<rastgele-string>              # openssl rand -hex 32
NETGUARD_ENCRYPTION_KEY=<encryption-key>      # python -c "from server.crypto import generate_key; print(generate_key())"
ADMIN_PASSWORD=<güçlü-şifre>
VIEWER_PASSWORD=<viewer-şifresi>
POSTGRES_PASSWORD=<db-şifresi>
INFLUXDB_TOKEN=<influx-token>
INFLUXDB_ADMIN_PASSWORD=<influx-admin-şifresi>
INFLUXDB_ORG=netguard
INFLUXDB_BUCKET=netguard
NETGUARD_HOST=localhost                       # veya sunucu IP'si
ZEEK_INTERFACE=eth0                           # izlenecek ağ arayüzü
```

```bash
docker compose up -d
```

Dashboard: `https://localhost` · API dokümantasyonu: `https://localhost/api/v1/docs`

İlk açılışta self-signed sertifika uyarısı çıkar — geliştirme ortamında güvenle geçilebilir.

**Docker Compose servisleri:** `backend` (FastAPI + tüm collector/detector döngüleri), `frontend` (Next.js), `nginx` (TLS reverse proxy), `postgres` (TimescaleDB), `influxdb`, `zeek`, `opencanary` (honeypot).

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
sudo apt install -y postgresql-16
sudo -u postgres psql -c "CREATE DATABASE netguard; CREATE USER netguard WITH PASSWORD 'şifre'; GRANT ALL ON DATABASE netguard TO netguard;"
# TimescaleDB extension kurulumu: https://docs.timescale.com/self-hosted/latest/install/
```

### Backend

```bash
cd netguard
python3.12 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# .env dosyasını düzenle

export DATABASE_URL="postgresql://netguard:şifre@localhost:5432/netguard"
alembic upgrade head

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
# Kolay kurulum:
scp scripts/install-agent.sh user@192.168.x.x:~/ && ssh user@192.168.x.x "bash install-agent.sh"

# Manuel kurulum:
scp -r agent/ user@192.168.x.x:~/netguard-agent/
ssh user@192.168.x.x "cd ~/netguard-agent && pip install psutil httpx python-dotenv"

cat > ~/netguard-agent/.env << EOF
NETGUARD_SERVER=https://192.168.x.x
AGENT_API_KEY=<dashboard Agents sayfasından alınan key>
EOF

python main.py
```

### Zeek (Opsiyonel — Network Intelligence için)

```bash
# Zeek LTS kurulumu: https://docs.zeek.org/en/master/install.html
zeek -i eth0 config/zeek/local.zeek

# JSON çıktı ve log rotasyonu config/zeek/local.zeek ile önceden yapılandırılmıştır.
ZEEK_LOG_DIR=/var/log/zeek/current
```

---

## Yapılandırma

### Zorunlu

| Değişken | Açıklama |
|----------|----------|
| `JWT_SECRET_KEY` | JWT imzalama anahtarı — `openssl rand -hex 32` |
| `NETGUARD_ENCRYPTION_KEY` | At-rest şifreleme anahtarı (TOTP secret vb.) |
| `ADMIN_PASSWORD` | Dashboard admin şifresi |
| `VIEWER_PASSWORD` | Dashboard viewer şifresi (salt okunur) |
| `POSTGRES_PASSWORD` | PostgreSQL şifresi |
| `INFLUXDB_TOKEN` / `INFLUXDB_ADMIN_PASSWORD` / `INFLUXDB_ORG` / `INFLUXDB_BUCKET` | InfluxDB bağlantı bilgileri |

### Ağ

| Değişken | Varsayılan | Açıklama |
|----------|-----------|----------|
| `NETGUARD_INTERFACE` | `eth0` | Paket yakalama arayüzü |
| `ZEEK_INTERFACE` | `eth0` | Zeek izleme arayüzü |
| `ZEEK_LOG_DIR` | `/zeek-logs` | Zeek log dizini |
| `NETGUARD_CORS_ORIGINS` | `https://localhost` | Frontend URL'leri (virgülle ayrılmış) |
| `NETGUARD_HOST` | `localhost` | Sunucu IP/hostname |
| `SYSLOG_PORT` | `5140` | Syslog UDP port |
| `NETGUARD_SYSLOG_TCP_PORT` / `NETGUARD_SYSLOG_TLS_PORT` | `6010` / `6514` | Syslog TCP (RFC 6587) / TLS (RFC 5425) |
| `NETFLOW_PORT` | `2055` | NetFlow/IPFIX UDP port |
| `SFLOW_PORT` | `6343` | sFlow UDP port |

### Aktif Yanıt

| Değişken | Açıklama |
|----------|----------|
| `OPNSENSE_HOST` / `OPNSENSE_KEY` / `OPNSENSE_SECRET` | OPNsense REST API bağlantısı |
| `OPNSENSE_BLOCK_ALIAS` | Firewall alias adı (`NETGUARD_BLOCK`) |
| `VYOS_HOST` / `VYOS_USER` / `VYOS_KEY_PATH` | VyOS SSH fallback bağlantısı |
| `VYOS_FW_NAME` | VyOS firewall kural adı (`BLOCK-LIST`) |
| `PROTECTED_CIDRS` | Hiçbir zaman engellenmeyecek IP'ler |
| `BLOCK_MIN_SEVERITY` | Minimum severity eşiği (`high`) |
| `BLOCK_PROGRESSIVE_TTL` | Saat cinsinden TTL kademeleri (`1,4,24,168`) |
| `BREAK_GLASS_TOKEN` | Acil unblock token — `openssl rand -hex 32` |
| `AUTO_BLOCK_ON_FULL_CHAIN` | `1` → FULL_ATTACK_CHAIN'de otomatik blok (varsayılan `0`) |

### Bildirim

| Değişken | Açıklama |
|----------|----------|
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_FROM` / `SMTP_TO` | E-posta bildirimi (HTML+plain MIME) |
| `WEBHOOK_URL` / `WEBHOOK_TYPE` | Discord veya Slack webhook |

### Tehdit İstihbaratı ve AI

| Değişken | Açıklama |
|----------|----------|
| `ABUSEIPDB_API_KEY` | [Ücretsiz key](https://www.abuseipdb.com/api) |
| `GROQ_API_KEY` / `GROQ_MODEL` | AI Alert Explainer — [console.groq.com](https://console.groq.com) ücretsiz key |

### Bulut Denetim Kayıtları (Opsiyonel)

| Değişken | Açıklama |
|----------|----------|
| `M365_TENANT_ID` / `M365_CLIENT_ID` / `M365_CLIENT_SECRET` / `M365_POLL_INTERVAL` | Microsoft 365 Audit API |
| `GWS_SERVICE_ACCOUNT_JSON` / `GWS_ADMIN_EMAIL` / `GWS_DOMAIN` / `GWS_POLL_INTERVAL` | Google Workspace Audit API |

### Log Retention ve Döngü Aralıkları (Opsiyonel)

| Değişken | Varsayılan | Açıklama |
|----------|-----------|----------|
| `NETGUARD_RETAIN_NORMALIZED_DAYS` | `30` | Normalize log saklama süresi |
| `NETGUARD_RETAIN_SECURITY_DAYS` | `90` | Security event saklama süresi |
| `NETGUARD_RETAIN_CORRELATED_DAYS` | `365` | Correlated event saklama süresi |
| `NETGUARD_RETAIN_ALERTS_DAYS` | `90` | Alert saklama süresi |
| `NETGUARD_CORR_INTERVAL` | `60` | Korelasyon döngüsü (saniye) |
| `NETGUARD_DETECTOR_INTERVAL` | `30` | Ağ saldırı dedektörleri (saniye) |
| `NETGUARD_SNMP_INTERVAL` | `60` | SNMP polling (saniye) |

---

## Sigma Kuralı Ekleme

NetGuard standart SIGMA formatını destekler. Kural eklemek için kod değişikliği gerekmez:

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
curl -X POST https://localhost/api/v1/sigma/validate \
     -H "Authorization: Bearer $TOKEN" \
     -F "file=@ornek.yml"
```

Dashboard'daki **Sigma Wizard** (4 adımlı form) veya **Monaco YAML Editör** ile kod yazmadan da kural oluşturulabilir.

---

## JSON Korelasyon Kuralı Ekleme

`config/correlation_rules.json` dosyasına sunucu yeniden başlatılmadan kural eklenebilir (Dashboard → Correlation Rules sayfasından da yönetilebilir):

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

## Teknoloji Yığını

### Backend

| Teknoloji | Sürüm | Kullanım |
|-----------|-------|----------|
| Python | 3.12 | Runtime |
| FastAPI | 0.115 | ASGI API sunucusu |
| PostgreSQL | 16 | İlişkisel veri (log, incident, cihaz) |
| TimescaleDB | latest | `normalized_logs` hypertable, compression |
| InfluxDB | 2.7 | SNMP/agent metrik zaman serileri |
| Zeek | LTS | Ağ trafiği analizi (21 log tipi) |
| Suricata | latest | IDS/IPS, 45.000+ ET kuralı |
| pySigma | 1.3.3 | SIGMA kural motoru |
| scikit-learn | ≥1.5 | Isolation Forest anomaly detection |
| pyshark | 0.6 | TCP SYN paket analizi |
| pysnmp | 7.1 | SNMP v2c/v3 polling ve trap |
| paramiko | ≥3.0 | VyOS SSH aktif yanıt |
| psycopg | ≥3.2 | PostgreSQL async sürücüsü |
| Alembic | ≥1.13 | DB şema migration |
| slowapi | 0.1.9 | Rate limiting |
| pyotp | ≥2.9 | TOTP/MFA |
| cryptography | 46.0 | At-rest şifreleme, mTLS sertifika üretimi |

### Frontend

| Teknoloji | Sürüm | Kullanım |
|-----------|-------|----------|
| Next.js | 16 | App Router, SSR |
| React | 19 | UI runtime |
| TypeScript | 5 | Tip güvenliği |
| TanStack Query | v5 | Server state ve önbellekleme |
| TanStack Virtual | — | Canlı log akışı sanallaştırma |
| Zustand | v5 | Global UI state |
| ECharts | v6 | Topoloji, heatmap, grafikler |
| shadcn/ui + Tailwind | — | UI bileşenleri |
| Monaco Editor | — | Sigma YAML editörü |

### Portlar

| Port | Protokol | Hizmet |
|------|----------|--------|
| 443 | TCP/HTTPS | Dashboard + API (nginx) |
| 80 | TCP/HTTP | HTTPS yönlendirme |
| 8000 | TCP | FastAPI (dahili) |
| 5140 | UDP | Syslog alıcı |
| 6010 / 6514 | TCP/TLS | Syslog (RFC 6587 / RFC 5425) |
| 2055 | UDP | NetFlow/IPFIX alıcı |
| 6343 | UDP | sFlow alıcı |
| 161 / 162 | UDP | SNMP polling / TRAP |

---

## Proje Yapısı

```
netguard/
├── agent/                     # İzlenen makinelerde çalışan agent (psutil, mTLS destekli)
├── server/
│   ├── main.py                # FastAPI app, async döngüler, startup
│   ├── database.py            # PostgreSQL + TimescaleDB yöneticisi (psycopg3 pool)
│   ├── auth.py                # JWT + API key + MFA + agent mTLS doğrulama
│   ├── correlator.py          # Korelasyon motoru (JSON + pySigma v2, 60s)
│   ├── sigma_executor.py      # pySigma v2 çalıştırıcı (153 kural)
│   ├── attack_chain.py        # Kill chain dedektörü (5 aşama)
│   ├── active_response.py     # OPNsense REST + VyOS SSH IP bloklama
│   ├── anomaly/                # IsolationForest + Welford anomaly
│   ├── detectors/              # port_scan, arp_spoof, dns_anomaly, icmp_flood, lateral, beaconing, rare_dest
│   ├── parsers/                # firewall, netflow, zeek, suricata, windows, opencanary, cloud, web_log
│   ├── collectors/             # m365_collector, gworkspace_collector, kev_monitor
│   ├── discovery/               # subnet_scanner, fingerprinter
│   ├── routes/                  # 31 API endpoint modülü
│   ├── log_normalizer.py       # Raw log → NormalizedLog (ECS) dönüşümü
│   ├── incident_enricher.py    # Incident + MITRE + threat intel zenginleştirme
│   ├── threat_intel.py         # AbuseIPDB + Feodo + ThreatFox + GreyNoise composite
│   ├── zeek_collector.py       # Zeek log tail + inotify (21 log tipi)
│   ├── suricata_collector.py   # Suricata EVE JSON (inode rotation-safe)
│   ├── netflow_receiver.py     # NetFlow v5/v9/IPFIX/sFlow UDP alıcı
│   ├── syslog_receiver.py      # Syslog UDP + TCP/TLS alıcı
│   ├── snmp_collector.py       # SNMP polling döngüsü
│   ├── agent_pki.py            # Agent mTLS CA üretimi + sertifika imzalama
│   ├── notifier.py             # Email + webhook bildirimi
│   └── retention.py            # Log retention (hot/warm/cold)
├── shared/
│   └── models.py               # Pydantic modelleri (Agent↔Server protokolü)
├── config/
│   ├── correlation_rules.json  # JSON korelasyon kuralları
│   ├── sigma_rules_v2/         # pySigma v2 YAML (15 dosya, 153 kural)
│   └── zeek/                   # Zeek konfigürasyonu (JSON log, rotation)
├── nginx/                       # TLS reverse proxy + self-signed sertifika
├── scripts/                      # Kurulum, backup/restore, GNS3 lab otomasyonu
├── dashboard-v2/                # Next.js 16 frontend (40+ sayfa)
├── alembic/versions/             # 28 DB migration dosyası
├── tests/                        # 3.300+ pytest testi
├── docs/                         # Mimari kararlar (ADR), kullanıcı kılavuzu
├── docker-compose.yml
├── Dockerfile
└── .env.example
```

---

## Testler

```bash
# Tüm testler (testcontainers otomatik Docker PostgreSQL başlatır)
pytest tests/ -q

# Belirli modül
pytest tests/test_attack_chain.py -v

# Anahtar kelimeyle filtrele
pytest tests/ -k "active_response"

# Mevcut PostgreSQL ile test (Docker gerekmez)
DATABASE_URL="postgresql://netguard:test@localhost:5432/netguard_test" pytest tests/ -q
```

**3.300+ test** — alert engine, anomaly, attack chain, auth, MFA, compliance, correlator, database, detectors, discovery, EVTX, incidents, log normalizer, MITRE, NetFlow, notifier, retention, sigma, SNMP, threat intel, topology, RLS multi-tenant, agent mTLS, audit log zinciri ve daha fazlası.

> **Not:** Testler PostgreSQL gerektirir. Docker varsa testcontainers otomatik Docker container başlatır. `DATABASE_URL` ortam değişkeni tanımlıysa o PostgreSQL kullanılır.

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

# Community ID ile aynı bağlantının Zeek/Suricata/NetFlow kayıtlarını bul
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://localhost/api/v1/logs/by-community-id/1:abc123..." | jq
```

---

## Katkıda Bulunma

NetGuard açık kaynak bir proje ve geliştirilmeye devam ediyor. Fikir, hata bildirimi, kural önerisi veya pull request — hepsine açığız:

- **Issue açın:** hata, özellik isteği veya soru için GitHub Issues kullanın
- **Sigma/korelasyon kuralı önerin:** `config/sigma_rules_v2/` ve `config/correlation_rules.json` kod değişikliği gerektirmeden genişletilebilir
- **Pull request gönderin:** değişikliğinizi açıklayan kısa bir özetle birlikte

Proje [MIT lisansı](LICENSE) ile yayınlanmıştır.

---

## Geliştirici

**Mehmet Çapar** — [20mehmetcapar02@gmail.com](mailto:20mehmetcapar02@gmail.com)

Hata bildirimi ve öneriler için GitHub Issues kullanabilirsiniz.
