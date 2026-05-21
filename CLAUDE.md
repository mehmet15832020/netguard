# NetGuard — Claude Rehberi

Bu dosya Claude Code'un her oturumda otomatik okuduğu proje rehberidir.
Tamamlanan adımlar `[x]` ile işaretlenir.

---

## Ürün Kimliği

**NetGuard: Orta ölçekli şirketler için açık kaynak NSM platformu (NDR-lite).**

> "Splunk 50K$/yıl. QRadar 30K$/yıl. NetGuard: açık kaynak, Docker ile 30 dakikada kurulum."

- **Hedef kitle:** 50–500 çalışanlı, siber güvenlik bütçesi kısıtlı şirketlerin IT yöneticileri
- **Rekabet konumu:** Wazuh endpoint/HIDS odaklı → NetGuard network/NSM odaklı (bu gap gerçek)
- **Ne değildir:** Wireshark (PCAP), Zabbix (NMS), Splunk (log), Wazuh (EDR), Darktrace (full NDR)

---

## Mimari

```
COLLECT                 DETECT                      RESPOND
───────                 ──────                      ───────
Syslog (firewall)       JSON korelasyon motoru       Incident yönetimi
SNMP v2c/v3             pySigma v2 (30+ kural)       Kill chain timeline
NetFlow v5/v9           Kill chain (5 aşama)         Email + webhook
pyshark (SYN/BPF)       IsolationForest anomaly      OPNsense REST blok
Agent (psutil)          MITRE ATT&CK mapping         VyOS SSH fallback
Zeek TAP                Threat intel (AbuseIPDB)     Audit log
EVTX (Windows)          ARP/DNS/ICMP/port_scan det.
```

**Pipeline:** Kaynak → `normalized_logs` → correlator/detectors → kill chain → incident → aktif yanıt

---

## Veritabanı Mimarisi

| Ortam | Veritabanı | Koşul |
|-------|-----------|-------|
| Production | PostgreSQL + TimescaleDB | `DATABASE_URL` env set |
| Test (tmp_db) | SQLite (geçici) | `DATABASE_URL` yok |
| Test (pg_db) | PostgreSQL (testcontainers) | `DATABASE_URL` set |

**Mevcut sorun:** `database.py` (2583 satır SQLite) + `database_pg.py` (1584 satır PG) = ~2600 satır tekrar → FAZ 2'de çözülecek.

---

## Mimari Kararlar

- **Event pipeline:** Her kaynak → `normalized_logs` (tek merkezi tablo)
- **Sigma engine:** Yalnızca pySigma v2 — `config/sigma_rules_v2/` (11 dosya, 30+ kural)
- **Korelasyon:** JSON (`correlation_rules.json`) + pySigma v2 — iki katmanlı
- **Token:** `verify_token(token, token_type=)` — tip karıştırma engeli
- **API key:** SHA-256 hash saklanır, plaintext asla DB'ye yazılmaz
- **Aktif yanıt:** OPNsense REST → VyOS SSH fallback, audit log zorunlu
- **Blok güvenlik geçitleri:** RFC1918 → FP gate → severity gate → duplicate gate (bu sıra değişmez)
- **Progressive TTL:** `_progressive_ttl(offense_count)` — 1h / 4h / 24h / 168h
- **Break-glass:** `BREAK_GLASS_TOKEN` env — JWT bypass, sadece unblock
- **Placeholder:** Her yerde `%s` — dialect flag yok
- **dict_row:** `row["kolon"]` kullan, `row[0]` asla

---

## Yol Haritası — Öncelik Sırası

Araştırma kaynakları: CrowdStrike 2025, Verizon DBIR 2025, MITRE ATT&CK v17, CIS Controls v8.1, NIST SP 800-94, OWASP API Security 2023, Gartner NDR Market Guide 2025.

> **Üretim eşiği notu (Mayıs 2026):** Tahmini kapasite ~%65 (Security Onion benchmark). G2+U2+F4 tamamlanırsa ~%82, U3+U4+T2-3 ile ~%88. Bu 3 görev olmadan production pilot için kritik kör nokta kalır.

### AŞAMA 1 — Acil Güvenlik (Tamamlandı)

- [x] **G5** — `routes/active_response.py` rate limiting (`10/minute` block, `5/minute` break-glass)
- [x] **G1** — FULL_ATTACK_CHAIN → otomatik IP bloklama (`AUTO_BLOCK_ON_FULL_CHAIN=1`)
- [x] **G6** — JA4 geçişi (JA3 legacy fallback, entropi threshold 4.0, FP regression testleri)

### AŞAMA 2 — Tespit Genişletme (Tamamlandı)

- [x] **G4** — DNS tunneling: entropi (4.0 bit), uzun sorgu (>50c), NXDOMAIN 2 katmanlı spike
- [x] **G3** — Çoklu threat intel: Feodo Tracker + ThreatFox + GreyNoise + composite score 0-100

### AŞAMA 2.5 — Kritik Tespit Eksikleri (ÜRETİM ÖNCESİ ZORUNLU)

> Bu üç görev olmadan NetGuard %65 kapasitede kalır. Sırayla yapılır, paralel değil — G2 bağımsız, U2 bağımsız, F4 ikisinden beslenirse daha güçlü.

---

- [x] **G2** — Suricata EVE JSON collector
  - *CIS Controls v8.1 Safeguard 13.8 zorunlu. Zeek behavioral + Suricata imza = altın standart NSM. Zeek'in göremediği TLS içi payload, exploit kit imzaları Suricata yakalar.*
  - **Teslim:** `server/parsers/suricata.py` (9 event_type parser), `server/suricata_collector.py` (inode rotation-safe offset), `config/sigma_rules_v2/suricata_ids.yml` (6 kural), 60 test — 1271 toplam test ✓

- [x] **U2** — Sysmon / Windows HIDS entegrasyonu
  - *Verizon DBIR 2025: ihlallerin %32'si credential compromise — Windows host blind spot. EVTX parser var ama Sysmon event mapping yok.*
  - **Teslim:** `evtx_parser.py` 12 EID (Sysmon 1/3/10/22 + Security 4648/4720/4732/4768/4769); `parsers/windows.py` NormalizedLog dönüşümü; `routes/evtx.py` normalized_logs yazımı; 8 Sysmon sigma kuralı; 39 test — STAGE_MAP Sysmon eventi kill chain'e bağlandı ✓

- [x] **F4** — Anomaly engine → kill chain entegrasyonu
  - *Gartner NDR: ML anomali behavioral context'te değerlendirilmeli. Slow-and-low saldırılar Sigma eşiğini geçer, IsolationForest yakalar — ama şu an kill chain'e beslenmiyor.*
  - **Teslim:** `engine.py` anomaly tespitinde trigger yakalanıyor → `chain_trigger_to_correlated_event()` çağrısı, FULL_ATTACK_CHAIN alerti/auto-block tetikleniyor; IP doğrulaması; quality audit düzeltmeleri (F4+U2 kritik bulgular) — 1311 toplam test ✓

---

### AŞAMA 2.6 — Dashboard Görselleştirme

Araştırma kaynakları: Gartner NDR Market Guide 2024, CIS Controls v8 Control 13, NIST SP 800-94, Security Onion 2.4, Malcolm/CISA, ntopng, Arkime, Grafana Best Practices 2024, ArmorPoint SOC KPIs 2025.

**Uygulama sırası:** Blok A (bağımsız, ~4 gün) → Blok B (G4/G3/G2 sonrası) → Blok C (ertelenebilir)

**Altyapı durumu:** Next.js dashboard ✓, api.ts ✓, TanStack Query ✓ — analytics route YOK (yazılacak), top-talkers endpoint YOK (yazılacak)

#### Blok A — Hızlı Kazanımlar (~4 gün, bağımsız)

- [ ] **D1** — Top Talkers Panel
  - Top src/dst IP + top dst port → horizontal ranked bar; `GET /api/v1/analytics/top-talkers?hours=24&limit=20`
  - Altyapı: backend route YOK, frontend component YOK
- [ ] **D5** — Alert Volume Stacked Area Chart
  - `alerts` GROUP BY hour × severity → critical/high/medium renk kodlaması
  - Altyapı: `alerts` tablosu VAR ✓, route YOK
- [ ] **D2** — Protocol Distribution Donut
  - `normalized_logs.network_protocol` GROUP BY; CIS Control 13.6
  - Altyapı: `network_protocol` kolonu VAR ✓, route YOK
- [ ] **D3** — Traffic Volume Area Chart (east-west / north-south)
  - RFC1918 kaynak → iç/dış ayrımı, stacked area; Gartner NDR zorunlu
  - Altyapı: `source_ip` kolonu VAR ✓, RFC1918 check aktif yanıtta VAR ✓

#### Blok B — Bağımlı Dashboard Görselleri (~4-5 gün)

- [ ] **D4** — Kill Chain Swimlane Timeline — Bağımlılık: G1 ✓ (zaten tamamlandı, yapılabilir)
- [ ] **D8** — DNS Analiz Derinleştirme — Bağımlılık: G4 ✓
- [ ] **D6** — Threat Intel Geo Harita + Composite Score — Bağımlılık: G3 ✓

#### Blok C — Karmaşık Görseller (ertelenebilir, F4 sonrası)

- [ ] **D7** — East-West Connection Matrix Heatmap — Bağımlılık: F4
- [ ] **D9** — Asset Risk Heatmap — Bağımlılık: F4
- [ ] **D10** — MTTD/MTTR Metrik Paneli — Bağımlılık: incident lifecycle

### AŞAMA 3 — Güvenlik Derinleştirme

- [ ] **U3** — Tamperproof audit log (SHA-256 zinciri)
  - *NIST SP 800-92 §3.2 + NIS2 Article 21(2)(i): log bütünlüğü yasal gereklilik. Attacker PG'ye erişirse audit siler.*
  - **Altyapı:** `audit_log` tablosu VAR ✓; `previous_hash` kolonu YOK (Alembic 006 eklenecek); `hashlib` stdlib VAR ✓
  - **Yapılacaklar:** `audit_log` tablosuna `previous_hash VARCHAR(64)` ekle (Alembic 006); insert_audit_log() SHA-256 chain; `GET /api/v1/audit-log/verify` bütünlük route
  - Bağımlılık: yok (SQLite/PG uyumlu)
  - Tahmini süre: 2-3 gün

- [ ] **U4** — Beaconing detection (C2 inter-arrival time)
  - *MITRE ATT&CK T1071: Cobalt Strike default 60s, APT1 5m jitter ±%10-15. Zeek conn logs akar ama analiz yok.*
  - **Altyapı:** `server/detectors/beaconing.py` YOK (yazılacak); STAGE_MAP'te `"firewall_beacon": "recon"` VAR ✓ (`"c2_beaconing"` eklenecek); `normalized_logs` Zeek conn kayıtları VAR ✓; TimescaleDB aggregation uygun ✓
  - **Yapılacaklar:** `beaconing.py` — (src_ip, dst_ip, dst_port) grup, inter-arrival time stddev; jitter < %20 + interval < 5dk → `c2_beaconing` alert; correlator loop'una ekle (5dk aralık)
  - Bağımlılık: F4 sonrası yapılırsa kill chain'e daha temiz beslenir
  - Tahmini süre: 2-3 gün

- [ ] **T2-3** — MFA / TOTP
  - *Verizon DBIR 2025: kimlik ihlallerinin %32'si. NIS2 Article 21(2)(i) zorunlu.*
  - **Altyapı:** `server/auth.py` VAR ✓; `pyotp` YOK (`pip install pyotp` gerekli); `users` tablosunda `totp_secret/totp_enabled` YOK (Alembic 006/007); frontend MFA sayfası YOK
  - **Yapılacaklar:** `pyotp` bağımlılığı ekle; users tablosuna 2 kolon; `/auth/totp-setup` + `/auth/totp-verify` + `/auth/totp-confirm` route; frontend QR sayfası
  - Bağımlılık: yok
  - Tahmini süre: 3-4 gün

### AŞAMA 4 — Mimari Temizlik

- [ ] **F2-3** — 9 test dosyasını PG uyumlu hale getir (`tmp_db` fixture; Docker yoksa skip)
- [ ] **F2-1** — `database.py` → sadece PostgreSQL (SQLite sınıfını sil, `database_pg.py` merge)
- [ ] **F2-2** — `database_pg.py` kaldır — Bağımlılık: F2-1
- [ ] **F3** — Ham SQL → DB metodları (correlator, asset_baseline, retention, mitre, network_intel)
- [ ] **F2-6** — Alembic migration notları güncelle (DATABASE_URL zorunlu)

### AŞAMA 5 — Ticari Hazırlık (6-12 Ay, Teknikle Paralel)

- [ ] **U5** — SOAR entegrasyonu (TheHive/Shuffle)
  - **Altyapı:** `server/notifier.py` webhook VAR ✓; TheHive endpoint YOK; `THEHIVE_URL/THEHIVE_API_KEY` env eklenecek
  - Bağımlılık: U3 + F4 tamamlanmalı (incident volume stabil olmalı)
- [ ] **U6** — Multi-tenant PostgreSQL RLS — Bağımlılık: F2 + U3 + T1
- [ ] **U1** — East-West görünürlük (L3 switch NetFlow) — NetFlow altyapısı VAR ✓, GNS3 L3 konfig gerekli
- [ ] **T1** — Hukuki altyapı (şirket, KVKK DPA, Tech E&O sigortası)
- [ ] **T2** — Teknik ticari (T2-1 tamperproof ✓U3, T2-2 at-rest şifreleme, T2-3 MFA ✓T2-3, T2-4 RLS, T2-5 rate limiting)
- [ ] **T3** — Sertifikasyon (pentest + SOC 2 Type I) — Bağımlılık: T2
- [ ] **T4** — Pazar hazırlığı (3 pilot müşteri, MSSP ortaklığı) — Bağımlılık: T1+T2+T3
- [ ] **T2-5** — Sistematik rate limiting middleware (tüm endpoint'ler) — G5 point fix'ini genelleştirir

### Küçük Kod Sorunları (Herhangi Bir Anda)

- [ ] `correlator.py:178` — Yanıltıcı yorum `"JSON + sigma_v1 YAML"` → `"JSON korelasyon kuralları"`
- [ ] `correlator.py:244` — Sessiz `except: pass` → `logger.debug("ws broadcast: %s", exc)`
- [x] **Frontend** — Block verify panel (P6) ✓, Break-glass butonu (P8) ✓ — Port/protocol input (P7) kaldı

---

## Tamamlanan Fazlar

| Faz | İçerik | Commit |
|-----|--------|--------|
| **FAZ 1** | Sigma V1 kaldır, pySigma v2 tek engine | `455dced` |
| **FAZ 2a** | `_IS_PG/_PH` dialect flag 6 modülden kaldırıldı, `LogStore` eklendi | `6187e0d` |
| **V1-1..V1-9** | ECS rename, DNS resolver, pySigma, enrichment, baseline, FP, PostgreSQL, Zeek, aktif yanıt | çeşitli |
| **P1-P8** | RFC1918, TTL, FP gate, severity gate, progressive TTL, verify, port/protocol, break-glass | çeşitli |
| **GNS3 Lab** | PostgreSQL kurulum, Alembic migrasyon, API key, dashboard build, topoloji bağlantıları | çeşitli |

**Test durumu:** 1311 test, 0 hata (21 Mayıs 2026)

---

## Mevcut Envanter

### Backend Modülleri

| Dosya | Rol |
|-------|-----|
| `server/active_response.py` | OPNsense REST + VyOS SSH IP bloklama (P1-P8) |
| `server/alert_engine.py` | Ajan alert motoru |
| `server/anomaly/` | IsolationForest + Welford — kill chain bağlantısı F4'te |
| `server/asset_baseline.py` | Per-IP 7 günlük davranış profili + spike |
| `server/attack_chain.py` | Kill chain (RECON/WEAPONIZE/ACCESS/LATERAL/FULL) |
| `server/auth.py` | JWT access/refresh + API key (SHA-256) |
| `server/compliance.py` | 26 güvenlik kontrolü |
| `server/config_monitor.py` | Konfigürasyon değişiklik tespiti |
| `server/correlator.py` | 60s döngü, JSON + pySigma v2 |
| `server/database.py` | Factory: PG (prod) / SQLite (test) — F2'de birleşecek |
| `server/database_pg.py` | PostgreSQL + TimescaleDB, psycopg3 pool — F2'de kalkacak |
| `server/detectors/` | port_scan, arp, dns, icmp, lateral |
| `server/discovery/` | fingerprinter.py + subnet_scanner.py |
| `server/dns_resolver.py` | PTR lookup, TTL cache (300s/60s) |
| `server/evtx_parser.py` | Windows EVTX log ayrıştırıcı |
| `server/fp_manager.py` | False positive suppression (CIDR + 30gün TTL) |
| `server/incident_enricher.py` | MITRE + related logs + threat intel |
| `server/incident_priority.py` | Severity formula, priority_score |
| `server/influx_writer.py` | InfluxDB metrics yazıcı |
| `server/log_normalizer.py` | syslog/netflow/zeek/agent/EVTX parser |
| `server/log_store.py` | LogStore Protocol + PostgreSQLLogStore |
| `server/mitre.py` | MITRE ATT&CK yardımcı modülü |
| `server/netflow_receiver.py` | NetFlow v5/v9 UDP 2055 |
| `server/notifier.py` | Email + webhook, retry |
| `server/ntp_validator.py` | Log timestamp NTP doğrulama |
| `server/port_monitor.py` | Yerel port değişiklik tespiti |
| `server/retention.py` | hot/warm/cold veri tutma |
| `server/security_log_parser.py` | auth.log parser (SSH/sudo/PAM) |
| `server/sigma_executor.py` | pySigma v2, 30+ çalıştırılabilir kural |
| `server/snmp_auth.py` | SNMP auth helper |
| `server/snmp_collector.py` | SNMP v2c/v3 poll + trap |
| `server/snmp_trap_receiver.py` | SNMP trap UDP alıcısı |
| `server/storage.py` | RAM snapshot cache (metrics/health) |
| `server/syslog_receiver.py` | UDP 514 syslog alıcı |
| `server/threat_intel.py` | AbuseIPDB cache (score ≥ 70 → critical) |
| `server/uptime_checker.py` | Cihaz uptime / ICMP ping |
| `server/ws_manager.py` | WebSocket bağlantı yöneticisi |
| `server/zeek_collector.py` | Zeek log tail (DNS/HTTP/SSL/Conn/SSH/Notice/x509/SMTP/FTP) |
| `server/parsers/` | firewall.py, web_log.py, zeek.py, netflow.py |

### Route'lar (30 dosya)

| Grup | Dosyalar |
|------|---------|
| Güvenlik çekirdeği | auth, incidents, active_response, sigma, correlation, mitre, attack_chains |
| Veri toplama | logs, alerts, agents, devices, snmp, netflow, evtx |
| Analiz | network_intel, anomaly, assets, fp_rules, threat_intel, topology |
| Platform | health, metrics, maintenance, compliance, security, reports |
| Altyapı | discovery, tenants, ws |

### Sigma Kuralları (`config/sigma_rules_v2/` — 11 dosya)

`anomaly_and_impact`, `auth_and_web`, `c2_and_exfil`, `device_and_snmp`, `network_community`, `port_scan`, `sql_injection`, `ssh_brute_force`, `web_attacks`, `windows_events`, `zeek_advanced`

### Frontend Sayfaları (dashboard-v2)

Overview, Logs, Incidents, Aktif Bloklar, Alerts, Agents, Correlation, Network Intelligence, MITRE ATT&CK, Timeline, Topology, Devices/SNMP/Discovery, Settings/Audit, Reports/Security, Uyumluluk (Compliance) — **⏳ Eksik:** Port/protocol input (P7)

---

## Aktif Yanıt Referans

### Env Değişkenleri

```bash
OPNSENSE_HOST=10.0.30.1        OPNSENSE_KEY=<key>      OPNSENSE_SECRET=<secret>
OPNSENSE_BLOCK_ALIAS=NETGUARD_BLOCK
VYOS_HOST=192.168.203.200      VYOS_USER=vyos          VYOS_KEY_PATH=/path/to/key
VYOS_FW_NAME=BLOCK-LIST
PROTECTED_CIDRS=10.0.30.1/32,192.168.203.134/32
BLOCK_MIN_SEVERITY=high        BLOCK_PROGRESSIVE_TTL=1,4,24,168
BREAK_GLASS_TOKEN=<rastgele>   BLOCK_EXPIRY_INTERVAL=60
AUTO_BLOCK_ON_FULL_CHAIN=0     # G1 sonrası: 1 yapılır
```

### Blok Akışı (Bu Sıra Değişmez)

```
POST /api/v1/response/block
  1. RFC1918 / PROTECTED_CIDRS → 400
  2. FP gate: is_suppressed(ip)? → 409 / force=true ile devam
  3. Severity kontrolü → 422
  4. Duplicate → 409
  5. OPNsense REST → VyOS SSH fallback
  6. DB: blocked_ips (expires_at + offense_count)
  7. audit_log zorunlu
```

### Alembic Migrations

`001` temel şema · `002` blocked_ips · `003` expires_at TIMESTAMPTZ · `004` offense_count DEFAULT 1

---

## GNS3 Lab

```
OPNsense 26.1.2  (10.0.30.1)  ← aktif yanıt hedefi
    │
VyOS rolling     (192.168.203.200 / 10.0.30.2)
    ├── DMZ → Alpine WebServer (10.0.10.2)
    └── LAN → Host1, Host2, Kali (192.168.203.132)
NetGuard Server  (192.168.203.134)
Agent VM         (192.168.203.142)
```

```bash
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.134        # server
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.142        # agent
ssh vyos@192.168.203.200                                  # VyOS (vyos/vyos)
ssh -J netguard@192.168.203.134,vyos@192.168.203.200 root@10.0.30.1  # OPNsense (root/netguard123)
```

**Doğrulanan senaryolar:** Reboot otomasyon ✅ · SSH brute force → WEAPONIZE ✅ · Port scan → RECON ✅ · RECON+WEAPONIZE+ACCESS → FULL_ATTACK_CHAIN + email ✅

---

## Kurallar

### Commit
- Format: `feat(detection):`, `refactor(db):`, `fix(security):`, `docs:`
- Her görev ayrı commit + push
- Testler geçmeden commit atma
- Tamamlanan adım commit sonrası CLAUDE.md'de `[x]` işaretlenir

### Kod
- Yorum yazma — açıklayıcı isimler yeterli
- Error handling sadece sistem sınırlarında (user input, external API)
- Yeni route → `routes/` + `main.py`'a ekle
- Yeni UI sayfası → `dashboard-v2/src/app/(protected)/`
- SQLite-specific syntax yazmaz (GLOB, PRAGMA)
- ECS alanları: `source_ip`, `destination_ip`, `network_protocol`, `observer_hostname`, `event_action`, `event_category`, `source_port`, `destination_port`
- Her yerde `%s` placeholder (dialect flag yok)

### Test
```bash
pytest tests/ -q   # → 1311 passed (21 Mayıs 2026)
```
Test piramidi: birim + çapraz (iki modül arası) + entegrasyon (tam pipeline)

### Agent Altyapısı
`.claude/agents/`: `backend-worker`, `detection-worker`, `frontend-worker`, `quality-auditor`

---

## Kırmızı Çizgiler

| Teklif | Neden Red |
|--------|-----------|
| Vulnerability scanner (OpenVAS/Nessus) | Farklı ürün kategorisi |
| FIM / Rootkit tespiti | EDR alanı |
| Full PCAP desteği | Storage altyapısı gerektirir, kapsam dışı |
| Compliance raporu iyileştirmesi | Sahte skorlama |
| ECS şema değişikliği | V1-1 tamamlandı, dokunma |
| NDR'ye tam dönüşüm | Security Onion zaten var, rekabet edilemez |
