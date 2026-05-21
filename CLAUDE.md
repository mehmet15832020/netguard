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

### AŞAMA 1 — Acil Güvenlik (Bu Hafta)

- [x] **G5** — `routes/active_response.py` → `@limiter.limit("10/minute")` block'a, `"5/minute"` break-glass'a
  - *OWASP API4: rate limiting eksikliği; break-glass JWT bypass yaptığı için özellikle kritik*
  - Bağımlılık: yok — 15 dakikalık iş, G1 öncesi şart

- [x] **G1** — `attack_chain.py` FULL_ATTACK_CHAIN → `active_response_manager.block_ip()` çağrısı
  - *CrowdStrike 2025: ortalama breakout time 48 dakika. Dedektör hazır, plug-in eklemek yeterli*
  - `AUTO_BLOCK_ON_FULL_CHAIN=1` env gate (varsayılan kapalı), `actor = "system/kill_chain"` audit
  - Güvenlik geçitleri korunur: RFC1918 → FP gate → severity gate
  - Bağımlılık: G5 tamamlanmalı

- [x] **G6** — JA4 geçişi (JA3 kaldır)
  - *Chrome 110+ (2023) her bağlantıda farklı JA3 üretiyor — dashboard yanlış veri gösteriyor*
  - `zeek_collector.py` JA4 field, `network_intel` route güncelleme; JA3 backward-compatible tut
  - Bağımlılık: yok

### AŞAMA 2 — Tespit Genişletme (2-3 Hafta)

- [x] **G4** — DNS tunneling sigma kuralları
  - *MITRE ATT&CK T1071.004: APT41/OilRig/Cobalt Group aktif kullanıyor. Zeek DNS zaten akıyor*
  - [x] G4-1: Entropi analizi (base64/hex subdomain) — eşik 4.0 bit, min_label 20 char
  - [x] G4-2: Uzun sorgu (>50 karakter) — [LONG_QUERY:Xc] indikatörü
  - [x] G4-3: NXDOMAIN spike — 2 katmanlı: 30/1m + 100/15m
  - [x] G4-4: TXT sorgu frekansı — `ng_dns_tunnel_base` mevcut (`network_community.yml`)
  - Bağımlılık: yok

- [x] **G3** — Çoklu threat intel
  - *GreyNoise: CISA KEV eklemelerinden %80 önce tespit. Feodo Tracker: aktif C2 listesi (ücretsiz)*
  - [x] G3-1: Feodo Tracker (Emotet/QakBot/AsyncRAT C2) — in-memory cache, 24h refresh
  - [x] G3-2: ThreatFox IOC — per-IP POST API, DB cache
  - [x] G3-3: GreyNoise Community — noise/riot FP filtresi
  - [x] G3-4: Composite score 0-100 — Feodo dominant, noise/riot cap

### AŞAMA 2.5 — Dashboard Görselleştirme

Araştırma kaynakları: Gartner NDR Market Guide 2024, CIS Controls v8 Control 13, NIST SP 800-94,
Security Onion 2.4, Malcolm/CISA, ntopng, Arkime, Grafana Best Practices 2024, ArmorPoint SOC KPIs 2025.

**Uygulama sırası:** Blok A (G1 sonrası, bağımsız) → Blok B (G4/G3 sonrası, bağımlı) → Blok C (ertelenebilir)

#### Blok A — Hızlı Kazanımlar (~2 gün, normalized_logs'tan beslenir)

- [ ] **D5** — Alert Volume Stacked Area Chart
  - `alerts` tablosu GROUP BY hour × severity → critical/high/medium renk kodlaması
  - Overview sayfası, mevcut LogVolumePanel yanına eklenir
  - Bağımlılık: yok

- [ ] **D2** — Protocol Distribution Donut
  - `normalized_logs.network_protocol` GROUP BY → TCP/UDP/DNS/HTTP/SSH/ICMP/diğer
  - *CIS Control 13.6: port/protokol izleme zorunlu*
  - Bağımlılık: yok

- [ ] **D3** — Traffic Volume Area Chart (east-west / north-south ayrımı)
  - RFC1918 kaynak → iç trafik (east-west) vs dış trafik (north-south), stacked area
  - *Gartner NDR zorunlu: çift yönlü görünürlük*
  - Bağımlılık: yok

- [ ] **D1** — Top Talkers Panel
  - Top src IP + top dst IP + top dst port → horizontal ranked bar
  - *ntopng / Malcolm / Arkime hepsinde var — NetGuard'da eksik*
  - Endpoint: `GET /api/v1/analytics/top-talkers?hours=24&limit=20`
  - Bağımlılık: yok

#### Blok B — Bağımlı Dashboard Görselleri (~4-5 gün)

- [ ] **D4** — Kill Chain Swimlane Timeline
  - Mevcut liste → horizontal swimlane: her satır=kaynak IP, sütunlar=RECON/WEAPONIZE/ACCESS/LATERAL/FULL
  - Tamamlanan aşama kırmızı, aktif titreşen; tıkla → log detayı
  - `attack_chain_state` tablosundan beslenir — *G1 bittikten sonra anlamlı*
  - Bağımlılık: G1

- [ ] **D8** — DNS Analiz Derinleştirme
  - Sorgu tipi dağılımı (A/AAAA/MX/TXT/PTR/CNAME), NXDOMAIN trend, entropi yüksek domainler
  - *G4 (DNS tunneling) sigma kuralları olmadan eksik kalır*
  - Bağımlılık: G4

- [ ] **D6** — Threat Intel Geo Harita + Score Dağılımı
  - Choropleth harita: `country_code` → saldırı yoğunluğu; AbuseIPDB score bar chart
  - *G3 (Feodo/ThreatFox/GreyNoise) ile country_code zenginleşirse daha değerli*
  - Bağımlılık: G3 (opsiyonel, mevcut AbuseIPDB verisiyle de başlanabilir)

#### Blok C — Karmaşık Görseller (ertelenebilir)

- [ ] **D7** — East-West Connection Matrix Heatmap
  - Satır=kaynak IP, sütun=hedef IP, hücre=connection sayısı (ısı yoğunluğu)
  - *Gartner NDR zorunlu, Security Onion + Malcolm'da varsayılan olarak yok*
  - Bağımlılık: F4 (anomaly engine entegrasyonu sonrası daha anlamlı)

- [ ] **D9** — Asset Risk Heatmap
  - `asset_baselines`: subnet × gün/saat heatmap, spike renk skalası
  - Bağımlılık: F4

- [ ] **D10** — MTTD/MTTR Metrik Paneli
  - MTTD: `incident.created_at - first_event.timestamp` | MTTR: kapanma süresi
  - *SOC KPI standardı (ArmorPoint, CrowdStrike)*
  - Bağımlılık: incident lifecycle tamamlanmalı

### AŞAMA 3 — Mimari Temizlik (1 Ay)

- [ ] **F2-3** — 9 test dosyasını PG uyumlu hale getir
  - `DatabaseManager(str(path))` → `tmp_db` fixture; Docker yoksa skip
  - Dosyalar: test_database, test_correlator, test_detectors, test_fts_search, test_fp_manager,
    test_asset_baseline, test_cross_domain_correlation, test_log_normalizer, test_pipeline_integration
  - Bağımlılık: yok — ama F2-1/F2-2 için ön koşul

- [ ] **F2-1** — `database.py` → sadece PostgreSQL implementasyonu
  - SQLite `DatabaseManager` sınıfını sil; `database_pg.py` içeriğini merge et
  - Bağımlılık: F2-3

- [ ] **F2-2** — `database_pg.py` kaldır
  - Bağımlılık: F2-1

- [ ] **G2** — Suricata EVE JSON collector
  - *CIS Controls v8.1 Safeguard 13.8 zorunlu. Zeek behavioral + Suricata imza = altın standart NSM*
  - `server/suricata_collector.py` (zeek_collector.py pattern), EVE JSON → normalized_logs, 5+ sigma kuralı
  - Bağımlılık: F2 tamamlanmış olursa testler güvenilir

- [ ] **F3** — Ham SQL → DB metodları (5 modül)
  - correlator.py → `db.get_normalized_logs_for_rule()`
  - asset_baseline.py, retention.py, routes/mitre.py, routes/network_intel.py
  - Bağımlılık: F2 (PG-only, `%s` sabit)

- [ ] **F4** — Anomaly engine → kill chain entegrasyonu
  - *Gartner NDR: ML anomaly behavioral context içinde değerlendirilmeli*
  - `anomaly/engine.py`: threshold aşınca `CorrelatedEvent` üret → `attack_chain_tracker.record()`
  - `event_action = "anomaly_spike"`, severity dynamic
  - Bağımlılık: bağımsız; G2 sonrası yapılırsa 3 kaynak (Zeek + Suricata + ML) birlikte akar

- [ ] **F2-6** — Alembic: DATABASE_URL zorunlu olduğunda migration notları güncelle

### AŞAMA 4 — Derinleştirme (2-3 Ay)

- [ ] **T2-3** — MFA (TOTP) — `auth.py`'a pyotp entegrasyonu
  - *Verizon DBIR 2025: kimlik bilgisi hırsızlığı tüm ihlallerin %32'si. NIS2 Article 21(2)(i)*

- [ ] **U3** — Tamperproof audit log (SHA-256 zinciri)
  - Her `audit_log` kaydı önceki kaydın hash'ini içerir
  - *NIST SP 800-92 §3.2: log bütünlüğü koruması temel gereklilik. T2 ticari ön koşulu*
  - Bağımlılık: F2 (PG atomik yazma garantisi)

- [ ] **U4** — Beaconing detection (NetFlow inter-arrival time)
  - *MITRE ATT&CK T1071: C2 implantları ±%10-15 jitter ile düzenli iletişim kurar*
  - Bağımlılık: F4 (anomaly pipeline hazırsa kill chain'e beslenebilir)

- [ ] **U2** — Sysmon entegrasyonu
  - *Verizon DBIR 2025: saldırıların %74'ü kimlik bilgisi içeriyor*
  - EVTX parser mevcut — event 4624/4625/4768/4769 mapping ekle

- [ ] **U1** — East-West görünürlük (L3 switch NetFlow)
  - *Gartner NDR: lateral movement iç ağda gerçekleşiyor, perimeter kör nokta*
  - NetFlow altyapısı mevcut; GNS3 L3 switch konfig gerekir

- [ ] **T2-5** — Sistematik rate limiting middleware (tüm endpoint'ler)
  - G5 point fix'ini genelleştirir; bağımlılık: G5

- [x] **Frontend** — Block verify panel (P6) ✓, Break-glass butonu (P8) ✓ — Port/protocol input (P7) kaldı

### AŞAMA 5 — Ticari Hazırlık (6-12 Ay, Teknikle Paralel)

- [ ] **U5** — SOAR entegrasyonu (TheHive/Shuffle) — bağımlılık: U3 + F4
- [ ] **U6** — Multi-tenant PostgreSQL RLS — bağımlılık: F2 + U3 + T1
- [ ] **T1** — Hukuki altyapı (şirket, sözleşme, KVKK DPA, Tech E&O sigortası, SGB)
- [ ] **T2** — Teknik ticari (T2-1 tamperproof, T2-2 at-rest şifreleme, T2-3 MFA, T2-4 RLS, T2-5 rate limiting)
- [ ] **T3** — Sertifikasyon (pentest + SOC 2 Type I) — bağımlılık: T2
- [ ] **T4** — Pazar hazırlığı (3 pilot müşteri, MSSP ortaklığı, pricing sayfası) — bağımlılık: T1+T2+T3

### Küçük Kod Sorunları (Herhangi Bir Anda)

- [ ] `correlator.py:178` — Yanıltıcı yorum `"JSON + sigma_v1 YAML"` → `"JSON korelasyon kuralları"`
- [ ] `correlator.py:244` — Sessiz `except: pass` → `logger.debug("ws broadcast: %s", exc)`

---

## Tamamlanan Fazlar

| Faz | İçerik | Commit |
|-----|--------|--------|
| **FAZ 1** | Sigma V1 kaldır, pySigma v2 tek engine | `455dced` |
| **FAZ 2a** | `_IS_PG/_PH` dialect flag 6 modülden kaldırıldı, `LogStore` eklendi | `6187e0d` |
| **V1-1..V1-9** | ECS rename, DNS resolver, pySigma, enrichment, baseline, FP, PostgreSQL, Zeek, aktif yanıt | çeşitli |
| **P1-P8** | RFC1918, TTL, FP gate, severity gate, progressive TTL, verify, port/protocol, break-glass | çeşitli |
| **GNS3 Lab** | PostgreSQL kurulum, Alembic migrasyon, API key, dashboard build, topoloji bağlantıları | çeşitli |

**Test durumu:** 1151 test, 0 hata (17 Mayıs 2026)

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
pytest tests/ -q   # → 1151 passed (16 Mayıs 2026)
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
