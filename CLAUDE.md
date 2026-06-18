# NetGuard — Claude Rehberi

Bu dosya Claude Code'un her oturumda otomatik okuduğu proje rehberidir.
Tamamlanan adımlar `[x]` ile işaretlenir.

---

## Ürün Kimliği

**NetGuard: Orta ölçekli şirketler için açık kaynak NSM (Network Security Monitoring) platformu.**

> "Splunk 50K$/yıl. QRadar 30K$/yıl. NetGuard: açık kaynak, Docker ile 30 dakikada kurulum."

- **Hedef kitle:** 50–500 çalışanlı, siber güvenlik bütçesi kısıtlı şirketlerin IT yöneticileri
- **Rekabet konumu:** Wazuh endpoint/HIDS odaklı → NetGuard network/NSM odaklı (bu gap gerçek)
- **Ne değildir:** Wireshark (PCAP), Zabbix (NMS), Splunk (log), Wazuh (EDR), Darktrace (full NDR), CloudSIEM
- **NSM kapsamı:** Ağ trafiği toplama + davranışsal analiz + imza tespiti + akış korelasyonu + alert + sınırlı IP blokajı. Full NDR (cloud entegrasyon, UEBA, otomatik playbook) değildir.

> **Pozisyonlama kararı (6 Haziran 2026 — Seçenek A):** NetGuard saf NSM platform olarak konumlandırıldı. Cloud log parser (N9), UEBA (N10), Arkime PCAP (N11) kapsam dışı veya ertelenmiş. IP blokajı NSM'in yardımcı özelliğidir, NDR'ın tanımlayıcı özelliği değildir.

---

## Mimari

```
COLLECT                      DETECT                       RESPOND
───────                      ──────                       ───────
Syslog (firewall)            JSON korelasyon motoru        Incident yönetimi
SNMP v2c/v3                  pySigma v2 (50+ kural)        Kill chain timeline
NetFlow v5/v9/IPFIX/sFlow    Kill chain (5 aşama)          Email + webhook
pyshark (SYN/BPF)            IsolationForest anomaly       OPNsense REST blok
Agent (psutil)               MITRE ATT&CK mapping          VyOS SSH fallback
Zeek TAP (14 log tipi)       ARP/DNS/ICMP/port_scan det.   Audit log
Suricata EVE JSON            Beaconing (IAT/C2)
EVTX (Windows 60+ EID)       Threat intel (composite 0-100)
OpenCanary (honeypot)        Community ID pivot (C1)
Windows Agent (5 kanal)
CISA KEV, M365, Workspace
```

**Pipeline:** Kaynak → `normalized_logs` → correlator/detectors → kill chain → incident → aktif yanıt

---

## Veritabanı Mimarisi

| Ortam | Veritabanı | Koşul |
|-------|-----------|-------|
| Production | PostgreSQL 16 + TimescaleDB (O1 tamamlandı) | `DATABASE_URL` env set |
| Test (tmp_db / pg_db) | PostgreSQL + TimescaleDB (testcontainers) | Docker daemon erişilebilir |

**Durum:** `database.py` PostgreSQL-only (`database_pg.py` kaldırıldı — F2-1/F2-2). VM'de TimescaleDB kurulu, `normalized_logs` hypertable (received_at/1d, compression 7d).

---

## Mimari Kararlar

- **Event pipeline:** Her kaynak → `normalized_logs` (tek merkezi tablo)
- **Sigma engine:** Yalnızca pySigma v2 — `config/sigma_rules_v2/` (14 dosya, 50+ kural)
- **Korelasyon:** JSON (`correlation_rules.json`) + pySigma v2 — iki katmanlı
- **Token:** `verify_token(token, token_type=)` — tip karıştırma engeli
- **API key:** SHA-256 hash saklanır, plaintext asla DB'ye yazılmaz
- **Aktif yanıt:** OPNsense REST → VyOS SSH fallback, audit log zorunlu
- **Blok güvenlik geçitleri:** RFC1918 → FP gate → severity gate → duplicate gate (bu sıra değişmez)
- **Progressive TTL:** `_progressive_ttl(offense_count)` — 1h / 4h / 24h / 168h
- **Break-glass:** `BREAK_GLASS_TOKEN` env — JWT bypass, sadece unblock
- **Placeholder:** Her yerde `%s` — dialect flag yok
- **dict_row:** `row["kolon"]` kullan, `row[0]` asla
- **Community ID:** Zeek/Suricata/NetFlow aynı TCP bağlantısını `community_id` üzerinden pivot eder — `normalized_logs.community_id VARCHAR(50)` (C1 tamamlandığında)

---

## Yol Haritası — Öncelik Sırası

Araştırma kaynakları: CrowdStrike 2025, Verizon DBIR 2025, MITRE ATT&CK v17, CIS Controls v8.1, NIST SP 800-94, OWASP API Security 2023, Gartner NDR Market Guide 2025, SANS NSM Course, Corelight Community ID Spec.

### AŞAMA 1 — Acil Güvenlik (Tamamlandı)

- [x] **G5** — `routes/active_response.py` rate limiting (`10/minute` block, `5/minute` break-glass)
- [x] **G1** — FULL_ATTACK_CHAIN → otomatik IP bloklama (`AUTO_BLOCK_ON_FULL_CHAIN=1`)
- [x] **G6** — JA4 geçişi (JA3 legacy fallback, entropi threshold 4.0, FP regression testleri)

### AŞAMA 2 — Tespit Genişletme (Tamamlandı)

- [x] **G4** — DNS tunneling: entropi (4.0 bit), uzun sorgu (>50c), NXDOMAIN 2 katmanlı spike
- [x] **G3** — Çoklu threat intel: Feodo Tracker + ThreatFox + GreyNoise + composite score 0-100

### AŞAMA 2.5 — Kritik Tespit Eksikleri (Tamamlandı)

- [x] **G2** — Suricata EVE JSON collector
  - **Teslim:** `server/parsers/suricata.py` (9 event_type parser), `server/suricata_collector.py` (inode rotation-safe offset), `config/sigma_rules_v2/suricata_ids.yml` (6 kural), 60 test ✓

- [x] **U2** — Sysmon / Windows HIDS entegrasyonu
  - **Teslim:** `evtx_parser.py` 12 EID (Sysmon 1/3/10/22 + Security 4648/4720/4732/4768/4769); `parsers/windows.py` NormalizedLog dönüşümü; `routes/evtx.py` normalized_logs yazımı; 8 Sysmon sigma kuralı; 39 test ✓

- [x] **F4** — Anomaly engine → kill chain entegrasyonu
  - **Teslim:** `engine.py` anomaly → `chain_trigger_to_correlated_event()`, FULL_ATTACK_CHAIN alert/auto-block; 1311 toplam test ✓

- [x] **G7** — Suricata Tespit Katmanı Genişletme
  - **Teslim:** `parsers/suricata.py` HTTP/TLS/SSH anomaly; `suricata_ids.yml` 4 yeni kural; STAGE_MAP 3 yeni giriş; 51 test ✓

---

### AŞAMA 2.6 — Dashboard Görselleştirme (Tamamlandı)

#### Blok A — Hızlı Kazanımlar

- [x] **D1** — Top Talkers Panel — `GET /api/v1/analytics/top-talkers`; 20 test ✓
- [x] **D5** — Alert Volume Stacked Area Chart — `GET /api/v1/analytics/alert-volume`; 23 test ✓
- [x] **D2** — Protocol Distribution Donut — `GET /api/v1/analytics/protocol-distribution`; 20 test ✓
- [x] **D3** — Traffic Volume Area Chart (east-west/north-south) — `GET /api/v1/analytics/traffic-volume`; 21 test ✓

#### Blok B — Bağımlı Dashboard Görselleri

- [x] **D4** — Kill Chain Swimlane Timeline — SVG swimlane, saat seçici; 17 test ✓
- [x] **D8** — DNS Analiz Derinleştirme ✓
- [x] **D6** — Threat Intel Geo Harita + Composite Score ✓

#### Blok C — Karmaşık Görseller

- [x] **D7** — East-West Connection Matrix Heatmap — ECharts heatmap; 20 test ✓
- [x] **D9** — Asset Risk Heatmap — 3 risk boyutu; 21 test ✓
- [x] **D10** — MTTD/MTTR Metrik Paneli — SLA uyumu (SANS 2023); 27 test ✓

### AŞAMA 3 — Güvenlik Derinleştirme (Tamamlandı)

- [x] **U3** — Tamperproof audit log (SHA-256 zinciri) — NIST SP 800-92 §3.2; 24 test ✓
- [x] **U4** — Beaconing detection (C2 inter-arrival time) — IAT algoritması, Bessel stddev; 35 test ✓
- [x] **T2-3** — MFA / TOTP — pyotp, Alembic 010; 30 test ✓

### AŞAMA 4 — Mimari Temizlik (Tamamlandı)

- [x] **F2-1** — `database.py` → sadece PostgreSQL (SQLite sınıfı silindi)
- [x] **F2-2** — `database_pg.py` kaldırıldı
- [x] **F2-3** — 9 test dosyasını PG uyumlu hale getir (`tmp_db` fixture); 1914 test ✓
- [x] **F3** — Ham SQL → DB metodları (8 yeni DatabaseManager metodu); 28 raw SQL kaldırıldı ✓
- [x] **F2-6** — Alembic migration notları güncellendi (DATABASE_URL zorunlu)

### AŞAMA 4.5 — Kural Yönetimi UI (Tamamlandı)

- [x] **R1** — Korelasyon Kuralları CRUD UI — 5 endpoint, atomik yazma, 50 test ✓
- [x] **R2** — Sigma Rule Wizard — 4 adımlı form, TypeScript YAML üretici; 28 test ✓
- [x] **R3** — Sigma YAML Monaco Editör — `@monaco-editor/react`; 16 test ✓

### AŞAMA 2.7 — Dashboard Modernizasyon (Tamamlandı)

- [x] **Sprint 1+2** — Deep Navy Visual Identity + Hover-Expand Sidebar
  - `#060c17` bg, `#0d1526` panel, cyber cyan primary (sky-400), dot-grid texture, glow utilities
  - VS Code hover-expand (48px → 228px overlay, localStorage pin), gradient logo badge
- [x] **Sprint 3** — Overview Bento Grid Layout (6 asimetrik zona, 12-col CSS grid)
  - Zone A: StatCards + KPI (grid-cols-3) · Zone B: Alert Trend + [Threat Intel + Kill Chain]
  - Zone C: Topology + [Risk Assets + MTTD] · Zone D: 3×4 mini paneller
  - Zone E: Agents + Alerts + Protocol Donut · Zone F: Traffic Volume full-width
  - **CSS Grid notu:** KPI grid-cols-2 → 3 satır (~250px), StatCards ~90px → Zone A gap. grid-cols-3 = 2 satır (~170px), dengeli.
- [x] **Sprint 4** — ECharts Tema Merkezileştirme (`src/lib/echarts-theme.ts`) — 10 chart, 10 sayfa ✓
- [x] **Sprint 5** — Badge Glassmorphism + Skeleton Loading — 20 sayfa, shimmer animation ✓
- [x] **Sprint 6** — Ctrl+K Command Palette — 39 komut, 6 bölüm, Zustand store ✓

### AŞAMA 4.6 — Mimari Sağlamlaştırma (Tamamlandı)

#### Kritik Buglar
- [x] **B1** — Agent SecurityEvents → `normalized_logs`'a yazılmıyor; 14 test ✓
- [x] **B2** — `GET /agents` rate limit yok → `@limiter.limit("120/minute")` ✓
- [x] **B3** — Silent `except` kill chain dispatch'i kesiyor → `logger.warning` ✓

#### Mimari Bütünleşme
- [x] **A1** — BeaconingDetector `DetectorManager`'a entegre; 9 test ✓
  - **Mimari karar:** Beaconing 300s cadence korundu (RITA BlackHat 2018); `run_beaconing()` `run_all()`'dan ayrı (C2 tespiti 60s correlator gecikmesini kaldıramaz)
- [x] **A2** — `log_store.count_by_group()` implement — OWASP A3 whitelist; 16 test ✓
- [x] **A3** — Lateral movement 28 test — TOCTOU fix, thread safety ✓

#### Operasyonel Hazırlık
- [x] **O1** — TimescaleDB production VM kurulumu — hypertable received_at/1d, compression 7d; 20 test ✓
- [x] **O2** — Docker Compose tek kurulum paketi — 6 servis, CIS resource limits; 47 test ✓
- [x] **O3** — Backup/restore prosedürü — RPO ~24s, RTO ~30dk (NIST SP 800-34); 52 test ✓

#### Tespit Genişletme
- [x] **D1** — NetFlow Sigma kuralları — 6 kural (Large Flow/Suspicious Port/Tunnel burst); 34 test ✓
- [x] **D2** — `network_bytes` Zeek + Suricata parser'larına eklendi; 23 test ✓

#### İleri Özellikler (Baklog)
- [x] **F1** — Sigma Rule Backtest Engine — 23 test ✓
- [x] **F2** — Live Log Stream (WebSocket + TanStack Virtual) — 6 test ✓
- [x] **F3** — MITRE ATT&CK Navigator matrix + coverage gap analizi — 19 test ✓
- [x] **F4** — AI Alert Explainer (Groq Llama 3.3 70B, 24h cache) — 24 test ✓
- [x] **F5** — Threat Hunt Workbench (no-code sorgu builder, saved hunts) — 33 test ✓

---

### AŞAMA 4.7 — NSM Veri Kapsamı Genişletme (Tamamlandı)

> Mevcut skor: 62/100 → P1+P2 tamamlanınca ~92/100 (Security Onion eşdeğer seviyeye yakın).

#### P1 — Kısa Vadeli (Tamamlandı)

- [x] **N1** — Windows EID 12 → 60+ EID (5 kanal: Security/Sysmon/PowerShell/System/AppLocker)
  - **Teslim:** `agent/windows_log_shipper.py` 5 kanal, `parsers/windows.py` 18 yeni action; STAGE_MAP 18 giriş; 37+19 test ✓
- [x] **N2** — Zeek weird.log + dpd.log + files.log — STAGE_MAP 20 yeni giriş; 50 test ✓
- [x] **N3** — Honeypot (OpenCanary) — 12 logtype, STAGE_MAP 12 giriş; 7+2 Sigma kural ✓
- [x] **N4** — Suricata ET Otomatik Kural Güncelleme — 45,343 kural aktif, systemd timer ✓
- [x] **N5** — Zeek RDP + Kerberos + SMB/DCE-RPC — 4 parser + Sigma; STAGE_MAP ✓
- [x] **W1-A** — Windows Agent Hızlı Demo — WIN-9DUCSU7LDJ0 (192.168.203.150) aktif ✓
- [x] **W1-B** — Windows Agent Tam (5 kanal, 60+ EID) ✓
- [x] **E1** — E-posta Bildirim Kalitesi — severity cooldown, HTML multipart ✓

#### P2 — Orta Vadeli (Tamamlandı)

- [x] **N6** — IPFIX/NetFlow v10 + sFlow ✓
- [x] **N7** — Kural Kalitesi + CISA KEV Entegrasyonu ✓
- [x] **N8** — Microsoft 365 + Google Workspace — `collectors/m365_collector.py` + `collectors/gworkspace_collector.py` + `parsers/cloud.py` ✓

#### P3 — Stratejik (Kapsam Kararı Verildi)

- [ ] **N9** — ❌ KAPSAM DIŞI (Cloud SIEM alanı, NSM değil — 6 Haziran 2026 kararı)
- [ ] **N10** — UEBA Temeli — 60-90g veri gerektirir; **Bağımlılık:** N1 + 60g üretim verisi; **KVKK:** DPO onayı zorunlu
- [ ] **N11** — Arkime Tam PCAP — Ayrı donanım: KOBİ 100-500 Mbps → 7-35 TB SSD; mevcut VM yetmez

---

### AŞAMA 4.8 — NSM Çekirdek Güçlendirme (Haziran 2026 — Onaylandı)

> **NSM referans mimarisine göre (SANS NSM, Malcolm/CISA, Security Onion) en kritik eksik:** Zeek + Suricata + NetFlow kayıtları arasında aynı TCP bağlantısını pivot eden Community ID yok. Bu olmadan üç kaynağın aynı olayı farklı kayıtlarda görmesi mümkün değil.

- [x] **C1** — Community ID cross-source korelasyon — 33 test ✓
  - **Teslim:** Alembic 018, `communityid` paketi, 16 Zeek + 9 Suricata + v5/v9/IPFIX/sFlow NetFlow parser, `get_logs_by_community_id()`, `GET /api/v1/logs/by-community-id/{cid:path}`
    - Frontend: Alert detay → Community ID göster + pivot butonu (aynı akışın Zeek/Suricata/NetFlow kayıtları)
  - **Beklenen:** ~25-30 test

- [x] **C2** — Alert → bağlam pivot workflow — 12 test ✓
  - **Teslim:** `get_event_context_logs()`, `GET /api/v1/correlation/events/{id}/context`, Correlation sayfasında ContextPanel (kaynak sekmeleri + CID pivot)

- [x] **C3** — Network behavioral baseline genişletme — 15 test ✓
  - **Teslim:** Alembic 019 `typical_protocols`, `get_distinct_values_by_ip()`, `new_port_detected` + `new_protocol_detected` anomali tespiti (NIST SP 800-94 §4.1)

- [x] **C4** — Sensor sağlık metrikleri — 32 test ✓
  - **Teslim:** `server/sensor_health.py` (Zeek JSON/TSV, Suricata EVE stats, psutil arayüz), `GET /api/v1/health/sensors`, Overview `SensorHealthPanel` (Zone D 4. panel)
  - CIS Control 13.1: Zeek `pkt_drop_rate`, Suricata `capture_kernel_drops`, 5%/15% uyarı/kritik eşikleri

---

### AŞAMA 5 — Ticari Hazırlık (6-12 Ay, Teknikle Paralel)

- [ ] **U5** — SOAR entegrasyonu (TheHive/Shuffle) — `notifier.py` webhook VAR ✓; TheHive endpoint YOK
- [x] **U6** — Multi-tenant PostgreSQL RLS — Alembic 021, 11 tablo, `_connect_as_tenant()`, 15 test ✓
- [x] **U1** — East-West görünürlük (L3 switch NetFlow) — VyOS NetFlow v9 aktif, 146.490+ kayıt ✓
- [ ] **T1** — Hukuki altyapı (şirket, KVKK DPA, Tech E&O sigortası)
- [ ] **T2** — Teknik ticari (T2-1 tamperproof ✓U3, T2-2 at-rest şifreleme ✓, T2-3 MFA ✓T2-3, T2-4 RLS ✓U6, T2-5 rate limiting ✓T2-5)
- [ ] **T3** — Sertifikasyon (pentest + SOC 2 Type I) — Bağımlılık: T2
- [ ] **T4** — Pazar hazırlığı (3 pilot müşteri, MSSP ortaklığı) — Bağımlılık: T1+T2+T3
- [x] **T2-5** — Sistematik rate limiting middleware — SlowAPI `default_limits=["60/minute"]`; 27 test ✓

### Küçük Kod Sorunları (Herhangi Bir Anda)

- [x] `correlator.py:178` — Yanıltıcı yorum düzeltildi ✓
- [x] `correlator.py:244` — Sessiz `except: pass` → `logger.debug` ✓
- [x] **Frontend** — Block verify panel (P6) ✓, Break-glass butonu (P8) ✓, Port/protocol input (P7) ✓
- [x] **Windows Sigma FP** — 4 korelasyon kuralında `group-by: source_ip` → `observer_hostname` (EID 4688/Sysmon 1/4776/Sysmon 22 kaynaklı event'lerde source_ip her zaman None); commit db46ca4 ✓
- [x] **U2 FP — EID 4672 SeImpersonate + PowerShell keyword tier** — SeImpersonatePrivilege `high_risk`'ten çıkarıldı (yalnızca SeDebugPrivilege/SeTcbPrivilege critical); NT SERVICE\/NT AUTHORITY\/WINDOW MANAGER\ is_system'e eklendi. `_PS_DANGEROUS` iki katmana ayrıldı: `_PS_CRITICAL_KEYWORDS` (mimikatz/reflectivepe/sekurlsa/dcsync vb.) → critical, `_PS_SUSPICIOUS_KEYWORDS` (iex/bypass/-enc/downloadstring vb.) → warning. Sigma `filter_system` NT SERVICE\/NT AUTHORITY\/WINDOW MANAGER\ eklendi. 16 yeni test; 94 test ✓
- [x] **Tehdit Skoru FP Azaltma (17 Haziran 2026)** — Kill chain eşik kalibrasyonu ve gürültülü STAGE_MAP temizliği:
  - `CHAIN_WINDOW_SEC` 1800→3600s (IBM QRadar/Splunk ESCU/Sentinel standardı)
  - `FULL_THRESHOLD` 3→4 + recon zorunlu (Splunk ESCU "Critical Kill Chain" — 4 aşama)
  - 13 gürültülü STAGE_MAP girişi kaldırıldı: `dns_query`, `sflow_flow`, `rdp_session_disconnect`, `interface_link_down`, `bgp_state_change`, `ospf_state_change`, `route_change`, `windows_fw_block`, `zeek_smb_open`, `zeek_smb_operation`, `zeek_smb_share_mapped`, `zeek_dce_rpc_operation`
  - U3: `multi_source_attack` kuralına `require_external_source_ip: true` — RFC1918 yönetim IP'lerinin koordineli saldırı tetiklemesi önlendi
  - O3: Yeni incident açmak için `severity∈{high,critical}` VEYA `matched_count≥3` zorunlu
  - `MIN_SAMPLE_HOURS_FOR_DEVIATION` 1→24 (SANS NSM/RITA/Security Onion standardı)
  - Port scan Sigma: timespan 2m→60s, eşik 10→15 (Snort ET sid:1228 / Zeek notice.bro standardı)
  - `analytics.py _FULL_THRESHOLD` senkronize edildi → 4

---

## Tamamlanan Fazlar

| Faz | İçerik | Commit |
|-----|--------|--------|
| **FAZ 1** | Sigma V1 kaldır, pySigma v2 tek engine | `455dced` |
| **FAZ 2a** | `_IS_PG/_PH` dialect flag 6 modülden kaldırıldı, `LogStore` eklendi | `6187e0d` |
| **V1-1..V1-9** | ECS rename, DNS resolver, pySigma, enrichment, baseline, FP, PostgreSQL, Zeek, aktif yanıt | çeşitli |
| **P1-P8** | RFC1918, TTL, FP gate, severity gate, progressive TTL, verify, port/protocol, break-glass | çeşitli |
| **GNS3 Lab** | PostgreSQL kurulum, Alembic migrasyon, API key, dashboard build, topoloji bağlantıları | çeşitli |

**Test durumu:** ~3300+ test (18 Haziran 2026 sonrası, improvement_todos maddeleri eklendi)

---

## Mevcut Envanter

### Backend Modülleri

| Dosya | Rol |
|-------|-----|
| `server/active_response.py` | OPNsense REST + VyOS SSH IP bloklama (P1-P8) |
| `server/alert_engine.py` | Ajan alert motoru |
| `server/alert_explainer.py` | Groq Llama 3.3 70B, 24h cache, prompt injection isolation |
| `server/anomaly/` | IsolationForest + Welford — kill chain entegre (F4) |
| `server/asset_baseline.py` | Per-IP 7 günlük davranış profili + spike |
| `server/attack_chain.py` | Kill chain (RECON/WEAPONIZE/ACCESS/LATERAL/FULL) |
| `server/agent_pki.py` | Agent mTLS CA üretimi + client sertifika imzalama (A3) |
| `server/auth.py` | JWT access/refresh + API key (SHA-256) + agent mTLS doğrulama |
| `server/compliance.py` | 26 güvenlik kontrolü |
| `server/config_monitor.py` | Konfigürasyon değişiklik tespiti |
| `server/correlator.py` | 60s döngü, JSON + pySigma v2 |
| `server/database.py` | PostgreSQL-only (F2-1); factory: PG prod / testcontainers test |
| `server/detectors/` | port_scan, arp, dns, icmp, lateral, beaconing (A1) |
| `server/dhcp_baseline.py` | IP→MAC değişim tespiti — Zeek (C1) + firewall syslog (F1) paylaşır |
| `server/parsers/firewall.py` | pfSense/OPNsense/ASA/FortiGate/VyOS + DHCP syslog (F1) + DNS resolver syslog (F2) + yönetim erişimi (F3: admin login success/failure, VyOS SSH bağlam düzeltmesi) |
| `server/discovery/` | fingerprinter.py + subnet_scanner.py |
| `server/dns_resolver.py` | PTR lookup, TTL cache (300s/60s) |
| `server/evtx_parser.py` | Windows EVTX — 60+ EID (Security/Sysmon/PowerShell/System/AppLocker) |
| `server/fp_manager.py` | False positive suppression (CIDR + 30gün TTL) |
| `server/host_traffic.py` | Agent trafik paneli — Zeek+NetFlow tabanlı agregasyon (B4, pyshark agent collector yerine) |
| `server/incident_enricher.py` | MITRE + related logs + threat intel |
| `server/incident_priority.py` | Severity formula, priority_score |
| `server/influx_writer.py` | InfluxDB metrics yazıcı |
| `server/log_normalizer.py` | syslog/netflow/zeek/agent/EVTX parser |
| `server/log_store.py` | LogStore Protocol + PostgreSQLLogStore |
| `server/mitre.py` | MITRE ATT&CK yardımcı modülü + Navigator layer |
| `server/netflow_receiver.py` | NetFlow v5/v9/IPFIX UDP 2055 |
| `server/notifier.py` | Email (HTML+plain MIME, severity cooldown) + webhook, retry |
| `server/ntp_validator.py` | Log timestamp NTP doğrulama |
| `server/port_monitor.py` | Yerel port değişiklik tespiti |
| `server/retention.py` | hot/warm/cold veri tutma |
| `server/security_log_parser.py` | auth.log parser (SSH/sudo/PAM) |
| `server/sigma_executor.py` | pySigma v2, 50+ çalıştırılabilir kural |
| `server/snmp_auth.py` | SNMP auth helper |
| `server/snmp_collector.py` | SNMP v2c/v3 poll + trap — interface octet/hata sayaçları `SNMP_COLLECT_INTERFACE_STATS=true` ile (D2, varsayılan kapalı — NetFlow zaten kapsıyor) |
| `server/snmp_trap_receiver.py` | SNMP trap UDP alıcısı |
| `server/storage.py` | RAM snapshot cache (metrics/health) |
| `server/suricata_collector.py` | Suricata EVE JSON (inode rotation-safe) |
| `server/syslog_receiver.py` | UDP syslog alıcı + TCP (RFC 6587) / TLS (RFC 5425) — B3 |
| `server/threat_intel.py` | AbuseIPDB + Feodo + ThreatFox + GreyNoise composite 0-100 |
| `server/uptime_checker.py` | Cihaz uptime / ICMP ping |
| `server/ws_manager.py` | WebSocket bağlantı yöneticisi |
| `server/zeek_collector.py` | Zeek log tail (21 log tipi: conn/dns/http/ssl/ssh/notice/smtp/ftp/rdp/kerberos/smb/dce_rpc/weird/dpd/files/dhcp/tunnel/pe/smb_mapping/software/ntp) + inotify (B2) |
| `server/parsers/` | zeek.py, suricata.py, netflow.py, windows.py, opencanary.py, cloud.py, firewall.py, web_log.py |
| `server/collectors/` | m365_collector.py, gworkspace_collector.py, kev_monitor.py |

### Route'lar (31 dosya)

| Grup | Dosyalar |
|------|---------|
| Güvenlik çekirdeği | auth, incidents, active_response, sigma, correlation, mitre, attack_chains |
| Veri toplama | logs, alerts, agents, devices, snmp, netflow, evtx, hunts |
| Analiz | network_intel, anomaly, assets, fp_rules, threat_intel, topology, analytics |
| Platform | health, metrics, maintenance, compliance, security, reports |
| Altyapı | discovery, tenants, ws |

### Sigma Kuralları (`config/sigma_rules_v2/` — 14 dosya)

`anomaly_and_impact`, `auth_and_web`, `c2_and_exfil`, `device_and_snmp`, `network_community`, `netflow`, `opencanary`, `port_scan`, `sql_injection`, `ssh_brute_force`, `suricata_ids`, `web_attacks`, `windows_events`, `zeek_advanced`

### Alembic Migrations

`001` temel şema · `002` blocked_ips · `003` expires_at TIMESTAMPTZ · `004` offense_count DEFAULT 1 · `005` threat_intel kolonlar · `006` audit_log SHA-256 zinciri · `007` alerts tenant+time index · `008` norm_logs tenant+received index · `009` network_bytes · `010` totp_secret+enabled · `011` analytics indexes · `012` totp secrets şifreleme · `013` TimescaleDB hypertable · `014` alert_explanations · `015` saved_hunts · `016` anomaly_tables · `017` kev_entries · **`018` community_id (C1 ✓)** · `019` asset_baseline_protocols · **`020` audit_log at-rest şifreleme (T2-2 ✓)** · **`021` RLS tenant isolation (U6 ✓)** · **`022` agent_certificates (A3 ✓)** · **`023` dhcp_mac_history (yapılacaklar-C1 ✓)** · **`024` asset_baseline detected_software (yapılacaklar-C5 ✓)**

### Frontend Sayfaları (dashboard-v2)

Overview (bento grid), Logs (live stream), Incidents, Aktif Bloklar, Alerts, Agents, Correlation (AI Explainer), Network Intelligence, MITRE ATT&CK (Navigator), Timeline (Kill Chain), Topology, Devices/SNMP/Discovery, Settings/Audit, Reports/Security, Uyumluluk, Threat Hunt, Sigma Rules/Wizard/Editor, Correlation Rules, Top Talkers, Alert Volume, Protocol Distribution, Traffic Volume, East-West Matrix, Asset Risk, MTTD/MTTR

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
AUTO_BLOCK_ON_FULL_CHAIN=0     # 1 yapınca otomatik blok açılır
GROQ_API_KEY=<key>             GROQ_MODEL=llama-3.3-70b-versatile
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

---

## Çevre Firewall NetFlow Yapılandırması (F4 — 16 Haziran 2026)

`server/netflow_receiver.py` zaten v5/v9/IPFIX/sFlow destekliyor (UDP 2055) — eksik olan firewall tarafının NetFlow göndermeye yapılandırılması. VyOS LAN tarafında zaten aktif (146.490+ kayıt); İnternet↔DMZ trafiği WAN tarafındaki firewall'dan (OPNsense/FortiGate/ASA) geçtiği için o taraf da yapılandırılmalı.

**Erişim notu:** Bu görev sırasında OPNsense'e programatik erişim denendi — SSH sadece publickey kabul ediyor (uygun key yok), `.env`'deki `OPNSENSE_KEY`/`OPNSENSE_SECRET` boş (yapılandırılmamış). Aşağıdaki adımlar bu yüzden uygulanmadı, dokümante edildi — VNC konsol (localhost:5901) veya web UI üzerinden manuel uygulanmalı.

### OPNsense (26.1.2)

**Araştırma düzeltmesi:** Orijinal not "os-softflowd eklentisi" diyordu — bu pfSense'in eski yaklaşımı. Modern OPNsense'de **native `os-netflow` eklentisi** var, softflowd gerekmiyor (docs.opnsense.org doğrulandı):

1. **System → Firmware → Plugins** → `os-netflow` kur
2. **Services → Netflow → Settings**:
   - Enable Netflow: ✓
   - Listen Interfaces: WAN arayüzü (DMZ↔İnternet trafiğini gören arayüz)
   - Destination: `192.168.203.134:2055`
   - Version: **9** (v5 IPv6 desteklemiyor)
3. Save → Apply

### FortiGate

```
config system netflow
    set collector-ip 192.168.203.134
    set collector-port 2055
    set source-ip <fortigate-source-ip>
    set active-flow-timeout 1
    set inactive-flow-timeout 15
end
```
(docs.fortinet.com doğrulandı)

### Cisco ASA (NSEL — NetFlow Secure Event Logging)

ASA'da NetFlow, MPF (Modular Policy Framework) service policy'sine bağlanmadan çalışmaz — sadece `flow-export destination` yeterli değil:

```
flow-export destination inside 192.168.203.134 2055
flow-export template timeout-rate 1
class-map flow_export_class
  match any
policy-map global_policy
  class flow_export_class
    flow-export event-type all destination 192.168.203.134
service-policy global_policy global
```
(Cisco resmi NSEL konfigürasyon kılavuzu doğrulandı — ASA NetFlow'u "NSEL" olarak adlandırır, klasik NetFlow değil, security-event odaklı bir varyanttır)

### VyOS

Zaten aktif ✓ — `set service netflow` LAN tarafında yapılandırılmış, referans için bakılabilir.

---

## WebServer Nginx Log İletimi (H2/J1 — 18 Haziran 2026)

**Kod tarafı:** Hazır — `/logs/webserver` ve `/logs/webserver/batch` endpoint'leri API Key (`X-API-Key`) ile çalışıyor. Syslog üzerinden gelen nginx satırları `log_normalizer` tarafından `LogSourceType.NGINX` → `web_request` olarak parse ediliyor (test edildi).

**Alpine tarafı (GNS3 açıkken uygulanacak):**

```bash
# Alpine'a SSH: ssh -J netguard@192.168.203.134 root@10.0.10.2

# rsyslog kur (apkovl'a kalıcı olarak ekle)
apk add rsyslog
rc-update add rsyslog

# /etc/rsyslog.conf sonuna ekle — nginx loglarını UDP 5140'a gönder
echo 'module(load="imfile")
input(type="imfile" File="/var/log/nginx/access.log"
      Tag="nginx:" Severity="info" Facility="local0")
input(type="imfile" File="/var/log/nginx/error.log"
      Tag="nginx:" Severity="error" Facility="local0")
local0.* @192.168.203.134:5140' >> /etc/rsyslog.conf

# rsyslog başlat
rc-service rsyslog start

# nginx access.log dosya yoksa oluştur
[ -f /var/log/nginx/access.log ] || touch /var/log/nginx/access.log
[ -f /var/log/nginx/error.log ]  || touch /var/log/nginx/error.log
```

**Doğrulama (NetGuard sunucusundan):**
```bash
# Alpine'dan syslog gelip gelmediğini kontrol et
curl -sk "https://192.168.203.134/api/v1/logs/normalized?source_type=nginx&limit=5" \
  -H "Authorization: Bearer <admin_jwt>" | jq '.[].event_action'
```

**Alternatif — Python Shipper (Seçenek B, rsyslog yoksa):**
Alpine'da `apk add python3` + log shipper script:
```python
# /etc/netguard-shipper.py — cron'a her dakika ekle
import subprocess, requests, os
last_pos = int(open("/tmp/ng_pos","r").read() or 0) if os.path.exists("/tmp/ng_pos") else 0
with open("/var/log/nginx/access.log") as f:
    f.seek(last_pos); lines = f.readlines(); open("/tmp/ng_pos","w").write(str(f.tell()))
if lines:
    requests.post("https://192.168.203.134/api/v1/logs/webserver/batch",
        headers={"X-API-Key": "NETGUARD_API_KEY"},
        json={"lines": [l.strip() for l in lines[:1000]], "observer_hostname": "alpine-webserver"},
        verify=False)
```

---

## VyOS SNMP Yapılandırması (G2 — 18 Haziran 2026)

SNMP trap receiver zaten UDP 162'de dinliyor (herhangi bir kaynaktan trap alır). VyOS'ta SNMP etkinleştirme ve NetGuard'a trap gönderme için VyOS CLI:

```bash
# VyOS'a SSH ile giriş: ssh vyos@192.168.203.200
configure

# SNMP v2c community tanımla (read-only, NetGuard IP'sine kısıtlı)
set service snmp community netguard authorization ro
set service snmp community netguard client 192.168.203.134

# Trap hedefini NetGuard olarak ayarla (IF-MIB link traps + BGP-MIB peer traps)
set service snmp trap-target 192.168.203.134 community netguard
set service snmp trap-target 192.168.203.134 port 162

# Listen interface (sadece LAN tarafı)
set service snmp listen-address 192.168.203.200

commit
save
exit
```

VyOS'u NetGuard SNMP collector'ına eklemek için (GNS3 lab açıkken çalıştır):

```bash
# NetGuard sunucusundan API ile ekle
curl -s -X POST "http://localhost:8000/api/v1/snmp/devices" \
  -H "Authorization: Bearer <admin_jwt>" \
  -H "Content-Type: application/json" \
  -d '{"host":"192.168.203.200","community":"netguard","label":"VyOS Router"}'
```

**Erişim notu (18 Haziran 2026):** GNS3 lab kapalıyken VyOS'a SSH erişimi yok — yukarıdaki komutlar GNS3 başlatıldıktan sonra uygulanmalı. Trap receiver her kaynaktan trap alır, VyOS tarafı yapılandırıldığında otomatik çalışır.

---

## Syslog Toplama (B3 — 16 Haziran 2026)

UDP 5140 yoğun trafikte sessizce paket düşürebilir (kernel/socket buffer dolduğunda) — TCP/TLS bu garantiyi transport katmanında verir. UDP eski/basit cihazlar için varsayılan açık kalır; OPNsense/VyOS gibi güvenilir teslimat istenen kaynaklar TCP/TLS'e yönlendirilebilir.

```bash
NETGUARD_SYSLOG_TCP_PORT=6010      # RFC 6587 — IANA 601'in root gerektirmeyen karşılığı (514→5140 ile aynı mantık)
NETGUARD_SYSLOG_TLS_PORT=6514      # RFC 5425 — IANA standart, zaten >1024
NETGUARD_SYSLOG_TLS_CERT=          # tanımlıysa TLS alıcısı açılır, değilse sadece düz TCP
NETGUARD_SYSLOG_TLS_KEY=
NETGUARD_SYSLOG_MAX_FRAME_BYTES=65536   # tek syslog mesajı için üst sınır (DoS koruması)
```

Framing: `SyslogFrameParser` RFC 6587 §3.4 — ilk byte rakamsa octet-counting (`MSGLEN SP MSG`), değilse LF-delimited (geleneksel rsyslog `@@` TCP forwarding). Her iki format otomatik tespit edilir.

OPNsense/VyOS'u TCP syslog gönderecek şekilde yapılandırmak için: syslog-ng/rsyslog hedefini `@@<netguard-ip>:6010` (çift `@` = TCP, tek `@` = UDP) olarak ayarla.

---

## Agent mTLS (A3 — 16 Haziran 2026)

`/agents/metrics` ve `/agents/security-events` artık API key + opsiyonel client sertifikası (mTLS) ile doğrulanıyor — `server/auth.py::get_agent_identity_verified()`. nginx `/api/v1/agents/*` location'ında `ssl_verify_client optional` ile sertifikayı doğrular, sonucu `X-SSL-Client-Verify/CN/Serial` header'larıyla backend'e iletir.

### Env Değişkenleri (Agent + Server)

```bash
# Server — mTLS zorunluluğu
AGENT_MTLS_REQUIRED=false      # true yapılınca mTLS header'ı olmayan istek 401
AGENT_CA_DIR=config/agent_ca   # CA cert+key burada saklanır (server/agent_pki.py)

# Agent — TLS doğrulama + client sertifika (agent/tls_config.py)
NETGUARD_CA_BUNDLE=            # özel CA ile sunucu sertifikası doğrulama
NETGUARD_VERIFY_TLS=true       # false → doğrulama kapanır, logger.warning basılır
NETGUARD_CLIENT_CERT=          # admin'in verdiği client_cert_pem dosya yolu
NETGUARD_CLIENT_KEY=           # admin'in verdiği client_key_pem dosya yolu
```

### Sertifika Yaşam Döngüsü

```
POST /api/v1/auth/agent-key?agent_id=X        → API key + client cert + key (tek seferlik gösterim)
POST /api/v1/auth/agent-key/{id}/revoke-cert  → sadece sertifikaları iptal et (key kalır)
DELETE /api/v1/auth/agent-key/{id}            → key sil + tüm sertifikaları iptal et
```

Sertifika geçerliliği 90 gün (NIST SP 800-204A kısa ömür önerisi) — süre dolmadan `revoke-cert` + tekrar `agent-key` ile rotasyon yapılmalı.

### Manuel Doğrulama (pytest nginx'i test edemez)

```bash
# 1. nginx mTLS kurulumu (production VM)
bash scripts/setup_https.sh   # agent-ca.pem otomatik üretilip /etc/ssl/netguard/'a kopyalanır

# 2. Admin'den agent key + sertifika al
curl -sk -X POST "https://192.168.203.134/api/v1/auth/agent-key?agent_id=test-agent" \
  -H "Authorization: Bearer <admin_jwt>" | tee /tmp/agent-creds.json

# 3. cert/key dosyalarını ayır
jq -r .client_cert_pem /tmp/agent-creds.json > /tmp/agent.crt
jq -r .client_key_pem  /tmp/agent-creds.json > /tmp/agent.key

# 4. mTLS handshake'i doğrula — sertifikasız istek hâlâ kabul edilmeli (optional)
curl -sk -X POST https://192.168.203.134/api/v1/agents/metrics \
  -H "X-API-Key: <api_key>" -d '{...}' -w "\n%{http_code}\n"

# 5. Sertifikalı istek — nginx access log'da "SUCCESS" görülmeli
curl -sk --cert /tmp/agent.crt --key /tmp/agent.key \
  -X POST https://192.168.203.134/api/v1/agents/metrics \
  -H "X-API-Key: <api_key>" -d '{...}' -w "\n%{http_code}\n"

# 6. nginx error/access log'da doğrulama sonucunu kontrol et
ssh netguard@192.168.203.134 "sudo tail -5 /var/log/nginx/access.log"
```

---

## Dashboard Deploy (Laptop → Production VM)

**Laptop** (`192.168.203.1`) geliştirme ortamı, **Production VM** (`192.168.203.134`) ayrı codebase'dir.

```bash
# 1. Değişen dosyaları rsync ile VM'e gönder (--relative zorunlu)
rsync -av --relative --checksum \
  dashboard-v2/src/... server/routes/... \
  -e "ssh -i ~/.ssh/id_ed25519" \
  netguard@192.168.203.134:/home/netguard/netguard/

# 2. VM'de build al
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.134 \
  "cd ~/netguard/dashboard-v2 && npm run build"

# 3a. Frontend service restart
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.134 \
  "sudo systemctl restart netguard-dashboard"

# 3b. Backend service restart (server/routes/*.py değiştiyse ZORUNLU)
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.134 \
  "sudo systemctl restart netguard"

# 4. Doğrula
curl -sk -I https://192.168.203.134/overview | grep -i cache-control
```

**VM servis:** `systemctl status netguard-dashboard` — WorkingDirectory: `/home/netguard/netguard/dashboard-v2/`
**VM nginx:** `location /` → no-cache; `/_next/static/` → immutable

### Next.js 16 Kuralları (proxy.ts)
- `middleware.ts` → `src/proxy.ts` (dosya adı değişti)
- Export: `export function proxy(request: NextRequest)` (`middleware` değil)
- GitHub SSH key laptop'ta yok → rsync kullan, git push yapma

---

## GNS3 Lab

```
OPNsense 26.1.2  (10.0.30.1)  ← aktif yanıt hedefi
    │
VyOS rolling     (192.168.203.200 / 10.0.30.2)
    ├── DMZ → Alpine WebServer (10.0.10.2)
    └── LAN → Host1, Host2, Kali (192.168.203.132)
NetGuard Server  (192.168.203.134)  ← ens3/LAN + ens4/MGMT (172.18.0.134)
Agent VM         (192.168.203.142)
Windows Server   (192.168.203.150, WIN-9DUCSU7LDJ0)  ← W1-A aktif
```

```bash
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.134        # server (birincil)
ssh -i ~/.ssh/id_ed25519 netguard@172.18.0.134           # server (yedek MGMT)
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.142        # agent
ssh windows-vm                                            # Windows Server 2022
ssh vyos@192.168.203.200                                  # VyOS (vyos/vyos)
ssh -J netguard@192.168.203.134,vyos@192.168.203.200 root@10.0.30.1  # OPNsense (root/netguard123)
ssh -J netguard@192.168.203.134 root@10.0.10.2           # Alpine WebServer
# VNC konsol: localhost:5901 (şifre: netguard123)
```

### GNS3 Lab Ağ Mimarisi (QEMU/KVM)

```
Host (192.168.203.1 / vmnet8)                    Host (172.18.0.1 / br-44b4e83253ed)
        │ [route + proxy-ARP]                              │ [gns3tap1-0]
        ▼                                                  ▼
  LAN-Switch (GNS3 internal)              MGMT-Bridge (br-44b4e83253ed cloud node)
        │                                                  │
   NetGuard ens3 (192.168.203.134)    NetGuard ens4 (172.18.0.134)
```

**Startup sonrası zorunlu komutlar** (GNS3 restart / host reboot sonrası):
```bash
# Otomatik: systemd user service gns3-mgmt-fix + gns3-host-routes
~/fix-gns3-mgmt-bridge.sh
sudo ip route replace 192.168.203.134/32 dev br-44b4e83253ed
```

**Doğrulanan senaryolar:** Reboot otomasyon ✅ · SSH brute force → WEAPONIZE ✅ · Port scan → RECON ✅ · FULL_ATTACK_CHAIN + email ✅ · Windows Agent (W1-A) ✅

---

## Kurallar

### Araştırma Önce, Kodlama Sonra (26 Mayıs 2026 — KESİNLİKLE UYULACAK)

**Her yeni değişiklik veya özellik için, başlamadan önce:**
1. Güvenilir kaynaklardan (NIST, CIS, Gartner, SANS, OWASP, MITRE, RFC, ilgili akademik/endüstri standartları) detaylı analiz yapılır
2. Analiz ve yaklaşım kullanıcıya sunulur, onay alınır
3. Onaydan sonra implementasyona geçilir

Bu adım atlanamaz. "Basit değişiklik" veya "küçük ekleme" olsa bile araştırma zorunludur.

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
pytest tests/ -q   # → 2644 passed (6 Haziran 2026)
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
| Full PCAP desteği | Storage altyapısı gerektirir, Arkime N11 ile ertelendi |
| Compliance raporu iyileştirmesi | Sahte skorlama |
| ECS şema değişikliği | V1-1 tamamlandı, dokunma |
| NDR'ye tam dönüşüm | Security Onion zaten var, rekabet edilemez |
| Cloud log parser (AWS/Azure/GCP) | N9 — Cloud SIEM alanı, NSM değil (6 Haziran 2026 kararı) |
| IP blokajının ötesinde otomatik yanıt | SOAR alanı (U5 ile TheHive entegrasyonu bekliyor) |
