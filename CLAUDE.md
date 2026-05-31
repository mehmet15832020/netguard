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
| Production | PostgreSQL 16 (VM'de TimescaleDB YOK — O1 görevi) | `DATABASE_URL` env set |
| Test (tmp_db / pg_db) | PostgreSQL + TimescaleDB (testcontainers) | Docker daemon erişilebilir |

**Not:** F2-1 tamamlandı — `database.py` PostgreSQL-only, `database_pg.py` kaldırıldı. Production VM'de TimescaleDB kurulumu O1 görevi olarak planlandı.

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

- [x] **G7** — Suricata Tespit Katmanı Genişletme — Bağımlılık: G2 ✓
  - *G2 ile collector tamamlandı (9 event_type parser). Ancak yalnızca `alert` + `anomaly` event_type'ları Sigma kuralı ve kill chain mapping'e sahip. 7 event_type (dns/http/tls/flow/ssh/smtp/fileinfo) normalize edilip yazılıyor ama tespit yok — bu Suricata'nın %78'ini blind spot bırakıyor.*
  - *MITRE ATT&CK v17: T1071 (HTTP/TLS C2), T1046 (network service scanning), T1048 (exfiltration over alt protocol), T1071.004 (DNS C2). Suricata HTTP/TLS/SSH logları bu teknikleri coverage'a alır.*
  - **Teslim:** `parsers/suricata.py` HTTP/TLS/SSH anomaly tespiti (token-bazlı UA, self-signed/old TLS, scanning SSH client); `suricata_ids.yml` 4 yeni Sigma kuralı (HTTP anomaly, TLS anomaly, SSH suspicious client, HTTP burst korelasyon); STAGE_MAP `suricata_http_anomaly: "recon"`, `suricata_tls_anomaly: "lateral"`, `suricata_ssh_anomaly: "weaponize"`; quality audit düzeltmeleri (token FP, STAGE_MAP semantik, tip güvenliği); 51 yeni test — toplam test ✓

---

### AŞAMA 2.6 — Dashboard Görselleştirme

Araştırma kaynakları: Gartner NDR Market Guide 2024, CIS Controls v8 Control 13, NIST SP 800-94, Security Onion 2.4, Malcolm/CISA, ntopng, Arkime, Grafana Best Practices 2024, ArmorPoint SOC KPIs 2025.

**Uygulama sırası:** Blok A (bağımsız, ~4 gün) → Blok B (G4/G3/G2 sonrası) → Blok C (ertelenebilir)

**Altyapı durumu:** Next.js dashboard ✓, api.ts ✓, TanStack Query ✓ — analytics route YOK (yazılacak), top-talkers endpoint YOK (yazılacak)

#### Blok A — Hızlı Kazanımlar (~4 gün, bağımsız)

- [x] **D1** — Top Talkers Panel
  - Top src/dst IP + top dst port → horizontal ranked bar; `GET /api/v1/analytics/top-talkers?hours=24&limit=20`
  - **Teslim:** `server/routes/analytics.py`, `TopTalkersChart.tsx`, `/top-talkers` sayfası, sidebar eklendi; 20 test — 1389 toplam test ✓
- [x] **D5** — Alert Volume Stacked Area Chart
  - `alerts` GROUP BY hour × severity → critical/high/warning/info renk kodlaması
  - **Teslim:** `GET /api/v1/analytics/alert-volume`, `AlertVolumeChart.tsx`, `/alert-volume` sayfası; zero-fill (eksik saatler sıfırla), triggered_at <= NOW() guard, Alembic 007 (idx_alerts_tenant_time); 23 test — 1456 toplam test ✓
- [x] **D2** — Protocol Distribution Donut
  - `normalized_logs.network_protocol` GROUP BY; CIS Control 13.6
  - **Teslim:** `GET /api/v1/analytics/protocol-distribution`, `ProtocolDonutChart.tsx`, `/protocol-distribution` sayfası; LOWER() case-insensitive, NULL/empty dışlama, yüzde hesabı; 20 test — 1456 toplam test ✓
- [x] **D3** — Traffic Volume Area Chart (east-west / north-south)
  - RFC1918 kaynak → iç/dış ayrımı, stacked area; Gartner NDR zorunlu
  - **Teslim:** `GET /api/v1/analytics/traffic-volume`, `TrafficVolumeChart.tsx`, `/traffic-volume` sayfası; CASE WHEN LIKE RFC1918 sınıflandırması (SQLite+PG uyumlu), zero-fill; 21 test — 88 analytics testi ✓

#### Blok B — Bağımlı Dashboard Görselleri (~4-5 gün)

- [x] **D4** — Kill Chain Swimlane Timeline — Bağımlılık: G1 ✓
  - **Teslim:** `GET /api/v1/analytics/kill-chain-timeline`, SVG swimlane (X=zaman, Y=IP, renkli aşama noktaları), saat seçici (6s/24s/48s/7g), tooltip; 17 test — 1550 toplam test ✓
- [x] **D8** — DNS Analiz Derinleştirme — Bağımlılık: G4 ✓
- [x] **D6** — Threat Intel Geo Harita + Composite Score — Bağımlılık: G3 ✓

#### Blok C — Karmaşık Görseller (ertelenebilir, F4 sonrası)

- [x] **D7** — East-West Connection Matrix Heatmap — Bağımlılık: F4
  - **Teslim:** `GET /api/v1/analytics/east-west-matrix` (RFC1918→RFC1918, top-N, hours, tenant isolation); `EastWestHeatmapChart.tsx` (ECharts heatmap, visualMap, tooltip); `/east-west-matrix` sayfası (saat seçici, özet stats); sidebar eklendi; 20 test — 1624 toplam test ✓
- [x] **D9** — Asset Risk Heatmap — Bağımlılık: F4
  - **Teslim:** `GET /api/v1/analytics/asset-risk` (RFC1918 IP bazında 3 risk boyutu: activity_score/chain_score/block_score, weighted total, tenant isolation); `AssetRiskHeatmapChart.tsx` (ECharts heatmap, Y=IP, X=boyutlar, kırmızı ton); `/asset-risk` sayfası (saat seçici, blok sayısı, en riskli IP özeti, legend); sidebar eklendi; 21 test — 1645 toplam test ✓
- [x] **D10** — MTTD/MTTR Metrik Paneli — Bağımlılık: incident lifecycle
  - **Teslim:** `GET /api/v1/analytics/mttd-mttr` (days, tenant isolation, overall MTTD/MTTR, resolution_rate, günlük trend, severity breakdown + SLA uyumu); SLA hedefleri SANS 2023 + Prophet Security: Critical 15dk/60dk, High 60dk/120dk; negatif diff + outlier >30g guard; `MttdMttrChart.tsx` (ECharts çift çizgi, MTTD mavi MTTR turuncu); `/mttd-mttr` sayfası (3 KPI kartı, trend grafik, severity SLA tablosu, kaynak notu); 27 test (basic/hesaplama/veri kalitesi/sla/tenant) — 1672 toplam test ✓

### AŞAMA 3 — Güvenlik Derinleştirme

- [x] **U3** — Tamperproof audit log (SHA-256 zinciri)
  - *NIST SP 800-92 §3.2 + NIS2 Article 21(2)(i): log bütünlüğü yasal gereklilik. Attacker PG'ye erişirse audit siler.*
  - **Teslim:** `audit_log` tablosuna `previous_hash + entry_hash` (Alembic 006); JSON canonical hash input (log forging önlemi); SQLite thread-lock + PG advisory lock serialization; `GET /api/v1/audit-log/verify` (rate-limited, async); PG smoke test dahil 24 test — 1330 toplam test ✓

- [x] **U4** — Beaconing detection (C2 inter-arrival time)
  - *MITRE ATT&CK T1071: Cobalt Strike default 60s, APT1 5m jitter ±%10-15. Zeek conn logs akar ama analiz yok.*
  - **Teslim:** `server/detectors/beaconing.py` (IAT algoritması, Bessel stddev, thread-safe _alerted, LRU pruning, FP suppression); STAGE_MAP `"c2_beaconing": "lateral"` (TA0011 C&C); `_beaconing_loop()` 300s aralık, ilk iterasyon anında; 35 test — 1369 toplam test ✓

- [x] **T2-3** — MFA / TOTP
  - *Verizon DBIR 2025: kimlik ihlallerinin %32'si. NIS2 Article 21(2)(i) zorunlu.*
  - **Teslim:** `pyotp>=2.9.0` requirements; Alembic 010 (totp_secret + totp_enabled); SQLite migration `_migrate_db_users_totp_columns()`; `create_mfa_token()` + `Token.mfa_required/mfa_token`; 4 yeni route (setup/confirm/verify/disable); rate limit 5/min; 30 test — 1604 toplam test ✓

### AŞAMA 4 — Mimari Temizlik

- [x] **F2-3** — 9 test dosyasını PG uyumlu hale getir (`tmp_db` fixture; Docker yoksa skip)
  - **Teslim:** 12 test dosyası; `DatabaseManager(db_path=...)` kaldırıldı; `sqlite3.connect(tmp_db._path)` → `tmp_db._connect()` + `%s` placeholder; `pg_db` fixture'ına 5 eksik patch + tenants tablosu eklendi; 1914 test ✓
- [x] **F2-1** — `database.py` → sadece PostgreSQL (SQLite sınıfını sil, `database_pg.py` merge)
- [x] **F2-2** — `database_pg.py` kaldır — Bağımlılık: F2-1
- [x] **F3** — Ham SQL → DB metodları (correlator, asset_baseline, retention, mitre, network_intel)
  - **Teslim:** 8 yeni DatabaseManager metodu (get_rule_alert_counts, get_log_aggregates_by_ip, get_top_values_by_ip, get_event_counts_by_ip, query_correlated_log_groups, get_network_intelligence, fetch_table_rows_before, delete_table_rows_before); 5 modülden 28 raw SQL kaldırıldı; test_retention.py dict_row fix ✓
- [x] **F2-6** — Alembic migration notları güncelle (DATABASE_URL zorunlu)
  - **Teslim:** `alembic/env.py` DATABASE_URL yoksa sys.exit(1) + hata mesajı; README.md `database_pg.py` referansı kaldırıldı, `database.py` açıklaması güncellendi, test/alembic komutları PG bağımlılığını açıkça belirtiyor

### AŞAMA 4.5 — Kural Yönetimi UI (Aşama 3/4 sonrası)

- [x] **R1** — Korelasyon Kuralları CRUD UI (4-5 gün, düşük risk)
  - **Teslim:** `GET/POST/PUT/DELETE/PATCH /api/v1/correlation/rules[/{rule_id}[/toggle]]` (CorrelationRuleIn Pydantic validation: slug regex, frozenset sev/group_by, window 10-86400, threshold 1-10000, 409 duplicate, 404 missing, hot-reload via correlator.load_rules()); `/correlation-rules` liste sayfası (Power toggle, Pencil edit, Trash2 sil, delete confirm dialog, stats bar); `RuleFormModal.tsx` (tüm alanlar, create/update mutations, enabled toggle); sidebar "Kural Yönetimi"; `correlationApi` 5 yeni metod; 30 test — 1702 toplam test ✓
  - **Quality audit düzeltmeleri:** atomik yazma (tempfile+fsync+os.replace), threading.Lock, correlator._rules_path tek kaynak, _VALID_GROUP_COLS import, max_length sınırları, bulk PUT tam validasyon, boundary testleri (50 test)
- [x] **R2** — Sigma Rule Wizard (6-7 gün, orta risk) — Bağımlılık: R1
  - **Teslim:** `PATCH /api/v1/sigma/rules/{rule_id}/toggle` (.yml ↔ .yml.disabled hot-reload); `_list_sigma_files()` disabled dosyaları da listeler; `/sigma-rules` liste sayfası (Power toggle, Trash2 sil, level badge, tag'lar); `/sigma-wizard` 4 adımlı form (Tespit→Korelasyon→Metadata→Önizleme); TypeScript YAML üretici (event_action, modifier, extra_filters, group_by, timespan, threshold, MITRE ATT&CK v17, false positives); doğrula + kaydet akışı; `sigmaApi` 6 metod; sidebar 2 yeni giriş; 28 test — MITRE ATT&CK v17, Sigma HQ spec, pySigma v2 kaynaklı
- [x] **R3** — Sigma YAML Monaco Editör (8-10 gün, yüksek risk, isteğe bağlı)
  - **Teslim:** `@monaco-editor/react` kurulumu; `/sigma-editor` sayfası (Monaco Editor ssr:false, YAML dili, vs-dark tema, 6 şablon); `?rule_id=` ile mevcut kural yükleme + üzerine yazma; Doğrula→Kaydet akışı (POST /sigma/rules/validate → POST /sigma/rules); `/sigma-rules` listesine Pencil edit butonu; sidebar "YAML Editör" (FileCode2); test_sigma_editor.py 16 test; test_correlation_routes.py RULES_PATH→correlator instance fix — 1766 toplam test ✓

### AŞAMA 2.7 — Dashboard Modernizasyon (Tamamlandı)

- [x] **Sprint 1+2** — Deep Navy Visual Identity + Hover-Expand Sidebar
  - **globals.css:** oklch deep-navy palette (`#060c17` bg, `#0d1526` panel, `#040911` sidebar), cyber cyan primary (sky-400 `#38bdf8`), dot-grid body texture, glow utilities (lamp-online/critical, glow-cyber-sm, topbar-glow-bottom), pulse-glow animations
  - **Sidebar:** VS Code inner-panel hover-expand (48px icon-only → 228px overlay, content area never shifts), pin/unpin persistence via localStorage, cyan active states + glow accent bar, navy flyout menus, gradient logo badge, slate section labels
  - **Topbar:** `DataLiveIndicator` (sourceHealth query + Wifi icon + glow lamp), section breadcrumb, dual-line clock, cy-tinted border + bottom glow
  - **Overview:** Panel/StatCard/KpiCard → navy bg + cyan borders, all `zinc-*`→`slate-*`, ECharts tooltips/axes/splitlines updated to cyber palette
  - **`src/lib/echarts-theme.ts`:** centralized CHART_COLORS, SEVERITY_COLORS, TOOLTIP_BASE, AXIS_BASE, GRID_DEFAULT, `lineSeries()` helper — Sprint 4 foundation
- [x] **Sprint 3** — Overview Bento Grid Layout
  - 8 lineer satır → 6 asimetrik zona dönüşümü (12-col CSS grid)
  - Zone A (8+4): StatCards sol + KPI compact panel sağ
  - Zone B (8+4): Alert Trend hero sol + [Threat Intel + Kill Chain] sağ stack
  - Zone C (7+5): Topology sol + [Risk Assets + MTTD] sağ stack
  - Zone D (3×4): Failed Auth + DNS Anomali + Anomali Detection
  - Zone E (4+5+3): Agents + Alerts + Protocol Donut
  - Zone F (12): Traffic Volume full-width alt
- [x] **Sprint 4** — ECharts Tema Merkezileştirme
  - **`src/lib/echarts-theme.ts`:** CHART_COLORS, SEVERITY_COLORS, SERIES_PALETTE, TOOLTIP_BASE, AXIS_BASE, CATEGORY_AXIS, VALUE_AXIS, LEGEND_TEXT, GRID_DEFAULT, GRID_SPARKLINE, `lineSeries()` helper
  - **10 chart bileşeni güncellendi:** AlertVolumeChart, AssetRiskHeatmapChart, CPUChart, EastWestHeatmapChart, MemoryGauge, MttdMttrChart, ProtocolDonutChart, TimeSeriesChart, TopTalkersChart, TrafficVolumeChart
  - **10 sayfa güncellendi:** anomaly, failed-auth, dns-analysis, correlation, mitre, logs, threat-intel-summary, topology, kill-chain-timeline, beaconing
  - **Bug fix:** CPUChart + TimeSeriesChart xAxis `type: 'event_category'` → `'category'`
  - Zinc/neutral palette tamamen kaldırıldı (0 kalan); TypeScript: 0 hata
- [x] **Sprint 5** — Badge Glassmorphism + Skeleton Loading
  - **SeverityBadge:** backdrop-blur-sm + tinted bg (*/10) + glowing border (*/30) + inset highlight + dot indicator (critical/high glow)
  - **ThreatBadge:** aynı glassmorphism + navy tooltip (#0a1120, sky-900/30 border, slate tokens)
  - **`src/components/ui/skeleton.tsx`:** Skeleton, SkeletonChart, SkeletonStatGrid, SkeletonTable
  - **`globals.css`:** `@keyframes shimmer` + `.animate-shimmer` (left-to-right highlight, 1.8s)
  - **20 sayfa güncellendi** — crude `bg-zinc-800 animate-pulse` kalıpları kaldırıldı; TypeScript: 0 hata
- [x] **Sprint 6** — Ctrl+K Command Palette (keyboard navigation)
  - **`src/store/commandPaletteStore.ts`:** Zustand store (isOpen/open/close)
  - **`src/components/layout/CommandPalette.tsx`:** 39 komut (6 bölüm), grouped view (query yok) + filtered flat view (section badge), ArrowUp/Down/Enter/Esc, flatIndex DOM ref eşlemesi, `max-h-[55vh] overflow-y-auto`, footer kbd hints
  - **`layout-client.tsx`:** Ctrl+K / Cmd+K global dinleyici, `<CommandPalette />` portal
  - **`Topbar.tsx`:** "Ara... Ctrl K" search pill (`hidden lg:flex`); TypeScript: 0 hata

### AŞAMA 4.6 — Mimari Sağlamlaştırma (ÜRETİM ÖNCESİ ZORUNLU)

> Kod analizi + derin araştırma (31 Mayıs 2026) ile tespit edildi. Bu sorunlar kapatılmadan pilot müşteriye gidilemez.

#### Kritik Buglar (1-2 Gün)

- [x] **B1** — Agent SecurityEvents → `normalized_logs`'a yazılmıyor
  - `server/routes/agents.py:157` — `receive_security_events()` sadece `security_events` tablosuna yazıyor
  - **Teslim:** `_security_event_to_normalized_log()` helper (12 WIN + AUTH_LOG + NETGUARD source_type mapping); `log_store.save()` çağrısı; 14 birim testi — `test_agents_security_events.py` ✓
- [x] **B2** — `GET /agents` ve `GET /agents/{id}/latest` endpoint'lerinde rate limit yok
  - `server/routes/agents.py` — `@limiter.limit("120/minute")` + `Request/Response` parametreleri eklendi
- [x] **B3** — Silent `except Exception: pass` kill chain dispatch'i sessizce kesiyor
  - `server/routes/agents.py` — `logger.warning(f"Kill chain dispatch hatası ...")` ile replace edildi; 2 test ✓

#### Mimari Bütünleşme (3-5 Gün)

- [x] **A1** — BeaconingDetector `DetectorManager`'a entegre edilmeli
  - `server/detectors/manager.py` — 5 dedektör var, beaconing yok; `main.py`'de ayrı `_beaconing_loop()` çalışıyor
  - **Teslim:** `BeaconingDetector` → `detector_manager._beaconing` (singleton); `DetectorManager.run_beaconing()` metodu (normalized_logs + security_events + kill chain `db_save=True`); `_EVENT_TYPE_MAP`'e `c2_beaconing` eklendi; `SecurityEventType.C2_BEACONING` enum eklendi; `_beaconing_loop()` sadeleşti (3 satır); 9 yeni test — toplam test ✓
  - **Mimari karar (RITA BlackHat 2018 + MITRE T1071):** Beaconing 300s cadence korundu — IAT istatistik analizi için 5 dakikalık örnekleme yeterli; 30s'de çalıştırmak 10× gereksiz DB sorgusu; `run_beaconing()` `run_all()`'dan ayrı çünkü C2 tespiti doğrudan kill chain feed gerektirir (60s correlator gecikmesi kabul edilemez)
- [x] **A2** — `log_store.count_by_group()` implement edilmeli
  - `server/log_store.py:134` — `raise NotImplementedError("Faz 3'te implement edilecek")` — Sigma backtest, analitik, retention çağırınca runtime crash
  - **Teslim:** PostgreSQL `GROUP BY` + OWASP A3 whitelist (`_VALID_LOG_GROUP_COLS`); NULL grup dışlama (`IS NOT NULL`); port → `str()` dönüşümü; ILIKE `%/_` escape; `since` None guard (NIST SP 800-94 §6.1); 16 test (basic/filters/edge-cases/security) — toplam test ✓
- [ ] **A3** — Lateral movement dedektörü test yok
  - `tests/` — `test_lateral*.py` yok; pyshark bağımlı, thread-based, en karmaşık dedektör
  - Fix: en az 8 birim testi + sniffer fail senaryosu

#### Operasyonel Hazırlık (1-2 Hafta)

- [ ] **O1** — TimescaleDB production VM'e kurulumu
  - VM'de sadece `plpgsql` var, TimescaleDB yok; `normalized_logs` düz tablo; büyük log hacminde ciddi yavaşlama
  - Fix: `sudo apt install timescaledb-2-postgresql-16` + `CREATE EXTENSION timescaledb` + hypertable dönüşümü
- [ ] **O2** — Docker Compose tek kurulum paketi
  - Şu an GNS3 lab'a özel konfigürasyon; müşteriye götürülemez
  - Fix: `docker-compose.yml` (server + dashboard + postgres + zeek), `.env.example`, kurulum scripti
- [ ] **O3** — Backup/restore prosedürü
  - DB yedekleme, config yedekleme, felaket kurtarma dökümantasyonu yok

#### Tespit Genişletme (1-2 Hafta)

- [ ] **D1** — NetFlow Sigma kuralları
  - NetFlow `normalized_logs`'a `source_type=NETFLOW` ile yazılıyor ama **sıfır Sigma kuralı** kapsamıyor
  - Eklenecek: büyük veri akışı (exfil), port sweep (recon), C2 beacon deseni (lateral)
- [ ] **D2** — `network_bytes` alanı Zeek + Suricata parser'larına eklenmeli
  - `migration 009` ile kolon eklendi ama sadece `parsers/netflow.py:84` dolduruyor
  - Bandwidth anomali + exfiltration tespiti için gerekli

#### İleri Özellikler (Baklog)

- [ ] **F1** — Sigma Rule Backtest Engine (`POST /api/v1/sigma/rules/backtest`) — 1-2 hafta
- [ ] **F2** — Live Log Stream (WebSocket + TanStack Virtual) — 1 hafta
- [ ] **F3** — MITRE ATT&CK Navigator matrix + coverage gap analizi — 2-3 hafta
- [ ] **F4** — AI Alert Explainer (Claude API, rate limit, 24h cache) — 1 hafta
- [ ] **F5** — Threat Hunt Workbench (no-code sorgu builder, saved hunts) — 2 hafta

---

### AŞAMA 5 — Ticari Hazırlık (6-12 Ay, Teknikle Paralel)

- [ ] **U5** — SOAR entegrasyonu (TheHive/Shuffle)
  - **Altyapı:** `server/notifier.py` webhook VAR ✓; TheHive endpoint YOK; `THEHIVE_URL/THEHIVE_API_KEY` env eklenecek
  - Bağımlılık: U3 + F4 tamamlanmalı (incident volume stabil olmalı)
- [ ] **U6** — Multi-tenant PostgreSQL RLS — Bağımlılık: F2 + U3 + T1
- [ ] **U1** — East-West görünürlük (L3 switch NetFlow) — NetFlow altyapısı VAR ✓, GNS3 L3 konfig gerekli
- [ ] **T1** — Hukuki altyapı (şirket, KVKK DPA, Tech E&O sigortası)
- [ ] **T2** — Teknik ticari (T2-1 tamperproof ✓U3, T2-2 at-rest şifreleme ✓T2-2, T2-3 MFA ✓T2-3, T2-4 RLS, T2-5 rate limiting ✓T2-5)
- [ ] **T3** — Sertifikasyon (pentest + SOC 2 Type I) — Bağımlılık: T2
- [ ] **T4** — Pazar hazırlığı (3 pilot müşteri, MSSP ortaklığı) — Bağımlılık: T1+T2+T3
- [x] **T2-5** — Sistematik rate limiting middleware (tüm endpoint'ler) — G5 point fix'ini genelleştirir
  - **Teslim:** SlowAPI `default_limits=["60/minute"]` + `_auth_key` (JWT→user:x, fallback IP); 10 route dosyası; kategori limitleri: discovery 2/min, reports 10/min, logs 30/min, agents 120/min, sigma/correlation 20/min, incidents 30/min, threat-intel 10/min; `response: Response` enjeksiyonu (X-RateLimit-* header'ları); 27 test — 1834 toplam test ✓

### Küçük Kod Sorunları (Herhangi Bir Anda)

- [x] `correlator.py:178` — Yanıltıcı yorum düzeltildi ✓
- [x] `correlator.py:244` — Sessiz `except: pass` → `logger.debug` ✓
- [x] **Frontend** — Block verify panel (P6) ✓, Break-glass butonu (P8) ✓, Port/protocol input (P7) ✓

---

## Tamamlanan Fazlar

| Faz | İçerik | Commit |
|-----|--------|--------|
| **FAZ 1** | Sigma V1 kaldır, pySigma v2 tek engine | `455dced` |
| **FAZ 2a** | `_IS_PG/_PH` dialect flag 6 modülden kaldırıldı, `LogStore` eklendi | `6187e0d` |
| **V1-1..V1-9** | ECS rename, DNS resolver, pySigma, enrichment, baseline, FP, PostgreSQL, Zeek, aktif yanıt | çeşitli |
| **P1-P8** | RFC1918, TTL, FP gate, severity gate, progressive TTL, verify, port/protocol, break-glass | çeşitli |
| **GNS3 Lab** | PostgreSQL kurulum, Alembic migrasyon, API key, dashboard build, topoloji bağlantıları | çeşitli |

**Test durumu:** 1931 test, 0 hata (31 Mayıs 2026) — PostgreSQL uyumluluk düzeltmeleri + JA4/JA4S hash doğrulaması

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

Overview, Logs, Incidents, Aktif Bloklar, Alerts, Agents, Correlation, Network Intelligence, MITRE ATT&CK, Timeline, Topology, Devices/SNMP/Discovery, Settings/Audit, Reports/Security, Uyumluluk (Compliance)

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

## Dashboard Deploy (Laptop → Production VM)

**Laptop** (`192.168.203.1`) geliştirme ortamı, **Production VM** (`192.168.203.134`) ayrı codebase'dir.
Docker rebuild'lar SADECE laptop'ı etkiler. Production'a değişiklik göndermek için:

```bash
# 1. Değişen dosyaları rsync ile VM'e gönder (--relative zorunlu)
rsync -av --relative --checksum \
  dashboard-v2/src/... server/routes/... \
  -e "ssh -i ~/.ssh/id_ed25519" \
  netguard@192.168.203.134:/home/netguard/netguard/

# 2. VM'de build al
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.134 \
  "cd ~/netguard/dashboard-v2 && npm run build"

# 3a. Frontend service restart (Next.js)
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.134 \
  "sudo systemctl restart netguard-dashboard"

# 3b. Backend service restart (uvicorn) — server/routes/*.py değiştiyse ZORUNLU
#     Python yeni kodu ancak restart sonrası yükler
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.134 \
  "sudo systemctl restart netguard"

# 4. Doğrula — beklenen: Cache-Control: no-cache, no-store, must-revalidate
curl -sk -I https://192.168.203.134/overview | grep -i cache-control
```

**VM servis:** `systemctl status netguard-dashboard` — WorkingDirectory: `/home/netguard/netguard/dashboard-v2/`
**VM nginx:** `/etc/nginx/sites-enabled/netguard` — `location /` → no-cache, `/_next/static/` → immutable

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
pytest tests/ -q   # → 1335 passed (21 Mayıs 2026)
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
