# NetGuard — Claude Rehberi

Bu dosya Claude Code'un her oturumda otomatik okuduğu proje rehberidir.
Her ilerleme adımından sonra ilgili checkbox'ı tik'le (`- [ ]` → `- [x]`).

---

## Kalite İlkesi — Derinlik ve Test (Değiştirme)

**Hiçbir şey yüzeysel yapılmaz.** Her implementasyon:
1. **Güvenilir kaynaklardan** araştırılmış verilerle desteklenmeli (SigmaHQ, CISA, MITRE ATT&CK, RFC, Gartner)
2. **Üç seviye test** yazılmalı: birim (unit) + çapraz (cross-cutting) + entegrasyon (integration)
3. **Gerçek saldırı senaryolarına** göre tasarlanmalı — toy examples değil gerçek IoC'ler

**Test piramidi (tüm yeni modüller için zorunlu):**
```
[Entegrasyon]  collect→normalize→detect→alert tam pipeline
[Çapraz]       iki modül arası etkileşim (parser→sigma→kill chain)
[Birim]        tek fonksiyon izole davranışı
```

---

## Ürün Kimliği (Değiştirme)

**NetGuard: Kurumsal bütçesi olmayan orta ölçekli şirketler için açık kaynak NSM platformu (NDR-lite özellikleriyle).**

> "Splunk yıllık 50K dolar. QRadar 30K dolar. NetGuard: açık kaynak, Docker ile 30 dakikada kurulum."

**Hedef kitle:** 50–500 çalışanlı, siber güvenlik bütçesi kısıtlı şirketlerin IT yöneticileri.

**NetGuard = NSM platformu + pasif NDR-lite + aktif yanıt.**

**Rekabet konumu:** Wazuh endpoint/HIDS odaklı, NetGuard network/NSM odaklı — bu gap gerçek ve doldurulamaya açık.

**Bu ürün ne DEĞİLDİR:**
- Wireshark gibi paket yakalayıcı değil
- Zabbix gibi saf NMS değil
- Splunk gibi log yöneticisi değil
- Wazuh gibi EDR/HIDS değil
- Darktrace/Vectra gibi full NDR değil (east-west PCAP yok)

---

## Mimari — Üç Katman (Collect → Detect → Respond)

```
COLLECT                 DETECT                  RESPOND
───────                 ──────                  ───────
Syslog (firewall)       Korelasyon motoru        Incident yönetimi
SNMP v2c/v3             pySigma v2 (30+ kural)   Saldırı timeline
NetFlow v5/v9           Kill chain (5 aşama)     Alert + bildirim
pyshark (SYN/BPF)       Anomaly (IsolationForest) Incident enrichment
Agent (psutil)          MITRE ATT&CK             AktifYanıt (IP blok)
Zeek TAP (DNS/HTTP/SSL) Threat intel (AbuseIPDB) Audit log
Web log (nginx syslog)  ARP/DNS/ICMP det.
EVTX (Windows)
         │                      │                      │
         └──────────────────────┴──────────────────────┘
                            Event Bus
                        (normalized_logs tablosu)
```

**Event pipeline:** Kaynak → `normalized_logs` → correlator/detectors → kill chain → incident → aktif yanıt

---

## Veritabanı Mimarisi — Gerçek Durum (10 Mayıs 2026)

**ÖNEMLİ:** Aşağıdaki factory database.py'ın sonunda çalışır:
```python
_DATABASE_URL = os.getenv("DATABASE_URL")
if _DATABASE_URL:
    db = _PgManager(_DATABASE_URL)   # PROD: PostgreSQL
else:
    db = DatabaseManager()            # TEST: SQLite
```

| Ortam | Veritabanı | Nasıl Seçilir |
|-------|-----------|---------------|
| Production | **PostgreSQL + TimescaleDB** | `DATABASE_URL` env set |
| Test (tmp_db fixture) | SQLite (geçici, in-memory) | `DATABASE_URL` yok |
| Test (pg_db fixture) | PostgreSQL (testcontainers) | `DATABASE_URL` set edilir |

**Tüm modüller `from server.database import db` kullanır — doğru soyutlama.**

**Mevcut sorun:** database.py (2583 satır SQLite impl) + database_pg.py (1584 satır PG impl) = 4167 satır, ~2600 satır kod tekrarı. 6 modülde `_IS_PG/_PH` dialect flag'i sızıyor.

---

## MİMARİ SADELEŞTİRME PLANI — Aktif Yol Haritası

Bu bölüm her adım tamamlandığında güncellenir. Tamamlanan adımlar `[x]` ile işaretlenir.

### FAZ 1 — Sigma V1 Kaldır (Hedef: 1 hafta)

**Neden:** Sigma V1 (sigma_parser.py + config/sigma_rules/) ve V2 (sigma_executor.py + config/sigma_rules_v2/) aynı anda çalışıyor. Testlerde V2 kapalı (prod-test uyumsuzluğu). V1 179 satır, kaldırılması temiz.

**Kapsam:**

- [x] **F1-1:** V1-only kuralları V2 pySigma formatına dönüştür
  - `config/sigma_rules_v2/device_and_snmp.yml` yeni dosya: device_sustained_outage + snmp_trap_burst
  - `config/sigma_rules_v2/windows_events.yml` yeni dosya: windows_brute_force + windows_password_spray + windows_pass_the_hash + windows_suspicious_process
  - `config/sigma_rules_v2/auth_and_web.yml` yeni dosya: web_scan + ssh_success
  - V2'deki ICMP Flood kuralı güncellendi: `icmp_flood_attempt` event_action

- [x] **F1-2:** correlator.py'dan V1 yükleme bloğunu kaldırdı
  - `load_sigma_rules_from_dir` import ve çağrısı silindi

- [x] **F1-3:** routes/sigma.py → V2 dizinine taşındı, pySigma (SigmaCollection) validasyonu
  - `SIGMA_RULES_V2_DIR` import, `parse_sigma_file` → `_SC.from_yaml` replace

- [x] **F1-4:** conftest.py'dan `_disable_sigma_v2_in_tests` kaldırıldı

- [x] **F1-5:** test_sigma.py → V2 testlerine dönüştürüldü (21 test)

- [x] **F1-6:** sigma_parser.py silindi
- [x] **F1-7:** config/sigma_rules/ dizini silindi
- [x] **F1-8:** correlator.py temizlendi
- [x] **F1-9:** 1151 test, 0 hata ✅
- [x] **F1-10:** Commit: `refactor(detection): sigma-v1-removed` → `455dced` ✅

**Sonuç:** Tek Sigma engine: pySigma v2. ~350 satır silinir. Testler prod'la uyumlu.

---

### FAZ 2 — PostgreSQL-Only Mimari (Hedef: 2-3 hafta)

**Neden:** 4167 satır DB kodu → ~1584 satıra iner. 6 modüldeki `_IS_PG/_PH` dialect flag'leri silinir. Test-prod mükemmel uyumu.

**Karar (10 Mayıs 2026):** Tam PostgreSQL geçişi seçildi. SQLite yalnızca isteğe bağlı geliştirici seçeneği.

**Kapsam:**

- [ ] **F2-1:** database.py → sadece PostgreSQL implementasyonu tut
  - SQLite `DatabaseManager` sınıfını sil (satır 1-~2575)
  - database_pg.py'ı database.py içine merge et (veya database.py → database_pg.py'a yönlendir)
  - Factory mantığı: `DATABASE_URL` yoksa geliştirici hatası fırlat (prod'da zorunlu)

- [ ] **F2-2:** database_pg.py'ı kaldır (içerik database.py'a taşındı)

- [ ] **F2-3:** conftest.py `tmp_db` fixture → `pg_db` (testcontainers) ile değiştir
  - `tmp_db` fixture: PostgreSQL testcontainer başlat
  - `DATABASE_URL` her test için set/unset
  - Tüm testler Docker gerektiriyor olacak

- [x] **F2-4:** `_IS_PG` ve `_PH` flag'lerini 6 modülden kaldır — `6187e0d` ✅
  - `server/correlator.py`, `asset_baseline.py`, `retention.py`, `sigma_executor.py`
  - `server/routes/mitre.py`, `routes/network_intel.py` — hepsi `%s` sabit
  - `server/log_store.py`: LogStore Protocol + PostgreSQLLogStore (Strangler Fig) eklendi

- [x] **F2-5:** sigma_executor.py'dan PG-specific workaroundları kaldır — `6187e0d` ✅
  - `_NetGuardSQLiteBackend` → `_NetGuardPGBackend`, ILIKE workaround silindi
  - `tests/conftest.py`: `to_char` + `mem_db` fixture eklendi (PGCompatConn sarılı)

- [ ] **F2-6:** Alembic: DATABASE_URL zorunlu olduğunda migration notları güncelle

- [x] **F2-7:** Testler çalıştır — 1151 test, 0 hata ✅

- [x] **F2-8:** CLAUDE.md Kod Kuralları bölümünden `_IS_PG/_PH` kuralını kaldır ✅

- [x] **F2-9:** Commit: `6187e0d` ✅

**Sonuç:** Tek DB implementasyonu. ~2600 satır silinir. Placeholder her yerde `%s`. Testler Docker gerektirir.

---

### FAZ 3 — Ham SQL Temizliği (Hedef: 1-2 hafta, Faz 2 sonrası)

**Neden:** 6 modüldeki ham SQL (Faz 2'de dialect temizlendikten sonra) DB metodlarına taşınır.

**Kapsam:**

- [ ] **F3-1:** `correlator.py` ham SQL → `db.get_normalized_logs_for_rule()` gibi DB metoduna taşı
- [ ] **F3-2:** `asset_baseline.py` ham SQL → DB metodu
- [ ] **F3-3:** `retention.py` ham SQL → `db.delete_old_logs()` metodu
- [ ] **F3-4:** `routes/mitre.py` ham SQL → `db.get_mitre_stats()` metodu
- [ ] **F3-5:** `routes/network_intel.py` ham SQL → `db.get_network_intel()` metodu
- [ ] **F3-6:** Testler çalıştır
- [ ] **F3-7:** Commit: `refactor(db): sql-to-methods`

---

### FAZ 4 — Anomaly → Kill Chain Entegrasyonu (Hedef: 1 hafta)

**Neden:** `anomaly/engine.py` silo çalışıyor. Tespit edilen anomaliler kill chain'e beslenmediği için incident üretmiyor.

**Mevcut durum:** AnomalyEngine → normalized_logs → (duraksıyor, correlator tetiklenmiyor)

**Kapsam:**

- [ ] **F4-1:** AnomalyEngine'de threshold aşıldığında `CorrelatedEvent` üret
- [ ] **F4-2:** Bu event'i correlator döngüsüne veya doğrudan `attack_chain_tracker`'a besle
- [ ] **F4-3:** Anomaly kaynaklı incident'ler: `event_action = "anomaly_spike"`, severity dynamic
- [ ] **F4-4:** Testler: anomaly → kill chain → incident pipeline entegrasyon testi
- [ ] **F4-5:** Commit: `feat(detection): anomaly-kill-chain`

---

## GÜVENLİK GELİŞTİRME PLANI — Kısa Dönem

Bu adımlar mimari sadeleştirme ile paralel veya hemen sonrasında yapılır.

### G1 — Auto-Block: FULL_ATTACK_CHAIN Tespitinde Otomatik OPNsense Engeli

**Öncelik: KRİTİK** — Şu an kill chain tespiti email+incident üretiyor ama OPNsense'i ÇAĞIRMIYOR.
CrowdStrike 2025: ortalama saldırı ilerleme süresi 48 dakika. Manuel blok bu süreyi aşıyor.

- [ ] **G1-1:** `attack_chain.py`'da FULL_ATTACK_CHAIN transition'ında `active_response_manager.block_ip()` çağrısı ekle
- [ ] **G1-2:** Güvenlik geçitleri geçerliliğini koru: RFC1918 → FP gate → severity gate
- [ ] **G1-3:** Auto-block audit_log kaydı: `actor = "system/kill_chain"`
- [ ] **G1-4:** Env: `AUTO_BLOCK_ON_FULL_CHAIN=1` (varsayılan kapalı — operatörün açması gerekir)
- [ ] **G1-5:** Testler: FULL_ATTACK_CHAIN → otomatik blok entegrasyon testi
- [ ] **G1-6:** Commit: `feat(response): auto-block-full-attack-chain`

### G2 — Suricata IDS Entegrasyonu

**Öncelik: YÜKSEK** — CIS 13.8 boşluğu. NIS2 uyumu için gerekli. zeek_collector.py mimarisiyle aynı pattern.

- [ ] **G2-1:** `server/suricata_collector.py` yaz (EVE JSON log tail, zeek_collector.py pattern)
- [ ] **G2-2:** EVE JSON → `normalized_logs` mapping (alert, dns, http, tls, flow kategorileri)
- [ ] **G2-3:** `main.py`'a Suricata collector loop ekle
- [ ] **G2-4:** Sigma kuralları: Suricata alert event_action için 5+ kural
- [ ] **G2-5:** Testler (3 seviye)
- [ ] **G2-6:** Commit: `feat(collect): suricata-eve-json`

### G3 — Çoklu Tehdit İstihbaratı

**Öncelik: ORTA** — Tek kaynak (AbuseIPDB) yeterli değil. Tüm ek kaynaklar ücretsiz.

- [ ] **G3-1:** `server/threat_intel.py`'a Feodo Tracker desteği (botnet C2 IP listesi, ücretsiz)
- [ ] **G3-2:** ThreatFox IOC entegrasyonu (ücretsiz API)
- [ ] **G3-3:** GreyNoise Community API (internet gürültüsü filtresi, ücretsiz tier)
- [ ] **G3-4:** `threat_intel_score` composite hesaplama: en yüksek skor kazanır
- [ ] **G3-5:** Testler
- [ ] **G3-6:** Commit: `feat(intel): multi-source-threat-intel`

### G4 — DNS Tunneling Tespiti

**Öncelik: ORTA** — Verizon DBIR 2025: C2 kanallarının %53'ü DNS tüneli. Zeek DNS logları zaten var.

- [ ] **G4-1:** Sigma kuralı: DNS sorgu entropi analizi (base64/hex encoded subdomain tespiti)
- [ ] **G4-2:** Sigma kuralı: Anormal DNS sorgu uzunluğu (>50 karakter)
- [ ] **G4-3:** Sigma kuralı: NXDOMAIN oranı spike (5 dakikada 20+)
- [ ] **G4-4:** Sigma kuralı: Tek domain'e yüksek TXT sorgu frekansı
- [ ] **G4-5:** Testler
- [ ] **G4-6:** Commit: `feat(detection): dns-tunneling-sigma`

### G5 — Block Endpoint Rate Limiting

**Öncelik: ORTA** — `POST /response/block` endpoint'inde `@limiter` decorator yok. Güvenlik açığı.

- [ ] **G5-1:** `routes/active_response.py` → `@limiter.limit("10/minute")` ekle
- [ ] **G5-2:** Break-glass endpoint'e de limit ekle (ayrı, daha yüksek: `"5/minute"`)
- [ ] **G5-3:** Test
- [ ] **G5-4:** Commit: `fix(security): block-endpoint-rate-limit`

### G6 — JA4 Geçişi (JA3 Deprecation)

**Öncelik: DÜŞÜK** — Chrome 117+ JA3 hash'ini her bağlantıda değiştiriyor, tespiti anlamsız kılıyor.

- [ ] **G6-1:** JA4 algoritması araştır (FoxIO-LLC, Apache 2.0)
- [ ] **G6-2:** zeek_collector.py'da JA4 field desteği
- [ ] **G6-3:** network_intel route'unda JA4 gösterimi
- [ ] **G6-4:** Mevcut JA3 alanlarını backward-compatible tut
- [ ] **G6-5:** Commit: `feat(enrich): ja4-fingerprint`

---

## GÜVENLİK GELİŞTİRME PLANI — Uzun Dönem (2-6 Ay)

### U1 — East-West Görünürlük (L3 Switch NetFlow)

Şu an tüm kaynaklar perimeter odaklı — iç ağ (east-west) kör nokta.

- [ ] L3 switch'ten NetFlow export konfigürasyonu (altyapı bağımlı)
- [ ] `netflow_receiver.py` multi-source support (switch IP'lerini tanı)
- [ ] East-west kill chain kuralları (lateral movement tespiti)

### U2 — Windows Sysmon Entegrasyonu

Verizon DBIR 2025: saldırıların %74'ünde kimlik bilgisi hırsızlığı. Tüm kaynaklar şu an perimeter.

- [ ] Windows Event Log → syslog (winlogbeat veya NXLog ile)
- [ ] Sysmon event_id mapping → normalized_logs event_action
- [ ] Credential access Sigma kuralları (4624, 4625, 4768, 4769)

### U3 — Tamperproof Audit Log

Finans/kamu sektörü müşteri için şart. NIST SP 800-92.

- [ ] Her audit_log kaydına SHA-256 zinciri (önceki kayıt hash'ini içerir)
- [ ] Read-only log streaming (S3 WORM veya syslog-ng iletim)

### U4 — Beaconing Detection

C2 implantları düzenli aralıklarla iletişim kurar. NetFlow inter-arrival time analizi.

- [ ] NetFlow akışlarında timing regularity tespiti
- [ ] Sigma kuralı: eşit aralıklı bağlantı burst'ı

### U5 — SOAR Entegrasyonu (TheHive / Shuffle)

- [ ] TheHive API → incident otomatik oluşturma
- [ ] Shuffle webhook → otomasyonlar

### U6 — Multi-Tenant PostgreSQL RLS

MSSP olarak birden fazla müşteri izlemek için şart.

- [ ] PostgreSQL Row-Level Security politikaları
- [ ] Her tenant için izole görünümler

---

## TİCARİ HAZIRLIK PLANI — Uzun Dönem (6-12 Ay)

Teknik değil hukuki ve süreçsel adımlar. Sözleşme imzalamak için zorunlu.

### T1 — Hukuki Altyapı (Ön Koşul, Atlanamazlar)

- [ ] **T1-1:** Siber güvenlik faaliyet kodlu şirket kurulumu
- [ ] **T1-2:** SaaS sözleşme şablonu + sorumluluk sınırlama (avukat)
- [ ] **T1-3:** KVKK Veri İşleme Sözleşmesi (DPA) hazırlama
- [ ] **T1-4:** Tech E&O sigortası başvurusu (yıllık ~3.000-8.000 USD)
- [ ] **T1-5:** Türkiye SGB yetkilendirme sürecini takibe başlama (Mart 2026'dan beri bekleniyor)
- [ ] **T1-6:** Güvenlik açığı bildirimi politikası (CVD/VDP) yayımlama

### T2 — Teknik Ticari Gereklilikler

- [ ] **T2-1:** Tamperproof audit log (U3 ile örtüşüyor)
- [ ] **T2-2:** At-rest şifreleme (PostgreSQL şifreli tablespace veya uygulama katmanı)
- [ ] **T2-3:** MFA (auth modülüne TOTP ekle)
- [ ] **T2-4:** Multi-tenant RLS (U6 ile örtüşüyor)
- [ ] **T2-5:** Sistematik input validation + rate limiting (FastAPI middleware)

### T3 — Sertifikasyon

- [ ] **T3-1:** Yıllık penetrasyon testi (6.000-25.000 USD)
- [ ] **T3-2:** SOC 2 Type I denetimi başlat (3-4 ay, ~10-15K USD)

### T4 — Pazar Hazırlığı

- [ ] **T4-1:** 3 pilot müşteri (indirimli/ücretsiz) → referans mektupları
- [ ] **T4-2:** MSSP kanal ortaklığı (1-2 Türk/Avrupa BT firması)
- [ ] **T4-3:** Pricing sayfası ve public demo ortamı

---

## Mevcut Durum — Tam Envanter (10 Mayıs 2026)

### Test Durumu

**1165 test, 0 hata** — 56 test dosyası.

### Backend Modülleri

| Dosya | Rol | Durum |
|-------|-----|-------|
| `server/active_response.py` | OPNsense REST + VyOS SSH IP bloklama | ✅ V1-9 |
| `server/alert_engine.py` | Ajan alert motoru | ✅ |
| `server/anomaly/` | IsolationForest + Welford anomaly | ✅ (kill chain bağlantısı F4'te) |
| `server/asset_baseline.py` | Per-IP 7 günlük davranış profili + spike | ✅ V1-5 |
| `server/attack_chain.py` | Kill chain (RECON/WEAPONIZE/ACCESS/LATERAL) | ✅ lab doğrulandı |
| `server/auth.py` | JWT access/refresh + API key (SHA-256) | ✅ |
| `server/compliance.py` | 26 güvenlik kontrolü, compliance API | ✅ aktif |
| `server/config_monitor.py` | Konfigürasyon değişiklik tespiti | ✅ main.py loop |
| `server/correlator.py` | 60s döngü, JSON + pySigma v2 | ✅ |
| `server/database.py` | Factory: PG (prod) / SQLite (test) | ✅ (Faz 2'de sadeleşecek) |
| `server/database_pg.py` | PostgreSQL + TimescaleDB, psycopg3 pool | ✅ (Faz 2'de database.py ile birleşecek) |
| `server/detectors/` | port_scan, arp, dns, icmp, lateral | ✅ |
| `server/dns_resolver.py` | PTR lookup, TTL cache (300s/60s) | ✅ V1-2 |
| `server/fp_manager.py` | False positive suppression (CIDR + 30gün TTL) | ✅ V1-6 |
| `server/incident_enricher.py` | MITRE + related logs + threat intel | ✅ V1-4 |
| `server/incident_priority.py` | Severity formula, priority_score | ✅ correlator kullanıyor |
| `server/influx_writer.py` | InfluxDB metrics yazıcı | ✅ aktif |
| `server/log_normalizer.py` | syslog/netflow/zeek/agent/EVTX parser | ✅ |
| `server/netflow_receiver.py` | NetFlow v5/v9 UDP 2055 | ✅ |
| `server/notifier.py` | Email + webhook, retry | ✅ |
| `server/ntp_validator.py` | Log timestamp NTP doğrulama | ✅ main.py loop |
| `server/port_monitor.py` | Yerel port değişiklik tespiti | ✅ main.py loop |
| `server/retention.py` | hot/warm/cold veri tutma | ✅ |
| `server/security_log_parser.py` | auth.log özgü parser (SSH/sudo/PAM) | ✅ main.py loop |
| `server/sigma_executor.py` | pySigma v2, 30 çalıştırılabilir kural | ✅ V1-3 |
| ~~`server/sigma_parser.py`~~ | v1 count-based parser | ✅ SİLİNDİ (Faz 1) |
| `server/snmp_auth.py` | SNMP auth helper (topology builder için) | ✅ minimal kullanım |
| `server/snmp_collector.py` | SNMP v2c/v3 poll + trap | ✅ |
| `server/storage.py` | RAM snapshot cache (metrics/health) | ✅ intentional hibrit |
| `server/syslog_receiver.py` | UDP 514 syslog alıcı | ✅ |
| `server/threat_intel.py` | AbuseIPDB cache (score ≥ 70 → critical) | ✅ |
| `server/uptime_checker.py` | Cihaz uptime / ICMP ping | ✅ main.py loop |
| `server/zeek_collector.py` | Zeek log tail (DNS/HTTP/SSL/Conn/SSH/Notice/x509/SMTP/FTP) | ✅ V1-8 |

### Parsers Dizini

| Dosya | Kullanan | Durum |
|-------|---------|-------|
| `server/parsers/firewall.py` | log_normalizer.py | ✅ |
| `server/parsers/web_log.py` | log_normalizer.py | ✅ |
| `server/parsers/zeek.py` | zeek_collector.py | ✅ |
| `server/parsers/netflow.py` | netflow_receiver.py | ✅ |

### Route'lar

| Endpoint | Dosya | Durum |
|----------|-------|-------|
| `/auth/*` | `routes/auth.py` | ✅ |
| `/incidents/*` | `routes/incidents.py` | ✅ |
| `/response/*` | `routes/active_response.py` | ✅ V1-9 + P1-P8 |
| `/network/intelligence` | `routes/network_intel.py` | ✅ |
| `/correlation/*` | `routes/correlation.py` | ✅ |
| `/sigma/*` | `routes/sigma.py` | ✅ V2 (SigmaCollection) |
| `/logs`, `/alerts`, `/agents`, `/devices`, `/snmp` | ilgili route dosyaları | ✅ |
| `/mitre`, `/attack-chains`, `/topology` | ilgili route dosyaları | ✅ |

### Sigma Kuralları

| Dizin | Format | Durum |
|-------|--------|-------|
| ~~`config/sigma_rules/`~~ | V1 count-based (15 kural) | ✅ SİLİNDİ (Faz 1) |
| `config/sigma_rules_v2/` | pySigma multi-doc YAML (8 dosya, 30+ kural) | ✅ aktif |

### Frontend Sayfaları (dashboard-v2)

| Sayfa | Route | Durum |
|-------|-------|-------|
| Overview | `/overview` | ✅ |
| Logs | `/logs` | ✅ DNS hostname |
| Incidents | `/incidents` | ✅ enrichment + aktif yanıt butonu |
| Aktif Bloklar | `/blocks` | ✅ V1-9 |
| Alerts | `/alerts` | ✅ |
| Agents | `/agents` | ✅ |
| Correlation | `/correlation` | ✅ |
| Network Intelligence | `/network-intelligence` | ✅ JA3/TLS/x509/FTP/SMTP |
| MITRE ATT&CK | `/mitre` | ✅ |
| Timeline | `/timeline` | ✅ |
| Topology | `/topology` | ✅ |
| Devices / SNMP / Discovery | `/devices`, `/snmp`, `/discovery` | ✅ |
| Settings / Audit | `/settings`, `/audit` | ✅ |
| Reports / Security | `/reports`, `/security` | ✅ |
| Block verify panel | yok | ⏳ Gelecek (P6 frontend) |
| Break-glass butonu | yok | ⏳ Gelecek (P8 frontend) |
| Port/protocol input | yok | ⏳ Gelecek (P7 frontend) |

---

## Aktif Yanıt — Detay (V1-9 + P1–P8)

### Env Değişkenleri

```bash
OPNSENSE_HOST=10.0.30.1
OPNSENSE_KEY=<api_key>
OPNSENSE_SECRET=<api_secret>
OPNSENSE_BLOCK_ALIAS=NETGUARD_BLOCK

VYOS_HOST=192.168.203.200
VYOS_USER=vyos
VYOS_KEY_PATH=/path/to/key
VYOS_FW_NAME=BLOCK-LIST

PROTECTED_CIDRS=10.0.30.1/32,192.168.203.134/32
BLOCK_MIN_SEVERITY=high
BLOCK_PROGRESSIVE_TTL=1,4,24,168
BREAK_GLASS_TOKEN=<rastgele>
BLOCK_EXPIRY_INTERVAL=60
AUTO_BLOCK_ON_FULL_CHAIN=0   # G1 sonrası: 1 yapılır
```

### Blok Akışı (P1–P4 Güvenlik Geçitleri — Bu Sıra Değişmez)

```
POST /api/v1/response/block (admin only)
    1. RFC1918 / PROTECTED_CIDRS kontrolü    → 400
    2. FP Manager: is_suppressed(ip)?        → 409 (force=false) / devam (force=true)
    3. source_incident_id severity kontrolü  → 422 (düşük severity)
    4. Zaten bloklu?                          → 409
    5. OPNsense REST → VyOS SSH fallback
    6. DB: blocked_ips (expires_at + offense_count)
    7. audit_log zorunlu
```

### Progressive TTL (P5)

| Offense | Default TTL |
|---------|-------------|
| 1. kez  | 1 saat      |
| 2. kez  | 4 saat      |
| 3. kez  | 24 saat     |
| 4.+     | 168 saat    |

### Alembic Migrations

| Dosya | İçerik |
|-------|--------|
| `001_initial_schema.py` | Temel şema |
| `002_blocked_ips.py` | blocked_ips tablosu |
| `003_blocked_ips_ttl.py` | expires_at TIMESTAMPTZ + index |
| `004_blocked_ips_offense_count.py` | offense_count INTEGER NOT NULL DEFAULT 1 |

---

## Mimari Kararlar (Değiştirme)

- **Veritabanı (prod):** PostgreSQL + TimescaleDB (DATABASE_URL zorunlu)
- **Veritabanı (test):** SQLite tmp_db (Faz 2 sonrası: pg testcontainers)
- **Event pipeline:** Her kaynak → `normalized_logs` (tek merkezi tablo)
- **Korelasyon (Faz 1 sonrası):** JSON (`correlation_rules.json`) + pySigma v2 — iki katmanlı
- **Sigma engine:** Yalnızca pySigma v2 (Faz 1 sonrası sigma_parser.py kaldırılır)
- **Token güvenliği:** `verify_token(token, token_type="access"|"refresh")` — tip karıştırma engeli
- **API key:** SHA-256 hash saklanır, plaintext asla DB'ye yazılmaz
- **Aktif yanıt:** OPNsense REST → VyOS SSH fallback, audit log zorunlu
- **Aktif yanıt güvenlik geçitleri:** RFC1918 → FP gate → severity gate → duplicate gate
- **Progressive TTL:** `_progressive_ttl(offense_count)` → Wazuh repeated_offenders eşdeğeri
- **Break-glass:** `BREAK_GLASS_TOKEN` env — JWT bypass, sadece unblock
- **Test fixture (şimdi):** `tmp_db` (SQLite) + `pg_db` (testcontainers)
- **Test fixture (Faz 2 sonrası):** Yalnızca `pg_db` (testcontainers, Docker zorunlu)

---

## GNS3 Lab

### Topoloji

```
INTERNET (Cloud/enp1s0)
    │
OPNsense 26.1.2  vtnet0=WAN, vtnet1=LAN(10.0.30.1/24)
    │
VyOS rolling     eth0=10.0.30.2, eth1=192.168.203.200, eth2=10.0.10.1
    ├── DMZ-Switch → Alpine WebServer (10.0.10.2)  telnet :5017
    └── LAN-Switch → Host1, Host2, Kali-Bridge
```

### Makine Listesi

| Makine | IP | Rol |
|--------|----|-----|
| NetGuard Server | 192.168.203.134 | Server + dashboard |
| Agent VM (Ubuntu) | 192.168.203.142 | Linux agent |
| Kali | 192.168.203.132 | Saldırı testleri |
| VyOS (GNS3) | 192.168.203.200 / 10.0.30.2 | Router, NetFlow, SNMP |
| OPNsense (GNS3) | 10.0.30.1 | Firewall — aktif yanıt hedefi |
| Alpine WebServer (GNS3) | 10.0.10.2 | nginx |

### Erişim Bilgileri

```bash
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.134   # server
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.142   # agent
ssh vyos@192.168.203.200                             # VyOS (vyos/vyos)
ssh -J netguard@192.168.203.134,vyos@192.168.203.200 root@10.0.30.1  # OPNsense (root/netguard123)
telnet localhost 5017                                 # Alpine
```

### Lab'da Doğrulanan Senaryolar

| Senaryo | Sonuç |
|---------|-------|
| Reboot → tüm otomasyon | ✅ |
| Kali → SSH brute force | ✅ WEAPONIZE tetiklendi |
| Kali → port scan | ✅ RECON tetiklendi |
| RECON + WEAPONIZE + ACCESS | ✅ FULL_ATTACK_CHAIN + email |

---

## Çözülmüş Sorunlar (Kronolojik)

| Sorun | Commit |
|-------|--------|
| `raw_log` kolon hatası | 6f0fb57 |
| sigma port_scan race condition | 9480aea |
| attack_chain STAGE_MAP prefix | 23fabbc |
| Compliance sidebar kaldırıldı | 6af811a |
| Anomaly → kill chain bağlandı | 0aa22f9 |
| Threat intel → critical escalation | 75c504f |
| web_scan sigma + nginx | f880c5c |
| Cross-source korelasyon | a08e54c |
| Lateral movement | f99f6e9 |
| ECS field rename (V1-1) | 2fc5e70 |
| Asset baseline (V1-5) | a4f7cdf |
| False positive yönetimi (V1-6) | 66f18fd |
| PostgreSQL + TimescaleDB (V1-7) | 5803d27 |
| Zeek TAP (V1-8) | fce65ec |
| Faz 1 zenginleştirme (JA3/x509/smtp/ftp) | ed00417 |
| Network Intelligence dashboard | 20b1606 |
| 13 test hatası (dict_row, LogCategory, rate limit) | 7fc36e4 |
| Aktif yanıt V1-9 (OPNsense + VyOS) | d81b860 |
| Aktif yanıt P1: RFC1918 koruması | 8eb9a59 |
| Aktif yanıt P2: TTL / auto-expiry | 8eb9a59 |
| Aktif yanıt P3: FP gate + force | 00eb569 |
| Aktif yanıt P4: severity threshold | 00eb569 |
| Aktif yanıt P5: progressive TTL | 7e376ff |
| Aktif yanıt P6-P7-P8 | 0621082 |

---

## Bilinen Sorunlar — Aktif

| Sorun | Dosya | Çözüm Planı |
|-------|-------|-------------|
| ~~Sigma V1 + V2 paralel çalışıyor~~ | ~~correlator.py~~ | ✅ FAZ 1 |
| 4167 satır DB kod tekrarı | database.py / database_pg.py | **FAZ 2** (F2-1, F2-2) |
| ~~6 modülde `_IS_PG/_PH` dialect sızıntısı~~ | — | ✅ FAZ 2a (6187e0d) |
| Anomaly kill chain'e bağlı değil | anomaly/engine.py | **FAZ 4** |
| Auto-block yok (manual blok gerekli) | attack_chain.py | **G1** |
| Block endpoint rate limiting yok | routes/active_response.py | **G5** |
| Frontend P1-P8 yok | dashboard-v2/ | Açık |
| NetFlow akışı doğrulanmadı | netflow_receiver.py | `tcpdump -i eth0 port 2055` |

---

## Claude Code Agent Altyapısı

| Dosya | Rol |
|-------|-----|
| `.claude/agents/backend-worker.md` | Python/FastAPI uzmanı |
| `.claude/agents/detection-worker.md` | Sigma/kill chain uzmanı |
| `.claude/agents/frontend-worker.md` | Next.js/React uzmanı |
| `.claude/agents/quality-auditor.md` | Kalite denetçisi (opus) |

---

## Commit Kuralları

- Her görev ayrı commit, push zorunlu
- Format: `feat(detection): ...`, `refactor(db): ...`, `fix(security): ...`
- Her yeni modül için test yaz — testler geçmeden commit atma
- Tamamlanan adım commit'ten sonra CLAUDE.md'de `[x]` işaretlenir

## Kod Kuralları

- Yorum yazma — açıklayıcı isimler yeterli
- Error handling sadece gerçek sınır noktalarında (user input, external API)
- Yeni route → `routes/` altına, router'ı `main.py`'a ekle
- Yeni UI sayfası → `dashboard-v2/src/app/(protected)/` altına
- **Yeni kod SQLite-specific syntax yazmaz** (GLOB, PRAGMA)
- **ECS alan adlarını kullan:** `source_ip`, `destination_ip`, `network_protocol`, `observer_hostname`, `event_action`, `event_category`, `source_port`, `destination_port`
- **Her yerde `%s` placeholder** — `_IS_PG/_PH` flag'i yok (Faz 2a tamamlandı)
- **dict_row uyumu (PG):** `row["kolon_adı"]` kullan, `row[0]` asla

## Test Çalıştırma

```bash
cd /home/mehmet/netguard
pytest tests/ -q
# → 1165 passed (10 Mayıs 2026)
```

## SSH Erişim

```bash
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.134   # server
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.142   # agent
```

---

## Kırmızı Çizgiler — Tartışmasız Red

| Teklif | Neden Red |
|--------|-----------|
| Vulnerability scanner (OpenVAS/Nessus) | Farklı ürün kategorisi |
| FIM (File Integrity Monitoring) | EDR kategorisi |
| Rootkit tespiti | EDR alanı |
| Full PCAP desteği | Storage altyapısı gerektirir, ürün kapsamı dışı |
| Compliance raporu iyileştirmesi | Sahte skorlama |
| ECS şema değişikliği | V1-1 tamamlandı, dokunma |
| NDR'ye tam dönüşüm | Security Onion zaten var, rekabet edilemez |
