# NetGuard — Claude Rehberi

Bu dosya Claude Code'un her oturumda otomatik okuduğu proje rehberidir.
Her yeni özellik veya değişiklikten sonra bu dosya güncellenmeli.

---

## Kalite İlkesi — Derinlik ve Test (Değiştirme)

**Hiçbir şey yüzeysel yapılmaz.** Her implementasyon:
1. **Güvenilir kaynaklardan** araştırılmış verilerle desteklenmeli (Salesforce/ja3, SigmaHQ, CISA, MITRE ATT&CK, RFC)
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

**NetGuard: Kurumsal bütçesi olmayan orta ölçekli şirketler için açık kaynak NSM platformu (NDR özellikleriyle).**

> "Splunk yıllık 50K dolar. QRadar 30K dolar. NetGuard: açık kaynak, Docker ile 30 dakikada kurulum."

**Hedef kitle:** 50–500 çalışanlı, siber güvenlik bütçesi kısıtlı şirketlerin IT yöneticileri.

**NetGuard = NSM platformu + pasif NDR + aktif yanıt.**

**Bu ürün ne DEĞİLDİR:**
- Wireshark gibi paket yakalayıcı değil
- Zabbix gibi saf NMS değil
- Splunk gibi log yöneticisi değil
- Wazuh gibi EDR/HIDS değil

---

## Mimari — Üç Katman (Collect → Detect → Respond)

```
COLLECT                 DETECT                  RESPOND
───────                 ──────                  ───────
Syslog (firewall)       Korelasyon motoru        Incident yönetimi
SNMP v2c/v3             Sigma v1 kuralları (15)  Saldırı timeline
NetFlow v5/v9           pySigma v2 (30 kural)    Alert + bildirim
pyshark (SYN/BPF)       Kill chain (5 aşama)     Incident enrichment
Agent (psutil)          Anomaly (IsolationForest) AktifYanıt(IP blok)
Zeek TAP (DNS/HTTP/SSL) MITRE ATT&CK             Audit log
Web log (nginx syslog)  Threat intel (AbuseIPDB)
EVTX (Windows)          ARP/DNS/ICMP det.
         │                      │                      │
         └──────────────────────┴──────────────────────┘
                            Event Bus
                        (normalized_logs tablosu)
```

**Event pipeline:** Kaynak → `normalized_logs` (tek merkezi tablo) → correlator/detectors → kill chain → incident → aktif yanıt

---

## Mevcut Durum — Tam Envanter (10 Mayıs 2026)

### Test Durumu

**1100 test, 0 hata** — 58 test dosyası, SQLite + PostgreSQL entegrasyon testleri dahil.

### Backend Modülleri

| Dosya | Rol | Durum |
|-------|-----|-------|
| `server/active_response.py` | OPNsense REST + VyOS SSH IP bloklama | ✅ V1-9 |
| `server/alert_engine.py` | Ajan alert motoru | ✅ |
| `server/anomaly/` | IsolationForest + Welford anomaly | ✅ kill chain'e bağlı |
| `server/asset_baseline.py` | Per-IP 7 günlük davranış profili + spike tespiti | ✅ V1-5 |
| `server/attack_chain.py` | Kill chain (RECON/WEAPONIZE/ACCESS/LATERAL) | ✅ lab doğrulandı |
| `server/auth.py` | JWT access/refresh + API key (SHA-256) | ✅ |
| `server/correlator.py` | 60s döngü, JSON+Sigma v1+pySigma v2 kural akışı | ✅ |
| `server/database.py` | SQLite WAL — `normalized_logs` tek merkezi tablo | ✅ |
| `server/database_pg.py` | PostgreSQL + TimescaleDB, psycopg3 pool | ✅ V1-7 |
| `server/detectors/` | port_scan, arp, dns, icmp, lateral | ✅ |
| `server/dns_resolver.py` | PTR lookup, TTL cache (300s/60s), fire-and-forget | ✅ V1-2 |
| `server/fp_manager.py` | False positive suppression (CIDR + 30gün TTL) | ✅ V1-6 |
| `server/incident_enricher.py` | MITRE + related logs + threat intel enrichment | ✅ V1-4 |
| `server/log_normalizer.py` | syslog/netflow/zeek/agent/EVTX parser | ✅ |
| `server/netflow_receiver.py` | NetFlow v5/v9 UDP 2055 | ✅ |
| `server/notifier.py` | Email + webhook, retry (_send_msg/_post_payload) | ✅ |
| `server/retention.py` | hot/warm/cold veri tutma | ✅ |
| `server/sigma_executor.py` | pySigma + sqliteBackend, 30 çalıştırılabilir kural | ✅ V1-3 |
| `server/sigma_parser.py` | v1 count-based parser (geriye dönük uyumluluk) | ✅ |
| `server/snmp_collector.py` | SNMP v2c/v3 poll + trap | ✅ |
| `server/syslog_receiver.py` | UDP 514 syslog alıcı | ✅ |
| `server/threat_intel.py` | AbuseIPDB cache (score ≥ 70 → critical) | ✅ |
| `server/zeek_collector.py` | Zeek log tail (DNS/HTTP/SSL/Conn/SSH/Notice) | ✅ V1-8 |

### Route'lar

| Endpoint | Dosya |
|----------|-------|
| `/auth/*` | `routes/auth.py` |
| `/incidents/*` | `routes/incidents.py` |
| `/response/*` | `routes/active_response.py` — V1-9 |
| `/network/intelligence` | `routes/network_intel.py` |
| `/correlation/*` | `routes/correlation.py` |
| `/logs`, `/alerts`, `/agents`, `/devices`, `/snmp` | ilgili route dosyaları |
| `/mitre`, `/attack-chains`, `/topology` | ilgili route dosyaları |

### Sigma Kuralları

| Dizin | Format | Kural Sayısı |
|-------|--------|-------------|
| `config/sigma_rules/` | v1 count-based | 15 kural |
| `config/sigma_rules_v2/` | pySigma multi-doc YAML | 8 dosya, 30 çalıştırılabilir kural |

### Frontend Sayfaları (dashboard-v2)

| Sayfa | Route | Durum |
|-------|-------|-------|
| Overview | `/overview` | ✅ |
| Logs | `/logs` | ✅ DNS hostname gösteriyor |
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

### Altyapı

| Bileşen | Durum |
|---------|-------|
| Docker Compose | backend + frontend + influxdb + nginx |
| Alembic migrations | `alembic/versions/001_initial_schema.py` + `002_blocked_ips.py` |
| CI-ready | pytest tests/ -q → 1100 passed |
| systemd | netguard.service, netguard-agent.service, vmware-netguard.service |

---

## Aktif Yanıt — V1-9 Detayı

### Env Değişkenleri

```bash
OPNSENSE_HOST=10.0.30.1          # OPNsense IP
OPNSENSE_KEY=<api_key>
OPNSENSE_SECRET=<api_secret>
OPNSENSE_BLOCK_ALIAS=NETGUARD_BLOCK

VYOS_HOST=192.168.203.200        # VyOS IP
VYOS_USER=vyos
VYOS_KEY_PATH=/path/to/key
VYOS_FW_NAME=BLOCK-LIST
```

### Blok Akışı

```
POST /api/v1/response/block (admin only)
    → OPNsense REST API dene
    → Başarısız → VyOS SSH fallback
    → DB: blocked_ips tablosu
    → audit_log kaydı
```

### Tablolar

```sql
blocked_ips (block_id, ip, reason, blocked_at, blocked_by,
             is_active, source_incident_id, provider,
             unblocked_at, unblocked_by, tenant_id)
```

---

## Çözülmüş Sorunlar (Kronolojik)

| Sorun | Çözüm | Commit |
|-------|-------|--------|
| `raw_log` kolon hatası | fix | 6f0fb57 |
| sigma port_scan race condition | id fix + 2m timeframe | 9480aea |
| attack_chain STAGE_MAP prefix | eklendi | 23fabbc |
| Compliance sidebar | kaldırıldı | 6af811a |
| Anomaly → kill chain | bağlandı (P1) | 0aa22f9 |
| Threat intel → critical escalation | (P2) | 75c504f |
| web_scan sigma + nginx | (P6) | f880c5c |
| Cross-source korelasyon | (P4) | a08e54c |
| Lateral movement | (P5) | f99f6e9 |
| ECS field rename (8 kolon) | (V1-1) | 2fc5e70 |
| V1-5 Asset baseline | | a4f7cdf |
| V1-6 False positive | | 66f18fd |
| V1-7 PostgreSQL + TimescaleDB | | 5803d27 |
| V1-8 Zeek TAP | | fce65ec |
| Faz 1 zenginleştirme (JA3/x509/smtp/ftp) | | ed00417 |
| Network Intelligence dashboard | | 20b1606 |
| 13 test hatası (dict_row, LogCategory, rate limit) | | 7fc36e4 |
| V1-9 Aktif yanıt | IN PROGRESS | — |

---

## Bilinen Sorunlar — Aktif

| Sorun | Dosya | Çözüm |
|-------|-------|-------|
| V1-9 commit bekliyor | `server/active_response.py` | Backend agent tamamlıyor |
| NetFlow akışı doğrulanmadı | `server/netflow_receiver.py` | `tcpdump -i eth0 port 2055` |

---

## Mimari Kararlar (Değiştirme)

- **Veritabanı:** SQLite WAL (prod) + PostgreSQL (V1-7 opsiyonel, testcontainers ile test)
- **Event pipeline:** Her kaynak → `normalized_logs` (tek merkezi tablo)
- **Korelasyon:** JSON (`correlation_rules.json`) + Sigma v1 YAML + pySigma v2 YAML — üç katmanlı
- **Sigma engine:** Sigma v1 count-based + pySigma (30 kural, 8 dosya)
- **Token güvenliği:** `verify_token(token, token_type="access"|"refresh")` — tip karıştırma engeli
- **API key:** SHA-256 hash saklanır, plaintext asla DB'ye yazılmaz
- **Aktif yanıt:** OPNsense REST → VyOS SSH fallback, audit log zorunlu
- **Test fixture:** `tmp_db` + `pg_db` conftest.py'da tanımlı

---

## GNS3 Lab — Mevcut Durum

### Topoloji

```
INTERNET (Cloud/enp1s0) — kablo yok
    │
OPNsense 26.1.2  vtnet0=WAN, vtnet1=LAN(10.0.30.1/24)
    SSH: ssh -J netguard@192.168.203.134,vyos@192.168.203.200 root@10.0.30.1
    │ 10.0.30.0/24
VyOS rolling     eth0=10.0.30.2, eth1=192.168.203.200, eth2=10.0.10.1
    SSH: ssh -J netguard@192.168.203.134 vyos@192.168.203.200
    ├── DMZ-Switch → Alpine WebServer (10.0.10.2)  telnet :5017
    └── LAN-Switch → Host1, Host2, Kali-Bridge(vmnet8→NetGuard)
```

### Makine Listesi

| Makine | IP | Rol |
|--------|----|-----|
| NetGuard Server | 192.168.203.134 | Server + dashboard (systemd: netguard.service) |
| Agent VM (Ubuntu) | 192.168.203.142 | Linux agent (systemd: netguard-agent.service) |
| Kali | 192.168.203.132 | Saldırı testleri |
| VyOS (GNS3) | 192.168.203.200 / 10.0.30.2 | Router, NetFlow, SNMP |
| OPNsense (GNS3) | 10.0.30.1 | Firewall — aktif yanıt hedefi |
| Alpine WebServer (GNS3) | 10.0.10.2 | nginx web server |

### Erişim Bilgileri

| Makine | Erişim | Kimlik |
|--------|--------|--------|
| NetGuard | `ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.134` | key |
| VyOS | `ssh vyos@192.168.203.200` | vyos/vyos |
| OPNsense | `ssh -J netguard@192.168.203.134,vyos@192.168.203.200 root@10.0.30.1` | root/netguard123 |
| Alpine | `telnet localhost 5017` | root (parola yok) |
| Agent VM | `ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.142` | key |

### Bilgisayar Açılış Sırası

| Adım | Kim | Nasıl |
|------|-----|-------|
| 1 | VMware + VM'ler | Otomatik — vmware-netguard.service |
| 2 | NetGuard servisler | Otomatik — netguard.service |
| 3 | GNS3 node'ları | GNS3'ü aç → proje yükle → auto_start=True |
| 4 | Alpine nginx | Tek manuel adım: `python3 ~/netguard/scripts/lab-start.sh` |

### Lab'da Doğrulanan Senaryolar

| Senaryo | Sonuç |
|---------|-------|
| Reboot → tüm otomasyon | ✅ |
| Kali → SSH brute force | ✅ WEAPONIZE tetiklendi |
| Kali → port scan | ✅ RECON tetiklendi |
| RECON + WEAPONIZE + ACCESS | ✅ FULL_ATTACK_CHAIN + email |

---

## Claude Code Agent Altyapısı

| Dosya | Rol |
|-------|-----|
| `.claude/agents/backend-worker.md` | Python/FastAPI uzmanı |
| `.claude/agents/detection-worker.md` | Sigma/kill chain uzmanı |
| `.claude/agents/frontend-worker.md` | Next.js/React uzmanı |
| `.claude/agents/quality-auditor.md` | Kalite denetçisi (opus) |

**Agent izolasyonu:** `.claude/settings.local.json` → `"defaultMode": "acceptEdits"`

---

## Commit Kuralları

- Her görev ayrı commit
- Format: `feat(detection): ...`, `feat(ndr): ...`, `fix(collect): ...`
- Her yeni modül için test yaz — testler geçmeden commit atma
- Commit sonrası push

## Kod Kuralları

- Yorum yazma — açıklayıcı isimler yeterli
- Error handling sadece gerçek sınır noktalarında (user input, external API)
- Yeni route → `routes/` altına, router'ı `main.py`'a ekle
- Yeni UI sayfası → `dashboard-v2/src/app/(protected)/` altına
- **Yeni kod SQLite'a özgü syntax yazmaz** (GLOB, PRAGMA)
- **ECS alan adlarını kullan:** `source_ip`, `destination_ip`, `network_protocol`, `observer_hostname`, `event_action`, `event_category`, `source_port`, `destination_port`
- **SQLite `?` / PG `%s` placeholder:** `_IS_PG = bool(os.getenv("DATABASE_URL"))` → `_PH = "%s" if _IS_PG else "?"`
- **dict_row uyumu (PG):** `row["kolon_adı"]` kullan, `row[0]` asla

## Test Çalıştırma

```bash
cd /home/mehmet/netguard
pytest tests/ -q
# → 1100 passed (10 Mayıs 2026 itibarıyla)
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
| Full PCAP desteği | Storage altyapısı gerektirir |
| Compliance raporu iyileştirmesi | Sahte skorlama |
| ECS şema değişikliği | V1-1 tamamlandı, dokunma |
