# NetGuard — Claude Rehberi

Bu dosya Claude Code'un her oturumda otomatik okuduğu proje rehberidir.
Her yeni özellik veya değişiklikten sonra bu dosya güncellenmeli.

---

## Temel İlke — Her Adımda Ön Planda Tut (Değiştirme)

**NetGuard bir hikayesi olan üründür. Her kod değişikliği bu hikayeye hizmet etmeli.**

Hikaye:
> Bir IT yöneticisi sabah işe gelir. Dashboard açar. Geceyi özetleyen bir güvenlik durumu görür.
> Anormal bir trafik tespit edilmiş, kill chain'in 2. aşamasına ulaşmış, incident açılmış.
> Bir tıkla zaman çizelgesine bakar — hangi IP, hangi port, hangi saat. Karar verir.

**Her geliştirme adımında şu soruyu sor:**
- Bu değişiklik o IT yöneticisinin işini somut olarak kolaylaştırıyor mu?
- Ürünün bütününde anlamlı, görünür ve profesyonel bir etki yaratıyor mu?
- "Demo'da gösterilince etkileyici" mi?
- "Bu NSM/NDR kimliğine uygun bir özellik mi?"

**Kaçınılacaklar:**
- Arka planda çalışıp UI'da görünmeyen altyapı işleri (zorunlu olmadıkça)
- Kullanıcıya değer katmayan teknik refactor
- Parça parça, birbirinden kopuk özellikler
- NSM/NDR dışı kategorilere giren özellikler

---

## Ürün Kimliği (Değiştirme)

**NetGuard: Kurumsal bütçesi olmayan orta ölçekli şirketler için açık kaynak NSM platformu (NDR özellikleriyle).**

> "Splunk yıllık 50K dolar. QRadar 30K dolar. NetGuard: açık kaynak, Docker ile 30 dakikada kurulum."

**Hedef kitle:** 50–500 çalışanlı, siber güvenlik bütçesi kısıtlı şirketlerin IT yöneticileri.

**Kategori netliği:**
- **NSM (Network Security Monitoring):** Ağ trafiğini güvenlik amacıyla toplama + analiz + yanıt pratiği. Bir disiplin, ürün değil.
- **NDR (Network Detection and Response):** NSM disiplininin Gartner ürün etiketi — detection + response workflow eklenmiş hali. Her NDR bir NSM aracıdır, tersinin doğruluğu şart değil.
- **NetGuard = NSM platformu + pasif NDR.** Hoca "network güvenliği izleme sistemi" dediğinde NSM'den bahsediyordu — NetGuard tam olarak bu.

**Bu ürün ne DEĞİLDİR:**
- Wireshark gibi paket yakalayıcı değil — tespiti amaçlar, ham veriyi değil
- Zabbix gibi saf NMS değil — güvenlik tespiti önceliktir
- Splunk gibi log yöneticisi değil — ağ odaklıdır
- Wazuh gibi EDR/HIDS değil — host değil ağ odaklıdır

---

## Mimari — Üç Katman (Collect → Detect → Respond)

```
COLLECT                 DETECT                  RESPOND
───────                 ──────                  ───────
Syslog (firewall)       Korelasyon motoru        Incident yönetimi
SNMP v2c/v3             Sigma kuralları          Saldırı timeline
NetFlow v5/v9           Kill chain (5 aşama)     Alert + bildirim
pyshark (SYN/BPF)       Anomaly detection        Audit log
Agent (psutil)          MITRE ATT&CK
Web log (nginx)         Threat intel (AbuseIPDB)
EVTX (Windows)          ARP/DNS/ICMP det.
         │                      │                      │
         └──────────────────────┴──────────────────────┘
                            Event Bus
                        (normalized_logs tablosu)
```

**Event pipeline:** Kaynak → `normalized_logs` (tek merkezi tablo) → correlator/detectors → kill chain → incident

---

## Collect → Detect → Respond: Dürüst Durum Analizi

### COLLECT — Veri Toplama

**Yöntemler ve endüstri standardı karşılaştırması:**

| Yöntem | NetGuard | Endüstri standardı | Fark |
|--------|----------|-------------------|------|
| Syslog | ✅ UDP 514, OPNsense/VyOS/nginx | Aynı | Yok |
| NetFlow | ✅ konfigüre, ⚠️ doğrulanmadı | Aynı | Yok |
| SNMP | ✅ çalışıyor | Monitoring tier — NDR için değil | Fazla vurgulanıyor |
| TAP/Span | ⚠️ Sadece SYN paketi | Zeek tüm trafiği görür: DNS/HTTP/SSL/SSH log üretir | Kritik fark |
| Agent | ⚠️ Sadece metrik (CPU/RAM) | Wazuh/Elastic: process+file+login olayları toplar | Monitoring agent, security değil |

**Toplama kapsamı haritası:**
```
[Kali] → [NetGuard]      pyshark SYN     ✅ görünür
[Kali] → [Agent VM]      direkt trafik   ❌ görünmez (east-west kör nokta)
[Kali] → VyOS syslog  → [NetGuard]       ✅ log akıyor
[Kali] → VyOS NetFlow → [NetGuard]       ✅ flow özeti
DNS sorguları (tüm hostlar)              ❌ içerik görünmez — C2 tespiti imkânsız
HTTP içeriği (tüm hostlar)               ❌ görünmez
```

**Veri kalitesi sorunları:**

| Sorun | Etki |
|-------|------|
| Tutarsız şema: syslog'da dst_ip genellikle boş, NetFlow'da dolu | Aynı saldırı farklı kaynaklarda eşleştirilemiyor |
| DNS sorgu içeriği yok | C2 domain'leri, data exfil tespit edilemiyor |
| İç ağ görünürlüğü yok | Perimeter'ı geçen saldırgan içeride kaybolur |
| Asset baseline yok | Anomaly detection'da "normal" tanımsız |
| Veri doğrulama zayıf — geçersiz log atılmıyor | Hatalı log → hatalı korelasyon |

> **Kural:** Collect doğruysa Detect güvenilir, Detect güvenilirse Respond etkili. Temeli atla, her şey kırık çalışır.

---

### DETECT — Tespit Derinliği

**Çalışan:**

| Modül | Durum |
|-------|-------|
| Sigma kuralları (count-based) | ✅ 14 kural aktif (web_scan eklendi) |
| Korelasyon motoru | ✅ 60s döngü |
| Kill chain RECON+WEAPONIZE+ACCESS | ✅ lab'da doğrulandı |
| MITRE ATT&CK heatmap | ✅ |
| ARP/DNS/ICMP dedektörler | ✅ normalized_logs'a yazıyor |
| Threat intel (AbuseIPDB) | ✅ score ≥ 70 → incident critical escalation |
| Anomaly (IsolationForest + Welford) | ✅ normalized_logs'a yazıyor → kill chain RECON |
| nginx access log ayrıştırma | ✅ syslog üzerinden web_request/web_client_error/web_auth_fail |

**Kopuk / eksik:**

| Sorun | Etki | Çözüm |
|-------|------|-------|
| Sigma engine sadece `count() by field > N` | Topluluk kuralları (10K+) kullanılamıyor | V1-3: pySigma |
| Lateral movement dedektörü yok | LATERAL stage hiç tetiklenemiyor | **P5 görevi** |
| EXECUTE dedektörü yok | 4. kill chain aşaması boş | V1 kapsamı |
| Cross-source korelasyon kuralı yok | Aynı IP syslog+NetFlow+agent'ta tespit edilemiyor | **P4 görevi** |
| Zaman penceresi max 2 dakika | APT ve yavaş saldırılar kaçırılıyor | V1 kapsamı |
| False positive yönetimi yok | Yetkili tarama da alarm üretiyor | V1-6 kapsamı |
| Context enrichment yok | Her olay izole, IP geçmişi görünmez | V1 kapsamı |

---

### RESPOND — Yanıt Kalitesi

**Çalışan:**

| Modül | Durum |
|-------|-------|
| Incident workflow (open/investigating/resolved) | ✅ |
| Email + webhook bildirimi | ✅ korelasyon + anomaly + agent |
| Saldırı timeline | ✅ |
| Audit log | ✅ |

**Eksik:**

| Sorun | Etki | Çözüm |
|-------|------|-------|
| Incident açılınca ilgili loglar otomatik bağlanmıyor | IT yöneticisi kanıt için manuel arama yapıyor | **P11 görevi** |
| Incident içinde MITRE tekniği ve threat intel yok | Bağlam eksik, karar almak zorlaşıyor | P11 kapsamında |
| Önceliklendirme mekanizması yok | 20 açık incident'te nereden başlanır? | V1 kapsamı |
| Müdahale rehberi yok | Her seferinde sıfırdan düşünmek | V1 kapsamı |
| Kapanış notu zorunlu değil | Root cause kaydedilmez, aynı saldırı tekrar gelince bağlantı kurulamaz | V1 kapsamı |
| Zaman bazlı eskalasyon yok | Kritik incident sessizce bekleyebilir | V1 kapsamı |
| Aktif yanıt yok (IP blok, firewall kural) | Sadece pasif — insan kararı gerekiyor | V1-9 kapsamı |

---

## Mevcut Durum — Tam Envanter

### Çalışan — Dokunma

| Modül | Dosya | Not |
|-------|-------|-----|
| Kill chain (RECON+WEAPONIZE+ACCESS) | `server/attack_chain.py` | Lab'da doğrulandı |
| Korelasyon motoru | `server/correlator.py` | 60s döngü |
| Syslog toplama | `server/syslog_receiver.py`, `parsers/firewall.py` | OPNsense/VyOS/nginx akıyor |
| SNMP polling + TRAP | `server/snmp_collector.py` | VyOS doğrulandı |
| NetFlow v5/v9 | `server/netflow_receiver.py`, `parsers/netflow.py` | ⚠️ doğrulanmadı |
| pyshark SYN sniffer | `server/detectors/port_scan.py` | Port scan → recon |
| ARP/DNS/ICMP dedektörler | `server/detectors/` | normalized_logs'a yazıyor |
| Incident workflow | `server/routes/incidents.py` | open/investigating/resolved |
| Notifier (email + webhook) | `server/notifier.py` | Korelasyon + anomaly + agent |
| MITRE ATT&CK heatmap | `server/mitre.py`, `/mitre` UI | Çalışıyor |
| 18 frontend sayfası | `dashboard-v2/src/app/(protected)/` | Tümü API'ye bağlı |
| Docker-compose | `docker-compose.yml` | backend+frontend+influxdb+nginx |
| 46 test dosyası ~6500 satır | `tests/` | Tümü geçiyor |
| JWT + API key güvenliği | `server/auth.py` | SHA-256, tip karıştırma engeli |
| Log retention | `server/retention.py` | hot/warm/cold |
| Anomaly (IsolationForest + Welford) | `server/anomaly/` | Çalışıyor ama kill chain'e bağlı değil |
| Threat intel (AbuseIPDB) | `server/threat_intel.py` | Cache çalışıyor ama incident'e bağlı değil |

### Kaldırılanlar

| Modül | Yapılan | Neden |
|-------|---------|-------|
| Compliance sayfası (sidebar) | ✅ Kaldırıldı (commit: 6af811a) | Sahte skorlama — NSM/NDR kimliğine zarar veriyor |
| EVTX frontend sayfası | ✅ Hiç eklenmedi | Host log analizi — NDR değil |

### Demo'da Öne Çıkarılmayacak (Kod Korunuyor)

| Modül | Neden |
|-------|-------|
| `server/compliance.py` | Testler bağımlı; backend kodu korunuyor, UI'da gizli |
| CPU/RAM metrikleri | Monitoring tier — NSM kimliğini zayıflatıyor, küçük tut |
| Multi-tenant mimarisi | Demo'da gereksiz karmaşıklık |
| SNMP sayfası | NDR için değil ama ağ görünürlüğü için tutulabilir |

---

## 3 Haftalık Sıkı Plan (3–24 Mayıs 2026)

**3 kural:**
1. Her görev = implementation + test + commit + push
2. Her görev "Bu NSM/NDR için doğal bir özellik mi?" testini geçmeli
3. Yeni özellik ekleme — mevcut modülleri birbirine bağla, derinleştir

### Hafta 1 (3–10 Mayıs) — Bağlantı Tamamlama (~5 saat)

| # | Görev | Dosyalar | Süre | NSM/NDR katkısı |
|---|-------|----------|------|-----------------|
| **P1** | Anomaly → normalized_logs → kill chain | `server/anomaly/engine.py`, `server/attack_chain.py` | 2s | ML sonuçları RECON stage'ini tetikler |
| **P2** | Threat intel → incident severity escalation | `server/correlator.py`, `server/routes/incidents.py` | 2s | Bilinen kötü IP → incident otomatik critical |
| **P6** | Web scan sigma kuralı | `config/sigma_rules/web_scan.yml` | 1s | Alpine nginx HTTP flood → tespit |

### Hafta 2 (11–17 Mayıs) — Tespit + Yanıt Derinliği (~8 saat)

| # | Görev | Dosyalar | Süre | NSM/NDR katkısı |
|---|-------|----------|------|-----------------|
| **P4** | Cross-source korelasyon kuralı | `config/correlation_rules.json` | 3s | Aynı IP syslog+NetFlow+agent'ta → tek alert |
| **P5** | Lateral movement dedektörü | `server/detectors/lateral.py`, `server/attack_chain.py` | 3s | 5. kill chain aşaması — LATERAL tamamlanır |
| **P11** | Incident enrichment | `server/correlator.py`, `server/routes/incidents.py` | 2s | Incident açılınca ilgili loglar + MITRE + threat intel otomatik bağlanır |

### Hafta 3 (18–24 Mayıs) — Sunum Hazırlığı (~7 saat)

| # | Görev | Dosyalar | Süre | Zorunlu mu |
|---|-------|----------|------|------------|
| **P9** | README | `README.md` | 4s | Teslim için zorunlu |
| **P10** | Demo senaryosu | `docs/demo-scenario.md` | 1s | Sunum güvencesi |
| **Buffer** | NetFlow doğrulama, bug fix, son test | — | 2s | — |

**Toplam: ~20 saat** — 3 haftada 2–3 odaklı oturum yeterli.

### Teslim Öncesi Yapılmayan ve Neden

| Görev | Neden Atlandı | Nereye Bırakıldı |
|-------|--------------|-----------------|
| Zeek/Suricata TAP entegrasyonu | 1 haftalık iş, yüksek risk — mevcut sistemi bozabilir | V1-8 |
| Full PCAP desteği | Storage altyapısı gerektirir | V1 kapsamı |
| DNS sorgu içeriği | Zeek olmadan yarım kalır | V1-8 ile birlikte |
| pySigma entegrasyonu | Tüm testleri bozar, V1 temeli | V1-3 |
| ECS şema migrasyonu | Foundation değişikliği | V1-1 |
| PostgreSQL geçişi | Veri büyüyünce gerekir, şimdi erken | V1-7 |
| Aktif yanıt (IP blok) | Network cihaz API entegrasyonu — ayrı proje | V1-9 |
| False positive whitelist | Kontrollü demoda gerekmiyor | V1-6 |
| Anomaly frontend sayfası | API var, bildirimler çalışıyor — nice-to-have | İleride |

---

## Demo Akışı — Teslimde Gösterilecek Senaryo

Tüm P görevleri tamamlandıktan sonra aşağıdaki senaryo eksiksiz çalışmalı:

```
1. Kali → port scan (252 port)
        → pyshark SYN yakalar
        → normalized_logs: event_type=port_scan_attempt
        → sigma kural tetiklenir: port_scan_detected
        → kill chain: RECON ✅

2. Kali → SSH brute force (10 deneme)
        → syslog: ssh_failure * 10
        → sigma kural tetiklenir: ssh_brute_force_detected
        → kill chain: WEAPONIZE ✅

3. Kali → SSH success (giriş)
        → syslog: ssh_success
        → sigma kural tetiklenir: ssh_success_detected
        → kill chain: ACCESS ✅

4. Kali (veya Agent VM) → lateral scan
        → lateral_movement dedektörü (P5)
        → kill chain: LATERAL ✅

5. Anomaly engine → anormal trafik
        → normalized_logs'a yazar (P1)
        → kill chain: RECON (ek sinyal) ✅

6. FULL_ATTACK_CHAIN tetiklenir (4+ aşama)
        → critical incident otomatik açılır
        → email bildirimi gider ✅

7. Incident detayı açılır (P11 sonrası)
        → ilgili loglar listesi
        → MITRE tekniği: T1046 (Network Service Scanning)
        → threat intel: "Bu IP AbuseIPDB'de kayıtlı" (P2 sonrası)
        → IT yöneticisi tek ekranda kararını verir ✅
```

---

## Version 1 — Endüstri Standardına Açık Kapı

**Kural: Teslim öncesi bu geçişi başlatma. Ama geçişi zorlaştıracak kararlar alma.**

### Adım Sırası (Sıra kritik — atlanırsa sonraki adım temelsiz kalır)

| Adım | Yapılacak | Neden Bu Sırada |
|------|-----------|----------------|
| **V1-1** | **ECS şema + veri tutarlılığı** | Temel — dst_ip ve protocol tüm kaynaklarda dolu olmalı. Bunu atlarsan her şey eksik veriyle çalışır. |
| **V1-2** | **DNS çözümleme** | Her IP → hostname. "192.168.1.5" yerine "muhasebe-pc" — tüm alertler anında okunabilir. |
| **V1-3** | **pySigma entegrasyonu** | Sigma engine gerçek olur → 10.000+ topluluk kuralı. Tespit kapsamı dramatik artar. |
| **V1-4** | **Incident enrichment (derinleştirilmiş)** | P11'in ötesinde: kapanış notu zorunlu, SLA takibi, önceliklendirme. |
| **V1-5** | **Asset baseline** | Her cihazın normal trafik davranışı öğrenilir. Ancak bundan sonra anomaly güvenilir olur. |
| **V1-6** | **False positive yönetimi** | Bilinen iyi davranışlar whitelist'e alınır. Alert yorgunluğu azalır. |
| **V1-7** | **PostgreSQL + TimescaleDB** | Veri hacmi büyüdüğünde. SQLite 10M satıra kadar dayanır. |
| **V1-8** | **Zeek/Suricata TAP entegrasyonu** | Span port → tüm trafik görünür. DNS/HTTP/SSL/SSH logları otomatik üretilir. En büyük görünürlük sıçraması. |
| **V1-9** | **Aktif yanıt** | Ancak pasif yanıt mükemmel olduktan sonra. Firewall API, IP blok, otomatik playbook. |

### Şu an ile V1 Karşılaştırması

| Katman | Şu an | Version 1 |
|--------|-------|-----------|
| Collect | Syslog/SNMP/NetFlow/SYN only | + ECS şema, DNS çözümleme, Zeek TAP (tüm trafik) |
| Detect | count-based sigma, ML kopuk | pySigma (10K+ kural), asset baseline, false positive yönetimi |
| Respond | İnce incident, pasif | Zengin incident, SLA takibi, aktif yanıt |
| Altyapı | SQLite + InfluxDB | PostgreSQL + TimescaleDB |

### Açık Kapıyı Koruma Kararları (Şimdi Uygulanacak)

1. **`normalized_logs` tek merkezi tablo** — PostgreSQL'e geçince sadece bu migrate edilir.
2. **`sigma_parser.py` interface'i sabit** — `parse_rule(path) → rule_obj` imzası değişmez; pySigma drop-in olur.
3. **docker-compose'daki `postgres` servisi silinmez** — Şu an opsiyonel, V1-7'de primary olur.
4. **Yeni kod SQLite'a özgü syntax yazmaz** — GLOB, PRAGMA yeni modüllere eklenmez.
5. **Yeni detector yazarken field adlarını not et** — `src_ip` ileride `source.ip` (ECS) olacak.

### V1 Sonucunda NetGuard

Syslog + NetFlow + Zeek TAP → ECS normalize → PostgreSQL → pySigma (10K+ kural)
→ kill chain → zengin incident → aktif yanıt → sigma-cli ekosistemiyle uyumlu

SMB segmentte Security Onion ile rekabet edebilir, daha kolay kurulumla.

---

## Kırmızı Çizgiler — Tartışmasız Red

| Teklif | Neden Red |
|--------|-----------|
| Vulnerability scanner (OpenVAS/Nessus) | Farklı ürün kategorisi — NDR değil |
| Aktif yanıt (IP blok, firewall kural) | Teslim öncesi yapılmaz — V1-9 kapsamı |
| Version 1 mimari geçişi (PostgreSQL/pySigma/Zeek) | Teslim öncesi yapılmaz — testleri bozar |
| Rule editor UI | Önce mevcut kurallar doğru çalışsın |
| FIM (File Integrity Monitoring) | Wazuh'un alanı — EDR kategorisi |
| Rootkit tespiti | EDR alanı, NDR değil |
| Full PCAP desteği | Storage altyapısı gerektirir — V1 kapsamı |
| Compliance raporu iyileştirmesi | Sahte skorlama — demo'da gösterme, geliştirme |
| ECS şema migrasyonu | Foundation değişikliği — teslim öncesi yapılmaz |

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
| OPNsense (GNS3) | 10.0.30.1 | Firewall |
| Alpine WebServer (GNS3) | 10.0.10.2 | nginx web server |

### Veri Akışı

| Kaynak | Protokol | Hedef | Durum |
|--------|----------|-------|-------|
| OPNsense | Syslog UDP 514 | NetGuard:5140 | ✅ akıyor |
| VyOS | Syslog UDP 514 | NetGuard:5140 | ✅ akıyor |
| VyOS | SNMP v2c community=public | NetGuard | ✅ çalışıyor |
| VyOS | NetFlow v9 UDP 2055 | NetGuard | ⚠️ konfigüre, doğrulanmadı |
| Alpine nginx | Syslog access_log | NetGuard:5140 | ✅ akıyor |

### Bilgisayar Açılış Sırası

| Adım | Kim | Nasıl |
|------|-----|-------|
| 1 | VMware + VM'ler | Otomatik — vmware-netguard.service (✅ reboot testinde doğrulandı) |
| 2 | NetGuard servisler | Otomatik — netguard-lab-routes.service → netguard.service |
| 3 | GNS3 node'ları | GNS3'ü aç → proje yükle → auto_start=True ile otomatik |
| 4 | Alpine nginx | **Tek manuel adım:** `python3 ~/netguard/scripts/lab-start.sh` |

### Erişim Bilgileri

| Makine | Erişim | Kimlik |
|--------|--------|--------|
| NetGuard | `ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.134` | key |
| VyOS | `ssh vyos@192.168.203.200` (port GNS3'te değişebilir) | vyos/vyos |
| OPNsense | `ssh -J netguard@192.168.203.134,vyos@192.168.203.200 root@10.0.30.1` | root/netguard123 |
| Alpine | `telnet localhost 5017` | root (parola yok) |
| Agent VM | `ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.142` | key |

### Lab'da Doğrulanan Senaryolar

| Senaryo | Sonuç |
|---------|-------|
| Reboot → tüm otomasyon | ✅ Tüm servisler otomatik başladı |
| Kali → SSH brute force | ✅ WEAPONIZE aşaması tetiklendi, critical incident |
| Kali → port scan | ✅ RECON aşaması tetiklendi |
| RECON + WEAPONIZE + ACCESS | ✅ FULL_ATTACK_CHAIN + email bildirimi |

### Lab Eksikleri (Çözülmemiş)

| Eksik | Çözüm |
|-------|-------|
| NetFlow doğrulanmadı | Buffer haftasında: `tcpdump -i eth0 port 2055` ile kontrol |
| P5 için Kali lateral movement scripti yok | P5 başlamadan önce senaryo: Kali → Agent VM SSH → Agent VM'den iç tarama |

---

## Mimari Kararlar (Değiştirme)

- **Kimlik:** NSM platformu + pasif NDR — NMS + SIEM + EDR değil
- **Veritabanı:** SQLite WAL + InfluxDB — V1-7'de PostgreSQL + TimescaleDB
- **Event pipeline:** Her kaynak → `normalized_logs` (tek merkezi tablo, V1 migration hedefi)
- **Korelasyon:** `config/correlation_rules.json` + `config/sigma_rules/` YAML
- **Sigma engine:** Şu an sadece `count() by field > N` — V1-3'te pySigma
- **Token güvenliği:** `verify_token(token, token_type="access"|"refresh")` — tip karıştırma engeli
- **API key:** SHA-256 hash saklanır, plaintext asla DB'ye yazılmaz
- **Multi-tenant:** `tenant_scope(user)` → kodu koru, demo'da öne çıkarma
- **Test fixture:** `tmp_db` conftest.py'da tanımlı, tüm test dosyaları kullanabilir

---

## Bilinen Sorunlar — Aktif

| Sorun | Dosya | Çözüm |
|-------|-------|-------|
| Cross-source korelasyon kuralı yok | `config/correlation_rules.json` | **P4** |
| Lateral movement dedektörü yok | `server/detectors/` | **P5** |
| Incident enrichment zayıf | `server/routes/incidents.py` | **P11** |
| Sigma engine sadece count-based | `server/sigma_parser.py` | V1-3: pySigma |
| NetFlow akışı doğrulanmadı | `server/netflow_receiver.py` | Buffer haftası |
| P5 için Kali test scripti yok | `scripts/` | P5 öncesi hazırla |

## Çözülmüş Sorunlar (Referans)

- `server/correlator.py:186` — `raw_log` kolon hatası (commit: 6f0fb57) ✅
- `config/sigma_rules/port_scan.yml` — id fix + 2m timeframe race condition fix (commit: 9480aea) ✅
- `server/attack_chain.py` — STAGE_MAP'e correlated event prefix'leri eklendi (commit: 23fabbc) ✅
- Compliance sidebar'dan kaldırıldı (commit: 6af811a) ✅
- Anomaly → normalized_logs → kill chain bağlandı (commit: 0aa22f9) ✅ **P1**
- Threat intel AbuseIPDB score ≥ 70 → incident critical escalation (commit: 75c504f) ✅ **P2**
- web_scan sigma kuralı: 60sn/50+ HTTP → web_scan_detected → RECON (commit: f880c5c) ✅ **P6**
- nginx syslog → log_normalizer bağlantısı: web_request/web_client_error/web_auth_fail (commit: 48daf41) ✅ **P6 tamamlama**
- vmware-netguard.service reboot testinde doğrulandı ✅

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
- **Yeni kod SQLite'a özgü syntax yazmaz** (GLOB, PRAGMA) — V1 geçişini kolaylaştırır
- **Yeni detector'da field adlarını not et** — `src_ip` ileride `source.ip` olacak (ECS)

## Test Çalıştırma

```bash
cd /home/mehmet/netguard
pytest tests/ -q
```

## SSH Erişim

```bash
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.134   # server
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.142   # agent
```
