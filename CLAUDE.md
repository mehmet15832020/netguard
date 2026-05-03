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

**Kaçınılacaklar:**
- Arka planda çalışıp UI'da görünmeyen "altyapı" işleri (zorunlu olmadıkça)
- Kullanıcıya değer katmayan teknik refactor
- Parça parça, birbirinden kopuk özellikler

**Her commit şu testi geçmeli:** "Bu değişikliği demo'da gösterebilir miyim? Birisi görünce 'bu işe yarıyor' der mi?"

---

## Ürün Kimliği (Değiştirme)

**NetGuard: Kurumsal bütçesi olmayan orta ölçekli şirketler için açık kaynak NSM platformu (NDR özellikleriyle).**

> "Splunk yıllık 50K dolar. QRadar 30K dolar. NetGuard: açık kaynak, Docker ile 30 dakikada kurulum."

**Hedef kitle:** 50–500 çalışanlı, siber güvenlik bütçesi kısıtlı şirketlerin IT yöneticileri.

**Kategori netliği:**
- **NSM (Network Security Monitoring):** Ağ trafiğini güvenlik amacıyla toplama + analiz + yanıt pratiği. Bir disiplin.
- **NDR (Network Detection and Response):** NSM disiplininin Gartner ürün etiketi — detection + response workflow eklenmiş hali.
- **NetGuard = NSM platformu + pasif NDR özellikleri.** Çelişmiyorlar; NDR, NSM'in içindeki bir etiket.
- Hoca "network güvenliği izleme sistemi" dediğinde NSM'den bahsediyordu — NetGuard tam olarak bu.

**Bu ürün ne DEĞİLDİR:**
- Wireshark gibi paket yakalayıcı değil — tespiti amaçlar, ham veriyi değil
- Zabbix gibi saf NMS değil — güvenlik tespiti önceliktir
- Splunk gibi log yöneticisi değil — ağ odaklıdır
- Wazuh gibi EDR/HIDS değil — host değil ağ odaklıdır

---

## Katman Bazında Derinlik Analizi — Hiç Yapılmayanlar

Bu bölüm NSM/NDR tanımı gereği olması gereken ama hiç uygulanmamış veya yüzeysel kalmış şeyleri belgeler.
**Geliştirme kararı verirken bu listeye bak — hangi eksik gerçek değer katıyor?**

### COLLECT — Veri Toplama Yöntemleri ve Kapsamı

> Kural: Yanlış veya eksik veri → yanlış tespit. Toplama katmanı doğruysa detect ve respond otomatik güçlenir.

**NetGuard'ın toplama yöntemleri:**

| Yöntem | Nasıl çalışır | Şu an | Standart ile fark |
|--------|--------------|-------|-------------------|
| **Syslog** | Cihaz logunu iter → UDP 514 | ✅ OPNsense/VyOS/nginx | Aynı — endüstri standardı |
| **NetFlow** | Router trafik özetini iter → UDP 2055 | ✅ konfigüre, ⚠️ doğrulanmadı | Aynı — endüstri standardı |
| **SNMP** | Biz cihazı sorgularız → 60s poll | ✅ çalışıyor | NDR için değil, monitoring — fazla vurgulanıyor |
| **pyshark TAP** | Kendi interface'imizi dinleriz | ⚠️ sadece SYN paketi | Zeek tüm trafiği görür: DNS/HTTP/SSL/SSH log üretir |
| **Agent** | Host'a kurulu yazılım iter | ⚠️ sadece metrik (CPU/RAM) | Wazuh/Elastic process+file+login olaylarını toplar |

**Toplama kapsamı haritası:**

```
[Kali] ──────────────────────────────► [NetGuard] görüyor ✅
[Kali] ──────────────────────────────► [Agent VM] görmüyor ❌
[Kali] ──── VyOS syslog ─────────────► [NetGuard] log akıyor ✅
[Kali] ──── VyOS NetFlow ────────────► [NetGuard] flow özeti ✅
[Agent VM] ─ iç trafik ──────────────► görünmüyor ❌ (east-west kör nokta)
Tüm hostlar ─ DNS sorguları ─────────► görünmüyor ❌
Tüm hostlar ─ HTTP içeriği ──────────► görünmüyor ❌
```

**Veri kalitesi eksikleri:**

| Eksik | Şu an | Etki |
|-------|-------|------|
| **Tutarsız şema** | Syslog'da dst_ip çoğu zaman boş, NetFlow'da dolu | Aynı saldırı farklı kaynaklarda eşleştirilemiyor |
| **DNS sorgu içeriği** | Yok — sadece DNS bağlantı sayısı var | C2 domain'leri, data exfil tespit edilemiyor |
| **İç ağ görünürlüğü** | Yok — sadece perimeter | Perimeter geçen saldırgan içeride kaybolur |
| **Asset baseline** | Yok | Anomaly detection'da "normal" tanımsız |
| **Veri doğrulama** | Zayıf — geçersiz log atılmıyor | Hatalı log → hatalı korelasyon |

### DETECT — Analiz Derinliği

| Eksik | Olması gereken | Şu an | Etki |
|-------|---------------|-------|------|
| **Dar zaman penceresi** | Korelasyon dakikalar değil saatler/günler span edebilmeli | Max 2 dakika | APT ve yavaş saldırılar tespit edilemiyor |
| **EXECUTE aşaması boş** | Komut çalıştırma, zararlı process tespiti | STAGE_MAP'te tanımlı, dedektör yok | Kill chain 3 aşamada kalıyor |
| **LATERAL aşaması boş** | Pivot yapma, iç ağda yayılma tespiti | STAGE_MAP'te tanımlı, dedektör yok (P5 görevi) | Saldırgan yayıldıktan sonra kaybolur |
| **False positive yönetimi yok** | Bilinen iyi davranış whitelist'e alınabilmeli | Yok — yetkili port tarama da alarm üretiyor | Alarm yorgunluğu (alert fatigue) |
| **Context enrichment yok** | Alert gelince "Bu IP daha önce ne yaptı?" otomatik eklenmeli | Yok — her olay izole görünüyor | IT yöneticisi bağlamı manuel araştırıyor |
| **Tespit kapsam ölçümü yok** | MITRE tekniklerinin kaçı tespit edilebiliyor? | MITRE heatmap var ama kapsam % bilinmiyor | Kör noktalar görünmez |

### RESPOND — Yanıt Kalitesi

| Eksik | Olması gereken | Şu an | Etki |
|-------|---------------|-------|------|
| **Otomatik evidence toplama** | Incident açılınca ilgili tüm loglar otomatik bağlanmalı | Yok — sadece source_event_id var | IT yöneticisi kanıt için manuel log araması yapıyor |
| **Önceliklendirme** | Hangi incident'e önce bakılmalı? Risk skoru + SLA | Sadece severity var | 20 açık incident'te nereden başlanır? |
| **Müdahale rehberi** | Her alert türü için "şu adımları izle" önerisi | Yok | Her seferinde sıfırdan düşünmek |
| **Kapanış notu zorunlu değil** | Kapanırken root cause ve aksiyon kaydedilmeli | Status değişiyor ama neden kapandı bilinmiyor | Aynı saldırı tekrar gelince bağlantı kurulamıyor |
| **Zaman bazlı eskalasyon** | 24 saat çözülmeyen incident otomatik eskalasyon | Yok | Kritik incident sessizce bekleyebilir |

### Öncelik Değerlendirmesi (Teslim Öncesi Yapılabilir)

Bu listedeki her şey V1 veya V2 kapsamı **değil** — bazıları 1-2 saatte kapatılabilir:

| Görev | Süre | Hangi plana ekle |
|-------|------|-----------------|
| NetFlow doğrulama | 30dk | Buffer haftası |
| Incident'e ilgili logları otomatik bağla | 2s | Respond derinliği — P11 |
| False positive için basit IP whitelist | 1s | Detect kalitesi — P12 |

---

## NDR/NSM Kimlik Analizi — Dürüst Değerlendirme

Gartner'ın tam NDR tanımı 3 katman gerektirir: collection + behavioral detection + response.

### Neye sahibiz, nerede boşluk var

| Katman | Gereklilik | Durum | Not |
|--------|-----------|-------|-----|
| Collection | Paket/flow/log | ✅ | Syslog, SNMP, NetFlow, pyshark, agent, web log |
| Detection — imza | Sigma/kural | ⚠️ | Sigma engine sadece `count() by field > N` destekliyor |
| Detection — behavioral | ML + anomaly | ⚠️ | IsolationForest var ama kill chain'e bağlı değil |
| Detection — kill chain | MITRE ATT&CK | ✅ | 5 aşama, RECON→LATERAL |
| Response — passive | Incident workflow | ✅ | create/update/resolve, email/webhook |
| Response — active | IP blok, firewall kural | ❌ | Yok — teslim sonrası V1 kapsamı |
| Full PCAP | Ham paket saklama | ❌ | Yok — pyshark sadece SYN tespiti |
| TLS analizi | Şifreli trafik | ❌ | Yok — modern ağlarda kritik ama ayrı kategori |
| Lateral movement | Gerçek dedektör | ❌ | STAGE_MAP'te tanımlı, bunu üreten dedektör yok |
| Cross-source korelasyon | Çok kaynakta aynı IP | ❌ | Kural yok |

### Dürüst konum

> NetGuard = **NSM platformu + pasif NDR**

"Tam NDR" için aktif yanıt, full PCAP ve TLS analizi gerekir. Bunlar teslim öncesi yapılmaz.
Ama pasif NDR (workflow tabanlı yanıt) SMB segmentte gerçek bir ihtiyacı karşılar ve bu geçerli bir ürün.

---

## Mimari — Üç Katman

```
KOLEKSIYON              TESPIT                  YANIT
──────────              ──────                  ─────
Agent (psutil)          Korelasyon motoru        Incident yönetimi
SNMP v2c/v3             Sigma kuralları          Saldırı timeline
Syslog (firewall)       Kill chain (5 aşama)     Alert + bildirim
NetFlow v5/v9           Anomaly detection        Audit log
Web log (nginx)         MITRE ATT&CK
pyshark (SYN/BPF)       Threat intel (AbuseIPDB)
EVTX (Windows)          ARP/DNS/ICMP det.
         │                      │                      │
         └──────────────────────┴──────────────────────┘
                            Event Bus
                        (normalized_logs tablosu)
```

**Event pipeline:** Her kaynak → `normalized_logs` (tek merkezi tablo) → correlator/detectors → kill chain → incident

---

## Mevcut Durum — Tam Envanter

### Çalışan — Dokunma

| Modül | Dosya | Not |
|-------|-------|-----|
| Kill chain (RECON+WEAPONIZE+ACCESS) | `server/attack_chain.py` | Lab'da doğrulandı |
| Korelasyon motoru | `server/correlator.py` | 60s döngü, 7 kural |
| Syslog toplama (OPNsense/VyOS/nginx) | `server/syslog_receiver.py`, `parsers/firewall.py` | Akıyor |
| SNMP polling + TRAP | `server/snmp_collector.py` | VyOS doğrulandı |
| NetFlow v5/v9 | `server/netflow_receiver.py`, `parsers/netflow.py` | Konfigüre, doğrulanmadı |
| pyshark SYN sniffer | `server/detectors/port_scan.py` | Port scan → recon |
| ARP/DNS/ICMP dedektörler | `server/detectors/` | normalized_logs'a yazıyor |
| Incident workflow | `server/routes/incidents.py` | open/investigating/resolved |
| Notifier (email + webhook) | `server/notifier.py` | Korelasyon + anomaly + agent |
| MITRE ATT&CK heatmap | `server/mitre.py`, `/mitre` UI | Çalışıyor |
| 19 frontend sayfası | `dashboard-v2/src/app/(protected)/` | Tümü API'ye bağlı |
| Docker-compose | `docker-compose.yml` | backend+frontend+influxdb+nginx |
| 46 test dosyası ~6500 satır | `tests/` | Tümü geçiyor |
| JWT + API key güvenliği | `server/auth.py` | SHA-256, tip karıştırma engeli |
| Log retention | `server/retention.py` | hot/warm/cold |

### Var ama Kopuk — Bağlanacak (Aktif Plan)

| Modül | Sorun | Görev |
|-------|-------|-------|
| `server/anomaly/engine.py` | anomaly_results tablosuna yazıyor, `normalized_logs`'a yazmıyor → kill chain göremez | P1 |
| `server/threat_intel.py` | AbuseIPDB skoru saklanıyor ama incident severity'yi değiştirmiyor | P2 |

### Tanımlı ama Fiilen Yok — İnşa Edilecek (Aktif Plan)

| Eksik | Açıklama | Görev |
|-------|----------|-------|
| Lateral movement dedektörü | STAGE_MAP'te `lateral` aşaması var, bunu üreten dedektör yok | P5 |
| Cross-source korelasyon | Aynı IP syslog+NetFlow+agent'ta görünüyor ama tespit yok | P4 |
| Web scan sigma kuralı | Alpine nginx HTTP flood geldiğinde kural yok | P6 |

### Kaldırılanlar (Yapıldı)

| Modül | Yapılan | Neden |
|-------|---------|-------|
| Compliance sayfası (sidebar) | ✅ Sidebar'dan kaldırıldı | Sahte skorlama — NSM/NDR kimliğine zarar veriyor |
| EVTX frontend sayfası | ✅ Hiç eklenmedi | Host log analizi — NDR değil |

### Var ama Dokunulmayacak

| Modül | Karar | Neden |
|-------|-------|-------|
| `server/compliance.py` backend | Kodu koru | Testler bağımlı; sadece sidebar'dan gizlendi |
| CPU/RAM metrikleri | Dashboard'da küçük tut | Agent sayfasında görmek normal, ana odak değil |
| Multi-tenant mimarisi | Kodu koru | Demo'da gösterme, V1'de değerlendir |

---

## 3 Haftalık Sıkı Plan (3–24 Mayıs 2026)

**Kural 1:** Her görev = implementation + test + commit + push.
**Kural 2:** Her görev NSM/NDR kimliğine hizmet etmeli — "Bu bir NSM platformu için doğal bir özellik mi?" testini geçmeli.
**Kural 3:** Yeni özellik ekleme, mevcut modülleri birbirine bağla ve derinleştir.

### Hafta 1 (3–10 Mayıs) — Bağlantı Tamamlama

| # | Görev | Dosyalar | Süre | NSM/NDR bağlantısı |
|---|-------|----------|------|---------------------|
| **P1** | Anomaly → normalized_logs → kill chain | `server/anomaly/engine.py`, `server/attack_chain.py` | 2s | NDR: Behavioral ML → detection pipeline |
| **P2** | Threat intel → incident severity escalation | `server/correlator.py`, `server/routes/incidents.py` | 2s | NDR: Threat context → response kalitesi |
| **P6** | Web scan sigma kuralı | `config/sigma_rules/web_scan.yml` | 1s | NSM: Web log kaynağından tespit |

### Hafta 2 (11–17 Mayıs) — Tespit Derinliği

| # | Görev | Dosyalar | Süre | NSM/NDR bağlantısı |
|---|-------|----------|------|---------------------|
| **P4** | Cross-source korelasyon kuralı | `config/correlation_rules.json` | 3s | NSM: Çok kaynaktan aynı tehdidi birleştir |
| **P5** | Lateral movement dedektörü | `server/detectors/lateral.py`, `server/attack_chain.py` | 3s | NDR: 5. kill chain aşaması — LATERAL tamamlanır |

### Hafta 3 (18–24 Mayıs) — Sunum Hazırlığı

| # | Görev | Dosyalar | Süre | Zorunlu mu |
|---|-------|----------|------|------------|
| **P9** | README | `README.md` | 4s | Teslim için zorunlu |
| **P10** | Demo senaryosu | `docs/demo-scenario.md` | 1s | Sunum güvencesi |
| **Buffer** | Bug fix, NetFlow doğrulama, son test | — | 2s | — |

**Toplam iş yükü: ~16 saat** — 3 haftada 2–3 odaklı oturum yeterli.

### Yapılmayan ve Neden

| Atlanan Görev | Neden Atlandı |
|---------------|---------------|
| Anomaly frontend sayfası | Bildirimler zaten çalışıyor; API endpoint var. UI sayfası nice-to-have, teslim için şart değil. |
| Full PCAP desteği | Storage altyapısı gerektirir, V1 kapsamı. |
| TLS/şifreli trafik analizi | Farklı mimari gerektirir, V1 kapsamı. |
| Aktif yanıt (IP blok) | Network cihaz API entegrasyonu — ayrı proje, V1 kapsamı. |
| pySigma entegrasyonu | Foundation değişikliği — tüm testleri bozar, V1 kapsamı. |

---

## Version 1 — Endüstri Standardına Açık Kapı

**Kural: Teslim öncesi bu geçişi başlatma. Ama geçişi zorlaştıracak kararlar alma.**

### Öncelikli Adım Sırası (Sıra kritik — atlanırsa sonraki adım temelsiz kalır)

| Adım | Yapılacak | Neden Bu Sırada |
|------|-----------|-----------------|
| **V1-1** | **ECS şema + veri tutarlılığı** | Temel — dst_ip, protocol tüm kaynaklarda dolu olmalı. Bunu düzeltmeden üstüne ne inşa edilse eksik veriyle çalışır. |
| **V1-2** | **DNS çözümleme** | Her IP → hostname eşlenmeli. "192.168.1.5" yerine "muhasebe-pc" — tüm alertler anında okunabilir hale gelir. |
| **V1-3** | **pySigma entegrasyonu** | Sigma engine'i gerçek hale getir → 10.000+ topluluk kuralı import edilebilir. Tespit kapsamı dramatik artar. |
| **V1-4** | **Incident enrichment** | Incident açılınca ilgili tüm loglar + MITRE tekniği + threat intel otomatik bağlanır. IT yöneticisi için en somut iyileştirme. |
| **V1-5** | **Asset baseline** | Her cihazın normal trafik davranışı öğrenilir. Ancak bundan sonra anomaly detection güvenilir olur. |
| **V1-6** | **False positive yönetimi** | Bilinen iyi davranışlar (yetkili port tarama, monitoring araçları) whitelist'e alınır. Alert yorgunluğu azalır. |
| **V1-7** | **PostgreSQL + TimescaleDB** | Veri hacmi büyüdüğünde. SQLite 10M satıra kadar dayanır — önce diğerleri. |
| **V1-8** | **Zeek/Suricata TAP entegrasyonu** | Span port üzerinden tüm trafik görünür. Şu anki pyshark SYN tespitinin çok ötesinde görünürlük. |
| **V1-9** | **Aktif yanıt** | Ancak pasif yanıt mükemmel olduktan sonra. Firewall API, IP blok, otomatik playbook. |

### Şu an ile V1 Karşılaştırması

| Katman | Şu an | Version 1 |
|--------|-------|-----------|
| **Collect** | Syslog/SNMP/NetFlow/pyshark SYN | + DNS çözümleme, ECS şema, Zeek/Suricata TAP |
| **Detect** | count-based sigma, ML kopuk | pySigma (10K+ kural), asset baseline, false positive mgmt |
| **Respond** | İnce incident, pasif | Zengin incident (log+MITRE+intel), aktif yanıt |
| **Altyapı** | SQLite + InfluxDB | PostgreSQL + TimescaleDB |

### Açık Kapıyı Koruma Kararları (Şu An Uygulanacak)

1. **`normalized_logs` tek merkezi tablo** — PostgreSQL'e geçince sadece bu tablo migrate edilir.
2. **`sigma_parser.py` interface'i sabit** — `parse_rule(path) → rule_obj` imzası değişmez, pySigma drop-in olur.
3. **docker-compose'daki `postgres` servisi silinmez** — Şu an opsiyonel, V1-7'de primary olur.
4. **Yeni kod SQLite'a özgü syntax yazmaz** — GLOB, PRAGMA gibi şeyler yeni modüllere eklenmez.
5. **Yeni detector yazarken field adlarını not et** — `src_ip` → V1'de `source.ip` (ECS) olacak.

### Version 1 Sonucunda NetGuard

- Syslog + NetFlow + TAP → ECS normalize → PostgreSQL → pySigma (10K+ kural) → kill chain → zengin incident → aktif yanıt
- sigma-cli ekosistemiyle uyumlu
- SMB segmentte Security Onion ile rekabet edebilir, daha kolay kurulumla

---

## Kırmızı Çizgiler — Tartışmasız Red

| Teklif | Neden Red |
|--------|-----------|
| Vulnerability scanner (OpenVAS/Nessus) | Farklı ürün kategorisi |
| Active Response (otomatik IP blok) | Teslim öncesi yapılmaz — V1 kapsamı |
| Version 1 mimari geçişi (PostgreSQL/pySigma/Fluent Bit) | Teslim öncesi yapılmaz — testleri bozar |
| Rule editor UI | Önce mevcut kurallar doğru çalışsın |
| FIM (File Integrity Monitoring) | Wazuh'un alanı |
| Rootkit tespiti | EDR alanı, NDR değil |
| Full PCAP desteği | Storage altyapısı gerektirir — V1 kapsamı |
| Compliance raporu iyileştirmesi | Sahte skorlama — demo'da gösterme, geliştirme |

---

## GNS3 Lab — Mevcut Durum

### Topoloji

```
INTERNET (Cloud/enp1s0) — kablo yok
    │
OPNsense 26.1.2  vtnet0=WAN, vtnet1=LAN(10.0.30.1/24)
    console: VNC :5901   RAM: 3GB
    SSH: ssh -J netguard@192.168.203.134,vyos@192.168.203.200 root@10.0.30.1
    │ 10.0.30.0/24
VyOS rolling     eth0=10.0.30.2, eth1=192.168.203.200, eth2=10.0.10.1
    console: GNS3 API'den port al (değişebilir, :5018 veya farklı)
    SSH: ssh -J netguard@192.168.203.134 vyos@192.168.203.200
    ├── DMZ-Switch → Alpine WebServer (10.0.10.2)  console: telnet :5017
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
| VyOS | `ssh vyos@192.168.203.200` | vyos/vyos |
| OPNsense | `ssh -J netguard@192.168.203.134,vyos@192.168.203.200 root@10.0.30.1` | root/netguard123 |
| Alpine | `telnet localhost 5017` | root (parola yok) |
| Agent VM | `ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.142` | key |

### Lab'da Doğrulanan Senaryolar

| Senaryo | Sonuç |
|---------|-------|
| Reboot → tüm otomasyon | ✅ Tüm servisler otomatik başladı |
| Kali → SSH brute force → `ssh_brute_force_detected` | ✅ WEAPONIZE aşaması tetiklendi |
| Kali → port scan → `port_scan_detected` | ✅ RECON aşaması tetiklendi |
| RECON + WEAPONIZE + ACCESS → FULL_ATTACK_CHAIN | ✅ critical incident + email bildirimi |

---

## Mimari Kararlar (Değiştirme)

- **Kimlik:** NSM platformu + pasif NDR — NMS + SIEM + EDR değil
- **Veritabanı:** SQLite WAL + InfluxDB (zaman serisi) — V1'de PostgreSQL+TimescaleDB olacak
- **Event pipeline:** Her kaynak → `normalized_logs` (tek merkezi tablo, migration hedefi)
- **Korelasyon:** `config/correlation_rules.json` (JSON) + `config/sigma_rules/` (YAML)
- **Sigma engine:** Şu an sadece `count() by field > N` — V1'de pySigma
- **Token güvenliği:** `verify_token(token, token_type="access"|"refresh")` — tip karıştırma engeli
- **API key:** SHA-256 hash saklanır, plaintext asla DB'ye yazılmaz
- **Multi-tenant:** `tenant_scope(user)` → kodu koru, demo'da öne çıkarma
- **Test fixture:** `tmp_db` conftest.py'da tanımlı, tüm test dosyaları kullanabilir

---

## Bilinen Sorunlar — Aktif

| Sorun | Dosya | Çözüm |
|-------|-------|-------|
| Sigma engine: sadece count-based | `server/sigma_parser.py` | V1'de pySigma |
| Anomaly → kill chain bağlantısı yok | `server/anomaly/engine.py` | P1 görevi |
| Threat intel → incident bağlantısı yok | `server/threat_intel.py` | P2 görevi |
| Lateral movement dedektörü yok | `server/detectors/` | P5 görevi |
| NetFlow akışı doğrulanmadı | `server/netflow_receiver.py` | Buffer haftasında doğrula |
| VyOS console port değişken | GNS3 API | Her oturumda GNS3 API'den al; CLAUDE.md'deki port sabit değil |
| P5 için Kali test scripti yok | `scripts/` | P5 başlamadan önce lateral movement senaryosu yaz |

## Çözülmüş Sorunlar (Referans)

- `server/correlator.py:186` — `raw_log` kolon hatası (commit: 6f0fb57) ✅
- `config/sigma_rules/port_scan.yml` — id fix + timeframe race condition fix (commit: 9480aea) ✅
- `server/attack_chain.py` — STAGE_MAP'e correlated event prefix'leri eklendi (commit: 23fabbc) ✅
- vmware-netguard.service → reboot testinde doğrulandı ✅

---

## Commit Kuralları

- Her görev ayrı commit
- Format: `fix(ndr): ...`, `feat(ndr): ...`, `feat(detection): ...`
- Her modül için test yaz; testler geçmeden commit atma
- Commit sonrası push

## Kod Kuralları

- Yorum yazma — açıklayıcı isimler yeterli
- Error handling sadece gerçek sınır noktalarında (user input, external API)
- Mevcut pattern'leri takip et: yeni route → `routes/` altına, router'ı `main.py`'a ekle
- Yeni UI sayfası → `dashboard-v2/src/app/(protected)/` altına
- **Yeni kod SQLite'a özgü syntax yazmaz** (GLOB, PRAGMA vb.) — V1 geçişini kolaylaştırır

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
