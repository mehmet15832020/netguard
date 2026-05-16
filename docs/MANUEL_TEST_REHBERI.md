# NetGuard — Manuel End-to-End Test Rehberi

Bu rehber, NetGuard'ın tüm özelliklerini GNS3 lab ortamında sıfırdan doğrulamak için  
adım adım talimatlar içerir. Her adımda **ne bekleneceği** ve **hata durumunda ne yapılacağı** belirtilmiştir.

---

## Ön Koşullar

### GNS3 Lab Başlatma Sırası

```
1. OPNsense VM'yi başlat  → 10.0.30.1 (GUI: https://10.0.30.1)
2. VyOS VM'yi başlat      → 192.168.203.200
3. NetGuard Server'ı başlat → 192.168.203.134
4. Agent VM'yi başlat     → 192.168.203.142
5. Kali Linux'u başlat    → 192.168.203.132
```

### NetGuard Server'da Servisler

```bash
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.134
cd ~/netguard

# Servisleri başlat
docker compose up -d          # PostgreSQL + InfluxDB + Nginx

# Backend'i başlat (ayrı terminal)
source venv/bin/activate
uvicorn server.main:app --host 0.0.0.0 --port 8000 --reload

# Zeek'i başlat (ayrı terminal, root gerekebilir)
sudo zeek -i eth0 LogAscii::use_json=T &
```

### Erişim Kontrolleri

```bash
# API sağlık kontrolü
curl -k https://192.168.203.134/api/v1/health
# Beklenen: {"status": "ok", ...}

# Dashboard
# Tarayıcı: https://192.168.203.134
# admin / [ADMIN_PASSWORD]
```

---

## BÖLÜM 1 — Veri Toplama Katmanı Testleri

### 1.1 Syslog Alıcı Testi

**Amaç:** OPNsense firewall loglarının NetGuard'a ulaştığını doğrula.

**OPNsense Konfigürasyonu** (bir kez yapılır):
```
System → Settings → Logging → Remote → Enable
Host: 192.168.203.134
Port: 5140   (UDP)
```

**Test:**
```bash
# NetGuard Server'da log akışını izle
tail -f /tmp/netguard_debug.log | grep syslog

# OPNsense'de test trafiği üret (Kali'den):
ping -c 3 10.0.30.1
```

**Dashboard'da Kontrol:**
- Logs sayfası → source: OPNsense IP → Syslog kayıtları görünmeli
- event_action: `fw_block` veya `fw_allow`

**✅ Başarı Kriteri:** Logs sayfasında OPNsense IP kaynaklı, son 1 dakika içinde kayıt var.

---

### 1.2 NetFlow Testi

**Amaç:** VyOS NetFlow v5/v9 akışının normalize edildiğini doğrula.

**VyOS Konfigürasyonu** (bir kez yapılır):
```bash
ssh vyos@192.168.203.200
configure
set system flow-accounting interface eth0
set system flow-accounting netflow version 9
set system flow-accounting netflow server 192.168.203.134 port 2055
set system flow-accounting netflow timeout expiry-interval 60
commit
save
exit
```

**Test:**
```bash
# NetGuard Server'da port 2055 dinleniyor mu?
ss -ulnp | grep 2055
# Beklenen: 0.0.0.0:2055 dinleniyor

# Trafik üret (Kali'den):
curl http://10.0.10.2   # DMZ web sunucusuna istek

# Tcpdump ile NetFlow paketle kontrol:
sudo tcpdump -i eth0 port 2055 -c 5
```

**Dashboard'da Kontrol:**
- Logs sayfası → event_category: `network`
- Network Intelligence sayfası → flow verileri görünmeli

**✅ Başarı Kriteri:** Logs sayfasında VyOS (192.168.203.200) kaynaklı `network_flow` kayıtları var.

---

### 1.3 Zeek TAP Testi

**Amaç:** 9 Zeek log türünün tamamının parse edildiğini doğrula.

```bash
# Zeek log dizinini kontrol et
ls /zeek-logs/
# dns.log http.log ssl.log conn.log ssh.log notice.log x509.log smtp.log ftp.log görünmeli

# Offset dosyasının oluştuğunu doğrula (restart-safety)
cat /tmp/netguard_zeek_offsets.json
# Beklenen: {"dns.log": 12345, "http.log": 67890, ...}

# Her log tipini test et:

# DNS testi
dig google.com @8.8.8.8

# HTTP testi
curl http://10.0.10.2

# SSH testi (başarısız giriş)
ssh wronguser@192.168.203.142 2>/dev/null || true

# FTP testi
ftp 10.0.10.2 <<EOF
user anonymous
bye
EOF
```

**Dashboard'da Kontrol:**
- Network Intelligence sayfası → DNS sorgular, HTTP istekler, TLS bağlantılar görünmeli
- Logs sayfası → event_action içinde `dns_query`, `http_request`, `tls_connection` var

**✅ Başarı Kriteri:** Zeek log türlerinin en az 5'i Logs sayfasında görünüyor.

---

### 1.4 SNMP Testi

**Amaç:** SNMP polling'in cihaz metriklerini topladığını doğrula.

```bash
# NetGuard Server'da SNMP test sorgusu
snmpwalk -v2c -c public 192.168.203.200 1.3.6.1.2.1.1.1.0
# VyOS sistem tanımı dönmeli

# SNMP Trap testi (VyOS'tan):
snmptrap -v2c -c public 192.168.203.134 '' 1.3.6.1.4.1.8072.2.3.0.1
```

**Dashboard'da Kontrol:**
- Devices/SNMP sayfası → VyOS (192.168.203.200) cihaz listede
- Metrikler: ifInOctets, ifOutOctets, sysUpTime

**✅ Başarı Kriteri:** Devices sayfasında en az bir cihaz SNMP verisiyle görünüyor.

---

### 1.5 Agent Testi

**Amaç:** psutil ajanının Agent VM'den metrik gönderdiğini doğrula.

```bash
# Agent VM'de
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.142
cd ~/netguard/agent
python3 agent.py --server https://192.168.203.134 --token [AGENT_TOKEN]
```

**Dashboard'da Kontrol:**
- Agents sayfası → 192.168.203.142 "online" görünmeli
- CPU, bellek, açık portlar görünmeli

**✅ Başarı Kriteri:** Agents sayfasında ajan online, son heartbeat < 2 dakika önce.

---

## BÖLÜM 2 — Tehdit Tespit Testleri

### 2.1 Port Tarama Tespiti (RECON Kill Chain)

**Amaç:** nmap port taramasının RECON kill chain aşamasını tetiklediğini doğrula.

```bash
# Kali'den NetGuard Server'a nmap tarama:
nmap -sS -p 1-1000 192.168.203.134

# Alternatif (daha hızlı tetiklemek için):
nmap -sS --min-rate 1000 192.168.203.134
```

**Beklenen Akış (30 sn içinde):**
1. `port_scan` dedektörü → RECON correlated event
2. Correlation sayfasında yeni olay
3. Attack Chains sayfasında 192.168.203.132 için RECON aşaması
4. Incident oluşur

**Dashboard'da Kontrol:**
```bash
# API ile kontrol
curl -k -H "Authorization: Bearer [TOKEN]" \
  https://192.168.203.134/api/v1/attack-chains | python3 -m json.tool
# 192.168.203.132 için recon aşaması görünmeli
```

**✅ Başarı Kriteri:** Attack Chains sayfasında RECON aşaması, Incidents'ta yeni incident.

---

### 2.2 SSH Brute Force Tespiti (WEAPONIZE Kill Chain)

**Amaç:** Hydra SSH saldırısının tespitini ve WEAPONIZE aşamasını doğrula.

```bash
# Kali'den — yavaş (60sn):
hydra -l root -P /usr/share/wordlists/rockyou.txt \
  -t 4 -W 1 ssh://192.168.203.142

# Hızlı tetiklemek için (5 başarısız giriş yeterli):
for i in {1..6}; do
  ssh -o StrictHostKeyChecking=no -o ConnectTimeout=3 \
    wrongpass@192.168.203.142 2>/dev/null || true
done
```

**Beklenen (< 60 sn):**
1. JSON korelasyon kuralı `ssh_brute_force` → correlated event
2. pySigma `SSH Targeted Attack` kuralı da tetiklenir
3. Kill chain: WEAPONIZE eklenir

**Dashboard'da Kontrol:**
- Correlation sayfası → `ssh_brute_force` kuralı tetiklenmiş
- Incidents → medium/high severity incident
- Attack Chains → RECON + WEAPONIZE (eğer nmap da yapıldıysa)

**✅ Başarı Kriteri:** WEAPONIZE aşaması kill chain'de görünüyor.

---

### 2.3 Tam Kill Chain Tespiti (FULL_ATTACK_CHAIN)

**Amaç:** ≥3 aşamanın 30 dakika içinde aynı IP'den tetiklenince FULL_ATTACK_CHAIN üretildiğini doğrula.

**Sırayla yap (hepsini 30 dakika içinde, Kali'den):**

```bash
# AŞAMA 1 — RECON (port tarama)
nmap -sS -p 1-1000 192.168.203.134

# 30 sn bekle

# AŞAMA 2 — WEAPONIZE (SSH brute force)
for i in {1..8}; do ssh wrongpass@192.168.203.142 2>/dev/null; done

# 30 sn bekle

# AŞAMA 3 — ACCESS (başarılı SSH girişi — zayıf şifreyle test kullanıcısı gerekir)
# NOT: Agent VM'de test kullanıcısı oluştur:
# sudo useradd -m testuser && echo "testuser:test123" | sudo chpasswd
ssh testuser@192.168.203.142
```

**Beklenen:**
- RECON + WEAPONIZE + ACCESS → FULL_ATTACK_CHAIN (critical)
- Email bildirimi gönderilir
- Discord/Slack webhook çağrılır
- Dashboard'da kırmızı "TAM ZINCIR" uyarısı

**Dashboard'da Kontrol:**
- Attack Chains sayfası → FULL_ATTACK_CHAIN (critical) görünmeli
- Incidents → severity: critical, yeni incident

**✅ Başarı Kriteri:** Attack Chains sayfasında "TAM" etiketi, Incidents'ta critical severity.

---

### 2.4 ARP Spoofing Tespiti

```bash
# Kali'den (arpspoof kurulu olmalı)
sudo arpspoof -i eth0 -t 192.168.203.134 192.168.203.200

# 30 sn sonra durdur (Ctrl+C)
```

**Beklenen:** ARP Spoof dedektörü → `arp_attack` correlated event → RECON kill chain

**✅ Başarı Kriteri:** Logs sayfasında `arp_spoof` event_action, Correlation'da uyarı.

---

### 2.5 DNS Anomali Tespiti

```bash
# DNS query burst (Kali'den):
for i in {1..30}; do
  host random$i.nonexistent.test 8.8.8.8 2>/dev/null
done

# DNS TXT sorgusu (C2 tüneli simülasyonu):
for i in {1..15}; do
  dig TXT $(cat /dev/urandom | tr -dc 'a-z0-9' | head -c 20).example.com @8.8.8.8
done
```

**✅ Başarı Kriteri:** Logs'da `nxdomain` veya `dns_query_burst` event_action.

---

### 2.6 Anomali Tespiti (IsolationForest)

**Amaç:** Anormal trafik hacminin ML ile tespit edildiğini doğrula.

```bash
# Kali'den ani bağlantı patlaması:
for i in {1..200}; do
  curl -s --max-time 1 http://192.168.203.134:8000/api/v1/health &
done
wait

# Dashboard kontrolü — 60 sn sonra:
curl -k -H "Authorization: Bearer [TOKEN]" \
  https://192.168.203.134/api/v1/anomaly/results | python3 -m json.tool
```

**✅ Başarı Kriteri:** Anomaly sayfasında `anomaly_spike` veya yüksek anomaly skoru görünüyor.

---

## BÖLÜM 3 — Aktif Yanıt Testleri (P1–P8)

### Hazırlık: JWT Token Al

```bash
TOKEN=$(curl -sk -X POST https://192.168.203.134/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"[ADMIN_PASSWORD]"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

echo $TOKEN   # boş olmamalı
```

---

### 3.1 P1 — RFC1918 Koruma Geçidi

**Amaç:** 192.168.x.x adreslerinin bloklanamadığını doğrula.

```bash
curl -sk -X POST https://192.168.203.134/api/v1/response/block \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip":"192.168.1.100","reason":"test"}'

# Beklenen: HTTP 400
# {"detail": "192.168.1.100 korumalı adres (RFC1918/loopback/PROTECTED_CIDRS)..."}
```

**✅ Başarı Kriteri:** HTTP 400, RFC1918 mesajı.

---

### 3.2 P4 — Severity Threshold (BLOCK_MIN_SEVERITY)

**Amaç:** Düşük severity'li incidentten gelen blok talebinin reddedildiğini doğrula.

```bash
# Önce low severity bir incident ID bul:
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://192.168.203.134/api/v1/incidents?severity=low&limit=1" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print(d[0]['incident_id'] if d else 'yok')"

# O incident ID ile blok dene (BLOCK_MIN_SEVERITY=high ise reddedilmeli):
curl -sk -X POST https://192.168.203.134/api/v1/response/block \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip":"1.2.3.4","reason":"test","source_incident_id":"[LOW_INCIDENT_ID]"}'

# Beklenen: HTTP 422 — "severity 'low', minimum 'high' gerekiyor"
```

**✅ Başarı Kriteri:** HTTP 422, severity mesajı.

---

### 3.3 P5 — Progressive TTL (Tekrarlayan İhlalci)

**Amaç:** Aynı IP tekrar bloklandığında TTL'nin arttığını doğrula.

```bash
TEST_IP="5.6.7.8"

# 1. Blok
curl -sk -X POST https://192.168.203.134/api/v1/response/block \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"$TEST_IP\",\"reason\":\"progressive test\"}" | python3 -m json.tool
# ttl_hours: 1 beklenen (1. ihlal)

# Unblock
curl -sk -X DELETE "https://192.168.203.134/api/v1/response/block/$TEST_IP" \
  -H "Authorization: Bearer $TOKEN"

# 2. Blok (aynı IP, offense_count=2 → TTL=4)
curl -sk -X POST https://192.168.203.134/api/v1/response/block \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"$TEST_IP\",\"reason\":\"progressive test 2\"}" | python3 -m json.tool
# ttl_hours: 4 beklenen (2. ihlal)
```

**✅ Başarı Kriteri:** TTL 1→4→24→168 saat sırasıyla artıyor.

---

### 3.4 Gerçek Blok — OPNsense veya VyOS

**Amaç:** Dış IP engelinin gerçekten firewall'a yazıldığını doğrula.

```bash
# DIŞARIDAN gelen public IP seç (Kali'nin WAN IP'si değil, GNS3 dışı bir IP):
EXTERNAL_IP="203.0.113.50"   # TEST-NET-3, RFC 5737 — güvenli test adresi

# Blokla
curl -sk -X POST https://192.168.203.134/api/v1/response/block \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"ip\":\"$EXTERNAL_IP\",\"reason\":\"e2e test blok\"}"

# OPNsense'de doğrula (SSH veya GUI):
ssh -J netguard@192.168.203.134,vyos@192.168.203.200 root@10.0.30.1 \
  "pfctl -t NETGUARD_BLOCK -T show"
# 203.0.113.50 listede görünmeli

# Audit log kontrolü:
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://192.168.203.134/api/v1/security/audit?limit=5" | python3 -m json.tool
# ip_blocked action, actor=admin, resource=ip:203.0.113.50

# Temizle
curl -sk -X DELETE "https://192.168.203.134/api/v1/response/block/$EXTERNAL_IP" \
  -H "Authorization: Bearer $TOKEN"
```

**✅ Başarı Kriteri:** OPNsense'de IP alias'ta görünüyor, audit log kaydı var.

---

### 3.5 P6 — Blok Doğrulama (Verify)

**Amaç:** verify_blocks'un phantom/orphan tespitini doğrula.

```bash
# Verify endpoint'ini çağır:
curl -sk -H "Authorization: Bearer $TOKEN" \
  "https://192.168.203.134/api/v1/response/verify" | python3 -m json.tool

# Beklenen normal durum:
# {"status":"ok","synced":[],"phantom":[],"orphan":[],"opnsense_up":true,"vyos_up":true}

# Phantom test (DB'de var, firewall'da yok):
# OPNsense GUI'den manuel olarak bir IP'yi alias'tan sil
# Sonra verify çağır → phantom listesinde görünmeli
```

**✅ Başarı Kriteri:** `status: "ok"` ve her iki provider'ın durumu görünüyor.

---

### 3.6 P8 — Break-Glass Acil Unblock

**Amaç:** Break-glass token'ıyla JWT olmadan acil unblock çalışıyor mu?

```bash
# Önce bir IP blokla:
curl -sk -X POST https://192.168.203.134/api/v1/response/block \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ip":"203.0.113.51","reason":"break-glass test"}'

# Break-glass ile unblock (JWT yok!):
curl -sk -X DELETE \
  "https://192.168.203.134/api/v1/response/break-glass/203.0.113.51" \
  -H "X-Break-Glass-Token: [BREAK_GLASS_TOKEN]" | python3 -m json.tool
# Beklenen: {"success": true, ...}

# Rate limit testi (5/dakika):
for i in {1..6}; do
  curl -sk -X DELETE \
    "https://192.168.203.134/api/v1/response/break-glass/1.2.3.4" \
    -H "X-Break-Glass-Token: yanlistoken"
  echo ""
done
# 6. istekte HTTP 429 beklenmeli
```

**✅ Başarı Kriteri:** Break-glass çalışıyor, 6. istekte rate limit (429) devreye giriyor.

---

## BÖLÜM 4 — Dashboard Sayfaları Kontrolü

Her sayfayı aç, 30 saniye incele. Hata veya boş sayfa varsa not al.

| Sayfa | URL | Kontrol Edilecekler |
|-------|-----|---------------------|
| Overview | `/` | Son 24h olay sayısı, sistem durumu, kill chain widget |
| Logs | `/logs` | Filtre (source_ip, tarih, event_action) çalışıyor mu? |
| Incidents | `/incidents` | Severity renk kodları, MITRE teknikler görünüyor mu? |
| Aktif Bloklar | `/active-response` | Liste, expires_at, offense_count gösteriliyor mu? |
| Alerts | `/alerts` | Son alertler, severity badge'leri |
| Correlation | `/correlation` | JSON ve Sigma kural tetiklenmeleri ayrı mı gösteriliyor? |
| Network Intelligence | `/network-intel` | JA3, DNS, TLS grafikleri render oluyor mu? |
| MITRE ATT&CK | `/mitre` | Heatmap render oluyor mu, tıklanabilir mi? |
| Timeline | `/timeline` | Kill chain aşamaları timeline'da görünüyor mu? |
| Topology | `/topology` | Ağ haritası oluşuyor mu? |
| Agents | `/agents` | Agent VM online görünüyor mu? |
| Reports | `/reports` | PDF/CSV export çalışıyor mu? |
| Audit | `/security` | Aktif yanıt audit kayıtları görünüyor mu? |
| Compliance | `/compliance` | 26 kontrol puan gösteriyor mu? |

---

## BÖLÜM 5 — Bildirim Testleri

### 5.1 Email Bildirimi

```bash
# .env'de SMTP ayarları doluysa:
# FULL_ATTACK_CHAIN tetiklenince otomatik email gönderilmeli
# Gelen kutusunu kontrol et
```

### 5.2 Webhook (Discord/Slack)

```bash
# .env'de WEBHOOK_URL varsa:
# FULL_ATTACK_CHAIN sonrası Discord/Slack kanalını kontrol et
```

---

## BÖLÜM 6 — Hata Durumu Rehberi

| Belirti | Muhtemel Neden | Çözüm |
|---------|---------------|-------|
| Logs sayfası boş | Syslog/Zeek aktarımı yok | `ZEEK_LOG_DIR` doğru mu? Zeek çalışıyor mu? |
| Kill chain tetiklenmiyor | STAGE_MAP eşleşmesi yok | event_action'ı Logs'ta kontrol et |
| OPNsense blok başarısız | API key hatalı / OPNSENSE_HOST boş | `.env` → `OPNSENSE_KEY`/`OPNSENSE_SECRET` |
| Rate limit (429) blok endpoint'inde | `@limiter` devrede | Bekle, 1 dakika sonra tekrar dene |
| Break-glass çalışmıyor | `BREAK_GLASS_TOKEN` env boş | `.env` dosyasını kontrol et |
| Zeek logları restart'ta yeniden yükleniyor | `ZEEK_OFFSET_FILE` yazılamıyor | `ls -la /tmp/netguard_zeek_offsets.json` |
| Verify phantom hataları | OPNsense erişilemiyor | VPN / network bağlantısını kontrol et |
| pySigma tespiti çalışmıyor | PostgreSQL bağlantısı yok | `DATABASE_URL` env var kontrolü |

---

## BÖLÜM 7 — Performans Referans Değerleri

Lab ortamında beklenen normal değerler:

| Metrik | Beklenen | Alarm Sınırı |
|--------|---------|-------------|
| Syslog normalize gecikme | < 2 sn | > 10 sn |
| Korelasyon döngüsü süresi | < 10 sn | > 30 sn |
| Port tarama tespit süresi | < 30 sn | > 60 sn |
| SSH brute force tespit | < 60 sn | > 120 sn |
| OPNsense blok uygulama | < 3 sn | > 10 sn |
| Dashboard sayfa yükleme | < 2 sn | > 5 sn |
| Backend RAM kullanımı | < 420 MB | > 800 MB |

---

## Kontrol Listesi (Tüm Testleri Geçtikten Sonra)

```
Veri Toplama:
[ ] 1.1 Syslog — OPNsense logları geliyor
[ ] 1.2 NetFlow — VyOS akışları normalize ediliyor
[ ] 1.3 Zeek — 5+ log türü Logs sayfasında görünüyor
[ ] 1.3 Zeek — /tmp/netguard_zeek_offsets.json oluşmuş
[ ] 1.4 SNMP — En az bir cihaz Devices sayfasında
[ ] 1.5 Agent — Agent VM "online"

Tehdit Tespiti:
[ ] 2.1 Port tarama → RECON kill chain
[ ] 2.2 SSH brute force → WEAPONIZE kill chain
[ ] 2.3 Tam kill chain → FULL_ATTACK_CHAIN (critical)
[ ] 2.4 ARP spoofing → tespit
[ ] 2.5 DNS anomali → tespit
[ ] 2.6 Anomali → ML skoru görünüyor

Aktif Yanıt:
[ ] 3.1 P1 RFC1918 → 400 hatası
[ ] 3.2 P4 Severity gate → 422 hatası
[ ] 3.3 P5 Progressive TTL → 1→4 saat artışı
[ ] 3.4 Gerçek blok → OPNsense pfctl listesinde
[ ] 3.4 Audit log → kayıt oluşmuş
[ ] 3.5 P6 Verify → synced/phantom/orphan doğru
[ ] 3.6 P8 Break-glass → JWT olmadan unblock çalışıyor
[ ] 3.6 Rate limit → 6. istekte 429

Dashboard:
[ ] Tüm 14 sayfa açılıyor, hata yok
[ ] MITRE heatmap render oluyor
[ ] Kill chain timeline doğru gösteriyor

Bildirimler:
[ ] Email (SMTP varsa)
[ ] Webhook (Discord/Slack varsa)
```

---

*Hazırlayan: NetGuard — Manuel Test Ekibi*
*Versiyon: 1.0 — Mayıs 2026*
