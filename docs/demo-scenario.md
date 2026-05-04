# NetGuard — Demo Senaryosu

**Hedef:** 5 aşamalı saldırı zincirini canlı olarak göstermek; NetGuard'ın her aşamayı nasıl tespit edip kill chain'e bağladığını, otomatik incident açıp bildirim gönderdiğini ve IT yöneticisine tek ekranda bağlam sunduğunu kanıtlamak.

**Süre:** ~15 dakika  
**Ortam:** GNS3 lab — Kali (192.168.203.132), NetGuard (192.168.203.134), Agent VM (192.168.203.142)

---

## Ön Hazırlık (Demo Öncesi ~5 Dakika)

### 1. Sistemi Başlat

```bash
# Tüm VM'lerin ayakta olduğunu doğrula
ping -c 1 192.168.203.134   # NetGuard Server
ping -c 1 192.168.203.132   # Kali
ping -c 1 192.168.203.142   # Agent VM
```

### 2. NetGuard Dashboard'u Aç

Tarayıcıda: `https://192.168.203.134`  
Giriş: `admin` / `netguard123`

Kontrol et:
- Overview sayfasında kill chain tüm aşamalar boş (gri)
- Incidents sayfasında aktif incident yok (veya az)
- Security Events akışı canlı

### 3. Temiz Başlangıç İçin (Opsiyonel)

Eğer önceki test verileri ekranı dolduracaksa, mevcut incident'ları "resolved" yap:  
Incidents → tüm açık incident'lar → Durum Değiştir → Çözüldü

---

## Demo Akışı

### AŞAMA 1 — RECON: Port Tarama

**Kali'de çalıştır:**
```bash
nmap -sS 192.168.203.134
```

**Arka planda ne olur:**
- pyshark TCP SYN paketlerini yakalar
- `port_scan_attempt` eventi `normalized_logs`'a yazılır
- Sigma kuralı `port_scan_detected` tetiklenir
- Kill chain RECON aşaması işaretlenir

**Dashboard'da göster:**
1. **Security Events** → `port_scan_attempt` kaydını göster (src_ip: 192.168.203.132)
2. **Attack Timeline** (Saldırı Zaman Çizelgesi) → RECON aşamasının yeşillendiğini göster
3. Mesaj: *"Kali'nin bir port taraması yaptığını otomatik tespit ettik — herhangi bir kural yazmamıza gerek kalmadı."*

---

### AŞAMA 2 — WEAPONIZE: SSH Brute Force

**Kali'de çalıştır:**
```bash
hydra -l netguard -P /usr/share/wordlists/rockyou.txt \
      -t 4 -V ssh://192.168.203.134
# 5-10 deneme yeterli, ardından Ctrl+C
```

**Arka planda ne olur:**
- OPNsense/VyOS syslog → syslog_receiver → `ssh_failure` eventleri
- 5+ başarısız giriş `ssh_brute_force` sigma kuralını tetikler
- Kill chain WEAPONIZE aşaması işaretlenir
- Korelasyon motoru otomatik incident açar

**Dashboard'da göster:**
1. **Incidents** → yeni açılan "SSH Brute Force" incident'ını göster
2. Incident'a tıkla → **Yönet** → zenginleştirme panelini göster:
   - MITRE teknik rozeti: **T1110** (Brute Force)
   - İlgili loglar: ardışık `ssh_failure` kayıtları
3. **Attack Timeline** → RECON + WEAPONIZE yeşil
4. Mesaj: *"5 başarısız giriş yeterli — sistem otomatik incident açtı, MITRE tekniği eşlendi."*

---

### AŞAMA 3 — ACCESS: Başarılı Giriş

**Kali'de çalıştır:**
```bash
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.134
# Başarılı giriş yap, ardından exit
```

**Arka planda ne olur:**
- Syslog → `ssh_success` eventi
- Kill chain ACCESS aşaması işaretlenir
- 3 aşama tamamlandı → `PARTIAL_ATTACK_CHAIN` uyarısı üretilebilir

**Dashboard'da göster:**
1. **Security Events** → `ssh_success` kaydı (aynı src_ip)
2. **Attack Timeline** → RECON + WEAPONIZE + ACCESS üçü birden yeşil
3. Önceki incident'ın zenginleştirme panelinde `ssh_success` kaydının ilgili loglar listesine girdiğini göster
4. Mesaj: *"Saldırgan içeri girdi. Sistem üç aşamayı birbirine bağladı — tek IP, ortak hikaye."*

---

### AŞAMA 4 — LATERAL: İç Ağ Taraması

**Kali'de önce Agent VM'e bağlan, sonra scripti çalıştır:**
```bash
# Kali'den Agent VM'e
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.142

# Agent VM'den iç ağ taraması
bash ~/netguard/scripts/lateral_movement_test.sh
```

Script ne yapar: `192.168.203.134`, `192.168.203.200`, `192.168.203.132` adreslerine port 22/445/3389 üzerinden bağlantı dener.

**Arka planda ne olur:**
- NetGuard'ın pyshark sniffer'ı Agent VM'in SYN paketlerini yakalar
- `192.168.203.142` → 3 farklı iç hedefe → `lateral_movement` eventi
- Kill chain LATERAL aşaması işaretlenir
- 4 aşama tamamlandı → `FULL_ATTACK_CHAIN` tetiklenir → critical incident açılır → email/webhook gönderilir

**Dashboard'da göster:**
1. **Incidents** → yeni `FULL_ATTACK_CHAIN` incident'ını göster (severity: critical)
2. Incident zenginleştirme paneli:
   - MITRE: **T1021** (Remote Services) veya lateral movement tekniği
   - İlgili loglar: tüm aşamaların logları birlikte
3. **Attack Timeline** → 4 aşama birden yeşil, zaman çizelgesi dolu
4. Mesaj: *"4 aşama tamamlandı. Sistem otomatik kritik incident açtı ve bildirim gönderdi — IT yöneticisi sabah bunu görür."*

---

### AŞAMA 5 — FULL CHAIN Gösterimi (Kapanış)

**Dashboard'da göster:**
1. **Overview** sayfası — risk skoru yüksek, kritik incident sayısı
2. **MITRE ATT&CK** sayfası — ısı haritasında bu saldırıdan eşlenen teknikler vurgulanmış
3. Incident detayı — tek ekranda:
   - Hangi IP saldırdı
   - Hangi MITRE teknikleri kullanıldı
   - İlgili logların zaman çizelgesi
   - Threat intel skoru (varsa)
4. Mesaj: *"Splunk'ta bunu kurmak için 6 ay ve 50.000 dolar gerekir. NetGuard: açık kaynak, 30 dakikada kurulum."*

---

## Olası Sorunlar ve Çözümler

| Sorun | Neden | Çözüm |
|-------|-------|-------|
| Port scan tespiti gecikiyor | pyshark 2 dakikalık pencere | 2 dk bekle, ardından Security Events'i yenile |
| SSH brute force incident açılmıyor | Hydra çok az deneme yaptı | En az 6 deneme yapıldığından emin ol |
| Lateral movement görünmüyor | Agent VM, NetGuard'ın sniffer'ı ens33 üzerinde göremeyebilir | Alternatif: Kali'den direkt lateral_movement_test.sh çalıştır |
| Kill chain dolmuyor | Korelasyon döngüsü 60 saniyede bir çalışır | 60-90 saniye bekle, sayfayı yenile |
| Dashboard açılmıyor | netguard-dashboard.service durmuş | `sudo systemctl restart netguard-dashboard.service` |
| API cevap vermiyor | netguard.service durmuş | `sudo systemctl restart netguard.service` |

---

## Demo Sonrası Soru-Cevap Notları

**"Gerçek üretim ortamında kullanılabilir mi?"**
> Evet. Docker ile 30 dakikada kurulur. Mevcut firewall/router'ın syslog çıkışını yönlendirmek yeterli — ağda değişiklik gerekmez.

**"Zeek veya Suricata kadar derin analiz yapıyor mu?"**
> Şu an SYN tabanlı paket analizi + syslog/NetFlow üzerinden çalışıyor. Span port + Zeek entegrasyonu yol haritasında — DNS/HTTP/SSL içerik analizi o adımda gelecek.

**"False positive nasıl yönetiliyor?"**
> Threshold'lar yapılandırılabilir (sigma YAML veya .env). Whitelist mekanizması yol haritasında.

**"Veri nereden toplanıyor, agent şart mı?"**
> Agent opsiyonel. Mevcut ağ cihazının syslog/NetFlow çıkışı yönlendirilirse agent olmadan da çalışır.
