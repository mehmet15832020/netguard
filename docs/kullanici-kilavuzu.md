# NetGuard Kullanıcı Kılavuzu

> Teknik bilgi gerektirmez. Bu kılavuz NetGuard'ı ilk kez kullananlar için yazılmıştır.

---

## İçindekiler

1. [NetGuard Nedir?](#1-netguard-nedir)
2. [Sistemi Başlatma](#2-sistemi-başlatma)
3. [İlk Giriş](#3-ilk-giriş)
4. [Genel Bakış Sayfası](#4-genel-bakış-sayfası)
5. [Cihazlar](#5-cihazlar)
6. [Ağ Keşfi](#6-ağ-keşfi)
7. [Topoloji Haritası](#7-topoloji-haritası)
8. [Agentlar](#8-agentlar)
9. [Alertler](#9-alertler)
10. [Güvenlik Olayları](#10-güvenlik-olayları)
11. [Korelasyon Kuralları](#11-korelasyon-kuralları)
12. [Log Akışı](#12-log-akışı)
13. [SNMP Yönetimi](#13-snmp-yönetimi)
14. [Raporlar](#14-raporlar)
15. [Ayarlar](#15-ayarlar)
16. [Lab Ortamı Senaryoları](#16-lab-ortamı-senaryoları)
17. [Sık Sorulan Sorular](#17-sık-sorulan-sorular)

---

## 1. NetGuard Nedir?

NetGuard, ağınızdaki tüm cihazları ve güvenlik olaylarını **tek bir ekrandan** izlemenizi sağlayan bir sistemdir.

İki ana işlevi vardır:

| İşlev | Ne yapar? |
|-------|-----------|
| **Ağ Yönetimi (NMS)** | Switch, router, sunucu gibi cihazların durumunu, bant genişliğini ve yanıt sürelerini izler |
| **Güvenlik İzleme (CSNM)** | Brute-force saldırıları, port taramaları, ARP zehirlenmesi gibi tehditleri tespit eder |

### Ne izler?

- **SNMP cihazları** — Router, switch, güvenlik duvarı (cihazın kendisinden metrik alır)
- **Agent kurulu sunucular** — Linux/Windows makinelere kurulu hafif yazılım sayesinde log ve metrik toplar
- **Keşfedilen cihazlar** — Ağa bağlı ama üzerinde yazılım olmayan her şey (IP kameralar, yazıcılar vb.)

---

## 2. Sistemi Başlatma

### Sunucu tarafında (VM1 — NetGuard Server)

```bash
cd /home/mehmet/netguard
source venv/bin/activate
uvicorn server.main:app --host 0.0.0.0 --port 8000
```

### Arayüz tarafında (aynı veya farklı makine)

```bash
cd /home/mehmet/netguard/dashboard-v2
npm run dev
```

Tarayıcıda `http://localhost:3000` adresine gidin.

> **Not:** Üretim ortamında her iki servis de arka planda (systemd servisi olarak) çalışır. Geliştirme ortamında yukarıdaki komutlar yeterlidir.

---

## 3. İlk Giriş

Tarayıcıda `http://localhost:3000` açıldığında otomatik olarak giriş sayfasına yönlendirilirsiniz.

**Varsayılan kimlik bilgileri:**

| Alan | Değer |
|------|-------|
| Kullanıcı adı | `admin` |
| Şifre | `.env` dosyasındaki `ADMIN_PASSWORD` değeri |

Giriş yaptıktan sonra **Genel Bakış** sayfasına yönlendirilirsiniz.

> Şifrenizi değiştirmek için Ayarlar → Kullanıcı Yönetimi bölümüne gidin.

---

## 4. Genel Bakış Sayfası

Sistemi açtığınızda gördüğünüz ilk ekran budur. Tek bakışta durumu anlamanızı sağlar.

### Üst kartlar (Özet Metrikler)

| Kart | Ne gösterir? |
|------|-------------|
| **Toplam Cihaz** | Sistemde kayıtlı tüm cihazların sayısı |
| **Aktif Alert** | Henüz çözümlenmemiş alarm sayısı |
| **Güvenlik Olayı** | Son 24 saatte tespit edilen tehdit sayısı |
| **Online Agent** | Şu anda aktif olarak veri gönderen agent sayısı |

### Canlı Metrik Grafiği

Sayfanın ortasında gerçek zamanlı güncellenen bir grafik gösterir. Bu grafik WebSocket bağlantısıyla canlı akar — sayfa yenilemek gerekmez.

### Mini Topoloji Haritası

Sayfanın alt kısmında ağınızdaki cihaz bağlantılarının küçük bir görsel haritası yer alır. "Tam görünüm →" linkine tıklayarak detaylı topoloji sayfasına geçebilirsiniz.

---

## 5. Cihazlar

Sol menüden **Cihazlar** seçeneğine tıklayın.

### Cihaz Listesi

Sistemde kayıtlı tüm cihazları görürsünüz:

- **Ad** — Cihaza verilen isim
- **IP Adresi** — Cihazın ağ adresi
- **Tür** — snmp / agent / discovered
- **Durum** — online / offline / unknown
- **Son Görülme** — En son ne zaman yanıt verdi

### Cihaz Filtreleme

Üst kısımdaki arama kutusuna IP adresi veya cihaz adı yazarak filtreleyebilirsiniz. Tür seçici ile sadece belirli türdeki cihazları görüntüleyebilirsiniz.

### Cihaz Detayı

Herhangi bir cihaza tıklayarak detay panelini açabilirsiniz:

- Metrik geçmişi (CPU, bellek, bant genişliği)
- SNMP bilgileri
- Son alertler
- Sistem bilgileri (vendor, OS)

---

## 6. Ağ Keşfi

Sol menüden **Keşif** seçeneğine tıklayın.

### Ne işe yarar?

NetGuard, belirttiğiniz IP aralığını otomatik olarak tarar ve ağınızdaki tüm cihazları bulur. Router'ınızı, kameralarınızı, yazıcılarınızı — her şeyi.

### Nasıl çalıştırılır?

1. **Subnet** alanına taranacak ağ aralığını girin (örn: `192.168.1.0/24`)
2. **Keşfi Başlat** butonuna tıklayın
3. Tarama arka planda çalışır, tamamlandığında sonuçlar listede görünür

### Sonuçları Anlamak

| Sütun | Açıklama |
|-------|----------|
| IP | Bulunan cihazın adresi |
| MAC | Fiziksel adres (mümkünse) |
| Vendor | MAC adresinden tahmin edilen üretici |
| OS | İşletim sistemi tahmini (TTL analizi ile) |
| Durum | open-ports / alive / unreachable |

### Cihazı Sisteme Eklemek

Bulunan bir cihazı sisteme kaydetmek için satırdaki **Ekle** butonuna tıklayın. Cihaz Cihazlar sayfasında görünmeye başlar.

---

## 7. Topoloji Haritası

Sol menüden **Topoloji** seçeneğine tıklayın.

### Ne gösterir?

Ağınızdaki cihazların birbirine nasıl bağlı olduğunu gösteren interaktif bir harita. Cihazlar arası bağlantılar SNMP ARP tabloları ve LLDP protokolü kullanılarak otomatik keşfedilir.

### Harita ile Etkileşim

- **Fare tekerleği** — Yakınlaştır / uzaklaştır
- **Sol tık + sürükle** — Haritayı kaydır
- **Düğüme tıkla** — Cihaz bilgilerini göster
- **Düğümü sürükle** — Konumu değiştir (geçici)

### Renk Kodları

| Renk | Anlam |
|------|-------|
| Mavi | Normal çalışan cihaz |
| Sarı | Uyarı durumunda |
| Kırmızı | Çevrimdışı veya kritik uyarı |

### Topoloji Yenilemek

Sağ üst köşedeki **Yenile** butonuna basın. Sistem tekrar ARP/LLDP taraması yapar ve haritayı günceller.

---

## 8. Agentlar

Sol menüden **Agents** seçeneğine tıklayın.

### Agent Nedir?

Agent, izlemek istediğiniz bir Linux/Windows makineye kurduğunuz küçük bir yazılımdır. Kurulduktan sonra o makineden:

- CPU / RAM / disk kullanımı
- Ağ trafiği
- Sistem logları
- Güvenlik olayları (başarısız girişler, port taramaları vb.)

gibi verileri otomatik olarak NetGuard'a gönderir.

### Agent Kurulumu (Linux)

NetGuard sunucusuna gidin ve **Yeni Agent Ekle** butonuna tıklayın. Size bir API anahtarı ve kurulum komutu verilecektir. O komutu agent kurmak istediğiniz makinede çalıştırın:

```bash
# Örnek (gerçek değerler NetGuard'dan alınır)
curl -s http://NETGUARD_IP:8000/agent-setup.sh | \
  AGENT_API_KEY=abc123 bash
```

Kurulum tamamlandığında agent listesinde yeşil olarak görünür.

### Agent Durumlarını Anlamak

| Durum | Anlam |
|-------|-------|
| **online** (yeşil) | Agent aktif, veri gönderiyor |
| **offline** (kırmızı) | Agent son 5 dakikadır veri göndermedi |
| **stale** (sarı) | Veri geliyor ama eskimiş |

---

## 9. Alertler

Sol menüden **Alertler** seçeneğine tıklayın.

Sidebar'da kırmızı bir rozet görürseniz bu, henüz görülmemiş yeni alertler olduğu anlamına gelir.

### Alert Seviyeleri

| Seviye | Renk | Ne anlama gelir? |
|--------|------|-----------------|
| **critical** | Kırmızı | Hemen müdahale gerektirir |
| **warning** | Sarı | İncelenmeli |
| **info** | Mavi | Bilgi amaçlı |

### Alertleri Yönetme

- **Çözümlendi işaretle** — Alerta baktınız ve gerekeni yaptınız
- **Filtrele** — Seviyeye veya cihaza göre filtrele
- **Arama** — Alert mesajında kelime ara

### Alertler Ne Zaman Oluşur?

- Bir cihaz çevrimdışı olduğunda
- CPU/bellek eşiği aşıldığında
- Güvenlik tehdidi tespit edildiğinde
- Korelasyon kuralı tetiklendiğinde

---

## 10. Güvenlik Olayları

Sol menüden **Güvenlik** seçeneğine tıklayın.

### Ne izlenir?

NetGuard aşağıdaki tehditleri otomatik olarak tespit eder:

| Tehdit | Açıklama |
|--------|----------|
| **Brute-Force / SSH Saldırısı** | Bir IP'den kısa sürede çok sayıda başarısız giriş denemesi |
| **Port Taraması** | Bir IP'nin çok sayıda farklı porta bağlanmaya çalışması |
| **ARP Zehirlenmesi** | Ağdaki ARP tablolarının manipüle edilmesi (MITM saldırısı) |
| **ICMP Flood** | Ping bombardımanı (DoS saldırısı) |
| **DNS Anomalisi** | Olağandışı DNS sorgu hacmi |
| **Suricata Uyarısı** | Suricata IDS kurallarına uyan trafik |
| **Zeek/Wazuh Olayı** | Zeek veya Wazuh tarafından işaretlenen olay |

### Olayları Okumak

Her olay satırında şunlar gösterilir:

- **Zaman** — Tespit zamanı
- **Tür** — Tehdit kategorisi
- **Kaynak IP** — Saldırıyı yapan adres
- **Kullanıcı adı** — Varsa hedef kullanıcı
- **Mesaj** — Ne olduğunun özeti
- **Seviye** — critical / warning / info

### Ham Log

Bir olayın detayına tıkladığınızda ham log satırını görebilirsiniz — tam olarak sistemden gelen orijinal log.

---

## 11. Korelasyon Kuralları

Sol menüden **Korelasyon** seçeneğine tıklayın.

### Korelasyon Nedir?

Tek başına anlamsız görünen olayları birleştirerek daha büyük bir tehdidi ortaya çıkarır.

**Örnek:** 
- 60 saniye içinde aynı IP'den 5'ten fazla başarısız SSH girişi → "SSH Brute-Force Saldırısı" alarmı üretir

### Mevcut Kurallar

Kural listesi sayfada görüntülenir. Her kural için:

- **Ad** — Kuralın ismi
- **Tetikleyici** — Hangi olay türüne bakıyor
- **Eşik** — Kaç olay olduğunda tetiklenir
- **Süre** — Kaç saniyelik zaman penceresi
- **Aktif mi** — Kural çalışıyor mu

### Kural Durumunu Değiştirme

Bir kuralı geçici olarak devre dışı bırakmak için yanındaki toggle'a tıklayın.

> **Teknik not:** Korelasyon kuralları `config/correlation_rules.json` dosyasından yüklenir. Yeni kural eklemek için bu dosyayı düzenleyin ve servisi yeniden başlatın.

---

## 12. Log Akışı

Sol menüden **Loglar** seçeneğine tıklayın.

### Ne gösterir?

Tüm kaynaklardan gelen normalize edilmiş logların canlı akışı. Agent'lardan, Suricata'dan, Wazuh'tan, sistem loglarından gelen her şey tek listede görünür.

### Filtreleme

- **Kaynak** — Hangi sistemden geldiğine göre filtrele
- **Seviye** — error / warning / info
- **Arama** — Log mesajında anahtar kelime ara
- **Tarih aralığı** — Belirli bir zaman dilimini görüntüle

---

## 13. SNMP Yönetimi

Sol menüden **SNMP** seçeneğine tıklayın.

### SNMP Nedir?

SNMP (Simple Network Management Protocol), router, switch ve güvenlik duvarı gibi ağ cihazlarından bilgi almanın standart yoludur. Cihaza agent kurmaya gerek yoktur — cihaz zaten bu protokolü destekler.

### Cihaz Sorgulamak

1. **Host** alanına cihazın IP adresini girin
2. **Versiyon** seçin: v2c (standart) veya v3 (şifreli)
3. **v2c için:** Community string girin (genellikle `public`)
4. **v3 için:** Kullanıcı adı, kimlik doğrulama protokolü ve anahtarları girin
5. **Sorgula** butonuna tıklayın

### Sonuçları Anlamak

Sorgu sonucunda cihazdan alınan metrikler tablo halinde görünür:

| Metrik | Açıklama |
|--------|----------|
| sysDescr | Cihaz açıklaması |
| sysUpTime | Cihazın ne kadar süredir açık olduğu |
| ifInOctets | Her arayüzde gelen veri miktarı |
| ifOutOctets | Her arayüzde giden veri miktarı |

### SNMPv2c vs SNMPv3

| | v2c | v3 |
|--|-----|-----|
| Güvenlik | Düşük (community string şifresiz gider) | Yüksek (şifreli, kimlik doğrulamalı) |
| Kullanım kolaylığı | Kolay | Daha karmaşık |
| Tavsiye | Lab/test ortamı | Üretim ortamı |

---

## 14. Raporlar

Sol menüden **Raporlar** seçeneğine tıklayın.

### Özet Kartlar

Sayfa açıldığında dört kart gösterir:

- Toplam cihaz sayısı
- Aktif alert sayısı
- Güvenlik olayı sayısı
- Topoloji bağlantı sayısı

### CSV İndirme

Dört farklı raporu CSV olarak indirebilirsiniz:

| Rapor | İçerik |
|-------|--------|
| **Cihaz Envanteri** | Tüm cihazlar — IP, MAC, tür, durum, ilk/son görülme |
| **Alert Geçmişi** | Tüm alertler — seviye, mesaj, oluşma zamanı |
| **Güvenlik Olayları** | Tüm güvenlik olayları — kaynak IP, tür, zaman |
| **Topoloji Kenarları** | Hangi cihaz hangisine bağlı |

**İndirmek için:** İlgili butonun yanındaki **İndir** simgesine tıklayın. Tarayıcı dosyayı otomatik indirir.

> CSV dosyaları Excel, Google Sheets veya herhangi bir tablo programıyla açılabilir.

---

## 15. Ayarlar

Sol menüden **Ayarlar** seçeneğine tıklayın.

### API Anahtarları

Agent'ların NetGuard'a bağlanmak için kullandığı anahtarları buradan yönetirsiniz:

- Yeni anahtar oluşturma
- Mevcut anahtarı silme (o anahtarla bağlanan agent artık bağlanamaz)
- Son kullanım zamanını görme

### Kullanıcı Yönetimi

- Yeni kullanıcı ekleme
- Şifre değiştirme
- Kullanıcı rolü: `admin` (tam yetki) veya `viewer` (sadece görüntüleme)

---

## 16. Lab Ortamı Senaryoları

Bu bölüm mevcut lab kurulumunuz için pratik kullanım örneklerini içerir.

### Mevcut Lab Yapısı

```
VM1 (192.168.203.134) — NetGuard Server
VM2 (192.168.203.142) — Agent + Kali (saldırı testleri)
```

### Senaryo 1: Agent Kurulumu ve İzleme

**Amaç:** VM2'yi NetGuard'a agent olarak bağlamak.

1. NetGuard arayüzünde **Ayarlar → API Anahtarları** → Yeni anahtar oluşturun
2. VM2'de agent yazılımını başlatın:
   ```bash
   cd /home/mehmet/netguard
   NETGUARD_URL=http://192.168.203.134:8000 \
   AGENT_API_KEY=<oluşturduğunuz_anahtar> \
   python agent/agent.py
   ```
3. **Agents** sayfasında VM2'nin online göründüğünü doğrulayın
4. **Güvenlik** sayfasında VM2'den gelen sistem loglarının aktığını görün

### Senaryo 2: Brute-Force Saldırısı Testi

**Amaç:** Kali'den VM2'ye SSH brute-force saldırısı yaparak NetGuard'ın tespit ettiğini doğrulamak.

1. VM1'de NetGuard'ın çalıştığından emin olun
2. VM2'de agent çalışıyor olmalı
3. Kali'de (VM2 içinde):
   ```bash
   hydra -l root -P /usr/share/wordlists/rockyou.txt \
     ssh://192.168.203.134
   ```
4. NetGuard **Güvenlik** sayfasında `ssh_failure` olaylarının listelendiğini görün
5. **Alertler** sayfasında brute-force alarmının oluştuğunu doğrulayın

### Senaryo 3: Ağ Keşfi

**Amaç:** Lab ağındaki tüm cihazları keşfetmek.

1. **Keşif** sayfasına gidin
2. Subnet: `192.168.203.0/24` girin
3. **Keşfi Başlat**'a tıklayın
4. Birkaç dakika sonra VM1 ve VM2'nin listede göründüğünü doğrulayın
5. Switch veya router varsa onlar da listelenecektir

### Senaryo 4: SNMP ile Router İzleme

**Amaç:** Lab'daki router veya switch'i SNMP ile izlemek.

1. **SNMP** sayfasına gidin
2. Cihazın IP'sini girin (örn: `192.168.203.1`)
3. Versiyon: `v2c`, Community: `public` (cihaz ayarlarına göre değişir)
4. **Sorgula** butonuna tıklayın
5. Uptime, arayüz istatistikleri görünmeli
6. Sonuçlar beğendiyse cihazı **Cihazlara Ekle** ile kaydedin

### Senaryo 5: Topoloji Haritasını Oluşturma

**Amaç:** Lab ağının görsel haritasını oluşturmak.

1. Önce Senaryo 3 veya 4'ü yaparak cihazları sisteme ekleyin
2. **Topoloji** sayfasına gidin
3. **Yenile** butonuna tıklayın
4. Sistem SNMP üzerinden ARP tablolarını okuyarak bağlantıları çizer
5. Haritada cihazların birbirine nasıl bağlandığını görün

### Senaryo 6: Rapor Alma

**Amaç:** Haftalık envanter raporu almak.

1. **Raporlar** sayfasına gidin
2. **Cihaz Envanteri** → **İndir** tıklayın
3. İndirilen CSV'yi Excel'de açın
4. Tüm cihazların listesi, MAC adresleri ve durumları görünür

---

## 17. Sık Sorulan Sorular

**S: Dashboard açılmıyor, "Cannot connect" hatası veriyor.**

Sunucu tarafının çalıştığından emin olun:
```bash
# VM1'de:
curl http://localhost:8000/health
# "ok" döndürmeli
```
Döndürmüyorsa `uvicorn server.main:app --host 0.0.0.0 --port 8000` komutunu çalıştırın.

---

**S: Agent "offline" gösteriyor ama makine açık.**

- Agentin gerçekten çalışıp çalışmadığını kontrol edin: `ps aux | grep agent.py`
- NetGuard sunucusuna ağ bağlantısı var mı: `ping 192.168.203.134`
- API anahtarı doğru mu: agent loglarında hata mesajı var mı

---

**S: Güvenlik olayları görünmüyor.**

- Agent çalışmalı ve NetGuard'a bağlı olmalı
- `auth.log` dosyasının okunabilir olduğundan emin olun: `ls -la /var/log/auth.log`
- Suricata/Wazuh entegrasyonu için o servislerin de çalışıyor olması gerekir

---

**S: SNMP sorgusu "timeout" veriyor.**

- Cihazda SNMP aktif mi? (Router/switch yönetim arayüzünden kontrol edin)
- Community string doğru mu? (Varsayılan `public`)
- Firewall SNMP portunu (UDP 161) bloklüyor olabilir

---

**S: Topoloji haritası boş görünüyor.**

- En az birkaç cihaz sisteme kayıtlı olmalı
- SNMP erişimi olan cihazlar olmadan ARP tabloları okunamaz
- **Yenile** butonuna basın ve birkaç saniye bekleyin

---

**S: CSV indirmesi çalışmıyor.**

- Tarayıcının pop-up / indirme engelleyicisi devrede olabilir
- Tarayıcı konsolunu açın (F12) ve hata mesajı var mı bakın
- NetGuard API'sine erişilebilir mi: `http://localhost:8000/api/v1/reports/summary`

---

**S: "Unauthorized" hatası alıyorum.**

Oturum süresi dolmuş olabilir. Sayfayı yenileyin — otomatik olarak giriş sayfasına yönlendirilirsiniz. Yeniden giriş yapın.

---

## Hızlı Referans

### Önemli Adresler

| Servis | Adres |
|--------|-------|
| Dashboard | `http://localhost:3000` |
| API | `http://localhost:8000` |
| API Dokümantasyonu | `http://localhost:8000/docs` |

### Klavye Kısayolları (Dashboard)

| Kısayol | İşlev |
|---------|-------|
| `G` ardından `O` | Genel Bakış'a git |
| `G` ardından `D` | Cihazlar'a git |
| `G` ardından `A` | Alertler'e git |

---

*NetGuard — Unified Network Intelligence Platform*
*Kılavuz sürümü: Nisan 2026*
