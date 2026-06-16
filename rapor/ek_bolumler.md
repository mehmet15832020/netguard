# EK BÖLÜMLER — Rapora Eklenecek

## NEREYE EKLENECEK
- 3.10 → Bölüm 3'ün sonuna (3.9'dan sonra)
- 5.5 → Bölüm 5'in sonuna (5.4'ten sonra)

---

## 3.10 Değişiklik Yönetimi ve Mühendislik Standartları

### 3.10.1 Sürüm Denetim Sistemi

NetGuard geliştirme süreci boyunca Git sürüm denetim sistemi ve GitHub uzak deposu kullanılmıştır. Tüm kod değişiklikleri Conventional Commits spesifikasyonuna uygun biçimde işlenmiştir. Commit mesaj formatı şu şekilde standardize edilmiştir:

| Ön Ek | Kapsam | Açıklama |
|-------|--------|----------|
| feat | detection, security, nsm | Yeni özellik eklenmesi |
| fix | ui, baseline, sensor | Hata düzeltmesi |
| refactor | db, auth | Yeniden yapılandırma |
| docs | | Belgeleme güncellemesi |
| test | | Test eklenmesi veya düzenlenmesi |

Her görev bağımsız bir commit ile sonlandırılmış; testler geçmeden commit oluşturulmamıştır. Bu kural, kod tabanının her commit noktasında çalışır ve doğrulanmış durumda kalmasını güvence altına almaktadır.

### 3.10.2 Değişiklik Yönetimi Süreci

Yeni özellik veya değişiklik talepleri üç aşamalı bir süreçten geçmektedir:

**Araştırma Aşaması:** Her yeni bileşen veya değişiklik, kodlamaya başlanmadan önce NIST, CIS, SANS, OWASP, MITRE ve ilgili RFC dokümanları incelenerek endüstri standardı referans alınır. Yaklaşım kullanıcıya sunulur ve onay alınır.

**Geliştirme Aşaması:** Onaylanan tasarım doğrultusunda implementasyon gerçekleştirilir. Yeni bileşen; birim testi, çapraz test ve entegrasyon testi olmak üzere üç katmanlı test piramidine göre doğrulanır.

**Doğrulama Aşaması:** Tüm testler geçildikten sonra değişiklik commit edilir ve CLAUDE.md proje rehberinde ilgili görev tamamlandı olarak işaretlenir. Bu süreç, proje durumunun her an izlenebilir ve tekrarlanabilir olmasını sağlamaktadır.

### 3.10.3 Uygulanan Mühendislik Standartları

NetGuard'ın tasarım ve gerçekleştirme sürecinde başvurulan standartlar ve çerçeveler şu şekilde özetlenebilir:

| Standart / Çerçeve | Kapsam | Uygulandığı Bileşen |
|-------------------|--------|-------------------|
| NIST SP 800-94 Rev. 1 [1] | IDPS mimarisi referansı | Genel sistem tasarımı |
| NIST SP 800-92 [2] | Log yönetimi gereksinimleri | Audit log, normalized_logs |
| NIST SP 800-34 Rev. 1 [3] | Yedekleme ve kurtarma | Backup/restore prosedürü |
| NIST SP 800-137 [4] | Sürekli izleme | Korelasyon döngüsü, sensor health |
| CIS Controls v8.1 — Kontrol 13 [5] | Ağ izleme ve savunma | Sensor health eşikleri (%5/%15) |
| MITRE ATT&CK v17 [6] | Tehdit sınıflandırma | Kill chain, Sigma kuralları |
| OWASP API Security Top 10 2023 [19] | API güvenlik gereksinimleri | Rate limiting, input validation |
| ISO/IEC 27001:2022 [22] | Bilgi güvenliği yönetimi | Audit log, şifreleme, erişim kontrolü |
| RFC 7011 — IPFIX [11] | NetFlow protokol standardı | netflow_receiver.py |
| RFC 3164 — Syslog [13] | Syslog protokol standardı | syslog_receiver.py |
| Community ID Spesifikasyonu [15] | Çapraz kaynak korelasyon | normalized_logs.community_id |
| Conventional Commits | Commit mesaj standardı | Tüm git geçmişi |

### 3.10.4 Kod Kalitesi ve Güvenli Kodlama İlkeleri

Geliştirme sürecinde aşağıdaki ilkeler zorunlu olarak uygulanmıştır:

**SQL Enjeksiyon Koruması:** Tüm veritabanı sorgularında parametreli `%s` placeholder kullanılmıştır; dinamik SQL string birleştirme hiçbir noktada uygulanmamıştır.

**Kimlik Doğrulama Güvenliği:** `verify_token(token, token_type=)` fonksiyonunda zorunlu tip doğrulaması uygulanmış; access token ile refresh token'ın birbirinin yerine kullanılması engellenmiştir. API anahtarları SHA-256 hash olarak saklanmakta, plaintext hiçbir zaman veritabanına yazılmamaktadır.

**Sır Yönetimi:** Tüm hassas konfigürasyon değerleri (API anahtarları, veritabanı parolası, JWT secret) ortam değişkenleri üzerinden yönetilmektedir; kaynak koduna veya sürüm geçmişine gömülmemiştir.

**Hata Yönetimi:** Sistem sınırlarında (kullanıcı girdisi, harici API) kapsamlı doğrulama uygulanmıştır. İç modüller arası çağrılarda gereksiz try/except bloklarından kaçınılmış; sessiz hata yutma (`except: pass`) yerine `logger.warning` veya `logger.debug` kullanılmıştır.

---

## 5.5 Ticarileşme Planı

### 5.5.1 Hedef Pazar ve Değer Önerisi

NetGuard'ın birincil hedef pazarı, 50–500 çalışanlı, kurumsal siber güvenlik çözümlerine bütçe ayıramayan ancak ağ görünürlüğüne ihtiyaç duyan orta ölçekli şirketlerdir. Bu segmentin temel problemi şu şekilde özetlenebilir: Splunk ve QRadar gibi kurumsal çözümler yıllık 30.000–100.000 dolar lisans maliyetiyle bu kurumların erişim sınırlarının ötesindeyken, Security Onion gibi açık kaynak alternatiflerin kurulum ve yönetim karmaşıklığı uzman SOC personeli gerektirmektedir.

NetGuard'ın değer önerisi üç eksende konumlandırılmaktadır:

- **Maliyet:** Sıfır lisans bedeli; yalnızca altyapı ve isteğe bağlı yönetilen servis maliyeti
- **Kurulum kolaylığı:** Docker Compose ile 30 dakikada çalışır hale getirilecek şekilde tasarlanmış platform
- **Kapsam:** Security Onion ile karşılaştırılabilir NSM kapsamı; ek olarak bulut log entegrasyonu, AI destekli alert açıklaması ve multi-tenant izolasyon

### 5.5.2 Gelir Modeli Seçenekleri

Açık kaynak projelerin ticarileştirilmesinde kanıtlanmış üç model değerlendirilmiştir:

| Model | Açıklama | Örnek |
|-------|---------|-------|
| Açık Çekirdek (Open Core) | Temel platform açık kaynak; gelişmiş özellikler (UEBA, SOAR, Arkime PCAP) ücretli eklenti olarak sunulur | Elastic, GitLab |
| Yönetilen Servis (Managed Service) | Kurulum, yapılandırma ve süregelen yönetim aylık sabit ücretle MSSP ortaklığı modeli üzerinden sunulur | Wazuh Cloud |
| Destek Aboneliği | Platform ücretsiz; öncelikli teknik destek, SLA ve özelleştirme danışmanlığı ücretlidir | Red Hat |

NetGuard için birincil model olarak **Yönetilen Servis + Açık Çekirdek** hibrit yaklaşımı önerilmektedir. Platform açık kaynak kalır; N10 (UEBA) ve Arkime PCAP gibi yüksek altyapı gerektiren özellikler ücretli bulut servis olarak sunulabilir.

### 5.5.3 Ticarileşme Yol Haritası

**Aşama 1 — Teknik Olgunluk (Tamamlandı):**
Platform, 2.788 test ve GNS3 ortamı doğrulamasıyla üretim düzeyine ulaşmıştır. T2 teknik ticari hazırlık serisi (tamper-proof audit log, at-rest şifreleme, MFA/TOTP, RLS multi-tenant izolasyon, rate limiting) eksiksiz tamamlanmıştır.

**Aşama 2 — Hukuki ve Uyumluluk Altyapısı (Planlanan):**
Şirket kuruluşu, KVKK kapsamında Veri Sorumlusu kaydı, Kişisel Verilerin Korunması Kurumu (KVKK) DPA uyumu ve Teknoloji Hatası & İhmal (Tech E&O) sigortası bu aşamanın temel çıktılarıdır.

**Aşama 3 — Güvenlik Sertifikasyonu (Planlanan):**
Bağımsız sızma testi ve SOC 2 Type I denetimi, kurumsal müşteri güveninin inşası açısından zorunludur. Bu aşama, Aşama 2'nin tamamlanmasına bağımlıdır.

**Aşama 4 — Pazar Girişi (Planlanan):**
3 KOBİ pilot müşterisiyle gerçek üretim ortamında platform doğrulaması, MSSP (Managed Security Service Provider) ortaklık modelinin kurulması ve ilk ticari sözleşmelerin imzalanması bu aşamayı oluşturmaktadır.

