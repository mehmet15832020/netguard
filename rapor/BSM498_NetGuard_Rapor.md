# T.C. SAKARYA ÜNİVERSİTESİ  
## BİLGİSAYAR VE BİLİŞİM BİLİMLERİ FAKÜLTESİ

---

**BSM 498 BİLGİSAYAR MÜHENDİSLİĞİ TASARIMI**

---

# AÇIK KAYNAK AĞ GÜVENLİK İZLEME PLATFORMU GELİŞTİRİLMESİ: NETGUARD

---

**HAZIRLAYAN**

B201210102 — Mehmet Çapar

---

**Bölüm:** Bilgisayar Mühendisliği  
**Tez Danışmanı:** Prof. Dr. İbrahim ÖZÇELİK

---

*Bu tez .. / .. / ... tarihinde aşağıdaki jüri tarafından oybirliği / oyçokluğu ile kabul edilmiştir.*

……………………  ……………………  ……………………  
Jüri Başkanı &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Üye &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; Üye

---

## ÖNSÖZ

Günümüzde kurumsal ağlara yönelik siber saldırıların sıklığı ve karmaşıklığı her geçen yıl artmaktadır. Verizon'un 2025 Veri İhlali Soruşturma Raporu'na (DBIR) göre, veri ihlallerinin ortalama tespit süresi hâlâ 197 günü aşmakta; bu süre zarfında saldırganlar ağ içinde serbestçe hareket edebilmektedir [7]. Ağ Güvenlik İzleme (NSM — Network Security Monitoring), bu açığı kapatmaya yönelik en etkin yaklaşımlardan biri olmakla birlikte, mevcut ticari çözümlerin yüksek lisans maliyetleri (Splunk: ~50.000 $/yıl, QRadar: ~30.000 $/yıl) orta ölçekli kurumların bu teknolojiye erişimini ciddi biçimde kısıtlamaktadır.

Bu tasarım projesi, Sakarya Üniversitesi Bilgisayar Mühendisliği eğitimim boyunca edindiğim ağ güvenliği, sistem programlama ve yazılım mühendisliği bilgilerini bir araya getirerek, bütçe kısıtlı kurumların da kurumsal düzeyde ağ güvenlik izlemesi yapabilmesini sağlayacak açık kaynaklı bir platform geliştirme amacıyla hazırlanmıştır. NetGuard projesi; NIST SP 800-94 [1], CIS Controls v8.1 [5] ve MITRE ATT&CK [6] çerçevelerine dayanan, çok katmanlı bir NSM mimarisi olarak tasarlanmış ve gerçekleştirilmiştir.

Bu çalışmanın ortaya çıkmasında değerli bilgi ve tecrübelerini paylaşan, mimari tasarım kararlarında yol gösteren danışman hocam Sayın Prof. Dr. İbrahim ÖZÇELİK'e en içten teşekkürlerimi sunarım. Ayrıca üniversite hayatım boyunca yanımda olan aileme sonsuz minnet duyuyorum.

---

## İÇİNDEKİLER

- ÖNSÖZ
- SİMGELER VE KISALTMALAR LİSTESİ
- ŞEKİLLER LİSTESİ
- TABLOLAR LİSTESİ
- ÖZET
- **BÖLÜM 1. GİRİŞ**
  - 1.1 Projenin Konusu ve Amacı
  - 1.2 Ağ Güvenlik İzlemesinin (NSM) Önemi
  - 1.3 Mevcut Sistemlerin Analizi
  - 1.4 Projenin Kapsamı ve Sınırları
  - 1.5 Yazılım Gereksinim Analizi
    - 1.5.1 Fonksiyonel Gereksinimler
    - 1.5.2 Fonksiyonel Olmayan Gereksinimler
- **BÖLÜM 2. SİSTEMATİK YAKLAŞIM VE MİMARİ TASARIM**
  - 2.1 Genel Sistem Mimarisi ve Veri Akış Pipeline'ı
  - 2.2 Veri Toplama Katmanı Tasarımı
  - 2.3 Normalleştirme ve Veri Modeli
  - 2.4 Tespit Katmanı Mimarisi
    - 2.4.1 pySigma v2 Kural Motoru
    - 2.4.2 JSON Korelasyon Motoru
    - 2.4.3 Davranışsal Anomali Tespiti (IsolationForest)
    - 2.4.4 Öldürme Zinciri (Kill Chain) Modeli
    - 2.4.5 Beaconing (C2 Sinyal) Tespiti
  - 2.5 Aktif Yanıt Katmanı Tasarımı
  - 2.6 Web Arayüzü Mimari Tasarımı
  - 2.7 Veritabanı ve Zaman Serisi Tasarımı
- **BÖLÜM 3. GERÇEKLEŞTİRME VE YAZILIM BİLEŞENLERİ**
  - 3.1 Veri Toplama Modülleri
    - 3.1.1 Syslog Toplayıcı
    - 3.1.2 SNMP Toplayıcı
    - 3.1.3 Zeek Ağ Analiz Entegrasyonu
    - 3.1.4 Suricata EVE JSON Entegrasyonu
    - 3.1.5 NetFlow/IPFIX/sFlow Toplayıcı
    - 3.1.6 Windows Agent ve EVTX Parser
    - 3.1.7 OpenCanary Honeypot Entegrasyonu
    - 3.1.8 Bulut Toplayıcılar (M365 ve Google Workspace)
  - 3.2 Log Normalleştirme ve Parser Mimarisi
  - 3.3 Tespit Motorunun Gerçekleştirilmesi
    - 3.3.1 Sigma Kuralları ve pySigma v2
    - 3.3.2 Korelasyon Motoru
    - 3.3.3 Anomali Tespiti
    - 3.3.4 Kill Chain Dedektörü
    - 3.3.5 Özel Dedektörler
  - 3.4 Tehdit İstihbaratı Entegrasyonu
  - 3.5 Aktif Yanıt Sistemi
  - 3.6 Dashboard ve Görselleştirme
    - 3.6.1 Genel Bakış Paneli (Bento Grid)
    - 3.6.2 Kill Chain Swimlane Timeline
    - 3.6.3 MITRE ATT&CK Navigator
    - 3.6.4 AI Alert Explainer
    - 3.6.5 Tehdit Avı (Threat Hunt) Workbench
  - 3.7 Güvenlik ve Uyumluluk Özellikleri
    - 3.7.1 JWT ve MFA/TOTP Kimlik Doğrulama
    - 3.7.2 Tamper-Proof Denetim Günlüğü
    - 3.7.3 Multi-Tenant Row-Level Security
    - 3.7.4 At-Rest Şifreleme
    - 3.7.5 Sistematik Rate Limiting
  - 3.8 Community ID Çapraz Kaynak Korelasyonu
  - 3.9 Operasyonel Altyapı
- **BÖLÜM 4. TEST ORTAMI VE PERFORMANS ANALİZİ**
  - 4.1 GNS3 Sanal Laboratuvar Ortamı
  - 4.2 Test Metodolojisi
  - 4.3 Birim ve Entegrasyon Test Sonuçları
  - 4.4 Saldırı Senaryosu Doğrulama
  - 4.5 Sistem Performans Metrikleri
- **BÖLÜM 5. SONUÇ**
  - 5.1 Elde Edilen Kazanımlar
  - 5.2 Rakip Sistemlerle Karşılaştırma
  - 5.3 Karşılaşılan Zorluklar ve Çözümler
  - 5.4 Gelecek Çalışmalar
- KAYNAKLAR
- EKLER
- ÖZGEÇMİŞ

---

## SİMGELER VE KISALTMALAR LİSTESİ

| Kısaltma | Açıklama |
|----------|----------|
| API | Application Programming Interface (Uygulama Programlama Arayüzü) |
| ARP | Address Resolution Protocol (Adres Çözümleme Protokolü) |
| ATT&CK | Adversarial Tactics, Techniques and Common Knowledge |
| BPF | Berkeley Packet Filter |
| C2 | Command and Control (Komuta ve Kontrol) |
| CIS | Center for Internet Security |
| CISA | Cybersecurity and Infrastructure Security Agency |
| DNS | Domain Name System (Alan Adı Sistemi) |
| ECS | Elastic Common Schema |
| EDR | Endpoint Detection and Response (Uç Nokta Tespiti ve Yanıtı) |
| EVE | Extensible Event Format (Suricata çıktı formatı) |
| FTP | File Transfer Protocol |
| HIDS | Host-based Intrusion Detection System |
| IAT | Inter-Arrival Time (Paket Geliş Arası Süre) |
| ICMP | Internet Control Message Protocol |
| IDS | Intrusion Detection System (Saldırı Tespit Sistemi) |
| IPFIX | IP Flow Information Export |
| JWT | JSON Web Token |
| KEV | Known Exploited Vulnerabilities |
| MITRE | Massachusetts Institute of Technology Research and Engineering |
| MFA | Multi-Factor Authentication (Çok Faktörlü Kimlik Doğrulama) |
| MTTR | Mean Time to Respond (Ortalama Yanıt Süresi) |
| MTTD | Mean Time to Detect (Ortalama Tespit Süresi) |
| NDR | Network Detection and Response |
| NIDS | Network-based Intrusion Detection System |
| NIST | National Institute of Standards and Technology |
| NSM | Network Security Monitoring (Ağ Güvenlik İzleme) |
| PCAP | Packet Capture |
| RLS | Row-Level Security |
| RFC | Request for Comments |
| REST | Representational State Transfer |
| SHA | Secure Hash Algorithm |
| SIEM | Security Information and Event Management |
| SNMP | Simple Network Management Protocol |
| SOC | Security Operations Center |
| SSH | Secure Shell |
| TCP | Transmission Control Protocol |
| TLS | Transport Layer Security |
| TOTP | Time-based One-Time Password |
| UDP | User Datagram Protocol |
| UEBA | User and Entity Behavior Analytics |
| VPN | Virtual Private Network |
| WebSocket | RFC 6455 — Web üzerinden çift yönlü iletişim protokolü |

---

## ŞEKİLLER LİSTESİ

| Şekil No | Açıklama |
|----------|----------|
| Şekil 2.1 | NetGuard üç katmanlı NSM pipeline mimarisi |
| Şekil 2.2 | Veri akışı: Kaynak → normalized_logs → Tespit → Yanıt |
| Şekil 2.3 | Kill chain 5 aşama modeli ve tetikleme eşikleri |
| Şekil 2.4 | Beaconing tespitinde IAT (Inter-Arrival Time) algoritması |
| Şekil 2.5 | Aktif yanıt blok akışı (RFC1918 → FP gate → severity gate → duplicate gate) |
| Şekil 2.6 | Veritabanı ana tablo şeması (normalized_logs / alerts / incidents) |
| Şekil 3.1 | Dashboard genel bakış ekranı — Bento Grid layout |
| Şekil 3.2 | Alerts sayfası — gerçek zamanlı alert listesi ve AI Explainer |
| Şekil 3.3 | Kill Chain Swimlane Timeline |
| Şekil 3.4 | MITRE ATT&CK Navigator — kapsam görselleştirmesi |
| Şekil 3.5 | Sigma Rule Wizard — 4 adımlı kural oluşturma formu |
| Şekil 3.6 | Correlation Rules CRUD sayfası |
| Şekil 3.7 | Threat Hunt Workbench — no-code sorgu builder |
| Şekil 3.8 | Sensor Health Panel — Zeek/Suricata paket düşme oranları |
| Şekil 3.9 | Community ID çapraz kaynak pivot — aynı bağlantının Zeek/Suricata/NetFlow görünümü |
| Şekil 3.10 | Top Talkers paneli — ağdaki en aktif IP'ler |
| Şekil 3.11 | East-West Connection Matrix Heatmap |
| Şekil 4.1 | GNS3 sanal laboratuvar topolojisi |
| Şekil 4.2 | pytest test sonuçları — 2788 test, 0 hata |
| Şekil 4.3 | SSH brute force → FULL_ATTACK_CHAIN kill chain doğrulaması |
| Şekil 4.4 | Asset Risk Heatmap — varlık risk görünümü |

---

## TABLOLAR LİSTESİ

| Tablo No | Açıklama |
|----------|----------|
| Tablo 1.1 | Mevcut NSM/SIEM sistemlerin karşılaştırmalı analizi |
| Tablo 1.2 | Fonksiyonel gereksinimler listesi (FR-01 – FR-15) |
| Tablo 1.3 | Fonksiyonel olmayan gereksinimler listesi (NFR-01 – NFR-08) |
| Tablo 2.1 | Veri toplama kaynakları ve protokolleri |
| Tablo 2.2 | STAGE_MAP — event_action → kill chain aşaması eşlemeleri |
| Tablo 3.1 | Sigma kural dosyaları ve kapsadıkları tehdit kategorileri |
| Tablo 3.2 | Zeek log tipleri ve NetGuard parser kapsamı |
| Tablo 3.3 | Windows Event ID kapsamı (60+ EID) |
| Tablo 3.4 | Tehdit istihbaratı kaynakları ve composite skor ağırlıkları |
| Tablo 3.5 | Alembic migration listesi (021 aşama) |
| Tablo 3.6 | REST API endpoint grupları (31 route dosyası) |
| Tablo 4.1 | Test piramidi — birim / çapraz / entegrasyon test dağılımı |
| Tablo 4.2 | Saldırı senaryosu doğrulama sonuçları |
| Tablo 5.1 | NetGuard ile Security Onion kapabilite karşılaştırması |

---

## ÖZET

**Anahtar Kelimeler:** Ağ Güvenlik İzleme, NSM, SIEM, Kill Chain, Sigma, IsolationForest, TimescaleDB, MITRE ATT&CK, Community ID, Açık Kaynak.

Günümüzde orta ölçekli kurumlar, kurumsal düzeyde siber güvenlik altyapısı kurmanın hem teknik hem de mali güçlükleriyle karşı karşıyadır. Mevcut ticari çözümler yüksek lisans bedelleri nedeniyle bu kurumların büyük çoğunluğunun erişim sınırlarının ötesinde kalmaktadır. Bu proje kapsamında, 50–500 çalışanlı şirketlerin IT yöneticilerini hedef alan, Docker ile 30 dakikada kurulabilen açık kaynaklı bir Ağ Güvenlik İzleme (NSM) platformu olan **NetGuard** tasarlanmış ve eksiksiz biçimde gerçekleştirilmiştir.

NetGuard, üç ana katmandan oluşan bir mimariyle çalışmaktadır: **Toplama katmanı** Syslog, SNMP, Zeek (14 log tipi), Suricata EVE JSON, NetFlow v5/v9/IPFIX/sFlow, Windows Agent (60+ EID, 5 kanal), OpenCanary honeypot ve Microsoft 365/Google Workspace bulut toplayıcılarını kapsamaktadır. **Tespit katmanı** pySigma v2 (50+ kural, 14 kural dosyası), JSON tabanlı korelasyon motoru, scikit-learn IsolationForest anomali tespiti, 5 aşamalı kill chain dedektörü ve C2 beaconing (IAT analizi) motorunu bünyesinde barındırmaktadır. **Yanıt katmanı** ise OPNsense REST API ve VyOS SSH üzerinden IP blokajını, e-posta/webhook bildirimlerini ve kapsamlı denetim günlüğünü yönetmektedir.

Güvenlik mimarisi açısından JWT + TOTP çok faktörlü kimlik doğrulama, SHA-256 zincirli tamper-proof audit log, PostgreSQL Row-Level Security (RLS) ile multi-tenant veri izolasyonu, at-rest alan şifrelemesi ve sistematik rate limiting (60 istek/dakika) uygulanmıştır. TimescaleDB hypertable ile zaman serisi verisi 1 günlük bölümleme ve 7 günlük sıkıştırma politikasıyla yönetilmektedir. Tüm bileşenler GNS3 sanal laboratuvar ortamında test edilmiş; **2788 birim, çapraz ve entegrasyon testi** ile sistem doğrulanmıştır.

---

# BÖLÜM 1. GİRİŞ

## 1.1 Projenin Konusu ve Amacı

NetGuard, ağ trafiği üzerindeki güvenlik tehditlerini gerçek zamanlı olarak toplayan, normalleştiren, tespit eden ve yanıt veren açık kaynaklı bir Ağ Güvenlik İzleme (NSM) platformudur. Proje, piyasadaki kurumsal güvenlik araçlarının (Splunk, IBM QRadar, Darktrace) yüksek lisans maliyetleri nedeniyle erişilemeyen orta ölçekli şirket segmentini hedeflemektedir.

Projenin temel hedefleri şu şekilde özetlenebilir:

- **Kapsamlı Veri Toplama:** Syslog, SNMP, Zeek, Suricata, NetFlow, Windows Agent, OpenCanary ve bulut hizmetleri gibi heterojen kaynaklardan log toplanması; tüm verilerin tek bir normalleştirilmiş formata (ECS uyumlu) dönüştürülmesi.

- **Çok Katmanlı Tespit:** İmza tabanlı (Sigma/pySigma v2), kural tabanlı (JSON korelasyon) ve davranışsal (IsolationForest anomali) tespit yöntemlerinin bir arada kullanılması; saldırı aşamalarının MITRE ATT&CK çerçevesiyle eşlenerek 5 aşamalı kill chain modeliyle izlenmesi.

- **Otomatik Yanıt:** Tespit edilen tehditlerde OPNsense güvenlik duvarı veya VyOS yönlendiricisi üzerinden kaynak IP adresinin bloke edilmesi; olay yönetimi, bildirim ve denetim günlüğü süreçlerinin otomatikleştirilmesi.

- **Erişilebilir Platform:** Docker Compose ile 30 dakikada kurulum, Next.js tabanlı modern web arayüzü ve kapsamlı REST API ile platform operasyonel eşiğinin düşürülmesi.

## 1.2 Ağ Güvenlik İzlemesinin (NSM) Önemi

NIST SP 800-94 Rev. 1, Saldırı Tespit ve Önleme Sistemleri (IDPS) için referans çerçeve olarak tanımlanmış olup ağ temelli izlemenin siber güvenlik mimarisindeki zorunlu konumuna dikkat çekmektedir [1]. Bejtlich'in tanımlamasıyla NSM; "ağı tehlikeye girdiğinde bunu fark edecek şekilde izleme, toplama ve analiz etme pratiği"dir [9]. Bu pratik, geleneksel güvenlik duvarı (firewall) ve IDS çözümlerinin ötesine geçerek ağ trafiğinin bütüncül değerlendirilmesini öngörmektedir.

Verizon 2025 DBIR verileri, başarılı saldırıların %43'ünün ağ trafiğinde tespit edilebilir izler bıraktığını; ancak kurumların büyük bölümünün bu izleri yakalamak için gerekli görünürlükten yoksun olduğunu ortaya koymaktadır [7]. CrowdStrike 2025 Küresel Tehdit Raporu'na göre saldırganların ağ içinde "bekleme süresi" (dwell time) ortalama 10 gündür; bu süre, tespit edilemeyen lateral movement (yanal hareket) ile doğrudan ilişkilidir [8].

NSM yaklaşımı üç temel soruyu yanıtlamayı amaçlar: (1) Ağda neler oluyor? (2) Bu durum normal mi? (3) Anormal duruma nasıl yanıt verilmeli? Bu soruların cevaplanması; ham ağ trafiğinin toplanması, normalize edilmesi, bağlamlandırılması ve analiz edilmesini gerektirmektedir.

CIS Controls v8.1 Kontrol 13 (Ağ İzleme ve Savunma), her kurumun ağ akış verilerini toplamasını, anormal ağ trafiğini tespit etmesini ve yanıt verme kapasitesi geliştirmesini zorunlu kılmaktadır [5]. NetGuard, bu gereksinimin açık kaynak bir uygulama örneğidir.

## 1.3 Mevcut Sistemlerin Analizi

Proje geliştirilmeden önce mevcut NSM/SIEM çözümleri incelenmiştir. Tablo 1.1, başlıca rakip sistemlerin karşılaştırmalı analizini sunmaktadır.

**Tablo 1.1: Mevcut NSM/SIEM Sistemlerin Karşılaştırmalı Analizi**

| Sistem | Tür | Yıllık Maliyet | Ağ İzleme | SIEM | Endpoint | Açık Kaynak | Kurulum Süresi |
|--------|-----|---------------|-----------|------|----------|-------------|----------------|
| Splunk Enterprise Security | SIEM | ~50.000 $ | Kısıtlı | ✓ | ✗ | ✗ | Haftalarca |
| IBM QRadar | SIEM/UEBA | ~30.000 $ | Kısıtlı | ✓ | ✗ | ✗ | Haftalarca |
| Darktrace | NDR/AI | ~100.000 $ | ✓ | ✓ | Kısmi | ✗ | Günlerce |
| Security Onion | NSM | Ücretsiz | ✓ | Kısmi | ✗ | ✓ | Günlerce |
| Wazuh | EDR/HIDS | Ücretsiz | ✗ | Kısmi | ✓ | ✓ | Saatlerce |
| Zeek (Standalone) | Ağ Analiz | Ücretsiz | ✓ | ✗ | ✗ | ✓ | Saatlerce |
| Suricata (Standalone) | NIDS | Ücretsiz | ✓ | ✗ | ✗ | ✓ | Saatlerce |
| **NetGuard** | **NSM** | **Ücretsiz** | **✓** | **Kısmi** | **✗** | **✓** | **~30 dakika** |

**Splunk Enterprise Security:** Piyasanın en olgun SIEM çözümü olmakla birlikte, veri hacmine bağlı lisans modeli (GB/gün başına ücretlendirme) orta ölçekli kurumlar için sürdürülemez maliyetler doğurmaktadır. Ağ akış analizi için ek modül gerektirmektedir.

**IBM QRadar:** Güçlü korelasyon yetenekleri sunmakla birlikte, karmaşık kurulum süreci ve donanım gereksinimleri ciddi uzman ihtiyacı doğurmaktadır. Açık kaynak alternatiflere göre yapılandırma esnekliği sınırlıdır.

**Security Onion:** En yakın rakip olarak değerlendirilebilir; Zeek, Suricata ve Elasticsearch entegrasyonu sunar. Ancak kurulum süreci karmaşıktır, dedicated donanım gerektirir ve kullanıcı arayüzü operasyonel öğrenme eğrisi yüksek olan SOC analistlerine yöneliktir.

**Wazuh:** HIDS/EDR odaklı yapısı ağ tabanlı tespiti sınırlamaktadır. NetFlow veya Zeek entegrasyonu yerel olarak sunulmamaktadır.

NetGuard'ın konumlandırma farkı şu şekilde özetlenebilir: Security Onion ile karşılaştırılabilir NSM kapsamını Docker ile 30 dakikada, sıfır lisans maliyetiyle sunmak ve orta ölçekli IT yöneticisi profilindeki kullanıcılar için operasyonel eşiği düşürmek.

## 1.4 Projenin Kapsamı ve Sınırları

**Kapsam dahilinde:**

- Syslog (güvenlik duvarı, switch), SNMP v2c/v3, NetFlow v5/v9/IPFIX/sFlow veri toplama
- Zeek (14 log tipi), Suricata EVE JSON, pyshark SYN/BPF paket yakalama
- Windows Agent (5 olay kanalı: Security/Sysmon/PowerShell/System/AppLocker, 60+ EID)
- OpenCanary honeypot (12 log tipi), Microsoft 365 ve Google Workspace toplayıcıları
- pySigma v2 imza tespiti (50+ kural, 14 dosya), JSON korelasyon motoru
- IsolationForest davranışsal anomali tespiti, 5 aşamalı kill chain (Lockheed Martin modeli)
- Beaconing/C2 tespiti (IAT — Inter-Arrival Time analizi)
- MITRE ATT&CK v17 eşlemesi, CISA KEV tehdit istihbaratı entegrasyonu
- OPNsense REST + VyOS SSH aktif yanıt, Community ID çapraz kaynak korelasyonu
- Next.js tabanlı web arayüzü (30+ sayfa), TimescaleDB zaman serisi veritabanı
- Docker Compose kurulum paketi, PostgreSQL RLS multi-tenant izolasyon

**Kapsam dışında (mimari karar, 6 Haziran 2026):**

- Tam PCAP (packet capture) depolama — Arkime gibi ayrı donanım altyapısı gerektirir
- UEBA (User and Entity Behavior Analytics) — 60+ günlük üretim verisi gerektirir
- Cloud SIEM log parser (AWS/Azure/GCP) — Cloud SIEM alanı, NSM değil
- SOAR (Security Orchestration, Automation and Response) — TheHive entegrasyonu gelecek çalışmadır
- Güvenlik açığı tarama (Vulnerability Scanner) — Farklı ürün kategorisi

## 1.5 Yazılım Gereksinim Analizi

### 1.5.1 Fonksiyonel Gereksinimler

**Tablo 1.2: Fonksiyonel Gereksinimler Listesi**

| ID | Gereksinim | Öncelik |
|----|-----------|---------|
| FR-01 | Sistem; Syslog (UDP 514), SNMP v2c/v3, NetFlow/IPFIX/sFlow (UDP 2055), Zeek log dosyaları ve Suricata EVE JSON akışından eş zamanlı log toplamalıdır | Kritik |
| FR-02 | Toplanan tüm loglar, ECS uyumlu normalized_logs tablosuna (source_ip, destination_ip, network_protocol, event_action, event_category) normalleştirilmelidir | Kritik |
| FR-03 | pySigma v2 kural motoru, config/sigma_rules_v2/ dizinindeki YAML kurallarını çalıştırarak imza eşleşmelerini tespit etmelidir | Kritik |
| FR-04 | JSON tabanlı korelasyon motoru, 60 saniyelik pencere içinde eşik aşan olay gruplarını tespit etmelidir | Kritik |
| FR-05 | IsolationForest algoritması, per-IP davranışsal profil üzerinden anomali skoru hesaplamalı ve anormal davranışları raporlamalıdır | Yüksek |
| FR-06 | Kill chain dedektörü, kaynak IP bazında 5 aşamayı (RECON/WEAPONIZE/ACCESS/LATERAL/FULL) takip etmeli; 30 dakika penceresi içinde 2 aşama → PARTIAL, 3+ aşama → FULL_ATTACK_CHAIN uyarısı üretmelidir | Kritik |
| FR-07 | Beaconing dedektörü, düzenli aralıklı bağlantılarda IAT standart sapmasını hesaplayarak C2 iletişim örüntülerini tespit etmelidir | Yüksek |
| FR-08 | Tehdit istihbaratı modülü AbuseIPDB, Feodo Tracker, ThreatFox ve GreyNoise kaynaklarını sorgulayarak 0–100 arası composite skor üretmelidir | Yüksek |
| FR-09 | Aktif yanıt modülü; RFC1918 koruması, FP gate, severity gate ve duplicate gate sıralamasını takip ederek OPNsense REST veya VyOS SSH üzerinden IP blokajı uygulamalıdır | Kritik |
| FR-10 | JWT erişim/yenileme token çifti ve TOTP (pyotp, RFC 6238) tabanlı çok faktörlü kimlik doğrulama zorunlu olmalıdır | Kritik |
| FR-11 | Audit log; SHA-256 zinciriyle tamper-proof olmalı, alanlar at-rest şifreli tutulmalıdır | Kritik |
| FR-12 | PostgreSQL Row-Level Security ile multi-tenant veri izolasyonu sağlanmalı; her kiracı yalnızca kendi verisine erişebilmelidir | Yüksek |
| FR-13 | Sistem; korelasyon olayları için e-posta (HTML multipart) ve webhook bildirimleri göndermelidir | Orta |
| FR-14 | MITRE ATT&CK v17 eşlemesi tüm tespit kategorilerini kapsamalı, Navigator layer dosyası oluşturulabilmelidir | Orta |
| FR-15 | Community ID standardına (RFC benzeri Corelight spesifikasyonu) göre hesaplanan akış hash'i, aynı TCP bağlantısının Zeek/Suricata/NetFlow kayıtları arasında pivot yapılmasını sağlamalıdır | Yüksek |

### 1.5.2 Fonksiyonel Olmayan Gereksinimler

**Tablo 1.3: Fonksiyonel Olmayan Gereksinimler Listesi**

| ID | Gereksinim | Ölçüt |
|----|-----------|-------|
| NFR-01 | Korelasyon döngüsü 60 saniyede bir çalışmalı, yüksek log hacminde gecikme 120 saniyeyi aşmamalıdır | Ölçülebilir |
| NFR-02 | TimescaleDB hypertable ile normalized_logs 1 günlük bölümleme, 7 günden eski veriler sıkıştırma politikasına tabi olmalıdır | Zorunlu |
| NFR-03 | Tüm REST API endpoint'leri SlowAPI ile rate limiting korumasına (varsayılan: 60 istek/dk) tabi olmalıdır | Zorunlu |
| NFR-04 | Docker Compose ile tüm servisler 30 dakikadan kısa sürede production ortamında çalışır hale getirilmelidir | Zorunlu |
| NFR-05 | Toplam test sayısı ≥2788 olmalı; 0 hata ile geçmeden commit yapılmamalıdır | Zorunlu |
| NFR-06 | Veritabanı yedekleme RPO ~24 saniye, RTO ~30 dakika olmalıdır (NIST SP 800-34 uyumu) | Ölçülebilir |
| NFR-07 | Web arayüzü sayfa yükleme süresi 3 saniyenin altında olmalı, WebSocket bağlantısı kesintisiz sürdürülmelidir | Ölçülebilir |
| NFR-08 | Tüm kullanıcı girdileri API katmanında doğrulanmalı; SQL injection, XSS ve komut enjeksiyonu güvenlik açıklarına karşı OWASP API Security Top 10 2023 uyumu sağlanmalıdır | Zorunlu |

---

# BÖLÜM 2. SİSTEMATİK YAKLAŞIM VE MİMARİ TASARIM

## 2.1 Genel Sistem Mimarisi ve Veri Akış Pipeline'ı

NetGuard, NIST SP 800-94 Rev. 1'in öngördüğü IDPS mimarisi [1] ile SANS NSM metodolojisinin [9] birleşiminden türetilmiş üç katmanlı bir pipeline üzerine inşa edilmiştir:

```
╔══════════════════════════════════════════════════════════════════════════╗
║                        NETGUARD NSM PIPELINE                           ║
╠══════════════╦═══════════════════════════╦════════════════════════════╣
║   TOPLAMA    ║        TESPİT             ║          YANIT             ║
║  (COLLECT)   ║       (DETECT)            ║        (RESPOND)           ║
╠══════════════╬═══════════════════════════╬════════════════════════════╣
║ Syslog       ║ pySigma v2 (50+ kural)    ║ Incident yönetimi          ║
║ SNMP v2c/v3  ║ JSON korelasyon motoru    ║ Kill chain timeline         ║
║ NetFlow/IPFIX║ IsolationForest anomaly   ║ E-posta + webhook           ║
║ sFlow        ║ Kill chain (5 aşama)      ║ OPNsense REST blok         ║
║ pyshark BPF  ║ Beaconing (IAT/C2)        ║ VyOS SSH fallback           ║
║ Zeek (14 tip)║ ARP/DNS/ICMP/port_scan    ║ Denetim günlüğü            ║
║ Suricata EVE ║ MITRE ATT&CK eşleme       ║                            ║
║ EVTX/Windows ║ Tehdit istihbaratı        ║                            ║
║ OpenCanary   ║ Community ID pivot        ║                            ║
║ M365/GWS     ║                           ║                            ║
╠══════════════╩═══════════════════════════╩════════════════════════════╣
║           normalized_logs (PostgreSQL + TimescaleDB hypertable)        ║
╚══════════════════════════════════════════════════════════════════════════╝
```

**Şekil 2.1:** NetGuard üç katmanlı NSM pipeline mimarisi

Veri akışı şu şekilde gerçekleşir: Her kaynak kendi toplayıcı modülü (Syslog: `syslog_receiver.py`, NetFlow: `netflow_receiver.py`, Zeek: `zeek_collector.py`, vb.) aracılığıyla ham veriyi alır. Ham veri, kaynak tipine özgü parser (zeek.py, suricata.py, netflow.py, windows.py, opencanary.py, cloud.py) tarafından ECS uyumlu NormalizedLog nesnesine dönüştürülür ve tek merkezi tabloya (`normalized_logs`) yazılır. Korelasyon motoru (`correlator.py`) 60 saniyede bir bu tabloyu sorgular, eşik aşmalarını tespit eder ve `correlated_events` tablosuna yazar. Kill chain dedektörü correlated events üzerinden per-IP aşama takibi yapar. Aktif yanıt ise FULL_ATTACK_CHAIN tespitinde otomatik veya operatör onayıyla tetiklenir.

## 2.2 Veri Toplama Katmanı Tasarımı

**Tablo 2.1: Veri Toplama Kaynakları ve Protokolleri**

| Kaynak | Protokol/Format | Port/Konum | Toplayıcı Modül |
|--------|----------------|------------|-----------------|
| Güvenlik duvarı/switch syslog | UDP Syslog (RFC 3164) | UDP 514 | `syslog_receiver.py` |
| SNMP cihazlar | SNMP v2c/v3 poll + trap | UDP 161/162 | `snmp_collector.py` |
| Zeek NSM sensörü | JSON/TSV log dosyaları | /opt/zeek/logs/ | `zeek_collector.py` |
| Suricata IDS | EVE JSON (inode-safe) | /var/log/suricata/eve.json | `suricata_collector.py` |
| NetFlow | v5/v9/IPFIX/sFlow UDP | UDP 2055 | `netflow_receiver.py` |
| Windows Agent | psutil + EVTX (5 kanal) | HTTPS agent push | `evtx_parser.py` |
| OpenCanary | JSON log (12 tip) | Dosya | opencanary parser |
| Microsoft 365 | Graph API (REST) | HTTPS | `m365_collector.py` |
| Google Workspace | Admin SDK (REST) | HTTPS | `gworkspace_collector.py` |
| CISA KEV | HTTPS JSON feed | Günlük | `kev_monitor.py` |

Zeek toplayıcısı 14 farklı log tipini izler: conn, dns, http, ssl, ssh, notice, smtp, ftp, rdp, kerberos, smb, dce_rpc, weird, dpd ve files. `zeek_collector.py`, dosya döngüsüne (log rotation) karşı inode-safe offset mekanizmasıyla çalışır; yeni log dosyası açıldığında offset sıfırlanarak veri kaybı önlenir. Suricata toplayıcısı da aynı mekanizmayı kullanır.

Suricata için 45.343 adet Emerging Threats (ET) kuralı systemd timer aracılığıyla otomatik olarak güncellenmektedir (N4 görevi). Bu sayede yeni tehdit imzaları üretim ortamına operatör müdahalesi olmaksızın yayılmaktadır.

## 2.3 Normalleştirme ve Veri Modeli

Tüm kaynaklardan gelen heterojen verinin tek bir şemada buluşturulması için Elastic Common Schema (ECS) uyumlu bir normalleştirme modeli benimsenmiştir. `normalized_logs` tablosunun temel alanları:

```
normalized_logs
├── id               UUID PRIMARY KEY
├── received_at      TIMESTAMPTZ NOT NULL  ← TimescaleDB bölümleme boyutu
├── source_ip        VARCHAR(45)           ← ECS: source.ip
├── destination_ip   VARCHAR(45)           ← ECS: destination.ip
├── source_port      INTEGER
├── destination_port INTEGER
├── network_protocol VARCHAR(20)           ← ECS: network.protocol
├── event_action     VARCHAR(100)          ← ECS: event.action
├── event_category   VARCHAR(50)           ← ECS: event.category
├── severity         VARCHAR(20)
├── observer_hostname VARCHAR(100)         ← ECS: observer.hostname
├── raw_log          TEXT
├── network_bytes    BIGINT                ← Alembic 009
├── community_id     VARCHAR(50)           ← Alembic 018, Community ID spec
└── tenant_id        UUID                  ← RLS izolasyon anahtarı
```

TimescaleDB hypertable (Alembic 013), `received_at` sütunu üzerinde 1 günlük bölümleme (chunk_time_interval) ile sorgu performansını önemli ölçüde artırmaktadır. 7 günden eski veriler otomatik sıkıştırma politikasına tabi tutularak depolama optimizasyonu sağlanmaktadır.

## 2.4 Tespit Katmanı Mimarisi

### 2.4.1 pySigma v2 Kural Motoru

Sigma, SIEM sistemleri için platform-agnostik tehdit tespit kuralları yazmayı sağlayan açık bir spesifikasyondur [16]. NetGuard, pySigma v2 kütüphanesini kullanarak Sigma kurallarını doğrudan PostgreSQL sorgularına dönüştürür ve çalıştırır. Bu yaklaşım, kural yönetimini koddan bağımsız kılarak dinamik kural ekleme/güncelleme olanağı tanır.

14 kural dosyası aşağıdaki tehdit kategorilerini kapsamaktadır:

**Tablo 3.1: Sigma Kural Dosyaları ve Kapsadıkları Tehdit Kategorileri**

| Kural Dosyası | Tehdit Kategorisi | Kural Sayısı |
|--------------|------------------|-------------|
| ssh_brute_force.yml | SSH kaba kuvvet saldırısı | 3 |
| port_scan.yml | Port tarama (Reconnaissance) | 4 |
| auth_and_web.yml | Web kimlik doğrulama saldırıları | 5 |
| c2_and_exfil.yml | C2 iletişimi ve veri sızdırma | 6 |
| windows_events.yml | Windows olay günlüğü tehditleri | 8 |
| zeek_advanced.yml | Zeek gelişmiş anomaliler | 6 |
| suricata_ids.yml | Suricata IDS uyarıları | 10 |
| netflow.yml | NetFlow akış anomalileri | 6 |
| anomaly_and_impact.yml | Anomali ve etki tespiti | 4 |
| sql_injection.yml | SQL enjeksiyon saldırıları | 3 |
| web_attacks.yml | Web uygulama saldırıları | 4 |
| opencanary.yml | Honeypot tetiklenmeleri | 7 |
| network_community.yml | Ağ topluluk anomalileri | 5 |
| device_and_snmp.yml | Cihaz ve SNMP anomalileri | 3 |
| **Toplam** | | **74** |

### 2.4.2 JSON Korelasyon Motoru

Korelasyon motoru (`correlator.py`), koddan ayrıştırılmış kural yönetimi felsefesiyle `config/correlation_rules.json` dosyasındaki kuralları yükler. Her kural; `match_event_action` (ön-ek eşleşmesi), `group_by` (source_ip veya observer_hostname), `window_seconds` (zaman penceresi), `threshold` (eşik) ve `severity` (üretilen olayın ciddiyeti) alanlarından oluşur.

Motor 60 saniyede bir döngü çalıştırır:

```
[Döngü Başlangıcı: 60s]
      │
      ▼
[normalized_logs sorgu: son window_seconds içindeki eşleşen event_action'lar]
      │
      ▼
[group_by alanına göre say → threshold aşıldı mı?]
      │
    Evet ──► [CorrelatedEvent oluştur + DB'ye yaz]
      │              │
      │              ▼
      │      [Kill chain dispatch]
      │              │
      │              ▼
      │      [Bildirim (e-posta/webhook)]
      │
      ▼
[Sonraki döngü]
```

**Şekil 2.2:** Korelasyon motoru 60 saniyelik çalışma döngüsü

### 2.4.3 Davranışsal Anomali Tespiti (IsolationForest)

Scikit-learn kütüphanesinin IsolationForest algoritması [21], her IP adresi için bağlantı sayısı, aktarılan bayt miktarı ve protokol çeşitliliği özelliklerini kullanarak normal davranış modelinden sapmaları tespit eder. Welford online algoritması, sürekli gelen veri akışı için kayartalık ortalama ve varyans hesaplamasını sağlar.

Anomali motoru (`anomaly/engine.py`), kill chain sistemine entegre edilmiştir: Anomali skoru eşiği aşan bir IP'den gelen anomali olayı, kill chain'e aşama olarak dispatch edilir; böylece izole bir anomali bile genel saldırı örüntüsünün parçası olarak değerlendirilebilir.

### 2.4.4 Öldürme Zinciri (Kill Chain) Modeli

NetGuard, Lockheed Martin Kill Chain modeli ve MITRE ATT&CK çerçevesi [6] ilkelerinden esinlenerek 5 aşamalı bir saldırı ilerleme modeli uygulamaktadır:

```
┌──────────────┬────────────────────────────────────────────────────────┐
│    AŞAMA     │  Tetikleyen event_action'lar                           │
├──────────────┼────────────────────────────────────────────────────────┤
│ RECON        │ port_scan, dns_anomaly                                 │
│ WEAPONIZE    │ ssh_failure, windows_brute_force                       │
│ ACCESS       │ ssh_success, windows_logon_success                     │
│ LATERAL      │ lateral_movement, windows_lateral                      │
│ EXECUTE      │ windows_process_create, sudo_abuse                     │
├──────────────┼────────────────────────────────────────────────────────┤
│ PARTIAL      │ 2 farklı aşama / 30 dakika → WARNING                  │
│ FULL_CHAIN   │ 3+ farklı aşama / 30 dakika → CRITICAL + otomatik blok│
└──────────────┴────────────────────────────────────────────────────────┘
```

**Şekil 2.3:** Kill chain 5 aşama modeli ve tetikleme eşikleri

Her IP adresi için aşama kayıtları bellek içi thread-safe bir sözlükte tutulur. 30 dakika geçmişe düşen kayıtlar otomatik temizlenir; bu tasarım TOCTOU yarış koşullarını engellemektedir.

### 2.4.5 Beaconing (C2 Sinyal) Tespiti

C2 (Command and Control) beaconing, zararlı yazılımların komuta-kontrol sunucusuna düzenli aralıklarla sinyal gönderdiği davranış örüntüsüdür. NetGuard'ın beaconing dedektörü (`detectors/beaconing.py`), RITA (Real Intelligence Threat Analytics) [9] metodolojisini temel alarak:

1. Kaynak-hedef IP çifti başına bağlantı zaman damgalarını toplar
2. Ardışık bağlantılar arasındaki IAT (Inter-Arrival Time) değerlerini hesaplar
3. IAT serisi için Bessel düzeltmeli standart sapma hesaplar
4. Düşük varyans (yüksek düzenlilik) → beaconing uyarısı üretir

Dedektör, 300 saniyede bir çalışacak şekilde yapılandırılmıştır. RITA BlackHat 2018 araştırması, C2 tespiti için en az 300 saniyelik gözlem penceresinin gerekli olduğunu ortaya koyduğundan bu cadence korelasyon motorundan bağımsız tutulmuştur [9].

## 2.5 Aktif Yanıt Katmanı Tasarımı

Aktif yanıt, belirli bir güvenlik geçitleri zincirini sırayla uygular. Bu sıra değiştirilemez çünkü her gate önceki gate'in doğrulamasına bağımlıdır:

```
POST /api/v1/response/block
        │
        ▼
[1] RFC1918 / PROTECTED_CIDRS kontrolü
        │ başarısız → HTTP 400 (özel IP bloke edilemez)
        ▼
[2] FP Gate: is_suppressed(ip)? (False Positive yönetimi)
        │ bastırılmış → HTTP 409 (force=true ile atlanabilir)
        ▼
[3] Severity Gate: minimum_severity kontrolü (BLOCK_MIN_SEVERITY=high)
        │ yetersiz → HTTP 422
        ▼
[4] Duplicate Gate: zaten bloklu mu?
        │ evet → HTTP 409 (offense_count artırılır)
        ▼
[5] OPNsense REST API → başarısız → VyOS SSH fallback
        │
        ▼
[6] DB: blocked_ips (expires_at + progressive TTL hesabı)
        │
        ▼
[7] Audit log (zorunlu, şifreli, SHA-256 zincirli)
```

**Şekil 2.5:** Aktif yanıt blok akışı

Progressive TTL mekanizması (`_progressive_ttl(offense_count)`): 1. ihlal → 1 saat, 2. ihlal → 4 saat, 3. ihlal → 24 saat, 4.+ ihlal → 168 saat (7 gün). Bu yaklaşım tekrarlayan saldırılar için giderek artan ceza uygular.

## 2.6 Web Arayüzü Mimari Tasarımı

Web arayüzü Next.js 14 (App Router) ve TypeScript ile geliştirilmiştir. Durum yönetimi için Zustand, sunucu-taraflı veri getirme için TanStack Query (React Query) ve gerçek zamanlı güncellemeler için WebSocket kullanılmaktadır. UI bileşen sistemi Tailwind CSS üzerine inşa edilmiştir.

Mimari katmanlar:

- **`/app/(protected)/`** — Kimlik doğrulama gerektiren sayfa bileşenleri (30+ sayfa)
- **`/lib/api/`** — FastAPI backend ile iletişim kuran tip-güvenli istemci fonksiyonları
- **`/lib/echarts-theme.ts`** — Merkezi ECharts tema konfigürasyonu (10 grafik tipi)
- **`/store/`** — Zustand global durum deposu (alerts, command palette, UI)
- **`/components/`** — Yeniden kullanılabilir UI bileşenleri

WebSocket bağlantısı (`ws_manager.py`), gerçek zamanlı log akışı için `/ws/logs` endpoint'i üzerinden TanStack Virtual ile sanallaştırılmış liste render'ı kullanır; böylece binlerce log satırı DOM performansını etkilemeden listelenebilmektedir.

## 2.7 Veritabanı ve Zaman Serisi Tasarımı

NetGuard yalnızca PostgreSQL 16 + TimescaleDB uzantısını destekler. SQLite dahil başka bir veritabanı dialect'i bulunmamaktadır; tüm SQL sorguları `%s` placeholder kullanır.

Alembic migration sistemi 21 aşamayı kapsamaktadır (Tablo 3.5'e bakınız). Ana tablolar:

- **`normalized_logs`** — TimescaleDB hypertable, tüm kaynak logların merkezi deposu
- **`correlated_events`** — Korelasyon motoru çıktıları
- **`incidents`** — Olay yönetimi kayıtları
- **`blocked_ips`** — Aktif blok listesi (expires_at, offense_count, progressive TTL)
- **`audit_log`** — Şifreli + SHA-256 zincirli değişmez kayıt
- **`alerts`** — Sigma/korelasyon tetiklemelerinin özetleri
- **`saved_hunts`** — Threat hunt sorgu şablonları
- **`alert_explanations`** — AI açıklayıcı önbelleği (24 saat TTL)
- **`kev_entries`** — CISA KEV veritabanı yerel kopyası

---

# BÖLÜM 3. GERÇEKLEŞTİRME VE YAZILIM BİLEŞENLERİ

## 3.1 Veri Toplama Modülleri

### 3.1.1 Syslog Toplayıcı

`syslog_receiver.py`, UDP port 514 üzerinden RFC 3164 formatındaki [13] syslog mesajlarını dinler. Güvenlik duvarı (OPNsense, pfSense), yönetilen switch ve Linux sunucu syslog akışlarını işleyebilir. `parsers/firewall.py`, OPNsense filterlog formatını kaynak/hedef IP, port ve eylem bilgilerine ayrıştırır.

### 3.1.2 SNMP Toplayıcı

SNMP toplayıcısı v2c ve v3 (SHA/AES şifrelemeli) cihaz sorgulama (poll) ile trap alımını destekler. `snmp_collector.py`, yapılandırılmış cihaz listesini periyodik olarak sorgulayarak arayüz istatistikleri, CPU/bellek kullanımı ve bant genişliği verilerini toplar. `snmp_trap_receiver.py`, UDP 162 üzerinden trap mesajlarını alır ve normalize eder.

### 3.1.3 Zeek Ağ Analiz Entegrasyonu

Zeek, pasif trafik analizi için endüstri standardıdır [9]. `zeek_collector.py`, Zeek'in `/opt/zeek/logs/` çıktı dizinini inode-safe offset mekanizmasıyla izler. Her log tipi için özel parser fonksiyonu mevcuttur:

**Tablo 3.2: Zeek Log Tipleri ve NetGuard Parser Kapsamı**

| Log Tipi | İçerik | STAGE_MAP Eşlemesi |
|----------|--------|-------------------|
| conn.log | TCP/UDP bağlantı özeti | recon, lateral |
| dns.log | DNS sorguları ve yanıtları | recon, c2 |
| http.log | HTTP istek/yanıt detayları | access, exfil |
| ssl.log | TLS el sıkışma bilgileri | c2, exfil |
| ssh.log | SSH oturum detayları | weaponize, access |
| smtp.log | E-posta iletimi | exfil |
| ftp.log | FTP komutları ve aktarımları | exfil |
| rdp.log | RDP oturum bilgileri | lateral |
| kerberos.log | Kerberos kimlik doğrulama | weaponize, lateral |
| smb_mapping.log | SMB paylaşım erişimleri | lateral |
| dce_rpc.log | Windows RPC çağrıları | lateral |
| weird.log | Protokol anomalileri | anomaly |
| dpd.log | Dinamik protokol tespiti | anomaly |
| files.log | Dosya aktarımları | exfil |

`zeek.py` parser'ı, Community ID alanını (`community_id`) doğrudan Zeek'in hesapladığı değerden okur ve `normalized_logs.community_id` alanına yazar.

### 3.1.4 Suricata EVE JSON Entegrasyonu

Suricata, kural tabanlı ağ saldırı tespiti için kullanılmaktadır. `suricata_collector.py`, `/var/log/suricata/eve.json` dosyasını inode-safe biçimde izler; log rotation sonrasında veri kaybı yaşanmaz. `parsers/suricata.py`, 9 farklı event_type'ı ayrıştırır: alert, dns, http, tls, ssh, flow, stats, anomaly ve fileinfo.

45.343 Emerging Threats kuralı systemd timer ile otomatik güncellenmektedir:

```bash
# /etc/systemd/system/suricata-update.timer
[Timer]
OnCalendar=daily
RandomizedDelaySec=3600
```

Suricata parser'ı da Community ID alanını EVE JSON çıktısından okuyarak cross-source pivot desteği sağlar.

### 3.1.5 NetFlow/IPFIX/sFlow Toplayıcı

`netflow_receiver.py`, UDP 2055 üzerinden NetFlow v5, NetFlow v9, IPFIX (RFC 7011) [11] ve sFlow protokollerini destekler. `parsers/netflow.py`, protokol türünü başlık incelemesiyle otomatik belirler ve normalleştirir. Community ID, her akış için kaynak/hedef IP, port ve protokol bilgilerinden hesaplanır.

NetFlow v9 ve IPFIX şablon tabanlı yapıları bellekte template cache'de saklanır; yeni şablon mesajları geldiğinde cache güncellenir. Üretim ortamında VyOS yönlendiricisi üzerinden NetFlow v9 ile 146.490'dan fazla akış kaydı toplanmıştır.

### 3.1.6 Windows Agent ve EVTX Parser

Windows güvenlik olayları için çift bileşenli bir mimari benimsenmiştir:

**Windows Agent** (`agent/windows_log_shipper.py`): psutil ile sistem metriklerini, 5 olay kanalından EVTX formatındaki kayıtları toplar ve HTTPS üzerinden NetGuard sunucusuna gönderir.

**EVTX Parser** (`evtx_parser.py`): 60+ Windows Event ID'sini ayrıştırır. Kapsanan kanallar:

**Tablo 3.3: Windows Event ID Kapsamı**

| Kanal | EID'ler | Güvenlik Değeri |
|-------|---------|----------------|
| Security | 4624, 4625, 4634, 4648, 4720, 4732, 4768, 4769, 4776 ve 50+ | Oturum açma, hesap yönetimi, Kerberos |
| Sysmon | 1 (süreç), 3 (ağ), 7 (DLL), 10 (işlem erişimi), 22 (DNS) | Süreç ve ağ izleme |
| PowerShell | 4103, 4104 (script block) | Komut çalıştırma izleme |
| System | 7045 (servis kurulum), 7040 | Servis değişiklikleri |
| AppLocker | 8003, 8004, 8006 | Uygulama denetimi |

[EKRAN GÖRÜNTÜSÜ: Windows Agent'ın aktif olduğu Agents sayfasının ekran görüntüsü — WIN-9DUCSU7LDJ0 (192.168.203.150) agent kartı görünür olmalı]

### 3.1.7 OpenCanary Honeypot Entegrasyonu

OpenCanary (Thinkst Applied Research) [20], ağ içine yerleştirilen sahte servisler aracılığıyla yetkisiz erişim girişimlerini tespit eder. `parsers/opencanary.py`, 12 log tipini normalleştirir: ftp-login, http-login, http-request, rdp-login, smb-file-open, ssh-login, ssh-new-client, telnet-login, mssql-login, mysql-login, vnc-login ve ntp-monlist.

OpenCanary'ye yönelik herhangi bir erişim girişimi kural-gereği şüphelidir; bu nedenle tüm OpenCanary olayları yüksek öncelikli STAGE_MAP eşlemelerine sahiptir.

### 3.1.8 Bulut Toplayıcılar (M365 ve Google Workspace)

**Microsoft 365:** `collectors/m365_collector.py`, Microsoft Graph API üzerinden oturum açma günlüklerini, posta kutusu denetim olaylarını ve güvenlik uyarılarını toplar.

**Google Workspace:** `collectors/gworkspace_collector.py`, Google Admin SDK üzerinden yönetici etkinliklerini, oturum açma olaylarını ve Drive erişim günlüklerini toplar.

**CISA KEV:** `collectors/kev_monitor.py`, CISA'nın Bilinen Sömürülen Güvenlik Açıkları (Known Exploited Vulnerabilities) feed'ini günlük olarak yerel `kev_entries` tablosuna indirir ve tehdit istihbaratı bağlamı sağlar.

## 3.2 Log Normalleştirme ve Parser Mimarisi

`log_normalizer.py` modülü, kaynak tipini belirleyen bir dispatcher görevi görür ve uygun parser fonksiyonuna yönlendirir. Her parser, `shared/models.py`'daki `NormalizedLog` dataclass'ını döner:

```python
@dataclass
class NormalizedLog:
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    network_protocol: str | None
    event_action: str
    event_category: str
    severity: str
    observer_hostname: str | None
    raw_log: str
    network_bytes: int | None
    community_id: str | None
    tenant_id: str | None
```

ECS uyumlu alan adları tüm parser'larda tutarlı biçimde kullanılır; bu sayede korelasyon motoru kaynak tipinden bağımsız olarak aynı sorgularla çalışabilmektedir.

## 3.3 Tespit Motorunun Gerçekleştirilmesi

### 3.3.1 Sigma Kuralları ve pySigma v2

Sigma kuralları YAML formatında `config/sigma_rules_v2/` dizininde tutulur. `sigma_executor.py`, bu kuralları pySigma v2 kütüphanesi [17] ile yükler ve PostgreSQL backend'i kullanarak SQL sorgularına dönüştürür. Her kural; başlık, açıklama, tespit mantığı, MITRE ATT&CK etiketleri ve önem derecesi içerir.

NetGuard ayrıca Sigma Rule Wizard (4 adımlı form UI, TypeScript YAML üretici) ve Monaco tabanlı YAML editör sunarak operatörlerin yeni kural yazmasını kolaylaştırmaktadır.

[EKRAN GÖRÜNTÜSÜ: Sigma Rule Wizard ekran görüntüsü — 4 adımlı form, kural adı, tespit koşulları, MITRE etiket seçimi görünür olmalı]

[EKRAN GÖRÜNTÜSÜ: Monaco YAML editör ekran görüntüsü — bir sigma kuralı düzenleniyor]

### 3.3.2 Korelasyon Motoru

Korelasyon kuralları `config/correlation_rules.json` dosyasındaki JSON yapısıyla tanımlanır. Motor, `reload_rules()` çağrısıyla çalışma zamanında kural değişikliğini destekler; servis yeniden başlatılması gerekmez.

[EKRAN GÖRÜNTÜSÜ: Correlation Rules CRUD sayfası — kural listesi, düzenleme formu ve aktif/pasif toggle görünür olmalı]

### 3.3.3 Anomali Tespiti

`anomaly/engine.py`, periyodik olarak `normalized_logs` tablosunu sorgular, her kaynak IP için özellik vektörü oluşturur ve IsolationForest modelini günceller. Anomali skoru -1 ile 1 arasında üretilir; -1 yüksek anomali anlamına gelir.

Isınma süresi (warmup): Her IP için en az 7 günlük veri toplanmadan anomali skoru üretilmez; bu sayede yetersiz veriyle yanlış pozitif üretimi önlenir.

### 3.3.4 Kill Chain Dedektörü

`attack_chain.py`, STAGE_MAP sözlüğünde tanımlanan 40'tan fazla event_action'ı 5 kill chain aşamasına eşler. Tablo 2.2, kritik STAGE_MAP eşlemelerini özetlemektedir:

**Tablo 2.2: STAGE_MAP — Kritik event_action → Kill Chain Aşama Eşlemeleri**

| event_action | Kill Chain Aşaması | Kaynak |
|-------------|-------------------|--------|
| port_scan | RECON | Port scan dedektörü |
| dns_anomaly | RECON | DNS anomali dedektörü |
| ssh_failure | WEAPONIZE | Zeek/Syslog |
| windows_brute_force | WEAPONIZE | EVTX EID 4625 |
| ssh_success | ACCESS | Zeek ssh.log |
| windows_logon_success | ACCESS | EVTX EID 4624 |
| lateral_movement | LATERAL | Lateral dedektör |
| smb_lateral | LATERAL | Zeek smb.log |
| kerberoasting | LATERAL | EVTX EID 4769 |
| windows_process_create | EXECUTE | EVTX/Sysmon EID 1 |
| honeypot_trigger | RECON | OpenCanary |
| c2_beaconing | ACCESS | Beaconing dedektörü |

### 3.3.5 Özel Dedektörler

`server/detectors/` dizinindeki özel dedektörler `DetectorManager` tarafından yönetilir:

- **`port_scan.py`:** Kısa zaman penceresinde tek IP'den 20'den fazla farklı porta bağlantı girişimi tespiti
- **`arp_spoof.py`:** ARP reply tablosundaki MAC-IP tutarsızlık tespiti (ARP cache poisoning)
- **`dns_anomaly.py`:** DNS sorgu entropisi (>4.0 bit), uzun alan adı (>50 karakter), NXDOMAIN spike tespiti (DNS tünelleme)
- **`icmp_flood.py`:** ICMP paket frekansı eşik tespiti
- **`lateral.py`:** İç ağ içinde olağandışı bağlantı örüntüsü tespiti (TOCTOU güvenli, thread-safe)

## 3.4 Tehdit İstihbaratı Entegrasyonu

`threat_intel.py`, dört farklı tehdit istihbaratı kaynağını sorgular ve composite skor üretir:

| Kaynak | Veri Türü | Katkı Ağırlığı |
|--------|-----------|----------------|
| AbuseIPDB | IP itibar skoru (0-100) | %35 |
| Feodo Tracker | Botnet C2 IP listesi | %25 |
| ThreatFox | Kötü amaçlı yazılım IOC'leri | %25 |
| GreyNoise | Gürültü/tarama IP listesi | %15 |

Composite skor 0-100 arasında üretilir; 70+ kritik tehdit göstergesidir. Sonuçlar Redis benzeri bellek önbelleğinde saklanarak API hız sınırlamaları yönetilir.

[EKRAN GÖRÜNTÜSÜ: Threat Hunt Workbench sayfası — composite skor sütunlu IP listesi ve tehdit istihbaratı detay paneli görünür olmalı]

## 3.5 Aktif Yanıt Sistemi

`routes/active_response.py` ve `active_response.py` modülleri, bölüm 2.5'te açıklanan 7 adımlı blok zincirini gerçekleştirir. Rate limiting güvenlik katmanı uygulanmıştır: blok endpoint'i 10 istek/dakika, break-glass endpoint'i 5 istek/dakika ile sınırlandırılmıştır.

**Break-glass mekanizması:** Meşru blok listesindeki bir IP'nin acil durum çıkarılması için `BREAK_GLASS_TOKEN` ortam değişkeniyle JWT bypass yetkilendirmesi sağlanmaktadır; bu işlem audit log'a zorunlu olarak kaydedilir.

Aktif yanıt blok UI'ı, blok geçerliliğini anlık olarak doğrulayan bir "Verify Panel" içermektedir. Break-glass butonu ve port/protokol bazlı blok seçeneği de arayüzde mevcuttur.

## 3.6 Dashboard ve Görselleştirme

### 3.6.1 Genel Bakış Paneli (Bento Grid)

Overview sayfası, 12 sütunlu asimetrik CSS Grid ile 6 zona ayrılmıştır:

- **Zona A:** StatCard'lar (toplam alert, aktif incident, blok sayısı) + KPI metrikleri
- **Zona B:** Alert trend grafiği (ECharts stacked area) + Tehdit İstihbaratı + Kill Chain özeti
- **Zona C:** Ağ topolojisi + Risk varlık listesi + MTTD/MTTR paneli
- **Zona D:** Sensor sağlık metrikleri + mini paneller (3×4)
- **Zona E:** Agent durumu + Canlı alert akışı + Protokol dağılımı (donut)
- **Zona F:** Trafik hacmi (east-west/north-south, full-width)

[EKRAN GÖRÜNTÜSÜ: Dashboard Overview sayfası tam ekran görüntüsü — bento grid layout, tüm zona'lar görünür, gerçek veri ile]

### 3.6.2 Kill Chain Swimlane Timeline

Kill Chain sayfası, tespit edilen saldırı aşamalarını SVG swimlane formatında zaman ekseninde görselleştirir. Her aşama (RECON, WEAPONIZE, ACCESS, LATERAL, EXECUTE) ayrı bir yüzme şeridinde gösterilir; aşamalar arası geçiş okları saldırı ilerlemesini net biçimde ortaya koyar.

[EKRAN GÖRÜNTÜSÜ: Kill Chain Timeline sayfası — swimlane görünümü, aktif saldırı aşamaları renkli şeritler halinde gösterilmeli]

### 3.6.3 MITRE ATT&CK Navigator

`mitre.py` modülü, tespit edilen taktik ve teknikleri MITRE ATT&CK matrisine eşler ve Navigator layer (JSON) dosyası oluşturur. Dashboard, coverage gap analizini renk kodlamalı matris görünümüyle sunar: kırmızı hücreler kapsanmayan teknikleri, yeşil hücreler aktif tespit kapsamını gösterir.

[EKRAN GÖRÜNTÜSÜ: MITRE ATT&CK Navigator sayfası — renk kodlamalı matris, kapsanan teknikler vurgulanmış]

### 3.6.4 AI Alert Explainer

`alert_explainer.py`, Groq API üzerinden Llama 3.3 70B modelini kullanarak seçilen alert için doğal dil açıklaması üretir. Prompt injection güvenlik izolasyonu uygulanmıştır; log verisi doğrudan prompt içine yerleştirilmez, ayrıştırılmış yapısal veri kullanılır. Açıklamalar 24 saatlik önbellekte saklanarak API çağrısı sayısı minimize edilir.

[EKRAN GÖRÜNTÜSÜ: Alerts sayfası — bir alert seçili, sağ panelde AI Explainer açıklaması görünür]

### 3.6.5 Tehdit Avı (Threat Hunt) Workbench

Threat Hunt Workbench, güvenlik analistlerine SQL bilgisi gerektirmeyen no-code bir sorgu builder sunar. Operatörler kaynak IP, hedef port, zaman aralığı, protokol ve olay kategorisi gibi filtreler seçerek özel sorgular oluşturabilir; bu sorgular `saved_hunts` tablosunda saklanabilir.

[EKRAN GÖRÜNTÜSÜ: Threat Hunt Workbench sayfası — filtre paneli, sonuç tablosu ve kayıtlı hunt listesi görünür]

## 3.7 Güvenlik ve Uyumluluk Özellikleri

### 3.7.1 JWT ve MFA/TOTP Kimlik Doğrulama

`auth.py`, JWT erişim token (kısa ömürlü) ve yenileme token (uzun ömürlü) çiftini yönetir. `verify_token(token, token_type=)` fonksiyonu, token tip karıştırma (token confusion) saldırılarına karşı zorunlu tip doğrulaması uygular.

TOTP (Time-based One-Time Password), RFC 6238 uyumlu pyotp kütüphanesiyle gerçekleştirilmiştir (Alembic 010, 012). TOTP secret'ları veritabanında şifreli saklanır; plaintext hiçbir zaman persistence katmanına yazılmaz. Kullanıcı, TOTP cihazını QR kodu ile bağlar; 30 saniyelik TOTP kodu her oturum açmada zorunludur.

### 3.7.2 Tamper-Proof Denetim Günlüğü

NIST SP 800-92 §3.2 [2] uyumlu audit log, her kayıt için SHA-256 hash zinciri oluşturur. Her yeni kayıt, önceki kaydın hash değerini içerir; bu sayede herhangi bir geçmiş kaydın değiştirilmesi tüm zinciri geçersiz kılar (Alembic 006).

### 3.7.3 Multi-Tenant Row-Level Security

Alembic 021 ile uygulanan PostgreSQL RLS politikası, 11 kritik tabloyu kapsar. `_connect_as_tenant(tenant_id)` yardımcı fonksiyonu, her veritabanı oturumunu ilgili kiracı bağlamıyla yapılandırır. Bu sayede paylaşımlı veritabanında bile her kiracı yalnızca kendi tenant_id'siyle eşleşen satırlara erişebilir; uygulama katmanı izolasyonu veritabanı düzeyinde güvence altına alınır.

### 3.7.4 At-Rest Şifreleme

Alembic 020 ile audit log'un hassas alanları (eylem detayı, IP adresi, kullanıcı bilgisi) AES-256-GCM ile şifrelenmektedir. Şifreleme anahtarı ortam değişkeni olarak yönetilir; anahtar hiçbir zaman veritabanına yazılmaz.

### 3.7.5 Sistematik Rate Limiting

SlowAPI middleware, `default_limits=["60/minute"]` ile tüm API endpoint'lerine uygulanmaktadır. Kritik endpoint'ler özel limitlerle ayrıca korunur: blok endpoint'i 10/dakika, break-glass endpoint'i 5/dakika. Bu yapı OWASP API Security Top 10 2023 API4:2023 (Sınırsız Kaynak Tüketimi) riskini hafifletir [19].

## 3.8 Community ID Çapraz Kaynak Korelasyonu

Corelight'ın Community ID Flow Hashing spesifikasyonu [15], aynı ağ bağlantısının farklı NSM araçlarında (Zeek, Suricata, NetFlow) aynı hash değeriyle tanımlanmasını sağlar. Alembic 018 ile `normalized_logs.community_id` sütunu eklendi.

`communityid` Python paketi, kaynak/hedef IP, port ve protokol bilgilerinden deterministik bir base64 hash üretir. Bu hash sayesinde:

1. Bir Suricata alert'inin ilgili Zeek conn.log kaydına otomatik pivot yapılabilir
2. NetFlow akış verisi ile IDS alert'i ilişkilendirilebilir
3. Aynı saldırı bağlantısının tüm kaynak gözlemleri tek bir olay zaman çizelgesinde birleştirilebilir

`GET /api/v1/logs/by-community-id/{cid}` endpoint'i, belirli bir Community ID için tüm kayıtları döner. Dashboard'da alert detay paneli, Community ID'yi gösterir ve tek tıkla pivot sağlar.

[EKRAN GÖRÜNTÜSÜ: Correlation sayfasındaki ContextPanel — bir alert seçili, Community ID değeri görünüyor ve "Zeek / Suricata / NetFlow" sekmeleri ile pivot sonuçları listeleniyor]

## 3.9 Operasyonel Altyapı

**Docker Compose:** 6 servis içeren `docker-compose.yml`; PostgreSQL+TimescaleDB, Redis, Zeek, Suricata, NetGuard backend ve Next.js frontend'i tek komutla ayağa kaldırır. CIS resource limits (CPU/bellek) her servise uygulanmıştır.

**Yedekleme/Geri Yükleme:** NIST SP 800-34 [3] uyumlu yedekleme prosedürü ile RPO ~24 saniye, RTO ~30 dakika hedeflenmektedir. PostgreSQL WAL arşivleme ve pg_dump tabanlı günlük yedek mekanizması uygulanmıştır.

**Alembic Migration:**

**Tablo 3.5: Alembic Migration Listesi**

| Aşama | İçerik |
|-------|--------|
| 001 | Temel şema (normalized_logs, alerts, incidents, users, blocked_ips) |
| 002 | blocked_ips tablosu |
| 003 | expires_at TIMESTAMPTZ |
| 004 | offense_count DEFAULT 1 |
| 005 | Tehdit istihbaratı sütunları |
| 006 | audit_log SHA-256 zinciri |
| 007 | alerts tenant+zaman indeksi |
| 008 | normalized_logs tenant+received indeksi |
| 009 | network_bytes sütunu |
| 010 | totp_secret + totp_enabled sütunları |
| 011 | Analitik sorgular için bileşik indeksler |
| 012 | TOTP secret at-rest şifreleme |
| 013 | TimescaleDB hypertable (received_at/1d, sıkıştırma 7d) |
| 014 | alert_explanations tablosu (AI önbellek) |
| 015 | saved_hunts tablosu |
| 016 | anomaly_baselines, anomaly_results tabloları |
| 017 | kev_entries tablosu (CISA KEV yerel kopya) |
| 018 | community_id VARCHAR(50) sütunu |
| 019 | asset_baseline_protocols (typical_protocols JSON) |
| 020 | audit_log alanları at-rest şifreleme |
| 021 | Row-Level Security — 11 tablo, tenant izolasyon politikası |

**Tablo 3.6: REST API Endpoint Grupları**

| Grup | Route Dosyaları | Amaç |
|------|-----------------|------|
| Güvenlik çekirdeği | auth, incidents, active_response, sigma, correlation, mitre, attack_chains | Kimlik doğrulama, olay yönetimi, aktif yanıt |
| Veri toplama | logs, alerts, agents, devices, snmp, netflow, evtx, hunts | Log sorgulama, agent yönetimi |
| Analiz | network_intel, anomaly, assets, fp_rules, threat_intel, topology, analytics | Analitik ve görselleştirme API |
| Platform | health, metrics, maintenance, compliance, security, reports | Sistem sağlık ve uyumluluk |
| Altyapı | discovery, tenants, ws | Ağ keşfi, kiracı yönetimi, WebSocket |

---

# BÖLÜM 4. TEST ORTAMI VE PERFORMANS ANALİZİ

## 4.1 GNS3 Sanal Laboratuvar Ortamı

Sistem testleri, GNS3 (Graphical Network Simulator 3) üzerinde kurulu izole bir sanal ağ ortamında gerçekleştirilmiştir. Bu yaklaşım, gerçek ağ trafiği üretme, saldırı simülasyonu ve savunma mekanizması doğrulaması için kontrollü bir ortam sağlamaktadır.

```
Host Makinesi (192.168.203.1 / vmnet8)
        │
        │ [VMware NAT + GNS3 route]
        ▼
┌─────────────────────────────────────────────────────────┐
│                    GNS3 Sanal Ağı                       │
│                                                         │
│  OPNsense 26.1.2 ──── VyOS rolling ──── NetGuard VM    │
│  (10.0.30.1)          (192.168.203.200) (192.168.203.134)│
│       │                    │                            │
│       │               ┌────┤                            │
│       │             LAN   DMZ                           │
│       │           Windows  Alpine                       │
│       │           (203.150) WebServer                   │
│       │                    (10.0.10.2)                  │
│  Kali Linux                                             │
│  (192.168.203.132)                                      │
└─────────────────────────────────────────────────────────┘
```

**Şekil 4.1:** GNS3 sanal laboratuvar topolojisi

**Test Ortamı Donanım/Yazılım Özellikleri:**

| Bileşen | Özellik |
|---------|---------|
| Host İşletim Sistemi | Ubuntu 24.04 LTS |
| Hipervizör | VMware Workstation + GNS3 |
| NetGuard VM | Ubuntu 24.04, 4 GB RAM, 4 vCPU |
| Saldırgan VM | Kali Linux 2024.x, 4 GB RAM, 2 vCPU |
| Windows Agent VM | Windows Server 2022 (WIN-9DUCSU7LDJ0) |
| Güvenlik Duvarı | OPNsense 26.1.2 |
| Yönlendirici | VyOS rolling |
| Ağ Bağlantısı | 1 Gbps sanal bağlantı |
| NetGuard Versiyonu | Python 3.12, FastAPI, Next.js 14 |

## 4.2 Test Metodolojisi

NetGuard test stratejisi, NIST SP 800-94'ün önerdiği doğrulama yaklaşımını [1] temel alır. Üç katmanlı test piramidi uygulanmıştır:

**Tablo 4.1: Test Piramidi — Test Dağılımı**

| Test Türü | Kapsam | Örnek Sayısı |
|-----------|--------|-------------|
| Birim testi | Tek modül, izole fonksiyon | ~1.200 |
| Çapraz test | İki modül arası etkileşim | ~900 |
| Entegrasyon testi | Tam pipeline doğrulama | ~688 |
| **Toplam** | | **2.788** |

Test altyapısı `pytest` ve `testcontainers` (gerçek PostgreSQL + TimescaleDB Docker container) kullanır. SQLite mock veritabanı kullanılmamaktadır; bu tasarım kararı, üretim ortamında TimescaleDB spesifik özelliklerinin test edilmesini sağlar.

[EKRAN GÖRÜNTÜSÜ: Terminal'de `pytest tests/ -q` çıktısı — "2788 passed" satırı görünür olmalı]

## 4.3 Saldırı Senaryosu Doğrulama

Dört temel saldırı senaryosu GNS3 ortamında doğrulanmıştır:

**Tablo 4.2: Saldırı Senaryosu Doğrulama Sonuçları**

| Senaryo | Saldırı Aracı | Beklenen Tespit | Sonuç | Yanıt Süresi |
|---------|--------------|----------------|-------|-------------|
| Port tarama | nmap -sS -p 1-65535 | RECON aşaması → port_scan alert | ✓ Doğrulandı | < 90s |
| SSH brute force | hydra -l root -P wordlist | WEAPONIZE → ssh_failure korelasyonu | ✓ Doğrulandı | < 70s |
| SSH başarılı giriş + yanal hareket | SSH + SMB pivot | FULL_ATTACK_CHAIN → otomatik blok | ✓ Doğrulandı | < 120s |
| DNS tünelleme | dnscat2 | dns_anomaly (entropi + NXDOMAIN spike) | ✓ Doğrulandı | < 60s |
| Beaconing (C2 simülasyonu) | Periyodik curl | IAT düşük varyans → beaconing uyarısı | ✓ Doğrulandı | < 320s |

### 4.4 SSH Brute Force → FULL_ATTACK_CHAIN Doğrulaması

En kritik entegrasyon senaryosu, kill chain'in uçtan uca doğrulamasıdır:

1. **RECON:** Kali Linux'tan `nmap -sS 192.168.203.134` → Port tarama tespiti → RECON aşaması kaydedildi
2. **WEAPONIZE:** `hydra -l root -P /usr/share/wordlists/rockyou.txt 192.168.203.134 ssh` → 10'dan fazla başarısız SSH denemesi → ssh_failure korelasyon eşiği aşıldı → WEAPONIZE aşaması
3. **ACCESS:** Başarılı SSH girişi → ssh_success → ACCESS aşaması
4. **FULL_CHAIN TETİKLEME:** 3 farklı aşama / 30 dakika penceresi → `FULL_ATTACK_CHAIN` critical alert → `AUTO_BLOCK_ON_FULL_CHAIN=1` ortam değişkeni aktifse Kali IP'si OPNsense üzerinden otomatik bloke edildi
5. **E-POSTA BİLDİRİMİ:** SMTP üzerinden HTML formatında kill chain özeti gönderildi

[EKRAN GÖRÜNTÜSÜ: Kill Chain Timeline sayfası — yukarıdaki 3 aşamanın swimlane üzerinde gösterildiği aktif saldırı senaryosu]

## 4.5 Sistem Performans Metrikleri

Üretim ortamında (NetGuard VM, 4 GB RAM, 4 vCPU) ölçülen performans metrikleri:

| Metrik | Değer |
|--------|-------|
| Korelasyon döngüsü süresi (ortalama) | ~2.3 saniye |
| Log normalleştirme hızı | ~8.000 olay/dakika |
| NetFlow akış işleme kapasitesi | ~146.490 akış/oturum |
| TimescaleDB sorgu süresi (7 günlük veri) | < 200ms |
| Dashboard API yanıt süresi (P95) | < 180ms |
| WebSocket gecikme | < 50ms |
| Bellek kullanımı (tüm servisler) | ~2.1 GB |

Sensor sağlık metrikleri CIS Control 13.1 uyumlu eşiklerle izlenmektedir: Zeek paket düşme oranı (`pkt_drop_rate`) için %5 uyarı / %15 kritik eşikleri, Suricata çekirdek paket düşme (`capture_kernel_drops`) için aynı eşikler uygulanmaktadır.

[EKRAN GÖRÜNTÜSÜ: Sensor Health paneli — Zeek ve Suricata için paket düşme oranı göstergeleri, yeşil/sarı/kırmızı durum indikatörleri görünür]

---

# BÖLÜM 5. SONUÇ

## 5.1 Elde Edilen Kazanımlar

Bu tasarım projesi kapsamında, NIST SP 800-94 [1], CIS Controls v8.1 [5] ve MITRE ATT&CK v17 [6] çerçeveleriyle uyumlu, üretim düzeyinde bir Ağ Güvenlik İzleme platformu başarıyla gerçekleştirilmiştir. Temel kazanımlar aşağıda özetlenmiştir:

**Kapsamlı Veri Toplama:** 10 farklı kaynak tipinden (Syslog, SNMP, Zeek 14 tip, Suricata EVE, NetFlow/IPFIX/sFlow, Windows Agent 60+ EID, OpenCanary, M365, Google Workspace, CISA KEV) ECS uyumlu normalleştirme ile veri toplanması sağlanmıştır.

**Çok Katmanlı Tespit:** Tek bir tespit yöntemi yerine dört tamamlayıcı yaklaşım (Sigma imzası, JSON korelasyon, IsolationForest anomali, IAT beaconing) entegre edilmiş; tespit zenginliği artırılmıştır.

**Kill Chain Bütünleşmesi:** Farklı kaynaklardan gelen olayların MITRE ATT&CK aşamalarıyla eşlenerek uçtan uca saldırı ilerleme zincirinin izlenmesi, tek olay bazlı tespite kıyasla önemli ölçüde daha az yanlış pozitif üretmektedir.

**Güvenlik Derinliği:** JWT+TOTP MFA, SHA-256 tamper-proof audit log, PostgreSQL RLS multi-tenant izolasyon, at-rest şifreleme ve sistematik rate limiting, platformun kendisini de güvenlik tehditlerine karşı korumaktadır.

**2.788 Test Başarısı:** Yalnızca birim değil; çapraz ve entegrasyon testleriyle pipeline'ın tüm aşamaları doğrulanmıştır. Gerçek PostgreSQL + TimescaleDB üzerinde çalışan test altyapısı, üretim ortamıyla tam eşdeğer güvence sağlamaktadır.

**Community ID:** NSM referans mimarisinde (SANS NSM, Malcolm/CISA, Security Onion) kritik bileşen olarak tanımlanan cross-source pivot, Zeek/Suricata/NetFlow kayıtlarının aynı TCP bağlantısı üzerinden birleştirilmesini mümkün kılmıştır.

## 5.2 Rakip Sistemlerle Karşılaştırma

**Tablo 5.1: NetGuard ile Security Onion Kapabilite Karşılaştırması**

| Özellik | Security Onion | NetGuard | NetGuard Farkı |
|---------|---------------|---------|----------------|
| Zeek entegrasyonu | ✓ | ✓ | Eşdeğer |
| Suricata entegrasyonu | ✓ | ✓ | Eşdeğer |
| NetFlow/IPFIX | ✓ | ✓ | Eşdeğer |
| Windows EVTX (60+ EID) | Kısmi | ✓ | NetGuard üstün |
| OpenCanary honeypot | ✗ | ✓ | NetGuard üstün |
| M365/Google Workspace | ✗ | ✓ | NetGuard üstün |
| Kill chain (5 aşama) | Kısmi (Kibana) | ✓ | NetGuard üstün |
| AI alert açıklayıcı | ✗ | ✓ | NetGuard üstün |
| Multi-tenant RLS | ✗ | ✓ | NetGuard üstün |
| Docker kurulum süresi | Günlerce | ~30 dakika | NetGuard üstün |
| Lisans maliyeti | Ücretsiz | Ücretsiz | Eşdeğer |
| Ölçeklenebilirlik | Yüksek | Orta | Security Onion üstün |
| Topluluk büyüklüğü | Büyük | Küçük | Security Onion üstün |

NetGuard, Security Onion ile karşılaştırıldığında kurumsal ölçek ve topluluk açısından avantajlı olan Security Onion'a kıyasla kurulum kolaylığı, bulut entegrasyonu ve AI destekli analiz konularında belirgin farklılık ortaya koymaktadır.

## 5.3 Karşılaşılan Zorluklar ve Çözümler

**Zorluk 1 — Heterojen Log Normalleştirmesi:** 10 farklı kaynak tipinin tutarsız log formatları (CEF, EVE JSON, TSV, syslog, Windows XML), ECS uyumlu tek bir şemaya dönüştürülmesini zorlaştırmaktadır.

*Çözüm:* Her kaynak için bağımsız parser modülü (`parsers/` dizini) ve merkezi NormalizedLog dataclass tanımlanmıştır. Yeni kaynak eklenmesi için tek bir parser modülü yazmak yeterli olmaktadır.

**Zorluk 2 — TimescaleDB Test Altyapısı:** SQLite mock ile test etmek mümkün değil; gerçek TimescaleDB gerekiyor.

*Çözüm:* `testcontainers` kütüphanesi ile her test çalıştırmasında gerçek PostgreSQL + TimescaleDB Docker container başlatılmaktadır. Bu yaklaşım CI/CD uyumlu, temiz ve güvenilirdir.

**Zorluk 3 — Thread Safety — Kill Chain TOCTOU:** Eş zamanlı saldırı olaylarında kill chain aşama kaydının yarış koşuluna girmesi riski.

*Çözüm:* Per-IP kilitleme mekanizması (`_get_block_lock(ip)`) ile TOCTOU yarış koşulları önlenmiştir. Her IP için bağımsız threading.Lock nesnesi kullanılmaktadır.

**Zorluk 4 — Community ID NetFlow Hesaplama:** NetFlow v5/v9/IPFIX üç farklı paket yapısında Community ID hesaplama tutarlılığı.

*Çözüm:* `communityid` Python paketi, protocol/src_ip/dst_ip/src_port/dst_port parametrelerini normalleştirerek tüm protokol versiyonlarında deterministik hash üretir.

## 5.4 Gelecek Çalışmalar

Mevcut platform, NSM temel kapsamını eksiksiz biçimde karşılamaktadır. Gelecek geliştirme dönemleri için aşağıdaki çalışmalar planlanmaktadır:

**SOAR Entegrasyonu (U5):** TheHive ve Shuffle ile entegrasyon; incident yönetiminin otomatik playbook'larla zenginleştirilmesi. Webhook altyapısı (`notifier.py`) mevcut olduğundan TheHive endpoint bağlantısı görece az çalışma gerektirecektir.

**UEBA Temeli (N10):** 60+ günlük üretim verisi biriktiğinde IsolationForest modelinin kullanıcı davranış analitik katmanına genişletilmesi. KVKK/GDPR uyumu için DPO onayı zorunludur.

**Arkime Tam PCAP (N11):** Kritik bağlantılar için full packet capture ve PCAP depolama. KOBİ (100–500 Mbps trafik) için 7–35 TB SSD altyapısı gerektiğinden ayrı donanım planlaması zorunludur.

**Pentest ve SOC 2 Type I Sertifikasyonu (T3):** Bağımsız güvenlik denetimi ve SOC 2 uyumluluk belgesi; kurumsal müşteri güvenine yönelik kritik adım.

**Pilot Müşteri (T4):** 3 KOBİ pilot müşterisi ile gerçek üretim ortamında doğrulama; MSSP ortaklığı modelinin araştırılması.

---

## KAYNAKLAR

[1] National Institute of Standards and Technology, "Guide to Intrusion Detection and Prevention Systems (IDPS)," NIST Special Publication 800-94 Rev. 1, Feb. 2007.

[2] National Institute of Standards and Technology, "Guide to Computer Security Log Management," NIST Special Publication 800-92, Sept. 2006.

[3] National Institute of Standards and Technology, "Contingency Planning Guide for Federal Information Systems," NIST Special Publication 800-34 Rev. 1, May 2010.

[4] National Institute of Standards and Technology, "Information Security Continuous Monitoring (ISCM) for Federal Information Systems and Organizations," NIST Special Publication 800-137, Jan. 2011.

[5] Center for Internet Security, "CIS Controls v8.1," 2021. [Çevrimiçi]. Erişim: https://www.cisecurity.org/cis-controls/

[6] MITRE Corporation, "ATT&CK Framework v17," 2025. [Çevrimiçi]. Erişim: https://attack.mitre.org/

[7] Verizon Business, "2025 Data Breach Investigations Report (DBIR)," Verizon Communications Inc., Mayıs 2025.

[8] CrowdStrike Holdings, Inc., "Global Threat Report 2025," CrowdStrike, 2025.

[9] R. Bejtlich, "The Practice of Network Security Monitoring," No Starch Press, 2013.

[10] Gartner, Inc., "Market Guide for Network Detection and Response," Gartner Research, 2025.

[11] B. Claise, Ed., "Specification of the IP Flow Information Export (IPFIX) Protocol," RFC 7011, IETF, Sept. 2013.

[12] B. Claise, Ed., "Cisco Systems NetFlow Services Export Version 9," RFC 3954, IETF, Ekim 2004.

[13] C. Lonvick, "The BSD syslog Protocol," RFC 3164, IETF, Ağustos 2001.

[14] J. Case, M. Fedor, M. Schoffstall, J. Davin, "Simple Network Management Protocol (SNMP)," RFC 1157, IETF, Mayıs 1990.

[15] Corelight, Inc., "Community ID Flow Hashing Specification," GitHub. [Çevrimiçi]. Erişim: https://github.com/corelight/community-id-spec

[16] F. Roth, T. Patzke ve Sigma Community, "Sigma: Generic Signature Format for SIEM Systems," GitHub. [Çevrimiçi]. Erişim: https://github.com/SigmaHQ/sigma

[17] Sigma Community, "pySigma: Sigma Processing and Conversion," GitHub. [Çevrimiçi]. Erişim: https://github.com/SigmaHQ/pySigma

[18] TimescaleDB, Inc., "TimescaleDB: An open-source time-series SQL database," 2024. [Çevrimiçi]. Erişim: https://www.timescaledb.com/

[19] Open Web Application Security Project (OWASP), "API Security Top 10 2023," 2023. [Çevrimiçi]. Erişim: https://owasp.org/www-project-api-security/

[20] Thinkst Applied Research, "OpenCanary: Canary honeypot framework," GitHub. [Çevrimiçi]. Erişim: https://github.com/thinkst/opencanary

[21] F. T. Liu, K. M. Ting ve Z.-H. Zhou, "Isolation Forest," in Proc. IEEE 8th Int. Conf. Data Mining (ICDM), Aralık 2008, ss. 413–422.

[22] International Organization for Standardization, "ISO/IEC 27001:2022 Information Security, Cybersecurity and Privacy Protection," ISO, 2022.

---

## EKLER

### EK A: Sigma Kuralı Örneği — SSH Brute Force Tespiti

```yaml
title: SSH Brute Force Detection
id: ng-ssh-001
status: production
description: Kısa süre içinde aynı kaynaktan çok sayıda başarısız SSH girişimi
author: NetGuard
date: 2026-01-15
logsource:
    category: network
    product: netguard
detection:
    selection:
        event_action: 'ssh_failure'
    timeframe: 5m
    condition: selection | count() by source_ip > 10
falsepositives:
    - Meşru yönetici hata girişimleri (düşük olasılık)
level: high
tags:
    - attack.credential_access
    - attack.t1110.001
```

### EK B: Korelasyon Kuralı Örneği (JSON)

```json
{
  "rule_id": "CORR-SSH-BF-001",
  "name": "SSH Brute Force Korelasyonu",
  "description": "5 dakika içinde aynı kaynak IP'den 10+ SSH başarısız girişimi",
  "match_event_action": "ssh_failure",
  "match_severity": null,
  "group_by": "source_ip",
  "window_seconds": 300,
  "threshold": 10,
  "severity": "high",
  "output_event_action": "ssh_brute_force",
  "enabled": true
}
```

### EK C: API Endpoint Referans Listesi

| HTTP Yöntemi | Endpoint | Açıklama |
|-------------|---------|---------|
| POST | /api/v1/auth/login | JWT token alma |
| POST | /api/v1/auth/totp/verify | TOTP doğrulama |
| GET | /api/v1/logs | Log listesi (filtreli) |
| GET | /api/v1/logs/by-community-id/{cid} | Community ID pivot |
| GET | /api/v1/alerts | Alert listesi |
| POST | /api/v1/response/block | IP blokajı |
| DELETE | /api/v1/response/unblock/{ip} | IP blok kaldırma |
| GET | /api/v1/correlation/events | Korelasyon olayları |
| GET | /api/v1/correlation/events/{id}/context | Olay bağlam pivot |
| GET | /api/v1/attack-chains | Kill chain durumu |
| GET | /api/v1/health/sensors | Sensör sağlık metrikleri |
| GET | /api/v1/analytics/top-talkers | En aktif IP'ler |
| GET | /api/v1/analytics/alert-volume | Alert hacmi zaman serisi |
| GET | /api/v1/analytics/protocol-distribution | Protokol dağılımı |
| GET | /api/v1/analytics/traffic-volume | Trafik hacmi |
| GET | /api/v1/mitre/navigator-layer | ATT&CK Navigator layer |
| POST | /api/v1/sigma/backtest | Sigma kural backtest |
| GET | /api/v1/compliance | Uyumluluk kontrolü |
| WS | /ws/logs | Gerçek zamanlı log akışı |

### EK D: GNS3 Lab Kurulum Adımları

```bash
# 1. NetGuard sunucusuna SSH
ssh -i ~/.ssh/id_ed25519 netguard@192.168.203.134

# 2. Alembic migration çalıştır
cd ~/netguard && alembic upgrade head

# 3. Servisleri başlat
sudo systemctl start netguard netguard-dashboard

# 4. Dashboard erişimi
# https://192.168.203.134

# 5. OPNsense bağlantısı (jump host üzerinden)
ssh -J netguard@192.168.203.134,vyos@192.168.203.200 root@10.0.30.1
```

### EK E: Docker Compose Servis Yapısı

```
docker-compose.yml
├── postgres      — PostgreSQL 16 + TimescaleDB (port 5432)
├── netguard      — FastAPI backend (port 8000)
├── dashboard     — Next.js frontend (port 3000)
├── zeek          — Zeek NSM sensörü
├── suricata      — Suricata IDS
└── nginx         — Ters proxy (HTTPS, port 443)
```

CIS resource limits her servise uygulanmıştır:
- `cpu_quota: 50000` (her servis için CPU sınırı)
- `mem_limit: 512m` – `2g` (servis tipine göre)

---

## ÖZGEÇMİŞ

Mehmet Çapar, 2002 yılında Kayseri'de doğdu. İlk, orta ve lise eğitimini Kayseri'de tamamladı. Yükseköğrenimine Sakarya Üniversitesi Bilgisayar ve Bilişim Bilimleri Fakültesi, Bilgisayar Mühendisliği Bölümü'nde başladı.

Eğitim hayatı boyunca ağ teknolojileri ve siber güvenlik alanlarına yoğunlaştı. Bu kapsamda Akbank Gençlik Akademisi "Siber Güvenlik Analisti Programı"nı ve Cisco Networking Academy bünyesindeki "CCNA 1" ile "Linux Essentials" eğitimlerini tamamlayarak sertifikalarını aldı.

2025 yılının bahar döneminde Sakarya Üniversitesi SARGEM bünyesinde Öğrenci Asistanı olarak görev aldı. 2025 yaz döneminde ise Erciyes Anadolu Holding Boytrans Lojistik firmasında Bilgi İşlem Stajyeri olarak stajını tamamladı. Halen Sakarya Üniversitesi Bilgisayar Mühendisliği Bölümü'nde 4. sınıf öğrencisi olarak öğrenimine devam etmekte olup, 2026 yılında mezun olması planlanmaktadır.

---

## BSM 498 BİLGİSAYAR MÜHENDİSLİĞİ TASARIMI DEĞERLENDİRME VE SÖZLÜ SINAV TUTANAĞI

**KONU:** Açık Kaynak Ağ Güvenlik İzleme Platformu Geliştirilmesi: NetGuard  
**ÖĞRENCİ:** B201210102 — Mehmet Çapar

| Değerlendirme Konusu | İstenenler | Not Aralığı | Not |
|---------------------|-----------|-------------|-----|
| **Yazılı Çalışma** | | | |
| Çalışma klavuza uygun hazırlanmış mı? | x | 0-5 | |
| **Teknik Yönden** | | | |
| Problemin tanımı yapılmış mı? | x | 0-5 | |
| Mimarisi blok şeması ile açıklanmış mı? | | | |
| Blok şemadaki birimler arası bilgi akışı gösterilmiş mi? | | | |
| Yazılımın gereksinim listesi oluşturulmuş mu? | | | |
| Kullanılan araçlar/teknolojiler anlatılmış mı? | | | |
| UML ile modelleme yapılmış mı? | | | |
| Veritabanı kavramsal model çıkarılmış mı? | | | |
| Sürüm denetim sistemi (Git) kullanılmış mı? | | | |
| Sistemin genel testi için uygulanan metotlar verilmiş mi? | | | |
| Performans testi yapılmış mı? | | | |
| Yazılımın sızma testi yapılmış mı? | | | |
| Tasarımın uygulamasında zorluklar ve çözümler belirtilmiş mi? | | | |
| **Yapılan işlerin zorluk derecesi** | x | 0-25 | |
| **Sözlü Sınav** | | | |
| Yapılan sunum başarılı mı? | x | 0-5 | |
| Soruları yanıtlama yetkinliği | x | 0-20 | |
| **Devam Durumu** | | | |
| Dönem raporlarını düzenli hazırladı mı? | x | 0-5 | |
| **Toplam** | | | |

**DANIŞMAN:**  
**DANIŞMAN İMZASI:**
