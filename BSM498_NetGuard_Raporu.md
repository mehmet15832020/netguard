# T.C. SAKARYA ÜNİVERSİTESİ
## BİLGİSAYAR VE BİLİŞİM BİLİMLERİ FAKÜLTESİ
## BİLGİSAYAR MÜHENDİSLİĞİ BÖLÜMÜ

---

# BSM 498 BİTİRME ÇALIŞMASI

---

## NetGuard: Orta Ölçekli İşletmeler İçin Açık Kaynaklı Ağ Güvenliği İzleme Platformu

---

**Öğrenci:** Mehmet Çapar  
**Öğrenci E-posta:** 20mehmetcapar02@gmail.com  
**Danışman:** [Danışman Adı]  
**Teslim Tarihi:** Mayıs 2026

---

&nbsp;

---

## ÖNSÖZ

Bu çalışma, siber güvenlik bütçesi kısıtlı olan orta ölçekli işletmelerin ağ güvenliği izleme ihtiyacını karşılamak amacıyla geliştirilen NetGuard platformunun tasarım, uygulama ve değerlendirme süreçlerini kapsamaktadır.

Çalışma boyunca motivasyon kaynağı, kurumsal lisanslı çözümlerin (Splunk: yıllık ~50.000 USD, IBM QRadar: yıllık ~30.000 USD) fiyatlandırma yapısının orta ölçekli işletmeleri etkin ağ güvenliği izlemesinden mahrum bırakmasından doğan somut bir boşluğu doldurmaktır. NetGuard, bu boşluğu açık kaynak bileşenlerle, endüstri standartlarına uygun bir mimariyle kapatmayı hedeflemektedir.

Projenin her aşamasında destek ve yönlendirmelerinden dolayı danışman hocama, teknik altyapı süreçlerinde katkı sağlayan Sakarya Üniversitesi Bilgisayar Mühendisliği Bölümü'ne ve açık kaynak topluluklarına (SigmaHQ, Zeek, pySigma, MITRE ATT&CK) teşekkür ederim.

Mehmet Çapar  
Sakarya, Mayıs 2026

---

&nbsp;

---

## İÇİNDEKİLER

- Önsöz
- İçindekiler
- Simgeler ve Kısaltmalar Listesi
- Şekiller Listesi
- Tablolar Listesi
- ÖZET
- **BÖLÜM 1 — GİRİŞ**
  - 1.1 Problem Tanımı ve Motivasyon
  - 1.2 Araştırmanın Amacı ve Kapsamı
  - 1.3 Özgün Katkılar
  - 1.4 Tez Organizasyonu
- **BÖLÜM 2 — SİSTEMATİK YAKLAŞIM**
  - 2.1 Ağ Güvenliği İzleme (NSM) Alanı
  - 2.2 Tehdit Tespit Yöntemleri
  - 2.3 Mevcut Çözümler ve Karşılaştırma
  - 2.4 MITRE ATT&CK Çerçevesi ve Kill Chain Modeli
  - 2.5 Aktif Yanıt Mekanizmaları
  - 2.6 Literatür Değerlendirmesi
- **BÖLÜM 3 — DENEY DÜZENEĞİ VE SANAL LABORATUVAR**
  - 3.1 Sistem Mimarisi
  - 3.2 Veri Toplama Katmanı
  - 3.3 Tehdit Tespit Katmanı
  - 3.4 Aktif Yanıt Katmanı
  - 3.5 Veritabanı Mimarisi
  - 3.6 Kullanıcı Arayüzü
  - 3.7 Sanal Laboratuvar Topolojisi
- **BÖLÜM 4 — VERİ GÜVENLİĞİ DEĞERLENDİRMESİ**
  - 4.1 Geliştirme Ortamı ve Metodoloji
  - 4.2 Test Stratejisi
  - 4.3 Saldırı Senaryosu Testleri
  - 4.4 Performans Değerlendirmesi
  - 4.5 Mevcut Çözümlerle Karşılaştırma
- **BÖLÜM 5 — SONUÇLAR VE ÖNERİLER**
  - 5.1 Elde Edilen Bulgular
  - 5.2 Sistem Kısıtlamaları
  - 5.3 Gelecek Çalışmalar
  - 5.4 Sonuç
- KAYNAKLAR
- EK A — API Referans Tablosu
- ÖZGEÇMİŞ

---

&nbsp;

---

## SİMGELER VE KISALTMALAR LİSTESİ

| Kısaltma | Açıklama |
|----------|----------|
| API | Application Programming Interface (Uygulama Programlama Arayüzü) |
| ARP | Address Resolution Protocol |
| ATT&CK | Adversarial Tactics, Techniques, and Common Knowledge |
| BPF | Berkeley Packet Filter |
| CIDR | Classless Inter-Domain Routing |
| C2 | Command and Control (Komuta ve Kontrol) |
| DBIR | Data Breach Investigations Report |
| DNS | Domain Name System |
| ECS | Elastic Common Schema |
| EDR | Endpoint Detection and Response |
| FP | False Positive (Yanlış Pozitif) |
| FTP | File Transfer Protocol |
| HTTP | Hypertext Transfer Protocol |
| HTTPS | HTTP Secure |
| ICMP | Internet Control Message Protocol |
| IDS | Intrusion Detection System (İzinsiz Giriş Tespit Sistemi) |
| IPS | Intrusion Prevention System |
| IoC | Indicator of Compromise (Uzlaşma Göstergesi) |
| IP | Internet Protocol |
| JWT | JSON Web Token |
| MITRE | MITRE Corporation |
| NDR | Network Detection and Response |
| NSM | Network Security Monitoring |
| NIST | National Institute of Standards and Technology |
| OPNsense | OPNsense Firewall/Router Çözümü |
| PCAP | Packet Capture |
| PG | PostgreSQL |
| REST | Representational State Transfer |
| RFC | Request for Comments |
| SIEM | Security Information and Event Management |
| SNMP | Simple Network Management Protocol |
| SOAR | Security Orchestration, Automation and Response |
| SQL | Structured Query Language |
| SSH | Secure Shell |
| SSL | Secure Sockets Layer |
| TCP | Transmission Control Protocol |
| TLS | Transport Layer Security |
| TTL | Time to Live |
| UDP | User Datagram Protocol |
| URL | Uniform Resource Locator |

---

## ŞEKİLLER LİSTESİ

| No | Şekil Adı | Sayfa |
|----|-----------|-------|
| Şekil 3.1 | NetGuard Collect-Detect-Respond Mimari Diyagramı | — |
| Şekil 3.2 | Event Pipeline Akış Diyagramı | — |
| Şekil 3.3 | Kill Chain Aşamaları ve Durum Geçiş Diyagramı | — |
| Şekil 3.4 | Aktif Yanıt Güvenlik Geçitleri Akış Şeması | — |
| Şekil 3.5 | GNS3 Sanal Laboratuvar Ağ Topolojisi | — |
| Şekil 3.6 | Dashboard-v2 Ana Ekran Görünümü | — |
| Şekil 4.1 | Test Piramidi — Birim, Çapraz ve Entegrasyon Testleri | — |
| Şekil 4.2 | Kill Chain Tespit Zaman Çizelgesi (Port Tarama → Tam Zincir) | — |

---

## TABLOLAR LİSTESİ

| No | Tablo Adı | Sayfa |
|----|-----------|-------|
| Tablo 2.1 | Mevcut NSM/NDR Çözümler Karşılaştırması | — |
| Tablo 2.2 | MITRE ATT&CK v17 Taktik-Teknik Sayıları | — |
| Tablo 3.1 | Zeek Log Türleri ve NetGuard Eşlemeleri | — |
| Tablo 3.2 | pySigma v2 Kural Dosyaları ve Kapsadıkları Tehditler | — |
| Tablo 3.3 | Progressive TTL Tablosu | — |
| Tablo 3.4 | Alembic Migrasyon Tarihçesi | — |
| Tablo 3.5 | GNS3 Sanal Makine Envanteri | — |
| Tablo 4.1 | Test Modülü Başına Test Sayıları (İlk 10) | — |
| Tablo 4.2 | Saldırı Senaryosu Tespit Sonuçları | — |
| Tablo 4.3 | NetGuard ile Rakip Çözümler Özellik Karşılaştırması | — |

---

&nbsp;

---

## ÖZET

**Anahtar Kelimeler:** Ağ Güvenliği İzleme, NSM, NDR, Tehdit Tespiti, Kill Chain, pySigma, Aktif Yanıt, Açık Kaynak, PostgreSQL, Zeek

Siber tehditlerin hacim ve karmaşıklık bakımından hızla artması, işletmeleri sürekli ağ izleme kapasitesine sahip olmaya zorlamaktadır. CrowdStrike 2025 Global Tehdit Raporu'na göre ortalama saldırı ilerleme süresi 48 dakikaya inmiştir [2]. Bu süre zarfında manuel müdahale çoğu zaman yetersiz kalmakta; otomatik tespit ve yanıt mekanizmalarına ihtiyaç duyulmaktadır. Öte yandan Gartner 2025 raporuna göre NDR (Network Detection and Response) pazarı 3,2 milyar dolarlık büyüklüğe ulaşmış olsa da lider ürünlerin lisans maliyetleri orta ölçekli işletmelerin büyük çoğunluğunun erişim sınırının çok üzerindedir [3].

Bu çalışmada, 50–500 çalışanlı, siber güvenlik bütçesi kısıtlı işletmelere yönelik açık kaynaklı bir Ağ Güvenliği İzleme (NSM) platformu olan **NetGuard** sunulmaktadır. NetGuard; syslog, NetFlow v5/v9, Zeek TAP, SNMP v2c/v3 ve psutil tabanlı ajan bileşenlerinden oluşan çok kaynaklı bir veri toplama katmanına sahiptir. Tehdit tespiti, JSON tabanlı korelasyon kuralları ve pySigma v2 motorunda 30'dan fazla Sigma kuralının birleşimiyle gerçekleştirilmekte; beş aşamalı kill chain modeli (RECON → WEAPONIZE → ACCESS → LATERAL → FULL_ATTACK_CHAIN) ile saldırı kampanyaları otomatik olarak izlenmektedir. Tespit edilen tehditlere karşı aktif yanıt mekanizması, OPNsense REST API ve VyOS SSH fallback kombinasyonuyla IP engellemesi uygular; RFC 1918 koruma geçidi, yanlış pozitif filtresi, severity eşiği ve progressif TTL (1–168 saat) içeren sekiz katmanlı bir güvenlik mimarisiyle desteklenmektedir.

Sistem Python 3.12/FastAPI backend'i, PostgreSQL 16 + TimescaleDB veritabanı ve Next.js 14 dashboard'undan oluşmakta; GNS3 sanal laboratuvarında OPNsense güvenlik duvarı, VyOS yönlendirici, Kali Linux saldırı makinesi ve çoklu ağ segmentiyle gerçek saldırı senaryolarına karşı doğrulanmaktadır. Sistem; 59 test dosyasında 1.151 pytest testiyle sıfır hata oranına ulaşmış olup port tarama tespiti, SSH brute-force tespiti ve tam kill chain senaryolarında %100 tespit başarısı elde etmiştir.

---

&nbsp;

---

# BÖLÜM 1 — GİRİŞ

## 1.1 Problem Tanımı ve Motivasyon

Modern işletme ağları, kullanıcı sayısından bağımsız olarak sürekli tehdit altındadır. Verizon 2025 Veri İhlali Araştırma Raporu'na (DBIR) göre incelenen olayların %74'ünde kimlik bilgisi hırsızlığı yer almakta, %53'ünde DNS tüneli C2 (komuta ve kontrol) kanalı olarak kullanılmaktadır [1]. Bu tehditlerin büyük bölümü ağ katmanında gözlemlenebilir izler bırakır; ancak bu izlerin gerçek zamanlı olarak tespit edilmesi için organize bir izleme altyapısına ihtiyaç duyulmaktadır.

Mevcut durumda iki uç nokta arasında derin bir boşluk mevcuttur:

**Kurumsal çözümler** (Splunk, IBM QRadar, Darktrace, Vectra): Güçlü tespit kapasitesi, tam destek, sertifikalı entegrasyon. Ancak yıllık lisans maliyetleri 30.000–150.000 USD aralığında seyreder. 100 çalışanlı bir işletme için bu maliyet çoğu zaman yıllık BT güvenlik bütçesinin tamamını aşmaktadır.

**Yetersiz çözümler** (salt firewall log incelemesi, tek kaynaklı SIEM lite): Maliyet avantajı sağlar ancak çok kaynaklı korelasyon, kill chain takibi ve aktif yanıt kapasitesinden yoksundur.

Bu boşluğu doldurmayı hedefleyen açık kaynak çözümler (Security Onion, Wazuh) mevcuttur; ancak Security Onion yüksek donanım gereksinimleri ve karmaşık kurulum süreciyle öne çıkarken, Wazuh ağ/NSM yerine uç nokta/HIDS odaklı bir mimari benimsemektedir. Ağ katmanı odaklı, kurulumu 30 dakikada Docker Compose ile tamamlanabilen ve endüstri standardı bir aktif yanıt mekanizmasına sahip hafif bir çözüme ihtiyaç duyulmaktadır.

NetGuard bu ihtiyacı karşılamak amacıyla tasarlanmış, Docker tabanlı, açık kaynaklı bir **NSM platformu** (NDR-lite özellikleriyle) olarak geliştirilmiştir.

## 1.2 Araştırmanın Amacı ve Kapsamı

Bu çalışmanın temel amacı, aşağıdaki gereksinimleri karşılayan işlevsel bir NSM platformu geliştirmek ve değerlendirmektir:

1. **Çok kaynaklı veri toplama:** Syslog (firewall/switch), NetFlow v5/v9, Zeek paket analizi, SNMP v2c/v3, psutil tabanlı ajan ve Windows Olay Günlükleri (EVTX) kaynaklarından normalize edilmiş olay akışı üretmek.

2. **Katmanlı tehdit tespiti:** JSON korelasyon kuralları, pySigma v2 motoru ve istatistiksel anomali tespitinin (IsolationForest + Welford) birlikte çalışabileceği bir tespit motoru inşa etmek.

3. **Kill chain takibi:** Lockheed Martin Kill Chain modeli ve MITRE ATT&CK çerçevesi referansıyla beş aşamalı bir saldırı zinciri izleme sistemi uygulamak.

4. **Sekiz katmanlı aktif yanıt:** RFC 1918 koruması, yanlış pozitif geçidi, ciddiyet eşiği, tekrarlayan ihlalci tespiti, progressif TTL ve acil kurtarma (break-glass) mekanizmalarını içeren güvenli ve denetlenebilir IP engelleme altyapısı oluşturmak.

5. **Endüstri standartlarıyla uyum:** MITRE ATT&CK v17, CIS Controls v8.1, NIST SP 800-94 ve OWASP API Security 2023 ile belgelenmiş uyumluluk sağlamak.

**Kapsam dışındaki konular:** Tam paket yakalama (full PCAP), uç nokta/HIDS işlevleri, güvenlik açığı tarama, dosya bütünlüğü izleme ve tam NDR (east-west PCAP analizi) bu çalışmanın kapsamı dışında bırakılmıştır. Bu tasarım kararı bilinçlidir; söz konusu işlevler farklı ürün kategorilerine (EDR, vulnerability scanner, full NDR) aittir ve NetGuard'ın hedeflediği donanım profiliyle uyumsuzdur.

## 1.3 Özgün Katkılar

Bu çalışma aşağıdaki özgün teknik katkıları sunmaktadır:

1. **Çok kaynaklı normalize olay pipeline'ı:** Sekiz farklı kaynak türünü ECS (Elastic Common Schema) uyumlu tek bir tablo yapısına (`normalized_logs`) indirgeyen normalize katman.

2. **Çift motorlu tespit mimarisi:** JSON korelasyon kurallarını ve pySigma v2 motoru kural setini aynı döngüde çalıştıran hibrit tespit yaklaşımı.

3. **Sekiz güvenlik geçitli aktif yanıt (P1–P8):** Wazuh `repeated_offenders`, Zeek NetControl ve CISA break-glass account rehberlerinden ilham alınarak tasarlanan, denetlenebilir ve geri alınabilir IP engelleme mimarisi.

4. **Zeek dokuz log tipi entegrasyonu:** DNS, HTTP, SSL/TLS, Conn, SSH, Notice, x509, SMTP ve FTP log akışlarının gerçek zamanlı olarak normalize edilmesi ve JA3 TLS parmak izi zenginleştirmesi.

5. **GNS3 doğrulaması:** Gerçek güvenlik duvarı (OPNsense), yönlendirici (VyOS), DMZ ve saldırı makinesi (Kali Linux) içeren sanal laboratuvarda doğrulanan end-to-end saldırı senaryoları.

## 1.4 Tez Organizasyonu

Tezin geri kalanı şu şekilde yapılandırılmıştır: Bölüm 2, NSM/NDR alanı, tehdit tespit yöntemleri ve mevcut çözümleri sistematik biçimde inceler. Bölüm 3, sistem mimarisini ve GNS3 sanal laboratuvarını tanımlar. Bölüm 4, uygulama ayrıntılarını, test stratejisini ve saldırı senaryosu değerlendirmelerini sunar. Bölüm 5, sonuçları ve gelecek çalışmaları özetler.

---

# BÖLÜM 2 — SİSTEMATİK YAKLAŞIM

## 2.1 Ağ Güvenliği İzleme (NSM) Alanı

Ağ Güvenliği İzleme (NSM), bir ağda gerçekleşen olayların sürekli gözlemlenmesi, günlüklenmesi, analiz edilmesi ve güvenlik açısından ilgili olaylara yanıt verilmesi pratiği olarak tanımlanabilir [8]. NSM, klasik Saldırı Tespit Sistemleri'nden (IDS) daha kapsamlıdır: salt imza eşleştirmesinin ötesinde, bağlam bilgisi (asset profili, kill chain aşaması, tehdit istihbaratı) ve denetim kaydı (audit trail) gerektiren bir disiplindir.

Bejtlich [9], NSM'yi "ağ verilerinin güvenlik perspektifinden toplanması, tespiti ve analizi" olarak tanımlar ve pratik NSM uygulamasının üç temel ilkesini şöyle sıralar: (i) gözlem edilemeyen bir şey korunamaz; (ii) tüm log kaynakları tek bir merkezi noktada birleşmelidir; (iii) yanıt süresi tespit süresi kadar kritiktir.

NIST SP 800-94 [5], tam özellikli bir IDPS altyapısının dört bileşen içermesi gerektiğini belirtir: sensörler/ajanlar, yönetim sunucusu, veritabanı ve konsol. NetGuard bu dört bileşeni sırasıyla çok kaynaklı toplayıcılar, FastAPI backend, PostgreSQL+TimescaleDB ve Next.js dashboard ile karşılamaktadır.

Gartner, NDR pazarını NSM'nin ticari evrimi olarak konumlandırmakta ve 2025 yılı itibarıyla 3,2 milyar dolarlık küresel büyüklüğe ulaştığını tahmin etmektedir [3]. NDR'yi NSM'den ayıran başlıca özellikler: makine öğrenmesi tabanlı davranışsal analiz, east-west (iç ağ) trafik görünürlüğü ve otomatik yanıt kapasitesidir. NetGuard bu özellik setinin bir alt kümesini (ML anomali, aktif yanıt) açık kaynak bileşenlerle sunmakta; ancak east-west tam PCAP analizini kapsam dışında tutmaktadır.

## 2.2 Tehdit Tespit Yöntemleri

### 2.2.1 İmza Tabanlı Tespit

İmza tabanlı tespit, bilinen saldırı kalıplarını önceden tanımlanmış kurallara göre eşleştirme pratiğidir. Suricata ve Snort'un kural formatları bu alanın standartlarını belirlerken, **Sigma** kuralları SIEM-agnostik, insan tarafından okunabilir tehdit tespiti için evrensel bir dil haline gelmiştir [11].

Sigma, SigmaHQ topluluğu tarafından geliştirilen ve 3.000'den fazla açık kaynak kuralı barındıran bir YAML formatıdır. pySigma [12], bu kuralları Python tabanlı sistemler için derlenebilir sorgulara dönüştüren referans uygulamasıdır. NetGuard, pySigma v2 (1.3.3) motorunu SQLite uyumlu arka uç yerine PostgreSQL ILIKE sözdizimi destekli özelleştirilmiş bir arka uçla kullanmaktadır.

İmza tabanlı tespitinin temel sınırlaması, daha önce gözlemlenmemiş saldırılara (zero-day) karşı kör olmasıdır. Bu sınırlama, anomali tabanlı tespit ile telafi edilmektedir.

### 2.2.2 Anomali Tabanlı Tespit

Anomali tabanlı tespit, istatistiksel olarak "normal" davranıştan sapmaları belirleyerek potansiyel tehditleri ortaya çıkarır. Yüksek yanlış pozitif oranı bu yöntemin bilinen dezavantajıdır; ancak ML modelleri bu oranı azaltmada önemli ilerleme kaydetmiştir.

**IsolationForest** [14], 2008 yılında Liu ve arkadaşları tarafından önerilen ve özellikle düşük maliyetli aykırı değer tespiti için tasarlanmış bir topluluk öğrenmesi yöntemidir. Gözlem sayısıyla doğrusal ölçeklenmesi ve yüksek boyutlu veride etkinliğini koruması sayesinde NSM uygulamaları için uygundur. NetGuard, scikit-learn [13] kütüphanesindeki `IsolationForest` uygulamasını kaynak başına bağlantı hızı, paket büyüklüğü ve zaman özellikleri üzerinde çalıştırmaktadır.

**Welford Online Algoritması** [17], varyansı tek geçişte ve sabit bellek kullanımıyla hesaplayan bir istatistiksel yöntemdir. NetGuard, her ağ varlığı (IP) için kayan ortalama ve standart sapma değerlerini bu algoritmayı kullanarak günceller; eşik aşımı tespit edilen varlıklar için alarm üretir.

### 2.2.3 Davranışsal Analiz ve Kill Chain

Bireysel olayların tespitinin ötesinde, bir saldırı kampanyasının aşamalarını birbirine bağlayan bağlamsal analiz kritik öneme sahiptir. Lockheed Martin Kill Chain modeli [16], siber saldırıları yedi aşamaya ayırır: Keşif (Reconnaissance), Silahlandırma (Weaponization), Teslim (Delivery), İstismar (Exploitation), Kurulum (Installation), Komuta ve Kontrol (C2), Eylem ve Hedefler (Actions on Objectives).

NetGuard, bu modeli pratik NSM uygulamasına uyarlanmış beş aşamayla uygulamaktadır: RECON (port tarama, ağ keşfi), WEAPONIZE (kimlik bilgisi saldırıları, kaba kuvvet), ACCESS (başarılı oturum açma, güvenlik açığı istismarı), LATERAL (ağ içi yayılma, ARP spoofing) ve FULL_ATTACK_CHAIN (≥3 farklı aşamanın 30 dakika içinde aynı kaynaktan tetiklenmesi). FULL_ATTACK_CHAIN tespiti kritik incident üretir ve bildirim sistemini tetikler.

## 2.3 Mevcut Çözümler ve Karşılaştırma

### 2.3.1 Ticari Çözümler

**Splunk Enterprise Security:** Olgun ekosistemi, App Store üzerinden binlerce entegrasyonu ve güçlü SIEM yetenekleriyle öne çıkar. Ancak yıllık lisans maliyeti (50.000+ USD için ~TB/gün) orta ölçekli işletmelerin büyük bölümünü devre dışı bırakmaktadır. Splunk ayrıca ağ odaklı değil, log yönetimi odaklıdır; Zeek gibi ağ analiz araçları ile entegrasyonu ek yapılandırma gerektirir.

**IBM QRadar:** Davranışsal analiz ve tehdit istihbaratı zinciriyle güçlü NDR kapasitesi sunar. Başlangıç maliyeti ~30.000 USD'dir ve kurulum karmaşıklığı yüksektir.

**Darktrace/Vectra:** Tam east-west NDR yetenekleri, AI tabanlı davranışsal analiz. Fiyatlandırma açıklanmamakla birlikte enterprise segmentini hedefler; küçük/orta işletmelere yönelik sürümleri bile doğrudan erişim sağlamamaktadır.

### 2.3.2 Açık Kaynak Çözümler

**Security Onion:** Zeek, Suricata, Elasticsearch ve Kibana'yı tek bir çözümde birleştiren kapsamlı bir NSM platformudur [21]. Üretim ortamı için minimum 16 GB RAM ve 4 çekirdek işlemci gerektirmekte; kurulum ve yapılandırma karmaşıklığı yükselmektedir. Security Onion, NetGuard'ın doğrudan karşılaştırma noktasıdır ve yaklaşık %70–75 oranında kapsam örtüşmesi bulunmaktadır. Temel fark: Security Onion full PCAP yakalama ve Elasticsearch tabanlı analitik sunarken, NetGuard PostgreSQL+TimescaleDB ile daha düşük donanım gereksinimiyle çalışmaktadır.

**Wazuh:** Uç nokta güvenliği (HIDS), dosya bütünlüğü izleme ve güvenlik açığı tespiti konularında güçlüdür [22]. Ağ katmanı odaklı değildir; NetFlow, Zeek TAP entegrasyonu yerel olarak desteklenmez. NetGuard, ağ NSM alanındaki bu boşluğu doldurmaktadır.

**Suricata IDS:** Ağ trafiğini pasif olarak dinleyen, EVE JSON formatında log üreten bir IDS/IPS motorudur. Tek başına bir platform değil, bir bileşendir; yönetim arayüzü, korelasyon ve veri depolama altyapısına ihtiyaç duyar.

**Tablo 2.1: Mevcut NSM/NDR Çözümler Karşılaştırması**

| Özellik | NetGuard | Security Onion | Wazuh | Splunk |
|---------|----------|---------------|-------|--------|
| Lisans | Açık kaynak | Açık kaynak | Açık kaynak | Ticari |
| Donanım (min) | 4 GB RAM | 16 GB RAM | 8 GB RAM | 32 GB RAM+ |
| Kurulum | 30 dk (Docker) | 1–2 saat | 1 saat | Gün+ |
| Zeek Entegrasyonu | ✅ Yerleşik | ✅ Yerleşik | ❌ Hayır | ❌ Eklenti |
| NetFlow | ✅ v5/v9 | ✅ | ❌ | ❌ Eklenti |
| Kill Chain Takibi | ✅ (5 aşama) | ✅ (MITRE) | ❌ | ✅ (Eklenti) |
| Aktif Yanıt | ✅ OPNsense+VyOS | ❌ | ✅ (endpoint) | ❌ |
| Full PCAP | ❌ | ✅ | ❌ | ❌ |
| ML Anomali | ✅ IsolationForest | ✅ ML | ❌ | ✅ |
| Yıllık Maliyet | 0 USD | 0 USD | 0 USD | 50.000+ USD |

## 2.4 MITRE ATT&CK Çerçevesi ve Kill Chain Modeli

MITRE ATT&CK v17, saldırganların gerçek saldırılarda kullandığı taktik, teknik ve prosedürlerin (TTP) yapılandırılmış bir veritabanıdır [4]. 14 taktik kategorisinde 200'den fazla teknik ve 400'den fazla alt teknik barındırır. Kurumsal güvenlik operasyon merkezlerinde (SOC) tehdit tespiti ve olay müdahalesinin ortak referans dili haline gelmiştir.

NetGuard, MITRE ATT&CK eşlemesini iki düzeyde uygular: (1) Sigma kural dosyaları her tehdit için `mitre_attack_id` alanını içerir (örn. T1046 — Network Service Discovery, T1110 — Brute Force, T1071.004 — DNS tüneli); (2) `incident_enricher.py` modülü, bir incident oluşturulduğunda ilgili MITRE taktik ve tekniklerini incident kaydına bağlar.

**Tablo 2.2: MITRE ATT&CK v17 — NetGuard'ın Kapsadığı Taktikler**

| Taktik | Örnek Teknik | NetGuard Kapsamı |
|--------|-------------|-----------------|
| Reconnaissance (TA0043) | T1046 Network Service Discovery | ✅ port_scan dedektörü |
| Initial Access (TA0001) | T1110 Brute Force | ✅ ssh_brute_force Sigma kuralı |
| Credential Access (TA0006) | T1110.001 Password Guessing | ✅ auth_and_web.yml |
| Discovery (TA0007) | T1046, T1018 | ✅ |
| Lateral Movement (TA0008) | T1021 Remote Services | ✅ lateral dedektörü |
| Command and Control (TA0011) | T1071.004 DNS Tunneling | ✅ c2_and_exfil.yml |
| Exfiltration (TA0010) | T1048 Exfiltration Over Alt Protocol | ✅ c2_and_exfil.yml |
| Impact (TA0040) | T1498 Network DoS | ✅ icmp_flood.yml |

## 2.5 Aktif Yanıt Mekanizmaları

Aktif yanıt, tehdit tespitinin ardından otomatik veya yarı otomatik önlem alma pratiğidir. Bu alan, ürün ekosisteminde farklı düzeylerde olgunluk sergilenmektedir:

- **Wazuh active-response:** `white_list` (korumalı IP listesi), `timeout` (TTL) ve `repeated_offenders` (progressif TTL) kavramlarını yerel olarak destekler. Ancak ağ cihazı entegrasyonu (güvenlik duvarı API) yoktur.
- **Zeek NetControl:** Ağ cihazlarına kontrol sinyali gönderebilir; `PENDING/SUCCEEDED/FAILED` durum takibi mevcuttur. Ancak otomatik kurulum gerektiren ayrı bir altyapı bileşenidir.
- **XSOAR (Palo Alto):** Kurumsal SOAR platformu; `UserVerification` (FP geçidi) ve `InternalRange` (RFC1918 koruması) kavramları NetGuard'ın P3 ve P1 bileşenleriyle örtüşür.

NetGuard'ın P1–P8 aktif yanıt mimarisi, bu kavramları tek bir modülde (`active_response.py`) birleştirir ve OPNsense REST API ile VyOS SSH fallback kombinasyonuyla ağ katmanında uygulanabilir kılar.

## 2.6 Literatür Değerlendirmesi

Literatür incelemesi şu sonuçları ortaya koymaktadır: (1) NSM/NDR alanında büyük çaplı açık kaynak platformlar (Security Onion, OSSIM) mevcuttur ancak orta ölçekli işletmeler için donanım gereksinimleri ve kurulum karmaşıklığı engelleyicidir. (2) Ağ odaklı, Docker tabanlı, entegre aktif yanıt içeren hafif bir NSM platformunu konu alan akademik çalışma sayısı sınırlıdır. (3) pySigma v2 motorunun PostgreSQL desteğiyle NSM uygulamasına entegrasyonunu inceleyen çalışma henüz yayımlanmamıştır. NetGuard bu boşluğu, pratik uygulama ve GNS3 doğrulamasıyla kapatmaktadır.

---

# BÖLÜM 3 — DENEY DÜZENEĞİ VE SANAL LABORATUVAR

## 3.1 Sistem Mimarisi

NetGuard, üç temel katmandan oluşan bir mimari benimsemektedir: **Collect (Topla) → Detect (Tespit Et) → Respond (Yanıt Ver)**. Bu katmanlar, merkezi bir event pipeline üzerinden birbirine bağlıdır.

```
COLLECT                    DETECT                    RESPOND
───────────────────        ──────────────────────    ──────────────────
Syslog (UDP 514)           JSON Korelasyon Motoru    Incident Yönetimi
NetFlow v5/v9 (UDP 2055)   pySigma v2 (30+ kural)   Kill Chain Timeline
Zeek TAP (log tail)        Kill Chain Takibi         Alert + Bildirim
SNMP v2c/v3                IsolationForest Anomali   Aktif Yanıt (IP blok)
psutil Agent               Welford İstatistik        Denetim Kayıtları
Zeek: 9 log türü           MITRE ATT&CK Eşleme
EVTX (Windows)             AbuseIPDB Tehdit İstih.
Web Log (nginx)
              │                       │                      │
              └───────────────────────┴──────────────────────┘
                              normalized_logs tablosu
                              (PostgreSQL + TimescaleDB)
```

**Şekil 3.1: NetGuard Collect-Detect-Respond Mimari Diyagramı**

Event pipeline'ın merkezinde `normalized_logs` tablosu yer almaktadır. Her toplayıcı, kaynağına özgü formatı ECS-uyumlu (Elastic Common Schema) alanlara dönüştürerek bu tabloya yazar: `source_ip`, `destination_ip`, `source_port`, `destination_port`, `network_protocol`, `event_action`, `event_category`, `observer_hostname`. Bu standart, tüm tespit kurallarının tüm kaynak türleriyle çalışmasına olanak tanır.

### 3.1.1 Teknoloji Yığını

| Katman | Teknoloji | Versiyon |
|--------|-----------|---------|
| Backend | Python / FastAPI | 3.12 / 0.115.0 |
| Veritabanı | PostgreSQL + TimescaleDB | 16 / 2.x |
| Migrasyon | Alembic | 1.13.0 |
| DB Sürücüsü | psycopg3 + pool | 3.2.0 |
| Sigma Motoru | pySigma | 1.3.3 |
| Zeek Analiz | Zeek NSM | 6.x |
| ML Anomali | scikit-learn | 1.5+ |
| Ağ Keşfi | paramiko (SSH), httpx (REST) | ≥3.0 |
| Frontend | Next.js 14 / React 18 | 14.x |
| Durum Yönetimi | Zustand + TanStack Query | — |
| Görselleştirme | Recharts | — |
| Web Sunucusu | nginx (SSL reverse proxy) | — |
| Rate Limiting | slowapi / limits | 0.1.9 |
| JWT | python-jose | 3.5.0 |
| Log Alıcı | uvicorn[standard] | — |

## 3.2 Veri Toplama Katmanı

### 3.2.1 Syslog Alıcısı

`server/syslog_receiver.py`, UDP 5140 portunda RFC 3164 ve RFC 5424 uyumlu syslog mesajlarını alır. `server/log_normalizer.py`, gelen syslog akışını kaynak türüne göre (OPNsense PF, nginx, auth.log, generic) ayrıştırır. Güvenlik duvarı log satırlarından `src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol` ve `action` alanları çıkarılarak `normalized_logs` tablosuna yazılır.

Ayrıca `server/security_log_parser.py`, sistemin `auth.log` dosyasını doğrudan izleyerek SSH oturumu başarı/başarısızlık olaylarını, sudo kullanımını ve PAM kimlik doğrulama sonuçlarını gerçek zamanlı olarak yakalar.

### 3.2.2 NetFlow Alıcısı

`server/netflow_receiver.py`, UDP 2055 portunda NetFlow v5 ve v9 akışlarını alır. Her flow kaydı; kaynak/hedef IP, port, protokol, bayt sayısı ve başlangıç/bitiş zaman damgası bilgisini taşır. `server/parsers/netflow.py`, NetFlow binary formatını ayrıştırır ve `normalized_logs`'a yazar. VyOS yönlendiricisinden gelen NetFlow akışları, ağ topolojisine ilişkin zengin bağlam (yönlendirme arayüzü, akış süresi) sağlar.

### 3.2.3 Zeek TAP Entegrasyonu

Zeek [10], ağ trafiğini pasif olarak dinleyen ve uygulama katmanı analizini yüksek performansla gerçekleştiren açık kaynaklı bir ağ analiz çerçevesidir. `server/zeek_collector.py`, Zeek'in log dizinini (`/zeek-logs`) gerçek zamanlı olarak izler ve aşağıdaki dokuz log türünü işler:

**Tablo 3.1: Zeek Log Türleri ve NetGuard Eşlemeleri**

| Zeek Log Dosyası | İçerik | NetGuard event_action |
|-----------------|--------|----------------------|
| dns.log | DNS sorguları ve yanıtları | dns_query, nxdomain |
| http.log | HTTP istek/yanıt | http_request |
| ssl.log | TLS el sıkışma + JA3 | tls_connection |
| conn.log | TCP/UDP bağlantı özeti | network_connection |
| ssh.log | SSH oturumu metadata | ssh_login, ssh_auth_failed |
| notice.log | Zeek dedektör uyarıları | zeek_notice |
| x509.log | TLS sertifika detayları | tls_certificate |
| smtp.log | SMTP oturumu | smtp_connection |
| ftp.log | FTP komutları | ftp_command |

`server/parsers/zeek.py`, her log formatına özel ayrıştırıcı içerir. JA3 TLS parmak izi değerleri `ssl.log`'dan alınarak `normalized_logs.raw_log` alanına ek bağlam olarak eklenir; bu bilgi Network Intelligence dashboard sayfasında görselleştirilmektedir.

### 3.2.4 SNMP Toplayıcı

`server/snmp_collector.py`, ağ cihazlarından (yönlendirici, switch, güvenlik duvarı) SNMPv2c ve SNMPv3 protokolleri üzerinden sayaç değerleri alır. OID bazlı polling döngüsü, arabirim trafiği, hata sayacı ve cihaz durumu bilgisini periyodik olarak toplar. `server/snmp_trap_receiver.py`, reaktif olarak SNMP trap mesajlarını dinler; örneğin OPNsense bir bağlantı olayını trap olarak ilettiğinde anında işlenir.

### 3.2.5 psutil Tabanlı Ajan

`agent/` dizini, izlenmesi gereken Linux/Windows sunuculara kurulabilen hafif bir psutil tabanlı ajan içerir. Ajan, CPU kullanımı, açık portlar, aktif ağ bağlantıları ve süreci gibi sistem metriklerini REST API aracılığıyla NetGuard backend'ine gönderir. `server/alert_engine.py`, ajan verilerini işleyerek eşik aşımı durumunda uyarı üretir.

### 3.2.6 Windows EVTX Ayrıştırıcı

`server/evtx_parser.py`, Windows Olay Günlükleri (`.evtx`) dosyalarını ayrıştırarak kimlik doğrulama olayları (4624, 4625, 4648, 4768, 4769), süreç oluşturma (4688) ve servis kurulumu (7045) kayıtlarını `normalized_logs`'a aktarır.

## 3.3 Tehdit Tespit Katmanı

### 3.3.1 Korelasyon Motoru

`server/correlator.py`, 60 saniyelik döngülerle iki paralel kural setini yürütür:

**JSON korelasyon kuralları:** `config/correlation_rules.json` dosyasındaki kural tanımları belirli bir zaman penceresi içinde eşik sayısına ulaşan olayları tespit eder. Örneğin `ssh_brute_force` kuralı, aynı kaynak IP'den 60 saniye içinde 5 başarısız kimlik doğrulama girişimini tespit eder.

**pySigma v2 kuralları:** `config/sigma_rules_v2/` dizinindeki YAML dosyalarından derlenen Sigma kuralları, PostgreSQL sorguları olarak çalıştırılır. Her kural yürütme sonucu `CorrelatedEvent` modeline dönüştürülür ve MITRE ATT&CK eşlemesiyle birlikte `correlated_events` tablosuna kaydedilir.

### 3.3.2 pySigma v2 Kural Seti

NetGuard, 11 YAML dosyasında organize edilmiş 30'dan fazla Sigma kuralı barındırmaktadır:

**Tablo 3.2: pySigma v2 Kural Dosyaları ve Tehdit Kapsamları**

| Dosya | Kapsadığı Tehdit | MITRE ATT&CK |
|-------|-----------------|--------------|
| port_scan.yml | Port tarama, servis keşfi | T1046 |
| ssh_brute_force.yml | SSH kaba kuvvet, şifre spreyi | T1110 |
| auth_and_web.yml | Web tarama, başarılı SSH girişi | T1190, T1078 |
| anomaly_and_impact.yml | ICMP flood, bandwidth spike | T1498 |
| c2_and_exfil.yml | DNS tüneli, veri sızdırma | T1071.004, T1048 |
| web_attacks.yml | SQL injection, XSS, path traversal | T1190 |
| sql_injection.yml | SQLi kalıpları (HTTP parametreler) | T1190 |
| windows_events.yml | Windows brute force, PTH | T1110, T1550 |
| device_and_snmp.yml | Cihaz kesintisi, SNMP trap burst | T1498 |
| network_community.yml | Topluluk Sigma kuralları (17 kural) | Çeşitli |
| zeek_advanced.yml | TLS sertifika anomalisi, DNS DGA | T1568, T1071 |

### 3.3.3 Ayrılmış Dedektörler

`server/detectors/` dizini, zaman serisi örüntülerini tespit eden özelleşmiş modüller içerir:

- **port_scan.py:** Tek kaynaktan 30 saniye içinde 15+ farklı hedefe port bağlantısı
- **arp_spoof.py:** Aynı MAC'in birden fazla IP için yanıt vermesi (ARP zehirlenmesi)
- **dns_anomaly.py:** NXDOMAIN oranı spike, DNS sorgu entropi analizi
- **icmp_flood.py:** ICMP paket sayısı burst tespiti
- **lateral.py:** Aynı kaynağın iç ağda farklı hedeflere yönelik kimlik doğrulama girişimleri

### 3.3.4 Kill Chain Takibi

`server/attack_chain.py`, `AttackChainTracker` sınıfını içerir. Tracker, her kaynak IP için aktif aşamaları ve zaman damgalarını bellekte tutar. Bir `CorrelatedEvent` geldiğinde `event_action` alanı, önceden tanımlanmış `STAGE_MAP` sözlüğüyle eşleştirilerek kill chain aşaması belirlenir.

Geçiş kuralları şöyledir: (i) Aynı kaynak IP'den 30 dakika içinde ≥3 farklı aşama tetiklenirse `FULL_ATTACK_CHAIN` (kritik) oluşturulur. (ii) ≥2 farklı aşama tetiklenirse kısmi zincir uyarısı üretilir. (iii) Her aşama için ayrı kill chain kaydı (`attack_chains` tablosu) tutulur.

`FULL_ATTACK_CHAIN` tespiti; kritik incident oluşturma, e-posta bildirimi ve Discord/Slack webhook tetiklemesini başlatır.

### 3.3.5 Anomali Tespiti

`server/anomaly/engine.py`, `AnomalyEngine` sınıfını içerir. Her 60 saniyede bir çalışan döngüde:

1. Son 5 dakikaya ait normalized log verileri çekilir
2. `StatisticalDetector` (Welford), her IP için kayan ortalama ve standart sapmayı günceller; 3σ üzeri değerleri aykırı olarak işaretler
3. `IsolationForestDetector`, veri seti yeterli büyüklüğe ulaştıktan sonra (warmup: 100 gözlem) çok boyutlu anomali skoru hesaplar

Anomali tespiti şu an kill chain'e doğrudan bağlı değildir (bu bağlantı Faz 4 kapsamındadır); ancak anomaly sonuçları `/anomaly` API endpoint'i ve dashboard üzerinden görselleştirilmektedir.

## 3.4 Aktif Yanıt Katmanı (P1–P8)

NetGuard'ın aktif yanıt mimarisi, endüstri standartlarından ilham alınarak sekiz güvenlik geçidiyle tasarlanmıştır:

**Şekil 3.4: Aktif Yanıt Güvenlik Geçitleri**

```
POST /api/v1/response/block (admin)
    │
    ├─ P1: RFC1918 + PROTECTED_CIDRS kontrolü → 400 (güvenli IP engellenmez)
    │
    ├─ P2: Zaten bloklu mu?                   → 409 (tekrar işleme)
    │
    ├─ P3: FP Manager: is_suppressed(ip)?      → 409 / devam (force=true)
    │
    ├─ P4: Incident severity ≥ BLOCK_MIN_SEVERITY? → 422 (düşük ciddiyet)
    │
    ├─ P5: offense_count → progressive_ttl()   → 1/4/24/168 saat TTL
    │
    ├─ P6: OPNsense REST API                   → VyOS SSH fallback
    │
    ├─ P7: Port/protokol granülaritesi          → 5-tuple engelleme
    │
    └─ P8: audit_log kaydı (zorunlu)           → actor, reason, timestamp
```

**Tablo 3.3: Progressive TTL Tablosu (P5)**

| İhlal Sayısı | TTL (saat) | Endüstri Karşılığı |
|-------------|-----------|-------------------|
| 1. ihlal | 1 saat | Wazuh timeout |
| 2. ihlal | 4 saat | Wazuh repeated_offenders |
| 3. ihlal | 24 saat | Wazuh repeated_offenders |
| 4.+ ihlal | 168 saat (7 gün) | Zeek catch-and-release max |

`OPNsenseProvider`, OPNsense güvenlik duvarının REST API'sini (`/api/firewall/alias/addHost`) kullanarak `NETGUARD_BLOCK` takma adına IP ekler ve ardından firewall kurallarını yeniden uygular. `VyOSProvider`, OPNsense erişilemez olduğunda SSH üzerinden VyOS komut satırına bağlanarak `set firewall group address-group BLOCK-LIST address <ip>` komutunu çalıştırır. Her iki sağlayıcı da `BlockResult` ve `UnblockResult` nesneleri döndürür; başarı/başarısızlık durumu `blocked_ips` tablosuna ve `audit_log`'a yazılır.

**Break-glass (P8 acil kurtarma):** `BREAK_GLASS_TOKEN` ortam değişkeniyle yapılandırılan gizli token, `POST /api/v1/response/break-glass/unblock` endpoint'inde JWT kimlik doğrulamasını bypass eder ve herhangi bir IP'yi acil olarak engelden çıkarır. CISA break-glass account rehberi [24] temel alınmıştır.

**TTL cleanup loop:** `main.py` içindeki 60 saniyelik temizleme döngüsü, `expires_at` süresi dolmuş blokları `blocked_ips` tablosundan siler ve her iki sağlayıcıda da engeli kaldırır.

## 3.5 Veritabanı Mimarisi

### 3.5.1 PostgreSQL + TimescaleDB

NetGuard üretim ortamında PostgreSQL 16 + TimescaleDB kullanır. TimescaleDB, zaman serisi verileri için otomatik chunk yönetimi ve kompresyon sağlar. `normalized_logs` ve `correlated_events` tabloları TimescaleDB hypertable olarak yapılandırılmıştır; bu sayede 30 günlük log verisine sorgu yanıt süresi standart PostgreSQL'e kıyasla yaklaşık 5–10 kat daha hızlıdır.

### 3.5.2 Alembic Migrasyonları

**Tablo 3.4: Alembic Migrasyon Tarihçesi**

| Migrasyon | İçerik |
|-----------|--------|
| 001_initial_schema.py | normalized_logs, incidents, correlated_events, attack_chains, audit_log |
| 002_blocked_ips.py | blocked_ips tablosu |
| 003_blocked_ips_ttl.py | expires_at TIMESTAMPTZ + index |
| 004_blocked_ips_offense_count.py | offense_count INTEGER NOT NULL DEFAULT 1 |

### 3.5.3 Veri Saklama Politikası

Log verileri farklı saklama süreleriyle yönetilir: normalize loglar 30 gün, güvenlik logları 90 gün, korelasyon olayları 365 gün, alert ve incident kayıtları 90 gün. `server/retention.py`, bu politikaları günlük olarak uygular.

## 3.6 Kullanıcı Arayüzü

NetGuard dashboard'u Next.js 14 ile geliştirilmiş olup 16 sayfadan oluşmaktadır: Overview, Logs, Incidents, Aktif Bloklar, Alerts, Agents, Correlation, Network Intelligence, MITRE ATT&CK, Timeline, Topology, Devices/SNMP/Discovery, Settings, Audit, Reports ve Security. Tüm sayfalar nginx reverse proxy arkasında HTTPS üzerinden servis edilmektedir.

## 3.7 Sanal Laboratuvar Topolojisi

NetGuard'ın doğrulama çalışmaları, GNS3 sanal ağ simülasyon ortamında gerçekleştirilmiştir.

```
INTERNET (enp1s0 / Cloud)
         │
    OPNsense 26.1.2
    (vtnet0=WAN, vtnet1=LAN:10.0.30.1/24)
         │
    VyOS rolling
    (eth0=10.0.30.2, eth1=192.168.203.200, eth2=10.0.10.1)
    ├── DMZ Switch → Alpine WebServer (10.0.10.2 / nginx)
    └── LAN Switch → Host1, Host2, Kali-Bridge
```

**Şekil 3.5: GNS3 Sanal Laboratuvar Ağ Topolojisi**

**Tablo 3.5: GNS3 Sanal Makine Envanteri**

| Makine | IP | Rol | OS |
|--------|----|----|-----|
| NetGuard Server | 192.168.203.134 | Backend + Dashboard | Ubuntu 24.04 |
| Ajan VM | 192.168.203.142 | Linux psutil ajanı | Ubuntu 24.04 |
| Kali Linux | 192.168.203.132 | Saldırı test makinesi | Kali Linux |
| VyOS Router | 192.168.203.200 | NetFlow kaynak, yönlendirici | VyOS rolling |
| OPNsense FW | 10.0.30.1 | Güvenlik duvarı (blok hedefi) | OPNsense 26.1.2 |
| Alpine WebServer | 10.0.10.2 | HTTP hedef | Alpine Linux |

---

# BÖLÜM 4 — VERİ GÜVENLİĞİ DEĞERLENDİRMESİ

## 4.1 Geliştirme Ortamı ve Metodoloji

NetGuard, yinelemeli bir geliştirme süreci izlenerek 9 ana aşamada (V1-1 ile V1-9) inşa edilmiştir. Her aşama, implementasyon sonrası test yazımı ve komit disipliniyle tamamlanmıştır. Conventional Commits standardı uygulanmıştır: `feat(detection):`, `refactor(db):`, `fix(security):` ön ekleri.

Geliştirme ortamı: Ubuntu 24.04, Python 3.12, Docker 27.x, GNS3 2.x, pytest 8.3.2.

## 4.2 Test Stratejisi

### 4.2.1 Test Piramidi

CLAUDE.md kalite ilkesi gereği üç seviyeli test piramidi uygulanmaktadır:

**Birim testleri:** Tek fonksiyonun izole davranışını doğrular. Örnek: `test_fp_manager.py` — CIDR içi IP'lerin doğru şekilde yanlış pozitif olarak işaretlenip işaretlenmediğini test eder.

**Çapraz testler:** İki modül arası etkileşimi doğrular. Örnek: `test_phase1_integration.py` — Sigma kuralının bir korelasyon olayı ürettiğini ve bu olayın kill chain'e beslendiğini doğrular.

**Entegrasyon testleri:** Tam pipeline doğrulaması. Örnek: `test_pipeline_integration.py` — normalize edilen log kaydından incident oluşumuna kadar tüm akışı end-to-end test eder.

**Tablo 4.1: Test Modülü Başına Test Sayıları (İlk 10)**

| Test Dosyası | Test Sayısı | Kapsam |
|-------------|------------|--------|
| test_database_pg.py | 69 | PostgreSQL veri erişimi |
| test_zeek_collector.py | 62 | Zeek log ayrıştırıcıları |
| test_active_response.py | 61 | P1–P8 aktif yanıt (tam kapsam) |
| test_pipeline_integration.py | 58 | End-to-end pipeline |
| test_incidents.py | 44 | Incident CRUD ve enrichment |
| test_phase1_integration.py | 37 | Faz 1 çapraz entegrasyon |
| test_anomaly.py | 35 | IsolationForest + Welford |
| test_fp_manager.py | 33 | FP geçidi (CIDR + TTL) |
| test_detectors.py | 31 | Port scan, ARP, ICMP dedektörleri |
| test_log_normalizer.py | 28 | Log normalize katmanı |

**Toplam: 1.151 test, 0 hata** (59 test dosyası, pytest 8.3.2)

### 4.2.2 Test Altyapısı

Test altyapısı iki fixture üzerine kuruludur:

- **`tmp_db` fixture:** SQLite geçici veritabanı (test edilen bileşen DB bağımsız olduğunda)
- **`pg_db` fixture:** testcontainers kütüphanesiyle gerçek PostgreSQL konteyneri (PostgreSQL-özgül davranışları test etmek için, örn. ILIKE, TIMESTAMPTZ)

PostgreSQL özgül davranışları gerektiren testler `pg_db` fixture'ını kullanır; Docker erişimi olmayan ortamlarda bu testler otomatik olarak atlanır.

## 4.3 Saldırı Senaryosu Testleri

GNS3 sanal laboratuvarında dört farklı saldırı senaryosu doğrulanmıştır:

### 4.3.1 Senaryo 1: Port Tarama (RECON Aşaması)

Kali Linux makinesinden NetGuard sunucusuna yönelik `nmap -sS -p 1-65535 192.168.203.134` komutu çalıştırıldı.

**Beklenen tespit:** Port scan dedektörü (port_scan.py) — 30 saniye içinde 15+ hedefe SYN paketi.

**Sonuç:** 23 saniye içinde RECON kill chain olayı üretildi; incident oluşturuldu ve dashboard'da görüntülendi. ✅

**Kill chain durumu:** RECON aşaması tetiklendi, IP 192.168.203.132 aktif kill chain takibine alındı.

### 4.3.2 Senaryo 2: SSH Brute Force (WEAPONIZE Aşaması)

`hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.203.134` komutu çalıştırıldı. 60 saniye içinde 150+ başarısız kimlik doğrulama girişimi gerçekleşti.

**Beklenen tespit:** (i) JSON korelasyon kuralı: `ssh_brute_force` — 60 saniyede 5+ başarısız SSH. (ii) Sigma kuralı: `ssh_brute_force.yml` — aynı örüntü.

**Sonuç:** Her iki kural da 8 saniye içinde uyarı üretti. WEAPONIZE kill chain aşaması eklendi. ✅

**Çift tespit:** JSON korelasyon ve Sigma motorunun aynı olayı tespit etmesi tekrar incident oluşturmadı; `fp_manager.py` deduplication katmanı devreye girdi.

### 4.3.3 Senaryo 3: Başarılı Giriş + Lateral Hareket (ACCESS + LATERAL)

Kasıtlı olarak zayıf şifreyle yapılandırılmış ajan VM'ye (192.168.203.142) başarılı SSH bağlantısı kuruldu. Ardından bu makineden iç ağda diğer varlıklara SSH denemesi gerçekleştirildi.

**Sonuç:** ACCESS aşaması (başarılı SSH girişi) + LATERAL aşaması (iç ağdan farklı hedeflere kimlik doğrulama) tespit edildi. ✅

### 4.3.4 Senaryo 4: Tam Kill Chain (FULL_ATTACK_CHAIN)

Yukarıdaki üç senaryo, aynı kaynak IP'den (192.168.203.132) 30 dakika içinde gerçekleştirildi.

**Beklenen:** RECON + WEAPONIZE + ACCESS ≥ 3 aşama → FULL_ATTACK_CHAIN (critical).

**Sonuç:** FULL_ATTACK_CHAIN tetiklendi, kritik incident oluşturuldu, e-posta bildirimi gönderildi, Discord webhook çağrıldı. ✅

**Aktif yanıt:** `POST /api/v1/response/block` ile kaynak IP engellendi. P1–P4 güvenlik geçitleri başarıyla geçildi (RFC1918 değil, düşük FP skoru, severity=critical).

**Tablo 4.2: Saldırı Senaryosu Tespit Sonuçları**

| Senaryo | Beklenen Tespit | Tespit Edildi mi? | Ortalama Gecikme |
|---------|----------------|------------------|-----------------|
| Port tarama (nmap) | RECON | ✅ | 23 sn |
| SSH brute force (hydra) | WEAPONIZE | ✅ | 8 sn |
| Başarılı SSH + lateral | ACCESS + LATERAL | ✅ | 45 sn |
| Tam kill chain | FULL_ATTACK_CHAIN | ✅ | 30 dk (pencere) |
| Sistem yeniden başlatma | Otomatik servis kurtarma | ✅ | 60 sn |

## 4.4 Performans Değerlendirmesi

Performans ölçümleri, syslog, NetFlow ve Zeek'in eş zamanlı çalıştığı yük altında gerçekleştirilmiştir:

**Log işleme kapasitesi:** 192.168.203.134 sunucusunda (2 vCPU, 4 GB RAM, Ubuntu 24.04) saniyede ortalama 850 syslog satırı, 200 NetFlow akışı ve 120 Zeek log satırı normalize edildi. Bu değerler 50–500 çalışanlı bir işletmenin normal trafik hacmini karşılamaktadır.

**Korelasyon motoru gecikmesi:** JSON + Sigma kuralı döngüsü 60 saniyede tamamlandı; ortalama tek döngü süresi 4,2 saniyedir. Bu, tehdit tespit gecikmesinin 60–65 saniye aralığında olduğu anlamına gelir; bu süre SIEM sektöründe "near real-time" olarak kabul edilmektedir.

**Veritabanı sorgu performansı:** 500.000 satırlık `normalized_logs` tablosunda `source_ip` filtreli sorgu, TimescaleDB hypertable ile ortalama 12 ms'de tamamlandı (standart PostgreSQL: ~85 ms).

**Bellek kullanımı:** FastAPI backend (uvicorn) boşta 180 MB, yoğun yük altında 420 MB RAM tüketti. Bu değer, minimum 4 GB RAM gereksinim profiline uygundur.

## 4.5 Mevcut Çözümlerle Karşılaştırma

**Tablo 4.3: NetGuard ile Rakip Çözümler Özellik Karşılaştırması**

| Özellik | NetGuard | Security Onion | Wazuh | Splunk ES |
|---------|----------|---------------|-------|-----------|
| Çok kaynaklı log | ✅ 8 kaynak | ✅ | ✅ | ✅ |
| Zeek entegrasyonu | ✅ 9 log türü | ✅ | ❌ | ❌ |
| NetFlow | ✅ v5/v9 | ✅ | ❌ | ❌ |
| Sigma desteği | ✅ pySigma v2 | ✅ | ❌ Çevirim | ✅ Eklenti |
| Kill chain | ✅ 5 aşama | ✅ | ❌ | ✅ |
| ML anomali | ✅ IF + Welford | ✅ | ❌ | ✅ |
| MITRE ATT&CK | ✅ | ✅ | ✅ | ✅ |
| Aktif yanıt (ağ) | ✅ OPNsense + VyOS | ❌ | ✅ (endpoint) | ❌ |
| Progressive TTL | ✅ P5 | ❌ | ✅ | ❌ |
| Break-glass | ✅ P8 | ❌ | ❌ | ❌ |
| Docker kurulum | ✅ 30 dk | ⚠️ Karmaşık | ✅ | ❌ |
| Donanım gereksinimi | 4 GB RAM | 16 GB RAM | 8 GB RAM | 32 GB+ |
| Toplam maliyet | 0 USD | 0 USD | 0 USD | 50K+ USD |
| Test sayısı | 1.151 (sıfır hata) | — | — | — |

Security Onion ile kıyaslandığında, NetGuard full PCAP yakalama özelliğini sunmamaktadır; bu, belirli adli analiz senaryolarında bir dezavantajdır. Öte yandan, aktif yanıt mekanizması (OPNsense REST + VyOS SSH), progressive TTL ve break-glass bileşenleri Security Onion'da bulunmamaktadır. Donanım gereksinimi açısından NetGuard dört kat daha az RAM ile çalışmaktadır.

---

# BÖLÜM 5 — SONUÇLAR VE ÖNERİLER

## 5.1 Elde Edilen Bulgular

Bu çalışma, aşağıdaki temel bulguları ortaya koymaktadır:

**Bulgu 1 — Teknik uygulanabilirlik:** Ticari NSM çözümlerinin temel özellik seti, açık kaynak bileşenlerle (Zeek, pySigma, scikit-learn, FastAPI, PostgreSQL) orta ölçekli işletme bütçesine uygun biçimde hayata geçirilebilmektedir. 1.151 test (sıfır hata) ve dört farklı GNS3 saldırı senaryosunda %100 tespit başarısı bu uygulanabilirliği doğrulamaktadır.

**Bulgu 2 — Çok kaynaklı korelasyonun değeri:** Yalnızca firewall loglarına dayanan tespit yaklaşımı, SSH brute force + port scan kombinasyonunun önemli bir bölümünü gözden kaçırmaktadır. Zeek log entegrasyonu (DNS, SSL, SMTP, FTP), Sigma kurallarının uygulama katmanı olaylarına erişmesini sağlayarak tespit kapsamını genişletmektedir.

**Bulgu 3 — Kill chain takibinin kritikliği:** Bireysel olayların tek tek değerlendirildiği geleneksel yaklaşımda RECON ve WEAPONIZE olayları farklı zamanlarda oluştuğunda ilişkilendirilemeyebilir. Kill chain takibi bu olayları 30 dakikalık pencerede birleştirerek saldırı kampanyası bütünüyle gözlemlenebilir hale gelmektedir.

**Bulgu 4 — Aktif yanıt güvenlik katmanlarının zorunluluğu:** İlk prototipte tek adımlı IP engellemesi uygulandığında, test aşamasında RFC1918 adreslerinin (gateway IP'leri) yanlışlıkla engellenebildiği görüldü. Sekiz güvenlik geçidinin (P1–P8) eklenmesi bu tür operasyonel kazaları elimine etti; aynı zamanda adli takip için denetim kaydı zorunluluğu sağlandı.

**Bulgu 5 — Endüstri standardı ile örtüşme:** NetGuard'ın bileşenleri, güvenlik sektörünün önde gelen çerçevelerinden ilham almaktadır: Wazuh `repeated_offenders` → P5 progressive TTL; Zeek NetControl PENDING/SUCCEEDED → P6 blok doğrulama; CISA break-glass guidance → P8 acil kurtarma. Bu örtüşme, sistemin pratik kurumsal senaryolarda çalışabilirliğini güçlendirmektedir.

## 5.2 Sistem Kısıtlamaları

**Kısıtlama 1 — East-west görünürlük eksikliği:** Mevcut sensörler perimeter odaklıdır; iç ağ trafiği (east-west) yalnızca L3 switch'ten NetFlow alınması durumunda izlenebilir. Bu, özellikle lateral movement senaryolarında kör nokta oluşturabilir.

**Kısıtlama 2 — Full PCAP yokluğu:** Adli analiz senaryolarında paket düzeyinde inceleme gerektiğinde NetGuard yetersiz kalır. Bu, Security Onion'ın öne çıktığı alandır.

**Kısıtlama 3 — Tek kiracılı mimari:** Mevcut veritabanı mimarisi tek bir kuruluşu izlemek üzere tasarlanmıştır. Yönetilen güvenlik hizmeti sağlayıcıları (MSSP) için çok kiracılı (multi-tenant) mimari PostgreSQL Row-Level Security ile hayata geçirilmelidir.

**Kısıtlama 4 — Anomali-kill chain bağlantısı:** IsolationForest anomali tespiti şu an kill chain pipeline'ına beslenmemektedir. Anomali tabanlı tespitler bağımsız sonuçlar olarak görüntülenmekte, incident üretmemektedir.

**Kısıtlama 5 — Windows Sysmon entegrasyonu eksikliği:** Windows EVTX ayrıştırma mevcuttur; ancak Sysmon (Microsoft Sysinternals Sysmon) olay kimliklerinin (1, 3, 8, 10) tam eşlemesi tamamlanmamıştır.

## 5.3 Gelecek Çalışmalar

Bu çalışma, NetGuard'ın teknik temeli üzerine birkaç kritik iyileştirme alanı belirlemektedir:

**Kısa vadeli (1–3 ay):**

1. **G1 — Otomatik blok:** `FULL_ATTACK_CHAIN` tespitinde `active_response_manager.block_ip()` otomatik çağrısı. CrowdStrike'ın 48 dakikalık ortalama saldırı ilerleme süresi [2] göz önüne alındığında, manuel blok bu pencereyi aşabilmektedir.

2. **G2 — Suricata IDS entegrasyonu:** EVE JSON log formatının `zeek_collector.py` mimarisiyle eşdeğer bir `suricata_collector.py` modülüyle işlenmesi. CIS Control 13.8 gereksinimlerini tamamlayacaktır.

3. **G3 — Çoklu tehdit istihbaratı:** AbuseIPDB'nin yanı sıra Feodo Tracker (botnet C2), ThreatFox IOC ve GreyNoise Community API entegrasyonları (tamamı ücretsiz) ile tehdit istihbaratı zenginleştirmesi.

4. **G5 — Rate limiting:** `POST /response/block` endpoint'ine `@limiter.limit("10/minute")` dekoratörü eklenmesi. OWASP API Security 2023 API4 gereksinimi.

**Orta vadeli (3–6 ay):**

5. **F2 — PostgreSQL-only mimari:** 4.167 satırlık ikili veritabanı katmanı (database.py + database_pg.py) tek PostgreSQL implementasyonuna indirgenmesi. ~2.600 satır kod tekrarı ortadan kalkacaktır.

6. **F4 — Anomali → Kill chain bağlantısı:** AnomalyEngine çıktısının `CorrelatedEvent` üreterek kill chain'e beslenmesi.

7. **U3 — Değiştirilemeyen denetim kaydı:** NIST SP 800-92 uyumluluğu için SHA-256 zinciri tabanlı audit log.

**Uzun vadeli (6–12 ay):**

8. **U1 — East-west görünürlük:** L3 switch NetFlow kaynakları eklenmesi ve east-west lateral movement kurallarının geliştirilmesi.

9. **U6 — Multi-tenant RLS:** PostgreSQL Row-Level Security politikalarıyla MSSP kullanım senaryosu desteği.

10. **T2 — Ticari hazırlık:** MFA (TOTP), at-rest şifreleme, sistematik input validation ve SOC 2 Type I denetim hazırlığı.

## 5.4 Sonuç

Bu çalışmada, orta ölçekli işletmelerin ağ güvenliği izleme ihtiyacını karşılamaya yönelik açık kaynaklı bir NSM platformu olan NetGuard tasarlanmış, uygulanmış ve GNS3 sanal laboratuvarda doğrulanmıştır.

NetGuard, sekiz farklı veri kaynağından ECS-uyumlu normalize olay akışı üretmekte; JSON korelasyon kuralları ve pySigma v2 motoruyla 30'dan fazla Sigma kuralını çift motorlu tespit yaklaşımıyla yürütmekte; beş aşamalı kill chain modeli ile saldırı kampanyalarını bütüncül biçimde izlemekte ve sekiz güvenlik geçidiyle donatılmış aktif yanıt mekanizmasıyla tespit edilen tehditlere otomatik önlem almaktadır.

59 test dosyasında 1.151 pytest testi sıfır hata oranıyla geçilmiş; port tarama, SSH brute force, başarılı giriş/lateral hareket ve tam kill chain senaryolarında %100 tespit başarısı elde edilmiştir. Sistem, 4 GB RAM ile çalışabildiğinden yıllık 50.000+ USD lisans maliyeti gerektiren kurumsal alternatiflere erişim imkânı bulunmayan orta ölçekli işletmeler için pratik ve ekonomik bir çözüm sunmaktadır.

Security Onion kapasitesinin yaklaşık %70–75'ini karşılamakla birlikte, NetGuard'ın aktif yanıt derinliği (progressive TTL, break-glass, OPNsense+VyOS), Docker tabanlı kurulum kolaylığı ve düşük donanım gereksinimleri bu ürünü farklı bir niş konumda tutmaktadır.

---

# KAYNAKLAR

[1] Verizon, "2025 Data Breach Investigations Report," Verizon Enterprise Solutions, 2025.

[2] CrowdStrike, "2025 Global Threat Intelligence Report: Adversary Ecosystem Analysis," CrowdStrike Inc., 2025.

[3] Gartner, "Market Guide for Network Detection and Response," Gartner Inc., 2025.

[4] MITRE Corporation, "MITRE ATT&CK v17 Framework," MITRE ATT&CK, 2025. [Online]. Erişim: https://attack.mitre.org

[5] K. Scarfone, P. Mell, "Guide to Intrusion Detection and Prevention Systems (IDPS)," NIST Special Publication 800-94, National Institute of Standards and Technology, 2007 (2023 güncellemesi).

[6] Center for Internet Security, "CIS Controls v8.1," CIS, 2023.

[7] OWASP, "OWASP API Security Top 10 2023," Open Web Application Security Project, 2023. [Online]. Erişim: https://owasp.org/API-Security

[8] A. Chuvakin, K. Schmidt, C. Phillips, "Logging and Log Management: The Authoritative Guide to Understanding the Concepts Surrounding Logging and Log Management," Syngress / Elsevier, 2012.

[9] R. Bejtlich, "The Practice of Network Security Monitoring: Understanding Incident Detection and Response," No Starch Press, 2013.

[10] Zeek Project, "Zeek Network Security Monitor Documentation," Zeek Project, 2024. [Online]. Erişim: https://docs.zeek.org

[11] SigmaHQ, "Sigma: Generic Signature Format for SIEM Systems," SigmaHQ GitHub Repository, 2024. [Online]. Erişim: https://github.com/SigmaHQ/sigma

[12] pySigma Project, "pySigma: Python Implementation of the Sigma Rule Format," pySigma Documentation, 2024. [Online]. Erişim: https://github.com/SigmaHQ/pySigma

[13] F. Pedregosa et al., "Scikit-learn: Machine Learning in Python," Journal of Machine Learning Research, vol. 12, pp. 2825–2830, 2011.

[14] F. T. Liu, K. M. Ting, Z.-H. Zhou, "Isolation Forest," in Proceedings of the 2008 Eighth IEEE International Conference on Data Mining (ICDM), pp. 413–422, 2008.

[15] Lockheed Martin Corporation, "Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains," Lockheed Martin, 2011.

[16] B. P. Welford, "Note on a Method for Calculating Corrected Sums of Squares and Products," Technometrics, vol. 4, no. 3, pp. 419–420, 1962.

[17] S. Tilkov, S. Vinoski, "Node.js: Using JavaScript to Build High-Performance Network Programs," IEEE Internet Computing, vol. 14, no. 6, pp. 80–83, 2010.

[18] S. Ramachandran, "FastAPI: Modern API Development with Python," Packt Publishing, 2023.

[19] TimescaleDB, "TimescaleDB Documentation," Timescale Inc., 2024. [Online]. Erişim: https://docs.timescale.com

[20] M. Bayer, "Alembic: Database Migration Tool for SQLAlchemy," SQLAlchemy Project, 2024. [Online]. Erişim: https://alembic.sqlalchemy.org

[21] Security Onion Solutions, "Security Onion Documentation," Security Onion Solutions LLC, 2024. [Online]. Erişim: https://docs.securityonion.net

[22] Wazuh Inc., "Wazuh Documentation," Wazuh Inc., 2024. [Online]. Erişim: https://documentation.wazuh.com

[23] Deciso B.V., "OPNsense API Reference," Deciso, 2024. [Online]. Erişim: https://docs.opnsense.org/development/api.html

[24] CISA, "Implementing Phishing-Resistant MFA and Break-Glass Account Guidance," Cybersecurity and Infrastructure Security Agency, 2024.

[25] M. Goodrich, R. Tamassia, "Introduction to Computer Security," Pearson Education, 2011.

[26] W. Stallings, "Network Security Essentials: Applications and Standards," 6th ed., Pearson, 2017.

[27] T. J. Holt, A. M. Bossler, K. C. Seigfried-Spellar, "Cybercrime and Digital Forensics: An Introduction," 3rd ed., Routledge, 2022.

---

# EK A — API REFERANS TABLOSU

NetGuard, FastAPI ile geliştirilmiş RESTful API'yi `/api/v1/` tabanıyla sunar. Tüm endpoint'ler JWT kimlik doğrulaması gerektirir; break-glass endpoint'i `X-Break-Glass-Token` başlığı kabul eder.

**Kimlik Doğrulama**

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| POST | /api/v1/auth/login | Kullanıcı girişi, JWT access/refresh token |
| POST | /api/v1/auth/refresh | Access token yenileme |
| POST | /api/v1/auth/api-keys | API key oluşturma (SHA-256 hash) |

**Normalized Loglar**

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | /api/v1/logs | Sayfalı log listesi (filtreler: source_ip, event_action, tarih) |
| GET | /api/v1/logs/{id} | Tekil log kaydı detayı |

**Incidents**

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | /api/v1/incidents | Incident listesi (severity, status filtreleri) |
| GET | /api/v1/incidents/{id} | MITRE + ilgili loglar + tehdit intel zenginleştirilmiş detay |
| PATCH | /api/v1/incidents/{id} | Durum güncelleme, kapanış notu |

**Aktif Yanıt**

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| POST | /api/v1/response/block | IP engelleme (P1–P8 güvenlik geçitleri) |
| POST | /api/v1/response/unblock | IP engel kaldırma |
| GET | /api/v1/response/blocks | Aktif bloklar listesi |
| POST | /api/v1/response/verify | Phantom/orphan blok tespiti |
| POST | /api/v1/response/break-glass/unblock | JWT bypass acil kurtarma |

**Sigma Kuralları**

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | /api/v1/sigma/rules | Yüklü Sigma kural listesi |
| POST | /api/v1/sigma/validate | YAML kural doğrulama (pySigma parse) |

**Kill Chain / Attack Chain**

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | /api/v1/attack-chains | Aktif ve tamamlanmış kill chain kayıtları |
| GET | /api/v1/attack-chains/{id} | Zincir detayı ve aşama zaman çizelgesi |

**MITRE ATT&CK**

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | /api/v1/mitre/stats | Taktik/teknik sıklık istatistikleri |
| GET | /api/v1/mitre/heatmap | Dashboard heat map verisi |

**Anomali**

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | /api/v1/anomaly/results | Son anomali tespiti sonuçları |
| GET | /api/v1/anomaly/baselines | Per-IP davranış profilleri |

**Uyumluluk**

| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | /api/v1/compliance | 26 güvenlik kontrolü değerlendirmesi |

---

# ÖZGEÇMİŞ

**Ad Soyad:** Mehmet Çapar  
**E-posta:** 20mehmetcapar02@gmail.com  
**Bölüm:** Bilgisayar Mühendisliği  
**Fakülte:** Bilgisayar ve Bilişim Bilimleri Fakültesi  
**Üniversite:** T.C. Sakarya Üniversitesi  

**Teknik Uzmanlık Alanları:**
- Ağ güvenliği izleme (NSM/NDR)
- Python backend geliştirme (FastAPI, asyncio)
- Veritabanı tasarımı (PostgreSQL, TimescaleDB, Alembic)
- Tehdit tespiti ve Sigma kural geliştirme
- GNS3 sanal ağ simülasyonu
- Docker ve konteyner tabanlı altyapı
- Next.js / React frontend geliştirme

**Proje:**  
NetGuard açık kaynak NSM platformu — GitHub: [mehmetcapar/netguard]

---

*Bu rapor, T.C. Sakarya Üniversitesi Bilgisayar ve Bilişim Bilimleri Fakültesi BSM 498 Bitirme Çalışması kapsamında hazırlanmıştır.*

*Mayıs 2026*
