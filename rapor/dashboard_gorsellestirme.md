# NetGuard Dashboard ve Görselleştirme Sayfaları

NetGuard dashboard'u, React 19 + Next.js 16 App Router üzerinde TanStack Query v5 ve ECharts 5 ile inşa edilmiştir. Tüm grafikler merkezi `src/lib/echarts-theme.ts` dosyasındaki Deep Navy temasını paylaşır; renk paleti, glow efektleri ve animasyon süreleri tek noktadan yönetilir. Arayüz 37 sayfadan oluşmaktadır ve sayfalar 6 işlevsel grupta toplanmıştır.

---

## Analitik ve Ağ İzleme Sayfaları

### Top Talkers
`GET /api/v1/analytics/top-talkers` endpoint'inden beslenen panel, ağdaki en aktif kaynak ve hedef IP'leri gönderilen/alınan byte miktarına göre sıralar. Yatay bar grafiği her IP için protokol dağılımını renk kodlamasıyla gösterir; anormal trafik hacmine sahip iç IP'ler hızla saptanabilir.

### Alert Volume
Stacked area chart, son 24 saatteki alert yoğunluğunu `critical / high / medium / low` katmanlarına ayırarak zaman ekseninde gösterir. `GET /api/v1/analytics/alert-volume` verisi; saatlik, 6 saatlik ve günlük seçici ile yeniden örneklenir. SOC analistleri, spike noktalarını tıklayarak ilgili alert listesine doğrudan pivot yapabilir.

### Protocol Distribution
Donut grafik, ağ trafiğini protokol türüne (TCP, UDP, ICMP, HTTP, DNS, TLS vb.) göre yüzdesel olarak dağıtır. Beklenmedik protokol oranları — örneğin DNS trafiğinin ani artışı — DNS tünelleme şüphesini anında gündeme getirir.

### Traffic Volume
East-west (iç ağ) ve north-south (dış ağ) trafik hacmini ayrı renkli seriler halinde gösteren alan grafiği, ağ trafiği temel çizgisinden sapmaları görselleştirir. VyOS NetFlow v9 verileriyle beslenen bu sayfa, lateral movement dönemlerinde iç-iç trafiğin arttığını net biçimde ortaya koyar.

### East-West Connection Matrix
ECharts heatmap, iç ağ segmentleri arasındaki bağlantı yoğunluğunu matris formatında gösterir. Satır kaynak subnet, sütun hedef subnet, renk yoğunluğu bağlantı sayısıdır. Olağandışı subnet çiftleri arasındaki yoğun trafik, lateral movement veya yetkisiz erişim girişimlerini işaret eder.

### Asset Risk Heatmap
Her varlık için alert sayısı, aktif blok durumu ve tehdit istihbaratı composite skorunu birleştiren üç boyutlu risk matrisi; IP adreslerini öncelik sırasına dizer. Yüksek riskli varlıklar tek tıkla detay sayfasına bağlanır.

### MTTD / MTTR Paneli
Mean Time to Detect (MTTD) ve Mean Time to Respond (MTTR) metriklerini SANS 2023 referans değerleriyle karşılaştıran panel, SLA uyum oranını renk kodlamalı göstergelerle sunar. Trend çizgisi haftalık performans değişimini takip eder.

---

## Güvenlik Tespit Sayfaları

### DNS Analiz
Shannon entropisi ≥ 4.0 bit eşiği ve 50 karakteri aşan sorgu uzunluğu ölçütlerini kullanan DNS tünelleme tespiti bu sayfada görselleştirilir. NXDOMAIN spike'ları zaman ekseninde gösterilir; şüpheli domainler için PTR kaydı çözümlemesi ve geçmiş sorgu sıklığı tablosuna erişilir.

### TLS Parmak İzleri
JA4 parmak izi (JA3 legacy fallback ile) tabanlı bu sayfa, SSL/TLS bağlantılarını istemci davranışına göre gruplandırır. Entropi eşiği 4.0 olarak belirlenmiş anormal parmak izleri kırmızı satır olarak işaretlenir. Bilinen C2 framework parmak izleriyle (Cobalt Strike, Metasploit) eşleşme halinde otomatik kritik severity atanır.

### Beaconing Tespiti
IAT (Inter-Arrival Time) algoritması, RITA BlackHat 2018 metodolojisine dayalı olarak C2 beacon davranışını tespit eder. Düzenli aralıklı HTTP/HTTPS istekleri Bessel düzeltmeli standart sapma ile ölçülür; jitter oranı düşük bağlantılar beacon adayı olarak listelenir. 300 saniyelik kadans bağımsız olarak çalışır.

### Başarısız Kimlik Doğrulama
SSH brute force, RDP spray ve Windows logon failure (EID 4625/4776) olaylarını zaman bazlı heatmap ile sunar. Kaynak IP başına deneme sayısı ve başarı oranı gösterilir; WEAPONIZE aşamasına tırmanan olaylar kill chain bağlantısıyla işaretlenir.

### Anomali Tespiti
IsolationForest modelinin ürettiği anomali skorları scatter plot formatında gösterilir. Her nokta bir IP veya olay grubunu temsil eder; kontaminasyon skoru 0.02 eşiğini aşan noktalar ayrı renkte vurgulanır. Welford online algoritmasıyla hesaplanan z-skor ve IQR aykırı değer analizi sonuçları yan panelde listelenir.

---

## Araştırma ve Kural Yönetimi Sayfaları

### Tehdit Avı (Threat Hunt) Workbench
No-code sorgu builder; kaynak/hedef IP, port, protokol, olay kategorisi ve zaman aralığı filtrelerini sürükle-bırak arayüzüyle birleştirir. Oluşturulan sorgular `saved_hunts` tablosunda saklanır ve paylaşılabilir. Sonuç tablosu TanStack Virtual ile sanallaştırılmış satır rendering kullanır; yüz binlerce log kaydı sayfa yenilenmeden gezilir.

### Sigma Kural Yönetimi
**Kural Listesi:** Aktif 50+ pySigma v2 kuralını durum/kategori/şiddet filtreleriyle görüntüler; tek tıkla etkinleştir/devre dışı bırak.  
**Sigma Wizard:** 4 adımlı form wizard (meta → log kaynağı → tespitler → koşullar) TypeScript ile YAML üretir ve sunucuya atomik yazar.  
**Monaco Editör:** `@monaco-editor/react` entegrasyonu ile sözdizimi vurgulamalı, hata işaretlemeli YAML düzenleme ortamı sunar.

### Korelasyon Kuralları
JSON tabanlı korelasyon kuralları için CRUD arayüzü; kural adı, grup-by alanı, zaman penceresi, eşik sayısı ve şiddet değerini form üzerinden düzenler. Atomik dosya yazma ile tutarlılık garantisi sağlanır.

### Uyumluluk Paneli
26 güvenlik kontrolünün otomatik ölçüm sonuçlarını CIS Controls v8.1 ve NIST SP 800-94 referanslarıyla karşılaştırır. Geçen/başarısız kontroller renk kodlamalı tablo ile gösterilir; her kontrol için ilgili log kanıtına doğrudan bağlantı mevcuttur.

---

## Görsel Tasarım Altyapısı

Tüm arayüz `#060c17` arka plan ve `#0d1526` panel rengiyle Deep Navy kimliğini taşır. Birincil renk sky-400 (cyber cyan) olup kritik alert'lerde kırmızı glow efekti devreye girer. Hover-expand sidebar (48px → 228px, localStorage pin), skeleton loading shimmer animasyonu ve Ctrl+K command palette (39 komut, 6 bölüm, Zustand store) operasyonel akışı hızlandırır.
