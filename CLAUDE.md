# NetGuard — Claude Rehberi

Bu dosya Claude Code'un her oturumda otomatik okuduğu proje rehberidir.

## Proje Kimliği

NetGuard: NMS + CSNM (Continuous Network Security Monitoring) birleşimi.
Her ağ olayını hem performans hem güvenlik boyutuyla analiz eden unified platform.

## Mevcut Durum — FAZ 2 TAMAMLANDI ✓

### Tamamlanan Fazlar

**Faz 0 ✓** — Zemin temizleme (env değişkenleri, API key SQLite, JWT secret zorunlu, CORS dinamik)
**Faz 1 ✓** — Unified Device Model (`devices` tablosu, tüm modüller device_id kullanır)
**Faz 2 ✓** — NMS Çekirdeği

Faz 2 teslim edilen modüller:
- `server/snmp_collector.py` — Interface table walk, 64-bit sayaç, bandwidth delta, SNMPInterface modeli
- `server/influx_writer.py` — Per-arayüz snmp_interface point yazımı
- `server/uptime_checker.py` — ICMP ping + TCP port kontrolü, device_down/up olayları
- `server/snmp_trap_receiver.py` — UDP 162 TRAP dinleyicisi, minimal BER ayrıştırma
- `server/main.py` — uptime_task + trap_receiver lifespan'a eklendi
- `shared/models.py` — DEVICE_DOWN, DEVICE_UP, SNMP_TRAP event tipleri
- `server/database.py` — service_checks, snmp_poll_history, devices tabloları + metodları
- `tests/conftest.py` — tmp_db fixture ortak hale getirildi (tüm test modülleri kullanır)

Test durumu: **227 test, tümü geçiyor**

## Sonraki Faz — FAZ 3: Auto-Discovery

Hedef: Ağdaki cihazları otomatik keşfetme.

### Yapılacaklar:

**1. Subnet Sweep**
- Dosya: `server/discovery/subnet_scanner.py` (YENİ)
- `ip_network` ile subnet'i tarar
- Her IP için asyncio ICMP ping (uptime_checker.ping kullan)
- Paralel tarama: asyncio.gather + semaphore (max 50 eş zamanlı)

**2. Port/Banner Fingerprinting**
- Dosya: `server/discovery/fingerprinter.py` (YENİ)
- Yaygın portları tarar (22, 23, 80, 161, 443, 8080...)
- Banner grabbing: SSH version, HTTP server header, SNMP sysDescr
- Vendor tespiti: MAC OUI lookup (lokal tablo)

**3. Discovery API Route**
- Dosya: `server/routes/discovery.py` (YENİ)
- `POST /api/v1/discovery/scan` → subnet tarama başlatır (arka plan task)
- `GET /api/v1/discovery/results` → bulunan cihazlar
- Bulunan cihazlar `devices` tablosuna type='discovered' ile kaydedilir

**4. main.py'a router ekle**
- `from server.routes import discovery`
- `app.include_router(discovery.router, ...)`

**5. Testler**
- `tests/test_discovery.py` — mock ping/tcp ile tarama testleri

## Commit Kuralları

- Her görev ayrı commit
- Format: Conventional Commits — `fix(auth): ...`, `feat(discovery): ...`
- Her modül için test yaz, testler geçmeden commit atma
- Commit sonrası push

## Kod Kuralları

- Yorum yazma (açıklayıcı isimler yeterli)
- Error handling sadece gerçek sınır noktalarında (user input, external API)
- Yeni feature için önce test, sonra implementasyon değil — implementasyon + test birlikte
- Mevcut pattern'leri takip et (örn: yeni route → routes/ altına, router'ı main.py'a ekle)

## Mimari Kararlar (Değiştirme)

- **Veritabanı:** SQLite (server/database.py, WAL mode) + InfluxDB (metrikler)
- **Device modeli:** agents + SNMP + discovered hepsi `devices` tablosunda birleşir
- **Ana sayfa:** Network Command Center (topoloji haritası + canlı incidents) (Faz 6)
- **NetFlow/WMI/RRD:** Kapsam dışı, ekleme
- **tmp_db fixture:** conftest.py'da tanımlı, tüm test dosyaları kullanabilir

## Faz Yol Haritası

- Faz 0 ✓ Zemin temizleme
- Faz 1 ✓ Unified Device Model
- Faz 2 ✓ NMS Çekirdeği (SNMP walk, uptime, TRAP)
- Faz 3 → Auto-Discovery (subnet sweep, vendor tespiti)
- Faz 4: Topology Engine (L2/L3 harita)
- Faz 5: Cross-Domain Correlation
- Faz 6: Frontend Dönüşümü (topology-first dashboard)
- Faz 7: SNMPv3 + Security Hardening
- Faz 8: Polish + Raporlama

## Test Çalıştırma

```bash
cd /home/mehmet/netguard
pytest tests/ -q
```

## Ortam

- Ubuntu 24.04, Python 3.12
- VM1 (192.168.203.134): NetGuard Server
- VM2 (192.168.203.142): Agent / Kali (saldırı testleri)
- Dashboard: `cd dashboard-v2 && npm run dev` (port 3000)
