# NetGuard — Claude Rehberi

Bu dosya Claude Code'un her oturumda otomatik okuduğu proje rehberidir.

## Proje Kimliği

NetGuard: NMS + CSNM (Continuous Network Security Monitoring) birleşimi.
Her ağ olayını hem performans hem güvenlik boyutuyla analiz eden unified platform.

## Mevcut Durum — FAZ 0 (Zemin Temizleme)

Faz 0 tamamlanmadan Faz 1'e geçilmez.

### Yapılacaklar (sırayla):

**1. ens33 hardcoded → env değişkeni**
- Dosya: `server/detectors/port_scan.py`
- `ens33` → `os.getenv("NETGUARD_INTERFACE", "ens33")`
- `.env.example`'a `NETGUARD_INTERFACE=ens33` ekle

**2. API key → SQLite kalıcı**
- Dosyalar: `server/auth.py` + `server/database.py`
- `_api_keys` in-memory dict → SQLite `api_keys` tablosu
- Tablo: `api_keys(agent_id TEXT PK, api_key TEXT, created_at DATETIME)`
- Sunucu restart sonrası agent bağlantısı kopmaz

**3. JWT secret → .env zorunlu**
- Dosya: `server/auth.py`
- `secrets.token_hex(32)` otomatik üretimi kaldır
- `.env`'de yoksa `RuntimeError` fırlat, sessizce üretme
- `.env.example`'a `JWT_SECRET_KEY=` ekle

**4. Kural kaydetme backend endpoint**
- Dosya: `server/routes/correlation.py`
- `PUT /api/v1/correlation/rules` ekle — JSON dosyasına yazar, reload_rules() çağırır
- Dosya: `dashboard-v2/src/app/(protected)/settings/page.tsx`
- setTimeout simülasyonu → gerçek API çağrısı

**5. CORS → env'den dinamik**
- Dosya: `server/main.py`
- Hardcoded IP listesi → `NETGUARD_CORS_ORIGINS` env (virgülle ayrılmış)
- `.env.example`'a ekle

## Commit Kuralları

- Her görev ayrı commit
- Format: Conventional Commits — `fix(auth): ...`, `feat(correlation): ...`
- Her modül için test yaz, testler geçmeden commit atma
- Commit sonrası push

## Kod Kuralları

- Yorum yazma (açıklayıcı isimler yeterli)
- Error handling sadece gerçek sınır noktalarında (user input, external API)
- Yeni feature için önce test, sonra implementasyon değil — implementasyon + test birlikte
- Mevcut pattern'leri takip et (örn: yeni route → routes/ altına, router'ı main.py'a ekle)

## Mimari Kararlar (Değiştirme)

- **Veritabanı:** Hybrid — eski tablolar source data, yeni tablolar üstüne eklenir
- **Device modeli:** agents + SNMP + discovered hepsi `devices` tablosunda birleşir (Faz 1)
- **Ana sayfa:** Network Command Center (topoloji haritası + canlı incidents) (Faz 6)
- **NetFlow/WMI/RRD:** Kapsam dışı, ekleme

## Sonraki Fazlar (Faz 0 Bittikten Sonra)

- Faz 1: Unified Device Model (`devices` tablosu, tüm modüller device_id kullanır)
- Faz 2: NMS Çekirdeği (64-bit SNMP, GETBULK, uptime checker, TRAP receiver)
- Faz 3: Auto-Discovery
- Faz 4: Topology Engine
- Faz 5: Cross-Domain Correlation
- Tam plan: `weekly_plan.md` memory dosyasında

## Test Çalıştırma

```bash
cd /home/mehmet/netguard
pytest tests/ -v
```

## Ortam

- Ubuntu 24.04, Python 3.12
- VM1 (192.168.203.134): NetGuard Server
- VM2 (192.168.203.142): Agent / Kali (saldırı testleri)
- Dashboard: `cd dashboard-v2 && npm run dev` (port 3000)
