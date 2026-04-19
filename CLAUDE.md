# NetGuard — Claude Rehberi

Bu dosya Claude Code'un her oturumda otomatik okuduğu proje rehberidir.

## Proje Kimliği

NetGuard: NMS + CSNM (Continuous Network Security Monitoring) birleşimi.
Her ağ olayını hem performans hem güvenlik boyutuyla analiz eden unified platform.

## Mevcut Durum — FAZ 7 TAMAMLANDI ✓

### Tamamlanan Fazlar

**Faz 0 ✓** — Zemin temizleme (env değişkenleri, API key SQLite, JWT secret zorunlu, CORS dinamik)
**Faz 1 ✓** — Unified Device Model (`devices` tablosu, tüm modüller device_id kullanır)
**Faz 2 ✓** — NMS Çekirdeği (SNMP walk, uptime, TRAP)
**Faz 3 ✓** — Auto-Discovery (subnet sweep, fingerprinting)
**Faz 4 ✓** — Topology Engine

Faz 4 teslim edilen modüller:
- `server/topology/builder.py` — SNMP ARP walk, LLDP komşu keşfi, subnet fallback
- `server/routes/topology.py` — GET /graph, POST /refresh
- `server/database.py` — topology_nodes + topology_edges tabloları

**Faz 5 ✓** — Cross-Domain Correlation
**Faz 6 ✓** — Frontend Dönüşümü (devices, discovery, topology sayfaları, overview'da mini topoloji haritası)
**Faz 7 ✓** — SNMPv3 + Security Hardening

Faz 7 teslim edilen modüller:
- `server/snmp_auth.py` — v2c/v3 birleşik auth builder (CommunityData/UsmUserData)
- `server/database.py` — snmp_v3_* kolonları idempotent migration
- `server/snmp_collector.py` — poll_device_async v3 parametreleri
- `server/topology/builder.py` — ARP/LLDP walk v3 destekli
- `server/routes/snmp.py` — v3 Pydantic modelleri, secret key response'dan çıkarıldı
- `tests/test_snmpv3.py` — 14 yeni test

Test durumu: **302 test, tümü geçiyor**

## Sonraki Faz — FAZ 8: Polish + Raporlama

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
- Faz 3 ✓ Auto-Discovery (subnet sweep, vendor tespiti)
- Faz 4 ✓ Topology Engine (L2/L3 harita)
- Faz 5 ✓ Cross-Domain Correlation
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
