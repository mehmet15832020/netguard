# NetGuard — Claude Rehberi

Bu dosya Claude Code'un her oturumda otomatik okuduğu proje rehberidir.

## Proje Kimliği

NetGuard: NMS + CSNM (Continuous Network Security Monitoring) birleşimi.
Her ağ olayını hem performans hem güvenlik boyutuyla analiz eden unified platform.

## Mevcut Durum — FAZ 5 TAMAMLANDI ✓

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

Faz 5 teslim edilen modüller:
- `server/security_log_parser.py` — ssh_failure/success/sudo → normalized_logs
- `server/snmp_trap_receiver.py` — snmp_trap → normalized_logs
- `server/uptime_checker.py` — device_down/up → normalized_logs
- `config/correlation_rules.json` — 7 cross-domain korelasyon kuralı
- `tests/test_cross_domain_correlation.py` — 13 yeni test

Test durumu: **288 test, tümü geçiyor**

## Sonraki Faz — FAZ 6: Frontend Dönüşümü

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
