# Backend Agent — Bağlam

NetGuard backend (Python 3.12 + FastAPI).

## Kritik Kurallar
- SQLite-specific syntax yazma: GLOB, PRAGMA yeni modüllere eklenmez
- Field adları: `src_ip`, `dst_ip`, `event_type`, `category`, `tenant_id`, `timestamp`
- Yeni route → `routes/` altına, router `main.py`'a eklenir
- Her yeni modül için `tests/` altına test yaz — pytest tests/ -q geçmeli
- Error handling sadece system boundary'de: user input, external API, UDP socket
- asyncio context içinde blocking I/O kullanma — `asyncio.to_thread()` kullan

## Mimari
```
normalized_logs (tek merkezi tablo)
    ↑
syslog/netflow/snmp/pyshark (collect)
    ↓
correlator.py + sigma_parser.py (detect)
    ↓
attack_chain.py → incident (respond)
```

## Bilinen Sorunlar (Dokunma)
- `correlator.py:192` → SQL injection riski (column whitelist fix gerekiyor)
- `main.py` loops → asyncio içinde senkron blocking (asyncio.to_thread gerekiyor)
- `attack_chain.py:86` → chain state sadece RAM'de (DB persist gerekiyor)
- `log_normalizer.py:166` → Suricata parser `dest_ip` kullanıyor, `dst_ip` olmalı

## Test Fixture
```python
# conftest.py'dan
def test_example(tmp_db, admin_token):
    # tmp_db: izole SQLite instance
    # admin_token: JWT Bearer token
```
