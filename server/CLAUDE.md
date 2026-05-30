# Backend Agent — Bağlam

NetGuard backend (Python 3.12 + FastAPI).

## Kritik Kurallar
- SQLite-specific syntax yazma: GLOB, PRAGMA yeni modüllere eklenmez
- ECS field adları: `source_ip`, `destination_ip`, `event_action`, `event_category`, `observer_hostname`, `network_protocol`, `source_port`, `destination_port`, `tenant_id`, `timestamp`
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

## Test Fixture
```python
# conftest.py'dan
def test_example(tmp_db, admin_token):
    # tmp_db: izole SQLite instance
    # admin_token: JWT Bearer token
```
