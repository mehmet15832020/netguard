# NetGuard — Mimari Kararlar

Bu dosya projedeki önemli teknik kararları ve gerekçelerini belgeler.
Gerçek dünyada buna ADR (Architecture Decision Record) denir.

---

## ADR-001: Dil Stratejisi

**Tarih:** 2026-03-19
**Durum:** Kabul edildi

### Karar
- Faz 1-4: Python ile geliştir
- Faz 5+: Agent kritik kısımlarını Go ile yeniden yaz

### Gerekçe
- Python ile hızlı prototipleme → mimariyi öğrenme sürecini hızlandırır
- Modüler yapı sayesinde dil değişimi mimariyi bozmaz
- Go: Zabbix agent benzeri düşük kaynak tüketimi hedefi

---

## ADR-002: Veri Modeli Stratejisi

**Tarih:** 2026-03-19
**Durum:** Kabul edildi

### Karar
Tüm veri modelleri `shared/models.py` içinde Pydantic ile tanımlanır.
Agent ve server bu modüle bağımlıdır, birbirine değil.

### Gerekçe
- Tek kaynak of truth: model değişince iki taraf otomatik güncellenir
- Pydantic validasyon: Geçersiz veri server'a ulaşmadan reddedilir
- JSON serializasyon otomatik: `.model_dump_json()` yeterli

---

## ADR-003: İletişim Protokolü

**Tarih:** 2026-03-19
**Durum:** Kabul edildi

### Karar
Agent → Server iletişimi HTTP/REST, JSON payload.

### Gerekçe
- Debug edilmesi kolay (curl ile test edilebilir)
- Firewall kuralları HTTP'yi tanır
- İleride WebSocket veya gRPC'ye geçiş mümkün — endpoint'ler `shared/protocol.py`'de merkezi