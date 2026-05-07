# NetGuard — Multi-Agent Geliştirme Protokolü

Bu dosya Claude Code subagent sisteminin nasıl kullanılacağını tanımlar.
Orchestrator (ana Claude Code oturumu) bu protokolü izleyerek subagent'ları yönetir.

---

## Agent Rolleri

### 1. Backend Agent
**Kapsam:** `server/` dizini — Python/FastAPI kodu
**Subagent tipi:** `general-purpose`
**Worktree:** Evet (`isolation: "worktree"`)
**Briefing şablonu:**
```
Sen NetGuard projesinin backend mühendisisin.
Proje: /home/mehmet/netguard
Kapsam: server/ dizini
Kural: SQLite'a özgü syntax yazma (GLOB, PRAGMA). Field adları: src_ip, dst_ip, event_type.
Görev: [GÖREV TANIMI]
Test: Değişiklik için tests/ altına test yaz, pytest tests/ -q geçmeli.
```

### 2. Frontend Agent
**Kapsam:** `dashboard-v2/` dizini — Next.js/React/TypeScript
**Subagent tipi:** `general-purpose`
**Worktree:** Evet (`isolation: "worktree"`)
**Briefing şablonu:**
```
Sen NetGuard projesinin frontend mühendisisin.
Proje: /home/mehmet/netguard
Kapsam: dashboard-v2/ dizini
Stack: Next.js App Router, React 19, TypeScript strict, Tailwind CSS, TanStack Query, Zustand
API: /api/v1/* → FastAPI backend (http://localhost:8000)
WebSocket: ws://localhost:8000/ws
Görev: [GÖREV TANIMI]
```

### 3. Detection Agent
**Kapsam:** `server/correlator.py`, `server/sigma_parser.py`, `server/attack_chain.py`, `config/sigma_rules/`
**Subagent tipi:** `general-purpose`
**Worktree:** Evet
**Briefing şablonu:**
```
Sen NetGuard'ın detection logic mühendisisin.
Sigma kuralları: config/sigma_rules/*.yml
Korelasyon kuralları: config/correlation_rules.json
Kill chain: server/attack_chain.py (RECON→WEAPONIZE→ACCESS→LATERAL→EXECUTE)
Görev: [GÖREV TANIMI]
Not: Sigma parser şu an custom DSL (pySigma değil). count() by field > N syntax kullan.
```

### 4. Test Agent
**Kapsam:** `tests/` dizini
**Subagent tipi:** `general-purpose`
**Worktree:** Hayır (okuma ağırlıklı, mevcut worktree üzerinde yazar)
**Briefing şablonu:**
```
Sen NetGuard'ın test mühendisisin.
Test framework: pytest, FastAPI TestClient
Fixture: tests/conftest.py — tmp_db, admin_token, superadmin_token
Görev: [MODÜL] için test yaz. Mevcut test patterns: tests/test_correlator.py, tests/test_anomaly.py
Hedef: pytest tests/ -q → tüm testler geçmeli.
```

### 5. Security Reviewer Agent
**Kapsam:** Tüm kod — sadece okuma
**Subagent tipi:** `Explore`
**Worktree:** Hayır
**Briefing şablonu:**
```
NetGuard projesinde güvenlik review yap.
Odak: [DEĞIŞEN DOSYALAR]
Kontrol listesi:
- SQL injection (dinamik string birleştirme var mı?)
- asyncio içinde blocking I/O var mı?
- Hardcoded credentials var mı?
- Auth bypass riski var mı?
- Input validation eksik mi?
Sadece gerçek bulgular raporla, potansiyel değil.
```

### 6. Explore/Research Agent
**Kapsam:** Kod araştırma, web arama
**Subagent tipi:** `Explore` veya `general-purpose`
**Worktree:** Hayır
**Kullanım:** Mimari kararlar, kütüphane karşılaştırması, piyasa araştırması

---

## Paralel vs Sıralı Çalıştırma

### Paralel çalıştır (bağımsız modüller):
- Backend Agent + Frontend Agent (farklı dizinler)
- Birden fazla Explore Agent (farklı araştırma konuları)
- Test Agent + Backend Agent (farklı feature'lar)

### Sıralı çalıştır (bağımlı işler):
1. Backend Agent → feature yaz
2. Test Agent → aynı feature için test yaz
3. Security Reviewer → değişiklikleri tara

---

## Worktree Protokolü

Her büyük feature için (`isolation: "worktree"` ile):
- Dal adı: `feature/[faz]-[kısa-isim]` (örn: `feature/f0-1-sql-injection-fix`)
- Agent bitince: branch + path döner, orchestrator review yapar
- Onaylanırsa: `git merge` ile main'e alınır

Küçük fix'ler (< 50 satır, 1 dosya) için worktree gerekmez.

---

## Mevcut Kritik Bağlam

Orchestrator her agent'a şunları iletmeli:
- `normalized_logs` tek merkezi tablo — doğrudan SQL yazma yerine `db.*` metotlarını kullan
- Field convention: `src_ip`, `dst_ip`, `event_type`, `category`, `tenant_id`
- Test fixture: `tmp_db` conftest.py'da, her test bu fixture'u kullanmalı
- Commit format: `feat(modül): açıklama` / `fix(modül): açıklama`

---

## Öncelik Matrisi (Güncel)

```
Faz 0 — Kritik (hemen):
  F0-1: SQL injection fix (correlator.py:192)
  F0-2: asyncio blocking fix (main.py loops)
  F0-3: Auth log year boundary fix (log_normalizer.py:103)
  F0-4: purge() periyodik çağrısı (attack_chain + main.py)
  F0-5: docker-compose credentials → .env
  F0-6: dest_ip → dst_ip Suricata fix

Faz 1 — Kararlılık:
  F1-1: Attack chain DB persistence
  F1-2: WebSocket → 5 event tipi
  F1-3: Alert dedup fingerprinting
  F1-4: Notification retry queue
  F1-5: Incident FSM state validation
  F1-6: Parser fail → raw log flag

Faz 2 — Algılama Kalitesi:
  F2-1: pySigma entegrasyonu
  F2-2: Anomaly model persistence
  F2-3: Windowed baseline reset
  F2-4: CI/CD GitHub Actions
  F2-5: E2E test pipeline
  F2-6: Docker hardening

Faz 3 — Ölçek:
  F3-1: PostgreSQL + TimescaleDB
  F3-2: aiosqlite/asyncpg
  F3-3: Kubernetes manifests
  F3-4: Zeek/Suricata TAP
```
