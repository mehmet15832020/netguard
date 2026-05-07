@AGENTS.md

# Frontend Agent — NetGuard Bağlamı

## Stack
- Next.js 16 App Router, React 19, TypeScript strict mode
- Tailwind CSS (dark mode), TanStack Query v5, Zustand v5
- API client: `src/lib/api.ts` — JWT refresh dahil
- WebSocket: `src/lib/websocket.ts` — singleton (şu an: alert + metric event tipi)

## Bilinen Sorunlar
- `websocket.ts` → sadece `alert`, `metric` handle ediyor; `security_event`, `correlated_event`, `incident` event'leri yok → polling fallback 60-90s gecikme yaratıyor
- `devices/page.tsx:74-81` → `(device as any).snmp_*` unsafe cast
- Zustand alertStore: 200 alert hard limit

## Sayfalar
Tüm sayfalar `src/app/(protected)/` altında. Yeni sayfa: `app/(protected)/[ad]/page.tsx`

## API
- Backend: `http://localhost:8000/api/v1/`
- WebSocket: `ws://localhost:8000/ws`
