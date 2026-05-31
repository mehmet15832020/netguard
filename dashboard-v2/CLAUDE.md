@AGENTS.md

# Frontend Agent — NetGuard Bağlamı

## Stack
- Next.js 16 App Router, React 19, TypeScript strict mode
- Tailwind CSS (dark mode), TanStack Query v5, Zustand v5
- API client: `src/lib/api.ts` — JWT refresh dahil
- WebSocket: `src/lib/websocket.ts` — singleton, post-connect auth (RFC 6750), heartbeat, jitter backoff
- WS event types: `alert | metric | security_event | correlated_event | incident | attack_chain`

## Sayfalar
Tüm sayfalar `src/app/(protected)/` altında. Yeni sayfa: `app/(protected)/[ad]/page.tsx`

## API
- Backend: `http://localhost:8000/api/v1/`
- WebSocket: `ws://localhost:8000/ws`
