// NetGuard — Metrics store (Zustand)
// WebSocket'ten gelen canlı metrik snapshot'larını tutar.

import { create } from 'zustand'
import type { MetricSnapshot } from '@/types/models'

// Agent başına son N snapshot'ı tut (grafik için)
const MAX_HISTORY = 60

interface MetricsStore {
  snapshots: Record<string, MetricSnapshot[]>   // agentId → snapshot geçmişi
  latest: Record<string, MetricSnapshot>        // agentId → son snapshot
  updateSnapshot: (snapshot: MetricSnapshot) => void
  getHistory: (agentId: string) => MetricSnapshot[]
}

export const useMetricsStore = create<MetricsStore>((set, get) => ({
  snapshots: {},
  latest: {},

  updateSnapshot: (snapshot) =>
    set((state) => {
      const history = state.snapshots[snapshot.agent_id] ?? []
      const updated = [...history, snapshot].slice(-MAX_HISTORY)
      return {
        snapshots: { ...state.snapshots, [snapshot.agent_id]: updated },
        latest: { ...state.latest, [snapshot.agent_id]: snapshot },
      }
    }),

  getHistory: (agentId) => get().snapshots[agentId] ?? [],
}))
