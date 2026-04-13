'use client'

import { useQuery } from '@tanstack/react-query'
import { agentsApi } from '@/lib/api'
import { useMetricsStore } from '@/store/metricsStore'

// Agent listesi — 30s'de bir yenile
export function useAgents() {
  return useQuery({
    queryKey: ['agents'],
    queryFn: () => agentsApi.list(),
    refetchInterval: 30_000,
  })
}

// Belirli agent'ın son snapshot'ı — önce Zustand store'a bak (WebSocket),
// store boşsa REST API'den çek
export function useLatestSnapshot(agentId: string) {
  const storeSnapshot = useMetricsStore((s) => s.latest[agentId])

  const query = useQuery({
    queryKey: ['snapshot', agentId],
    queryFn: () => agentsApi.getLatestSnapshot(agentId),
    refetchInterval: 15_000,
    enabled: !storeSnapshot,  // store'da varsa API'ye gitme
  })

  return {
    snapshot: storeSnapshot ?? query.data,
    isLoading: !storeSnapshot && query.isLoading,
    error: query.error,
  }
}

const EMPTY_SNAPSHOTS: never[] = []

// Belirli agent'ın geçmiş snapshot'ları (grafik için)
export function useSnapshotHistory(agentId: string) {
  return useMetricsStore((s) => s.snapshots[agentId] ?? EMPTY_SNAPSHOTS)
}
