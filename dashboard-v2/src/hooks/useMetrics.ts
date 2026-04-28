'use client'

import { useQuery } from '@tanstack/react-query'
import { agentsApi, metricsApi } from '@/lib/api'
import type { MetricRange } from '@/lib/api'
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

// InfluxDB'den agent metrik geçmişi
export function useInfluxMetrics(agentId: string, range: MetricRange = '1h') {
  return useQuery({
    queryKey: ['influx-metrics', agentId, range],
    queryFn: () => metricsApi.agentMetrics(agentId, range),
    enabled: !!agentId,
    refetchInterval: 60_000,
  })
}

// Saatlik log hacmi
export function useLogVolume(range: MetricRange = '24h') {
  return useQuery({
    queryKey: ['log-volume', range],
    queryFn: () => metricsApi.logVolume(range),
    refetchInterval: 60_000,
  })
}
