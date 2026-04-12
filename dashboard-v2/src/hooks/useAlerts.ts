'use client'

import { useQuery } from '@tanstack/react-query'
import { alertsApi } from '@/lib/api'
import { useAlertStore } from '@/store/alertStore'

export function useAlerts(status?: 'active' | 'resolved', limit = 100) {
  const liveAlerts = useAlertStore((s) => s.liveAlerts)

  const query = useQuery({
    queryKey: ['alerts', status, limit],
    queryFn: () => alertsApi.list({ status, limit }),
    refetchInterval: 20_000,
  })

  // Canlı alert'leri REST sonucunun önüne koy, duplikaları çıkar
  const apiAlerts = query.data?.alerts ?? []
  const liveIds = new Set(liveAlerts.map((a) => a.alert_id))
  const merged = [
    ...liveAlerts,
    ...apiAlerts.filter((a) => !liveIds.has(a.alert_id)),
  ]

  const filtered = status ? merged.filter((a) => a.status === status) : merged

  return {
    alerts: filtered.slice(0, limit),
    isLoading: query.isLoading,
    error: query.error,
  }
}
