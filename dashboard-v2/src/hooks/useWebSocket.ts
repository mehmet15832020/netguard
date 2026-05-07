'use client'

// NetGuard — WebSocket hook
// Bağlantıyı başlatır, gelen mesajları ilgili store'lara yönlendirir.
// Tek bir yerde mount edilir (layout.tsx), uygulama boyunca aktif kalır.

import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { wsClient } from '@/lib/websocket'
import { useAlertStore } from '@/store/alertStore'
import { useMetricsStore } from '@/store/metricsStore'
import type { Alert, MetricSnapshot } from '@/types/models'

export function useWebSocket() {
  const addAlert = useAlertStore((s) => s.addAlert)
  const updateSnapshot = useMetricsStore((s) => s.updateSnapshot)
  const queryClient = useQueryClient()

  useEffect(() => {
    wsClient.connect()

    const unsubscribe = wsClient.subscribe((msg) => {
      switch (msg.type) {
        case 'alert':
          addAlert(msg.data as Alert)
          break
        case 'metric':
          updateSnapshot(msg.data as MetricSnapshot)
          break
        case 'correlated_event':
          queryClient.invalidateQueries({ queryKey: ['correlated-events'] })
          queryClient.invalidateQueries({ queryKey: ['security-events'] })
          break
        case 'incident':
          queryClient.invalidateQueries({ queryKey: ['incidents'] })
          break
        default:
          break
      }
    })

    return () => {
      unsubscribe()
      // Bağlantıyı kapatmıyoruz — layout unmount olunca sidebar değişir ama WS aktif kalmalı
    }
  }, [addAlert, updateSnapshot, queryClient])
}
