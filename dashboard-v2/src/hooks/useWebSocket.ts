'use client'

// NetGuard — WebSocket hook
// Bağlantıyı başlatır, gelen mesajları ilgili store'lara yönlendirir.
// Tek bir yerde mount edilir (layout.tsx), uygulama boyunca aktif kalır.

import { useEffect } from 'react'
import { wsClient } from '@/lib/websocket'
import { useAlertStore } from '@/store/alertStore'
import { useMetricsStore } from '@/store/metricsStore'
import type { Alert, MetricSnapshot } from '@/types/models'

export function useWebSocket() {
  const addAlert = useAlertStore((s) => s.addAlert)
  const updateSnapshot = useMetricsStore((s) => s.updateSnapshot)

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
        // security_event ve correlated_event için TanStack Query refetch kullanıyoruz
        default:
          break
      }
    })

    return () => {
      unsubscribe()
      // Bağlantıyı kapatmıyoruz — layout unmount olunca sidebar değişir ama WS aktif kalmalı
    }
  }, [addAlert, updateSnapshot])
}
