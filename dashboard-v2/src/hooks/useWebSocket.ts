'use client'

import { useEffect } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { wsClient } from '@/lib/websocket'
import { useAlertStore } from '@/store/alertStore'
import { useMetricsStore } from '@/store/metricsStore'
import type { Alert, MetricSnapshot } from '@/types/models'

export function useWebSocket() {
  const addAlert    = useAlertStore((s) => s.addAlert)
  const updateSnapshot = useMetricsStore((s) => s.updateSnapshot)
  const queryClient = useQueryClient()

  useEffect(() => {
    wsClient.connect()

    const unsubscribe = wsClient.subscribe((msg) => {
      switch (msg.type) {

        case 'alert':
          addAlert(msg.data as Alert)
          queryClient.invalidateQueries({ queryKey: ['alerts'] })
          queryClient.invalidateQueries({ queryKey: ['security-status'] })
          queryClient.invalidateQueries({ queryKey: ['attack-chain-stats'] })
          break

        case 'metric':
          updateSnapshot(msg.data as MetricSnapshot)
          break

        case 'correlated_event':
          queryClient.invalidateQueries({ queryKey: ['correlated-events'] })
          queryClient.invalidateQueries({ queryKey: ['corr-events-timeline'] })
          queryClient.invalidateQueries({ queryKey: ['security-events'] })
          queryClient.invalidateQueries({ queryKey: ['security-summary'] })
          queryClient.invalidateQueries({ queryKey: ['security-status'] })
          break

        case 'attack_chain':
          queryClient.invalidateQueries({ queryKey: ['attack-chains-active'] })
          queryClient.invalidateQueries({ queryKey: ['attack-chains-stats'] })
          queryClient.invalidateQueries({ queryKey: ['attack-chains-history'] })
          queryClient.invalidateQueries({ queryKey: ['attack-chain-stats'] })
          queryClient.invalidateQueries({ queryKey: ['security-status'] })
          break

        case 'incident':
          queryClient.invalidateQueries({ queryKey: ['incidents'] })
          queryClient.invalidateQueries({ queryKey: ['incident-summary'] })
          queryClient.invalidateQueries({ queryKey: ['incident-summary-overview'] })
          queryClient.invalidateQueries({ queryKey: ['security-status'] })
          queryClient.invalidateQueries({ queryKey: ['mttd-mttr-incidents'] })
          queryClient.invalidateQueries({ queryKey: ['mttd-mttr-overview'] })
          break

        default:
          break
      }
    })

    return () => { unsubscribe() }
  }, [addAlert, updateSnapshot, queryClient])
}
