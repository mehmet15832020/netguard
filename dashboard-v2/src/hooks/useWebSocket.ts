'use client'

import { useEffect, useRef } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { wsClient } from '@/lib/websocket'
import { useAlertStore } from '@/store/alertStore'
import { useMetricsStore } from '@/store/metricsStore'
import type { Alert, MetricSnapshot } from '@/types/models'

const ALERT_KEYS    = new Set(['alerts', 'security-status', 'attack-chain-stats'])
const CORREL_KEYS   = new Set(['correlated-events', 'corr-events-timeline', 'security-events', 'security-summary', 'security-status'])
const SEC_EVT_KEYS  = new Set(['security-events', 'security-summary', 'security-status'])
const CHAIN_KEYS    = new Set(['attack-chains-active', 'attack-chains-stats', 'attack-chains-history', 'attack-chain-stats', 'security-status'])
const INCIDENT_KEYS = new Set(['incidents', 'incident-summary', 'incident-summary-overview', 'security-status', 'mttd-mttr-incidents', 'mttd-mttr-overview'])

export function useWebSocket() {
  const addAlert       = useAlertStore((s) => s.addAlert)
  const updateSnapshot = useMetricsStore((s) => s.updateSnapshot)
  const queryClient    = useQueryClient()

  // Stable refs — avoids re-subscribing when Zustand emits action identity changes
  const addAlertRef       = useRef(addAlert)
  const updateSnapshotRef = useRef(updateSnapshot)
  addAlertRef.current       = addAlert
  updateSnapshotRef.current = updateSnapshot

  useEffect(() => {
    wsClient.connect()

    const unsubscribe = wsClient.subscribe((msg) => {
      switch (msg.type) {

        case 'alert':
          addAlertRef.current(msg.data as Alert)
          queryClient.invalidateQueries({
            predicate: (q) => ALERT_KEYS.has(q.queryKey[0] as string),
          })
          break

        case 'metric':
          updateSnapshotRef.current(msg.data as MetricSnapshot)
          break

        case 'security_event':
          queryClient.invalidateQueries({
            predicate: (q) => SEC_EVT_KEYS.has(q.queryKey[0] as string),
          })
          break

        case 'correlated_event':
          queryClient.invalidateQueries({
            predicate: (q) => CORREL_KEYS.has(q.queryKey[0] as string),
          })
          break

        case 'attack_chain':
          queryClient.invalidateQueries({
            predicate: (q) => CHAIN_KEYS.has(q.queryKey[0] as string),
          })
          break

        case 'incident':
          queryClient.invalidateQueries({
            predicate: (q) => INCIDENT_KEYS.has(q.queryKey[0] as string),
          })
          break

        default:
          break
      }
    })

    return () => { unsubscribe() }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [queryClient])
}
