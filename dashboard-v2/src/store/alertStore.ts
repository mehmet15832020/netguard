// NetGuard — Alert store (Zustand)
// WebSocket'ten gelen canlı alertleri tutar.

import { create } from 'zustand'
import type { Alert } from '@/types/models'

interface AlertStore {
  liveAlerts: Alert[]
  unreadCount: number
  addAlert: (alert: Alert) => void
  markAllRead: () => void
  clearResolved: () => void
}

export const useAlertStore = create<AlertStore>((set) => ({
  liveAlerts: [],
  unreadCount: 0,

  addAlert: (alert) =>
    set((state) => {
      // Aynı alert_id varsa güncelle, yoksa başa ekle
      const exists = state.liveAlerts.some((a) => a.alert_id === alert.alert_id)
      const updated = exists
        ? state.liveAlerts.map((a) => (a.alert_id === alert.alert_id ? alert : a))
        : [alert, ...state.liveAlerts].slice(0, 200) // max 200 alert bellekte

      return {
        liveAlerts: updated,
        unreadCount: exists ? state.unreadCount : state.unreadCount + 1,
      }
    }),

  markAllRead: () => set({ unreadCount: 0 }),

  clearResolved: () =>
    set((state) => ({
      liveAlerts: state.liveAlerts.filter((a) => a.status === 'active'),
    })),
}))
