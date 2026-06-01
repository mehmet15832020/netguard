import { create } from 'zustand'
import type { NormalizedLog } from '@/types/models'

const MAX_BUFFER = 1000

interface LogStreamState {
  streamLogs: NormalizedLog[]
  addStreamLog: (log: NormalizedLog) => void
  setStreamLogs: (logs: NormalizedLog[]) => void
  clearStream: () => void
}

export const useLogStreamStore = create<LogStreamState>((set) => ({
  streamLogs: [],

  addStreamLog: (log) =>
    set((s) => ({
      streamLogs: [log, ...s.streamLogs].slice(0, MAX_BUFFER),
    })),

  setStreamLogs: (logs) =>
    set({ streamLogs: logs.slice(0, MAX_BUFFER) }),

  clearStream: () => set({ streamLogs: [] }),
}))
