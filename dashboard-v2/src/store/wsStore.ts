import { create } from 'zustand'

interface WsState {
  isConnected: boolean
  setConnected: (v: boolean) => void
}

export const useWsStore = create<WsState>((set) => ({
  isConnected: false,
  setConnected: (v) => set({ isConnected: v }),
}))
