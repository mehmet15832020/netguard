// NetGuard — WebSocket istemcisi
// Singleton pattern: uygulama boyunca tek bağlantı.
// Yeniden bağlanma (reconnect) otomatik.

import { auth } from '@/lib/api'

const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? 'ws://localhost:8000'

export type WSMessageType = 'alert' | 'metric' | 'security_event' | 'correlated_event' | 'ping'

export interface WSMessage<T = unknown> {
  type: WSMessageType
  data: T
}

type MessageHandler = (msg: WSMessage) => void

class NetGuardWebSocket {
  private ws: WebSocket | null = null
  private handlers: Set<MessageHandler> = new Set()
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private reconnectDelay = 2000   // ms
  private maxDelay = 30000        // 30s üst sınır
  private shouldConnect = false

  connect(): void {
    this.shouldConnect = true
    this._connect()
  }

  private _connect(): void {
    if (typeof window === 'undefined') return
    if (this.ws?.readyState === WebSocket.OPEN) return

    const token = auth.getToken()
    const url = token
      ? `${WS_URL}/ws?token=${token}`
      : `${WS_URL}/ws`

    try {
      this.ws = new WebSocket(url)
    } catch {
      this._scheduleReconnect()
      return
    }

    this.ws.onopen = () => {
      console.log('[NetGuard WS] Bağlandı')
      this.reconnectDelay = 2000
    }

    this.ws.onmessage = (event) => {
      try {
        const msg: WSMessage = JSON.parse(event.data)
        this.handlers.forEach((h) => h(msg))
      } catch {
        // parse hatası — yoksay
      }
    }

    this.ws.onclose = () => {
      console.log('[NetGuard WS] Bağlantı kesildi')
      if (this.shouldConnect) this._scheduleReconnect()
    }

    this.ws.onerror = () => {
      this.ws?.close()
    }
  }

  private _scheduleReconnect(): void {
    if (this.reconnectTimer) return
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      this._connect()
      // Exponential backoff
      this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxDelay)
    }, this.reconnectDelay)
  }

  disconnect(): void {
    this.shouldConnect = false
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer)
      this.reconnectTimer = null
    }
    this.ws?.close()
    this.ws = null
  }

  subscribe(handler: MessageHandler): () => void {
    this.handlers.add(handler)
    return () => this.handlers.delete(handler)
  }

  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN
  }
}

// Singleton
export const wsClient = new NetGuardWebSocket()
