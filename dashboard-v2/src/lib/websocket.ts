// NetGuard — WebSocket istemcisi
// Singleton pattern: uygulama boyunca tek bağlantı.
// Auth: bağlantı sonrası JSON mesajı — token URL'de asla gönderilmez (RFC 6750 §5.3)

import { auth } from '@/lib/api'
import { useWsStore } from '@/store/wsStore'

const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? 'ws://localhost:8000'

export type WSMessageType = 'alert' | 'metric' | 'security_event' | 'correlated_event' | 'incident' | 'attack_chain' | 'ping' | 'log'

export interface WSMessage<T = unknown> {
  type: WSMessageType
  data: T
}

type MessageHandler = (msg: WSMessage) => void

class NetGuardWebSocket {
  private ws: WebSocket | null = null
  private handlers: Set<MessageHandler> = new Set()
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null
  private reconnectDelay = 2000
  private maxDelay = 30000
  private shouldConnect = false

  connect(): void {
    this.shouldConnect = true
    this._connect()
  }

  private _connect(): void {
    if (typeof window === 'undefined') return
    const state = this.ws?.readyState
    if (state === WebSocket.OPEN || state === WebSocket.CONNECTING) return

    try {
      this.ws = new WebSocket(`${WS_URL}/ws`)
    } catch {
      this._scheduleReconnect()
      return
    }

    this.ws.onopen = () => {
      console.log('[NetGuard WS] Bağlandı')
      this.reconnectDelay = 2000
      const token = auth.getToken()
      if (token) {
        this.ws!.send(JSON.stringify({ type: 'auth', token }))
      }
      this._startHeartbeat()
      useWsStore.getState().setConnected(true)
    }

    this.ws.onmessage = (event) => {
      try {
        const msg: WSMessage = JSON.parse(event.data)
        if ((msg.type as string) === 'pong') return
        this.handlers.forEach((h) => h(msg))
      } catch {
        // parse hatası — yoksay
      }
    }

    this.ws.onclose = (event) => {
      console.log('[NetGuard WS] Bağlantı kesildi', event.code)
      this._stopHeartbeat()
      useWsStore.getState().setConnected(false)
      if (event.code === 4401) {
        auth.refreshToken().then((ok) => {
          if (!ok) {
            auth.removeToken()
            window.location.href = '/login'
            return
          }
          if (this.shouldConnect) this._scheduleReconnect()
        })
        return
      }
      if (this.shouldConnect) this._scheduleReconnect()
    }

    this.ws.onerror = () => {
      this.ws?.close()
    }
  }

  private _startHeartbeat(): void {
    this._stopHeartbeat()
    this.heartbeatTimer = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send('{"type":"ping"}')
      }
    }, 30_000)
  }

  private _stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer)
      this.heartbeatTimer = null
    }
  }

  private _scheduleReconnect(): void {
    if (this.reconnectTimer) return
    // ±30% jitter — Thundering Herd önlemi
    const jitter = 1 + (Math.random() * 0.6 - 0.3)
    const delay = Math.min(this.reconnectDelay * jitter, this.maxDelay)
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null
      this._connect()
      this.reconnectDelay = Math.min(this.reconnectDelay * 2, this.maxDelay)
    }, delay)
  }

  disconnect(): void {
    this.shouldConnect = false
    this._stopHeartbeat()
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
