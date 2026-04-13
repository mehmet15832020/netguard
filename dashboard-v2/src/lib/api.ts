// NetGuard — API istemcisi
// Tüm backend iletişimi buradan geçer. Token yönetimi burada.

import type {
  Alert,
  Agent,
  MetricSnapshot,
  SecurityEvent,
  NormalizedLog,
  CorrelatedEvent,
  CorrelationRule,
} from '@/types/models'

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000'
const API = `${BASE_URL}/api/v1`

// ------------------------------------------------------------------ //
//  Token yönetimi
// ------------------------------------------------------------------ //

export const auth = {
  getToken: (): string | null =>
    typeof window !== 'undefined' ? localStorage.getItem('ng_token') : null,

  setToken: (token: string) => localStorage.setItem('ng_token', token),

  removeToken: () => localStorage.removeItem('ng_token'),

  isLoggedIn: (): boolean => !!auth.getToken(),
}

// ------------------------------------------------------------------ //
//  Fetch wrapper
// ------------------------------------------------------------------ //

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  const token = auth.getToken()

  const res = await fetch(`${API}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  })

  if (res.status === 401) {
    auth.removeToken()
    window.location.href = '/login'
    throw new Error('Oturum süresi doldu')
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(body.detail ?? 'Bilinmeyen hata')
  }

  return res.json() as Promise<T>
}

// ------------------------------------------------------------------ //
//  Auth
// ------------------------------------------------------------------ //

export const authApi = {
  login: async (username: string, password: string): Promise<{ access_token: string }> => {
    const res = await fetch(`${API}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({ detail: 'Giriş başarısız' }))
      throw new Error(body.detail)
    }
    return res.json()
  },
}

// ------------------------------------------------------------------ //
//  Agents
// ------------------------------------------------------------------ //

export const agentsApi = {
  list: () =>
    request<{ agents: Agent[] }>('/agents'),

  getLatestSnapshot: (agentId: string) =>
    request<MetricSnapshot>(`/agents/${agentId}/latest`),
}

// ------------------------------------------------------------------ //
//  Alerts
// ------------------------------------------------------------------ //

export const alertsApi = {
  list: (params?: { status?: string; limit?: number }) => {
    const q = new URLSearchParams()
    if (params?.status) q.set('status', params.status)
    if (params?.limit) q.set('limit', String(params.limit))
    return request<{ count: number; alerts: Alert[] }>(`/alerts?${q}`)
  },
}

// ------------------------------------------------------------------ //
//  Security Events
// ------------------------------------------------------------------ //

export const securityApi = {
  listEvents: (params?: { event_type?: string; source_ip?: string; limit?: number }) => {
    const q = new URLSearchParams()
    if (params?.event_type) q.set('event_type', params.event_type)
    if (params?.source_ip) q.set('source_ip', params.source_ip)
    if (params?.limit) q.set('limit', String(params.limit))
    return request<{ count: number; events: SecurityEvent[] }>(`/security/events?${q}`)
  },

  summary: () =>
    request<{ summary: Record<string, number> }>('/security/events/summary'),

  triggerScan: () =>
    request<{ scanned: boolean; events_found: Record<string, number> }>('/security/scan', {
      method: 'POST',
    }),
}

// ------------------------------------------------------------------ //
//  Normalized Logs
// ------------------------------------------------------------------ //

export const logsApi = {
  listNormalized: (params?: {
    source_type?: string
    category?: string
    src_ip?: string
    event_type?: string
    limit?: number
  }) => {
    const q = new URLSearchParams()
    if (params?.source_type) q.set('source_type', params.source_type)
    if (params?.category) q.set('category', params.category)
    if (params?.src_ip) q.set('src_ip', params.src_ip)
    if (params?.event_type) q.set('event_type', params.event_type)
    if (params?.limit) q.set('limit', String(params.limit))
    return request<{ count: number; logs: NormalizedLog[] }>(`/logs/normalized?${q}`)
  },

  ingest: (rawContent: string, sourceHost: string) =>
    request('/logs/ingest', {
      method: 'POST',
      body: JSON.stringify({ raw_content: rawContent, source_host: sourceHost }),
    }),
}

// ------------------------------------------------------------------ //
//  Correlation
// ------------------------------------------------------------------ //

export const correlationApi = {
  listEvents: (params?: { rule_id?: string; severity?: string; limit?: number }) => {
    const q = new URLSearchParams()
    if (params?.rule_id) q.set('rule_id', params.rule_id)
    if (params?.severity) q.set('severity', params.severity)
    if (params?.limit) q.set('limit', String(params.limit))
    return request<{ count: number; events: CorrelatedEvent[] }>(`/correlation/events?${q}`)
  },

  listRules: () =>
    request<{ count: number; rules: CorrelationRule[] }>('/correlation/rules'),

  runNow: () =>
    request<{ triggered: number; events: CorrelatedEvent[] }>('/correlation/run', {
      method: 'POST',
    }),

  reloadRules: () =>
    request<{ loaded: number; rules: string[] }>('/correlation/rules/reload', {
      method: 'POST',
    }),
}

// ------------------------------------------------------------------ //
//  SNMP
// ------------------------------------------------------------------ //

export interface SNMPDeviceInfo {
  host: string
  community: string
  sys_descr: string
  sys_name: string
  uptime_ticks: number
  if_in_octets: number
  if_out_octets: number
  if_oper_status: number
  reachable: boolean
  error: string
}

export const snmpApi = {
  poll: (host: string, community = 'public') =>
    request<SNMPDeviceInfo>('/snmp/poll', {
      method: 'POST',
      body: JSON.stringify({ host, community }),
    }),
}
