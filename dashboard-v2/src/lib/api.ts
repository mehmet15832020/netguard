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
  Device,
  TopologyGraph,
  ScanState,
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

  getRefreshToken: (): string | null =>
    typeof window !== 'undefined' ? localStorage.getItem('ng_refresh_token') : null,

  setRefreshToken: (token: string) => localStorage.setItem('ng_refresh_token', token),

  removeToken: () => {
    localStorage.removeItem('ng_token')
    localStorage.removeItem('ng_refresh_token')
  },

  isLoggedIn: (): boolean => !!auth.getToken(),
}

// ------------------------------------------------------------------ //
//  Fetch wrapper
// ------------------------------------------------------------------ //

async function _fetchWithAuth(path: string, options: RequestInit, token: string | null) {
  return fetch(`${API}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...options.headers,
    },
  })
}

async function request<T>(
  path: string,
  options: RequestInit = {},
): Promise<T> {
  let res = await _fetchWithAuth(path, options, auth.getToken())

  if (res.status === 401) {
    const refreshToken = auth.getRefreshToken()
    if (refreshToken) {
      try {
        const refreshRes = await fetch(`${API}/auth/refresh`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ refresh_token: refreshToken }),
        })
        if (refreshRes.ok) {
          const data = await refreshRes.json()
          auth.setToken(data.access_token)
          auth.setRefreshToken(data.refresh_token)
          res = await _fetchWithAuth(path, options, data.access_token)
        }
      } catch {
        // refresh başarısız — logout
      }
    }
    if (res.status === 401) {
      auth.removeToken()
      window.location.href = '/login'
      throw new Error('Oturum süresi doldu')
    }
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
  login: async (
    username: string,
    password: string,
  ): Promise<{ access_token: string; refresh_token: string }> => {
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

  logout: () =>
    request<{ ok: boolean }>('/auth/logout', { method: 'POST' }),
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

  updateRules: (rules: CorrelationRule[]) =>
    request<{ saved: number; loaded: number }>('/correlation/rules', {
      method: 'PUT',
      body: JSON.stringify({ rules }),
    }),
}

// ------------------------------------------------------------------ //
//  SNMP
// ------------------------------------------------------------------ //

export interface SNMPInterface {
  index: string
  name: string
  oper_status: number
  hc_in_octets: number
  hc_out_octets: number
  in_errors: number
  out_errors: number
  in_discards: number
  bandwidth_in_bps: number
  bandwidth_out_bps: number
}

export interface SNMPDeviceInfo {
  host: string
  community: string
  sys_descr: string
  sys_name: string
  sys_object_id: string
  uptime_ticks: number
  interfaces: SNMPInterface[]
  reachable: boolean
  error: string
  polled_at: string | null
}

export interface SNMPPollParams {
  host: string
  community?: string
  snmp_version?: 'v2c' | 'v3'
  v3_username?: string
  v3_auth_protocol?: 'MD5' | 'SHA'
  v3_auth_key?: string
  v3_priv_protocol?: 'DES' | 'AES'
  v3_priv_key?: string
}

export const snmpApi = {
  poll: (params: SNMPPollParams) =>
    request<SNMPDeviceInfo>('/snmp/poll', {
      method: 'POST',
      body: JSON.stringify(params),
    }),
}

// ------------------------------------------------------------------ //
//  Devices
// ------------------------------------------------------------------ //

export const devicesApi = {
  list: (device_type?: string) => {
    const q = new URLSearchParams()
    if (device_type) q.set('device_type', device_type)
    return request<{ count: number; devices: Device[] }>(`/devices?${q}`)
  },

  get: (device_id: string) =>
    request<Device>(`/devices/${device_id}`),

  updateSnmp: (device_id: string, body: {
    community: string
    snmp_version: 'v2c' | 'v3'
    v3_username?: string
    v3_auth_protocol?: 'MD5' | 'SHA'
    v3_auth_key?: string
    v3_priv_protocol?: 'DES' | 'AES'
    v3_priv_key?: string
  }) =>
    request<{ ok: boolean; device_id: string }>(`/devices/${device_id}/snmp`, {
      method: 'PATCH',
      body: JSON.stringify(body),
    }),
}

// ------------------------------------------------------------------ //
//  Discovery
// ------------------------------------------------------------------ //

export const discoveryApi = {
  startScan: (cidr: string, community = 'public', fingerprint = true) =>
    request<{ scan_id: string; cidr: string; status: string }>('/discovery/scan', {
      method: 'POST',
      body: JSON.stringify({ cidr, community, fingerprint }),
    }),

  status: () =>
    request<ScanState>('/discovery/status'),

  results: (limit = 100) =>
    request<{ count: number; devices: Device[] }>(`/discovery/results?limit=${limit}`),
}

// ------------------------------------------------------------------ //
//  Topology
// ------------------------------------------------------------------ //

export const topologyApi = {
  graph: () =>
    request<TopologyGraph>('/topology/graph'),

  getGraph: () =>
    request<TopologyGraph>('/topology/graph'),

  refresh: () =>
    request<{ status: string; message: string }>('/topology/refresh', {
      method: 'POST',
    }),
}

// ------------------------------------------------------------------ //
//  Reports
// ------------------------------------------------------------------ //

export interface ReportSummary {
  generated_at: string
  devices: { total: number; by_type: Record<string, number>; by_status: Record<string, number> }
  alerts: { active: number; by_severity: Record<string, number> }
  security: { total: number; by_type: Record<string, number> }
  topology: { nodes: number; edges: number }
}

// ------------------------------------------------------------------ //
//  Maintenance
// ------------------------------------------------------------------ //

export interface MaintenanceStatus {
  table_counts: Record<string, number>
  retention_policy: {
    normalized_logs_days: number
    security_events_days: number
    correlated_events_days: number
    alerts_resolved_days: number
    archive_total_days: number
  }
  archive: {
    directory: string
    file_count: number
    total_size_mb: number
  }
}

export interface RetentionReport {
  started_at: string
  completed_at: string
  elapsed_seconds: number
  total_archived: number
  total_deleted: number
  purged_archives: number
  tables: Record<string, { archived?: number; deleted?: number; error?: string }>
}

export interface AuditEvent {
  id: number
  event_id: string
  actor: string
  action: string
  resource: string
  detail: string | null
  ip_address: string | null
  timestamp: string
}

export const maintenanceApi = {
  status: () =>
    request<MaintenanceStatus>('/maintenance/status'),

  cleanup: () =>
    request<RetentionReport>('/maintenance/cleanup', { method: 'POST' }),

  auditLog: (params?: { limit?: number; actor?: string }) => {
    const qs = new URLSearchParams()
    if (params?.limit)  qs.set('limit', String(params.limit))
    if (params?.actor)  qs.set('actor', params.actor)
    const q = qs.toString()
    return request<{ events: AuditEvent[] }>(`/maintenance/audit${q ? `?${q}` : ''}`)
  },
}

export interface ThreatIntel {
  ip: string
  score: number | null
  total_reports: number
  country_code: string
  isp: string
  queried_at: string
}

export const threatIntelApi = {
  lookup: (ip: string) =>
    request<ThreatIntel & { cached: boolean; message?: string }>(`/threat-intel/${encodeURIComponent(ip)}`),
}

export interface Incident {
  incident_id: string
  title: string
  description: string
  severity: string
  status: 'open' | 'investigating' | 'resolved'
  assigned_to: string | null
  source_event_id: string | null
  source_type: string | null
  created_by: string
  notes: string
  created_at: string
  updated_at: string
  resolved_at: string | null
}

export interface IncidentSummary {
  open: number
  investigating: number
  resolved: number
  total: number
}

export interface IncidentEvent {
  id: number
  incident_id: string
  event_id: string
  event_type: string
  severity: string
  message: string
  occurred_at: string
  added_at: string
}

export const incidentApi = {
  list: (params?: { status?: string; severity?: string; limit?: number }) => {
    const qs = new URLSearchParams()
    if (params?.status)   qs.set('status', params.status)
    if (params?.severity) qs.set('severity', params.severity)
    if (params?.limit)    qs.set('limit', String(params.limit))
    const q = qs.toString()
    return request<{ count: number; incidents: Incident[] }>(`/incidents${q ? `?${q}` : ''}`)
  },

  get: (id: string) =>
    request<Incident>(`/incidents/${id}`),

  summary: () =>
    request<IncidentSummary>('/incidents/summary'),

  create: (body: {
    title: string
    description?: string
    severity: string
    assigned_to?: string
    notes?: string
    source_event_id?: string
    source_type?: string
  }) => request<Incident>('/incidents', { method: 'POST', body: JSON.stringify(body) }),

  update: (id: string, body: {
    status?: string
    assigned_to?: string
    notes?: string
    title?: string
    description?: string
  }) => request<Incident>(`/incidents/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),

  delete: (id: string) =>
    request<void>(`/incidents/${id}`, { method: 'DELETE' }),

  getEvents: (id: string) =>
    request<{ incident_id: string; count: number; events: IncidentEvent[] }>(`/incidents/${id}/events`),
}

export const reportsApi = {
  summary: () =>
    request<ReportSummary>('/reports/summary'),

  download: async (type: 'devices' | 'alerts' | 'security' | 'topology') => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('ng_token') : ''
    const res = await fetch(`${API}/reports/${type}.csv`, {
      headers: { Authorization: `Bearer ${token ?? ''}` },
    })
    if (!res.ok) throw new Error(`Rapor indirilemedi: ${res.status}`)
    const blob = await res.blob()
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    const disp = res.headers.get('Content-Disposition') ?? ''
    const match = disp.match(/filename="([^"]+)"/)
    a.href     = url
    a.download = match?.[1] ?? `${type}.csv`
    a.click()
    URL.revokeObjectURL(url)
  },
}
