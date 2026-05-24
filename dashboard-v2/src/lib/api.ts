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
  TrafficSummary,
} from '@/types/models'

const BASE_URL = process.env.NEXT_PUBLIC_API_URL ?? ''
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

export interface Token {
  access_token:  string | null
  refresh_token: string | null
  token_type:    string
  expires_in:    number | null
  mfa_required:  boolean
  mfa_token:     string | null
}

export interface CurrentUser {
  username: string
  role: string
  tenant_id: string | null
  totp_enabled: boolean
}

export const authApi = {
  me: () =>
    request<CurrentUser>('/auth/me'),

  login: async (
    username: string,
    password: string,
  ): Promise<Token> => {
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

  totpSetup: () =>
    request<{ secret: string; otpauth_uri: string }>('/auth/totp-setup', { method: 'POST' }),

  totpConfirm: (code: string) =>
    request<{ enabled: boolean }>('/auth/totp-confirm', { method: 'POST', body: JSON.stringify({ code }) }),

  totpVerify: (mfa_token: string, code: string) =>
    request<Token>('/auth/totp-verify', { method: 'POST', body: JSON.stringify({ mfa_token, code }) }),

  totpDisable: () =>
    request<{ disabled: boolean }>('/auth/totp-disable', { method: 'POST' }),
}

// ------------------------------------------------------------------ //
//  Agents
// ------------------------------------------------------------------ //

export const agentsApi = {
  list: () =>
    request<{ agents: Agent[] }>('/agents'),

  getLatestSnapshot: (agentId: string) =>
    request<MetricSnapshot>(`/agents/${agentId}/latest`),

  trafficSummary: (agentId: string) =>
    request<TrafficSummary>(`/agents/${encodeURIComponent(agentId)}/traffic`),
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
  resolveAll: () =>
    request<{ resolved: number }>('/alerts/resolve-all', { method: 'POST' }),
}

// ------------------------------------------------------------------ //
//  Security Events
// ------------------------------------------------------------------ //

export const securityApi = {
  listEvents: (params?: { event_action?: string; source_ip?: string; limit?: number }) => {
    const q = new URLSearchParams()
    if (params?.event_action) q.set('event_action', params.event_action)
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
    event_category?: string
    source_ip?: string
    event_action?: string
    limit?: number
  }) => {
    const q = new URLSearchParams()
    if (params?.source_type) q.set('source_type', params.source_type)
    if (params?.event_category) q.set('event_category', params.event_category)
    if (params?.source_ip) q.set('source_ip', params.source_ip)
    if (params?.event_action) q.set('event_action', params.event_action)
    if (params?.limit) q.set('limit', String(params.limit))
    return request<{ count: number; logs: NormalizedLog[] }>(`/logs/normalized?${q}`)
  },

  searchLogs: (params: {
    q: string
    source_type?: string
    event_category?: string
    severity?: string
    limit?: number
  }) => {
    const query = new URLSearchParams({ q: params.q })
    if (params.source_type) query.set('source_type', params.source_type)
    if (params.event_category)    query.set('event_category', params.event_category)
    if (params.severity)    query.set('severity', params.severity)
    if (params.limit)       query.set('limit', String(params.limit))
    return request<{ query: string; count: number; logs: NormalizedLog[] }>(
      `/logs/search?${query}`
    )
  },

  ingest: (rawContent: string, sourceHost: string) =>
    request('/logs/ingest', {
      method: 'POST',
      body: JSON.stringify({ raw_content: rawContent, observer_hostname: sourceHost }),
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

  alerts: (device_id: string, limit = 20) =>
    request<{ count: number; alerts: Alert[] }>(`/devices/${encodeURIComponent(device_id)}/alerts?limit=${limit}`),

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

export interface IncidentRelatedLog {
  log_id: string
  timestamp: string
  event_action: string
  severity: string
  source_type: string
  source_ip: string | null
  source_hostname: string | null
  destination_ip: string | null
  message: string
}

export interface IncidentThreatIntel {
  score: number
  total_reports: number
  country_code: string
  isp: string
}

export interface IncidentEnrichment {
  mitre_techniques: string[]
  mitre_tactics: string[]
  related_logs: IncidentRelatedLog[]
  threat_intel: IncidentThreatIntel | null
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
  priority_score: number
  closure_note: string
  created_at: string
  updated_at: string
  resolved_at: string | null
  acknowledged_at: string | null
  enrichment?: IncidentEnrichment
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
  event_action: string
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
    closure_note?: string
  }) => request<Incident>(`/incidents/${id}`, { method: 'PATCH', body: JSON.stringify(body) }),

  delete: (id: string) =>
    request<void>(`/incidents/${id}`, { method: 'DELETE' }),

  resolveAll: () =>
    request<{ resolved: number }>('/incidents/resolve-all', { method: 'POST' }),

  getEvents: (id: string) =>
    request<{ incident_id: string; count: number; events: IncidentEvent[] }>(`/incidents/${id}/events`),
}

export interface MitreTechniqueRule {
  rule_id: string
  rule_name: string
  severity: string
  mitre_techniques: string[]
  mitre_tactics: string[]
}

export interface MitreCoverage {
  tactics: Record<string, {
    label: string
    tactic_id: string
    techniques: string[]
    rule_count: number
  }>
  techniques: Record<string, string[]>
  total_rules_with_mitre: number
  total_techniques: number
}

export interface MitreActivity {
  tactics: Record<string, { count_24h: number; count_7d: number }>
}

export const mitreApi = {
  coverage:  () => request<MitreCoverage>('/mitre/coverage'),
  heatmap:   (days = 30) => request<Record<string, unknown>>(`/mitre/heatmap?days=${days}`),
  techniques: () => request<{ count: number; rules: MitreTechniqueRule[] }>('/mitre/techniques'),
  activity:  () => request<MitreActivity>('/mitre/activity'),
}

export interface ComplianceControl {
  control_id: string
  title: string
  framework: string
  event_category: string
  status: 'compliant' | 'partial' | 'gap'
  score: number
  evidence: string[]
  recommendations: string[]
}

export interface ComplianceReport {
  overall_score: number
  total_controls: number
  compliant: number
  partial: number
  gaps: number
  by_framework: Record<string, {
    score: number
    compliant: number
    partial: number
    gap: number
    total: number
  }>
  controls: ComplianceControl[]
}

export const complianceApi = {
  report: (framework = '') => {
    const q = framework ? `?framework=${encodeURIComponent(framework)}` : ''
    return request<ComplianceReport>(`/compliance/report${q}`)
  },
  summary: () => request<{
    pci_dss: { score: number; compliant: number; partial: number; gaps: number; total: number }
    iso_27001: { score: number; compliant: number; partial: number; gaps: number; total: number }
  }>('/compliance/summary'),
}

export interface SecurityStatus {
  risk_score:      number
  status:          'safe' | 'warning' | 'danger'
  label:           string
  critical_alerts: number
  open_incidents:  number
  corr_events_24h: number
  anomalies_24h:   number
  updated_at:      string
}

export const reportsApi = {
  securityStatus: () =>
    request<SecurityStatus>('/reports/security-status'),

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

export type MetricRange = '1h' | '6h' | '24h' | '7d'

export interface TimeSeries {
  t: string
  v: number
}

export interface AgentMetricsResponse {
  available: boolean
  agent_id: string
  range: MetricRange
  cpu?: TimeSeries[]
  memory?: TimeSeries[]
  net_in?: TimeSeries[]
  net_out?: TimeSeries[]
}

export interface LogVolumeResponse {
  range: MetricRange
  data: { t: string; c: number }[]
}

export const metricsApi = {
  agentMetrics: (agentId: string, range: MetricRange = '1h') =>
    request<AgentMetricsResponse>(`/metrics/agent/${encodeURIComponent(agentId)}?range=${range}`),

  logVolume: (range: MetricRange = '24h') =>
    request<LogVolumeResponse>(`/metrics/log-volume?range=${range}`),
}

export interface ActiveChain {
  source_ip:       string
  stages:       Record<string, number>
  stage_labels: Record<string, string>
  stage_count:  number
  severity:     string
  chain_type:   string
}

export interface ChainStats {
  active_ips:         number
  chains_24h:         number
  critical_24h:       number
  unique_ips_24h:     number
  stage_distribution: Record<string, number>
}

export const attackChainsApi = {
  active: () =>
    request<{ count: number; chains: ActiveChain[] }>('/attack-chains/active'),

  history: (limit = 50) =>
    request<{ count: number; events: CorrelatedEvent[] }>(`/attack-chains/history?limit=${limit}`),

  stats: () =>
    request<ChainStats>('/attack-chains/stats'),
}

export interface FPRule {
  fp_rule_id:       string
  event_action:     string | null
  source_ip:        string | null
  destination_ip:   string | null
  destination_port: string | null
  observer_hostname: string | null
  tenant_id:        string
  reason:           string
  created_by:       string
  created_at:       string
  expires_at:       string | null
  is_active:        boolean
  hit_count:        number
}

export interface FPRuleCreate {
  event_action?:     string
  source_ip?:        string
  destination_ip?:   string
  destination_port?: string
  reason:            string
  expires_in_days?:  number
}

export const fpRulesApi = {
  list: (activeOnly = false) =>
    request<FPRule[]>(`/fp-rules?active_only=${activeOnly}`),

  create: (data: FPRuleCreate) =>
    request<FPRule>('/fp-rules', { method: 'POST', body: JSON.stringify(data) }),

  deactivate: (id: string) =>
    request<{ ok: boolean }>(`/fp-rules/${id}`, { method: 'DELETE' }),
}

export interface AssetBaseline {
  source_ip:             string
  tenant_id:             string
  first_seen_at:         string
  last_seen_at:          string
  avg_events_per_hour:   number
  typical_ports:         number[]
  typical_destinations:  string[]
  typical_event_actions: string[]
  sample_hours:          number
  updated_at:            string
}

export const assetsApi = {
  baselines: (tenant_id = 'default') =>
    request<AssetBaseline[]>(`/assets/baselines?tenant_id=${tenant_id}`),

  refresh: (tenant_id = 'default') =>
    request<{ updated: number }>(`/assets/baselines/refresh?tenant_id=${tenant_id}`, { method: 'POST' }),
}

// ── Network Intelligence ──────────────────────────────────────────────────────

export interface NetworkIntelSummary {
  ja3_suspicious_count:   number
  ssl_anomaly_count:      number
  self_signed_cert_count: number
  ftp_sensitive_count:    number
  smtp_session_count:     number
  zeek_total_24h:         number
}

export interface NetworkIntelEvent {
  source_ip:        string | null
  destination_ip:   string | null
  message:          string
  timestamp:        string
  severity?:        string
  fingerprint_type?: 'ja4' | 'ja3'
}

export interface NetworkIntelResponse {
  hours:             number
  summary:           NetworkIntelSummary
  zeek_distribution: Record<string, number>
  ja3_suspicious:    NetworkIntelEvent[]
  ssl_anomalies:     NetworkIntelEvent[]
  self_signed_certs: NetworkIntelEvent[]
  ftp_sensitive:     NetworkIntelEvent[]
  smtp_sessions:     NetworkIntelEvent[]
  top_sources:       { ip: string; count: number }[]
  dns_top:           { query: string; count: number }[]
  timeline:          { t: string; v: number }[]
}

export const networkIntelApi = {
  get: (hours = 24) =>
    request<NetworkIntelResponse>(`/network/intelligence?hours=${hours}`),
}

// ------------------------------------------------------------------ //
//  Active Response (V1-9)
// ------------------------------------------------------------------ //

export interface BlockedIP {
  block_id: string
  ip: string
  reason: string
  blocked_at: string
  blocked_by: string
  is_active: number | boolean
  source_incident_id: string | null
  provider: string
  unblocked_at: string | null
  unblocked_by: string | null
  tenant_id: string
}

export interface PlaybookSuggestion {
  action: string
  ip: string
  reason: string
  incident_id: string
  already_blocked: boolean
}

export interface PlaybookResponse {
  incident_id: string
  suggestions: PlaybookSuggestion[]
}

export interface BlockListResponse {
  count: number
  blocks: BlockedIP[]
}

export interface BlockVerifyResponse {
  ok: boolean
  missing: string[]
  extra: string[]
  opnsense_up: boolean
  vyos_up: boolean
  db_count: number
  fw_count: number
}

export const activeResponse = {
  block: (params: {
    ip: string
    reason: string
    source_incident_id?: string
    destination_port?: number | null
    network_protocol?: string | null
    ttl_hours?: number | null
  }) =>
    request<{ success: boolean; provider: string; error?: string }>('/response/block', {
      method: 'POST',
      body: JSON.stringify(params),
    }),

  unblock: (ip: string) =>
    request<{ success: boolean; error?: string }>(`/response/block/${encodeURIComponent(ip)}`, {
      method: 'DELETE',
    }),

  listBlocks: () =>
    request<BlockListResponse>('/response/blocks'),

  playbook: (incident_id: string) =>
    request<PlaybookResponse>('/response/playbook', {
      method: 'POST',
      body: JSON.stringify({ incident_id }),
    }),

  verify: () =>
    request<BlockVerifyResponse>('/response/blocks/verify'),

  breakGlass: (ip: string, token: string) =>
    request<{ success: boolean; error?: string }>(`/response/break-glass/${encodeURIComponent(ip)}`, {
      method: 'DELETE',
      headers: { 'X-Break-Glass-Token': token },
    }),
}

// ── Analytics ─────────────────────────────────────────────────────────────────

export interface TopTalkersResponse {
  hours:            number
  top_sources:      { ip: string; count: number }[]
  top_destinations: { ip: string; count: number }[]
  top_dst_ports:    { port: number; count: number }[]
}

export interface AlertPoint {
  t: string
  v: number
}

export interface AlertVolumeResponse {
  hours:          number
  bucket_minutes: number
  series: {
    critical: AlertPoint[]
    high:     AlertPoint[]
    warning:  AlertPoint[]
    info:     AlertPoint[]
  }
}

export interface ProtocolItem {
  protocol: string
  count:    number
  pct:      number
}

export interface ProtocolDistributionResponse {
  hours:     number
  total:     number
  protocols: ProtocolItem[]
}

export interface TrafficPoint {
  t: string
  v: number
}

export interface TrafficVolumeResponse {
  hours:  number
  series: {
    east_west:  TrafficPoint[]
    ns_egress:  TrafficPoint[]
    ns_ingress: TrafficPoint[]
  }
}

export interface FailedAuthResponse {
  hours:        number
  total:        number
  top_sources:  { ip: string; count: number }[]
  hourly:       { t: string; v: number }[]
}

export interface DnsAnalysisResponse {
  hours:                    number
  top_queried_destinations: { ip: string; count: number }[]
  nxdomain_count:           number
  nxdomain_rate:            number
  hourly_volume:            { t: string; v: number }[]
  unique_destinations:      number
  high_entropy_count:       number
  long_query_count:         number
  anomaly_count:            number
}

export interface TlsFingerprintResponse {
  hours:            number
  top_fingerprints: { fingerprint: string; count: number }[]
  unique_count:     number
}

export interface BeaconingSummaryResponse {
  hours:      number
  detections: { source_ip: string; destination_ip: string; message: string; detected_at: string }[]
  total:      number
}

export interface EastWestMatrixRow {
  src: string
  dst: string
  count: number
}

export interface EastWestMatrixResponse {
  hours:        number
  rows:         EastWestMatrixRow[]
  max_count:    number
  unique_pairs: number
}

export interface ThreatSource {
  ip:              string
  count:           number
  last_seen:       string
  composite_score: number
  country_code:    string
  isp:             string
}

export interface ThreatSummaryResponse {
  hours:                number
  top_sources:          ThreatSource[]
  total_alerts:         number
  critical_count:       number
  high_risk_count:      number
  country_distribution: { country_code: string; ip_count: number }[]
}

export interface KillChainEvent {
  stage:       string
  label:       string
  occurred_at: string
}

export interface KillChainRow {
  source_ip:   string
  chain_type:  string
  stage_count: number
  events:      KillChainEvent[]
  first_seen:  string
  last_seen:   string
}

export interface KillChainTimelineResponse {
  hours:        number
  window_start: string
  window_end:   string
  rows:         KillChainRow[]
}

export const analyticsApi = {
  topTalkers: (hours = 24, limit = 10) =>
    request<TopTalkersResponse>(`/analytics/top-talkers?hours=${hours}&limit=${limit}`),

  alertVolume: (hours = 24) =>
    request<AlertVolumeResponse>(`/analytics/alert-volume?hours=${hours}`),

  protocolDistribution: (hours = 24) =>
    request<ProtocolDistributionResponse>(`/analytics/protocol-distribution?hours=${hours}`),

  trafficVolume: (hours = 24) =>
    request<TrafficVolumeResponse>(`/analytics/traffic-volume?hours=${hours}`),

  failedAuth: (hours = 24) =>
    request<FailedAuthResponse>(`/analytics/failed-auth?hours=${hours}`),

  dnsAnalysis: (hours = 24, limit = 20) =>
    request<DnsAnalysisResponse>(`/analytics/dns-analysis?hours=${hours}&limit=${limit}`),

  tlsFingerprints: (hours = 24, limit = 20) =>
    request<TlsFingerprintResponse>(`/analytics/tls-fingerprints?hours=${hours}&limit=${limit}`),

  beaconingSummary: (hours = 24) =>
    request<BeaconingSummaryResponse>(`/analytics/beaconing-summary?hours=${hours}`),

  threatSummary: (hours = 24, limit = 20) =>
    request<ThreatSummaryResponse>(`/analytics/threat-summary?hours=${hours}&limit=${limit}`),

  killChainTimeline: (hours = 24, limit = 20) =>
    request<KillChainTimelineResponse>(`/analytics/kill-chain-timeline?hours=${hours}&limit=${limit}`),

  eastWestMatrix: (hours = 24, limit = 20) =>
    request<EastWestMatrixResponse>(`/analytics/east-west-matrix?hours=${hours}&limit=${limit}`),
}

