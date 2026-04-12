// NetGuard — Tüm domain modelleri
// Bu tipler backend shared/models.py ile birebir eşleşir

export type Severity = 'info' | 'warning' | 'critical'
export type AlertStatus = 'active' | 'resolved'
export type LogCategory = 'authentication' | 'network' | 'intrusion' | 'system' | 'unknown'
export type LogSourceType = 'suricata' | 'zeek' | 'wazuh' | 'syslog' | 'auth_log' | 'netguard'

// ------------------------------------------------------------------ //
//  Metrik modelleri
// ------------------------------------------------------------------ //

export interface CPUMetrics {
  usage_percent: number
  core_count: number
  load_avg_1m: number
}

export interface MemoryMetrics {
  total_bytes: number
  used_bytes: number
  available_bytes: number
  usage_percent: number
}

export interface DiskMetrics {
  mount_point: string
  total_bytes: number
  used_bytes: number
  free_bytes: number
  usage_percent: number
}

export interface NetworkBandwidth {
  interface_name: string
  bytes_sent_per_sec: number
  bytes_recv_per_sec: number
  packets_sent_per_sec: number
  packets_recv_per_sec: number
}

export interface MetricSnapshot {
  agent_id: string
  hostname: string
  collected_at: string
  status: 'online' | 'degraded' | 'offline'
  cpu: CPUMetrics
  memory: MemoryMetrics
  disks: DiskMetrics[]
  network_interfaces: NetworkBandwidth[]
}

export interface Agent {
  agent_id: string
  hostname: string
  os_name: string
  os_version: string
  registered_at: string
}

// ------------------------------------------------------------------ //
//  Alert
// ------------------------------------------------------------------ //

export interface Alert {
  alert_id: string
  agent_id: string
  hostname: string
  severity: Severity
  status: AlertStatus
  metric: string
  message: string
  value: number
  threshold: number
  triggered_at: string
  resolved_at: string | null
}

// ------------------------------------------------------------------ //
//  Güvenlik olayları
// ------------------------------------------------------------------ //

export type SecurityEventType =
  | 'brute_force'
  | 'ssh_failure'
  | 'ssh_success'
  | 'sudo_usage'
  | 'port_opened'
  | 'port_closed'
  | 'checksum_changed'

export interface SecurityEvent {
  event_id: string
  agent_id: string
  hostname: string
  event_type: SecurityEventType
  severity: Severity
  source_ip: string | null
  username: string | null
  message: string
  raw_data: string | null
  occurred_at: string
  created_at: string
}

// ------------------------------------------------------------------ //
//  Log normalizasyon
// ------------------------------------------------------------------ //

export interface NormalizedLog {
  log_id: string
  raw_id: string
  source_type: LogSourceType
  source_host: string
  timestamp: string
  severity: Severity
  category: LogCategory
  event_type: string
  src_ip: string | null
  dst_ip: string | null
  src_port: number | null
  dst_port: number | null
  username: string | null
  message: string
  tags: string[]
  processed_at: string
}

// ------------------------------------------------------------------ //
//  Korelasyon
// ------------------------------------------------------------------ //

export interface CorrelatedEvent {
  corr_id: string
  rule_id: string
  rule_name: string
  event_type: string
  severity: Severity
  group_value: string
  matched_count: number
  window_seconds: number
  first_seen: string
  last_seen: string
  message: string
  created_at: string
}

export interface CorrelationRule {
  rule_id: string
  name: string
  description: string
  match_event_type: string
  group_by: string
  window_seconds: number
  threshold: number
  severity: Severity
  output_event_type: string
}

// ------------------------------------------------------------------ //
//  API response sarmalayıcılar
// ------------------------------------------------------------------ //

export interface PaginatedResponse<T> {
  count: number
  items: T[]
}

export interface ApiError {
  detail: string
  status: number
}
