'use client'

import Link from 'next/link'
import {
  Bell, Server, Shield, GitMerge, Share2, ChevronRight,
  AlertTriangle, Activity, Swords, ShieldAlert, Zap, Clock,
  CheckCircle2, Globe, Radio, Wifi,
} from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import ReactECharts from 'echarts-for-react'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { useAgents, useLatestSnapshot } from '@/hooks/useMetrics'
import { useAlerts } from '@/hooks/useAlerts'
import {
  securityApi, correlationApi, reportsApi, analyticsApi,
  attackChainsApi, incidentApi, anomalyApi, healthApi,
  type SourceHealthItem, type SensorHealthResponse,
} from '@/lib/api'
import type {
  AlertVolumeResponse, AssetRiskEntry,
  FailedAuthResponse, DnsAnalysisResponse,
  ThreatSummaryResponse, TrafficVolumeResponse,
  ProtocolDistributionResponse,
} from '@/lib/api'
import { MiniTopology } from '@/components/topology/MiniTopology'
import { Skeleton } from '@/components/ui/skeleton'
import { StatCard, KpiCard } from '@/components/ui/stat-card'
import type { Severity } from '@/types/models'
import { cn } from '@/lib/utils'

// ─────────────────────────────────────────────
//  Constants
// ─────────────────────────────────────────────

const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  high:     'bg-orange-500',
  warning:  'bg-yellow-500',
  info:     'bg-blue-500',
}

const TACTIC_COLORS: Record<string, string> = {
  reconnaissance:         'bg-blue-900/50 text-blue-400',
  'initial-access':       'bg-yellow-900/50 text-yellow-400',
  execution:              'bg-orange-900/50 text-orange-400',
  persistence:            'bg-orange-900/50 text-orange-400',
  'privilege-escalation': 'bg-red-900/50 text-red-400',
  'defense-evasion':      'bg-purple-900/50 text-purple-400',
  'credential-access':    'bg-red-900/50 text-red-400',
  discovery:              'bg-blue-900/50 text-blue-400',
  'lateral-movement':     'bg-rose-900/50 text-rose-400',
  collection:             'bg-amber-900/50 text-amber-400',
  'command-and-control':  'bg-red-900/50 text-red-400',
  exfiltration:           'bg-red-900/50 text-red-400',
  impact:                 'bg-red-900/50 text-red-400',
}

const PROTO_COLORS = ['#38bdf8', '#6366f1', '#10b981', '#f59e0b', '#f43f5e', '#8b5cf6', '#06b6d4']

// ─────────────────────────────────────────────
//  Shared primitives
// ─────────────────────────────────────────────

function SectionLabel({ label, icon: Icon }: { label: string; icon?: React.ElementType }) {
  return (
    <div className="col-span-12 flex items-center gap-2 -mt-1 -mb-1">
      {Icon && <Icon size={10} className="text-sky-900/50 flex-shrink-0" />}
      <span className="text-[9px] font-semibold text-sky-900/50 uppercase tracking-[0.2em]">{label}</span>
      <div className="flex-1 h-px bg-gradient-to-r from-sky-900/25 to-transparent" />
    </div>
  )
}

function Panel({ title, icon: Icon, href, children, className }: {
  title: string; icon: React.ElementType; href?: string
  children: React.ReactNode; className?: string
}) {
  return (
    <div className={cn('bg-[#0d1526] border border-sky-900/25 rounded-lg overflow-hidden hover:border-sky-800/35 transition-colors', className)}>
      <div className="ui-panel-header justify-between">
        <div className="flex items-center gap-2">
          <Icon size={13} className="text-sky-700" />
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wide">{title}</span>
        </div>
        {href && (
          <Link href={href} className="text-[11px] text-sky-600 hover:text-sky-400 transition-colors font-medium">
            Tümü →
          </Link>
        )}
      </div>
      {children}
    </div>
  )
}

function Empty({ text }: { text: string }) {
  return <div className="flex items-center justify-center py-8 text-slate-600 text-sm">{text}</div>
}

// ─────────────────────────────────────────────
//  Security Status Banner
// ─────────────────────────────────────────────

function RiskGauge({ score }: { score: number }) {
  const pct = Math.min(100, Math.max(0, score))
  const color = pct === 0 ? 'bg-emerald-500' : pct <= 25 ? 'bg-sky-400' : pct <= 55 ? 'bg-yellow-500' : pct <= 80 ? 'bg-orange-500' : 'bg-red-500'
  return (
    <div className="w-full mt-2">
      <div className="flex items-center justify-between mb-1">
        <span className="text-[11px] text-slate-600">0</span>
        <span className="text-[11px] text-slate-600">100</span>
      </div>
      <div className="h-2 bg-slate-800/60 rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full transition-all duration-700', color)} style={{ width: `${pct}%` }} />
      </div>
    </div>
  )
}

function SecurityStatusBanner() {
  const { data } = useQuery({
    queryKey: ['security-status'],
    queryFn:  () => reportsApi.securityStatus(),
    refetchInterval: 30_000,
  })
  if (!data) return null
  const cfg = ({
    safe:     { border: 'border-emerald-500/30', bg: 'bg-emerald-500/10',  text: 'text-emerald-400', dot: 'bg-emerald-500', accent: 'from-emerald-500/60 to-emerald-500/0', glow: 'shadow-emerald-900/30' },
    low:      { border: 'border-sky-500/30',     bg: 'bg-sky-500/10',      text: 'text-sky-400',     dot: 'bg-sky-400',     accent: 'from-sky-500/60 to-sky-500/0',         glow: 'shadow-sky-900/30' },
    warning:  { border: 'border-yellow-500/30',  bg: 'bg-yellow-500/10',   text: 'text-yellow-400',  dot: 'bg-yellow-500',  accent: 'from-yellow-500/60 to-yellow-500/0',   glow: 'shadow-yellow-900/30' },
    elevated: { border: 'border-orange-500/30',  bg: 'bg-orange-500/10',   text: 'text-orange-400',  dot: 'bg-orange-500',  accent: 'from-orange-500/60 to-orange-500/0',   glow: 'shadow-orange-900/30' },
    danger:   { border: 'border-red-500/40',     bg: 'bg-red-500/10',      text: 'text-red-400',     dot: 'bg-red-500',     accent: 'from-red-500/60 to-red-500/0',         glow: 'shadow-red-900/30' },
  } as Record<string, { border: string; bg: string; text: string; dot: string; accent: string; glow: string }>)[data.status]
    ?? { border: 'border-slate-500/30', bg: 'bg-slate-500/10', text: 'text-slate-400', dot: 'bg-slate-500', accent: 'from-slate-500/60 to-slate-500/0', glow: 'shadow-slate-900/30' }

  return (
    <div className={cn('relative rounded-lg border overflow-hidden p-4 flex items-center gap-6 shadow-lg', cfg.border, cfg.bg, cfg.glow)}>
      {/* gradient accent top bar */}
      <div className={cn('absolute inset-x-0 top-0 h-[2px] bg-gradient-to-r', cfg.accent)} />
      <div className="flex items-center gap-5 flex-shrink-0">
        <div className="text-center">
          <p className={cn('text-6xl font-bold tabular-nums leading-none', cfg.text)}>{data.risk_score}</p>
          <p className="text-[10px] text-slate-500 mt-1.5 uppercase tracking-widest">Risk Skoru</p>
        </div>
        <div className="w-px h-14 bg-sky-900/40" />
        <div>
          <div className="flex items-center gap-2">
            <span className={cn('w-2.5 h-2.5 rounded-full flex-shrink-0 animate-pulse', cfg.dot)} />
            <span className={cn('text-xl font-bold', cfg.text)}>{data.label}</span>
          </div>
          <p className="text-[11px] text-slate-500 mt-1.5">
            {new Date(data.updated_at).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })} güncellendi
          </p>
        </div>
      </div>
      <div className="flex-1 hidden sm:block"><RiskGauge score={data.risk_score} /></div>
      <div className="hidden md:flex items-center gap-6 flex-shrink-0 text-center">
        {[
          { label: 'Kritik Alert',   value: data.critical_alerts,  href: '/alerts',      color: data.critical_alerts  > 0 ? 'text-red-400'    : 'text-slate-400' },
          { label: 'Açık Incident',  value: data.open_incidents,   href: '/incidents',   color: data.open_incidents   > 0 ? 'text-orange-400' : 'text-slate-400' },
          { label: 'Korelasyon 24s', value: data.corr_events_24h,  href: '/correlation', color: data.corr_events_24h  > 0 ? 'text-yellow-400' : 'text-slate-400' },
          { label: 'Anomali 24s',    value: data.anomalies_24h,    href: '/anomaly',     color: data.anomalies_24h    > 0 ? 'text-yellow-400' : 'text-slate-400' },
        ].map(({ label, value, href, color }) => (
          <Link key={label} href={href} className="hover:opacity-80 transition-opacity group">
            <p className={cn('text-4xl font-bold leading-none tabular-nums', color)}>{value}</p>
            <p className="text-[10px] text-slate-600 mt-1 whitespace-nowrap group-hover:text-slate-500 transition-colors">{label}</p>
          </Link>
        ))}
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────
//  Row 2 — Attack Chain + Incident KPIs
// ─────────────────────────────────────────────

function AttackChainKpis() {
  const { data } = useQuery({
    queryKey: ['attack-chain-stats'],
    queryFn:  attackChainsApi.stats,
    refetchInterval: 60_000,
    staleTime: 30_000,
  })
  return (
    <>
      <KpiCard label="Aktif Saldırı IP"  value={data?.active_ips    ?? '—'} icon={Swords}        valueCls={data && data.active_ips   > 0 ? 'text-red-400'    : undefined} href="/timeline" />
      <KpiCard label="Zincir 24s"         value={data?.chains_24h    ?? '—'} icon={Swords}        valueCls={data && data.chains_24h   > 0 ? 'text-orange-400' : undefined} href="/timeline" />
      <KpiCard label="Kritik Zincir 24s"  value={data?.critical_24h  ?? '—'} icon={AlertTriangle} valueCls={data && data.critical_24h > 0 ? 'text-red-400'    : undefined} href="/timeline" />
    </>
  )
}

function IncidentKpis() {
  const { data } = useQuery({
    queryKey: ['incident-summary-overview'],
    queryFn:  incidentApi.summary,
    refetchInterval: 60_000,
    staleTime: 30_000,
  })
  return (
    <>
      <KpiCard label="Açık Incident"     value={data?.open          ?? '—'} icon={AlertTriangle} valueCls={data && data.open          > 0 ? 'text-red-400'    : undefined} href="/incidents" />
      <KpiCard label="İnceleniyor"       value={data?.investigating  ?? '—'} icon={Activity}      valueCls={data && data.investigating > 0 ? 'text-yellow-400' : undefined} href="/incidents" />
      <KpiCard label="Çözüldü (Toplam)"  value={data?.resolved       ?? '—'} icon={CheckCircle2}  valueCls="text-emerald-400"                                               href="/incidents" sub={data ? `${data.total} toplam` : undefined} />
    </>
  )
}

// ─────────────────────────────────────────────
//  Row 3 — MTTD / MTTR
// ─────────────────────────────────────────────

function MttdRow() {
  const { data } = useQuery({
    queryKey: ['mttd-mttr-overview'],
    queryFn:  () => analyticsApi.mttdMttr(7),
    refetchInterval: 300_000,
    staleTime: 120_000,
  })
  const fmt = (min: number | null) => {
    if (min === null) return '—'
    return min < 60 ? `${Math.round(min)}dk` : `${(min / 60).toFixed(1)}s`
  }
  const rate = data?.resolution_rate ?? null
  return (
    <div className="grid grid-cols-3 gap-3">
      <div className="bg-[#0d1526] border border-sky-900/25 rounded-lg p-4 flex items-start gap-3">
        <div className="w-8 h-8 rounded-md bg-blue-500/10 flex items-center justify-center flex-shrink-0"><Clock size={14} className="text-blue-400" /></div>
        <div className="min-w-0">
          <p className="text-[11px] text-slate-500 uppercase tracking-wide">Ort. Tespit Süresi</p>
          <p className="text-3xl font-bold leading-none tabular-nums text-blue-400 mt-1">{fmt(data?.overall_mttd_minutes ?? null)}</p>
          <p className="text-[11px] text-slate-600 mt-0.5">MTTD · Son 7 gün</p>
        </div>
      </div>
      <div className="bg-[#0d1526] border border-sky-900/25 rounded-lg p-4 flex items-start gap-3">
        <div className="w-8 h-8 rounded-md bg-orange-500/10 flex items-center justify-center flex-shrink-0"><Activity size={14} className="text-orange-400" /></div>
        <div className="min-w-0">
          <p className="text-[11px] text-slate-500 uppercase tracking-wide">Ort. Yanıt Süresi</p>
          <p className="text-3xl font-bold leading-none tabular-nums text-orange-400 mt-1">{fmt(data?.overall_mttr_minutes ?? null)}</p>
          <p className="text-[11px] text-slate-600 mt-0.5">MTTR · Son 7 gün</p>
        </div>
      </div>
      <div className="bg-[#0d1526] border border-sky-900/25 rounded-lg p-4 flex items-start gap-3">
        <div className={cn('w-8 h-8 rounded-md flex items-center justify-center flex-shrink-0', rate === null ? 'bg-[#0f1c30]' : rate >= 80 ? 'bg-emerald-500/10' : 'bg-yellow-500/10')}>
          <CheckCircle2 size={14} className={rate === null ? 'text-slate-600' : rate >= 80 ? 'text-emerald-400' : 'text-yellow-400'} />
        </div>
        <div className="min-w-0">
          <p className="text-[11px] text-slate-500 uppercase tracking-wide">Çözüm Oranı</p>
          <p className={cn('text-3xl font-bold leading-none tabular-nums mt-1', rate === null ? 'text-slate-500' : rate >= 80 ? 'text-emerald-400' : 'text-yellow-400')}>
            {rate !== null ? `${rate.toFixed(0)}%` : '—'}
          </p>
          <p className="text-[11px] text-slate-600 mt-0.5">
            {data ? `${data.resolved_incidents} / ${data.total_incidents} incident` : 'Son 7 gün'}
          </p>
        </div>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────
//  Row 4 — Topology + Kill Chain
// ─────────────────────────────────────────────

function AgentRow({ agent }: { agent: { agent_id: string; hostname: string; os: string; last_seen: string } }) {
  const { snapshot } = useLatestSnapshot(agent.agent_id)
  const isOnline = Date.now() - new Date(agent.last_seen).getTime() < 60_000
  const pct = (val: number | null, warn = 70, crit = 90) => {
    if (val === null) return <span className="text-slate-600">—</span>
    const c = val >= crit ? 'text-red-400' : val >= warn ? 'text-yellow-400' : 'text-slate-400'
    return <span className={`font-mono text-xs ${c}`}>{val.toFixed(0)}%</span>
  }
  return (
    <Link href={`/agents/${agent.agent_id}`} className="flex items-center gap-3 px-4 py-2.5 hover:bg-sky-950/20 transition-colors border-b border-sky-900/15 last:border-0">
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${isOnline ? 'bg-emerald-500' : 'bg-slate-700'}`} />
      <span className="text-sm text-slate-300 flex-1 truncate font-medium">{agent.hostname}</span>
      <div className="flex items-center gap-4">
        <div className="text-right"><p className="text-[10px] text-slate-600 mb-0.5">CPU</p>{pct(snapshot?.cpu.usage_percent ?? null)}</div>
        <div className="text-right"><p className="text-[10px] text-slate-600 mb-0.5">RAM</p>{pct(snapshot?.memory.usage_percent ?? null)}</div>
      </div>
      <ChevronRight size={13} className="text-slate-600 flex-shrink-0" />
    </Link>
  )
}

// ─────────────────────────────────────────────
//  Row 5 — Failed Auth | DNS | Anomaly
// ─────────────────────────────────────────────

function sparklineOption(data: { t: string; v: number }[], color: string) {
  return {
    backgroundColor: 'transparent',
    grid: { top: 4, right: 4, bottom: 4, left: 4 },
    xAxis: { type: 'category', show: false, data: data.map(d => d.t) },
    yAxis: { type: 'value', show: false },
    series: [{
      type: 'line',
      data: data.map(d => d.v),
      smooth: 0.4,
      symbol: 'none',
      lineStyle: { color, width: 2 },
      areaStyle: { color: color + '22' },
    }],
  }
}

function FailedAuthPanel({ data }: { data: FailedAuthResponse | undefined }) {
  const hasSparkline = (data?.hourly ?? []).length > 1
  const top = data?.top_sources?.[0]
  return (
    <Panel title="Başarısız Auth (24s)" icon={Bell} href="/failed-auth">
      <div className="p-4 space-y-3">
        <div className="flex items-end justify-between">
          <div>
            <p className={cn('text-3xl font-bold tabular-nums', (data?.total ?? 0) > 0 ? 'text-orange-400' : 'text-slate-300')}>
              {data?.total ?? '—'}
            </p>
            <p className="text-[11px] text-slate-500 mt-0.5">Toplam başarısız giriş</p>
          </div>
          {top && (
            <div className="text-right">
              <p className="text-[10px] text-slate-500 mb-0.5">En aktif kaynak</p>
              <p className="text-xs font-mono text-orange-300">{top.ip}</p>
              <p className="text-[10px] text-slate-600">{top.count} deneme</p>
            </div>
          )}
        </div>
        {hasSparkline ? (
          <ReactECharts option={sparklineOption(data!.hourly, '#f97316')} notMerge style={{ height: 64 }} />
        ) : (
          <div className="h-16 flex items-center justify-center text-slate-600 text-xs">Yeterli veri yok</div>
        )}
      </div>
    </Panel>
  )
}

function DnsAnomalyPanel({ data }: { data: DnsAnalysisResponse | undefined }) {
  const rows = [
    { label: 'NXDOMAIN Oranı',       value: data ? `${(data.nxdomain_rate * 100).toFixed(1)}%` : '—', alert: (data?.nxdomain_rate ?? 0) > 0.15 },
    { label: 'Yüksek Entropi Sorgu', value: data?.high_entropy_count ?? '—',                            alert: (data?.high_entropy_count ?? 0) > 0 },
    { label: 'Uzun Sorgu',            value: data?.long_query_count ?? '—',                              alert: (data?.long_query_count ?? 0) > 0 },
    { label: 'Anomali Tespiti',       value: data?.anomaly_count ?? '—',                                alert: (data?.anomaly_count ?? 0) > 0 },
    { label: 'Benzersiz Hedef',       value: data?.unique_destinations ?? '—',                          alert: false },
  ]
  return (
    <Panel title="DNS Anomali (24s)" icon={Globe} href="/dns-analysis">
      <div className="divide-y divide-sky-900/20">
        {rows.map(r => (
          <div key={r.label} className="flex items-center justify-between px-4 py-2.5">
            <span className="text-xs text-slate-500">{r.label}</span>
            <span className={cn('text-xs font-mono font-semibold', r.alert ? 'text-yellow-400' : 'text-slate-300')}>{String(r.value)}</span>
          </div>
        ))}
      </div>
    </Panel>
  )
}

function AnomalyPanel() {
  const { data } = useQuery({
    queryKey: ['anomaly-summary-overview'],
    queryFn:  () => anomalyApi.summary(24),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })
  const bars = [
    { label: 'Kritik', value: data?.critical ?? 0,  color: 'bg-red-500',    text: 'text-red-400' },
    { label: 'Yüksek', value: data?.high ?? 0,      color: 'bg-orange-500', text: 'text-orange-400' },
    { label: 'Uyarı',  value: data?.warning ?? 0,   color: 'bg-yellow-500', text: 'text-yellow-400' },
  ]
  const max = Math.max(1, ...bars.map(b => b.value))
  return (
    <Panel title="Anomali Tespiti (24s)" icon={Activity} href="/anomaly">
      <div className="p-4 space-y-3">
        <div className="flex items-end justify-between">
          <div>
            <p className={cn('text-3xl font-bold tabular-nums', (data?.total ?? 0) > 0 ? 'text-sky-400' : 'text-slate-300')}>
              {data?.total ?? '—'}
            </p>
            <p className="text-[11px] text-slate-500 mt-0.5">Toplam anomali</p>
          </div>
          <div className="text-right">
            <p className="text-[10px] text-slate-500 mb-0.5">Etkilenen IP</p>
            <p className="text-lg font-bold text-sky-300">{data?.affected_entities ?? '—'}</p>
          </div>
        </div>
        <div className="space-y-2">
          {bars.map(b => (
            <div key={b.label} className="flex items-center gap-2">
              <span className={cn('text-[11px] w-12 flex-shrink-0', b.text)}>{b.label}</span>
              <div className="flex-1 h-1.5 bg-[#0f1c30] rounded-full overflow-hidden">
                <div className={cn('h-full rounded-full', b.color)} style={{ width: `${(b.value / max) * 100}%` }} />
              </div>
              <span className="text-[11px] font-mono text-slate-500 w-5 text-right">{b.value}</span>
            </div>
          ))}
        </div>
      </div>
    </Panel>
  )
}

// ─────────────────────────────────────────────
//  Sensor Health Panel (C4 — CIS Control 13.1)
// ─────────────────────────────────────────────

const STATUS_CFG = {
  ok:      { dot: 'bg-emerald-500', text: 'text-emerald-400', label: 'Normal' },
  warning: { dot: 'bg-yellow-500',  text: 'text-yellow-400',  label: 'Uyarı'  },
  critical:{ dot: 'bg-red-500',     text: 'text-red-400',     label: 'Kritik' },
  unknown: { dot: 'bg-slate-600',   text: 'text-slate-500',   label: 'Bilinmiyor' },
} as const

function SensorHealthPanel() {
  const { data, isLoading } = useQuery<SensorHealthResponse>({
    queryKey: ['sensor-health'],
    queryFn:  healthApi.sensors,
    refetchInterval: 30_000,
    staleTime: 15_000,
  })

  const overall = data?.overall ?? 'unknown'
  const cfg = STATUS_CFG[overall]

  const sensors = data ? [
    { key: 'zeek',     label: 'Zeek',     ...data.sensors.zeek },
    { key: 'suricata', label: 'Suricata', ...data.sensors.suricata },
  ] : []

  return (
    <Panel title="Sensör Sağlığı" icon={Radio}>
      {isLoading ? (
        <div className="p-4 space-y-2">
          {[0, 1, 2].map(i => <Skeleton key={i} style={{ height: 20 }} className="w-full" />)}
        </div>
      ) : (
        <div className="p-4 space-y-3">
          <div className="flex items-center gap-2">
            <span className={cn('w-2 h-2 rounded-full flex-shrink-0', cfg.dot, overall !== 'ok' && overall !== 'unknown' ? 'animate-pulse' : '')} />
            <span className={cn('text-sm font-semibold', cfg.text)}>{cfg.label}</span>
            {data?.timestamp && (
              <span className="ml-auto text-[10px] text-slate-600">
                {new Date(data.timestamp).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })}
              </span>
            )}
          </div>
          <div className="space-y-2 pt-1">
            {sensors.map(s => {
              const sc = STATUS_CFG[s.status as keyof typeof STATUS_CFG] ?? STATUS_CFG.unknown
              return (
                <div key={s.key} className="flex items-center gap-2">
                  <span className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0', sc.dot)} />
                  <span className="text-[11px] text-slate-400 w-16">{s.label}</span>
                  {s.drop_rate !== null ? (
                    <span className={cn('text-[11px] font-mono', sc.text)}>
                      {(s.drop_rate * 100).toFixed(1)}% kayıp
                    </span>
                  ) : (
                    <span className="text-[11px] text-slate-600">{s.error ? 'Erişilemiyor' : '—'}</span>
                  )}
                  <span className={cn('ml-auto text-[10px] font-semibold px-1.5 py-0.5 rounded')}>
                    <span className={sc.text}>{sc.label}</span>
                  </span>
                </div>
              )
            })}
          </div>
          {(data?.interfaces ?? []).length > 0 && (
            <div className="pt-1 border-t border-sky-900/20">
              <p className="text-[10px] text-slate-600 mb-1.5 uppercase tracking-wide">Arayüzler</p>
              {data!.interfaces.slice(0, 3).map(ifc => {
                const ic = STATUS_CFG[ifc.status] ?? STATUS_CFG.unknown
                return (
                  <div key={ifc.interface} className="flex items-center gap-1.5 mb-1">
                    <span className={cn('w-1 h-1 rounded-full flex-shrink-0', ic.dot)} />
                    <span className="text-[11px] text-slate-500 font-mono">{ifc.interface}</span>
                    <span className={cn('text-[11px] ml-auto', ic.text)}>{(ifc.drop_rate * 100).toFixed(1)}%</span>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}
    </Panel>
  )
}

// ─────────────────────────────────────────────
//  Data Freshness Bar (Security Onion model)
// ─────────────────────────────────────────────

const SOURCE_LABEL: Record<string, string> = {
  syslog: 'Syslog', netflow: 'NetFlow', zeek: 'Zeek', suricata: 'Suricata',
  agent: 'Agent', snmp: 'SNMP', evtx: 'EVTX', auth_log: 'Auth',
  opnsense: 'OPNsense', vyos: 'VyOS',
}

function FreshnessChip({ item }: { item: SourceHealthItem }) {
  const label = SOURCE_LABEL[item.source_type] ?? item.source_type
  const age = item.age_minutes
  let dot = 'bg-emerald-500'
  let text = 'text-slate-400'
  let title = age !== null ? `${age.toFixed(0)} dk önce` : 'Bilinmiyor'
  if (item.stale || age === null) { dot = 'bg-red-500'; text = 'text-red-400' }
  else if (age > 5) { dot = 'bg-yellow-500'; text = 'text-yellow-400' }
  return (
    <div className="flex items-center gap-1.5 px-2 py-1 rounded-md bg-[#0a1120] border border-sky-900/30" title={title}>
      <span className={cn('w-1.5 h-1.5 rounded-full flex-shrink-0', dot)} />
      <span className={cn('text-[11px] font-medium', text)}>{label}</span>
      {age !== null && <span className="text-[10px] text-slate-600">{age < 1 ? '<1dk' : `${age.toFixed(0)}dk`}</span>}
    </div>
  )
}

function DataFreshnessBar() {
  const { data } = useQuery({
    queryKey: ['source-health'],
    queryFn:  analyticsApi.sourceHealth,
    refetchInterval: 60_000,
    staleTime: 30_000,
  })
  if (!data || data.sources.length === 0) return null
  const staleCount = data.sources.filter(s => s.stale).length
  return (
    <div className="bg-[#0d1526] border border-sky-900/25 rounded-lg px-4 py-2.5">
      <div className="flex items-center gap-3 flex-wrap">
        <span className="text-[11px] text-slate-500 uppercase tracking-wide flex-shrink-0">Veri Kaynakları</span>
        {staleCount > 0 && (
          <span className="text-[11px] text-red-400 flex-shrink-0">{staleCount} kaynak bayat (&gt;15dk)</span>
        )}
        <div className="flex flex-wrap gap-2">
          {data.sources.map(s => <FreshnessChip key={s.source_type} item={s} />)}
        </div>
      </div>
    </div>
  )
}

// ─────────────────────────────────────────────
//  Row 6 — Protocol | Traffic | Threat Intel
// ─────────────────────────────────────────────

function ProtocolPanel({ data }: { data: ProtocolDistributionResponse | undefined }) {
  const protos = (data?.protocols ?? []).slice(0, 6)
  if (!protos.length) return (
    <Panel title="Protokol Dağılımı (24s)" icon={Wifi} href="/protocol-distribution">
      <Empty text="Veri yok" />
    </Panel>
  )
  const option = {
    backgroundColor: 'transparent',
    tooltip: {
      trigger: 'item',
      backgroundColor: '#0a1120',
      borderColor: 'rgba(56,189,248,0.15)',
      textStyle: { color: '#cbd5e1', fontSize: 12 },
      formatter: '{b}: {c} ({d}%)',
    },
    legend: {
      bottom: 4,
      textStyle: { color: '#64748b', fontSize: 11 },
      itemWidth: 10,
      itemHeight: 10,
    },
    series: [{
      type: 'pie',
      radius: ['38%', '60%'],
      center: ['50%', '42%'],
      data: protos.map((p, i) => ({
        name: p.protocol.toUpperCase(),
        value: p.count,
        itemStyle: { color: PROTO_COLORS[i % PROTO_COLORS.length] },
      })),
      label: { show: false },
      emphasis: { label: { show: false } },
    }],
  }
  return (
    <Panel title="Protokol Dağılımı (24s)" icon={Wifi} href="/protocol-distribution">
      <ReactECharts option={option} notMerge style={{ height: 200 }} />
    </Panel>
  )
}

function TrafficVolumePanel({ data }: { data: TrafficVolumeResponse | undefined }) {
  const hasData = data && (
    data.series.east_west.some(p => p.v > 0) ||
    data.series.ns_egress.some(p => p.v > 0) ||
    data.series.ns_ingress.some(p => p.v > 0)
  )
  if (!hasData) return (
    <Panel title="Trafik Hacmi (24s)" icon={Activity} href="/traffic-volume">
      <Empty text="Veri yok" />
    </Panel>
  )
  const times = data!.series.east_west.map(p => {
    const d = new Date(p.t)
    return d.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' })
  })
  const option = {
    backgroundColor: 'transparent',
    grid: { top: 10, right: 8, bottom: 28, left: 40, containLabel: false },
    tooltip: {
      trigger: 'axis',
      backgroundColor: '#0a1120',
      borderColor: 'rgba(56,189,248,0.15)',
      textStyle: { color: '#cbd5e1', fontSize: 11 },
    },
    legend: {
      bottom: 2,
      textStyle: { color: '#64748b', fontSize: 10 },
      itemWidth: 8, itemHeight: 8,
    },
    xAxis: {
      type: 'category',
      data: times,
      axisLabel: { color: '#475569', fontSize: 9, interval: Math.floor(times.length / 4) },
      axisLine: { show: false }, axisTick: { show: false },
    },
    yAxis: {
      type: 'value',
      axisLabel: { color: '#475569', fontSize: 9 },
      axisLine: { show: false }, axisTick: { show: false },
      splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
    },
    series: [
      { name: 'İç-İç', type: 'line', stack: 'total', smooth: 0.3, symbol: 'none', data: data!.series.east_west.map(p => p.v), lineStyle: { color: '#6366f1', width: 1.5 }, areaStyle: { color: '#6366f120' }, itemStyle: { color: '#6366f1' } },
      { name: 'Çıkış',  type: 'line', stack: 'total', smooth: 0.3, symbol: 'none', data: data!.series.ns_egress.map(p => p.v), lineStyle: { color: '#f97316', width: 1.5 }, areaStyle: { color: '#f9731620' }, itemStyle: { color: '#f97316' } },
      { name: 'Giriş',  type: 'line', stack: 'total', smooth: 0.3, symbol: 'none', data: data!.series.ns_ingress.map(p => p.v), lineStyle: { color: '#10b981', width: 1.5 }, areaStyle: { color: '#10b98120' }, itemStyle: { color: '#10b981' } },
    ],
  }
  return (
    <Panel title="Trafik Hacmi (24s)" icon={Activity} href="/traffic-volume">
      <ReactECharts option={option} notMerge style={{ height: 200 }} />
    </Panel>
  )
}

function ThreatIntelPanel({ data }: { data: ThreatSummaryResponse | undefined }) {
  const top = (data?.top_sources ?? []).slice(0, 4)
  return (
    <Panel title="Tehdit İstihbaratı (24s)" icon={Radio} href="/threat-intel-summary">
      {top.length === 0 ? (
        <Empty text="Tehdit tespiti yok" />
      ) : (
        <div className="p-3 space-y-2">
          {data && (
            <div className="flex gap-3 mb-3">
              <div className="flex-1 bg-[#080f1e] rounded p-2 text-center">
                <p className={cn('text-2xl font-bold leading-none tabular-nums', data.critical_count > 0 ? 'text-red-400' : 'text-slate-300')}>{data.critical_count}</p>
                <p className="text-[10px] text-slate-600 mt-0.5">Kritik</p>
              </div>
              <div className="flex-1 bg-[#080f1e] rounded p-2 text-center">
                <p className={cn('text-2xl font-bold leading-none tabular-nums', data.high_risk_count > 0 ? 'text-orange-400' : 'text-slate-300')}>{data.high_risk_count}</p>
                <p className="text-[10px] text-slate-600 mt-0.5">Yüksek Risk</p>
              </div>
              <div className="flex-1 bg-[#080f1e] rounded p-2 text-center">
                <p className="text-2xl font-bold leading-none tabular-nums text-slate-300">{data.total_alerts}</p>
                <p className="text-[10px] text-slate-600 mt-0.5">Alert</p>
              </div>
            </div>
          )}
          {top.map(src => (
            <div key={src.ip} className="flex items-center gap-2">
              <span className="font-mono text-[11px] text-slate-400 w-28 truncate flex-shrink-0" title={src.ip}>{src.ip}</span>
              <div className="flex-1 h-1 bg-[#0f1c30] rounded-full overflow-hidden">
                <div className="h-full rounded-full bg-red-500" style={{ width: `${src.composite_score}%` }} />
              </div>
              <span className="text-[11px] font-mono text-slate-500 w-6 text-right">{src.composite_score}</span>
              {src.country_code && (
                <span className="text-[10px] text-slate-600 w-6 text-right flex-shrink-0">{src.country_code}</span>
              )}
            </div>
          ))}
        </div>
      )}
    </Panel>
  )
}

// ─────────────────────────────────────────────
//  Row 7 — Alert Trend
// ─────────────────────────────────────────────

function buildAlertTrendOption(data: AlertVolumeResponse) {
  const times = data.series.critical.map(p => {
    const d = new Date(p.t)
    return d.toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit', day: '2-digit', month: '2-digit' })
  })
  return {
    backgroundColor: 'transparent',
    grid: { top: 12, right: 12, bottom: 24, left: 44, containLabel: false },
    tooltip: {
      trigger: 'axis',
      backgroundColor: '#0a1120',
      borderColor: 'rgba(56,189,248,0.15)',
      textStyle: { color: '#cbd5e1', fontSize: 12 },
    },
    legend: {
      top: 0, right: 0,
      textStyle: { color: '#64748b', fontSize: 11 },
      itemWidth: 10, itemHeight: 10,
    },
    xAxis: {
      type: 'category',
      data: times,
      axisLine: { show: false }, axisTick: { show: false },
      axisLabel: { color: '#475569', fontSize: 10, interval: Math.floor(times.length / 8) },
    },
    yAxis: {
      type: 'value',
      minInterval: 1,
      axisLine: { show: false }, axisTick: { show: false },
      splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
      axisLabel: { color: '#475569', fontSize: 10 },
    },
    series: [
      { name: 'Kritik', type: 'line', stack: 'total', smooth: 0.3, symbol: 'none', data: data.series.critical.map(p => p.v), lineStyle: { color: '#ef4444', width: 1.5 }, areaStyle: { color: '#ef444420' }, itemStyle: { color: '#ef4444' } },
      { name: 'Yüksek', type: 'line', stack: 'total', smooth: 0.3, symbol: 'none', data: data.series.high.map(p => p.v),     lineStyle: { color: '#f97316', width: 1.5 }, areaStyle: { color: '#f9731620' }, itemStyle: { color: '#f97316' } },
      { name: 'Uyarı',  type: 'line', stack: 'total', smooth: 0.3, symbol: 'none', data: data.series.warning.map(p => p.v),  lineStyle: { color: '#eab308', width: 1.5 }, areaStyle: { color: '#eab30820' }, itemStyle: { color: '#eab308' } },
      { name: 'Bilgi',  type: 'line', stack: 'total', smooth: 0.3, symbol: 'none', data: data.series.info.map(p => p.v),     lineStyle: { color: '#3b82f6', width: 1.5 }, areaStyle: { color: '#3b82f620' }, itemStyle: { color: '#3b82f6' } },
    ],
  }
}

function AlertTrendPanel({ data }: { data: AlertVolumeResponse | undefined }) {
  const hasData = data && data.series.critical.some(p => p.v > 0 || data.series.high.some(p => p.v > 0))
  return (
    <Panel title="Alert Trendi (48 saat)" icon={Bell} href="/alert-volume">
      {!data ? (
        <div className="px-1 py-2"><Skeleton style={{ height: 160 }} className="w-full" /></div>
      ) : !hasData ? (
        <Empty text="Bu dönemde alert yok" />
      ) : (
        <div className="px-1 py-2">
          <ReactECharts option={buildAlertTrendOption(data)} notMerge style={{ height: 220 }} />
        </div>
      )}
    </Panel>
  )
}

// ─────────────────────────────────────────────
//  Row 5 — Agent list + Alert list + Risk
// ─────────────────────────────────────────────

function RiskBar({ score }: { score: number }) {
  const color = score >= 70 ? 'bg-red-500' : score >= 40 ? 'bg-orange-500' : 'bg-yellow-500'
  return (
    <div className="flex items-center gap-2 flex-1 min-w-0">
      <div className="flex-1 h-1 bg-[#0f1c30] rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full', color)} style={{ width: `${score}%` }} />
      </div>
      <span className="text-[11px] font-mono text-slate-500 w-6 text-right flex-shrink-0">{score.toFixed(0)}</span>
    </div>
  )
}

function TopRiskPanel({ data }: { data: AssetRiskEntry[] }) {
  return (
    <Panel title="Yüksek Riskli Varlıklar" icon={ShieldAlert} href="/asset-risk">
      {data.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-8 gap-2">
          <CheckCircle2 size={18} className="text-emerald-500/40" />
          <p className="text-slate-600 text-sm">Risk tespiti yok</p>
        </div>
      ) : (
        <div className="divide-y divide-sky-900/20">
          {data.map(a => (
            <div key={a.ip} className="flex items-center gap-3 px-4 py-2.5">
              <span className={cn('text-xs font-mono flex-shrink-0 w-28 truncate', a.total_score >= 70 ? 'text-red-400' : a.total_score >= 40 ? 'text-orange-400' : 'text-yellow-400')} title={a.ip}>{a.ip}</span>
              <RiskBar score={a.total_score} />
              {a.is_blocked && <span className="text-[10px] font-medium text-red-400 border border-red-800/60 rounded px-1 flex-shrink-0">BLK</span>}
            </div>
          ))}
        </div>
      )}
    </Panel>
  )
}

// ─────────────────────────────────────────────
//  Main page
// ─────────────────────────────────────────────

export default function OverviewPage() {
  const { data: agentsData, isLoading: agentsLoading } = useAgents()
  const { alerts } = useAlerts('active', 10)

  const { data: corrData } = useQuery({
    queryKey: ['correlated-events', 'overview'],
    queryFn:  () => correlationApi.listEvents({ limit: 5 }),
    refetchInterval: 30_000,
  })

  const { data: securitySummary } = useQuery({
    queryKey: ['security-summary'],
    queryFn:  () => securityApi.summary(),
    refetchInterval: 60_000,
  })

  // Row 5 analytics
  const { data: failedAuthData } = useQuery({
    queryKey: ['failed-auth-overview'],
    queryFn:  () => analyticsApi.failedAuth(24),
    refetchInterval: 120_000,
    staleTime: 60_000,
  })

  const { data: dnsData } = useQuery({
    queryKey: ['dns-analysis-overview'],
    queryFn:  () => analyticsApi.dnsAnalysis(24, 5),
    refetchInterval: 120_000,
    staleTime: 60_000,
  })

  // Row 6 analytics
  const { data: protoData } = useQuery({
    queryKey: ['protocol-dist-overview'],
    queryFn:  () => analyticsApi.protocolDistribution(24),
    refetchInterval: 300_000,
    staleTime: 120_000,
  })

  const { data: trafficData } = useQuery({
    queryKey: ['traffic-volume-overview'],
    queryFn:  () => analyticsApi.trafficVolume(24),
    refetchInterval: 120_000,
    staleTime: 60_000,
  })

  const { data: threatData } = useQuery({
    queryKey: ['threat-summary-overview'],
    queryFn:  () => analyticsApi.threatSummary(24, 4),
    refetchInterval: 120_000,
    staleTime: 60_000,
  })

  // Row 7 alert trend
  const { data: alertVolumeData } = useQuery({
    queryKey: ['alert-volume-overview'],
    queryFn:  () => analyticsApi.alertVolume(48),
    refetchInterval: 120_000,
    staleTime: 60_000,
  })

  // Risk assets
  const { data: assetRiskData } = useQuery({
    queryKey: ['asset-risk-overview'],
    queryFn:  () => analyticsApi.assetRisk(24, 5),
    refetchInterval: 120_000,
    staleTime: 60_000,
  })

  const agents       = agentsData?.agents ?? []
  const onlineAgents = agents.filter(a => Date.now() - new Date(a.last_seen).getTime() < 60_000).length
  const totalSecurity = securitySummary
    ? Object.values(securitySummary.summary).reduce((a: number, b) => a + (b as number), 0)
    : 0
  const criticalAlerts = alerts.filter(a => a.severity === 'critical').length

  return (
    <div className="p-5 max-w-[1600px]">

      {/* ── Always-top: status + data freshness ─────────────────────── */}
      <div className="space-y-3 mb-3">
        <SecurityStatusBanner />
        <DataFreshnessBar />
      </div>

      {/* ═══════════════════════════════════════════════════════════════
          BENTO GRID — 12-column asymmetric mosaic layout
          ═══════════════════════════════════════════════════════════════ */}
      <div className="grid grid-cols-12 gap-3">

        {/* ┌── Zone A: StatCards (8 cols) + KPI sidebar (4 cols) ───────┐ */}
        {/* └────────────────────────────────────────────────────────────┘ */}

        {/* A-left: 4 primary stat cards */}
        <div className="col-span-12 lg:col-span-8 grid grid-cols-2 xl:grid-cols-4 gap-3 content-start">
          <StatCard
            label="Aktif Alert" value={alerts.length}
            sub={criticalAlerts > 0 ? `${criticalAlerts} kritik` : 'Kritik yok'}
            iconCls={criticalAlerts > 0 ? 'bg-red-500/10 border border-red-500/20 text-red-400' : 'bg-emerald-500/10 border border-emerald-500/20 text-emerald-400'}
            accentCls={criticalAlerts > 0 ? 'bg-red-400/40' : 'bg-emerald-400/40'}
            icon={Bell} href="/alerts"
          />
          <StatCard
            label="Güvenlik Olayı" value={totalSecurity}
            sub="Toplam kayıtlı"
            iconCls={totalSecurity > 50 ? 'bg-orange-500/10 border border-orange-500/20 text-orange-400' : 'bg-purple-500/10 border border-purple-500/20 text-purple-400'}
            accentCls={totalSecurity > 50 ? 'bg-orange-400/40' : 'bg-purple-400/40'}
            icon={Shield} href="/security"
          />
          <StatCard
            label="Korelasyon" value={(corrData?.events ?? []).length}
            sub="Son tetiklenen"
            iconCls="bg-sky-500/10 border border-sky-500/20 text-sky-400"
            accentCls="bg-sky-400/40"
            icon={GitMerge} href="/correlation"
          />
          <StatCard
            label="Bağlı Agent" value={`${onlineAgents}/${agents.length}`}
            sub="Online / Toplam"
            iconCls={onlineAgents < agents.length && agents.length > 0 ? 'bg-yellow-500/10 border border-yellow-500/20 text-yellow-400' : 'bg-sky-500/10 border border-sky-500/20 text-sky-400'}
            accentCls={onlineAgents < agents.length && agents.length > 0 ? 'bg-yellow-400/40' : 'bg-sky-400/40'}
            icon={Server} href="/agents"
          />
        </div>

        {/* A-right: compact KPI panel — attack chain + incident metrics */}
        <div className="col-span-12 lg:col-span-4">
          <div className="bg-[#0d1526] border border-sky-900/25 rounded-lg h-full overflow-hidden hover:border-sky-800/40 transition-colors">
            <div className="ui-panel-header">
              <Swords size={13} className="text-sky-700" />
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wide">Zincir & Incident</span>
            </div>
            <div className="p-3 grid grid-cols-3 gap-2">
              <AttackChainKpis />
              <IncidentKpis />
            </div>
          </div>
        </div>

        {/* ── Section: Tespit ─────────────────────────────────────────── */}
        <SectionLabel label="Tespit" icon={ShieldAlert} />

        {/* ┌── Zone B: Alert Trend HERO (8 cols) + right stack (4 cols) ─┐ */}
        {/* └─────────────────────────────────────────────────────────────┘ */}

        {/* B-left: alert trend — the most time-critical view, hero-sized */}
        <div className="col-span-12 xl:col-span-8">
          <AlertTrendPanel data={alertVolumeData} />
        </div>

        {/* B-right: threat intel + live kill chain events */}
        <div className="col-span-12 xl:col-span-4 flex flex-col gap-3">
          <ThreatIntelPanel data={threatData} />

          <Panel title="Kill Chain" icon={Swords} href="/timeline">
            {(corrData?.events ?? []).length === 0 ? (
              <div className="flex flex-col items-center justify-center py-8 gap-2">
                <Zap size={18} className="text-emerald-500/40" />
                <p className="text-slate-600 text-sm">Aktif saldırı zinciri yok</p>
              </div>
            ) : (
              <div className="divide-y divide-sky-900/20">
                {(corrData?.events ?? []).slice(0, 5).map((ev) => (
                  <div key={ev.corr_id} className="flex items-start gap-3 px-4 py-2.5">
                    <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 mt-1.5 ${SEV_DOT[ev.severity] ?? 'bg-slate-600'}`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-slate-300 truncate font-medium">{ev.rule_name}</p>
                      <p className="text-[11px] text-slate-600 font-mono">{ev.group_value}</p>
                      {ev.mitre_tactics.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-1">
                          {ev.mitre_tactics.slice(0, 2).map(t => (
                            <span key={t} className={cn('text-[10px] px-1.5 py-0.5 rounded font-medium', TACTIC_COLORS[t] ?? 'bg-[#0f1c30] text-slate-400')}>
                              {t.replace(/-/g, ' ')}
                            </span>
                          ))}
                        </div>
                      )}
                    </div>
                    <SeverityBadge severity={ev.severity as Severity} />
                  </div>
                ))}
              </div>
            )}
          </Panel>
        </div>

        {/* ── Section: Varlıklar ──────────────────────────────────────── */}
        <SectionLabel label="Varlıklar" icon={Server} />

        {/* ┌── Zone C: Topology 7/12 + Risk & MTTD 5/12 (asymmetric) ───┐ */}
        {/* └─────────────────────────────────────────────────────────────┘ */}

        {/* C-left: network topology map */}
        <div className="col-span-12 xl:col-span-7">
          <Panel title="Ağ Topolojisi" icon={Share2} href="/topology">
            <div className="h-80"><MiniTopology /></div>
          </Panel>
        </div>

        {/* C-right: risk assets + MTTD/MTTR metrics */}
        <div className="col-span-12 xl:col-span-5 flex flex-col gap-3">
          <TopRiskPanel data={assetRiskData?.assets ?? []} />
          <MttdRow />
        </div>

        {/* ── Section: Operasyon ──────────────────────────────────────── */}
        <SectionLabel label="Operasyon" icon={Activity} />

        {/* ┌── Zone D: Operational 4 panels ─────────────────────────────┐ */}
        {/* └─────────────────────────────────────────────────────────────┘ */}
        <div className="col-span-12 grid grid-cols-1 lg:grid-cols-4 gap-3">
          <FailedAuthPanel data={failedAuthData} />
          <DnsAnomalyPanel data={dnsData} />
          <AnomalyPanel />
          <SensorHealthPanel />
        </div>

        {/* ── Section: Ağ İzleme ──────────────────────────────────────── */}
        <SectionLabel label="Ağ İzleme" icon={Wifi} />

        {/* ┌── Zone E: Agents (4) + Alerts (5) + Protocol (3) ──────────┐ */}
        {/* └─────────────────────────────────────────────────────────────┘ */}
        <div className="col-span-12 grid grid-cols-12 gap-3">
          <div className="col-span-12 lg:col-span-4">
            <Panel title="Agents" icon={Server} href="/agents">
              {agentsLoading
                ? <div className="space-y-2 p-2">{[0,1,2].map(i => <Skeleton key={i} style={{ height: 36 }} className="w-full" />)}</div>
                : agents.length === 0
                  ? <Empty text="Agent bağlı değil" />
                  : <div>{agents.slice(0, 6).map(a => <AgentRow key={a.agent_id} agent={a} />)}</div>
              }
            </Panel>
          </div>

          <div className="col-span-12 lg:col-span-5">
            <Panel title="Son Alertler" icon={AlertTriangle} href="/alerts">
              {alerts.length === 0 ? <Empty text="Alert yok" /> : (
                <div className="divide-y divide-sky-900/20">
                  {alerts.slice(0, 6).map((alert) => (
                    <div key={alert.alert_id} className="flex items-center gap-3 px-4 py-2.5">
                      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${SEV_DOT[alert.severity] ?? 'bg-slate-600'}`} />
                      <div className="flex-1 min-w-0">
                        <p className="text-xs text-slate-300 truncate font-medium">{alert.message}</p>
                        <p className="text-[11px] text-slate-600">{alert.hostname}</p>
                      </div>
                      <SeverityBadge severity={alert.severity} />
                    </div>
                  ))}
                </div>
              )}
            </Panel>
          </div>

          <div className="col-span-12 lg:col-span-3">
            <ProtocolPanel data={protoData} />
          </div>
        </div>

        {/* ┌── Zone F: Traffic Volume — full-width bottom ───────────────┐ */}
        {/* └─────────────────────────────────────────────────────────────┘ */}
        <div className="col-span-12">
          <TrafficVolumePanel data={trafficData} />
        </div>

      </div>
    </div>
  )
}
