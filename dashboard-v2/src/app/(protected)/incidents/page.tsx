'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ShieldAlert, RefreshCw, Plus, X, CheckCheck, Clock, ChevronDown, ChevronUp, TrendingUp } from 'lucide-react'
import { incidentApi, activeResponse, analyticsApi, type Incident, type IncidentEvent, type IncidentEnrichment } from '@/lib/api'
import { useCurrentUser } from '@/hooks/useCurrentUser'
import { MttdMttrChart } from '@/components/charts/MttdMttrChart'
import { Skeleton, SkeletonTable } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

// ─── Sabitler ─────────────────────────────────────────────────────────────────

const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  high:     'bg-orange-500',
  warning:  'bg-yellow-500',
  info:     'bg-blue-400',
}

const STATUS_LABELS: Record<string, string> = {
  open:          'Açık',
  investigating: 'İnceleniyor',
  resolved:      'Çözüldü',
}

const STATUS_CLS: Record<string, string> = {
  open:          'bg-red-500/10 text-red-400 border-red-500/25',
  investigating: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/25',
  resolved:      'bg-emerald-500/10 text-emerald-400 border-emerald-500/25',
}

const SEV_TEXT: Record<string, string> = {
  critical: 'text-red-400',
  high:     'text-orange-400',
  warning:  'text-yellow-400',
  info:     'text-blue-400',
}

const SLA_TARGETS: Record<string, { mttd: number; mttr: number }> = {
  critical: { mttd: 15,  mttr: 60  },
  high:     { mttd: 60,  mttr: 120 },
  warning:  { mttd: 120, mttr: 240 },
  info:     { mttd: 240, mttr: 480 },
}

const INPUT_CLS = "ui-input"
const SELECT_CLS = "ui-select"

// ─── PriorityBadge ────────────────────────────────────────────────────────────

function PriorityBadge({ score, large }: { score: number; large?: boolean }) {
  const cls = score >= 70 ? 'bg-red-500/15 text-red-400 border-red-500/30'
            : score >= 40 ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/25'
            :               'bg-sky-950/20 text-slate-500 border-sky-900/20'
  return (
    <span className={cn('inline-flex items-center rounded border font-mono font-bold', cls,
      large ? 'text-base px-3 py-1' : 'text-xs px-1.5 py-0.5')}>
      {score}
    </span>
  )
}

// ─── EventTimeline ────────────────────────────────────────────────────────────

function EventTimeline({ incidentId }: { incidentId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['incident-events', incidentId],
    queryFn:  () => incidentApi.getEvents(incidentId),
    refetchInterval: 15_000,
  })
  const events: IncidentEvent[] = data?.events ?? []

  if (isLoading) return <div className="space-y-2 py-2">{[0,1,2].map(i => <Skeleton key={i} style={{ height: 28 }} className="w-full" />)}</div>
  if (events.length === 0) return <p className="text-xs text-slate-600 py-2">Henüz event yok</p>

  return (
    <div className="relative ml-2 mt-2">
      {events.map((ev, i) => (
        <div key={ev.id} className="flex gap-3 relative pb-4">
          <div className="flex flex-col items-center">
            <span className={cn('mt-1 w-2.5 h-2.5 rounded-full flex-shrink-0', SEV_DOT[ev.severity] ?? 'bg-slate-600')} />
            {i < events.length - 1 && <div className="w-px flex-1 bg-sky-900/30 mt-1" />}
          </div>
          <div className="pb-1">
            <p className="text-xs text-slate-300 leading-snug">{ev.message}</p>
            <p className="text-[10px] text-slate-600 mt-0.5 font-mono">
              {new Date(ev.occurred_at).toLocaleString('tr-TR')}
              {' · '}
              <span className="uppercase">{ev.event_action}</span>
            </p>
          </div>
        </div>
      ))}
    </div>
  )
}

// ─── EnrichmentPanel ──────────────────────────────────────────────────────────

function EnrichmentPanel({ enrichment, incidentId }: { enrichment?: IncidentEnrichment; incidentId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['incident-detail', incidentId],
    queryFn:  () => incidentApi.get(incidentId),
    refetchInterval: 30_000,
  })
  const enr: IncidentEnrichment | undefined = data?.enrichment ?? enrichment

  if (isLoading && !enr) return <div className="space-y-2 py-2">{[0,1,2,3].map(i => <Skeleton key={i} style={{ height: 24 }} className="w-full" />)}</div>
  if (!enr) return null

  const hasMitre = enr.mitre_techniques.length > 0 || enr.mitre_tactics.length > 0
  const hasTI    = !!enr.threat_intel
  const hasLogs  = enr.related_logs.length > 0

  if (!hasMitre && !hasTI && !hasLogs) return null

  return (
    <div className="space-y-4">
      {hasMitre && (
        <div>
          <p className="text-[10px] text-slate-600 mb-2 font-medium uppercase tracking-wide">MITRE ATT&CK</p>
          <div className="flex flex-wrap gap-1.5">
            {enr.mitre_techniques.map(t => (
              <span key={t} className="px-2 py-0.5 rounded bg-violet-950/50 text-violet-300 text-xs font-mono border border-violet-900/50">
                {t}
              </span>
            ))}
            {enr.mitre_tactics.map(t => (
              <span key={t} className="px-2 py-0.5 rounded bg-sky-950/30 border border-sky-900/20 text-slate-400 text-xs">
                {t.replace(/_/g, ' ')}
              </span>
            ))}
          </div>
        </div>
      )}

      {hasTI && enr.threat_intel && (
        <div>
          <p className="text-[10px] text-slate-600 mb-2 font-medium uppercase tracking-wide">Threat Intelligence</p>
          <div className="flex items-center gap-3 p-3 rounded-lg bg-sky-950/20 border border-sky-900/15">
            <div className="text-center">
              <p className={cn('text-xl font-bold',
                enr.threat_intel.score >= 70 ? 'text-red-400'
                : enr.threat_intel.score >= 30 ? 'text-yellow-400'
                : 'text-emerald-400')}>
                {enr.threat_intel.score}
              </p>
              <p className="text-[10px] text-slate-600">AbuseIPDB</p>
            </div>
            <div className="text-xs text-slate-500 space-y-0.5">
              {enr.threat_intel.country_code && <p>Ülke: <span className="text-slate-300">{enr.threat_intel.country_code}</span></p>}
              {enr.threat_intel.isp && <p>ISP: <span className="text-slate-300 truncate max-w-[200px] inline-block align-bottom">{enr.threat_intel.isp}</span></p>}
              <p>Raporlar: <span className="text-slate-300">{enr.threat_intel.total_reports}</span></p>
            </div>
          </div>
        </div>
      )}

      {hasLogs && (
        <div>
          <p className="text-[10px] text-slate-600 mb-2 font-medium uppercase tracking-wide">
            İlgili Loglar <span className="normal-case text-slate-700">({enr.related_logs.length})</span>
          </p>
          <div className="space-y-1 max-h-48 overflow-y-auto pr-1">
            {enr.related_logs.map(log => (
              <div key={log.log_id} className="flex gap-2 items-start p-1.5 rounded bg-sky-950/20 border border-sky-900/15">
                <span className={cn('mt-0.5 w-1.5 h-1.5 rounded-full flex-shrink-0', SEV_DOT[log.severity] ?? 'bg-slate-600')} />
                <div className="min-w-0">
                  <p className="text-xs text-slate-300 truncate">{log.message}</p>
                  <p className="text-[10px] text-slate-600 font-mono mt-0.5">
                    {new Date(log.timestamp).toLocaleString('tr-TR')}
                    {' · '}
                    <span className="uppercase">{log.event_action}</span>
                    {' · '}
                    {log.source_type}
                    {(log.source_hostname || log.source_ip) && (
                      <>
                        {' · '}
                        {log.source_hostname
                          ? <><span className="text-slate-500">{log.source_hostname}</span><span className="text-slate-700 ml-0.5">({log.source_ip})</span></>
                          : log.source_ip}
                      </>
                    )}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── SummaryCard ──────────────────────────────────────────────────────────────

function SummaryCard({ label, value, color, sub }: { label: string; value: number; color: string; sub?: string }) {
  return (
    <div className="ui-panel p-4">
      <p className="text-xs text-slate-500 mb-1">{label}</p>
      <p className={cn('text-3xl font-bold leading-none', color)}>{value}</p>
      {sub && <p className="text-[11px] text-slate-700 mt-0.5">{sub}</p>}
    </div>
  )
}

// ─── SlaBar ───────────────────────────────────────────────────────────────────

function fmtMin(min: number | null) {
  if (min === null) return '—'
  if (min < 60) return `${Math.round(min)}dk`
  return `${(min / 60).toFixed(1)}s`
}

function SlaBar({ pct }: { pct: number }) {
  const color = pct >= 90 ? 'bg-emerald-500' : pct >= 70 ? 'bg-yellow-500' : 'bg-red-500'
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-sky-950/20 rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full', color)} style={{ width: `${Math.min(100, pct)}%` }} />
      </div>
      <span className={cn('text-[11px] font-mono', pct >= 90 ? 'text-emerald-400' : pct >= 70 ? 'text-yellow-400' : 'text-red-400')}>
        {pct.toFixed(0)}%
      </span>
    </div>
  )
}

// ─── MTTD/MTTR Section ────────────────────────────────────────────────────────

function MttdMttrSection() {
  const [expanded, setExpanded] = useState(false)
  const { data } = useQuery({
    queryKey: ['mttd-mttr-incidents'],
    queryFn:  () => analyticsApi.mttdMttr(30),
    refetchInterval: 300_000,
    staleTime: 120_000,
  })
  const rate = data?.resolution_rate ?? null

  return (
    <div className="ui-panel">
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full flex items-center gap-4 px-4 py-3 hover:bg-sky-950/15 transition-colors"
      >
        <TrendingUp size={13} className="text-slate-600 flex-shrink-0" />
        <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide flex-1 text-left">
          MTTD / MTTR Performansı — Son 30 Gün
        </span>
        <div className="hidden md:flex items-center gap-6 mr-4">
          <div className="text-center">
            <p className="text-xs font-mono font-bold text-sky-400">{fmtMin(data?.overall_mttd_minutes ?? null)}</p>
            <p className="text-[10px] text-slate-700">Ort. MTTD</p>
          </div>
          <div className="text-center">
            <p className="text-xs font-mono font-bold text-orange-400">{fmtMin(data?.overall_mttr_minutes ?? null)}</p>
            <p className="text-[10px] text-slate-700">Ort. MTTR</p>
          </div>
          <div className="text-center">
            <p className={cn('text-xs font-mono font-bold', rate === null ? 'text-slate-600' : rate >= 80 ? 'text-emerald-400' : 'text-yellow-400')}>
              {rate !== null ? `${rate.toFixed(0)}%` : '—'}
            </p>
            <p className="text-[10px] text-slate-700">Çözüm Oranı</p>
          </div>
        </div>
        {expanded ? <ChevronUp size={13} className="text-slate-700 flex-shrink-0" /> : <ChevronDown size={13} className="text-slate-700 flex-shrink-0" />}
      </button>

      {expanded && data && (
        <div className="border-t border-sky-900/15 p-4 space-y-5">
          {data.trend.length > 1 && (
            <div>
              <p className="text-[11px] text-slate-600 mb-2 uppercase tracking-wide">Günlük MTTD / MTTR Trendi</p>
              <MttdMttrChart trend={data.trend} height={180} />
            </div>
          )}
          {data.by_severity.length > 0 && (
            <div>
              <p className="text-[11px] text-slate-600 mb-2 uppercase tracking-wide">Severity SLA Uyumu</p>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-slate-600 border-b border-sky-900/15">
                      <th className="ui-th">Severity</th>
                      <th className="ui-th text-right">Hedef MTTD</th>
                      <th className="ui-th">MTTD SLA</th>
                      <th className="ui-th text-right">Ort. MTTD</th>
                      <th className="ui-th text-right">Hedef MTTR</th>
                      <th className="ui-th">MTTR SLA</th>
                      <th className="ui-th text-right">Ort. MTTR</th>
                      <th className="ui-th text-right">Incident</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.by_severity.map(row => (
                      <tr key={row.severity} className="border-b border-sky-900/10 last:border-0">
                        <td className="ui-td pr-4">
                          <span className={cn('font-medium uppercase', SEV_TEXT[row.severity] ?? 'text-slate-400')}>{row.severity}</span>
                        </td>
                        <td className="ui-td text-right text-slate-600">{fmtMin(row.mttd_target_minutes)}</td>
                        <td className="ui-td"><SlaBar pct={row.mttd_sla_pct} /></td>
                        <td className="ui-td text-right font-mono text-slate-300">{fmtMin(row.avg_mttd_minutes)}</td>
                        <td className="ui-td text-right text-slate-600">{fmtMin(row.mttr_target_minutes)}</td>
                        <td className="ui-td"><SlaBar pct={row.mttr_sla_pct} /></td>
                        <td className="ui-td text-right font-mono text-slate-300">{fmtMin(row.avg_mttr_minutes)}</td>
                        <td className="ui-td pl-3 text-right text-slate-600">{row.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="text-[10px] text-slate-700 mt-2">Kaynak: SANS Incident Response 2023, Prophet Security SOC KPIs 2025</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── IncidentAge ──────────────────────────────────────────────────────────────

function IncidentAge({ createdAt, resolvedAt, severity, status }: {
  createdAt: string; resolvedAt?: string | null; severity: string; status: string
}) {
  const end  = resolvedAt ? new Date(resolvedAt) : new Date()
  const mins = Math.floor((end.getTime() - new Date(createdAt).getTime()) / 60000)
  const sla  = SLA_TARGETS[severity]?.mttr ?? 480

  const text = mins < 60 ? `${mins}dk`
             : mins < 1440 ? `${Math.floor(mins / 60)}s ${mins % 60}dk`
             : `${Math.floor(mins / 1440)}g`

  const isActive = status === 'open' || status === 'investigating'
  const color = !isActive      ? 'text-slate-700'
    : mins > sla        ? 'text-red-400'
    : mins > sla * 0.7  ? 'text-yellow-400'
    : 'text-slate-600'

  return <span className={cn('text-xs font-mono', color)}>{text}</span>
}

// ─── Ana Sayfa ────────────────────────────────────────────────────────────────

export default function IncidentsPage() {
  const qc = useQueryClient()
  const currentUser = useCurrentUser()
  const [statusFilter, setStatusFilter]       = useState('all')
  const [severityFilter, setSeverityFilter]   = useState('all')
  const [showCreate, setShowCreate]           = useState(false)
  const [newTitle, setNewTitle]               = useState('')
  const [newSeverity, setNewSeverity]         = useState('warning')
  const [newDesc, setNewDesc]                 = useState('')
  const [selected, setSelected]               = useState<Incident | null>(null)
  const [editNotes, setEditNotes]             = useState('')
  const [editClosureNote, setEditClosureNote] = useState('')
  const [pendingStatus, setPendingStatus]     = useState<string | null>(null)
  const [showBlockDialog, setShowBlockDialog] = useState(false)
  const [blockReason, setBlockReason]         = useState('')
  const [blockingIp, setBlockingIp]           = useState<string | null>(null)

  const { data: summary, refetch: refetchSummary } = useQuery({
    queryKey: ['incident-summary'],
    queryFn:  () => incidentApi.summary(),
    refetchInterval: 30_000,
  })

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['incidents', statusFilter, severityFilter],
    queryFn: () => incidentApi.list({
      status:   statusFilter   !== 'all' ? statusFilter   : undefined,
      severity: severityFilter !== 'all' ? severityFilter : undefined,
      limit: 200,
    }),
    refetchInterval: 30_000,
  })

  const createMutation = useMutation({
    mutationFn: () => incidentApi.create({ title: newTitle, severity: newSeverity, description: newDesc }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['incidents'] })
      qc.invalidateQueries({ queryKey: ['incident-summary'] })
      setShowCreate(false); setNewTitle(''); setNewDesc('')
    },
  })

  const updateMutation = useMutation({
    mutationFn: (body: { id: string; status?: string; notes?: string; assigned_to?: string; closure_note?: string }) =>
      incidentApi.update(body.id, { status: body.status, notes: body.notes, assigned_to: body.assigned_to, closure_note: body.closure_note }),
    onSuccess: (updated) => {
      qc.invalidateQueries({ queryKey: ['incidents'] })
      qc.invalidateQueries({ queryKey: ['incident-summary'] })
      setSelected(updated)
    },
  })

  const resolveAllMutation = useMutation({
    mutationFn: () => incidentApi.resolveAll(),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['incidents'] })
      qc.invalidateQueries({ queryKey: ['incident-summary'] })
      qc.invalidateQueries({ queryKey: ['security-status'] })
      setSelected(null)
    },
  })

  const playbookQuery = useQuery({
    queryKey: ['playbook', selected?.incident_id],
    queryFn:  () => activeResponse.playbook(selected!.incident_id),
    enabled:  !!selected && selected.severity === 'critical',
    retry: false,
  })

  const blockMutation = useMutation({
    mutationFn: ({ ip, reason }: { ip: string; reason: string }) =>
      activeResponse.block({ ip, reason, source_incident_id: selected?.incident_id }),
    onSuccess: () => {
      setShowBlockDialog(false); setBlockReason(''); setBlockingIp(null)
      qc.invalidateQueries({ queryKey: ['active-blocks'] })
      qc.invalidateQueries({ queryKey: ['playbook', selected?.incident_id] })
    },
  })

  const incidents = [...(data?.incidents ?? [])].sort(
    (a, b) => (b.priority_score ?? 0) - (a.priority_score ?? 0),
  )

  const openCount = (summary?.open ?? 0) + (summary?.investigating ?? 0)

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-orange-500/10 border border-orange-500/20 flex items-center justify-center">
            <ShieldAlert size={15} className="text-orange-400" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-slate-100 leading-tight">Incident Yönetimi</h1>
            <p className="text-xs text-slate-600">{openCount} açık · {summary?.total ?? 0} toplam</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => { refetch(); refetchSummary() }}
            className="p-1.5 rounded-md text-slate-500 hover:text-slate-300 hover:bg-sky-950/40 transition-colors"
          >
            <RefreshCw size={14} />
          </button>
          <button
            onClick={() => resolveAllMutation.mutate()}
            disabled={resolveAllMutation.isPending || openCount === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs text-emerald-400 border border-emerald-700/40 bg-emerald-500/5 hover:bg-emerald-500/10 transition-colors disabled:opacity-40"
          >
            <CheckCheck size={13} /> Tümünü Çözüldü Yap
          </button>
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs bg-sky-600 hover:bg-sky-500 text-white font-medium transition-colors shadow-[0_0_12px_rgba(56,189,248,0.15)]"
          >
            <Plus size={13} /> Yeni Incident
          </button>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <SummaryCard label="Toplam"      value={summary?.total         ?? 0} color="text-slate-200"    sub="Tüm zamanlar" />
        <SummaryCard label="Açık"        value={summary?.open          ?? 0} color="text-red-400"     sub="Müdahale bekliyor" />
        <SummaryCard label="İnceleniyor" value={summary?.investigating ?? 0} color="text-yellow-400"  sub="Aktif analiz" />
        <SummaryCard label="Çözüldü"     value={summary?.resolved      ?? 0} color="text-emerald-400" sub="Kapatıldı" />
      </div>

      {/* MTTD / MTTR */}
      <MttdMttrSection />

      {/* Create form */}
      {showCreate && (
        <div className="ui-panel p-4 space-y-3">
          <div className="flex items-center justify-between mb-1">
            <span className="text-sm font-semibold text-slate-200">Yeni Incident</span>
            <button onClick={() => setShowCreate(false)} className="text-slate-600 hover:text-slate-400 transition-colors">
              <X size={16} />
            </button>
          </div>
          <input
            placeholder="Başlık"
            value={newTitle}
            onChange={e => setNewTitle(e.target.value)}
            className={INPUT_CLS}
          />
          <input
            placeholder="Açıklama (opsiyonel)"
            value={newDesc}
            onChange={e => setNewDesc(e.target.value)}
            className={INPUT_CLS}
          />
          <div className="flex items-center gap-3">
            <select value={newSeverity} onChange={e => setNewSeverity(e.target.value)} className={cn(SELECT_CLS, 'w-40')}>
              <option value="critical">Critical</option>
              <option value="warning">Warning</option>
              <option value="info">Info</option>
            </select>
            <button
              disabled={!newTitle || createMutation.isPending}
              onClick={() => createMutation.mutate()}
              className="ui-btn ui-btn-primary"
            >
              Oluştur
            </button>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)} className={cn(SELECT_CLS, 'w-40')}>
          <option value="all">Tüm Durumlar</option>
          <option value="open">Açık</option>
          <option value="investigating">İnceleniyor</option>
          <option value="resolved">Çözüldü</option>
        </select>
        <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)} className={cn(SELECT_CLS, 'w-40')}>
          <option value="all">Tüm Severity</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="warning">Warning</option>
          <option value="info">Info</option>
        </select>
      </div>

      {/* Table */}
      <div className="ui-panel">
        {isLoading ? (
          <div className="p-4"><SkeletonTable rows={5} height={44} /></div>
        ) : incidents.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-600">
            <ShieldAlert size={28} className="opacity-20" />
            <p className="text-sm">Incident bulunamadı</p>
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr >
                <th className="ui-th">Başlık</th>
                <th className="ui-th w-16">Öncelik</th>
                <th className="ui-th w-24">Severity</th>
                <th className="ui-th w-28">Durum</th>
                <th className="ui-th w-28">Atanan</th>
                <th className="ui-th w-36">Tarih</th>
                <th className="ui-th w-20">
                  <Clock size={11} className="inline mr-1 text-slate-700" />Süre
                </th>
                <th className="ui-th w-20" />
              </tr>
            </thead>
            <tbody className="divide-y divide-sky-900/10">
              {incidents.map(inc => (
                <tr key={inc.incident_id} className="hover:bg-sky-950/20 transition-colors">
                  <td className="ui-td font-medium text-slate-200 max-w-xs truncate">{inc.title}</td>
                  <td className="ui-td"><PriorityBadge score={inc.priority_score ?? 0} /></td>
                  <td className={cn('ui-td font-mono uppercase font-semibold', SEV_TEXT[inc.severity] ?? 'text-slate-400')}>
                    {inc.severity}
                  </td>
                  <td className="ui-td">
                    <span className={cn('px-2 py-0.5 rounded text-xs font-medium border', STATUS_CLS[inc.status] ?? 'text-slate-400 bg-sky-950/20 border-sky-900/20')}>
                      {STATUS_LABELS[inc.status] ?? inc.status}
                    </span>
                  </td>
                  <td className="ui-td text-slate-500 text-xs font-mono">{inc.assigned_to ?? '—'}</td>
                  <td className="ui-td text-slate-700 text-xs whitespace-nowrap">
                    {new Date(inc.created_at).toLocaleString('tr-TR')}
                  </td>
                  <td className="ui-td">
                    <IncidentAge createdAt={inc.created_at} resolvedAt={inc.resolved_at} severity={inc.severity} status={inc.status} />
                  </td>
                  <td className="ui-td text-right">
                    <button
                      onClick={() => { setSelected(inc); setEditNotes(inc.notes ?? ''); setEditClosureNote(inc.closure_note ?? ''); setPendingStatus(null) }}
                      className="ui-btn ui-btn-secondary text-sky-400"
                    >
                      Yönet
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Detail / Edit Panel */}
      {selected && (
        <div className="ui-panel p-5 space-y-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h2 className="text-sm font-semibold text-slate-100">{selected.title}</h2>
              {selected.description && <p className="text-xs text-slate-500 mt-1">{selected.description}</p>}
            </div>
            <button onClick={() => setSelected(null)} className="text-slate-600 hover:text-slate-400 transition-colors flex-shrink-0">
              <X size={16} />
            </button>
          </div>

          <div className="flex gap-4 flex-wrap items-start">
            <div>
              <p className="text-xs text-slate-600 mb-1">Öncelik Skoru</p>
              <PriorityBadge score={selected.priority_score ?? 0} large />
            </div>
            <div>
              <p className="text-xs text-slate-600 mb-1">Durum Değiştir</p>
              <select
                value={pendingStatus ?? selected.status}
                onChange={e => {
                  const v = e.target.value
                  if (v === 'resolved') { setPendingStatus('resolved') }
                  else { setPendingStatus(null); updateMutation.mutate({ id: selected.incident_id, status: v }) }
                }}
                className={cn(SELECT_CLS, 'w-40')}
              >
                <option value="open">Açık</option>
                <option value="investigating">İnceleniyor</option>
                <option value="resolved">Çözüldü</option>
              </select>
            </div>
          </div>

          {/* Closure note */}
          {pendingStatus === 'resolved' && (
            <div className="p-3 rounded-lg border border-yellow-500/20 bg-yellow-500/5 space-y-2">
              <p className="text-xs text-yellow-400 font-medium">Kapatma Notu (zorunlu)</p>
              <textarea
                value={editClosureNote}
                onChange={e => setEditClosureNote(e.target.value)}
                placeholder="Ne yapıldı? Kök neden neydi? Nasıl çözüldü?"
                rows={3}
                className="ui-input resize-none"
              />
              <div className="flex gap-2">
                <button
                  disabled={!editClosureNote.trim() || updateMutation.isPending}
                  onClick={() => updateMutation.mutate({ id: selected.incident_id, status: 'resolved', closure_note: editClosureNote.trim() })}
                  className="ui-btn bg-emerald-700 hover:bg-emerald-600 text-white"
                >
                  Çözüldü Olarak Kapat
                </button>
                <button onClick={() => setPendingStatus(null)}
                  className="ui-btn ui-btn-secondary">
                  Vazgeç
                </button>
              </div>
            </div>
          )}

          {/* Notes */}
          <div>
            <p className="text-xs text-slate-600 mb-1">Notlar</p>
            <div className="flex gap-2">
              <input
                value={editNotes}
                onChange={e => setEditNotes(e.target.value)}
                placeholder="Not ekle..."
                className={cn(INPUT_CLS, 'flex-1')}
              />
              <button
                onClick={() => updateMutation.mutate({ id: selected.incident_id, notes: editNotes })}
                className="ui-btn ui-btn-primary"
              >
                Kaydet
              </button>
            </div>
          </div>

          {/* Meta */}
          <div className="text-[11px] text-slate-700 space-y-0.5 font-mono">
            {selected.acknowledged_at && (
              <p>İncelemeye alındı: <span className="text-slate-500">{new Date(selected.acknowledged_at).toLocaleString('tr-TR')}</span></p>
            )}
            {selected.resolved_at && (
              <p>Çözüldü: <span className="text-slate-500">{new Date(selected.resolved_at).toLocaleString('tr-TR')}</span></p>
            )}
            {selected.closure_note && (
              <div className="mt-2 p-2.5 rounded-lg bg-sky-950/15 border border-sky-900/15">
                <p className="text-slate-600 mb-0.5">Kapatma notu:</p>
                <p className="text-slate-300 text-xs font-sans">{selected.closure_note}</p>
              </div>
            )}
          </div>

          {/* Aktif Yanıt */}
          {selected.severity === 'critical' && (currentUser?.role === 'admin' || currentUser?.role === 'superadmin') && (
            <div className="p-3 rounded-lg border border-red-500/20 bg-red-950/15 space-y-2">
              <p className="text-xs font-medium uppercase tracking-wide text-red-400">Aktif Yanıt</p>
              {playbookQuery.isLoading && <p className="text-xs text-slate-600">Analiz ediliyor...</p>}
              {playbookQuery.data?.suggestions.map(s => (
                <div key={s.ip} className="flex items-center justify-between gap-2">
                  <span className="text-xs font-mono text-slate-300">{s.ip}</span>
                  {s.already_blocked ? (
                    <span className="text-xs text-emerald-400">Bloklu</span>
                  ) : (
                    <button
                      onClick={() => { setBlockingIp(s.ip); setShowBlockDialog(true) }}
                      className="text-xs px-2 py-1 rounded border border-red-500/30 text-red-400 hover:bg-red-500/10 transition-colors"
                    >
                      Bu IP&apos;yi Blokla
                    </button>
                  )}
                </div>
              ))}
              {playbookQuery.data?.suggestions.length === 0 && !playbookQuery.isLoading && (
                <p className="text-xs text-slate-700">Otomatik bloklama önerisi yok</p>
              )}
            </div>
          )}

          <EnrichmentPanel enrichment={selected.enrichment} incidentId={selected.incident_id} />

          <div>
            <p className="text-[10px] text-slate-600 mb-1 font-medium uppercase tracking-wide">Event Timeline</p>
            <EventTimeline incidentId={selected.incident_id} />
          </div>
        </div>
      )}

      {/* Block dialog */}
      {showBlockDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-[#040911]/80 backdrop-blur-sm">
          <div className="bg-[#0a1120] border border-sky-900/30 rounded-xl p-5 w-full max-w-md shadow-[0_24px_64px_rgba(0,0,0,0.7)] space-y-4">
            <h3 className="text-sm font-semibold text-slate-100">IP Adresi Bloklama Onayı</h3>
            <p className="text-xs text-slate-400">
              <span className="font-mono text-slate-200">{blockingIp}</span> adresini firewall&apos;da bloklamak üzeresiniz.
            </p>
            <div className="space-y-1">
              <label className="text-xs text-slate-600">Sebep (zorunlu)</label>
              <input
                value={blockReason}
                onChange={e => setBlockReason(e.target.value)}
                placeholder="Örn: SSH brute force saldırısı"
                className={INPUT_CLS}
              />
            </div>
            {blockMutation.isError && <p className="text-xs text-red-400">Hata oluştu. Tekrar dene.</p>}
            <div className="flex gap-2 justify-end">
              <button
                onClick={() => { setShowBlockDialog(false); setBlockReason('') }}
                className="ui-btn ui-btn-secondary"
              >
                Vazgeç
              </button>
              <button
                disabled={!blockReason.trim() || blockMutation.isPending}
                onClick={() => blockingIp && blockMutation.mutate({ ip: blockingIp, reason: blockReason })}
                className="ui-btn ui-btn-danger"
              >
                {blockMutation.isPending ? 'Bloklanıyor...' : 'Onayla ve Blokla'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
