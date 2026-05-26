'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ShieldAlert, RefreshCw, Plus, X, CheckCheck, Clock, ChevronDown, ChevronUp, TrendingUp } from 'lucide-react'
import { incidentApi, activeResponse, analyticsApi, type Incident, type IncidentEvent, type IncidentEnrichment } from '@/lib/api'
import { useCurrentUser } from '@/hooks/useCurrentUser'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { MttdMttrChart } from '@/components/charts/MttdMttrChart'
import { cn } from '@/lib/utils'

const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  warning:  'bg-yellow-500',
  info:     'bg-blue-500',
}

function PriorityBadge({ score, large }: { score: number; large?: boolean }) {
  const color =
    score >= 70 ? 'bg-red-500/20 text-red-400 border-red-700/40' :
    score >= 40 ? 'bg-yellow-500/20 text-yellow-400 border-yellow-700/40' :
                  'bg-zinc-700/40 text-zinc-400 border-zinc-600/30'
  return (
    <span className={`inline-flex items-center rounded border font-mono font-bold ${color} ${large ? 'text-base px-3 py-1' : 'text-xs px-1.5 py-0.5'}`}>
      {score}
    </span>
  )
}

function EventTimeline({ incidentId }: { incidentId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['incident-events', incidentId],
    queryFn:  () => incidentApi.getEvents(incidentId),
    refetchInterval: 15_000,
  })

  const events: IncidentEvent[] = data?.events ?? []

  if (isLoading) return <p className="text-xs text-zinc-500 py-2">Yükleniyor...</p>
  if (events.length === 0) return <p className="text-xs text-zinc-500 py-2">Henüz event yok</p>

  return (
    <div className="relative ml-2 mt-2 space-y-0">
      {events.map((ev, i) => (
        <div key={ev.id} className="flex gap-3 relative pb-4">
          <div className="flex flex-col items-center">
            <span className={`mt-1 w-2.5 h-2.5 rounded-full flex-shrink-0 ${SEV_DOT[ev.severity] ?? 'bg-zinc-500'}`} />
            {i < events.length - 1 && (
              <div className="w-px flex-1 bg-zinc-700 mt-1" />
            )}
          </div>
          <div className="pb-1">
            <p className="text-xs text-zinc-300 leading-snug">{ev.message}</p>
            <p className="text-[10px] text-zinc-500 mt-0.5 font-mono">
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

function EnrichmentPanel({ enrichment, incidentId }: { enrichment?: IncidentEnrichment; incidentId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['incident-detail', incidentId],
    queryFn:  () => incidentApi.get(incidentId),
    refetchInterval: 30_000,
  })

  const enr: IncidentEnrichment | undefined = data?.enrichment ?? enrichment

  if (isLoading && !enr) return <p className="text-xs text-zinc-500 py-2">Yükleniyor...</p>
  if (!enr) return null

  const hasMitre = enr.mitre_techniques.length > 0 || enr.mitre_tactics.length > 0
  const hasTI    = !!enr.threat_intel
  const hasLogs  = enr.related_logs.length > 0

  if (!hasMitre && !hasTI && !hasLogs) return null

  return (
    <div className="space-y-4">
      {hasMitre && (
        <div>
          <p className="text-xs text-zinc-500 mb-2 font-medium uppercase tracking-wide">MITRE ATT&CK</p>
          <div className="flex flex-wrap gap-1.5">
            {enr.mitre_techniques.map(t => (
              <span key={t} className="px-2 py-0.5 rounded bg-purple-900/50 text-purple-300 text-xs font-mono border border-purple-700/40">
                {t}
              </span>
            ))}
            {enr.mitre_tactics.map(t => (
              <span key={t} className="px-2 py-0.5 rounded bg-zinc-700/60 text-zinc-300 text-xs">
                {t.replace(/_/g, ' ')}
              </span>
            ))}
          </div>
        </div>
      )}

      {hasTI && enr.threat_intel && (
        <div>
          <p className="text-xs text-zinc-500 mb-2 font-medium uppercase tracking-wide">Threat Intelligence</p>
          <div className="flex items-center gap-3 p-2 rounded bg-zinc-800/60 border border-zinc-700/40">
            <div className="text-center">
              <p className={`text-xl font-bold ${enr.threat_intel.score >= 70 ? 'text-red-400' : enr.threat_intel.score >= 30 ? 'text-yellow-400' : 'text-emerald-400'}`}>
                {enr.threat_intel.score}
              </p>
              <p className="text-[10px] text-zinc-500">AbuseIPDB</p>
            </div>
            <div className="text-xs text-zinc-400 space-y-0.5">
              {enr.threat_intel.country_code && <p>Ülke: <span className="text-zinc-200">{enr.threat_intel.country_code}</span></p>}
              {enr.threat_intel.isp && <p>ISP: <span className="text-zinc-200 truncate max-w-[200px] inline-block align-bottom">{enr.threat_intel.isp}</span></p>}
              <p>Raporlar: <span className="text-zinc-200">{enr.threat_intel.total_reports}</span></p>
            </div>
          </div>
        </div>
      )}

      {hasLogs && (
        <div>
          <p className="text-xs text-zinc-500 mb-2 font-medium uppercase tracking-wide">
            İlgili Loglar <span className="text-zinc-600 normal-case">({enr.related_logs.length})</span>
          </p>
          <div className="space-y-1 max-h-48 overflow-y-auto pr-1">
            {enr.related_logs.map(log => (
              <div key={log.log_id} className="flex gap-2 items-start p-1.5 rounded bg-zinc-800/40 border border-zinc-700/30">
                <span className={`mt-0.5 w-1.5 h-1.5 rounded-full flex-shrink-0 ${SEV_DOT[log.severity] ?? 'bg-zinc-500'}`} />
                <div className="min-w-0">
                  <p className="text-xs text-zinc-300 truncate">{log.message}</p>
                  <p className="text-[10px] text-zinc-600 font-mono mt-0.5">
                    {new Date(log.timestamp).toLocaleString('tr-TR')}
                    {' · '}
                    <span className="uppercase">{log.event_action}</span>
                    {' · '}
                    {log.source_type}
                    {(log.source_hostname || log.source_ip) && (
                      <>
                        {' · '}
                        {log.source_hostname
                          ? <><span className="text-zinc-400">{log.source_hostname}</span><span className="text-zinc-700 ml-0.5">({log.source_ip})</span></>
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

const STATUS_LABELS: Record<string, string> = {
  open:          'Açık',
  investigating: 'İnceleniyor',
  resolved:      'Çözüldü',
}

const STATUS_COLORS: Record<string, string> = {
  open:          'bg-red-500/20 text-red-400',
  investigating: 'bg-yellow-500/20 text-yellow-400',
  resolved:      'bg-emerald-500/20 text-emerald-400',
}

const SEV_COLORS: Record<string, string> = {
  critical: 'text-red-400',
  warning:  'text-yellow-400',
  info:     'text-blue-400',
}

function SummaryCard({ label, value, color, sub }: { label: string; value: number; color: string; sub?: string }) {
  return (
    <Card className="bg-zinc-900 border-zinc-800">
      <CardContent className="pt-4 pb-4">
        <p className="text-xs text-zinc-400 mb-1">{label}</p>
        <p className={`text-2xl font-bold ${color}`}>{value}</p>
        {sub && <p className="text-[11px] text-zinc-600 mt-0.5">{sub}</p>}
      </CardContent>
    </Card>
  )
}

// ─── MTTD / MTTR Performans Paneli ───────────────────────────────────────────

const SLA_TARGETS: Record<string, { mttd: number; mttr: number }> = {
  critical: { mttd: 15,  mttr: 60  },
  high:     { mttd: 60,  mttr: 120 },
  warning:  { mttd: 120, mttr: 240 },
  info:     { mttd: 240, mttr: 480 },
}

function fmtMin(min: number | null) {
  if (min === null) return '—'
  if (min < 60) return `${Math.round(min)}dk`
  return `${(min / 60).toFixed(1)}s`
}

function SlaBar({ pct }: { pct: number }) {
  const color = pct >= 90 ? 'bg-emerald-500' : pct >= 70 ? 'bg-yellow-500' : 'bg-red-500'
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-zinc-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${Math.min(100, pct)}%` }} />
      </div>
      <span className={cn('text-[11px] font-mono', pct >= 90 ? 'text-emerald-400' : pct >= 70 ? 'text-yellow-400' : 'text-red-400')}>
        {pct.toFixed(0)}%
      </span>
    </div>
  )
}

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
    <div className="border border-white/[0.06] rounded-lg bg-[#13161e] overflow-hidden">
      {/* Header — always visible */}
      <button
        onClick={() => setExpanded(v => !v)}
        className="w-full flex items-center gap-4 px-4 py-3 hover:bg-white/[0.03] transition-colors"
      >
        <TrendingUp size={14} className="text-zinc-500 flex-shrink-0" />
        <span className="text-xs font-semibold text-zinc-400 uppercase tracking-wide flex-1 text-left">
          MTTD / MTTR Performansı — Son 30 Gün
        </span>
        {/* KPI chips */}
        <div className="hidden md:flex items-center gap-6 mr-4">
          <div className="text-center">
            <p className="text-xs font-mono font-bold text-blue-400">{fmtMin(data?.overall_mttd_minutes ?? null)}</p>
            <p className="text-[10px] text-zinc-600">Ort. MTTD</p>
          </div>
          <div className="text-center">
            <p className="text-xs font-mono font-bold text-orange-400">{fmtMin(data?.overall_mttr_minutes ?? null)}</p>
            <p className="text-[10px] text-zinc-600">Ort. MTTR</p>
          </div>
          <div className="text-center">
            <p className={cn('text-xs font-mono font-bold', rate === null ? 'text-zinc-500' : rate >= 80 ? 'text-emerald-400' : 'text-yellow-400')}>
              {rate !== null ? `${rate.toFixed(0)}%` : '—'}
            </p>
            <p className="text-[10px] text-zinc-600">Çözüm Oranı</p>
          </div>
        </div>
        {expanded ? <ChevronUp size={14} className="text-zinc-600 flex-shrink-0" /> : <ChevronDown size={14} className="text-zinc-600 flex-shrink-0" />}
      </button>

      {/* Expanded content */}
      {expanded && data && (
        <div className="border-t border-white/[0.06] p-4 space-y-5">
          {/* Trend chart */}
          {data.trend.length > 1 && (
            <div>
              <p className="text-[11px] text-zinc-500 mb-2 uppercase tracking-wide">Günlük MTTD / MTTR Trendi</p>
              <MttdMttrChart trend={data.trend} height={180} />
            </div>
          )}

          {/* SLA tablosu */}
          {data.by_severity.length > 0 && (
            <div>
              <p className="text-[11px] text-zinc-500 mb-2 uppercase tracking-wide">Severity SLA Uyumu</p>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-zinc-500 border-b border-white/[0.06]">
                      <th className="text-left py-2 pr-4 font-medium">Severity</th>
                      <th className="text-right py-2 px-3 font-medium">Hedef MTTD</th>
                      <th className="text-left py-2 px-3 font-medium">MTTD SLA</th>
                      <th className="text-right py-2 px-3 font-medium">Ort. MTTD</th>
                      <th className="text-right py-2 px-3 font-medium">Hedef MTTR</th>
                      <th className="text-left py-2 px-3 font-medium">MTTR SLA</th>
                      <th className="text-right py-2 px-3 font-medium">Ort. MTTR</th>
                      <th className="text-right py-2 pl-3 font-medium">Incident</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.by_severity.map(row => (
                      <tr key={row.severity} className="border-b border-white/[0.04] last:border-0">
                        <td className="py-2 pr-4">
                          <span className={cn('font-medium uppercase', {
                            critical: 'text-red-400',
                            high:     'text-orange-400',
                            warning:  'text-yellow-400',
                            info:     'text-blue-400',
                          }[row.severity] ?? 'text-zinc-400')}>{row.severity}</span>
                        </td>
                        <td className="py-2 px-3 text-right text-zinc-500">{fmtMin(row.mttd_target_minutes)}</td>
                        <td className="py-2 px-3"><SlaBar pct={row.mttd_sla_pct} /></td>
                        <td className="py-2 px-3 text-right font-mono text-zinc-300">{fmtMin(row.avg_mttd_minutes)}</td>
                        <td className="py-2 px-3 text-right text-zinc-500">{fmtMin(row.mttr_target_minutes)}</td>
                        <td className="py-2 px-3"><SlaBar pct={row.mttr_sla_pct} /></td>
                        <td className="py-2 px-3 text-right font-mono text-zinc-300">{fmtMin(row.avg_mttr_minutes)}</td>
                        <td className="py-2 pl-3 text-right text-zinc-500">{row.count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="text-[10px] text-zinc-600 mt-2">Kaynak: SANS Incident Response 2023, Prophet Security SOC KPIs 2025</p>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Incident Yaşlanma ────────────────────────────────────────────────────────

function IncidentAge({ createdAt, resolvedAt, severity, status }: {
  createdAt: string; resolvedAt?: string | null; severity: string; status: string
}) {
  const end = resolvedAt ? new Date(resolvedAt) : new Date()
  const mins = Math.floor((end.getTime() - new Date(createdAt).getTime()) / 60000)
  const sla = SLA_TARGETS[severity]?.mttr ?? 480

  let text: string
  if (mins < 60) text = `${mins}dk`
  else if (mins < 1440) text = `${Math.floor(mins / 60)}s ${mins % 60}dk`
  else text = `${Math.floor(mins / 1440)}g`

  const isActive = status === 'open' || status === 'investigating'
  const color = !isActive ? 'text-zinc-600'
    : mins > sla       ? 'text-red-400'
    : mins > sla * 0.7 ? 'text-yellow-400'
    : 'text-zinc-500'

  return <span className={cn('text-xs font-mono', color)}>{text}</span>
}

export default function IncidentsPage() {
  const qc = useQueryClient()
  const currentUser = useCurrentUser()
  const [statusFilter, setStatusFilter]     = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [showCreate, setShowCreate]         = useState(false)
  const [newTitle, setNewTitle]             = useState('')
  const [newSeverity, setNewSeverity]       = useState('warning')
  const [newDesc, setNewDesc]               = useState('')
  const [selected, setSelected]             = useState<Incident | null>(null)
  const [editNotes, setEditNotes]           = useState('')
  const [editClosureNote, setEditClosureNote] = useState('')
  const [pendingStatus, setPendingStatus]   = useState<string | null>(null)
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
      status:   statusFilter !== 'all' ? statusFilter : undefined,
      severity: severityFilter !== 'all' ? severityFilter : undefined,
      limit: 200,
    }),
    refetchInterval: 30_000,
  })

  const createMutation = useMutation({
    mutationFn: () => incidentApi.create({
      title: newTitle, severity: newSeverity, description: newDesc,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['incidents'] })
      qc.invalidateQueries({ queryKey: ['incident-summary'] })
      setShowCreate(false)
      setNewTitle('')
      setNewDesc('')
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
    queryFn: () => activeResponse.playbook(selected!.incident_id),
    enabled: !!selected && selected.severity === 'critical',
    retry: false,
  })

  const blockMutation = useMutation({
    mutationFn: ({ ip, reason }: { ip: string; reason: string }) =>
      activeResponse.block({ ip, reason, source_incident_id: selected?.incident_id }),
    onSuccess: () => {
      setShowBlockDialog(false)
      setBlockReason('')
      setBlockingIp(null)
      qc.invalidateQueries({ queryKey: ['active-blocks'] })
      qc.invalidateQueries({ queryKey: ['playbook', selected?.incident_id] })
    },
  })

  const incidents = [...(data?.incidents ?? [])].sort(
    (a, b) => (b.priority_score ?? 0) - (a.priority_score ?? 0)
  )

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-orange-400" />
          <h1 className="text-xl font-semibold">Incident Yönetimi</h1>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => { refetch(); refetchSummary() }}>
            <RefreshCw className="w-4 h-4" />
          </Button>
          <Button
            variant="outline" size="sm"
            className="border-emerald-700/50 text-emerald-400 hover:bg-emerald-500/10"
            disabled={resolveAllMutation.isPending || (summary?.open ?? 0) + (summary?.investigating ?? 0) === 0}
            onClick={() => resolveAllMutation.mutate()}
          >
            <CheckCheck className="w-4 h-4 mr-1" />
            Tümünü Çözüldü Yap
          </Button>
          <Button size="sm" onClick={() => setShowCreate(true)}>
            <Plus className="w-4 h-4 mr-1" /> Yeni Incident
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <SummaryCard label="Toplam"      value={summary?.total         ?? 0} color="text-zinc-200"    sub="Tüm zamanlar" />
        <SummaryCard label="Açık"        value={summary?.open          ?? 0} color="text-red-400"     sub="Müdahale bekliyor" />
        <SummaryCard label="İnceleniyor" value={summary?.investigating ?? 0} color="text-yellow-400"  sub="Aktif analiz" />
        <SummaryCard label="Çözüldü"     value={summary?.resolved      ?? 0} color="text-emerald-400" sub="Kapatıldı" />
      </div>

      {/* MTTD / MTTR Performansı */}
      <MttdMttrSection />

      {/* Create Form */}
      {showCreate && (
        <Card className="bg-zinc-900 border-zinc-700">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex justify-between">
              Yeni Incident
              <button onClick={() => setShowCreate(false)}><X className="w-4 h-4" /></button>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <Input
              placeholder="Başlık"
              value={newTitle}
              onChange={e => setNewTitle(e.target.value)}
              className="bg-zinc-800 border-zinc-700"
            />
            <Input
              placeholder="Açıklama (opsiyonel)"
              value={newDesc}
              onChange={e => setNewDesc(e.target.value)}
              className="bg-zinc-800 border-zinc-700"
            />
            <Select value={newSeverity} onValueChange={v => { if (v) setNewSeverity(v) }}>
              <SelectTrigger className="bg-zinc-800 border-zinc-700 w-40">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="warning">Warning</SelectItem>
                <SelectItem value="info">Info</SelectItem>
              </SelectContent>
            </Select>
            <Button size="sm" disabled={!newTitle} onClick={() => createMutation.mutate()}>
              Oluştur
            </Button>
          </CardContent>
        </Card>
      )}

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <Select value={statusFilter} onValueChange={v => { if (v) setStatusFilter(v) }}>
          <SelectTrigger className="bg-zinc-900 border-zinc-700 w-40">
            <SelectValue placeholder="Durum" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Tüm Durumlar</SelectItem>
            <SelectItem value="open">Açık</SelectItem>
            <SelectItem value="investigating">İnceleniyor</SelectItem>
            <SelectItem value="resolved">Çözüldü</SelectItem>
          </SelectContent>
        </Select>
        <Select value={severityFilter} onValueChange={v => { if (v) setSeverityFilter(v) }}>
          <SelectTrigger className="bg-zinc-900 border-zinc-700 w-40">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">Tüm Severity</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="warning">Warning</SelectItem>
            <SelectItem value="info">Info</SelectItem>
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      <Card className="bg-zinc-900 border-zinc-800">
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="border-zinc-800">
                <TableHead>Başlık</TableHead>
                <TableHead>Öncelik</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Durum</TableHead>
                <TableHead>Atanan</TableHead>
                <TableHead>Tarih</TableHead>
                <TableHead title="Incident'ın açık olduğu süre (SLA'ya göre renklenir)">
                  <Clock size={12} className="inline mr-1 text-zinc-600" />Süre
                </TableHead>
                <TableHead></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow><TableCell colSpan={8} className="text-center text-zinc-500 py-8">Yükleniyor...</TableCell></TableRow>
              ) : incidents.length === 0 ? (
                <TableRow><TableCell colSpan={8} className="text-center text-zinc-500 py-8">Incident bulunamadı</TableCell></TableRow>
              ) : incidents.map(inc => (
                <TableRow key={inc.incident_id} className="border-zinc-800 hover:bg-zinc-800/50">
                  <TableCell className="font-medium max-w-xs truncate">{inc.title}</TableCell>
                  <TableCell>
                    <PriorityBadge score={inc.priority_score ?? 0} />
                  </TableCell>
                  <TableCell className={`font-mono text-xs uppercase ${SEV_COLORS[inc.severity] ?? ''}`}>
                    {inc.severity}
                  </TableCell>
                  <TableCell>
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${STATUS_COLORS[inc.status] ?? ''}`}>
                      {STATUS_LABELS[inc.status] ?? inc.status}
                    </span>
                  </TableCell>
                  <TableCell className="text-zinc-400 text-sm">{inc.assigned_to ?? '—'}</TableCell>
                  <TableCell className="text-zinc-500 text-xs">
                    {new Date(inc.created_at).toLocaleString('tr-TR')}
                  </TableCell>
                  <TableCell>
                    <IncidentAge
                      createdAt={inc.created_at}
                      resolvedAt={inc.resolved_at}
                      severity={inc.severity}
                      status={inc.status}
                    />
                  </TableCell>
                  <TableCell>
                    <Button variant="ghost" size="sm" onClick={() => {
                      setSelected(inc)
                      setEditNotes(inc.notes ?? '')
                      setEditClosureNote(inc.closure_note ?? '')
                      setPendingStatus(null)
                    }}>
                      Yönet
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Detail / Edit Panel */}
      {selected && (
        <Card className="bg-zinc-900 border-zinc-700">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm flex justify-between">
              {selected.title}
              <button onClick={() => setSelected(null)}><X className="w-4 h-4" /></button>
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            {selected.description && (
              <p className="text-sm text-zinc-400">{selected.description}</p>
            )}
            <div className="flex gap-4 flex-wrap items-start">
              <div>
                <p className="text-xs text-zinc-500 mb-1">Öncelik Skoru</p>
                <PriorityBadge score={selected.priority_score ?? 0} large />
              </div>
              <div>
                <p className="text-xs text-zinc-500 mb-1">Durum Değiştir</p>
                <Select
                  value={pendingStatus ?? selected.status}
                  onValueChange={v => {
                    if (!v) return
                    if (v === 'resolved') {
                      setPendingStatus('resolved')
                    } else {
                      setPendingStatus(null)
                      updateMutation.mutate({ id: selected.incident_id, status: v })
                    }
                  }}
                >
                  <SelectTrigger className="bg-zinc-800 border-zinc-700 w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="open">Açık</SelectItem>
                    <SelectItem value="investigating">İnceleniyor</SelectItem>
                    <SelectItem value="resolved">Çözüldü</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Closure note — sadece resolved seçilince göster */}
            {pendingStatus === 'resolved' && (
              <div className="p-3 rounded border border-yellow-700/40 bg-yellow-900/10 space-y-2">
                <p className="text-xs text-yellow-400 font-medium">Kapatma Notu (zorunlu)</p>
                <textarea
                  value={editClosureNote}
                  onChange={e => setEditClosureNote(e.target.value)}
                  placeholder="Ne yapıldı? Kök neden neydi? Nasıl çözüldü?"
                  rows={3}
                  className="w-full bg-zinc-800 border border-zinc-700 rounded px-3 py-2 text-sm text-zinc-200 placeholder:text-zinc-600 resize-none focus:outline-none focus:ring-1 focus:ring-yellow-600"
                />
                <div className="flex gap-2">
                  <Button
                    size="sm"
                    disabled={!editClosureNote.trim() || updateMutation.isPending}
                    className="bg-emerald-700 hover:bg-emerald-600 text-white"
                    onClick={() => updateMutation.mutate({
                      id: selected.incident_id,
                      status: 'resolved',
                      closure_note: editClosureNote.trim(),
                    })}
                  >
                    Çözüldü Olarak Kapat
                  </Button>
                  <Button
                    size="sm" variant="outline"
                    onClick={() => setPendingStatus(null)}
                  >
                    Vazgeç
                  </Button>
                </div>
              </div>
            )}

            <div>
              <p className="text-xs text-zinc-500 mb-1">Notlar</p>
              <div className="flex gap-2">
                <Input
                  value={editNotes}
                  onChange={e => setEditNotes(e.target.value)}
                  placeholder="Not ekle..."
                  className="bg-zinc-800 border-zinc-700"
                />
                <Button size="sm" onClick={() => updateMutation.mutate({ id: selected.incident_id, notes: editNotes })}>
                  Kaydet
                </Button>
              </div>
            </div>

            {/* Meta bilgiler */}
            <div className="text-[11px] text-zinc-600 space-y-0.5 font-mono">
              {selected.acknowledged_at && (
                <p>İncelemeye alındı: <span className="text-zinc-400">{new Date(selected.acknowledged_at).toLocaleString('tr-TR')}</span></p>
              )}
              {selected.resolved_at && (
                <p>Çözüldü: <span className="text-zinc-400">{new Date(selected.resolved_at).toLocaleString('tr-TR')}</span></p>
              )}
              {selected.closure_note && (
                <div className="mt-2 p-2 rounded bg-zinc-800/60 border border-zinc-700/30">
                  <p className="text-zinc-500 mb-0.5">Kapatma notu:</p>
                  <p className="text-zinc-300 text-xs font-sans">{selected.closure_note}</p>
                </div>
              )}
            </div>
            {selected.severity === 'critical' && (currentUser?.role === 'admin' || currentUser?.role === 'superadmin') && (
              <div className="p-3 rounded border border-red-800/40 bg-red-950/20 space-y-2">
                <p className="text-xs font-medium uppercase tracking-wide text-red-400">
                  Aktif Yanıt
                </p>
                {playbookQuery.isLoading && (
                  <p className="text-xs text-zinc-500">Analiz ediliyor...</p>
                )}
                {playbookQuery.data?.suggestions.map(s => (
                  <div key={s.ip} className="flex items-center justify-between gap-2">
                    <span className="text-xs font-mono text-zinc-300">{s.ip}</span>
                    {s.already_blocked ? (
                      <span className="text-xs text-emerald-400">Bloklu</span>
                    ) : (
                      <button
                        onClick={() => { setBlockingIp(s.ip); setShowBlockDialog(true) }}
                        className="text-xs px-2 py-1 rounded border border-red-700/50 text-red-400 hover:bg-red-500/10"
                      >
                        Bu IP&apos;yi Blokla
                      </button>
                    )}
                  </div>
                ))}
                {playbookQuery.data?.suggestions.length === 0 && !playbookQuery.isLoading && (
                  <p className="text-xs text-zinc-600">Otomatik bloklama önerisi yok</p>
                )}
              </div>
            )}
            <EnrichmentPanel enrichment={selected.enrichment} incidentId={selected.incident_id} />
            <div>
              <p className="text-xs text-zinc-500 mb-1 font-medium uppercase tracking-wide">Event Timeline</p>
              <EventTimeline incidentId={selected.incident_id} />
            </div>
          </CardContent>
        </Card>
      )}

      {showBlockDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
          <div className="bg-zinc-900 border border-zinc-700 rounded-lg p-5 w-full max-w-md space-y-4">
            <h3 className="text-sm font-semibold text-zinc-100">IP Adresi Bloklama Onayı</h3>
            <p className="text-xs text-zinc-400">
              <span className="font-mono text-zinc-200">{blockingIp}</span> adresini firewall&apos;da bloklamak üzeresiniz.
            </p>
            <div className="space-y-1">
              <label className="text-xs text-zinc-500">Sebep (zorunlu)</label>
              <input
                value={blockReason}
                onChange={e => setBlockReason(e.target.value)}
                placeholder="Örn: SSH brute force saldırısı"
                className="w-full px-3 py-2 text-xs bg-zinc-800 border border-zinc-700 rounded text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-zinc-500"
              />
            </div>
            {blockMutation.isError && (
              <p className="text-xs text-red-400">Hata oluştu. Tekrar dene.</p>
            )}
            <div className="flex gap-2 justify-end">
              <button
                onClick={() => { setShowBlockDialog(false); setBlockReason('') }}
                className="text-xs px-3 py-1.5 rounded border border-zinc-700 text-zinc-400 hover:bg-zinc-800"
              >
                Vazgeç
              </button>
              <button
                disabled={!blockReason.trim() || blockMutation.isPending}
                onClick={() => blockingIp && blockMutation.mutate({ ip: blockingIp, reason: blockReason })}
                className="text-xs px-3 py-1.5 rounded bg-red-800 hover:bg-red-700 text-white disabled:opacity-50 disabled:cursor-not-allowed"
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
