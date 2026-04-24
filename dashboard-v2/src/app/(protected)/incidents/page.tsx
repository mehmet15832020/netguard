'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ShieldAlert, RefreshCw, Plus, X } from 'lucide-react'
import { incidentApi, type Incident, type IncidentEvent } from '@/lib/api'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'

const SEV_DOT: Record<string, string> = {
  critical: 'bg-red-500',
  warning:  'bg-yellow-500',
  info:     'bg-blue-500',
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
              <span className="uppercase">{ev.event_type}</span>
            </p>
          </div>
        </div>
      ))}
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

function SummaryCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <Card className="bg-zinc-900 border-zinc-800">
      <CardContent className="pt-4 pb-4">
        <p className="text-xs text-zinc-400 mb-1">{label}</p>
        <p className={`text-2xl font-bold ${color}`}>{value}</p>
      </CardContent>
    </Card>
  )
}

export default function IncidentsPage() {
  const qc = useQueryClient()
  const [statusFilter, setStatusFilter]     = useState('all')
  const [severityFilter, setSeverityFilter] = useState('all')
  const [showCreate, setShowCreate]         = useState(false)
  const [newTitle, setNewTitle]             = useState('')
  const [newSeverity, setNewSeverity]       = useState('warning')
  const [newDesc, setNewDesc]               = useState('')
  const [selected, setSelected]             = useState<Incident | null>(null)
  const [editNotes, setEditNotes]           = useState('')

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
    mutationFn: (body: { id: string; status?: string; notes?: string; assigned_to?: string }) =>
      incidentApi.update(body.id, { status: body.status, notes: body.notes, assigned_to: body.assigned_to }),
    onSuccess: (updated) => {
      qc.invalidateQueries({ queryKey: ['incidents'] })
      qc.invalidateQueries({ queryKey: ['incident-summary'] })
      setSelected(updated)
    },
  })

  const incidents = data?.incidents ?? []

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
          <Button size="sm" onClick={() => setShowCreate(true)}>
            <Plus className="w-4 h-4 mr-1" /> Yeni Incident
          </Button>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <SummaryCard label="Toplam"      value={summary?.total         ?? 0} color="text-zinc-200" />
        <SummaryCard label="Açık"        value={summary?.open          ?? 0} color="text-red-400" />
        <SummaryCard label="İnceleniyor" value={summary?.investigating ?? 0} color="text-yellow-400" />
        <SummaryCard label="Çözüldü"     value={summary?.resolved      ?? 0} color="text-emerald-400" />
      </div>

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
                <TableHead>Severity</TableHead>
                <TableHead>Durum</TableHead>
                <TableHead>Atanan</TableHead>
                <TableHead>Oluşturan</TableHead>
                <TableHead>Tarih</TableHead>
                <TableHead></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {isLoading ? (
                <TableRow><TableCell colSpan={7} className="text-center text-zinc-500 py-8">Yükleniyor...</TableCell></TableRow>
              ) : incidents.length === 0 ? (
                <TableRow><TableCell colSpan={7} className="text-center text-zinc-500 py-8">Incident bulunamadı</TableCell></TableRow>
              ) : incidents.map(inc => (
                <TableRow key={inc.incident_id} className="border-zinc-800 hover:bg-zinc-800/50">
                  <TableCell className="font-medium max-w-xs truncate">{inc.title}</TableCell>
                  <TableCell className={`font-mono text-xs uppercase ${SEV_COLORS[inc.severity] ?? ''}`}>
                    {inc.severity}
                  </TableCell>
                  <TableCell>
                    <span className={`px-2 py-0.5 rounded text-xs font-medium ${STATUS_COLORS[inc.status] ?? ''}`}>
                      {STATUS_LABELS[inc.status] ?? inc.status}
                    </span>
                  </TableCell>
                  <TableCell className="text-zinc-400 text-sm">{inc.assigned_to ?? '—'}</TableCell>
                  <TableCell className="text-zinc-400 text-sm">{inc.created_by}</TableCell>
                  <TableCell className="text-zinc-500 text-xs">
                    {new Date(inc.created_at).toLocaleString('tr-TR')}
                  </TableCell>
                  <TableCell>
                    <Button variant="ghost" size="sm" onClick={() => { setSelected(inc); setEditNotes(inc.notes ?? '') }}>
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
            <div className="flex gap-3 flex-wrap">
              <div>
                <p className="text-xs text-zinc-500 mb-1">Durum Değiştir</p>
                <Select
                  value={selected.status}
                  onValueChange={v => { if (v) updateMutation.mutate({ id: selected.incident_id, status: v }) }}
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
            {selected.resolved_at && (
              <p className="text-xs text-zinc-500">
                Çözüm: {new Date(selected.resolved_at).toLocaleString('tr-TR')}
              </p>
            )}
            <div>
              <p className="text-xs text-zinc-500 mb-1 font-medium uppercase tracking-wide">Event Timeline</p>
              <EventTimeline incidentId={selected.incident_id} />
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
