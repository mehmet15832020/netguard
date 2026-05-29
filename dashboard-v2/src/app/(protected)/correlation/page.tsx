'use client'

import { useMemo, useState } from 'react'
import { GitMerge, Play, RefreshCw, ChevronDown, ChevronRight, AlertTriangle, CheckCircle2, Circle } from 'lucide-react'
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query'
import ReactECharts from 'echarts-for-react'
import { correlationApi } from '@/lib/api'
import { TOOLTIP_BASE } from '@/lib/echarts-theme'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import type { CorrelatedEvent, Severity } from '@/types/models'
import { cn } from '@/lib/utils'

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('tr-TR', {
    day: '2-digit', month: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

// ─── Rule Trigger Frequency Chart ────────────────────────────────────────────

function RuleTriggerChart({ events }: { events: CorrelatedEvent[] }) {
  const data = useMemo(() => {
    const freq: Record<string, { name: string; count: number; sev: string }> = {}
    events.forEach((e) => {
      if (!freq[e.rule_id]) freq[e.rule_id] = { name: e.rule_name, count: 0, sev: e.severity }
      freq[e.rule_id].count++
      if (e.severity === 'critical') freq[e.rule_id].sev = 'critical'
    })
    return Object.values(freq).sort((a, b) => b.count - a.count).slice(0, 10)
  }, [events])

  if (data.length === 0) return null

  const SEV_COLOR: Record<string, string> = {
    critical: '#ef4444', high: '#f97316', warning: '#eab308', info: '#6366f1',
  }

  const option = {
    backgroundColor: 'transparent',
    grid: { top: 4, right: 40, bottom: 4, left: 8, containLabel: true },
    tooltip: {
      ...TOOLTIP_BASE,
      trigger: 'axis', axisPointer: { type: 'shadow' },
      formatter: (params: { name: string; value: number }[]) =>
        `${params[0].name}: <b>${params[0].value}</b> tetiklenme`,
    },
    xAxis: {
      type: 'value', minInterval: 1,
      axisLabel: { color: '#475569', fontSize: 9 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
    },
    yAxis: {
      type: 'category',
      data: data.map((d) => d.name.length > 22 ? d.name.slice(0, 21) + '…' : d.name),
      axisLabel: { color: '#64748b', fontSize: 10 },
      axisLine: { show: false }, axisTick: { show: false },
      splitLine: { show: false },
    },
    series: [{
      type: 'bar', barMaxWidth: 18,
      data: data.map((d) => ({
        value: d.count,
        itemStyle: { color: SEV_COLOR[d.sev] ?? '#6366f1' },
      })),
      label: {
        show: true, position: 'right', color: '#64748b', fontSize: 10,
        formatter: (p: { value: number }) => String(p.value),
      },
    }],
  }

  return <ReactECharts option={option} style={{ height: data.length * 30 + 20 }} notMerge />
}

// ─── Severity Distribution Bars ───────────────────────────────────────────────

function SeverityDistBar({ events }: { events: CorrelatedEvent[] }) {
  const counts = useMemo(() => {
    const c: Record<string, number> = { critical: 0, high: 0, warning: 0, info: 0 }
    events.forEach((e) => { c[e.severity] = (c[e.severity] ?? 0) + 1 })
    return c
  }, [events])
  const total = events.length || 1
  const SEV = [
    { key: 'critical', label: 'Kritik',  color: 'bg-red-500',    text: 'text-red-400' },
    { key: 'high',     label: 'Yüksek',  color: 'bg-orange-500', text: 'text-orange-400' },
    { key: 'warning',  label: 'Uyarı',   color: 'bg-yellow-500', text: 'text-yellow-400' },
    { key: 'info',     label: 'Bilgi',   color: 'bg-indigo-500', text: 'text-indigo-400' },
  ]
  return (
    <div className="space-y-1.5">
      {SEV.map(({ key, label, color, text }) => (
        <div key={key} className="flex items-center gap-2">
          <span className={cn('text-[11px] w-12 flex-shrink-0', text)}>{label}</span>
          <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
            <div className={cn('h-full rounded-full', color)}
              style={{ width: `${(counts[key] ?? 0) / total * 100}%` }} />
          </div>
          <span className="text-[11px] font-mono text-zinc-500 w-5 text-right">{counts[key] ?? 0}</span>
        </div>
      ))}
    </div>
  )
}

// ─── Expandable event row ─────────────────────────────────────────────────────

function EventRow({ ev }: { ev: CorrelatedEvent }) {
  const [open, setOpen] = useState(false)
  return (
    <>
      <TableRow
        className={cn('border-zinc-800 cursor-pointer transition-colors', open ? 'bg-zinc-800/60' : 'hover:bg-zinc-800/50')}
        onClick={() => setOpen((o) => !o)}
      >
        <TableCell className="w-4 pr-0">
          {open ? <ChevronDown size={12} className="text-zinc-500" /> : <ChevronRight size={12} className="text-zinc-500" />}
        </TableCell>
        <TableCell><SeverityBadge severity={ev.severity as Severity} /></TableCell>
        <TableCell>
          <p className="text-sm text-zinc-200">{ev.rule_name}</p>
          <p className="text-xs text-zinc-500 font-mono">{ev.event_action}</p>
        </TableCell>
        <TableCell className="text-xs text-zinc-300 font-mono">{ev.group_value}</TableCell>
        <TableCell>
          <Badge className="bg-zinc-800 text-zinc-300 border border-zinc-700 text-xs">
            {ev.matched_count} olay
          </Badge>
        </TableCell>
        <TableCell className="text-xs text-zinc-500">{ev.window_seconds}s</TableCell>
        <TableCell className="text-xs text-zinc-500">{formatDate(ev.created_at)}</TableCell>
      </TableRow>
      {open && (
        <TableRow className="border-zinc-800 bg-zinc-900/80">
          <TableCell colSpan={7} className="px-6 py-3">
            <div className="space-y-2">
              {ev.message && (
                <p className="text-xs text-zinc-400">{ev.message}</p>
              )}
              <div className="grid grid-cols-2 gap-4 text-[11px] text-zinc-500">
                <div>
                  <span className="text-zinc-600">İlk: </span>
                  <span className="text-zinc-300">{formatDate(ev.first_seen)}</span>
                </div>
                <div>
                  <span className="text-zinc-600">Son: </span>
                  <span className="text-zinc-300">{formatDate(ev.last_seen)}</span>
                </div>
              </div>
              {(ev.mitre_tactics.length > 0 || ev.mitre_techniques.length > 0) && (
                <div className="flex flex-wrap gap-1 pt-1">
                  {ev.mitre_tactics.map((t) => (
                    <span key={t} className="px-1.5 py-0.5 rounded text-[10px] bg-purple-500/20 text-purple-300 border border-purple-800/50">
                      {t.replace(/_/g, ' ')}
                    </span>
                  ))}
                  {ev.mitre_techniques.map((t) => (
                    <a
                      key={t}
                      href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                      target="_blank" rel="noopener noreferrer"
                      onClick={(e) => e.stopPropagation()}
                      className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-800/50 hover:border-indigo-500"
                    >
                      {t}
                    </a>
                  ))}
                </div>
              )}
            </div>
          </TableCell>
        </TableRow>
      )}
    </>
  )
}

// ─── Ana sayfa ────────────────────────────────────────────────────────────────

export default function CorrelationPage() {
  const queryClient = useQueryClient()

  const { data: eventsData, isLoading, isFetching } = useQuery({
    queryKey: ['correlated-events'],
    queryFn:  () => correlationApi.listEvents({ limit: 200 }),
    refetchInterval: 30_000,
  })

  const { data: rulesData } = useQuery({
    queryKey: ['correlation-rules'],
    queryFn:  () => correlationApi.listRules(),
  })

  const runMutation = useMutation({
    mutationFn: () => correlationApi.runNow(),
    onSuccess:  () => queryClient.invalidateQueries({ queryKey: ['correlated-events'] }),
  })

  const reloadMutation = useMutation({
    mutationFn: () => correlationApi.reloadRules(),
    onSuccess:  () => queryClient.invalidateQueries({ queryKey: ['correlation-rules'] }),
  })

  const events = eventsData?.events ?? []
  const rules  = rulesData?.rules ?? []

  const criticalCount = events.filter((e) => e.severity === 'critical').length
  const enabledRules  = rules.filter((r) => r.enabled).length

  const mostTriggered = useMemo(() => {
    const freq: Record<string, number> = {}
    events.forEach((e) => { freq[e.rule_name] = (freq[e.rule_name] ?? 0) + 1 })
    const top = Object.entries(freq).sort((a, b) => b[1] - a[1])[0]
    return top ? { name: top[0], count: top[1] } : null
  }, [events])

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-zinc-100 flex items-center gap-2">
            <GitMerge size={18} /> Korelasyon
          </h1>
          <p className="text-sm text-zinc-500 mt-0.5">
            {eventsData?.count ?? 0} olay · {rules.length} kural ({enabledRules} aktif)
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline" size="sm"
            onClick={() => queryClient.invalidateQueries({ queryKey: ['correlated-events'] })}
            disabled={isFetching}
            className="border-zinc-700 text-zinc-300 hover:bg-zinc-800"
          >
            <RefreshCw size={14} className={isFetching ? 'animate-spin' : ''} />
            <span className="ml-1.5">Yenile</span>
          </Button>
          <Button
            size="sm"
            onClick={() => runMutation.mutate()}
            disabled={runMutation.isPending}
            className="bg-indigo-600 hover:bg-indigo-500 text-white"
          >
            <Play size={14} />
            <span className="ml-1.5">{runMutation.isPending ? 'Çalışıyor…' : 'Şimdi Çalıştır'}</span>
          </Button>
        </div>
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          { label: 'Toplam Olay',    value: eventsData?.count ?? 0, color: 'text-zinc-100' },
          { label: 'Kritik',         value: criticalCount,           color: 'text-red-400' },
          { label: 'Aktif Kural',    value: enabledRules,            color: 'text-emerald-400' },
          { label: 'Pasif Kural',    value: rules.length - enabledRules, color: 'text-zinc-500' },
        ].map(({ label, value, color }) => (
          <Card key={label} className="bg-zinc-900 border-zinc-800">
            <CardContent className="pt-4 pb-4">
              <p className="text-xs text-zinc-500 mb-1">{label}</p>
              <p className={cn('text-2xl font-bold', color)}>{isLoading ? '—' : value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      {/* Charts row */}
      {events.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          {/* Rule trigger frequency */}
          <div className="lg:col-span-2 bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-zinc-800">
              <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">
                Kural Tetiklenme Sıklığı
              </p>
              {mostTriggered && (
                <p className="text-[11px] text-zinc-600 mt-0.5">
                  En çok: <span className="text-zinc-400">{mostTriggered.name}</span> ({mostTriggered.count}×)
                </p>
              )}
            </div>
            <div className="p-3">
              <RuleTriggerChart events={events} />
            </div>
          </div>

          {/* Severity distribution */}
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-zinc-800">
              <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">Severity Dağılımı</p>
            </div>
            <div className="p-4">
              <SeverityDistBar events={events} />
            </div>

            {/* Last run info */}
            {runMutation.data && (
              <div className="px-4 pb-3">
                <p className="text-[11px] text-zinc-600 border-t border-zinc-800 pt-3">
                  Son çalıştırma: <span className="text-zinc-400">{runMutation.data.triggered} tetiklenme</span>
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      <Tabs defaultValue="events">
        <TabsList className="bg-zinc-900 border border-zinc-800">
          <TabsTrigger value="events" className="text-xs data-[state=active]:bg-zinc-800 data-[state=active]:text-zinc-100">
            Olaylar ({events.length})
          </TabsTrigger>
          <TabsTrigger value="rules" className="text-xs data-[state=active]:bg-zinc-800 data-[state=active]:text-zinc-100">
            Kurallar ({rules.length})
          </TabsTrigger>
        </TabsList>

        {/* Events tab */}
        <TabsContent value="events">
          <Card className="bg-zinc-900 border-zinc-800">
            <CardContent className="p-0">
              {isLoading ? (
                <p className="text-zinc-500 text-sm text-center py-10">Yükleniyor…</p>
              ) : events.length === 0 ? (
                <div className="flex flex-col items-center py-12 text-zinc-600 gap-2">
                  <CheckCircle2 size={24} className="text-emerald-700 opacity-50" />
                  <p className="text-sm">Korelasyon olayı yok</p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow className="border-zinc-800 hover:bg-transparent">
                      <TableHead className="w-4" />
                      <TableHead className="text-zinc-500 text-xs w-24">Seviye</TableHead>
                      <TableHead className="text-zinc-500 text-xs">Kural</TableHead>
                      <TableHead className="text-zinc-500 text-xs w-40">Grup Değeri</TableHead>
                      <TableHead className="text-zinc-500 text-xs w-24">Eşleşme</TableHead>
                      <TableHead className="text-zinc-500 text-xs w-20">Pencere</TableHead>
                      <TableHead className="text-zinc-500 text-xs w-36">Zaman</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {events.map((ev) => <EventRow key={ev.corr_id} ev={ev} />)}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Rules tab */}
        <TabsContent value="rules">
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm text-zinc-300">Aktif Kurallar</CardTitle>
                <Button
                  variant="outline" size="sm"
                  onClick={() => reloadMutation.mutate()}
                  disabled={reloadMutation.isPending}
                  className="border-zinc-700 text-zinc-300 hover:bg-zinc-800 text-xs"
                >
                  {reloadMutation.isPending ? 'Yükleniyor…' : 'Kuralları Yeniden Yükle'}
                </Button>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              {rules.length === 0 ? (
                <div className="flex flex-col items-center py-12 text-zinc-600 gap-2">
                  <AlertTriangle size={24} className="opacity-40" />
                  <p className="text-sm">Kural bulunamadı</p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow className="border-zinc-800 hover:bg-transparent">
                      <TableHead className="text-zinc-500 text-xs w-16">Durum</TableHead>
                      <TableHead className="text-zinc-500 text-xs">Kural Adı</TableHead>
                      <TableHead className="text-zinc-500 text-xs w-32">Eşleşen Tip</TableHead>
                      <TableHead className="text-zinc-500 text-xs w-24">Grup</TableHead>
                      <TableHead className="text-zinc-500 text-xs w-20">Pencere</TableHead>
                      <TableHead className="text-zinc-500 text-xs w-16">Eşik</TableHead>
                      <TableHead className="text-zinc-500 text-xs w-24">Seviye</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {rules.map((rule) => (
                      <TableRow key={rule.rule_id} className="border-zinc-800 hover:bg-zinc-800/50">
                        <TableCell>
                          {rule.enabled
                            ? <CheckCircle2 size={14} className="text-emerald-500" />
                            : <Circle size={14} className="text-zinc-600" />}
                        </TableCell>
                        <TableCell>
                          <p className="text-sm text-zinc-200">{rule.name}</p>
                          {rule.description && (
                            <p className="text-xs text-zinc-500 mt-0.5">{rule.description}</p>
                          )}
                        </TableCell>
                        <TableCell className="text-xs text-zinc-400 font-mono">{rule.match_event_action}</TableCell>
                        <TableCell className="text-xs text-zinc-400">{rule.group_by}</TableCell>
                        <TableCell className="text-xs text-zinc-400">{rule.window_seconds}s</TableCell>
                        <TableCell className="text-xs text-zinc-400">{rule.threshold}</TableCell>
                        <TableCell><SeverityBadge severity={rule.severity} /></TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
