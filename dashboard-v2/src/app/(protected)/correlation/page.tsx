'use client'

import { useMemo, useState } from 'react'
import { GitMerge, Play, RefreshCw, ChevronDown, ChevronRight, AlertTriangle, CheckCircle2, Circle, Sparkles, X } from 'lucide-react'
import { useQuery, useQueryClient, useMutation } from '@tanstack/react-query'
import ReactECharts from 'echarts-for-react'
import { correlationApi, type AlertExplanation } from '@/lib/api'
import { TOOLTIP_BASE } from '@/lib/echarts-theme'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { SkeletonTable } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import type { CorrelatedEvent, Severity } from '@/types/models'

function formatDate(iso: string) {
  return new Date(iso).toLocaleString('tr-TR', {
    day: '2-digit', month: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

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
    critical: '#ef4444', high: '#f97316', warning: '#eab308', info: '#38bdf8',
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
        itemStyle: { color: SEV_COLOR[d.sev] ?? '#38bdf8' },
      })),
      label: {
        show: true, position: 'right', color: '#64748b', fontSize: 10,
        formatter: (p: { value: number }) => String(p.value),
      },
    }],
  }

  return <ReactECharts option={option} style={{ height: data.length * 30 + 20 }} notMerge />
}

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
    { key: 'info',     label: 'Bilgi',   color: 'bg-sky-500',    text: 'text-sky-400' },
  ]
  return (
    <div className="space-y-1.5">
      {SEV.map(({ key, label, color, text }) => (
        <div key={key} className="flex items-center gap-2">
          <span className={`text-[11px] w-12 flex-shrink-0 ${text}`}>{label}</span>
          <div className="flex-1 h-1.5 bg-sky-950/30 rounded-full overflow-hidden">
            <div className={`h-full rounded-full ${color}`}
              style={{ width: `${(counts[key] ?? 0) / total * 100}%` }} />
          </div>
          <span className="text-[11px] font-mono text-slate-500 w-5 text-right">{counts[key] ?? 0}</span>
        </div>
      ))}
    </div>
  )
}

function ExplainPanel({ corr_id, onClose }: { corr_id: string; onClose: () => void }) {
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['explain', corr_id],
    queryFn: () => correlationApi.explainEvent(corr_id),
    retry: false,
    staleTime: 24 * 60 * 60 * 1000,
  })

  return (
    <div className="bg-[#080f1e] border border-violet-500/30 rounded-xl p-4 space-y-3 mt-2">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Sparkles size={13} className="text-violet-400" />
          <span className="text-xs font-semibold text-violet-300">AI Analiz</span>
          {data?.cached && (
            <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-500">
              önbellekten
            </span>
          )}
        </div>
        <button onClick={onClose} className="text-slate-600 hover:text-slate-400 transition-colors">
          <X size={13} />
        </button>
      </div>

      {isLoading && (
        <div className="space-y-2 animate-pulse">
          <div className="h-3 bg-slate-800 rounded w-3/4" />
          <div className="h-3 bg-slate-800 rounded w-full" />
          <div className="h-3 bg-slate-800 rounded w-5/6" />
          <div className="h-3 bg-slate-800 rounded w-2/3" />
        </div>
      )}

      {isError && (
        <p className="text-xs text-red-400">
          {(error as Error)?.message?.includes('503')
            ? 'ANTHROPIC_API_KEY tanımlı değil veya servis erişilemez.'
            : 'Açıklama üretilemedi. Tekrar deneyin.'}
        </p>
      )}

      {data && (
        <div className="space-y-3">
          <div className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">
            {data.explanation}
          </div>
          <div className="flex items-center gap-3 pt-1 border-t border-violet-900/20 text-[10px] text-slate-600">
            <span>{data.model.split('-').slice(0, 2).join('-')}</span>
            <span>{data.input_tokens} in / {data.output_tokens} out tokens</span>
          </div>
        </div>
      )}
    </div>
  )
}

function EventRow({ ev }: { ev: CorrelatedEvent }) {
  const [open, setOpen]       = useState(false)
  const [showAI, setShowAI]   = useState(false)

  return (
    <>
      <tr
        className={cn('cursor-pointer transition-colors', open ? 'bg-sky-950/20' : 'hover:bg-sky-950/20')}
        onClick={() => setOpen((o) => !o)}
      >
        <td className="ui-td w-6">
          {open
            ? <ChevronDown size={12} className="text-slate-500" />
            : <ChevronRight size={12} className="text-slate-500" />}
        </td>
        <td className="ui-td w-24"><SeverityBadge severity={ev.severity as Severity} /></td>
        <td className="ui-td">
          <p className="text-sm text-slate-200">{ev.rule_name}</p>
          <p className="text-xs text-slate-500 font-mono">{ev.event_action}</p>
        </td>
        <td className="ui-td text-xs text-slate-300 font-mono w-40">{ev.group_value}</td>
        <td className="ui-td w-24">
          <span className="px-2 py-0.5 rounded border border-sky-900/20 bg-sky-950/30 text-xs text-slate-300">
            {ev.matched_count} olay
          </span>
        </td>
        <td className="ui-td text-xs text-slate-500 w-20">{ev.window_seconds}s</td>
        <td className="ui-td text-xs text-slate-500 w-36">{formatDate(ev.created_at)}</td>
      </tr>
      {open && (
        <tr className="bg-sky-950/10">
          <td colSpan={7} className="px-6 py-3">
            <div className="space-y-2">
              {ev.message && (
                <p className="text-xs text-slate-400">{ev.message}</p>
              )}
              <div className="grid grid-cols-2 gap-4 text-[11px] text-slate-500">
                <div>
                  <span className="text-slate-600">İlk: </span>
                  <span className="text-slate-300">{formatDate(ev.first_seen)}</span>
                </div>
                <div>
                  <span className="text-slate-600">Son: </span>
                  <span className="text-slate-300">{formatDate(ev.last_seen)}</span>
                </div>
              </div>
              {(ev.mitre_tactics.length > 0 || ev.mitre_techniques.length > 0) && (
                <div className="flex flex-wrap gap-1 pt-1">
                  {ev.mitre_tactics.map((t) => (
                    <span key={t} className="px-1.5 py-0.5 rounded text-[10px] bg-violet-500/15 text-violet-300 border border-violet-500/25">
                      {t.replace(/_/g, ' ')}
                    </span>
                  ))}
                  {ev.mitre_techniques.map((t) => (
                    <a
                      key={t}
                      href={`https://attack.mitre.org/techniques/${t.replace('.', '/')}/`}
                      target="_blank" rel="noopener noreferrer"
                      onClick={(e) => e.stopPropagation()}
                      className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-sky-500/15 text-sky-300 border border-sky-500/25 hover:border-sky-400/50 transition-colors"
                    >
                      {t}
                    </a>
                  ))}
                </div>
              )}

              {/* AI Explain button + panel */}
              <div className="pt-1">
                <button
                  onClick={(e) => { e.stopPropagation(); setShowAI((s) => !s) }}
                  className={cn(
                    'flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] border transition-colors',
                    showAI
                      ? 'bg-violet-500/15 border-violet-500/30 text-violet-300'
                      : 'bg-sky-950/20 border-sky-900/20 text-slate-500 hover:text-slate-300 hover:border-sky-800/40',
                  )}
                >
                  <Sparkles size={11} />
                  {showAI ? 'Kapat' : 'AI ile Açıkla'}
                </button>
                {showAI && (
                  <ExplainPanel corr_id={ev.corr_id} onClose={() => setShowAI(false)} />
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

export default function CorrelationPage() {
  const queryClient = useQueryClient()
  const [tab, setTab] = useState<'events' | 'rules'>('events')

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

  const TABS = [
    { key: 'events', label: `Olaylar (${events.length})` },
    { key: 'rules',  label: `Kurallar (${rules.length})` },
  ] as const

  return (
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
            <GitMerge size={15} className="text-sky-400" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-slate-100 leading-tight">Korelasyon</h1>
            <p className="text-xs text-slate-600">
              {eventsData?.count ?? 0} olay · {rules.length} kural ({enabledRules} aktif)
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => queryClient.invalidateQueries({ queryKey: ['correlated-events'] })}
            disabled={isFetching}
            className="ui-btn ui-btn-secondary"
          >
            <RefreshCw size={12} className={isFetching ? 'animate-spin' : ''} />
            Yenile
          </button>
          <button
            onClick={() => runMutation.mutate()}
            disabled={runMutation.isPending}
            className="ui-btn ui-btn-primary"
          >
            <Play size={12} />
            {runMutation.isPending ? 'Çalışıyor…' : 'Şimdi Çalıştır'}
          </button>
        </div>
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          { label: 'Toplam Olay',  value: eventsData?.count ?? 0, color: 'text-slate-100' },
          { label: 'Kritik',       value: criticalCount,           color: 'text-red-400' },
          { label: 'Aktif Kural',  value: enabledRules,            color: 'text-emerald-400' },
          { label: 'Pasif Kural',  value: rules.length - enabledRules, color: 'text-slate-500' },
        ].map(({ label, value, color }) => (
          <div key={label} className="ui-panel p-4">
            <p className="text-xs text-slate-500 mb-1">{label}</p>
            <p className={`text-3xl font-bold leading-none ${color}`}>{isLoading ? '—' : value}</p>
          </div>
        ))}
      </div>

      {/* Charts row */}
      {events.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2 ui-panel">
            <div className="ui-panel-header">
              <p className="ui-section-label">
                Kural Tetiklenme Sıklığı
              </p>
              {mostTriggered && (
                <p className="text-[11px] text-slate-600 mt-0.5">
                  En çok: <span className="text-slate-400">{mostTriggered.name}</span> ({mostTriggered.count}×)
                </p>
              )}
            </div>
            <div className="p-3">
              <RuleTriggerChart events={events} />
            </div>
          </div>

          <div className="ui-panel">
            <div className="ui-panel-header">
              <p className="ui-section-label">Severity Dağılımı</p>
            </div>
            <div className="p-4">
              <SeverityDistBar events={events} />
            </div>
            {runMutation.data && (
              <div className="px-4 pb-3">
                <p className="text-[11px] text-slate-600 border-t border-sky-900/15 pt-3">
                  Son çalıştırma: <span className="text-slate-400">{runMutation.data.triggered} tetiklenme</span>
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tabs */}
      <div>
        <div className="flex gap-1.5 mb-3">
          {TABS.map(({ key, label }) => (
            <button
              key={key}
              onClick={() => setTab(key)}
              className={`px-3 py-1 rounded-lg text-xs font-medium border transition-colors ${
                tab === key
                  ? 'bg-sky-500/15 border-sky-500/30 text-sky-300'
                  : 'bg-sky-950/20 border-sky-900/20 text-slate-500 hover:text-slate-300'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* Events tab */}
        {tab === 'events' && (
          <div className="ui-panel">
            {isLoading ? (
              <div className="p-4">
                <SkeletonTable rows={6} height={44} />
              </div>
            ) : events.length === 0 ? (
              <div className="flex flex-col items-center py-12 text-slate-700 gap-2">
                <CheckCircle2 size={24} className="text-emerald-700 opacity-50" />
                <p className="text-sm">Korelasyon olayı yok</p>
              </div>
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="border-b border-sky-900/20">
                    <th className="ui-th w-6" />
                    <th className="ui-th w-24">Seviye</th>
                    <th className="ui-th">Kural</th>
                    <th className="ui-th w-40">Grup Değeri</th>
                    <th className="ui-th w-24">Eşleşme</th>
                    <th className="ui-th w-20">Pencere</th>
                    <th className="ui-th w-36">Zaman</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-sky-900/10">
                  {events.map((ev) => <EventRow key={ev.corr_id} ev={ev} />)}
                </tbody>
              </table>
            )}
          </div>
        )}

        {/* Rules tab */}
        {tab === 'rules' && (
          <div className="ui-panel">
            <div className="ui-panel-header justify-between">
              <span className="text-xs font-medium text-slate-400">Aktif Kurallar</span>
              <button
                onClick={() => reloadMutation.mutate()}
                disabled={reloadMutation.isPending}
                className="ui-btn ui-btn-secondary"
              >
                {reloadMutation.isPending
                  ? <><RefreshCw size={11} className="animate-spin" />Yükleniyor…</>
                  : 'Kuralları Yeniden Yükle'
                }
              </button>
            </div>
            {rules.length === 0 ? (
              <div className="flex flex-col items-center py-12 text-slate-700 gap-2">
                <AlertTriangle size={24} className="opacity-40" />
                <p className="text-sm">Kural bulunamadı</p>
              </div>
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="border-b border-sky-900/20">
                    <th className="ui-th w-16">Durum</th>
                    <th className="ui-th">Kural Adı</th>
                    <th className="ui-th w-32">Eşleşen Tip</th>
                    <th className="ui-th w-24">Grup</th>
                    <th className="ui-th w-20">Pencere</th>
                    <th className="ui-th w-16">Eşik</th>
                    <th className="ui-th w-24">Seviye</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-sky-900/10">
                  {rules.map((rule) => (
                    <tr key={rule.rule_id} className="hover:bg-sky-950/20 transition-colors">
                      <td className="ui-td">
                        {rule.enabled
                          ? <CheckCircle2 size={14} className="text-emerald-500" />
                          : <Circle size={14} className="text-slate-600" />}
                      </td>
                      <td className="ui-td">
                        <p className="text-sm text-slate-200">{rule.name}</p>
                        {rule.description && (
                          <p className="text-xs text-slate-500 mt-0.5">{rule.description}</p>
                        )}
                      </td>
                      <td className="ui-td text-xs text-slate-400 font-mono">{rule.match_event_action}</td>
                      <td className="ui-td text-xs text-slate-400">{rule.group_by}</td>
                      <td className="ui-td text-xs text-slate-400">{rule.window_seconds}s</td>
                      <td className="ui-td text-xs text-slate-400">{rule.threshold}</td>
                      <td className="ui-td"><SeverityBadge severity={rule.severity} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
