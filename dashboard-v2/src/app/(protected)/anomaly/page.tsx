'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, AlertTriangle, RefreshCw, ChevronDown, ChevronUp, Shield, X, ExternalLink } from 'lucide-react'
import ReactECharts from 'echarts-for-react'
import { anomalyApi, fpRulesApi } from '@/lib/api'
import type { AnomalyResult } from '@/lib/api'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'
import { Input } from '@/components/ui/input'
import { cn } from '@/lib/utils'

// ─── Sabitler ────────────────────────────────────────────────────────────────

const SEV_META = {
  critical: { label: 'Kritik',  cls: 'text-red-400 bg-red-950/40 border-red-900',     bar: 'bg-red-500' },
  high:     { label: 'Yüksek', cls: 'text-orange-400 bg-orange-950/40 border-orange-900', bar: 'bg-orange-500' },
  warning:  { label: 'Uyarı',  cls: 'text-yellow-400 bg-yellow-950/40 border-yellow-900', bar: 'bg-yellow-500' },
}

const METRIC_LABELS: Record<string, string> = {
  fw_block_rate:     'FW Blok Hızı',
  conn_rate:         'Bağlantı Hızı',
  unique_dst_ips:    'Benzersiz Hedef IP',
  unique_dst_ports:  'Benzersiz Hedef Port',
  auth_failure_rate: 'Auth Hata Hızı',
}

// MITRE ATT&CK T-no ve açıklama — kaynak: MITRE ATT&CK v17
const METRIC_MITRE: Record<string, { id: string; name: string }> = {
  unique_dst_ports:  { id: 'T1046',  name: 'Network Service Discovery' },
  unique_dst_ips:    { id: 'T1046',  name: 'Network Service Discovery' },
  conn_rate:         { id: 'T1071',  name: 'Application Layer Protocol' },
  auth_failure_rate: { id: 'T1110',  name: 'Brute Force' },
  fw_block_rate:     { id: 'T1562',  name: 'Impair Defenses' },
}

const HOURS_OPTIONS = [6, 24, 48, 168] as const

// ─── Z-Score bar ─────────────────────────────────────────────────────────────

function ZScoreBar({ z }: { z: number }) {
  const clamped = Math.min(Math.abs(z), 6)
  const pct     = (clamped / 6) * 100
  const color   = z >= 4.5 ? 'bg-red-500' : z >= 3.5 ? 'bg-orange-500' : 'bg-yellow-500'
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-zinc-700 rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full', color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-zinc-400">{z.toFixed(1)}σ</span>
    </div>
  )
}

// ─── Warmup badge ─────────────────────────────────────────────────────────────

function WarmupBadge({ entityId }: { entityId: string }) {
  const { data } = useQuery({
    queryKey: ['anomaly', 'warmup', entityId],
    queryFn:  () => anomalyApi.warmupStatus(entityId),
    staleTime: 60_000,
  })
  if (!data) return null
  const pct = data.progress_pct
  const color = data.warmed_up ? 'bg-emerald-500' : pct > 60 ? 'bg-yellow-500' : 'bg-zinc-500'
  return (
    <div className="flex items-center gap-1.5" title={`${data.sample_count}/${data.needed} örnek`}>
      <div className="w-12 h-1 bg-zinc-700 rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full', color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-zinc-500">{pct}%</span>
    </div>
  )
}

// ─── Z-Score Distribution Histogram ──────────────────────────────────────────

function ZScoreHistogram({ results }: { results: AnomalyResult[] }) {
  const bins = useMemo(() => {
    const labels = ['3-3.5σ', '3.5-4σ', '4-4.5σ', '4.5-5σ', '>5σ']
    const counts = [0, 0, 0, 0, 0]
    results.forEach((r) => {
      const z = r.z_score
      if (z < 3.5)      counts[0]++
      else if (z < 4)   counts[1]++
      else if (z < 4.5) counts[2]++
      else if (z < 5)   counts[3]++
      else               counts[4]++
    })
    return { labels, counts }
  }, [results])

  const option = {
    backgroundColor: 'transparent',
    grid: { top: 8, right: 8, bottom: 28, left: 36 },
    tooltip: {
      trigger: 'axis',
      backgroundColor: '#18181b', borderColor: '#3f3f46',
      textStyle: { color: '#f4f4f5', fontSize: 11 },
      formatter: (params: { name: string; value: number }[]) =>
        `${params[0].name}: ${params[0].value} anomali`,
    },
    xAxis: {
      type: 'category', data: bins.labels,
      axisLabel: { color: '#71717a', fontSize: 9 },
      axisLine: { lineStyle: { color: '#3f3f46' } },
      splitLine: { show: false },
    },
    yAxis: {
      type: 'value', minInterval: 1,
      axisLabel: { color: '#71717a', fontSize: 9 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: '#27272a' } },
    },
    series: [{
      type: 'bar', barMaxWidth: 32,
      data: bins.counts.map((v, i) => ({
        value: v,
        itemStyle: { color: ['#eab308', '#f97316', '#ef4444', '#dc2626', '#b91c1c'][i] },
      })),
    }],
  }

  return <ReactECharts option={option} style={{ height: 130 }} notMerge />
}

// ─── Anomaly Timeline Scatter ─────────────────────────────────────────────────

function AnomalyTimeline({ results }: { results: AnomalyResult[] }) {
  const data = useMemo(() => results.map((r) => {
    const color = r.severity === 'critical' ? '#ef4444'
                : r.severity === 'high'     ? '#f97316'
                :                             '#eab308'
    return {
      value: [new Date(r.detected_at).getTime(), r.z_score, r.entity_id, r.metric],
      itemStyle: { color },
    }
  }), [results])

  const option = {
    backgroundColor: 'transparent',
    grid: { top: 8, right: 8, bottom: 32, left: 52 },
    tooltip: {
      trigger: 'item',
      backgroundColor: '#18181b', borderColor: '#3f3f46',
      textStyle: { color: '#f4f4f5', fontSize: 11 },
      formatter: (p: { value: [number, number, string, string] }) => {
        const [ts, z, ip, metric] = p.value
        return `${ip}<br/>${METRIC_LABELS[metric] ?? metric}<br/>Z-Score: ${z.toFixed(1)}σ<br/>${new Date(ts).toLocaleString('tr-TR')}`
      },
    },
    xAxis: {
      type: 'time',
      axisLabel: { color: '#71717a', fontSize: 9, formatter: (v: number) =>
        new Date(v).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' }) },
      axisLine: { lineStyle: { color: '#3f3f46' } },
      splitLine: { lineStyle: { color: '#27272a', type: 'dashed' } },
    },
    yAxis: {
      type: 'value', name: 'Z-Score',
      nameTextStyle: { color: '#71717a', fontSize: 9 },
      axisLabel: { color: '#71717a', fontSize: 9, formatter: (v: number) => `${v}σ` },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: '#27272a' } },
    },
    series: [{
      type: 'scatter', symbolSize: 7,
      data,
      emphasis: { itemStyle: { borderWidth: 2, borderColor: '#fff' } },
    }],
  }

  return <ReactECharts option={option} style={{ height: 140 }} notMerge />
}

// ─── Metric Breakdown ─────────────────────────────────────────────────────────

function MetricBreakdownChart({ results }: { results: AnomalyResult[] }) {
  const data = useMemo(() => {
    const freq: Record<string, number> = {}
    results.forEach((r) => { freq[r.metric] = (freq[r.metric] ?? 0) + 1 })
    return Object.entries(freq)
      .sort((a, b) => b[1] - a[1])
      .map(([k, v]) => ({ label: METRIC_LABELS[k] ?? k, value: v }))
  }, [results])

  const option = {
    backgroundColor: 'transparent',
    grid: { top: 4, right: 40, bottom: 4, left: 8, containLabel: true },
    tooltip: {
      trigger: 'axis', axisPointer: { type: 'shadow' },
      backgroundColor: '#18181b', borderColor: '#3f3f46',
      textStyle: { color: '#f4f4f5', fontSize: 11 },
    },
    xAxis: {
      type: 'value', minInterval: 1,
      axisLabel: { color: '#71717a', fontSize: 9 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: '#27272a' } },
    },
    yAxis: {
      type: 'category',
      data: data.map((d) => d.label),
      axisLabel: { color: '#a1a1aa', fontSize: 10 },
      axisLine: { lineStyle: { color: '#3f3f46' } },
      splitLine: { show: false },
    },
    series: [{
      type: 'bar', barMaxWidth: 18,
      data: data.map((d) => d.value),
      itemStyle: { color: '#6366f1' },
      label: { show: true, position: 'right', color: '#71717a', fontSize: 10 },
    }],
  }

  return <ReactECharts option={option} style={{ height: data.length * 32 + 16 }} notMerge />
}

// ─── Top Offending IPs ────────────────────────────────────────────────────────

function TopOffendersTable({ results, onSelectIp }: { results: AnomalyResult[]; onSelectIp: (ip: string) => void }) {
  const rows = useMemo(() => {
    const map: Record<string, { count: number; maxZ: number; severity: string }> = {}
    results.forEach((r) => {
      if (!map[r.entity_id]) map[r.entity_id] = { count: 0, maxZ: 0, severity: 'warning' }
      map[r.entity_id].count++
      if (r.z_score > map[r.entity_id].maxZ) {
        map[r.entity_id].maxZ = r.z_score
        map[r.entity_id].severity = r.severity
      }
    })
    return Object.entries(map)
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 5)
  }, [results])

  if (rows.length === 0) return null

  return (
    <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
      <div className="px-4 py-3 border-b border-zinc-800">
        <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">En Aktif IP&apos;ler</p>
        <p className="text-[11px] text-zinc-600 mt-0.5">En çok anomali üreten kaynak IP&apos;ler</p>
      </div>
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-zinc-800 text-zinc-500 uppercase">
            <th className="text-left px-4 py-2">IP</th>
            <th className="text-left px-4 py-2">Anomali</th>
            <th className="text-left px-4 py-2">Max Z-Score</th>
            <th className="text-left px-4 py-2">Seviye</th>
            <th className="px-4 py-2"></th>
          </tr>
        </thead>
        <tbody className="divide-y divide-zinc-800/50">
          {rows.map(([ip, { count, maxZ, severity }]) => {
            const m = SEV_META[severity as keyof typeof SEV_META]
            return (
              <tr key={ip} className="hover:bg-zinc-800/30 transition-colors">
                <td className="px-4 py-2.5 font-mono text-zinc-200">{ip}</td>
                <td className="px-4 py-2.5 text-zinc-300 font-semibold">{count}</td>
                <td className="px-4 py-2.5 font-mono text-zinc-300">{maxZ.toFixed(1)}σ</td>
                <td className="px-4 py-2.5">
                  <span className={cn('px-2 py-0.5 rounded text-xs font-medium border', m?.cls ?? 'text-zinc-400 bg-zinc-800 border-zinc-700')}>
                    {m?.label ?? severity}
                  </span>
                </td>
                <td className="px-4 py-2.5">
                  <div className="flex gap-2">
                    <button
                      onClick={() => onSelectIp(ip)}
                      className="text-indigo-400 hover:text-indigo-300 text-xs"
                    >
                      Filtrele
                    </button>
                    <a
                      href={`/logs?source_ip=${encodeURIComponent(ip)}`}
                      className="flex items-center gap-0.5 text-zinc-500 hover:text-zinc-300 text-xs"
                    >
                      Loglar <ExternalLink size={10} />
                    </a>
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// ─── Result row (expandable) ──────────────────────────────────────────────────

function ResultRow({ result }: { result: AnomalyResult }) {
  const [expanded, setExpanded] = useState(false)
  const [fpSent, setFpSent]     = useState(false)

  async function markFP() {
    await fpRulesApi.create({
      source_ip: result.entity_id,
      reason:    `Anomali FP: ${result.metric} z=${result.z_score.toFixed(1)}σ`,
      expires_in_days: 7,
    })
    setFpSent(true)
  }

  const m      = SEV_META[result.severity as keyof typeof SEV_META]
  const mitre  = METRIC_MITRE[result.metric]
  const ifScore = typeof result.extra?.if_score === 'number' ? result.extra.if_score as number : null

  return (
    <>
      <tr
        className={cn('border-b border-zinc-800/50 cursor-pointer transition-colors',
          expanded ? 'bg-zinc-800/60' : 'hover:bg-zinc-800/30')}
        onClick={() => setExpanded((e) => !e)}
      >
        <td className="px-4 py-3">
          <span className={cn('px-2 py-0.5 rounded text-xs font-medium border', m?.cls ?? 'text-zinc-400 bg-zinc-800 border-zinc-700')}>
            {result.severity.toUpperCase()}
          </span>
        </td>
        <td className="px-4 py-3 font-mono text-sm text-zinc-200">
          <div className="flex items-center gap-2">
            {result.entity_id}
            <a
              href={`/logs?source_ip=${encodeURIComponent(result.entity_id)}`}
              onClick={(e) => e.stopPropagation()}
              className="text-zinc-600 hover:text-indigo-400 transition-colors"
              title="Log'larda ara"
            >
              <ExternalLink size={11} />
            </a>
          </div>
        </td>
        <td className="px-4 py-3 text-sm text-zinc-300">
          <div className="flex items-center gap-2">
            {METRIC_LABELS[result.metric] ?? result.metric}
            {mitre && (
              <span className="text-xs px-1.5 py-0.5 rounded bg-violet-950/60 text-violet-400 border border-violet-900 font-mono">
                {mitre.id}
              </span>
            )}
          </div>
        </td>
        <td className="px-4 py-3 font-mono text-sm text-zinc-200">
          {result.observed_value.toFixed(2)}
          <span className="text-zinc-500 text-xs ml-1">/ ~{result.baseline_mean.toFixed(2)}</span>
        </td>
        <td className="px-4 py-3">
          <ZScoreBar z={result.z_score} />
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            <WarmupBadge entityId={result.entity_id} />
            <span className="text-xs text-zinc-500">{(result.confidence * 100).toFixed(0)}%</span>
          </div>
        </td>
        <td className="px-4 py-3 text-xs text-zinc-500">
          {new Date(result.detected_at).toLocaleString('tr-TR', { hour: '2-digit', minute: '2-digit', day: '2-digit', month: '2-digit' })}
        </td>
        <td className="px-4 py-3 text-zinc-500">
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-zinc-800/50 bg-zinc-900/50">
          <td colSpan={8} className="px-6 py-4">
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-3 flex-1">
                <p className="text-sm text-zinc-300">{result.message}</p>
                <div className="grid grid-cols-4 gap-4 text-xs text-zinc-500">
                  <div>
                    <span className="text-zinc-600">Baseline Ort.</span>
                    <p className="text-zinc-300 font-mono mt-0.5">{result.baseline_mean.toFixed(3)}</p>
                  </div>
                  <div>
                    <span className="text-zinc-600">Std Sapma</span>
                    <p className="text-zinc-300 font-mono mt-0.5">±{result.baseline_std.toFixed(3)}</p>
                  </div>
                  <div>
                    <span className="text-zinc-600">Gözlemlenen</span>
                    <p className="text-zinc-300 font-mono mt-0.5">{result.observed_value.toFixed(3)}</p>
                  </div>
                  {ifScore !== null && (
                    <div>
                      <span className="text-zinc-600">IF Skoru</span>
                      <p className={cn('font-mono mt-0.5', ifScore < -0.1 ? 'text-red-400' : 'text-zinc-300')}>
                        {ifScore.toFixed(3)}
                      </p>
                      <p className="text-zinc-600 mt-0.5">IsolationForest ham</p>
                    </div>
                  )}
                </div>
                {mitre && (
                  <div className="flex items-center gap-2 pt-1">
                    <span className="text-xs text-zinc-600">MITRE ATT&CK:</span>
                    <span className="text-xs px-2 py-0.5 rounded bg-violet-950/60 text-violet-400 border border-violet-900 font-mono">
                      {mitre.id}
                    </span>
                    <span className="text-xs text-zinc-400">{mitre.name}</span>
                  </div>
                )}
              </div>
              <div className="flex gap-2 shrink-0">
                <a
                  href={`/logs?source_ip=${encodeURIComponent(result.entity_id)}`}
                  className="flex items-center gap-1 px-3 py-1.5 rounded text-xs bg-zinc-800 hover:bg-zinc-700 text-indigo-400 border border-zinc-700"
                >
                  <ExternalLink size={12} /> Log&apos;larda Ara
                </a>
                {!fpSent ? (
                  <button
                    onClick={(e) => { e.stopPropagation(); markFP() }}
                    className="flex items-center gap-1 px-3 py-1.5 rounded text-xs bg-zinc-800 hover:bg-zinc-700 text-zinc-300 border border-zinc-700"
                  >
                    <Shield size={12} /> FP Olarak İşaretle
                  </button>
                ) : (
                  <span className="text-xs text-emerald-400 flex items-center gap-1">
                    <Shield size={12} /> FP kuralı oluşturuldu
                  </span>
                )}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ─── Ana sayfa ────────────────────────────────────────────────────────────────

export default function AnomalyPage() {
  const [hours, setHours]               = useState(24)
  const [severityFilter, setSeverityFilter] = useState('all')
  const [entityFilter, setEntityFilter]   = useState('')

  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ['anomaly', 'summary', hours],
    queryFn:  () => anomalyApi.summary(hours),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  const { data: resultsData, isLoading: resultsLoading, isFetching, refetch } = useQuery({
    queryKey: ['anomaly', 'results', hours, severityFilter, entityFilter],
    queryFn:  () => anomalyApi.results({
      since_hours: hours,
      severity:    severityFilter !== 'all' ? severityFilter : undefined,
      entity_id:   entityFilter || undefined,
      limit: 200,
    }),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  const { data: baselinesData } = useQuery({
    queryKey: ['anomaly', 'baselines'],
    queryFn:  anomalyApi.baselines,
    staleTime: 120_000,
  })

  const results   = resultsData?.results ?? []
  const baselines = baselinesData?.entities ?? []
  const hasFilters = severityFilter !== 'all' || entityFilter !== ''

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Activity size={20} className="text-indigo-400" />
          <h1 className="text-lg font-semibold text-zinc-100">Anomali Tespiti</h1>
          <span className="text-xs text-zinc-500 hidden sm:inline">IsolationForest + Welford</span>
          {isFetching && <RefreshCw size={13} className="text-zinc-500 animate-spin" />}
        </div>
        <div className="flex items-center gap-2">
          <div className="flex rounded overflow-hidden border border-zinc-700">
            {HOURS_OPTIONS.map((h) => (
              <button key={h} onClick={() => setHours(h)}
                className={cn('px-3 py-1.5 text-xs',
                  hours === h ? 'bg-indigo-600 text-white' : 'bg-zinc-800 text-zinc-400 hover:text-zinc-200')}>
                {h < 48 ? `${h}s` : h === 48 ? '2g' : '7g'}
              </button>
            ))}
          </div>
          <button onClick={() => refetch()} className="p-1.5 rounded text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800">
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        {[
          { label: 'Toplam',      value: summary?.total ?? 0,             color: 'text-zinc-100' },
          { label: 'Kritik',      value: summary?.critical ?? 0,          color: 'text-red-400' },
          { label: 'Yüksek',      value: summary?.high ?? 0,              color: 'text-orange-400' },
          { label: 'Uyarı',       value: summary?.warning ?? 0,           color: 'text-yellow-400' },
          { label: 'Etkilenen IP', value: summary?.affected_entities ?? 0, color: 'text-indigo-400' },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
            <div className="text-xs text-zinc-500 mb-1">{label}</div>
            <div className={cn('text-2xl font-bold', color)}>
              {summaryLoading ? '—' : value}
            </div>
          </div>
        ))}
      </div>

      {/* Charts row */}
      {results.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-zinc-800">
              <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">Z-Score Dağılımı</p>
              <p className="text-[11px] text-zinc-600 mt-0.5">3σ üzeri anomaliler · Welford algoritması</p>
            </div>
            <div className="p-3">
              <ZScoreHistogram results={results} />
            </div>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-zinc-800">
              <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">Zaman Çizgisi</p>
              <p className="text-[11px] text-zinc-600 mt-0.5">Anomali zamanı vs Z-Score</p>
            </div>
            <div className="p-3">
              <AnomalyTimeline results={results} />
            </div>
          </div>
          <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b border-zinc-800">
              <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wide">Metrik Dağılımı</p>
              <p className="text-[11px] text-zinc-600 mt-0.5">Hangi metrikler en çok anomali üretiyor?</p>
            </div>
            <div className="p-3">
              <MetricBreakdownChart results={results} />
            </div>
          </div>
        </div>
      )}

      {/* Top offenders */}
      {results.length > 0 && (
        <TopOffendersTable results={results} onSelectIp={(ip) => setEntityFilter(ip)} />
      )}

      {/* Engine warmup */}
      {baselines.length > 0 && (
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-4">
          <div className="flex items-center gap-2 mb-3">
            <Activity size={14} className="text-zinc-400" />
            <span className="text-sm font-medium text-zinc-300">Model Isınma Durumu</span>
            <span className="text-xs text-zinc-500">({baselines.length} entity izleniyor)</span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            {baselines.slice(0, 8).map((e) => (
              <div key={e.entity_id} className="flex items-center gap-2">
                <span className="font-mono text-xs text-zinc-400 w-28 truncate" title={e.entity_id}>
                  {e.entity_id}
                </span>
                <WarmupBadge entityId={e.entity_id} />
              </div>
            ))}
            {baselines.length > 8 && (
              <span className="text-xs text-zinc-500 self-center">+{baselines.length - 8} daha</span>
            )}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <Select value={severityFilter} onValueChange={(v) => setSeverityFilter(v ?? 'all')}>
          <SelectTrigger className="w-36 h-8 text-xs bg-zinc-800 border-zinc-700 text-zinc-300">
            <SelectValue />
          </SelectTrigger>
          <SelectContent className="bg-zinc-800 border-zinc-700">
            <SelectItem value="all" className="text-zinc-300">Tüm Seviyeler</SelectItem>
            <SelectItem value="critical" className="text-zinc-300">Kritik</SelectItem>
            <SelectItem value="high" className="text-zinc-300">Yüksek</SelectItem>
            <SelectItem value="warning" className="text-zinc-300">Uyarı</SelectItem>
          </SelectContent>
        </Select>
        <div className="relative">
          <Input
            placeholder="IP filtrele..."
            value={entityFilter}
            onChange={(e) => setEntityFilter(e.target.value)}
            className="h-8 text-xs bg-zinc-800 border-zinc-700 text-zinc-300 placeholder:text-zinc-600 w-36 pr-6"
          />
          {entityFilter && (
            <button onClick={() => setEntityFilter('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300">
              <X size={11} />
            </button>
          )}
        </div>
        {hasFilters && (
          <button onClick={() => { setSeverityFilter('all'); setEntityFilter('') }}
            className="text-xs text-zinc-500 hover:text-zinc-300">
            Temizle
          </button>
        )}
        <span className="text-xs text-zinc-500 ml-auto">{results.length} anomali</span>
      </div>

      {/* Results table */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg overflow-hidden">
        {resultsLoading ? (
          <div className="p-8 text-center text-zinc-500 text-sm">Yükleniyor…</div>
        ) : results.length === 0 ? (
          <div className="p-8 text-center">
            <Activity size={24} className="text-zinc-600 mx-auto mb-2" />
            <p className="text-zinc-500 text-sm">Bu zaman aralığında anomali tespit edilmedi</p>
            {baselines.length === 0 && (
              <p className="text-zinc-600 text-xs mt-1">Model henüz ısınıyor — baseline oluşturuluyor</p>
            )}
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800 text-xs text-zinc-500 uppercase">
                <th className="text-left px-4 py-3">Seviye</th>
                <th className="text-left px-4 py-3">Entity IP</th>
                <th className="text-left px-4 py-3">Metrik</th>
                <th className="text-left px-4 py-3">Gözlemlenen / Baseline</th>
                <th className="text-left px-4 py-3">Z-Score</th>
                <th className="text-left px-4 py-3">Model / Güven</th>
                <th className="text-left px-4 py-3">Zaman</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {results.map((r) => <ResultRow key={r.result_id} result={r} />)}
            </tbody>
          </table>
        )}
      </div>

      {/* Kaynak notu */}
      <p className="text-xs text-zinc-600">
        Welford online algoritması · 3σ eşiği (p&lt;0.0013) · MITRE ATT&CK v17 teknik mapping · IsolationForest contamination=0.05
      </p>

      {/* Engine warning */}
      {!summaryLoading && summary === undefined && (
        <div className="bg-yellow-950/30 border border-yellow-900/50 rounded-lg p-4 flex items-center gap-3">
          <AlertTriangle size={16} className="text-yellow-400 shrink-0" />
          <p className="text-sm text-yellow-300">
            Anomali motoru henüz başlatılmadı. Servis yeniden başlatıldıktan sonra veriler görünür.
          </p>
        </div>
      )}
    </div>
  )
}
