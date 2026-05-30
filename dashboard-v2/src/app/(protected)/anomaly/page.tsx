'use client'

import { useState, useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Activity, AlertTriangle, RefreshCw, ChevronDown, ChevronUp, Shield, X, ExternalLink } from 'lucide-react'
import ReactECharts from 'echarts-for-react'
import { anomalyApi, fpRulesApi } from '@/lib/api'
import { TOOLTIP_BASE, CHART_COLORS } from '@/lib/echarts-theme'
import { SkeletonTable, SkeletonStatGrid } from '@/components/ui/skeleton'
import type { AnomalyResult } from '@/lib/api'
import { cn } from '@/lib/utils'

const SEV_META = {
  critical: { label: 'Kritik',  cls: 'text-red-400 bg-red-500/10 border-red-500/30 backdrop-blur-sm',         bar: 'bg-red-500' },
  high:     { label: 'Yüksek', cls: 'text-orange-400 bg-orange-500/10 border-orange-500/30 backdrop-blur-sm', bar: 'bg-orange-500' },
  warning:  { label: 'Uyarı',  cls: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/25 backdrop-blur-sm', bar: 'bg-yellow-500' },
}

const METRIC_LABELS: Record<string, string> = {
  fw_block_rate:     'FW Blok Hızı',
  conn_rate:         'Bağlantı Hızı',
  unique_dst_ips:    'Benzersiz Hedef IP',
  unique_dst_ports:  'Benzersiz Hedef Port',
  auth_failure_rate: 'Auth Hata Hızı',
}

const METRIC_MITRE: Record<string, { id: string; name: string }> = {
  unique_dst_ports:  { id: 'T1046', name: 'Network Service Discovery' },
  unique_dst_ips:    { id: 'T1046', name: 'Network Service Discovery' },
  conn_rate:         { id: 'T1071', name: 'Application Layer Protocol' },
  auth_failure_rate: { id: 'T1110', name: 'Brute Force' },
  fw_block_rate:     { id: 'T1562', name: 'Impair Defenses' },
}

const HOURS_OPTIONS = [6, 24, 48, 168] as const

// ─── Z-Score bar ──────────────────────────────────────────────────────────────

function ZScoreBar({ z }: { z: number }) {
  const clamped = Math.min(Math.abs(z), 6)
  const pct     = (clamped / 6) * 100
  const color   = z >= 4.5 ? 'bg-red-500' : z >= 3.5 ? 'bg-orange-500' : 'bg-yellow-500'
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-sky-950/30 rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full', color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-slate-400">{z.toFixed(1)}σ</span>
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
  const pct   = data.progress_pct
  const color = data.warmed_up ? 'bg-emerald-500' : pct > 60 ? 'bg-yellow-500' : 'bg-slate-600'
  return (
    <div className="flex items-center gap-1.5" title={`${data.sample_count}/${data.needed} örnek`}>
      <div className="w-12 h-1 bg-sky-950/20 rounded-full overflow-hidden">
        <div className={cn('h-full rounded-full', color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-slate-600">{pct}%</span>
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
      ...TOOLTIP_BASE,
      trigger: 'axis',
      formatter: (params: { name: string; value: number }[]) =>
        `${params[0].name}: ${params[0].value} anomali`,
    },
    xAxis: {
      type: 'category', data: bins.labels,
      axisLabel: { color: '#475569', fontSize: 9 },
      axisLine: { show: false }, axisTick: { show: false }, splitLine: { show: false },
    },
    yAxis: {
      type: 'value', minInterval: 1,
      axisLabel: { color: '#475569', fontSize: 9 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
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
      ...TOOLTIP_BASE,
      trigger: 'item',
      formatter: (p: { value: [number, number, string, string] }) => {
        const [ts, z, ip, metric] = p.value
        return `${ip}<br/>${METRIC_LABELS[metric] ?? metric}<br/>Z-Score: ${z.toFixed(1)}σ<br/>${new Date(ts).toLocaleString('tr-TR')}`
      },
    },
    xAxis: {
      type: 'time',
      axisLabel: {
        color: '#475569', fontSize: 9,
        formatter: (v: number) => new Date(v).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' }),
      },
      axisLine: { show: false }, axisTick: { show: false },
      splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)', type: 'dashed' } },
    },
    yAxis: {
      type: 'value', name: 'Z-Score',
      nameTextStyle: { color: '#475569', fontSize: 9 },
      axisLabel: { color: '#475569', fontSize: 9, formatter: (v: number) => `${v}σ` },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
    },
    series: [{
      type: 'scatter', symbolSize: 7, data,
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
    tooltip: { ...TOOLTIP_BASE, trigger: 'axis', axisPointer: { type: 'shadow' } },
    xAxis: {
      type: 'value', minInterval: 1,
      axisLabel: { color: '#475569', fontSize: 9 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
    },
    yAxis: {
      type: 'category', data: data.map((d) => d.label),
      axisLabel: { color: '#64748b', fontSize: 10 },
      axisLine: { show: false }, axisTick: { show: false }, splitLine: { show: false },
    },
    series: [{
      type: 'bar', barMaxWidth: 18,
      data: data.map((d) => d.value),
      itemStyle: { color: CHART_COLORS.cyber },
      label: { show: true, position: 'right', color: '#64748b', fontSize: 10 },
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
    <div className="ui-panel">
      <div className="ui-panel-header">
        <p className="ui-section-label">En Aktif IP&apos;ler</p>
        <p className="text-[11px] text-slate-600 mt-0.5">En çok anomali üreten kaynak IP&apos;ler</p>
      </div>
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-sky-900/10 text-slate-600 uppercase tracking-wide">
            <th className="ui-th">IP</th>
            <th className="ui-th">Anomali</th>
            <th className="ui-th">Max Z-Score</th>
            <th className="ui-th">Seviye</th>
            <th className="ui-th"></th>
          </tr>
        </thead>
        <tbody className="divide-y divide-sky-900/10">
          {rows.map(([ip, { count, maxZ, severity }]) => {
            const m = SEV_META[severity as keyof typeof SEV_META]
            return (
              <tr key={ip} className="hover:bg-sky-950/20 transition-colors">
                <td className="ui-td font-mono text-slate-200">{ip}</td>
                <td className="ui-td text-slate-300 font-semibold">{count}</td>
                <td className="ui-td font-mono text-slate-300">{maxZ.toFixed(1)}σ</td>
                <td className="ui-td">
                  <span className={cn('px-2 py-0.5 rounded text-xs font-medium border', m?.cls ?? 'text-slate-400 bg-sky-950/20 border-sky-900/20')}>
                    {m?.label ?? severity}
                  </span>
                </td>
                <td className="ui-td">
                  <div className="flex gap-3">
                    <button onClick={() => onSelectIp(ip)} className="text-sky-400 hover:text-sky-300 transition-colors">
                      Filtrele
                    </button>
                    <a
                      href={`/logs?source_ip=${encodeURIComponent(ip)}`}
                      className="flex items-center gap-0.5 text-slate-600 hover:text-slate-300 transition-colors"
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
        className={cn('cursor-pointer transition-colors border-b border-sky-900/10',
          expanded ? 'bg-sky-950/25' : 'hover:bg-sky-950/20')}
        onClick={() => setExpanded((e) => !e)}
      >
        <td className="ui-td">
          <span className={cn('px-2 py-0.5 rounded text-xs font-medium border', m?.cls ?? 'text-slate-400 bg-sky-950/20 border-sky-900/20')}>
            {result.severity.toUpperCase()}
          </span>
        </td>
        <td className="ui-td font-mono text-sm text-slate-200">
          <div className="flex items-center gap-2">
            {result.entity_id}
            <a
              href={`/logs?source_ip=${encodeURIComponent(result.entity_id)}`}
              onClick={(e) => e.stopPropagation()}
              className="text-slate-700 hover:text-sky-400 transition-colors"
              title="Log'larda ara"
            >
              <ExternalLink size={11} />
            </a>
          </div>
        </td>
        <td className="ui-td text-sm text-slate-300">
          <div className="flex items-center gap-2">
            {METRIC_LABELS[result.metric] ?? result.metric}
            {mitre && (
              <span className="text-xs px-1.5 py-0.5 rounded bg-violet-950/60 text-violet-400 border border-violet-900/60 font-mono">
                {mitre.id}
              </span>
            )}
          </div>
        </td>
        <td className="ui-td font-mono text-sm text-slate-200">
          {result.observed_value.toFixed(2)}
          <span className="text-slate-600 text-xs ml-1">/ ~{result.baseline_mean.toFixed(2)}</span>
        </td>
        <td className="ui-td">
          <ZScoreBar z={result.z_score} />
        </td>
        <td className="ui-td">
          <div className="flex items-center gap-2">
            <WarmupBadge entityId={result.entity_id} />
            <span className="text-xs text-slate-600">{(result.confidence * 100).toFixed(0)}%</span>
          </div>
        </td>
        <td className="ui-td text-xs text-slate-600">
          {new Date(result.detected_at).toLocaleString('tr-TR', { hour: '2-digit', minute: '2-digit', day: '2-digit', month: '2-digit' })}
        </td>
        <td className="ui-td text-slate-700">
          {expanded ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </td>
      </tr>
      {expanded && (
        <tr className="border-b border-sky-900/10 bg-sky-950/10">
          <td colSpan={8} className="px-6 py-4">
            <div className="flex items-start justify-between gap-4">
              <div className="space-y-3 flex-1">
                <p className="text-sm text-slate-300">{result.message}</p>
                <div className="grid grid-cols-4 gap-4 text-xs text-slate-500">
                  <div>
                    <span className="text-slate-700">Baseline Ort.</span>
                    <p className="text-slate-300 font-mono mt-0.5">{result.baseline_mean.toFixed(3)}</p>
                  </div>
                  <div>
                    <span className="text-slate-700">Std Sapma</span>
                    <p className="text-slate-300 font-mono mt-0.5">±{result.baseline_std.toFixed(3)}</p>
                  </div>
                  <div>
                    <span className="text-slate-700">Gözlemlenen</span>
                    <p className="text-slate-300 font-mono mt-0.5">{result.observed_value.toFixed(3)}</p>
                  </div>
                  {ifScore !== null && (
                    <div>
                      <span className="text-slate-700">IF Skoru</span>
                      <p className={cn('font-mono mt-0.5', ifScore < -0.1 ? 'text-red-400' : 'text-slate-300')}>
                        {ifScore.toFixed(3)}
                      </p>
                      <p className="text-slate-700 mt-0.5">IsolationForest ham</p>
                    </div>
                  )}
                </div>
                {mitre && (
                  <div className="flex items-center gap-2 pt-1">
                    <span className="text-xs text-slate-600">MITRE ATT&CK:</span>
                    <span className="text-xs px-2 py-0.5 rounded bg-violet-950/60 text-violet-400 border border-violet-900/60 font-mono">
                      {mitre.id}
                    </span>
                    <span className="text-xs text-slate-400">{mitre.name}</span>
                  </div>
                )}
              </div>
              <div className="flex gap-2 shrink-0">
                <a
                  href={`/logs?source_ip=${encodeURIComponent(result.entity_id)}`}
                  className="ui-btn ui-btn-secondary text-sky-400"
                >
                  <ExternalLink size={12} /> Log&apos;larda Ara
                </a>
                {!fpSent ? (
                  <button
                    onClick={(e) => { e.stopPropagation(); markFP() }}
                    className="ui-btn ui-btn-secondary"
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
    <div className="p-6 space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-sky-500/10 border border-sky-500/20 flex items-center justify-center">
            <Activity size={15} className="text-sky-400" />
          </div>
          <div>
            <h1 className="text-base font-semibold text-slate-100 leading-tight">Anomali Tespiti</h1>
            <p className="text-xs text-slate-600">IsolationForest + Welford online algoritması</p>
          </div>
          {isFetching && <RefreshCw size={13} className="text-slate-500 animate-spin ml-1" />}
        </div>
        <div className="flex items-center gap-2">
          <div className="flex rounded-lg overflow-hidden border border-sky-900/20">
            {HOURS_OPTIONS.map((h) => (
              <button key={h} onClick={() => setHours(h)}
                className={cn('px-3 py-1.5 text-xs transition-colors',
                  hours === h
                    ? 'bg-sky-500/15 text-sky-400 border-x border-sky-500/30'
                    : 'bg-[#0a1120] text-slate-500 hover:text-slate-300')}>
                {h < 48 ? `${h}s` : h === 48 ? '2g' : '7g'}
              </button>
            ))}
          </div>
          <button
            onClick={() => refetch()}
            className="p-1.5 rounded-md text-slate-500 hover:text-slate-300 hover:bg-sky-950/40 transition-colors"
          >
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      {/* KPI cards */}
      {summaryLoading ? (
        <SkeletonStatGrid cols={5} height={80} />
      ) : (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {[
            { label: 'Toplam',       value: summary?.total ?? 0,             color: 'text-slate-100' },
            { label: 'Kritik',       value: summary?.critical ?? 0,          color: 'text-red-400' },
            { label: 'Yüksek',       value: summary?.high ?? 0,              color: 'text-orange-400' },
            { label: 'Uyarı',        value: summary?.warning ?? 0,           color: 'text-yellow-400' },
            { label: 'Etkilenen IP', value: summary?.affected_entities ?? 0, color: 'text-sky-400' },
          ].map(({ label, value, color }) => (
            <div key={label} className="ui-panel p-4">
              <div className="text-xs text-slate-500 mb-1">{label}</div>
              <div className={cn('text-2xl font-bold', color)}>{value}</div>
            </div>
          ))}
        </div>
      )}

      {/* Charts row */}
      {results.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
          <div className="ui-panel">
            <div className="ui-panel-header">
              <p className="ui-section-label">Z-Score Dağılımı</p>
              <p className="text-[11px] text-slate-600 mt-0.5">3σ üzeri anomaliler · Welford algoritması</p>
            </div>
            <div className="p-3">
              <ZScoreHistogram results={results} />
            </div>
          </div>
          <div className="ui-panel">
            <div className="ui-panel-header">
              <p className="ui-section-label">Zaman Çizgisi</p>
              <p className="text-[11px] text-slate-600 mt-0.5">Anomali zamanı vs Z-Score</p>
            </div>
            <div className="p-3">
              <AnomalyTimeline results={results} />
            </div>
          </div>
          <div className="ui-panel">
            <div className="ui-panel-header">
              <p className="ui-section-label">Metrik Dağılımı</p>
              <p className="text-[11px] text-slate-600 mt-0.5">Hangi metrikler en çok anomali üretiyor?</p>
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
        <div className="ui-panel p-4">
          <div className="flex items-center gap-2 mb-3">
            <Activity size={13} className="text-slate-500" />
            <span className="text-sm font-medium text-slate-300">Model Isınma Durumu</span>
            <span className="text-xs text-slate-600">({baselines.length} entity izleniyor)</span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
            {baselines.slice(0, 8).map((e) => (
              <div key={e.entity_id} className="flex items-center gap-2">
                <span className="font-mono text-xs text-slate-500 w-28 truncate" title={e.entity_id}>
                  {e.entity_id}
                </span>
                <WarmupBadge entityId={e.entity_id} />
              </div>
            ))}
            {baselines.length > 8 && (
              <span className="text-xs text-slate-600 self-center">+{baselines.length - 8} daha</span>
            )}
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <select
          value={severityFilter}
          onChange={e => setSeverityFilter(e.target.value)}
          className="ui-select"
        >
          <option value="all">Tüm Seviyeler</option>
          <option value="critical">Kritik</option>
          <option value="high">Yüksek</option>
          <option value="warning">Uyarı</option>
        </select>
        <div className="relative">
          <input
            placeholder="IP filtrele..."
            value={entityFilter}
            onChange={(e) => setEntityFilter(e.target.value)}
            className="ui-input w-36 pr-6"
          />
          {entityFilter && (
            <button onClick={() => setEntityFilter('')}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-slate-600 hover:text-slate-400">
              <X size={11} />
            </button>
          )}
        </div>
        {hasFilters && (
          <button onClick={() => { setSeverityFilter('all'); setEntityFilter('') }}
            className="text-xs text-slate-600 hover:text-slate-400 transition-colors">
            Temizle
          </button>
        )}
        <span className="text-xs text-slate-600 ml-auto">{results.length} anomali</span>
      </div>

      {/* Results table */}
      <div className="ui-panel">
        {resultsLoading ? (
          <div className="p-4">
            <SkeletonTable rows={7} height={44} />
          </div>
        ) : results.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 gap-3 text-slate-600">
            <Activity size={28} className="opacity-20" />
            <p className="text-sm">Bu zaman aralığında anomali tespit edilmedi</p>
            {baselines.length === 0 && (
              <p className="text-xs text-slate-700">Model henüz ısınıyor — baseline oluşturuluyor</p>
            )}
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr >
                <th className="ui-th">Seviye</th>
                <th className="ui-th">Entity IP</th>
                <th className="ui-th">Metrik</th>
                <th className="ui-th">Gözlemlenen / Baseline</th>
                <th className="ui-th">Z-Score</th>
                <th className="ui-th">Model / Güven</th>
                <th className="ui-th">Zaman</th>
                <th className="ui-th"></th>
              </tr>
            </thead>
            <tbody>
              {results.map((r) => <ResultRow key={r.result_id} result={r} />)}
            </tbody>
          </table>
        )}
      </div>

      {/* Kaynak notu */}
      <p className="text-xs text-slate-700">
        Welford online algoritması · 3σ eşiği (p&lt;0.0013) · MITRE ATT&CK v17 teknik mapping · IsolationForest contamination=0.05
      </p>

      {/* Engine warning */}
      {!summaryLoading && summary === undefined && (
        <div className="bg-yellow-500/5 border border-yellow-500/20 rounded-xl p-4 flex items-center gap-3">
          <AlertTriangle size={15} className="text-yellow-400 shrink-0" />
          <p className="text-sm text-yellow-300">
            Anomali motoru henüz başlatılmadı. Servis yeniden başlatıldıktan sonra veriler görünür.
          </p>
        </div>
      )}
    </div>
  )
}
