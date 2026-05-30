'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ShieldAlert, RefreshCw, Globe, AlertTriangle, TrendingUp } from 'lucide-react'
import ReactECharts from 'echarts-for-react'
import { analyticsApi, type ThreatSource } from '@/lib/api'
import { TOOLTIP_BASE } from '@/lib/echarts-theme'
import { SkeletonStatGrid, SkeletonChart, SkeletonTable } from '@/components/ui/skeleton'

const HOURS_OPTIONS = [
  { label: '1s',  value: 1 },
  { label: '6s',  value: 6 },
  { label: '24s', value: 24 },
  { label: '48s', value: 48 },
  { label: '7g',  value: 168 },
]

function scoreColor(score: number): string {
  if (score >= 70) return 'bg-red-500'
  if (score >= 40) return 'bg-amber-500'
  if (score > 0)   return 'bg-yellow-500'
  return 'bg-slate-600'
}

function scoreBadgeClass(score: number): string {
  if (score >= 70) return 'text-red-400 bg-red-500/10 border-red-500/30'
  if (score >= 40) return 'text-amber-400 bg-amber-500/10 border-amber-500/30'
  if (score > 0)   return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30'
  return 'text-slate-500 bg-sky-950/20 border-sky-900/20'
}

function fmtDate(s: string): string {
  if (!s) return '—'
  const d = new Date(s)
  return isNaN(d.getTime()) ? s : d.toLocaleString('tr-TR', { timeZone: 'UTC' })
}

function StatCard({
  label, value, sub, icon: Icon, colorClass,
}: {
  label: string; value: string | number; sub?: string
  icon: React.ElementType; colorClass: string
}) {
  return (
    <div className="bg-[#0a1120] rounded-xl border border-sky-900/20 p-4 flex items-start gap-3">
      <div className={`p-2 rounded-lg mt-0.5 ${colorClass}`}>
        <Icon className="w-4 h-4" />
      </div>
      <div>
        <p className="text-xs text-slate-500">{label}</p>
        <p className="text-2xl font-bold text-slate-100 leading-tight">{value}</p>
        {sub && <p className="text-xs text-slate-500 mt-0.5">{sub}</p>}
      </div>
    </div>
  )
}

function ScoreBar({ score }: { score: number }) {
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-sky-950/30 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all ${scoreColor(score)}`}
          style={{ width: `${score}%` }}
        />
      </div>
      <span className={`text-xs font-mono px-1.5 py-0.5 rounded border ${scoreBadgeClass(score)}`}>
        {score}
      </span>
    </div>
  )
}

function countryFlag(code: string): string {
  if (!code || code === 'XX') return '🌐'
  return code
    .toUpperCase()
    .split('')
    .map((c) => String.fromCodePoint(0x1f1e0 + c.charCodeAt(0) - 65))
    .join('')
}

function FeedBadges({ src }: { src: ThreatSource }) {
  const badges: { label: string; cls: string; title: string }[] = []
  if (src.feodo_listed)
    badges.push({ label: 'Feodo', cls: 'bg-red-900/50 text-red-300 border-red-700/50', title: src.feodo_malware || 'Feodo Tracker' })
  if (src.threatfox_score > 0)
    badges.push({ label: 'ThreatFox', cls: 'bg-orange-900/50 text-orange-300 border-orange-700/50', title: src.threatfox_malware || `score ${src.threatfox_score}` })
  if (src.greynoise_noise && !src.greynoise_classification.toLowerCase().includes('benign'))
    badges.push({ label: 'GreyNoise', cls: 'bg-yellow-900/50 text-yellow-300 border-yellow-700/50', title: src.greynoise_classification || 'Noise' })
  if (badges.length === 0) return <span className="text-slate-700 text-[10px]">—</span>
  return (
    <div className="flex flex-wrap gap-1">
      {badges.map(b => (
        <span key={b.label} title={b.title}
          className={`text-[9px] px-1.5 py-0.5 rounded border font-bold uppercase tracking-wide ${b.cls}`}>
          {b.label}
        </span>
      ))}
    </div>
  )
}

export default function ThreatIntelSummaryPage() {
  const [hours, setHours] = useState(24)

  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['threat-summary', hours],
    queryFn:  () => analyticsApi.threatSummary(hours),
    refetchInterval: 60_000,
    staleTime:       30_000,
  })

  const top10Sources = data?.top_sources.slice(0, 10) ?? []

  const scoreBarOption = top10Sources.length > 0 ? {
    backgroundColor: 'transparent',
    grid: { top: 8, right: 80, bottom: 8, left: 8, containLabel: true },
    xAxis: {
      type: 'value', min: 0, max: 100,
      axisLabel: { color: '#475569', fontSize: 10 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
    },
    yAxis: {
      type: 'category',
      data: [...top10Sources].reverse().map((s: ThreatSource) => s.ip),
      axisLabel: { color: '#64748b', fontSize: 10, width: 120, overflow: 'truncate' },
      axisLine: { show: false }, axisTick: { show: false },
      splitLine: { show: false },
    },
    tooltip: {
      ...TOOLTIP_BASE,
      trigger: 'axis',
      formatter: (p: { name: string; value: number }[]) =>
        `${p[0].name}<br/>Composite Score: <b>${p[0].value}</b>`,
    },
    series: [{
      name: 'Composite Score',
      type: 'bar',
      barMaxWidth: 16,
      data: [...top10Sources].reverse().map((s: ThreatSource) => ({
        value: s.composite_score,
        itemStyle: {
          color: s.composite_score >= 70 ? '#ef4444'
               : s.composite_score >= 40 ? '#f59e0b'
               : s.composite_score >  0  ? '#eab308'
               : '#52525b',
        },
      })),
      label: {
        show: true, position: 'right',
        color: '#64748b', fontSize: 10,
      },
    }],
  } : null

  const countryDist = data?.country_distribution ?? []
  const countryOption = countryDist.length > 0 ? {
    backgroundColor: 'transparent',
    grid: { top: 8, right: 48, bottom: 8, left: 8, containLabel: true },
    xAxis: {
      type: 'value',
      axisLabel: { color: '#475569', fontSize: 10 },
      axisLine: { show: false },
      splitLine: { lineStyle: { color: 'rgba(56,189,248,0.07)' } },
    },
    yAxis: {
      type: 'category',
      data: [...countryDist].reverse().map((c) => c.country_code || 'XX'),
      axisLabel: { color: '#64748b', fontSize: 11 },
      axisLine: { show: false }, axisTick: { show: false },
      splitLine: { show: false },
    },
    tooltip: {
      ...TOOLTIP_BASE,
      trigger: 'axis',
    },
    series: [{
      name: 'Benzersiz IP',
      type: 'bar',
      barMaxWidth: 16,
      color: '#818cf8',
      data: [...countryDist].reverse().map((c) => c.ip_count),
      label: { show: true, position: 'right', color: '#64748b', fontSize: 10 },
    }],
  } : null

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldAlert className="w-5 h-5 text-sky-400" />
          <h1 className="text-lg font-semibold text-slate-100">Threat Intelligence Özeti</h1>
          {isFetching && <RefreshCw className="w-4 h-4 text-slate-500 animate-spin" />}
        </div>
        <div className="flex items-center gap-2">
          <div className="flex gap-1">
            {HOURS_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                onClick={() => setHours(opt.value)}
                className={`px-3 py-1.5 rounded-lg border text-xs font-medium transition-colors ${
                  hours === opt.value
                    ? 'bg-sky-500/15 border-sky-500/30 text-sky-300'
                    : 'bg-sky-950/20 border-sky-900/20 text-slate-400 hover:bg-sky-950/40'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
          <button
            onClick={() => refetch()}
            className="p-1.5 rounded-lg border border-sky-900/20 text-slate-400 hover:text-slate-100 hover:bg-sky-950/30 transition-colors"
            title="Yenile"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Error */}
      {isError && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-sm text-red-400 flex items-center justify-between">
          <span>Veri yüklenemedi. Sunucu bağlantısını kontrol edin.</span>
          <button onClick={() => refetch()} className="text-xs underline hover:text-red-300">
            Tekrar dene
          </button>
        </div>
      )}

      {/* Stat kartlar */}
      {isLoading ? (
        <SkeletonStatGrid cols={3} height={80} />
      ) : data ? (
        <div className="grid grid-cols-3 gap-4">
          <StatCard
            label="Kritik Alert"
            value={data.critical_count.toLocaleString('tr-TR')}
            sub={`${data.total_alerts.toLocaleString('tr-TR')} toplam alert`}
            icon={AlertTriangle}
            colorClass="bg-red-500/15 text-red-400"
          />
          <StatCard
            label="Yüksek Risk IP"
            value={data.high_risk_count.toLocaleString('tr-TR')}
            sub="Composite score ≥ 70"
            icon={ShieldAlert}
            colorClass={data.high_risk_count > 0 ? 'bg-red-500/15 text-red-400' : 'bg-sky-950/20 text-slate-400'}
          />
          <StatCard
            label="Kaynak Ülke"
            value={data.country_distribution.length.toLocaleString('tr-TR')}
            sub="Tehdit kaynağı coğrafi dağılım"
            icon={Globe}
            colorClass="bg-sky-500/15 text-sky-400"
          />
        </div>
      ) : null}

      {/* Composite Score bar chart */}
      <div className="ui-panel">
        <div className="ui-panel-header">
          <TrendingUp className="w-4 h-4 text-slate-400" />
          <h2 className="text-sm font-semibold text-slate-200">Top 10 — Composite Threat Score</h2>
        </div>
        {isLoading ? (
          <SkeletonChart height={224} className="m-4" />
        ) : scoreBarOption ? (
          <div className="p-4">
            <ReactECharts
              option={scoreBarOption}
              style={{ height: Math.max(160, top10Sources.length * 32) }}
              notMerge
            />
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-12 text-slate-600">
            <ShieldAlert className="w-7 h-7 mb-2 opacity-30" />
            <p className="text-sm">Threat intel kaydı yok</p>
          </div>
        )}
      </div>

      {/* Detay tablosu */}
      <div className="ui-panel">
        <div className="ui-panel-header">
          <h2 className="text-sm font-semibold text-slate-200">Tehdit Kaynakları</h2>
        </div>
        {isLoading ? (
          <div className="p-4">
            <SkeletonTable rows={4} height={40} />
          </div>
        ) : top10Sources.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-slate-600">
            <ShieldAlert className="w-8 h-8 mb-2 opacity-30" />
            <p className="text-sm">Veri yok</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr >
                  <th className="ui-th">#</th>
                  <th className="ui-th">IP</th>
                  <th className="ui-th">Ülke</th>
                  <th className="ui-th w-40">Composite Score</th>
                  <th className="ui-th">Feed</th>
                  <th className="ui-th">ISP</th>
                  <th className="ui-th text-right">Olay</th>
                  <th className="ui-th text-right">Son Görülme</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-sky-900/10">
                {top10Sources.map((src, idx) => (
                  <tr key={src.ip} className="hover:bg-sky-950/20 transition-colors">
                    <td className="ui-td text-slate-600 text-xs">{idx + 1}</td>
                    <td className="ui-td font-mono text-slate-300 text-xs">{src.ip}</td>
                    <td className="ui-td text-slate-400 text-xs">
                      <span className="mr-1">{countryFlag(src.country_code)}</span>
                      {src.country_code || '—'}
                    </td>
                    <td className="ui-td">
                      <ScoreBar score={src.composite_score} />
                    </td>
                    <td className="ui-td">
                      <FeedBadges src={src} />
                    </td>
                    <td className="ui-td text-slate-500 text-xs truncate max-w-[160px]">
                      {src.isp || '—'}
                    </td>
                    <td className="ui-td text-right text-red-400 font-semibold text-xs">
                      {src.count.toLocaleString('tr-TR')}
                    </td>
                    <td className="ui-td text-right text-slate-500 text-xs">
                      {fmtDate(src.last_seen)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Ülke dağılımı */}
      {(isLoading || countryDist.length > 0) && (
        <div className="ui-panel">
          <div className="ui-panel-header">
            <Globe className="w-4 h-4 text-slate-400" />
            <h2 className="text-sm font-semibold text-slate-200">Coğrafi Dağılım</h2>
            {data && (
              <span className="text-xs text-slate-500 ml-auto">
                {data.country_distribution.length} ülke
              </span>
            )}
          </div>
          {isLoading ? (
            <SkeletonChart height={160} className="m-4" />
          ) : countryOption ? (
            <div className="p-4">
              <ReactECharts
                option={countryOption}
                style={{ height: Math.max(120, countryDist.length * 28) }}
                notMerge
              />
            </div>
          ) : null}
        </div>
      )}
    </div>
  )
}
