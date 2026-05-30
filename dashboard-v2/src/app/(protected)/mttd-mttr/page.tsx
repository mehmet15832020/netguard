'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Clock, RefreshCw } from 'lucide-react'
import { analyticsApi } from '@/lib/api'
import { MttdMttrChart } from '@/components/charts/MttdMttrChart'
import type { MttdMttrSeverityBreakdown } from '@/lib/api'
import { SkeletonChart } from '@/components/ui/skeleton'

const DAY_OPTIONS = [
  { label: '7g',  value: 7  },
  { label: '14g', value: 14 },
  { label: '30g', value: 30 },
  { label: '90g', value: 90 },
]

const SEV_COLORS: Record<string, string> = {
  critical: 'text-red-400',
  high:     'text-orange-400',
  warning:  'text-yellow-400',
  info:     'text-blue-400',
}

function fmtMin(m: number | null): string {
  if (m === null || m === 0) return '—'
  if (m < 60) return `${m.toFixed(0)} dk`
  const h = m / 60
  if (h < 24) return `${h.toFixed(1)} s`
  return `${(h / 24).toFixed(1)} g`
}

function SlaPct({ pct, hasData }: { pct: number; hasData: boolean }) {
  if (!hasData) return <span className="text-slate-600">—</span>
  const color = pct >= 90 ? 'text-emerald-400' : pct >= 70 ? 'text-yellow-400' : 'text-red-400'
  return <span className={`font-medium ${color}`}>{pct.toFixed(0)}%</span>
}

function SeverityTable({ rows }: { rows: MttdMttrSeverityBreakdown[] }) {
  if (rows.length === 0) return (
    <p className="text-sm text-slate-500 py-4 text-center">Bu dönemde incident bulunamadı</p>
  )
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr >
            <th className="ui-th">Önem</th>
            <th className="ui-th text-right">Adet</th>
            <th className="ui-th text-right">MTTD Ort.</th>
            <th className="ui-th text-right">
              MTTD SLA
              <span className="block text-slate-600 font-normal">(hedef)</span>
            </th>
            <th className="ui-th text-right">MTTR Ort.</th>
            <th className="ui-th text-right">
              MTTR SLA
              <span className="block text-slate-600 font-normal">(hedef)</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map(r => (
            <tr key={r.severity} className="border-b border-sky-900/10 hover:bg-sky-950/20">
              <td className="ui-td pr-4">
                <span className={`font-medium capitalize ${SEV_COLORS[r.severity] ?? 'text-slate-400'}`}>
                  {r.severity}
                </span>
              </td>
              <td className="ui-td text-right text-slate-300">{r.count}</td>
              <td className="ui-td text-right font-mono text-slate-300">
                {fmtMin(r.avg_mttd_minutes)}
              </td>
              <td className="ui-td text-right">
                <SlaPct pct={r.mttd_sla_pct} hasData={r.avg_mttd_minutes !== null} />
                <span className="block text-slate-600 text-xs">&lt;{fmtMin(r.mttd_target_minutes)}</span>
              </td>
              <td className="ui-td text-right font-mono text-slate-300">
                {fmtMin(r.avg_mttr_minutes)}
              </td>
              <td className="ui-td text-right">
                <SlaPct pct={r.mttr_sla_pct} hasData={r.avg_mttr_minutes !== null} />
                <span className="block text-slate-600 text-xs">&lt;{fmtMin(r.mttr_target_minutes)}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export default function MttdMttrPage() {
  const [days, setDays] = useState(30)

  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['analytics', 'mttd-mttr', days],
    queryFn:  () => analyticsApi.mttdMttr(days),
    staleTime: 60_000,
  })

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <Clock className="h-5 w-5 text-violet-400" />
          <div>
            <h1 className="text-lg font-semibold text-slate-100">MTTD / MTTR</h1>
            <p className="text-sm text-slate-400">Ortalama tespit ve yanıt süreleri — SOC KPI</p>
          </div>
          {isFetching && <RefreshCw className="w-4 h-4 text-slate-500 animate-spin" />}
        </div>
        <div className="flex items-center gap-2">
          <div className="flex gap-1">
            {DAY_OPTIONS.map(o => (
              <button
                key={o.value}
                onClick={() => setDays(o.value)}
                className={`px-3 py-1.5 rounded-lg border text-sm font-medium transition-colors ${
                  days === o.value
                    ? 'bg-violet-600 border-violet-500 text-white'
                    : 'bg-sky-950/20 border-sky-900/20 text-slate-400 hover:bg-sky-950/40'
                }`}
              >
                {o.label}
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

      {/* KPI Cards */}
      <div className="grid grid-cols-3 gap-4">
        <div className="rounded-lg border border-sky-900/20 bg-[#0a1120] p-4">
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Ortalama MTTD</p>
          <p className="text-2xl font-bold text-blue-400">
            {isLoading ? '…' : fmtMin(data?.overall_mttd_minutes ?? null)}
          </p>
          <p className="text-xs text-slate-600 mt-1">Tespit → Onay süresi</p>
        </div>
        <div className="rounded-lg border border-sky-900/20 bg-[#0a1120] p-4">
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Ortalama MTTR</p>
          <p className="text-2xl font-bold text-orange-400">
            {isLoading ? '…' : fmtMin(data?.overall_mttr_minutes ?? null)}
          </p>
          <p className="text-xs text-slate-600 mt-1">Tespit → Çözüm süresi</p>
        </div>
        <div className="rounded-lg border border-sky-900/20 bg-[#0a1120] p-4">
          <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">Çözüm Oranı</p>
          <p className="text-2xl font-bold text-emerald-400">
            {isLoading ? '…' : `${data?.resolution_rate ?? 0}%`}
          </p>
          <p className="text-xs text-slate-600 mt-1">
            {data ? `${data.resolved_incidents} / ${data.total_incidents} incident` : ''}
          </p>
        </div>
      </div>

      {/* Trend Chart */}
      <div className="rounded-lg border border-sky-900/20 bg-[#0a1120] p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Günlük Trend</h2>
        {isLoading && <SkeletonChart height={256} />}
        {isError && (
          <div className="h-32 flex items-center justify-center text-red-400 text-sm">
            Veri yüklenemedi
          </div>
        )}
        {data && <MttdMttrChart trend={data.trend} height={280} />}
      </div>

      {/* Severity Breakdown */}
      <div className="rounded-lg border border-sky-900/20 bg-[#0a1120] p-4">
        <h2 className="text-sm font-medium text-slate-400 mb-3">Önem Düzeyine Göre SLA Uyumu</h2>
        {isLoading && <SkeletonChart height={96} />}
        {data && <SeverityTable rows={data.by_severity} />}
      </div>

      {/* Source note */}
      <p className="text-xs text-slate-700">
        SLA hedefleri: SANS 2023 Incident Response Survey + Prophet Security SOC benchmarks.
        MTTD = incident oluşturma → ilk onay. MTTR = incident oluşturma → çözüm.
      </p>
    </div>
  )
}
