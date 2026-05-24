'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Clock } from 'lucide-react'
import { analyticsApi } from '@/lib/api'
import { MttdMttrChart } from '@/components/charts/MttdMttrChart'
import type { MttdMttrSeverityBreakdown } from '@/lib/api'

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
  if (!hasData) return <span className="text-zinc-600">—</span>
  const color = pct >= 90 ? 'text-emerald-400' : pct >= 70 ? 'text-yellow-400' : 'text-red-400'
  return <span className={`font-medium ${color}`}>{pct.toFixed(0)}%</span>
}

function SeverityTable({ rows }: { rows: MttdMttrSeverityBreakdown[] }) {
  if (rows.length === 0) return (
    <p className="text-sm text-zinc-500 py-4 text-center">Bu dönemde incident bulunamadı</p>
  )
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-zinc-800 text-zinc-500 text-xs">
            <th className="text-left py-2 pr-4 font-medium">Önem</th>
            <th className="text-right py-2 px-4 font-medium">Adet</th>
            <th className="text-right py-2 px-4 font-medium">MTTD Ort.</th>
            <th className="text-right py-2 px-4 font-medium">
              MTTD SLA
              <span className="block text-zinc-600 font-normal">(hedef)</span>
            </th>
            <th className="text-right py-2 px-4 font-medium">MTTR Ort.</th>
            <th className="text-right py-2 px-4 font-medium">
              MTTR SLA
              <span className="block text-zinc-600 font-normal">(hedef)</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map(r => (
            <tr key={r.severity} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
              <td className="py-2 pr-4">
                <span className={`font-medium capitalize ${SEV_COLORS[r.severity] ?? 'text-zinc-400'}`}>
                  {r.severity}
                </span>
              </td>
              <td className="text-right py-2 px-4 text-zinc-300">{r.count}</td>
              <td className="text-right py-2 px-4 font-mono text-zinc-300">
                {fmtMin(r.avg_mttd_minutes)}
              </td>
              <td className="text-right py-2 px-4">
                <SlaPct pct={r.mttd_sla_pct} hasData={r.avg_mttd_minutes !== null} />
                <span className="block text-zinc-600 text-xs">&lt;{fmtMin(r.mttd_target_minutes)}</span>
              </td>
              <td className="text-right py-2 px-4 font-mono text-zinc-300">
                {fmtMin(r.avg_mttr_minutes)}
              </td>
              <td className="text-right py-2 px-4">
                <SlaPct pct={r.mttr_sla_pct} hasData={r.avg_mttr_minutes !== null} />
                <span className="block text-zinc-600 text-xs">&lt;{fmtMin(r.mttr_target_minutes)}</span>
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

  const { data, isLoading, isError } = useQuery({
    queryKey: ['analytics', 'mttd-mttr', days],
    queryFn:  () => analyticsApi.mttdMttr(days),
    staleTime: 60_000,
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3">
          <Clock className="h-6 w-6 text-violet-400" />
          <div>
            <h1 className="text-xl font-semibold text-zinc-100">MTTD / MTTR</h1>
            <p className="text-sm text-zinc-400">Ortalama tespit ve yanıt süreleri — SOC KPI</p>
          </div>
        </div>
        <div className="flex gap-1">
          {DAY_OPTIONS.map(o => (
            <button
              key={o.value}
              onClick={() => setDays(o.value)}
              className={`px-3 py-1.5 rounded text-sm font-medium transition-colors ${
                days === o.value
                  ? 'bg-violet-600 text-white'
                  : 'bg-zinc-800 text-zinc-400 hover:bg-zinc-700'
              }`}
            >
              {o.label}
            </button>
          ))}
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-3 gap-4">
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
          <p className="text-xs text-zinc-500 uppercase tracking-wider mb-1">Ortalama MTTD</p>
          <p className="text-2xl font-bold text-blue-400">
            {isLoading ? '…' : fmtMin(data?.overall_mttd_minutes ?? null)}
          </p>
          <p className="text-xs text-zinc-600 mt-1">Tespit → Onay süresi</p>
        </div>
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
          <p className="text-xs text-zinc-500 uppercase tracking-wider mb-1">Ortalama MTTR</p>
          <p className="text-2xl font-bold text-orange-400">
            {isLoading ? '…' : fmtMin(data?.overall_mttr_minutes ?? null)}
          </p>
          <p className="text-xs text-zinc-600 mt-1">Tespit → Çözüm süresi</p>
        </div>
        <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
          <p className="text-xs text-zinc-500 uppercase tracking-wider mb-1">Çözüm Oranı</p>
          <p className="text-2xl font-bold text-emerald-400">
            {isLoading ? '…' : `${data?.resolution_rate ?? 0}%`}
          </p>
          <p className="text-xs text-zinc-600 mt-1">
            {data ? `${data.resolved_incidents} / ${data.total_incidents} incident` : ''}
          </p>
        </div>
      </div>

      {/* Trend Chart */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
        <h2 className="text-sm font-medium text-zinc-400 mb-3">Günlük Trend</h2>
        {isLoading && <div className="h-64 animate-pulse bg-zinc-800 rounded" />}
        {isError && (
          <div className="h-32 flex items-center justify-center text-red-400 text-sm">
            Veri yüklenemedi
          </div>
        )}
        {data && <MttdMttrChart trend={data.trend} height={280} />}
      </div>

      {/* Severity Breakdown */}
      <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-4">
        <h2 className="text-sm font-medium text-zinc-400 mb-3">Önem Düzeyine Göre SLA Uyumu</h2>
        {isLoading && <div className="h-24 animate-pulse bg-zinc-800 rounded" />}
        {data && <SeverityTable rows={data.by_severity} />}
      </div>

      {/* Source note */}
      <p className="text-xs text-zinc-700">
        SLA hedefleri: SANS 2023 Incident Response Survey + Prophet Security SOC benchmarks.
        MTTD = incident oluşturma → ilk onay. MTTR = incident oluşturma → çözüm.
      </p>
    </div>
  )
}
