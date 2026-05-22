'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, RefreshCw } from 'lucide-react'
import { analyticsApi } from '@/lib/api'
import { cn } from '@/lib/utils'

const HOURS_OPTIONS = [
  { label: '1s',  value: 1 },
  { label: '6s',  value: 6 },
  { label: '24s', value: 24 },
  { label: '48s', value: 48 },
  { label: '7g',  value: 168 },
]

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleString('tr-TR', { timeZone: 'UTC' })
}

export default function ThreatIntelSummaryPage() {
  const [hours, setHours] = useState(24)

  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['threat-summary', hours],
    queryFn:  () => analyticsApi.threatSummary(hours),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-indigo-400" />
          <h1 className="text-lg font-semibold text-zinc-100">Threat Intelligence Özeti</h1>
          {isFetching && <RefreshCw className="w-4 h-4 text-zinc-500 animate-spin" />}
        </div>
        <div className="flex items-center gap-3">
          <div className="flex rounded-md overflow-hidden border border-zinc-700">
            {HOURS_OPTIONS.map((opt) => (
              <button
                key={opt.value}
                onClick={() => setHours(opt.value)}
                className={cn(
                  'px-3 py-1 text-xs',
                  hours === opt.value
                    ? 'bg-indigo-600 text-white'
                    : 'bg-zinc-800 text-zinc-400 hover:bg-zinc-700',
                )}
              >
                {opt.label}
              </button>
            ))}
          </div>
          <button
            onClick={() => refetch()}
            className="p-1.5 rounded text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 transition-colors"
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
        <div className="grid grid-cols-2 gap-4">
          {[0, 1].map((i) => (
            <div key={i} className="bg-zinc-900 rounded-xl border border-zinc-800 h-20 animate-pulse" />
          ))}
        </div>
      ) : data ? (
        <div className="grid grid-cols-2 gap-4">
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
            <p className="text-xs text-zinc-500 mb-1">Toplam Kritik Alert</p>
            <p className="text-2xl font-bold text-red-400">
              {data.critical_count.toLocaleString('tr-TR')}
            </p>
          </div>
          <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
            <p className="text-xs text-zinc-500 mb-1">Toplam Tehdit Kaynağı</p>
            <p className="text-2xl font-bold text-zinc-100">
              {data.top_sources.length.toLocaleString('tr-TR')}
            </p>
            <p className="text-[10px] text-zinc-600 mt-0.5">
              {data.total_alerts.toLocaleString('tr-TR')} toplam alert
            </p>
          </div>
        </div>
      ) : null}

      {/* Top threat source tablosu */}
      <div className="bg-zinc-900 rounded-xl border border-zinc-800">
        <div className="px-4 py-3 border-b border-zinc-800">
          <h2 className="text-sm font-semibold text-zinc-200">Top Tehdit Kaynakları</h2>
        </div>

        {isLoading ? (
          <div className="p-4 space-y-2">
            {[0, 1, 2, 3].map((i) => (
              <div key={i} className="h-9 rounded bg-zinc-800 animate-pulse" />
            ))}
          </div>
        ) : !data || data.top_sources.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 text-zinc-600">
            <AlertTriangle className="w-8 h-8 mb-2 opacity-30" />
            <p className="text-sm">Veri yok</p>
            <p className="text-xs mt-1">Tehdit kaynağı tespit edilmedi</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 text-xs text-zinc-500">
                  <th className="text-left px-4 py-2.5 font-medium">#</th>
                  <th className="text-left px-4 py-2.5 font-medium">IP Adresi</th>
                  <th className="text-left px-4 py-2.5 font-medium">Alert Sayısı</th>
                  <th className="text-left px-4 py-2.5 font-medium">Son Görülme</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {data.top_sources.map((src, idx) => (
                  <tr key={src.ip} className="hover:bg-zinc-800/30 transition-colors">
                    <td className="px-4 py-2.5 text-zinc-600 text-xs">{idx + 1}</td>
                    <td className="px-4 py-2.5 font-mono text-zinc-300 text-xs">{src.ip}</td>
                    <td className="px-4 py-2.5 text-red-400 font-semibold">
                      {src.count.toLocaleString('tr-TR')}
                    </td>
                    <td className="px-4 py-2.5 text-zinc-500 text-xs">
                      {fmtDate(src.last_seen)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
