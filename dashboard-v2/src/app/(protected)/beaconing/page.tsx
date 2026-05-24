'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Radio, RefreshCw } from 'lucide-react'
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

export default function BeaconingPage() {
  const [hours, setHours] = useState(24)

  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['beaconing-summary', hours],
    queryFn:  () => analyticsApi.beaconingSummary(hours),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Radio className="w-5 h-5 text-indigo-400" />
          <h1 className="text-lg font-semibold text-zinc-100">Beaconing Tespiti</h1>
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

      {/* Stat kart */}
      {isLoading ? (
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 h-20 animate-pulse" />
      ) : data ? (
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4 flex items-center gap-4">
          <div className={`p-2 rounded-lg ${data.total > 0 ? 'bg-red-500/15 text-red-400' : 'bg-zinc-700/40 text-zinc-400'}`}>
            <Radio className="w-4 h-4" />
          </div>
          <div>
            <p className="text-xs text-zinc-500">Toplam Tespit</p>
            <div className="flex items-center gap-2">
              <p className="text-2xl font-bold text-zinc-100">
                {data.total.toLocaleString('tr-TR')}
              </p>
              {data.total > 0 && (
                <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-900/50 text-red-400 border border-red-800">
                  UYARI
                </span>
              )}
            </div>
            <p className="text-xs text-zinc-500 mt-0.5">Son {hours} saat</p>
          </div>
        </div>
      ) : null}

      {/* Tablo */}
      <div className="bg-zinc-900 rounded-xl border border-zinc-800">
        <div className="px-4 py-3 border-b border-zinc-800">
          <h2 className="text-sm font-semibold text-zinc-200">Tespit Edilen Beacon'lar</h2>
        </div>

        {isLoading ? (
          <div className="p-4 space-y-2">
            {[0, 1, 2].map((i) => (
              <div key={i} className="h-9 rounded bg-zinc-800 animate-pulse" />
            ))}
          </div>
        ) : !data || data.detections.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-16 rounded-b-xl bg-emerald-950/20 border-t border-emerald-900/40">
            <Radio className="w-8 h-8 mb-2 text-emerald-500 opacity-60" />
            <p className="text-sm text-emerald-400 font-medium">Bu zaman aralığında beaconing tespiti yapılmadı</p>
            <p className="text-xs text-emerald-600 mt-1">Ağda C2 beacon aktivitesi gözlemlenmedi</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 text-xs text-zinc-500">
                  <th className="text-left px-4 py-2.5 font-medium">Kaynak IP</th>
                  <th className="text-left px-4 py-2.5 font-medium">Hedef IP</th>
                  <th className="text-left px-4 py-2.5 font-medium">Mesaj</th>
                  <th className="text-left px-4 py-2.5 font-medium">Tespit Zamanı</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {data.detections.map((det, idx) => (
                  <tr
                    key={`${det.source_ip}-${det.destination_ip}-${idx}`}
                    className="hover:bg-zinc-800/30 transition-colors"
                  >
                    <td className="px-4 py-2.5 font-mono text-zinc-300 text-xs">{det.source_ip}</td>
                    <td className="px-4 py-2.5 font-mono text-zinc-300 text-xs">{det.destination_ip}</td>
                    <td className="px-4 py-2.5 text-zinc-400 text-xs max-w-sm truncate" title={det.message}>
                      {det.message}
                    </td>
                    <td className="px-4 py-2.5 text-zinc-500 text-xs whitespace-nowrap">
                      {fmtDate(det.detected_at)}
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
