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

function intervalColor(s: number): string {
  if (s < 120)  return 'text-red-400'
  if (s <= 600) return 'text-orange-400'
  return 'text-yellow-400'
}

function intervalBadge(s: number): string {
  if (s < 120)  return 'Agresif'
  if (s <= 600) return 'Orta'
  return 'Yavaş'
}

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
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4 inline-flex items-center gap-4">
          <Radio className="w-6 h-6 text-orange-400 flex-shrink-0" />
          <div>
            <p className="text-xs text-zinc-500">Toplam Tespit</p>
            <p className="text-2xl font-bold text-zinc-100">
              {data.total.toLocaleString('tr-TR')}
            </p>
          </div>
        </div>
      ) : null}

      {/* İnterval açıklaması */}
      <div className="flex gap-4 text-xs text-zinc-500">
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-2 h-2 rounded-full bg-red-500" />
          Agresif (&lt;120s)
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-2 h-2 rounded-full bg-orange-500" />
          Orta (120–600s)
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block w-2 h-2 rounded-full bg-yellow-500" />
          Yavaş (&gt;600s)
        </span>
      </div>

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
          <div className="flex flex-col items-center justify-center py-16 text-zinc-600">
            <Radio className="w-8 h-8 mb-2 opacity-30" />
            <p className="text-sm">Veri yok</p>
            <p className="text-xs mt-1">Beaconing aktivitesi tespit edilmedi</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 text-xs text-zinc-500">
                  <th className="text-left px-4 py-2.5 font-medium">Kaynak IP</th>
                  <th className="text-left px-4 py-2.5 font-medium">Hedef IP</th>
                  <th className="text-left px-4 py-2.5 font-medium">Interval</th>
                  <th className="text-left px-4 py-2.5 font-medium">Tespit Sayısı</th>
                  <th className="text-left px-4 py-2.5 font-medium">Son Tespit</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {data.detections.map((det, idx) => (
                  <tr
                    key={`${det.source_ip}-${det.dest_ip}-${idx}`}
                    className="hover:bg-zinc-800/30 transition-colors"
                  >
                    <td className="px-4 py-2.5 font-mono text-zinc-300 text-xs">{det.source_ip}</td>
                    <td className="px-4 py-2.5 font-mono text-zinc-300 text-xs">{det.dest_ip}</td>
                    <td className="px-4 py-2.5">
                      <span className={`font-semibold text-xs ${intervalColor(det.interval_s)}`}>
                        {det.interval_s}s
                      </span>
                      <span className="ml-1.5 text-[10px] text-zinc-600">
                        ({intervalBadge(det.interval_s)})
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-zinc-300 text-sm font-semibold">
                      {det.count.toLocaleString('tr-TR')}
                    </td>
                    <td className="px-4 py-2.5 text-zinc-500 text-xs">
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
