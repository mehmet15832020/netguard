'use client'

import { useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { TrendingUp, RefreshCw } from 'lucide-react'
import { analyticsApi } from '@/lib/api'
import { TrafficVolumeChart } from '@/components/charts/TrafficVolumeChart'
import { cn } from '@/lib/utils'

const HOURS_OPTIONS = [
  { label: '1s',  value: 1 },
  { label: '6s',  value: 6 },
  { label: '24s', value: 24 },
  { label: '48s', value: 48 },
  { label: '7g',  value: 168 },
]

export default function TrafficVolumePage() {
  const [hours, setHours] = useState(24)

  const { data, isLoading, isError, isFetching, refetch } = useQuery({
    queryKey: ['traffic-volume', hours],
    queryFn:  () => analyticsApi.trafficVolume(hours),
    refetchInterval: 60_000,
    refetchIntervalInBackground: false,
    staleTime: 30_000,
  })

  const isEmpty =
    !data ||
    (data.series.east_west.every((p) => p.v === 0) &&
      data.series.ns_egress.every((p) => p.v === 0) &&
      data.series.ns_ingress.every((p) => p.v === 0))

  const { totalEastWest, totalNsEgress, totalNsIngress } = useMemo(() => {
    if (!data) return { totalEastWest: 0, totalNsEgress: 0, totalNsIngress: 0 }
    return {
      totalEastWest:  data.series.east_west.reduce((sum, p) => sum + p.v, 0),
      totalNsEgress:  data.series.ns_egress.reduce((sum, p) => sum + p.v, 0),
      totalNsIngress: data.series.ns_ingress.reduce((sum, p) => sum + p.v, 0),
    }
  }, [data])

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <TrendingUp className="w-5 h-5 text-indigo-400" />
          <h1 className="text-lg font-semibold text-zinc-100">Trafik Hacmi</h1>
          {isFetching && (
            <RefreshCw className="w-4 h-4 text-zinc-500 animate-spin" />
          )}
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

      {/* Error state */}
      {isError && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-sm text-red-400 flex items-center justify-between">
          <span>Veri yüklenemedi. Sunucu bağlantısını kontrol edin.</span>
          <button
            onClick={() => refetch()}
            className="text-xs underline hover:text-red-300"
          >
            Tekrar dene
          </button>
        </div>
      )}

      {/* Chart */}
      {isLoading ? (
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 h-80 animate-pulse" />
      ) : isEmpty ? (
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
          <EmptyState />
        </div>
      ) : (
        <div className="bg-zinc-900 rounded-xl border border-zinc-800 p-4">
          <TrafficVolumeChart series={data!.series} hours={hours} height={320} />
        </div>
      )}

      {/* Summary row — 3 istatistik */}
      {data && !isEmpty && (
        <div className="flex items-center gap-6 text-xs text-zinc-500">
          <span>Son {hours} saat —</span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-2 h-2 rounded-full bg-indigo-500" />
            İç ↔ İç:{' '}
            <span className="text-zinc-300 font-medium">
              {totalEastWest.toLocaleString('tr-TR')}
            </span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-2 h-2 rounded-full bg-orange-500" />
            İç → Dış:{' '}
            <span className="text-zinc-300 font-medium">
              {totalNsEgress.toLocaleString('tr-TR')}
            </span>
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-2 h-2 rounded-full bg-red-500" />
            Dış → İç:{' '}
            <span className="text-zinc-300 font-medium">
              {totalNsIngress.toLocaleString('tr-TR')}
            </span>
          </span>
        </div>
      )}
    </div>
  )
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center h-48 text-zinc-600">
      <TrendingUp className="w-8 h-8 mb-2 opacity-30" />
      <p className="text-sm">Trafik Hacmi</p>
      <p className="text-xs mt-1">Veri yok</p>
    </div>
  )
}
